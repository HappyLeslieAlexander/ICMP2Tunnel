#![forbid(unsafe_code)]
#![deny(warnings)]

use std::time::{Duration, Instant};

use icmp2tunnel_proto::{derive_key, MuxFrame, MuxOp, ProtoError, ReplayWindow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketNo(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    New,
    HelloSent,
    Established,
    Draining,
    Closed,
}

#[derive(Debug)]
pub enum SessionError {
    InvalidTransition { from: SessionState, op: &'static str },
    Proto(ProtoError),
    Timeout,
    Replay,
}

impl From<ProtoError> for SessionError {
    fn from(value: ProtoError) -> Self { Self::Proto(value) }
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub idle_timeout: Duration,
    pub psk: Vec<u8>,
    pub salt: Vec<u8>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self { idle_timeout: Duration::from_secs(30), psk: b"dev-psk".to_vec(), salt: b"dev-salt".to_vec() }
    }
}

#[derive(Debug)]
pub struct Session {
    pub id: SessionId,
    pub state: SessionState,
    next_packet: PacketNo,
    replay: ReplayWindow,
    highest_ack: PacketNo,
    key: Option<[u8; 32]>,
    last_activity: Instant,
    cfg: SessionConfig,
}

impl Session {
    #[must_use]
    pub fn new(id: SessionId, cfg: SessionConfig) -> Self {
        Self {
            id,
            state: SessionState::New,
            next_packet: PacketNo(1),
            replay: ReplayWindow::new(),
            highest_ack: PacketNo(0),
            key: None,
            last_activity: Instant::now(),
            cfg,
        }
    }

    pub fn client_hello(&mut self) -> Result<MuxFrame, SessionError> {
        if self.state != SessionState::New {
            return Err(SessionError::InvalidTransition { from: self.state, op: "client_hello" });
        }
        self.key = Some(derive_key(&self.cfg.psk, &self.cfg.salt)?);
        self.state = SessionState::HelloSent;
        self.touch();
        Ok(MuxFrame { op: MuxOp::Hello, stream_id: 0, window: 0, body: self.id.0.to_be_bytes().to_vec() })
    }

    pub fn server_hello_reply(&mut self, hello: &MuxFrame) -> Result<MuxFrame, SessionError> {
        if self.state != SessionState::New {
            return Err(SessionError::InvalidTransition { from: self.state, op: "server_hello_reply" });
        }
        if hello.op != MuxOp::Hello {
            return Err(SessionError::InvalidTransition { from: self.state, op: "not_hello" });
        }
        self.key = Some(derive_key(&self.cfg.psk, &self.cfg.salt)?);
        self.state = SessionState::Established;
        self.touch();
        Ok(MuxFrame { op: MuxOp::HelloReply, stream_id: 0, window: 0, body: b"ok".to_vec() })
    }

    pub fn client_on_hello_reply(&mut self, reply: &MuxFrame) -> Result<(), SessionError> {
        if self.state != SessionState::HelloSent {
            return Err(SessionError::InvalidTransition { from: self.state, op: "client_on_hello_reply" });
        }
        if reply.op != MuxOp::HelloReply {
            return Err(SessionError::InvalidTransition { from: self.state, op: "not_hello_reply" });
        }
        self.state = SessionState::Established;
        self.touch();
        Ok(())
    }

    pub fn allocate_packet_no(&mut self) -> Result<PacketNo, SessionError> {
        if self.state != SessionState::Established && self.state != SessionState::Draining {
            return Err(SessionError::InvalidTransition { from: self.state, op: "allocate_packet_no" });
        }
        let pn = self.next_packet;
        self.next_packet.0 = self.next_packet.0.saturating_add(1);
        self.touch();
        Ok(pn)
    }

    pub fn make_ack_frame(&mut self, acked: PacketNo) -> Result<MuxFrame, SessionError> {
        if self.state != SessionState::Established {
            return Err(SessionError::InvalidTransition { from: self.state, op: "make_ack_frame" });
        }
        self.touch();
        Ok(MuxFrame { op: MuxOp::Ack, stream_id: 0, window: 0, body: acked.0.to_be_bytes().to_vec() })
    }

    pub fn process_ack_frame(&mut self, ack: &MuxFrame) -> Result<PacketNo, SessionError> {
        if ack.op != MuxOp::Ack || ack.body.len() != 8 {
            return Err(SessionError::InvalidTransition { from: self.state, op: "process_ack_frame" });
        }
        let n = PacketNo(u64::from_be_bytes(ack.body.as_slice().try_into().map_err(|_| SessionError::Replay)?));
        if n <= self.highest_ack {
            return Err(SessionError::Replay);
        }
        self.highest_ack = n;
        self.touch();
        Ok(n)
    }

    pub fn on_inbound_packet(&mut self, pn: PacketNo) -> Result<(), SessionError> {
        self.replay.check_and_mark(pn.0).map_err(|_| SessionError::Replay)?;
        self.touch();
        Ok(())
    }

    pub fn check_idle_timeout(&self, now: Instant) -> Result<(), SessionError> {
        if now.duration_since(self.last_activity) > self.cfg.idle_timeout { return Err(SessionError::Timeout); }
        Ok(())
    }

    pub fn start_draining(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Established {
            return Err(SessionError::InvalidTransition { from: self.state, op: "start_draining" });
        }
        self.state = SessionState::Draining;
        self.touch();
        Ok(())
    }

    pub fn graceful_shutdown(&mut self) -> Result<(), SessionError> {
        if self.state != SessionState::Draining && self.state != SessionState::Established {
            return Err(SessionError::InvalidTransition { from: self.state, op: "graceful_shutdown" });
        }
        self.state = SessionState::Closed;
        self.touch();
        Ok(())
    }

    fn touch(&mut self) { self.last_activity = Instant::now(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_state_transitions() {
        let mut client = Session::new(SessionId(1), SessionConfig::default());
        let mut server = Session::new(SessionId(1), SessionConfig::default());

        let hello = client.client_hello().expect("client hello");
        let reply = server.server_hello_reply(&hello).expect("hello reply");
        client.client_on_hello_reply(&reply).expect("client accepts reply");
        assert_eq!(client.state, SessionState::Established);
        assert_eq!(server.state, SessionState::Established);

        let pn1 = client.allocate_packet_no().expect("allocate packet");
        let ack = server.make_ack_frame(pn1).expect("make ack");
        let _ = client.process_ack_frame(&ack).expect("process ack");

        server.on_inbound_packet(PacketNo(10)).expect("first packet");
        server.on_inbound_packet(PacketNo(11)).expect("second packet");

        client.start_draining().expect("start draining");
        client.graceful_shutdown().expect("shutdown");
        assert_eq!(client.state, SessionState::Closed);
    }

    #[test]
    fn invalid_state_transitions_and_guards() {
        let mut s = Session::new(SessionId(2), SessionConfig::default());
        assert!(matches!(s.allocate_packet_no(), Err(SessionError::InvalidTransition { .. })));

        let bad = MuxFrame { op: MuxOp::Ack, stream_id: 0, window: 0, body: vec![0; 8] };
        assert!(matches!(s.client_on_hello_reply(&bad), Err(SessionError::InvalidTransition { .. })));

        let hello = s.client_hello().expect("hello");
        assert!(matches!(s.client_hello(), Err(SessionError::InvalidTransition { .. })));

        let mut server = Session::new(SessionId(2), SessionConfig::default());
        let _reply = server.server_hello_reply(&hello).expect("server reply");
        assert!(matches!(server.server_hello_reply(&hello), Err(SessionError::InvalidTransition { .. })));

        server.on_inbound_packet(PacketNo(200)).expect("first inbound");
        assert!(matches!(server.on_inbound_packet(PacketNo(200)), Err(SessionError::Replay)));

        let too_old = PacketNo(1);
        assert!(matches!(server.on_inbound_packet(too_old), Err(SessionError::Replay)));
    }

    #[test]
    fn session_times_out_after_idle_timeout() {
        let cfg = SessionConfig { idle_timeout: Duration::from_millis(1), ..SessionConfig::default() };
        let s = Session::new(SessionId(3), cfg);
        let now = Instant::now() + Duration::from_millis(10);
        assert!(matches!(s.check_idle_timeout(now), Err(SessionError::Timeout)));
    }
}
