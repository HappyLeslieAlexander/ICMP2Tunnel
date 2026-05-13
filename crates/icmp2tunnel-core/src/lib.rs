#![forbid(unsafe_code)]
#![deny(warnings)]

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use icmp2tunnel_proto::{derive_key, MuxFrame, MuxOp, ProtoError, ReplayWindow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketNo(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Opening,
    Open,
    LocalHalfClosed,
    RemoteHalfClosed,
    Closed,
}

#[derive(Debug, Clone)]
struct StreamEntry {
    state: StreamState,
    send_off: u64,
    recv_off: u64,
    pending_ack: u64,
    window: u32,
    reorder: BTreeMap<u64, Vec<u8>>,
}

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
    StreamLimit,
    UnknownStream,
    StreamClosed,
    StreamOffset,
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
    streams: BTreeMap<StreamId, StreamEntry>,
    stream_limit: usize,
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
            streams: BTreeMap::new(),
            stream_limit: 64,
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

    pub fn open_stream(&mut self, stream_id: StreamId) -> Result<MuxFrame, SessionError> {
        if self.streams.len() >= self.stream_limit {
            return Err(SessionError::StreamLimit);
        }
        let entry = self.streams.entry(stream_id).or_insert(StreamEntry {
            state: StreamState::Idle,
            send_off: 0,
            recv_off: 0,
            pending_ack: 0,
            window: u32::MAX,
            reorder: BTreeMap::new(),
        });
        entry.state = StreamState::Opening;
        let window = entry.window;
        self.touch();
        Ok(MuxFrame { op: MuxOp::Open, stream_id: stream_id.0, window, body: Vec::new() })
    }

    pub fn on_stream_frame(&mut self, frame: &MuxFrame) -> Result<Vec<u8>, SessionError> {
        match frame.op {
            MuxOp::Open => {
                if self.streams.len() >= self.stream_limit && !self.streams.contains_key(&StreamId(frame.stream_id)) {
                    return Err(SessionError::StreamLimit);
                }
                let e = self.streams.entry(StreamId(frame.stream_id)).or_insert(StreamEntry {
                    state: StreamState::Idle,
                    send_off: 0,
                    recv_off: 0,
                    pending_ack: 0,
                    window: frame.window,
                    reorder: BTreeMap::new(),
                });
                e.state = StreamState::Open;
                Ok(Vec::new())
            }
            MuxOp::OpenOk => {
                let e = self.streams.get_mut(&StreamId(frame.stream_id)).ok_or(SessionError::UnknownStream)?;
                e.state = StreamState::Open;
                Ok(Vec::new())
            }
            MuxOp::OpenErr => {
                let e = self.streams.get_mut(&StreamId(frame.stream_id)).ok_or(SessionError::UnknownStream)?;
                e.state = StreamState::Closed;
                Ok(Vec::new())
            }
            MuxOp::Data => self.on_stream_data(frame),
            MuxOp::Fin => {
                let e = self.streams.get_mut(&StreamId(frame.stream_id)).ok_or(SessionError::UnknownStream)?;
                e.state = match e.state {
                    StreamState::Open => StreamState::RemoteHalfClosed,
                    StreamState::LocalHalfClosed => StreamState::Closed,
                    s => s,
                };
                Ok(Vec::new())
            }
            MuxOp::Rst => {
                let e = self.streams.get_mut(&StreamId(frame.stream_id)).ok_or(SessionError::UnknownStream)?;
                e.state = StreamState::Closed;
                e.reorder.clear();
                Ok(Vec::new())
            }
            MuxOp::Ack => {
                let e = self.streams.get_mut(&StreamId(frame.stream_id)).ok_or(SessionError::UnknownStream)?;
                if frame.body.len() != 8 {
                    return Err(SessionError::StreamOffset);
                }
                let acked = u64::from_be_bytes(frame.body.as_slice().try_into().map_err(|_| SessionError::StreamOffset)?);
                if acked > e.send_off {
                    return Err(SessionError::StreamOffset);
                }
                Ok(Vec::new())
            }
            MuxOp::Window => {
                let e = self.streams.get_mut(&StreamId(frame.stream_id)).ok_or(SessionError::UnknownStream)?;
                e.window = frame.window;
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn on_stream_data(&mut self, frame: &MuxFrame) -> Result<Vec<u8>, SessionError> {
        if frame.body.len() < 8 {
            return Err(SessionError::StreamOffset);
        }
        let e = self.streams.get_mut(&StreamId(frame.stream_id)).ok_or(SessionError::UnknownStream)?;
        if matches!(e.state, StreamState::Closed | StreamState::Idle | StreamState::Opening) {
            return Err(SessionError::StreamClosed);
        }
        let off = u64::from_be_bytes(frame.body[0..8].try_into().map_err(|_| SessionError::StreamOffset)?);
        let payload = frame.body[8..].to_vec();
        if off < e.recv_off {
            return Ok(Vec::new());
        }
        if off > e.recv_off {
            e.reorder.entry(off).or_insert(payload);
            return Ok(Vec::new());
        }
        let mut out = payload;
        e.recv_off += u64::try_from(out.len()).unwrap_or(0);
        while let Some(next) = e.reorder.remove(&e.recv_off) {
            e.recv_off += u64::try_from(next.len()).unwrap_or(0);
            out.extend_from_slice(&next);
        }
        e.pending_ack = e.recv_off;
        Ok(out)
    }

    pub fn stream_data_frame(&mut self, stream_id: StreamId, body: &[u8]) -> Result<MuxFrame, SessionError> {
        let e = self.streams.get_mut(&stream_id).ok_or(SessionError::UnknownStream)?;
        if e.state != StreamState::Open && e.state != StreamState::RemoteHalfClosed {
            return Err(SessionError::StreamClosed);
        }
        let mut data = e.send_off.to_be_bytes().to_vec();
        data.extend_from_slice(body);
        e.send_off = e.send_off.saturating_add(u64::try_from(body.len()).map_err(|_| SessionError::StreamOffset)?);
        Ok(MuxFrame { op: MuxOp::Data, stream_id: stream_id.0, window: e.window, body: data })
    }

    pub fn stream_ack_frame(&self, stream_id: StreamId) -> Result<MuxFrame, SessionError> {
        let e = self.streams.get(&stream_id).ok_or(SessionError::UnknownStream)?;
        Ok(MuxFrame { op: MuxOp::Ack, stream_id: stream_id.0, window: e.window, body: e.pending_ack.to_be_bytes().to_vec() })
    }

    pub fn stream_fin_frame(&mut self, stream_id: StreamId) -> Result<MuxFrame, SessionError> {
        let e = self.streams.get_mut(&stream_id).ok_or(SessionError::UnknownStream)?;
        e.state = match e.state {
            StreamState::Open => StreamState::LocalHalfClosed,
            StreamState::RemoteHalfClosed => StreamState::Closed,
            s => s,
        };
        Ok(MuxFrame { op: MuxOp::Fin, stream_id: stream_id.0, window: e.window, body: Vec::new() })
    }

    pub fn stream_rst_frame(&mut self, stream_id: StreamId) -> Result<MuxFrame, SessionError> {
        let e = self.streams.get_mut(&stream_id).ok_or(SessionError::UnknownStream)?;
        e.state = StreamState::Closed;
        Ok(MuxFrame { op: MuxOp::Rst, stream_id: stream_id.0, window: e.window, body: Vec::new() })
    }

    pub fn stream_state(&self, stream_id: StreamId) -> Option<StreamState> { self.streams.get(&stream_id).map(|s| s.state) }
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

    #[test]
    fn one_stream_ordered_transfer_and_half_close() {
        let mut a = Session::new(SessionId(1), SessionConfig::default());
        let mut b = Session::new(SessionId(1), SessionConfig::default());
        a.state = SessionState::Established;
        b.state = SessionState::Established;
        let sid = StreamId(7);
        let open = a.open_stream(sid).expect("open");
        b.on_stream_frame(&open).expect("recv open");
        a.on_stream_frame(&MuxFrame { op: MuxOp::OpenOk, stream_id: sid.0, window: u32::MAX, body: Vec::new() })
            .expect("open ok");
        let data = a.stream_data_frame(sid, b"abc").expect("data");
        let got = b.on_stream_frame(&data).expect("deliver");
        assert_eq!(got, b"abc");
        let ack = b.stream_ack_frame(sid).expect("ack");
        a.on_stream_frame(&ack).expect("ack process");
        let fin = a.stream_fin_frame(sid).expect("fin");
        b.on_stream_frame(&fin).expect("remote fin");
        assert_eq!(b.stream_state(sid), Some(StreamState::RemoteHalfClosed));
    }

    #[test]
    fn concurrent_streams_and_reorder() {
        let mut s = Session::new(SessionId(1), SessionConfig::default());
        s.state = SessionState::Established;
        let sid = StreamId(9);
        s.on_stream_frame(&MuxFrame { op: MuxOp::Open, stream_id: sid.0, window: 0, body: Vec::new() }).expect("open");
        let mut o1 = 3_u64.to_be_bytes().to_vec();
        o1.extend_from_slice(b"def");
        let mut o0 = 0_u64.to_be_bytes().to_vec();
        o0.extend_from_slice(b"abc");
        assert!(s.on_stream_frame(&MuxFrame { op: MuxOp::Data, stream_id: sid.0, window: 0, body: o1 }).expect("buffer").is_empty());
        let delivered = s.on_stream_frame(&MuxFrame { op: MuxOp::Data, stream_id: sid.0, window: 0, body: o0 }).expect("flush");
        assert_eq!(delivered, b"abcdef");
    }

    #[test]
    fn stream_reset_propagates() {
        let mut s = Session::new(SessionId(1), SessionConfig::default());
        s.state = SessionState::Established;
        let sid = StreamId(3);
        s.on_stream_frame(&MuxFrame { op: MuxOp::Open, stream_id: sid.0, window: 0, body: Vec::new() }).expect("open");
        let rst = s.stream_rst_frame(sid).expect("rst");
        s.on_stream_frame(&rst).expect("receive rst");
        assert_eq!(s.stream_state(sid), Some(StreamState::Closed));
    }

    #[test]
    fn stream_limit_enforced() {
        let mut s = Session::new(SessionId(1), SessionConfig::default());
        s.state = SessionState::Established;
        s.stream_limit = 2;
        s.open_stream(StreamId(1)).expect("s1");
        s.open_stream(StreamId(2)).expect("s2");
        assert!(matches!(s.open_stream(StreamId(3)), Err(SessionError::StreamLimit)));
    }
}
