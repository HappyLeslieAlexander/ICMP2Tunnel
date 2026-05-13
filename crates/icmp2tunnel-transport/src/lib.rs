#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundEcho {
    pub payload: Vec<u8>,
    pub reply_token: ReplyToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyToken(pub u64);

pub trait ClientIcmp {
    fn send_echo(&mut self, payload: Vec<u8>);
    fn poll_reply(&mut self) -> Option<Vec<u8>>;
}

pub trait ServerIcmp {
    fn poll_echo(&mut self) -> Option<InboundEcho>;
    fn send_reply(&mut self, token: ReplyToken, payload: Vec<u8>);
}

#[derive(Debug, Clone, Copy)]
pub struct SimulationConfig {
    pub loss_every: Option<u64>,
    pub duplicate_every: Option<u64>,
    pub reorder_window: usize,
    pub latency_ticks: u64,
}
impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            loss_every: None,
            duplicate_every: None,
            reorder_window: 0,
            latency_ticks: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct Packet {
    seq: u64,
    deliver_at: u64,
    payload: Vec<u8>,
    token: ReplyToken,
}

#[derive(Debug, Default)]
pub struct DeterministicScheduler {
    now: u64,
    next_seq: u64,
    c2s: VecDeque<Packet>,
    s2c: VecDeque<Packet>,
}
impl DeterministicScheduler {
    pub fn tick(&mut self) {
        self.now += 1;
    }
    fn schedule(&mut self, to_server: bool, payload: Vec<u8>, cfg: SimulationConfig) {
        self.next_seq += 1;
        let seq = self.next_seq;
        if let Some(n) = cfg.loss_every {
            if seq % n == 0 {
                return;
            }
        }
        let token = ReplyToken(seq);
        let deliver_at = self.now + cfg.latency_ticks;
        let pkt = Packet {
            seq,
            deliver_at,
            payload: payload.clone(),
            token,
        };
        let queue = if to_server {
            &mut self.c2s
        } else {
            &mut self.s2c
        };
        queue.push_back(pkt);
        if let Some(n) = cfg.duplicate_every {
            if seq % n == 0 {
                queue.push_back(Packet {
                    seq,
                    deliver_at,
                    payload,
                    token,
                });
            }
        }
        if cfg.reorder_window > 1 && queue.len() >= cfg.reorder_window {
            let idx = queue.len() - cfg.reorder_window;
            queue.swap(idx, idx + 1);
        }
    }
    fn poll_server(&mut self) -> Option<InboundEcho> {
        let idx = self.c2s.iter().position(|p| p.deliver_at <= self.now)?;
        let p = self.c2s.remove(idx)?;
        let _ = p.seq;
        Some(InboundEcho {
            payload: p.payload,
            reply_token: p.token,
        })
    }
    fn poll_client(&mut self) -> Option<Vec<u8>> {
        let idx = self.s2c.iter().position(|p| p.deliver_at <= self.now)?;
        let p = self.s2c.remove(idx)?;
        let _ = p.seq;
        Some(p.payload)
    }
}

pub struct FakeClientTransport {
    scheduler: Rc<RefCell<DeterministicScheduler>>,
    cfg: SimulationConfig,
}
pub struct FakeServerTransport {
    scheduler: Rc<RefCell<DeterministicScheduler>>,
    cfg: SimulationConfig,
}

pub fn fake_pair(
    cfg: SimulationConfig,
) -> (
    FakeClientTransport,
    FakeServerTransport,
    Rc<RefCell<DeterministicScheduler>>,
) {
    let scheduler = Rc::new(RefCell::new(DeterministicScheduler::default()));
    (
        FakeClientTransport {
            scheduler: Rc::clone(&scheduler),
            cfg,
        },
        FakeServerTransport {
            scheduler: Rc::clone(&scheduler),
            cfg,
        },
        scheduler,
    )
}

impl ClientIcmp for FakeClientTransport {
    fn send_echo(&mut self, payload: Vec<u8>) {
        self.scheduler
            .borrow_mut()
            .schedule(true, payload, self.cfg);
    }
    fn poll_reply(&mut self) -> Option<Vec<u8>> {
        self.scheduler.borrow_mut().poll_client()
    }
}
impl ServerIcmp for FakeServerTransport {
    fn poll_echo(&mut self) -> Option<InboundEcho> {
        self.scheduler.borrow_mut().poll_server()
    }
    fn send_reply(&mut self, token: ReplyToken, payload: Vec<u8>) {
        let _ = token;
        self.scheduler
            .borrow_mut()
            .schedule(false, payload, self.cfg);
    }
}

#[cfg(test)]
mod tests {
    use super::{fake_pair, ClientIcmp, ServerIcmp, SimulationConfig};

    #[test]
    fn exchange_works() {
        let (mut client, mut server, _) = fake_pair(SimulationConfig::default());
        client.send_echo(b"ping".to_vec());
        let echo = server.poll_echo().expect("server should receive echo");
        assert_eq!(echo.payload, b"ping");
        server.send_reply(echo.reply_token, b"pong".to_vec());
        assert_eq!(
            client.poll_reply().expect("client should receive reply"),
            b"pong"
        );
    }

    #[test]
    fn simulates_loss_duplicate_reorder_latency() {
        let cfg = SimulationConfig {
            loss_every: Some(2),
            duplicate_every: Some(3),
            reorder_window: 2,
            latency_ticks: 2,
        };
        let (mut client, mut server, scheduler) = fake_pair(cfg);
        client.send_echo(vec![1]);
        client.send_echo(vec![2]);
        client.send_echo(vec![3]);

        assert!(server.poll_echo().is_none());
        scheduler.borrow_mut().tick();
        assert!(server.poll_echo().is_none());
        scheduler.borrow_mut().tick();

        let first = server.poll_echo().expect("first arrives");
        let second = server.poll_echo().expect("second arrives");
        let third = server.poll_echo().expect("third arrives");

        let mut payloads = vec![first.payload, second.payload, third.payload];
        payloads.sort();
        assert_eq!(payloads, vec![vec![1], vec![3], vec![3]]);
    }
}
