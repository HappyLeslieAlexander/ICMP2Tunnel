use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use icmp2tunnel::acl::{PeerAcl, PeerRateLimiters, RateLimiter, RateLimits, TargetAcl};
use icmp2tunnel::icmp::{
    build_echo_reply, parse_echo_packet, IcmpSocket, ICMP_ECHO_REQUEST,
};
use icmp2tunnel::wire::{self, Frame, FrameType};

#[derive(Debug, Parser)]
#[command(name = "icmp2tunnel-server", about = "Authenticated ICMP2Tunnel server")]
struct Cli {
    #[arg(short, long, default_value = "examples/server.toml")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    psk: String,
    salt: Option<String>,
    log_level: Option<String>,
    peer_acl: Vec<String>,
    target_acl: Vec<String>,
    max_sessions_per_peer: Option<usize>,
    packet_per_sec: Option<u64>,
    byte_per_sec: Option<u64>,
    read_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct ServerConfig {
    psk: Vec<u8>,
    salt: Vec<u8>,
    log_level: String,
    peer_acl: PeerAcl,
    target_acl: TargetAcl,
    max_sessions_per_peer: usize,
    rate_limits: RateLimits,
    read_timeout: Duration,
}

fn load_config(cli: &Cli) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(&cli.config)?;
    let file: FileConfig = toml::from_str(&text)?;
    let peer_acl = PeerAcl::parse(&file.peer_acl)?;
    let target_acl = TargetAcl::parse(&file.target_acl)?;
    let cfg = ServerConfig {
        psk: file.psk.into_bytes(),
        salt: file.salt.unwrap_or_else(|| "icmp2tunnel-v1".to_string()).into_bytes(),
        log_level: file.log_level.unwrap_or_else(|| "info".to_string()),
        peer_acl,
        target_acl,
        max_sessions_per_peer: file.max_sessions_per_peer.unwrap_or(8),
        rate_limits: RateLimits {
            packets_per_sec: file.packet_per_sec.unwrap_or(256),
            bytes_per_sec: file.byte_per_sec.unwrap_or(262_144),
        },
        read_timeout: Duration::from_millis(file.read_timeout_ms.unwrap_or(250)),
    };
    validate_config(&cfg)?;
    Ok(cfg)
}

fn validate_config(cfg: &ServerConfig) -> Result<(), String> {
    if cfg.psk.len() < 16 {
        return Err("PSK must be at least 16 bytes".to_string());
    }
    if cfg.peer_acl.is_empty() {
        return Err("peer_acl must not be empty".to_string());
    }
    if cfg.target_acl.is_empty() {
        return Err("target_acl must not be empty".to_string());
    }
    if cfg.max_sessions_per_peer == 0 {
        return Err("max_sessions_per_peer must be greater than 0".to_string());
    }
    if cfg.rate_limits.packets_per_sec == 0 || cfg.rate_limits.bytes_per_sec == 0 {
        return Err("rate limits must be greater than 0".to_string());
    }
    Ok(())
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .expect("default tracing filter parses");
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[derive(Debug, Clone)]
struct PendingFrame {
    kind: FrameType,
    stream_id: u32,
    payload: Vec<u8>,
}

impl PendingFrame {
    fn into_frame(self) -> Frame {
        Frame::new(self.kind, self.stream_id, self.payload)
    }
}

#[derive(Debug)]
struct StreamEntry {
    tcp: TcpStream,
    target: String,
    opened_at: Instant,
    bytes_up: u64,
    bytes_down: u64,
}

#[derive(Debug)]
struct SessionEntry {
    peer: IpAddr,
    streams: HashMap<u32, StreamEntry>,
    pending: VecDeque<PendingFrame>,
    reply_cache: HashMap<u64, Frame>,
    created_at: Instant,
}

impl SessionEntry {
    fn new(peer: IpAddr) -> Self {
        Self {
            peer,
            streams: HashMap::new(),
            pending: VecDeque::new(),
            reply_cache: HashMap::new(),
            created_at: Instant::now(),
        }
    }

    fn cache_reply(&mut self, packet_no: u64, frame: Frame) {
        self.reply_cache.insert(packet_no, frame);
        if self.reply_cache.len() > 1024 {
            let min_key = self.reply_cache.keys().min().copied();
            if let Some(key) = min_key {
                self.reply_cache.remove(&key);
            }
        }
    }

    fn next_pending_or_pong(&mut self, stream_id: u32) -> Frame {
        if let Some(pos) = self
            .pending
            .iter()
            .position(|frame| frame.stream_id == stream_id || stream_id == 0)
        {
            return self.pending.remove(pos).expect("position exists").into_frame();
        }
        Frame::new(FrameType::Pong, stream_id, Vec::new())
    }
}

#[derive(Debug)]
enum ServerEvent {
    Data {
        session_id: u64,
        stream_id: u32,
        data: Vec<u8>,
    },
    Fin {
        session_id: u64,
        stream_id: u32,
    },
    Rst {
        session_id: u64,
        stream_id: u32,
        reason: String,
    },
}

fn spawn_target_reader(session_id: u64, stream_id: u32, mut tcp: TcpStream, tx: Sender<ServerEvent>) {
    thread::spawn(move || {
        let mut buf = [0_u8; 900];
        loop {
            match tcp.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(ServerEvent::Fin { session_id, stream_id });
                    break;
                }
                Ok(n) => {
                    if tx
                        .send(ServerEvent::Data {
                            session_id,
                            stream_id,
                            data: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(err) => {
                    let _ = tx.send(ServerEvent::Rst {
                        session_id,
                        stream_id,
                        reason: err.to_string(),
                    });
                    break;
                }
            }
        }
    });
}

fn drain_events(rx: &Receiver<ServerEvent>, sessions: &mut HashMap<u64, SessionEntry>) {
    while let Ok(event) = rx.try_recv() {
        match event {
            ServerEvent::Data {
                session_id,
                stream_id,
                data,
            } => {
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(stream) = session.streams.get_mut(&stream_id) {
                        stream.bytes_down = stream.bytes_down.saturating_add(data.len() as u64);
                    }
                    session.pending.push_back(PendingFrame {
                        kind: FrameType::Data,
                        stream_id,
                        payload: data,
                    });
                }
            }
            ServerEvent::Fin {
                session_id,
                stream_id,
            } => {
                if let Some(session) = sessions.get_mut(&session_id) {
                    session.pending.push_back(PendingFrame {
                        kind: FrameType::Fin,
                        stream_id,
                        payload: Vec::new(),
                    });
                }
            }
            ServerEvent::Rst {
                session_id,
                stream_id,
                reason,
            } => {
                if let Some(session) = sessions.get_mut(&session_id) {
                    session.pending.push_back(PendingFrame {
                        kind: FrameType::Rst,
                        stream_id,
                        payload: reason.into_bytes(),
                    });
                }
            }
        }
    }
}

fn count_sessions_for_peer(sessions: &HashMap<u64, SessionEntry>, peer: IpAddr) -> usize {
    sessions.values().filter(|session| session.peer == peer).count()
}

fn handle_open(
    cfg: &ServerConfig,
    session_id: u64,
    stream_id: u32,
    payload: &[u8],
    session: &mut SessionEntry,
    event_tx: &Sender<ServerEvent>,
) -> Frame {
    let target = match std::str::from_utf8(payload) {
        Ok(target) => target.to_string(),
        Err(_) => {
            return Frame::new(FrameType::OpenErr, stream_id, b"target is not UTF-8".to_vec());
        }
    };

    let addr = match cfg.target_acl.resolve_allowed(&target) {
        Ok(addr) => addr,
        Err(err) => {
            warn!(peer = %session.peer, %target, error = %err, "target rejected by ACL");
            return Frame::new(FrameType::OpenErr, stream_id, err.to_string().into_bytes());
        }
    };

    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(tcp) => {
            if let Err(err) = tcp.set_nodelay(true) {
                debug!(error = %err, "failed to set TCP_NODELAY");
            }
            let reader = match tcp.try_clone() {
                Ok(reader) => reader,
                Err(err) => {
                    return Frame::new(FrameType::OpenErr, stream_id, err.to_string().into_bytes());
                }
            };
            spawn_target_reader(session_id, stream_id, reader, event_tx.clone());
            session.streams.insert(
                stream_id,
                StreamEntry {
                    tcp,
                    target: target.clone(),
                    opened_at: Instant::now(),
                    bytes_up: 0,
                    bytes_down: 0,
                },
            );
            info!(peer = %session.peer, %target, stream_id, "target opened");
            Frame::new(FrameType::OpenOk, stream_id, Vec::new())
        }
        Err(err) => {
            warn!(peer = %session.peer, %target, error = %err, "target connect failed");
            Frame::new(FrameType::OpenErr, stream_id, err.to_string().into_bytes())
        }
    }
}

fn handle_frame(
    cfg: &ServerConfig,
    opened: wire::OpenedFrame,
    peer: IpAddr,
    sessions: &mut HashMap<u64, SessionEntry>,
    event_tx: &Sender<ServerEvent>,
) -> Frame {
    let is_new_session = !sessions.contains_key(&opened.session_id);
    if is_new_session && count_sessions_for_peer(sessions, peer) >= cfg.max_sessions_per_peer {
        return Frame::new(FrameType::Rst, opened.frame.stream_id, b"peer session limit exceeded".to_vec());
    }

    let session = sessions
        .entry(opened.session_id)
        .or_insert_with(|| SessionEntry::new(peer));

    if let Some(cached) = session.reply_cache.get(&opened.packet_no) {
        return cached.clone();
    }

    let response = match opened.frame.kind {
        FrameType::Hello => Frame::new(FrameType::Pong, opened.frame.stream_id, b"ok".to_vec()),
        FrameType::Open => handle_open(
            cfg,
            opened.session_id,
            opened.frame.stream_id,
            &opened.frame.payload,
            session,
            event_tx,
        ),
        FrameType::Data => {
            if let Some(stream) = session.streams.get_mut(&opened.frame.stream_id) {
                match stream.tcp.write_all(&opened.frame.payload) {
                    Ok(()) => {
                        stream.bytes_up = stream.bytes_up.saturating_add(opened.frame.payload.len() as u64);
                        session.next_pending_or_pong(opened.frame.stream_id)
                    }
                    Err(err) => Frame::new(FrameType::Rst, opened.frame.stream_id, err.to_string().into_bytes()),
                }
            } else {
                Frame::new(FrameType::Rst, opened.frame.stream_id, b"unknown stream".to_vec())
            }
        }
        FrameType::Fin => {
            if let Some(stream) = session.streams.get_mut(&opened.frame.stream_id) {
                let _ = stream.tcp.shutdown(Shutdown::Write);
            }
            session.next_pending_or_pong(opened.frame.stream_id)
        }
        FrameType::Rst => {
            if let Some(stream) = session.streams.remove(&opened.frame.stream_id) {
                audit_stream_close(peer, opened.frame.stream_id, &stream, "reset by client");
            }
            Frame::new(FrameType::Pong, opened.frame.stream_id, Vec::new())
        }
        FrameType::Ping | FrameType::Pong | FrameType::OpenOk | FrameType::OpenErr => {
            session.next_pending_or_pong(opened.frame.stream_id)
        }
    };

    session.cache_reply(opened.packet_no, response.clone());
    response
}

fn audit_stream_close(peer: IpAddr, stream_id: u32, stream: &StreamEntry, reason: &str) {
    info!(
        peer = %peer,
        stream_id,
        target = %stream.target,
        bytes_up = stream.bytes_up,
        bytes_down = stream.bytes_down,
        duration_ms = stream.opened_at.elapsed().as_millis(),
        close_reason = reason,
        "audit stream close"
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let cfg = load_config(&cli)?;
    init_logging(&cfg.log_level);

    let socket = IcmpSocket::raw()?;
    socket.set_read_timeout(Some(cfg.read_timeout))?;
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = Arc::clone(&shutdown);
        ctrlc::set_handler(move || shutdown.store(true, Ordering::SeqCst))?;
    }

    let (event_tx, event_rx) = mpsc::channel::<ServerEvent>();
    let mut sessions: HashMap<u64, SessionEntry> = HashMap::new();
    let mut rate_limiters: PeerRateLimiters = HashMap::new();
    let mut buf = vec![0_u8; 4096];

    info!("server ready; raw ICMP socket opened");
    while !shutdown.load(Ordering::SeqCst) {
        drain_events(&event_rx, &mut sessions);
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let peer = IpAddr::V4(src);
                if !cfg.peer_acl.allows(peer) {
                    warn!(%peer, "peer rejected by ACL");
                    continue;
                }
                let limiter = rate_limiters
                    .entry(peer)
                    .or_insert_with(|| RateLimiter::new(cfg.rate_limits.clone(), Instant::now()));
                if !limiter.allow(Instant::now(), n as u64) {
                    warn!(%peer, "peer rate limited");
                    continue;
                }

                let echo = match parse_echo_packet(&buf[..n]) {
                    Ok(echo) => echo,
                    Err(err) => {
                        debug!(%peer, error = %err, "invalid ICMP packet");
                        continue;
                    }
                };
                if echo.kind != ICMP_ECHO_REQUEST {
                    continue;
                }
                let opened = match wire::open(&cfg.psk, &cfg.salt, &echo.payload) {
                    Ok(opened) => opened,
                    Err(err) => {
                        warn!(%peer, error = %err, "authentication or frame decode failed");
                        continue;
                    }
                };
                let packet_no = opened.packet_no;
                let session_id = opened.session_id;
                let response = handle_frame(&cfg, opened, peer, &mut sessions, &event_tx);
                let sealed = match wire::seal(&cfg.psk, &cfg.salt, session_id, packet_no, &response) {
                    Ok(sealed) => sealed,
                    Err(err) => {
                        error!(%peer, error = %err, "failed to seal response");
                        continue;
                    }
                };
                let reply = build_echo_reply(echo.identifier, echo.sequence, &sealed);
                if let Err(err) = socket.send_to(src, &reply) {
                    warn!(%peer, error = %err, "failed to send ICMP reply");
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(err) => {
                error!(error = %err, "raw ICMP receive failed");
                break;
            }
        }
    }

    for (_sid, session) in sessions.drain() {
        for (stream_id, stream) in session.streams {
            audit_stream_close(session.peer, stream_id, &stream, "server shutdown");
            let _ = stream.tcp.shutdown(Shutdown::Both);
        }
        info!(peer = %session.peer, age_ms = session.created_at.elapsed().as_millis(), "session closed");
    }
    info!("server shutting down");
    Ok(())
}
