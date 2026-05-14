use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
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
use icmp2tunnel::wire::{self, Direction, Frame, FrameType};

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
    connect_timeout_ms: Option<u64>,
    session_idle_timeout_ms: Option<u64>,
    rate_limiter_ttl_ms: Option<u64>,
    max_streams_per_session: Option<usize>,
    max_pending_frames_per_session: Option<usize>,
    max_pending_bytes_per_session: Option<usize>,
    event_queue_capacity: Option<usize>,
    max_rate_limiter_entries: Option<usize>,
    allow_private_targets: Option<bool>,
}

#[derive(Debug, Clone)]
struct ServerConfig {
    psk: Vec<u8>,
    salt: Vec<u8>,
    log_level: String,
    peer_acl: PeerAcl,
    target_acl: TargetAcl,
    max_sessions_per_peer: usize,
    max_streams_per_session: usize,
    max_pending_frames_per_session: usize,
    max_pending_bytes_per_session: usize,
    event_queue_capacity: usize,
    max_rate_limiter_entries: usize,
    rate_limits: RateLimits,
    read_timeout: Duration,
    connect_timeout: Duration,
    session_idle_timeout: Duration,
    rate_limiter_ttl: Duration,
}

fn load_config(cli: &Cli) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(&cli.config)?;
    let file: FileConfig = toml::from_str(&text)?;
    let peer_acl = PeerAcl::parse(&file.peer_acl)?;
    let target_acl = TargetAcl::parse_with_options(
        &file.target_acl,
        !file.allow_private_targets.unwrap_or(false),
    )?;
    let cfg = ServerConfig {
        psk: file.psk.into_bytes(),
        salt: file.salt.unwrap_or_else(|| "icmp2tunnel-v1".to_string()).into_bytes(),
        log_level: file.log_level.unwrap_or_else(|| "info".to_string()),
        peer_acl,
        target_acl,
        max_sessions_per_peer: file.max_sessions_per_peer.unwrap_or(8),
        max_streams_per_session: file.max_streams_per_session.unwrap_or(64),
        max_pending_frames_per_session: file.max_pending_frames_per_session.unwrap_or(512),
        max_pending_bytes_per_session: file.max_pending_bytes_per_session.unwrap_or(524_288),
        event_queue_capacity: file.event_queue_capacity.unwrap_or(4096),
        max_rate_limiter_entries: file.max_rate_limiter_entries.unwrap_or(4096),
        rate_limits: RateLimits {
            packets_per_sec: file.packet_per_sec.unwrap_or(256),
            bytes_per_sec: file.byte_per_sec.unwrap_or(262_144),
        },
        read_timeout: Duration::from_millis(file.read_timeout_ms.unwrap_or(250)),
        connect_timeout: Duration::from_millis(file.connect_timeout_ms.unwrap_or(5000)),
        session_idle_timeout: Duration::from_millis(file.session_idle_timeout_ms.unwrap_or(300_000)),
        rate_limiter_ttl: Duration::from_millis(file.rate_limiter_ttl_ms.unwrap_or(300_000)),
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
    if cfg.max_streams_per_session == 0
        || cfg.max_pending_frames_per_session == 0
        || cfg.max_pending_bytes_per_session == 0
        || cfg.event_queue_capacity == 0
        || cfg.max_rate_limiter_entries == 0
    {
        return Err("stream, pending, and event queue limits must be greater than 0".to_string());
    }
    if cfg.rate_limits.packets_per_sec == 0 || cfg.rate_limits.bytes_per_sec == 0 {
        return Err("rate limits must be greater than 0".to_string());
    }
    if cfg.read_timeout.is_zero()
        || cfg.connect_timeout.is_zero()
        || cfg.session_idle_timeout.is_zero()
        || cfg.rate_limiter_ttl.is_zero()
    {
        return Err("timeouts must be greater than 0".to_string());
    }
    Ok(())
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .expect("default tracing filter parses");
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[cfg(unix)]
fn drop_privileges_if_root() -> io::Result<()> {
    unsafe {
        if libc::geteuid() != 0 {
            return Ok(());
        }
        let user = std::ffi::CString::new("nobody")
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid user name"))?;
        let passwd = libc::getpwnam(user.as_ptr());
        if passwd.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "cannot drop privileges: user nobody not found",
            ));
        }
        let uid = (*passwd).pw_uid;
        let gid = (*passwd).pw_gid;
        let _ = libc::setgroups(0, std::ptr::null());
        if libc::setgid(gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::geteuid() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "failed to drop root privileges",
            ));
        }
        Ok(())
    }
}

#[cfg(not(unix))]
fn drop_privileges_if_root() -> io::Result<()> {
    Ok(())
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
    opening_streams: HashMap<u32, Instant>,
    pending: VecDeque<PendingFrame>,
    pending_bytes: usize,
    reply_cache: HashMap<u64, Frame>,
    highest_packet_no: u64,
    created_at: Instant,
    last_seen: Instant,
}

impl SessionEntry {
    fn new(peer: IpAddr, now: Instant) -> Self {
        Self {
            peer,
            streams: HashMap::new(),
            opening_streams: HashMap::new(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            reply_cache: HashMap::new(),
            highest_packet_no: 0,
            created_at: now,
            last_seen: now,
        }
    }

    fn cache_reply(&mut self, packet_no: u64, frame: Frame) {
        self.reply_cache.insert(packet_no, frame);
        self.highest_packet_no = self.highest_packet_no.max(packet_no);
        if self.reply_cache.len() > 1024 {
            let min_key = self.reply_cache.keys().min().copied();
            if let Some(key) = min_key {
                self.reply_cache.remove(&key);
            }
        }
    }

    fn total_stream_slots(&self) -> usize {
        self.streams.len().saturating_add(self.opening_streams.len())
    }

    fn queue_pending(
        &mut self,
        frame: PendingFrame,
        max_frames: usize,
        max_bytes: usize,
    ) -> Result<(), PendingFrame> {
        let frame_bytes = frame.payload.len();
        if self.pending.len() >= max_frames
            || self.pending_bytes.saturating_add(frame_bytes) > max_bytes
        {
            return Err(frame);
        }
        self.pending_bytes = self.pending_bytes.saturating_add(frame_bytes);
        self.pending.push_back(frame);
        Ok(())
    }

    fn drop_pending_for_stream(&mut self, stream_id: u32) {
        let mut retained = VecDeque::with_capacity(self.pending.len());
        while let Some(frame) = self.pending.pop_front() {
            if frame.stream_id == stream_id {
                self.pending_bytes = self.pending_bytes.saturating_sub(frame.payload.len());
            } else {
                retained.push_back(frame);
            }
        }
        self.pending = retained;
    }

    fn next_pending_or_pong(&mut self, stream_id: u32) -> Frame {
        if let Some(pos) = self
            .pending
            .iter()
            .position(|frame| frame.stream_id == stream_id || stream_id == 0)
        {
            let frame = self.pending.remove(pos).expect("position exists");
            self.pending_bytes = self.pending_bytes.saturating_sub(frame.payload.len());
            return frame.into_frame();
        }
        Frame::new(FrameType::Pong, stream_id, Vec::new())
    }
}

#[derive(Debug)]
enum ServerEvent {
    OpenResult {
        session_id: u64,
        stream_id: u32,
        result: Result<OpenedStream, String>,
    },
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

#[derive(Debug)]
struct OpenedStream {
    tcp: TcpStream,
    target: String,
}

fn spawn_target_reader(session_id: u64, stream_id: u32, mut tcp: TcpStream, tx: SyncSender<ServerEvent>) {
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

fn queue_pending_frame(cfg: &ServerConfig, session: &mut SessionEntry, frame: PendingFrame) -> bool {
    session
        .queue_pending(
            frame,
            cfg.max_pending_frames_per_session,
            cfg.max_pending_bytes_per_session,
        )
        .is_ok()
}

fn close_stream_for_pending_overflow(
    cfg: &ServerConfig,
    session: &mut SessionEntry,
    stream_id: u32,
) {
    session.drop_pending_for_stream(stream_id);
    if let Some(stream) = session.streams.remove(&stream_id) {
        audit_stream_close(session.peer, stream_id, &stream, "pending queue overflow");
        let _ = stream.tcp.shutdown(Shutdown::Both);
    }
    let _ = queue_pending_frame(
        cfg,
        session,
        PendingFrame {
            kind: FrameType::Rst,
            stream_id,
            payload: b"pending queue overflow".to_vec(),
        },
    );
}

fn drain_events(
    cfg: &ServerConfig,
    rx: &Receiver<ServerEvent>,
    sessions: &mut HashMap<u64, SessionEntry>,
    event_tx: &SyncSender<ServerEvent>,
) {
    while let Ok(event) = rx.try_recv() {
        match event {
            ServerEvent::OpenResult {
                session_id,
                stream_id,
                result,
            } => {
                let Some(session) = sessions.get_mut(&session_id) else {
                    if let Ok(opened) = result {
                        let _ = opened.tcp.shutdown(Shutdown::Both);
                    }
                    continue;
                };
                if session.opening_streams.remove(&stream_id).is_none() {
                    if let Ok(opened) = result {
                        let _ = opened.tcp.shutdown(Shutdown::Both);
                    }
                    continue;
                }
                match result {
                    Ok(opened) => {
                        let reader = match opened.tcp.try_clone() {
                            Ok(reader) => reader,
                            Err(err) => {
                                let _ = queue_pending_frame(
                                    cfg,
                                    session,
                                    PendingFrame {
                                        kind: FrameType::OpenErr,
                                        stream_id,
                                        payload: err.to_string().into_bytes(),
                                    },
                                );
                                continue;
                            }
                        };
                        session.streams.insert(
                            stream_id,
                            StreamEntry {
                                tcp: opened.tcp,
                                target: opened.target.clone(),
                                opened_at: Instant::now(),
                                bytes_up: 0,
                                bytes_down: 0,
                            },
                        );
                        spawn_target_reader(session_id, stream_id, reader, event_tx.clone());
                        info!(
                            peer = %session.peer,
                            target = %opened.target,
                            stream_id,
                            "target opened"
                        );
                        if !queue_pending_frame(
                            cfg,
                            session,
                            PendingFrame {
                                kind: FrameType::OpenOk,
                                stream_id,
                                payload: Vec::new(),
                            },
                        ) {
                            close_stream_for_pending_overflow(cfg, session, stream_id);
                        }
                    }
                    Err(reason) => {
                        let _ = queue_pending_frame(
                            cfg,
                            session,
                            PendingFrame {
                                kind: FrameType::OpenErr,
                                stream_id,
                                payload: reason.into_bytes(),
                            },
                        );
                    }
                }
            }
            ServerEvent::Data {
                session_id,
                stream_id,
                data,
            } => {
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(stream) = session.streams.get_mut(&stream_id) {
                        stream.bytes_down = stream.bytes_down.saturating_add(data.len() as u64);
                    }
                    if !queue_pending_frame(
                        cfg,
                        session,
                        PendingFrame {
                            kind: FrameType::Data,
                            stream_id,
                            payload: data,
                        },
                    ) {
                        close_stream_for_pending_overflow(cfg, session, stream_id);
                    }
                }
            }
            ServerEvent::Fin {
                session_id,
                stream_id,
            } => {
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(stream) = session.streams.remove(&stream_id) {
                        audit_stream_close(session.peer, stream_id, &stream, "target closed");
                        let _ = stream.tcp.shutdown(Shutdown::Both);
                    }
                    let _ = queue_pending_frame(
                        cfg,
                        session,
                        PendingFrame {
                            kind: FrameType::Fin,
                            stream_id,
                            payload: Vec::new(),
                        },
                    );
                }
            }
            ServerEvent::Rst {
                session_id,
                stream_id,
                reason,
            } => {
                if let Some(session) = sessions.get_mut(&session_id) {
                    if let Some(stream) = session.streams.remove(&stream_id) {
                        audit_stream_close(session.peer, stream_id, &stream, "target reader error");
                        let _ = stream.tcp.shutdown(Shutdown::Both);
                    }
                    let _ = queue_pending_frame(
                        cfg,
                        session,
                        PendingFrame {
                            kind: FrameType::Rst,
                            stream_id,
                            payload: reason.into_bytes(),
                        },
                    );
                }
            }
        }
    }
}

fn count_sessions_for_peer(sessions: &HashMap<u64, SessionEntry>, peer: IpAddr) -> usize {
    sessions.values().filter(|session| session.peer == peer).count()
}

fn spawn_target_connector(
    cfg: ServerConfig,
    session_id: u64,
    stream_id: u32,
    target: String,
    peer: IpAddr,
    event_tx: SyncSender<ServerEvent>,
) {
    thread::spawn(move || {
        let result = match cfg.target_acl.resolve_allowed(&target) {
            Ok(addr) => match TcpStream::connect_timeout(&addr, cfg.connect_timeout) {
                Ok(tcp) => {
                    if let Err(err) = tcp.set_nodelay(true) {
                        debug!(error = %err, "failed to set TCP_NODELAY");
                    }
                    Ok(OpenedStream { tcp, target })
                }
                Err(err) => {
                    warn!(%peer, %target, error = %err, "target connect failed");
                    Err(err.to_string())
                }
            },
            Err(err) => {
                warn!(%peer, %target, error = %err, "target rejected by ACL");
                Err(err.to_string())
            }
        };
        let _ = event_tx.send(ServerEvent::OpenResult {
            session_id,
            stream_id,
            result,
        });
    });
}

fn handle_open(
    cfg: &ServerConfig,
    session_id: u64,
    stream_id: u32,
    payload: &[u8],
    session: &mut SessionEntry,
    event_tx: &SyncSender<ServerEvent>,
) -> Frame {
    let target = match std::str::from_utf8(payload) {
        Ok(target) => target.to_string(),
        Err(_) => {
            return Frame::new(FrameType::OpenErr, stream_id, b"target is not UTF-8".to_vec());
        }
    };
    if target.len() > 512 {
        return Frame::new(FrameType::OpenErr, stream_id, b"target is too long".to_vec());
    }

    if session.streams.contains_key(&stream_id) {
        return Frame::new(FrameType::OpenOk, stream_id, Vec::new());
    }
    if session.opening_streams.contains_key(&stream_id) {
        return Frame::new(FrameType::Pong, stream_id, Vec::new());
    }
    if session.total_stream_slots() >= cfg.max_streams_per_session {
        return Frame::new(FrameType::OpenErr, stream_id, b"stream limit exceeded".to_vec());
    }

    session.opening_streams.insert(stream_id, Instant::now());
    spawn_target_connector(
        cfg.clone(),
        session_id,
        stream_id,
        target,
        session.peer,
        event_tx.clone(),
    );
    Frame::new(FrameType::Pong, stream_id, Vec::new())
}

fn handle_frame(
    cfg: &ServerConfig,
    opened: wire::OpenedFrame,
    peer: IpAddr,
    sessions: &mut HashMap<u64, SessionEntry>,
    event_tx: &SyncSender<ServerEvent>,
) -> Frame {
    let now = Instant::now();
    if let Some(session) = sessions.get(&opened.session_id) {
        if session.peer != peer {
            warn!(
                original_peer = %session.peer,
                %peer,
                session_id = opened.session_id,
                "rejecting packet for session owned by another peer"
            );
            return Frame::new(FrameType::Rst, opened.frame.stream_id, b"session peer mismatch".to_vec());
        }
    }

    let is_new_session = !sessions.contains_key(&opened.session_id);
    if is_new_session && count_sessions_for_peer(sessions, peer) >= cfg.max_sessions_per_peer {
        return Frame::new(FrameType::Rst, opened.frame.stream_id, b"peer session limit exceeded".to_vec());
    }

    let session = sessions
        .entry(opened.session_id)
        .or_insert_with(|| SessionEntry::new(peer, now));
    session.last_seen = now;

    if let Some(cached) = session.reply_cache.get(&opened.packet_no) {
        return cached.clone();
    }
    if opened.packet_no == 0 || opened.packet_no <= session.highest_packet_no {
        warn!(
            %peer,
            session_id = opened.session_id,
            packet_no = opened.packet_no,
            highest_packet_no = session.highest_packet_no,
            "rejecting replayed or stale packet"
        );
        return Frame::new(FrameType::Rst, opened.frame.stream_id, b"replayed packet".to_vec());
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
                    Err(err) => {
                        if let Some(stream) = session.streams.remove(&opened.frame.stream_id) {
                            audit_stream_close(peer, opened.frame.stream_id, &stream, "target write error");
                            let _ = stream.tcp.shutdown(Shutdown::Both);
                        }
                        Frame::new(FrameType::Rst, opened.frame.stream_id, err.to_string().into_bytes())
                    }
                }
            } else if session.opening_streams.contains_key(&opened.frame.stream_id) {
                Frame::new(FrameType::Pong, opened.frame.stream_id, Vec::new())
            } else {
                Frame::new(FrameType::Rst, opened.frame.stream_id, b"unknown stream".to_vec())
            }
        }
        FrameType::Fin => {
            if let Some(stream) = session.streams.remove(&opened.frame.stream_id) {
                audit_stream_close(peer, opened.frame.stream_id, &stream, "fin by client");
                let _ = stream.tcp.shutdown(Shutdown::Both);
            }
            session.drop_pending_for_stream(opened.frame.stream_id);
            session.next_pending_or_pong(opened.frame.stream_id)
        }
        FrameType::Rst => {
            if let Some(stream) = session.streams.remove(&opened.frame.stream_id) {
                audit_stream_close(peer, opened.frame.stream_id, &stream, "reset by client");
                let _ = stream.tcp.shutdown(Shutdown::Both);
            }
            session.opening_streams.remove(&opened.frame.stream_id);
            session.drop_pending_for_stream(opened.frame.stream_id);
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

fn cleanup_sessions(
    sessions: &mut HashMap<u64, SessionEntry>,
    now: Instant,
    idle_timeout: Duration,
) {
    let expired: Vec<u64> = sessions
        .iter()
        .filter_map(|(session_id, session)| {
            if now.duration_since(session.last_seen) >= idle_timeout {
                Some(*session_id)
            } else {
                None
            }
        })
        .collect();

    for session_id in expired {
        if let Some(session) = sessions.remove(&session_id) {
            for (stream_id, stream) in session.streams {
                audit_stream_close(session.peer, stream_id, &stream, "session idle timeout");
                let _ = stream.tcp.shutdown(Shutdown::Both);
            }
            info!(
                peer = %session.peer,
                session_id,
                age_ms = session.created_at.elapsed().as_millis(),
                "session expired"
            );
        }
    }
}

fn cleanup_rate_limiters(
    rate_limiters: &mut PeerRateLimiters,
    now: Instant,
    ttl: Duration,
) {
    rate_limiters.retain(|_, limiter| now.duration_since(limiter.last_seen()) < ttl);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let cfg = load_config(&cli)?;
    init_logging(&cfg.log_level);

    let socket = IcmpSocket::raw()?;
    socket.set_read_timeout(Some(cfg.read_timeout))?;
    drop_privileges_if_root()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = Arc::clone(&shutdown);
        ctrlc::set_handler(move || shutdown.store(true, Ordering::SeqCst))?;
    }

    let (event_tx, event_rx) = mpsc::sync_channel::<ServerEvent>(cfg.event_queue_capacity);
    let mut sessions: HashMap<u64, SessionEntry> = HashMap::new();
    let mut rate_limiters: PeerRateLimiters = HashMap::new();
    let mut buf = vec![0_u8; 4096];
    let mut last_cleanup = Instant::now();

    info!("server ready; raw ICMP socket opened");
    while !shutdown.load(Ordering::SeqCst) {
        drain_events(&cfg, &event_rx, &mut sessions, &event_tx);
        let now = Instant::now();
        if now.duration_since(last_cleanup) >= Duration::from_secs(1) {
            cleanup_sessions(&mut sessions, now, cfg.session_idle_timeout);
            cleanup_rate_limiters(&mut rate_limiters, now, cfg.rate_limiter_ttl);
            last_cleanup = now;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let peer = IpAddr::V4(src);
                if !cfg.peer_acl.allows(peer) {
                    warn!(%peer, "peer rejected by ACL");
                    continue;
                }
                if !rate_limiters.contains_key(&peer)
                    && rate_limiters.len() >= cfg.max_rate_limiter_entries
                {
                    warn!(%peer, "rate limiter table full");
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
                let opened = match wire::open(
                    &cfg.psk,
                    &cfg.salt,
                    Direction::ClientToServer,
                    &echo.payload,
                ) {
                    Ok(opened) => opened,
                    Err(err) => {
                        warn!(%peer, error = %err, "authentication or frame decode failed");
                        continue;
                    }
                };
                let packet_no = opened.packet_no;
                let session_id = opened.session_id;
                let response = handle_frame(&cfg, opened, peer, &mut sessions, &event_tx);
                let sealed = match wire::seal(
                    &cfg.psk,
                    &cfg.salt,
                    Direction::ServerToClient,
                    session_id,
                    packet_no,
                    &response,
                ) {
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
