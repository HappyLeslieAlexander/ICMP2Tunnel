use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clap::Parser;
use rand::RngCore;
use serde::Deserialize;
use tracing::{error, info, warn};

use icmp2tunnel::icmp::{build_echo_request, parse_echo_packet, IcmpSocket, ICMP_ECHO_REPLY};
use icmp2tunnel::socks::{
    bind_listener, default_loopback_bind_addr, negotiate_no_auth, parse_request, write_reply, Command,
};
use icmp2tunnel::wire::{self, Frame, FrameType};

#[derive(Debug, Parser)]
#[command(name = "icmp2tunnel-client", about = "Authenticated SOCKS5-over-ICMP client")]
struct Cli {
    #[arg(short, long, default_value = "examples/client.toml")]
    config: PathBuf,
    #[arg(long)]
    allow_non_loopback: bool,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    listen_addr: SocketAddr,
    server_addr: Ipv4Addr,
    psk: String,
    salt: Option<String>,
    log_level: Option<String>,
    allow_non_loopback: Option<bool>,
    poll_interval_ms: Option<u64>,
    request_timeout_ms: Option<u64>,
    retries: Option<u8>,
    max_payload: Option<usize>,
    icmp_identifier: Option<u16>,
}

#[derive(Debug, Clone)]
struct ClientConfig {
    listen_addr: SocketAddr,
    server_addr: Ipv4Addr,
    psk: Vec<u8>,
    salt: Vec<u8>,
    log_level: String,
    allow_non_loopback: bool,
    poll_interval: Duration,
    request_timeout: Duration,
    retries: u8,
    max_payload: usize,
    icmp_identifier: u16,
}

fn load_config(cli: &Cli) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(&cli.config)?;
    let file: FileConfig = toml::from_str(&text)?;
    let allow_non_loopback = file.allow_non_loopback.unwrap_or(cli.allow_non_loopback);
    let icmp_identifier = file
        .icmp_identifier
        .unwrap_or_else(|| (std::process::id() & 0xffff) as u16);
    Ok(ClientConfig {
        listen_addr: file.listen_addr,
        server_addr: file.server_addr,
        psk: file.psk.into_bytes(),
        salt: file
            .salt
            .unwrap_or_else(|| "icmp2tunnel-v1".to_string())
            .into_bytes(),
        log_level: file.log_level.unwrap_or_else(|| "info".to_string()),
        allow_non_loopback,
        poll_interval: Duration::from_millis(file.poll_interval_ms.unwrap_or(20)),
        request_timeout: Duration::from_millis(file.request_timeout_ms.unwrap_or(1000)),
        retries: file.retries.unwrap_or(3),
        max_payload: file.max_payload.unwrap_or(900).clamp(64, 1400),
        icmp_identifier,
    })
}

fn validate_config(cfg: &ClientConfig) -> Result<(), String> {
    if cfg.psk.len() < 16 {
        return Err("PSK must be at least 16 bytes".to_string());
    }
    let loopback = match cfg.listen_addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if !loopback && !cfg.allow_non_loopback {
        return Err("refusing non-loopback SOCKS listen address without --allow-non-loopback".to_string());
    }
    Ok(())
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .expect("default tracing filter parses");
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[derive(Debug)]
struct TunnelClient {
    socket: Mutex<IcmpSocket>,
    server_addr: Ipv4Addr,
    psk: Vec<u8>,
    salt: Vec<u8>,
    session_id: u64,
    next_packet: AtomicU64,
    next_stream: AtomicU32,
    icmp_identifier: u16,
    timeout: Duration,
    retries: u8,
}

impl TunnelClient {
    fn new(cfg: &ClientConfig) -> io::Result<Self> {
        let mut rng = rand::thread_rng();
        let session_id = rng.next_u64();
        let socket = IcmpSocket::raw()?;
        socket.set_read_timeout(Some(cfg.request_timeout))?;
        Ok(Self {
            socket: Mutex::new(socket),
            server_addr: cfg.server_addr,
            psk: cfg.psk.clone(),
            salt: cfg.salt.clone(),
            session_id,
            next_packet: AtomicU64::new(1),
            next_stream: AtomicU32::new(1),
            icmp_identifier: cfg.icmp_identifier,
            timeout: cfg.request_timeout,
            retries: cfg.retries,
        })
    }

    fn next_stream_id(&self) -> u32 {
        self.next_stream.fetch_add(1, Ordering::SeqCst)
    }

    fn exchange(&self, frame: Frame) -> io::Result<Frame> {
        let packet_no = self.next_packet.fetch_add(1, Ordering::SeqCst);
        let sealed = wire::seal(&self.psk, &self.salt, self.session_id, packet_no, &frame)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let icmp_seq = (packet_no & 0xffff) as u16;
        let request = build_echo_request(self.icmp_identifier, icmp_seq, &sealed);
        let mut buf = vec![0_u8; 2048];
        let socket = self
            .socket
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "ICMP socket lock poisoned"))?;
        socket.set_read_timeout(Some(self.timeout))?;

        for attempt in 0..=self.retries {
            socket.send_to(self.server_addr, &request)?;
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((n, _src)) => {
                        let echo = match parse_echo_packet(&buf[..n]) {
                            Ok(echo) => echo,
                            Err(_) => continue,
                        };
                        if echo.kind != ICMP_ECHO_REPLY
                            || echo.identifier != self.icmp_identifier
                            || echo.sequence != icmp_seq
                        {
                            continue;
                        }
                        let opened = wire::open(&self.psk, &self.salt, &echo.payload)
                            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
                        if opened.session_id == self.session_id && opened.packet_no == packet_no {
                            return Ok(opened.frame);
                        }
                    }
                    Err(err)
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::TimedOut =>
                    {
                        if attempt == self.retries {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "ICMP exchange timed out",
                            ));
                        }
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "ICMP exchange timed out"))
    }
}

fn process_reply(local: &mut TcpStream, reply: Frame) -> io::Result<bool> {
    match reply.kind {
        FrameType::Data => {
            local.write_all(&reply.payload)?;
            Ok(true)
        }
        FrameType::Fin => Ok(false),
        FrameType::Rst | FrameType::OpenErr => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            String::from_utf8_lossy(&reply.payload).to_string(),
        )),
        FrameType::Pong | FrameType::Ping | FrameType::OpenOk => Ok(true),
        FrameType::Hello | FrameType::Open => Ok(true),
    }
}

fn handle_socks_client(mut local: TcpStream, tunnel: Arc<TunnelClient>, cfg: ClientConfig) -> io::Result<()> {
    negotiate_no_auth(&mut local).map_err(io::Error::other)?;
    let req = parse_request(&mut local).map_err(io::Error::other)?;
    if req.command != Command::Connect {
        write_reply(&mut local, 0x07, default_loopback_bind_addr(0)).map_err(io::Error::other)?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only SOCKS5 CONNECT is supported"));
    }

    let stream_id = tunnel.next_stream_id();
    let target = req.target_string();
    info!(stream_id, %target, "opening tunnel stream");
    let open_reply = tunnel.exchange(Frame::new(FrameType::Open, stream_id, target.as_bytes().to_vec()))?;
    match open_reply.kind {
        FrameType::OpenOk => {
            write_reply(&mut local, 0x00, default_loopback_bind_addr(0)).map_err(io::Error::other)?;
        }
        FrameType::OpenErr | FrameType::Rst => {
            warn!(stream_id, reason = %String::from_utf8_lossy(&open_reply.payload), "server rejected stream");
            write_reply(&mut local, 0x05, default_loopback_bind_addr(0)).map_err(io::Error::other)?;
            return Ok(());
        }
        _ => {
            write_reply(&mut local, 0x01, default_loopback_bind_addr(0)).map_err(io::Error::other)?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected open reply"));
        }
    }

    local.set_read_timeout(Some(cfg.poll_interval))?;
    let mut buf = vec![0_u8; cfg.max_payload];
    loop {
        match local.read(&mut buf) {
            Ok(0) => {
                let _ = tunnel.exchange(Frame::new(FrameType::Fin, stream_id, Vec::new()));
                break;
            }
            Ok(n) => {
                let reply = tunnel.exchange(Frame::new(FrameType::Data, stream_id, buf[..n].to_vec()))?;
                if !process_reply(&mut local, reply)? {
                    break;
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut =>
            {
                let reply = tunnel.exchange(Frame::new(FrameType::Ping, stream_id, Vec::new()))?;
                if !process_reply(&mut local, reply)? {
                    break;
                }
            }
            Err(err) => {
                let _ = tunnel.exchange(Frame::new(FrameType::Rst, stream_id, err.to_string().into_bytes()));
                return Err(err);
            }
        }
    }

    let _ = local.shutdown(Shutdown::Both);
    info!(stream_id, "stream closed");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let cfg = load_config(&cli)?;
    init_logging(&cfg.log_level);
    validate_config(&cfg)?;

    let listener = bind_listener(Some(cfg.listen_addr))?;
    info!(listen_addr = %listener.local_addr()?, server_addr = %cfg.server_addr, "client ready");
    let tunnel = Arc::new(TunnelClient::new(&cfg)?);
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = Arc::clone(&shutdown);
        ctrlc::set_handler(move || shutdown.store(true, Ordering::SeqCst))?;
    }
    listener.set_nonblocking(true)?;

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                let tunnel = Arc::clone(&tunnel);
                let cfg = cfg.clone();
                info!(%peer, "accepted local SOCKS connection");
                thread::spawn(move || {
                    if let Err(err) = handle_socks_client(stream, tunnel, cfg) {
                        warn!(error = %err, "SOCKS connection failed");
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(25)),
            Err(err) => {
                error!(error = %err, "accept failed");
                break;
            }
        }
    }

    info!("client shutting down");
    Ok(())
}
