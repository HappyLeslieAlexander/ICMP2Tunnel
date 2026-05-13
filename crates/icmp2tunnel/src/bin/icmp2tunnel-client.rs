use std::fs;
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::Parser;
use icmp2tunnel_socks::{
    bind_listener, default_loopback_bind_addr, negotiate_no_auth, parse_request, write_reply,
    Command,
};
use serde::Deserialize;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "icmp2tunnel-client", about = "ICMP2Tunnel SOCKS5 client")]
struct Cli {
    #[arg(short, long, default_value = "examples/client.toml")]
    config: PathBuf,
    #[arg(long)]
    allow_non_loopback: bool,
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    listen_addr: Option<SocketAddr>,
    server_addr: Option<String>,
    psk: Option<String>,
    log_level: Option<String>,
    allow_non_loopback: Option<bool>,
}

#[derive(Debug)]
struct ClientConfig {
    listen_addr: SocketAddr,
    server_addr: String,
    psk: String,
    log_level: String,
    allow_non_loopback: bool,
}

fn load_file_config(path: &PathBuf) -> Result<FileConfig, io::Error> {
    let text = fs::read_to_string(path)?;
    toml::from_str::<FileConfig>(&text)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn env_or<T>(key: &str, fallback: Option<T>) -> Option<T>
where
    T: std::str::FromStr,
{
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .or(fallback)
}

fn build_config(cli: &Cli, file_cfg: FileConfig) -> Result<ClientConfig, String> {
    let listen_addr = env_or("I2T_CLIENT_LISTEN_ADDR", file_cfg.listen_addr)
        .unwrap_or_else(|| default_loopback_bind_addr(1080));
    let server_addr = std::env::var("I2T_CLIENT_SERVER_ADDR")
        .ok()
        .or(file_cfg.server_addr)
        .ok_or_else(|| {
            "missing server address: set in config or I2T_CLIENT_SERVER_ADDR".to_string()
        })?;
    let psk = std::env::var("I2T_CLIENT_PSK")
        .ok()
        .or(file_cfg.psk)
        .ok_or_else(|| "missing PSK: set in config or I2T_CLIENT_PSK".to_string())?;
    let log_level = std::env::var("I2T_CLIENT_LOG_LEVEL")
        .ok()
        .or(file_cfg.log_level)
        .unwrap_or_else(|| "info".to_string());
    let allow_non_loopback = env_or("I2T_CLIENT_ALLOW_NON_LOOPBACK", file_cfg.allow_non_loopback)
        .unwrap_or(cli.allow_non_loopback);

    Ok(ClientConfig {
        listen_addr,
        server_addr,
        psk,
        log_level,
        allow_non_loopback,
    })
}

fn validate_config(cfg: &ClientConfig) -> Result<(), String> {
    let is_loopback = match cfg.listen_addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if !is_loopback && !cfg.allow_non_loopback {
        return Err(
            "refusing non-loopback listen address without --allow-non-loopback".to_string(),
        );
    }
    if cfg.psk.trim().is_empty() {
        return Err("PSK must not be empty".to_string());
    }
    Ok(())
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .expect("default log filter should parse");
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn relay_bidirectional(left: TcpStream, right: TcpStream) -> io::Result<()> {
    let mut left_read = left.try_clone()?;
    let mut right_write = right.try_clone()?;
    let t1 = thread::spawn(move || io::copy(&mut left_read, &mut right_write));

    let mut right_read = right;
    let mut left_write = left;
    let t2 = thread::spawn(move || io::copy(&mut right_read, &mut left_write));

    let _ = t1
        .join()
        .map_err(|_| io::Error::other("relay thread panic"))??;
    let _ = t2
        .join()
        .map_err(|_| io::Error::other("relay thread panic"))??;
    Ok(())
}

fn handle_client(mut stream: TcpStream, tunnel_server_addr: &str) -> io::Result<()> {
    negotiate_no_auth(&mut stream).map_err(io::Error::other)?;
    let req = parse_request(&mut stream).map_err(io::Error::other)?;

    if req.command != Command::Connect {
        write_reply(&mut stream, 0x07, default_loopback_bind_addr(0)).map_err(io::Error::other)?;
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "unsupported SOCKS command",
        ));
    }

    let target = format!(
        "{}:{}",
        match req.target {
            icmp2tunnel_socks::TargetAddr::Ip(ip) => ip.to_string(),
            icmp2tunnel_socks::TargetAddr::Domain(domain) => domain,
        },
        req.port
    );
    info!(%target, %tunnel_server_addr, "opening stream for CONNECT");

    let upstream = TcpStream::connect(&target)?;
    write_reply(&mut stream, 0x00, upstream.local_addr()?).map_err(io::Error::other)?;

    relay_bidirectional(stream.try_clone()?, upstream.try_clone()?)?;
    let _ = stream.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    info!(%target, "stream closed");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let file_cfg = load_file_config(&cli.config)?;
    let cfg = build_config(&cli, file_cfg)?;

    init_logging(&cfg.log_level);
    validate_config(&cfg)?;

    info!(listen_addr = %cfg.listen_addr, server_addr = %cfg.server_addr, "client starting");
    let listener = bind_listener(Some(cfg.listen_addr))?;
    listener.set_nonblocking(true)?;
    info!(bound = %listener.local_addr()?, "SOCKS5 listener ready");

    let shutdown = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let signal = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })?;
    }
    #[cfg(windows)]
    {
        let signal = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })?;
    }

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, addr)) => {
                let server_addr = cfg.server_addr.clone();
                info!(peer_addr = %addr, "accepted local connection");
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, &server_addr) {
                        warn!(error = %err, "client stream failed");
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25))
            }
            Err(err) => {
                error!(error = %err, "accept failed");
                break;
            }
        }
    }

    info!("client shutting down gracefully");
    Ok(())
}
