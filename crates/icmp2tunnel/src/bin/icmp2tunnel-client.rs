use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::Parser;
use icmp2tunnel_socks::{bind_listener, default_loopback_bind_addr};
use serde::Deserialize;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "icmp2tunnel-client", about = "ICMP2Tunnel SOCKS5 client")]
struct Cli {
    /// Path to config file in TOML format.
    #[arg(short, long, default_value = "examples/client.toml")]
    config: PathBuf,

    /// Allow non-loopback listener bind address.
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let file_cfg = load_file_config(&cli.config)?;
    let cfg = build_config(&cli, file_cfg)?;

    init_logging(&cfg.log_level);
    validate_config(&cfg)?;

    info!(listen_addr = %cfg.listen_addr, server_addr = %cfg.server_addr, "client starting");
    let listener = bind_listener(Some(cfg.listen_addr))?;
    info!(bound = %listener.local_addr()?, "SOCKS5 listener ready");

    for stream in listener.incoming() {
        match stream {
            Ok(peer) => {
                info!(peer_addr = ?peer.peer_addr(), "accepted local connection");
                warn!("stream forwarding is not implemented yet");
            }
            Err(err) => {
                error!(error = %err, "accept failed");
                break;
            }
        }
    }

    Ok(())
}
