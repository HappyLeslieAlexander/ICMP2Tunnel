use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "icmp2tunnel-server", about = "ICMP2Tunnel server")]
struct Cli {
    /// Path to config file in TOML format.
    #[arg(short, long, default_value = "examples/server.toml")]
    config: PathBuf,

    /// Allow non-private bind address.
    #[arg(long)]
    allow_public_bind: bool,
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    bind_addr: Option<IpAddr>,
    psk: Option<String>,
    log_level: Option<String>,
    max_sessions: Option<u32>,
    max_streams_per_session: Option<u32>,
    allow_public_bind: Option<bool>,
}

#[derive(Debug)]
struct ServerConfig {
    bind_addr: IpAddr,
    psk: String,
    log_level: String,
    max_sessions: u32,
    max_streams_per_session: u32,
    allow_public_bind: bool,
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

fn build_config(cli: &Cli, file_cfg: FileConfig) -> Result<ServerConfig, String> {
    let bind_addr = env_or("I2T_SERVER_BIND_ADDR", file_cfg.bind_addr)
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

    let psk = std::env::var("I2T_SERVER_PSK")
        .ok()
        .or(file_cfg.psk)
        .ok_or_else(|| "missing PSK: set in config or I2T_SERVER_PSK".to_string())?;

    let log_level = std::env::var("I2T_SERVER_LOG_LEVEL")
        .ok()
        .or(file_cfg.log_level)
        .unwrap_or_else(|| "info".to_string());

    let max_sessions = env_or("I2T_SERVER_MAX_SESSIONS", file_cfg.max_sessions).unwrap_or(64);
    let max_streams_per_session = env_or(
        "I2T_SERVER_MAX_STREAMS_PER_SESSION",
        file_cfg.max_streams_per_session,
    )
    .unwrap_or(32);

    let allow_public_bind = env_or("I2T_SERVER_ALLOW_PUBLIC_BIND", file_cfg.allow_public_bind)
        .unwrap_or(cli.allow_public_bind);

    Ok(ServerConfig {
        bind_addr,
        psk,
        log_level,
        max_sessions,
        max_streams_per_session,
        allow_public_bind,
    })
}

fn validate_config(cfg: &ServerConfig) -> Result<(), String> {
    let is_private_or_local = match cfg.bind_addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    };

    if !is_private_or_local && !cfg.allow_public_bind {
        return Err("refusing public bind address without --allow-public-bind".to_string());
    }

    if cfg.psk.trim().is_empty() {
        return Err("PSK must not be empty".to_string());
    }

    if cfg.max_sessions == 0 {
        return Err("max_sessions must be greater than 0".to_string());
    }

    if cfg.max_streams_per_session == 0 {
        return Err("max_streams_per_session must be greater than 0".to_string());
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

    info!(
        bind_addr = %cfg.bind_addr,
        max_sessions = cfg.max_sessions,
        max_streams_per_session = cfg.max_streams_per_session,
        "server starting"
    );
    info!("raw ICMP transport backend is not implemented yet");

    Ok(())
}
