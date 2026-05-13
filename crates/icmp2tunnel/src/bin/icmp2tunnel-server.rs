use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use icmp2tunnel_core::{PeerAcl, RateLimiter, RateLimits, TargetAcl};
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
    max_sessions_per_peer: Option<u32>,
    peer_acl: Option<Vec<String>>,
    target_acl: Option<Vec<String>>,
    packet_per_sec: Option<u64>,
    byte_per_sec: Option<u64>,
    allow_public_bind: Option<bool>,
}

#[derive(Debug)]
struct ServerConfig {
    bind_addr: IpAddr,
    psk: String,
    log_level: String,
    max_sessions: u32,
    max_streams_per_session: u32,
    max_sessions_per_peer: u32,
    peer_acl: PeerAcl,
    target_acl: TargetAcl,
    target_acl_rules: Vec<String>,
    rate_limits: RateLimits,
    allow_public_bind: bool,
}

#[derive(Debug)]
struct AuditLogRecord {
    peer: IpAddr,
    target: SocketAddr,
    bytes: u64,
    duration: Duration,
    close_reason: &'static str,
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
    let max_sessions_per_peer = env_or(
        "I2T_SERVER_MAX_SESSIONS_PER_PEER",
        file_cfg.max_sessions_per_peer,
    )
    .unwrap_or(8);

    let peer_acl_rules = file_cfg.peer_acl.unwrap_or_default();
    let target_acl_rules = file_cfg.target_acl.unwrap_or_default();
    let peer_acl = PeerAcl::parse(
        &peer_acl_rules
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .map_err(|_| "invalid peer_acl rules".to_string())?;
    let target_acl = TargetAcl::parse(
        &target_acl_rules
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
    .map_err(|_| "invalid target_acl rules".to_string())?;
    let rate_limits = RateLimits {
        packets_per_sec: env_or("I2T_SERVER_PACKET_PER_SEC", file_cfg.packet_per_sec)
            .unwrap_or(256),
        bytes_per_sec: env_or("I2T_SERVER_BYTE_PER_SEC", file_cfg.byte_per_sec).unwrap_or(262_144),
    };

    Ok(ServerConfig {
        bind_addr,
        psk,
        log_level,
        max_sessions,
        max_streams_per_session,
        max_sessions_per_peer,
        peer_acl,
        target_acl,
        target_acl_rules,
        rate_limits,
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
    if cfg.max_sessions_per_peer == 0 {
        return Err("max_sessions_per_peer must be greater than 0".to_string());
    }
    if cfg.rate_limits.packets_per_sec == 0 || cfg.rate_limits.bytes_per_sec == 0 {
        return Err("rate limits must be greater than 0".to_string());
    }
    if cfg.target_acl_rules.is_empty() {
        return Err("target_acl must not be empty".to_string());
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
        max_sessions_per_peer = cfg.max_sessions_per_peer,
        "server starting"
    );
    let mut rate_limiter = RateLimiter::new(cfg.rate_limits.clone(), Instant::now());
    let _allowed = rate_limiter.allow(Instant::now(), 64);
    let audit_log_record = AuditLogRecord {
        peer: cfg.bind_addr,
        target: SocketAddr::from(([127, 0, 0, 1], 0)),
        bytes: 0,
        duration: Duration::from_secs(0),
        close_reason: "startup",
    };
    info!(
        peer = %audit_log_record.peer,
        target = %audit_log_record.target,
        bytes = audit_log_record.bytes,
        duration_ms = audit_log_record.duration.as_millis(),
        close_reason = audit_log_record.close_reason,
        peer_acl_match = cfg.peer_acl.allows(cfg.bind_addr),
        target_acl_match = cfg.target_acl.allows_socket(SocketAddr::from(([127, 0, 0, 1], 1))),
        "audit"
    );
    info!("raw ICMP transport backend is not implemented yet");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_target_acl() {
        let cli = Cli {
            config: PathBuf::from("unused"),
            allow_public_bind: true,
        };
        let cfg = FileConfig {
            bind_addr: Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            psk: Some("psk".to_string()),
            log_level: None,
            max_sessions: Some(1),
            max_streams_per_session: Some(1),
            max_sessions_per_peer: Some(1),
            peer_acl: Some(vec!["127.0.0.1/32".to_string()]),
            target_acl: Some(Vec::new()),
            packet_per_sec: Some(10),
            byte_per_sec: Some(1024),
            allow_public_bind: Some(true),
        };
        let built = build_config(&cli, cfg).expect("build");
        assert!(validate_config(&built).is_err());
    }
}
