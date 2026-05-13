use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclError {
    InvalidCidr(String),
    InvalidRule(String),
    MissingPort(String),
    ResolveFailed(String),
}

impl fmt::Display for AclError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCidr(v) => write!(f, "invalid CIDR rule: {v}"),
            Self::InvalidRule(v) => write!(f, "invalid ACL rule: {v}"),
            Self::MissingPort(v) => write!(f, "missing target ACL port: {v}"),
            Self::ResolveFailed(v) => write!(f, "failed to resolve target: {v}"),
        }
    }
}

impl std::error::Error for AclError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(input: &str) -> Result<Self, AclError> {
        let (base, prefix) = input
            .split_once('/')
            .ok_or_else(|| AclError::InvalidCidr(input.to_string()))?;
        let base: IpAddr = base
            .parse()
            .map_err(|_| AclError::InvalidCidr(input.to_string()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| AclError::InvalidCidr(input.to_string()))?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(AclError::InvalidCidr(input.to_string()));
        }
        Ok(Self { base, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => masked_eq_v4(a, b, self.prefix),
            (IpAddr::V6(a), IpAddr::V6(b)) => masked_eq_v6(a, b, self.prefix),
            _ => false,
        }
    }
}

fn masked_eq_v4(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

fn masked_eq_v6(a: Ipv6Addr, b: Ipv6Addr, prefix: u8) -> bool {
    let av = u128::from_be_bytes(a.octets());
    let bv = u128::from_be_bytes(b.octets());
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u128::from(prefix))
    };
    (av & mask) == (bv & mask)
}

#[derive(Debug, Clone)]
pub struct PeerAcl {
    rules: Vec<Cidr>,
}

impl PeerAcl {
    pub fn parse(rules: &[String]) -> Result<Self, AclError> {
        let mut parsed = Vec::with_capacity(rules.len());
        for rule in rules {
            parsed.push(Cidr::parse(rule)?);
        }
        Ok(Self { rules: parsed })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn allows(&self, peer: IpAddr) -> bool {
        self.rules.iter().any(|rule| rule.contains(peer))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostRule {
    Ip(IpAddr),
    Cidr(Cidr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetRule {
    host: HostRule,
    port: u16,
}

#[derive(Debug, Clone)]
pub struct TargetAcl {
    rules: Vec<TargetRule>,
    deny_local: bool,
}

impl TargetAcl {
    pub fn parse(rules: &[String]) -> Result<Self, AclError> {
        let mut parsed = Vec::with_capacity(rules.len());
        for rule in rules {
            let (host, port) = split_host_port(rule).ok_or_else(|| AclError::MissingPort(rule.clone()))?;
            let port: u16 = port
                .parse()
                .map_err(|_| AclError::InvalidRule(rule.clone()))?;
            let host_rule = if host.contains('/') {
                HostRule::Cidr(Cidr::parse(host)?)
            } else if let Ok(ip) = host.parse::<IpAddr>() {
                HostRule::Ip(ip)
            } else {
                HostRule::Domain(host.to_ascii_lowercase())
            };
            parsed.push(TargetRule {
                host: host_rule,
                port,
            });
        }
        Ok(Self {
            rules: parsed,
            deny_local: true,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn resolve_allowed(&self, target: &str) -> Result<SocketAddr, AclError> {
        let (host, port_s) = split_host_port(target).ok_or_else(|| AclError::MissingPort(target.to_string()))?;
        let port: u16 = port_s
            .parse()
            .map_err(|_| AclError::InvalidRule(target.to_string()))?;
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|_| AclError::ResolveFailed(target.to_string()))?
            .collect();
        for addr in addrs {
            if self.allows_host_ip_port(host, addr.ip(), port) {
                return Ok(addr);
            }
        }
        Err(AclError::InvalidRule(format!(
            "target not allowlisted after resolution: {target}"
        )))
    }

    pub fn allows_host_ip_port(&self, host: &str, ip: IpAddr, port: u16) -> bool {
        if self.deny_local && is_default_blocked_ip(ip) {
            return false;
        }
        let host_lc = host.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        self.rules.iter().any(|rule| {
            if rule.port != port {
                return false;
            }
            match &rule.host {
                HostRule::Ip(rule_ip) => *rule_ip == ip,
                HostRule::Cidr(cidr) => cidr.contains(ip),
                HostRule::Domain(rule_host) => *rule_host == host_lc,
            }
        })
    }
}

pub fn split_host_port(input: &str) -> Option<(&str, &str)> {
    if let Some(rest) = input.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = after.strip_prefix(':')?;
        return Some((host, port));
    }
    input.rsplit_once(':')
}

pub fn is_default_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.octets() == [169, 254, 169, 254]
                || v4.octets() == [169, 254, 169, 253]
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
    }
}

#[derive(Debug, Clone)]
pub struct RateLimits {
    pub packets_per_sec: u64,
    pub bytes_per_sec: u64,
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    limits: RateLimits,
    window_start: Instant,
    packets: u64,
    bytes: u64,
}

impl RateLimiter {
    pub fn new(limits: RateLimits, now: Instant) -> Self {
        Self {
            limits,
            window_start: now,
            packets: 0,
            bytes: 0,
        }
    }

    pub fn allow(&mut self, now: Instant, bytes: u64) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.packets = 0;
            self.bytes = 0;
        }
        if self.packets.saturating_add(1) > self.limits.packets_per_sec {
            return false;
        }
        if self.bytes.saturating_add(bytes) > self.limits.bytes_per_sec {
            return false;
        }
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        true
    }
}

pub type PeerRateLimiters = HashMap<IpAddr, RateLimiter>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_acl_matches_cidr() {
        let acl = PeerAcl::parse(&["192.0.2.0/24".to_string()]).expect("parse");
        assert!(acl.allows("192.0.2.10".parse().expect("ip")));
        assert!(!acl.allows("198.51.100.10".parse().expect("ip")));
    }

    #[test]
    fn target_acl_blocks_loopback_even_if_listed() {
        let acl = TargetAcl::parse(&["127.0.0.1:80".to_string()]).expect("parse");
        assert!(!acl.allows_host_ip_port("127.0.0.1", "127.0.0.1".parse().expect("ip"), 80));
    }
}
