#![forbid(unsafe_code)]
#![deny(warnings)]

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};

pub const SOCKS5_VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub command: Command,
    pub target: TargetAddr,
    pub port: u16,
}

#[derive(Debug)]
pub enum SocksError {
    InvalidVersion(u8),
    NoAcceptableMethod,
    UnsupportedAddressType(u8),
    InvalidDomain,
    Io(io::Error),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(v) => write!(f, "invalid SOCKS version: {v:#x}"),
            Self::NoAcceptableMethod => write!(f, "no acceptable authentication method"),
            Self::UnsupportedAddressType(atyp) => write!(f, "unsupported address type: {atyp:#x}"),
            Self::InvalidDomain => write!(f, "domain field is invalid"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for SocksError {}

impl From<io::Error> for SocksError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn negotiate_no_auth(stream: &mut TcpStream) -> Result<(), SocksError> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(header[0]));
    }

    let nmethods = usize::from(header[1]);
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods)?;

    let selected = if methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NO_ACCEPTABLE
    };

    stream.write_all(&[SOCKS5_VERSION, selected])?;

    if selected == METHOD_NO_ACCEPTABLE {
        return Err(SocksError::NoAcceptableMethod);
    }
    Ok(())
}

pub fn parse_request(stream: &mut TcpStream) -> Result<SocksRequest, SocksError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;

    if header[0] != SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(header[0]));
    }

    let command = match header[1] {
        0x01 => Command::Connect,
        0x02 => Command::Bind,
        0x03 => Command::UdpAssociate,
        other => Command::Other(other),
    };

    let target = match header[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr)?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(addr)))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            if len[0] == 0 {
                return Err(SocksError::InvalidDomain);
            }
            let mut buf = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut buf)?;
            let domain = String::from_utf8(buf).map_err(|_| SocksError::InvalidDomain)?;
            TargetAddr::Domain(domain)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr)?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        atyp => return Err(SocksError::UnsupportedAddressType(atyp)),
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes)?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(SocksRequest {
        command,
        target,
        port,
    })
}

pub fn write_reply(
    stream: &mut TcpStream,
    rep: u8,
    bind_addr: SocketAddr,
) -> Result<(), SocksError> {
    let mut out = Vec::with_capacity(22);
    out.push(SOCKS5_VERSION);
    out.push(rep);
    out.push(0x00);

    match bind_addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }

    out.extend_from_slice(&bind_addr.port().to_be_bytes());
    stream.write_all(&out)?;
    Ok(())
}

#[must_use]
pub fn default_loopback_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

pub fn bind_listener(bind_addr: Option<SocketAddr>) -> Result<TcpListener, io::Error> {
    TcpListener::bind(bind_addr.unwrap_or_else(|| default_loopback_bind_addr(0)))
}
