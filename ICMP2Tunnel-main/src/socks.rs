use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};

pub const SOCKS5_VERSION: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_USERNAME_PASSWORD: u8 = 0x02;
pub const METHOD_NO_ACCEPTABLE: u8 = 0xff;
pub const USERNAME_PASSWORD_VERSION: u8 = 0x01;

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

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(IpAddr::V4(v4)) => write!(f, "{v4}"),
            Self::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
            Self::Domain(name) => write!(f, "{name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksRequest {
    pub command: Command,
    pub target: TargetAddr,
    pub port: u16,
}

impl SocksRequest {
    pub fn target_string(&self) -> String {
        format!("{}:{}", self.target, self.port)
    }
}

#[derive(Debug)]
pub enum SocksError {
    InvalidVersion(u8),
    NoAcceptableMethod,
    UnsupportedAddressType(u8),
    InvalidDomain,
    AuthFailed,
    Io(io::Error),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(v) => write!(f, "invalid SOCKS version {v:#x}"),
            Self::NoAcceptableMethod => write!(f, "no acceptable SOCKS authentication method"),
            Self::UnsupportedAddressType(v) => write!(f, "unsupported SOCKS address type {v:#x}"),
            Self::InvalidDomain => write!(f, "invalid SOCKS domain field"),
            Self::AuthFailed => write!(f, "SOCKS username/password authentication failed"),
            Self::Io(err) => write!(f, "SOCKS I/O error: {err}"),
        }
    }
}

impl std::error::Error for SocksError {}

impl From<io::Error> for SocksError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn negotiate_no_auth<RW: Read + Write>(stream: &mut RW) -> Result<(), SocksError> {
    negotiate(stream, None)
}

pub fn negotiate<RW: Read + Write>(
    stream: &mut RW,
    auth: Option<(&str, &str)>,
) -> Result<(), SocksError> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != SOCKS5_VERSION {
        return Err(SocksError::InvalidVersion(header[0]));
    }

    let mut methods = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut methods)?;
    let selected = if auth.is_some() && methods.contains(&METHOD_USERNAME_PASSWORD) {
        METHOD_USERNAME_PASSWORD
    } else if auth.is_none() && methods.contains(&METHOD_NO_AUTH) {
        METHOD_NO_AUTH
    } else {
        METHOD_NO_ACCEPTABLE
    };
    stream.write_all(&[SOCKS5_VERSION, selected])?;
    stream.flush()?;

    if selected == METHOD_NO_ACCEPTABLE {
        return Err(SocksError::NoAcceptableMethod);
    }
    if selected == METHOD_USERNAME_PASSWORD {
        let (username, password) = auth.expect("selected username/password requires credentials");
        authenticate_username_password(stream, username.as_bytes(), password.as_bytes())?;
    }
    Ok(())
}

fn authenticate_username_password<RW: Read + Write>(
    stream: &mut RW,
    expected_username: &[u8],
    expected_password: &[u8],
) -> Result<(), SocksError> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] != USERNAME_PASSWORD_VERSION || header[1] == 0 {
        let _ = stream.write_all(&[USERNAME_PASSWORD_VERSION, 0x01]);
        let _ = stream.flush();
        return Err(SocksError::AuthFailed);
    }

    let mut username = vec![0_u8; usize::from(header[1])];
    stream.read_exact(&mut username)?;
    let mut password_len = [0_u8; 1];
    stream.read_exact(&mut password_len)?;
    let mut password = vec![0_u8; usize::from(password_len[0])];
    stream.read_exact(&mut password)?;

    let ok = constant_time_eq(&username, expected_username)
        & constant_time_eq(&password, expected_password);
    let status = if ok { 0x00 } else { 0x01 };
    stream.write_all(&[USERNAME_PASSWORD_VERSION, status])?;
    stream.flush()?;
    if !ok {
        return Err(SocksError::AuthFailed);
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for i in 0..max_len {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

pub fn parse_request<R: Read>(stream: &mut R) -> Result<SocksRequest, SocksError> {
    let mut header = [0_u8; 4];
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
            let mut raw = [0_u8; 4];
            stream.read_exact(&mut raw)?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(raw)))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len)?;
            if len[0] == 0 {
                return Err(SocksError::InvalidDomain);
            }
            let mut raw = vec![0_u8; usize::from(len[0])];
            stream.read_exact(&mut raw)?;
            let name = String::from_utf8(raw).map_err(|_| SocksError::InvalidDomain)?;
            TargetAddr::Domain(name)
        }
        0x04 => {
            let mut raw = [0_u8; 16];
            stream.read_exact(&mut raw)?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(raw)))
        }
        atyp => return Err(SocksError::UnsupportedAddressType(atyp)),
    };

    let mut port = [0_u8; 2];
    stream.read_exact(&mut port)?;
    Ok(SocksRequest {
        command,
        target,
        port: u16::from_be_bytes(port),
    })
}

pub fn write_reply<W: Write>(stream: &mut W, rep: u8, bind_addr: SocketAddr) -> Result<(), SocksError> {
    let mut out = Vec::with_capacity(22);
    out.push(SOCKS5_VERSION);
    out.push(rep);
    out.push(0);
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
    stream.flush()?;
    Ok(())
}

pub fn default_loopback_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

pub fn bind_listener(addr: Option<SocketAddr>) -> io::Result<TcpListener> {
    TcpListener::bind(addr.unwrap_or_else(|| default_loopback_bind_addr(0)))
}
