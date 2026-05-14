use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use std::fmt;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoPacket {
    pub kind: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IcmpAddr {
    ip: IpAddr,
    scope_id: u32,
}

impl IcmpAddr {
    pub fn new(ip: IpAddr, scope_id: u32) -> Self {
        Self { ip, scope_id }
    }

    pub fn parse(input: &str) -> io::Result<Self> {
        let trimmed = input.trim();
        let trimmed = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(trimmed);
        let (addr, scope) = trimmed.rsplit_once('%').unwrap_or((trimmed, ""));
        let ip: IpAddr = addr.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid ICMP peer address")
        })?;
        let scope_id = if scope.is_empty() {
            0
        } else if ip.is_ipv6() {
            parse_scope_id(scope)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv4 ICMP peer address cannot include a scope id",
            ));
        };
        Ok(Self::new(ip, scope_id))
    }

    pub fn ip(self) -> IpAddr {
        self.ip
    }

    pub fn protocol(self) -> IcmpProtocol {
        IcmpProtocol::for_addr(self.ip)
    }
}

impl fmt::Display for IcmpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(v4) => write!(f, "{v4}"),
            IpAddr::V6(v6) if self.scope_id == 0 => write!(f, "{v6}"),
            IpAddr::V6(v6) => write!(f, "{v6}%{}", self.scope_id),
        }
    }
}

impl From<IpAddr> for IcmpAddr {
    fn from(value: IpAddr) -> Self {
        Self::new(value, 0)
    }
}

fn parse_scope_id(scope: &str) -> io::Result<u32> {
    if let Ok(scope_id) = scope.parse::<u32>() {
        return Ok(scope_id);
    }
    interface_scope_id(scope)
}

#[cfg(unix)]
fn interface_scope_id(scope: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(scope)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 scope name"))?;
    let scope_id = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if scope_id == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(scope_id)
}

#[cfg(not(unix))]
fn interface_scope_id(_scope: &str) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPv6 interface scope names are unsupported on this platform; use a numeric scope id",
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpProtocol {
    V4,
    V6,
}

impl IcmpProtocol {
    pub fn for_addr(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    pub fn request_type(self) -> u8 {
        match self {
            Self::V4 => ICMP_ECHO_REQUEST,
            Self::V6 => ICMPV6_ECHO_REQUEST,
        }
    }

    pub fn reply_type(self) -> u8 {
        match self {
            Self::V4 => ICMP_ECHO_REPLY,
            Self::V6 => ICMPV6_ECHO_REPLY,
        }
    }
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum = sum.saturating_add(u32::from(word));
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

pub fn build_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    build_echo_request_for(IcmpProtocol::V4, identifier, sequence, payload)
}

pub fn build_echo_reply(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    build_echo_reply_for(IcmpProtocol::V4, identifier, sequence, payload)
}

pub fn build_echo_request_for(
    protocol: IcmpProtocol,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_echo(protocol, protocol.request_type(), identifier, sequence, payload)
}

pub fn build_echo_reply_for(
    protocol: IcmpProtocol,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_echo(protocol, protocol.reply_type(), identifier, sequence, payload)
}

fn build_echo(
    protocol: IcmpProtocol,
    kind: u8,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&identifier.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(payload);
    if protocol == IcmpProtocol::V4 {
        let csum = checksum(&out).to_be_bytes();
        out[2] = csum[0];
        out[3] = csum[1];
    }
    out
}

pub fn parse_echo_packet(packet: &[u8]) -> io::Result<EchoPacket> {
    parse_echo_packet_for(IcmpProtocol::V4, packet)
}

pub fn parse_echo_packet_for(protocol: IcmpProtocol, packet: &[u8]) -> io::Result<EchoPacket> {
    let icmp = match protocol {
        IcmpProtocol::V4 => strip_ipv4_header(packet)?,
        IcmpProtocol::V6 => strip_ipv6_header(packet)?,
    };
    if icmp.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ICMP packet too short"));
    }
    if protocol == IcmpProtocol::V4 && checksum(icmp) != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid ICMP checksum"));
    }
    Ok(EchoPacket {
        kind: icmp[0],
        identifier: u16::from_be_bytes([icmp[4], icmp[5]]),
        sequence: u16::from_be_bytes([icmp[6], icmp[7]]),
        payload: icmp[8..].to_vec(),
    })
}

fn strip_ipv4_header(packet: &[u8]) -> io::Result<&[u8]> {
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        if ihl < 20 || packet.len() < ihl + 8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4 header"));
        }
        if packet[9] != libc::IPPROTO_ICMP as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "IPv4 packet is not ICMP"));
        }
        Ok(&packet[ihl..])
    } else {
        Ok(packet)
    }
}

fn strip_ipv6_header(packet: &[u8]) -> io::Result<&[u8]> {
    if packet.len() >= 40 && (packet[0] >> 4) == 6 {
        if packet[6] != libc::IPPROTO_ICMPV6 as u8 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "IPv6 packet is not ICMPv6"));
        }
        if packet.len() < 48 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 header"));
        }
        Ok(&packet[40..])
    } else {
        Ok(packet)
    }
}

#[cfg(unix)]
mod raw_unix {
    use super::*;
    use std::mem;
    use std::os::fd::RawFd;

    #[derive(Debug)]
    pub struct IcmpSocket {
        fd: RawFd,
        protocol: IcmpProtocol,
    }

    impl IcmpSocket {
        pub fn raw() -> io::Result<Self> {
            Self::raw_for(IcmpProtocol::V4)
        }

        pub fn raw_for(protocol: IcmpProtocol) -> io::Result<Self> {
            let (family, raw_protocol) = match protocol {
                IcmpProtocol::V4 => (libc::AF_INET, libc::IPPROTO_ICMP),
                IcmpProtocol::V6 => (libc::AF_INET6, libc::IPPROTO_ICMPV6),
            };
            let fd = unsafe { libc::socket(family, libc::SOCK_RAW, raw_protocol) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd, protocol })
        }

        pub fn protocol(&self) -> IcmpProtocol {
            self.protocol
        }

        pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            let tv = timeout.map_or(libc::timeval { tv_sec: 0, tv_usec: 0 }, |duration| libc::timeval {
                tv_sec: duration.as_secs() as libc::time_t,
                tv_usec: i64::from(duration.subsec_micros()) as libc::suseconds_t,
            });
            let rc = unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&tv as *const libc::timeval).cast(),
                    mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn send_to(&self, dst: IcmpAddr, packet: &[u8]) -> io::Result<usize> {
            if dst.protocol() != self.protocol {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination address family does not match ICMP socket",
                ));
            }
            let scope_id = dst.scope_id;
            let rc = match dst.ip {
                IpAddr::V4(dst) => {
                    let addr = libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: 0,
                        sin_addr: libc::in_addr {
                            s_addr: u32::from_ne_bytes(dst.octets()),
                        },
                        sin_zero: [0; 8],
                    };
                    unsafe {
                        libc::sendto(
                            self.fd,
                            packet.as_ptr().cast(),
                            packet.len(),
                            0,
                            (&addr as *const libc::sockaddr_in).cast(),
                            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                        )
                    }
                }
                IpAddr::V6(dst) => {
                    let addr = libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: 0,
                        sin6_flowinfo: 0,
                        sin6_addr: libc::in6_addr {
                            s6_addr: dst.octets(),
                        },
                        sin6_scope_id: scope_id,
                    };
                    unsafe {
                        libc::sendto(
                            self.fd,
                            packet.as_ptr().cast(),
                            packet.len(),
                            0,
                            (&addr as *const libc::sockaddr_in6).cast(),
                            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                        )
                    }
                }
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(rc as usize)
        }

        pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, IcmpAddr)> {
            let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
            let mut addr_len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let rc = unsafe {
                libc::recvfrom(
                    self.fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    (&mut storage as *mut libc::sockaddr_storage).cast(),
                    &mut addr_len,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            let family = storage.ss_family as i32;
            let addr = match family {
                libc::AF_INET => {
                    let addr = unsafe { &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()) };
                    IcmpAddr::new(
                        IpAddr::V4(Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())),
                        0,
                    )
                }
                libc::AF_INET6 => {
                    let addr = unsafe { &*((&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()) };
                    IcmpAddr::new(
                        IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)),
                        addr.sin6_scope_id,
                    )
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "raw ICMP packet from unsupported address family",
                    ));
                }
            };
            Ok((rc as usize, addr))
        }
    }

    impl Drop for IcmpSocket {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    unsafe impl Send for IcmpSocket {}
    unsafe impl Sync for IcmpSocket {}
}

#[cfg(unix)]
pub use raw_unix::IcmpSocket;

#[cfg(not(unix))]
#[derive(Debug)]
pub struct IcmpSocket;

#[cfg(not(unix))]
impl IcmpSocket {
    pub fn raw() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw ICMP socket backend in this completion package is Unix-only",
        ))
    }

    pub fn raw_for(_protocol: IcmpProtocol) -> io::Result<Self> {
        Self::raw()
    }

    pub fn protocol(&self) -> IcmpProtocol {
        IcmpProtocol::V4
    }

    pub fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    pub fn send_to(&self, _dst: IcmpAddr, _packet: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"))
    }

    pub fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, IcmpAddr)> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_echo_request_round_trips_through_parser() {
        let packet = build_echo_request_for(IcmpProtocol::V4, 7, 9, b"hello");
        let parsed = parse_echo_packet_for(IcmpProtocol::V4, &packet).expect("parse");
        assert_eq!(parsed.kind, ICMP_ECHO_REQUEST);
        assert_eq!(parsed.identifier, 7);
        assert_eq!(parsed.sequence, 9);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn ipv6_echo_request_uses_icmpv6_type() {
        let packet = build_echo_request_for(IcmpProtocol::V6, 7, 9, b"hello");
        let parsed = parse_echo_packet_for(IcmpProtocol::V6, &packet).expect("parse");
        assert_eq!(parsed.kind, ICMPV6_ECHO_REQUEST);
        assert_eq!(parsed.identifier, 7);
        assert_eq!(parsed.sequence, 9);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn parses_scoped_ipv6_peer_address() {
        let addr = IcmpAddr::parse("fe80::1%3").expect("parse");
        assert_eq!(addr.ip(), "fe80::1".parse::<IpAddr>().expect("ip"));
        assert_eq!(addr.scope_id, 3);
    }
}
