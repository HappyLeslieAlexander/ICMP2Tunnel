use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoPacket {
    pub kind: u8,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
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
    build_echo(ICMP_ECHO_REQUEST, identifier, sequence, payload)
}

pub fn build_echo_reply(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    build_echo(ICMP_ECHO_REPLY, identifier, sequence, payload)
}

fn build_echo(kind: u8, identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&identifier.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(payload);
    let csum = checksum(&out).to_be_bytes();
    out[2] = csum[0];
    out[3] = csum[1];
    out
}

pub fn parse_echo_packet(packet: &[u8]) -> io::Result<EchoPacket> {
    let icmp = strip_ipv4_header(packet)?;
    if icmp.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ICMP packet too short"));
    }
    if checksum(icmp) != 0 {
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

#[cfg(unix)]
mod raw_unix {
    use super::*;
    use std::mem;
    use std::os::fd::RawFd;
    use std::ptr;

    #[derive(Debug)]
    pub struct IcmpSocket {
        fd: RawFd,
    }

    impl IcmpSocket {
        pub fn raw() -> io::Result<Self> {
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd })
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

        pub fn send_to(&self, dst: Ipv4Addr, packet: &[u8]) -> io::Result<usize> {
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(dst.octets()),
                },
                sin_zero: [0; 8],
            };
            let rc = unsafe {
                libc::sendto(
                    self.fd,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&addr as *const libc::sockaddr_in).cast(),
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(rc as usize)
        }

        pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Ipv4Addr)> {
            let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
            let mut addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let rc = unsafe {
                libc::recvfrom(
                    self.fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    0,
                    (&mut addr as *mut libc::sockaddr_in).cast(),
                    &mut addr_len,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((rc as usize, Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes())))
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

    pub fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    pub fn send_to(&self, _dst: Ipv4Addr, _packet: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"))
    }

    pub fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, Ipv4Addr)> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unsupported platform"))
    }
}
