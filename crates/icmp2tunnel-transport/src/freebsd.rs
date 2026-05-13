use std::io;

const IPV4_MIN_HEADER_LEN: usize = 20;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoMeta {
    pub identifier: u16,
    pub sequence: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEchoRequest {
    pub meta: EchoMeta,
    pub payload: Vec<u8>,
}

pub fn parse_echo_request_ipv4(packet: &[u8]) -> Result<ParsedEchoRequest, io::Error> {
    if packet.len() < IPV4_MIN_HEADER_LEN + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet too short",
        ));
    }

    let version_ihl = packet[0];
    let version = version_ihl >> 4;
    if version != 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not IPv4"));
    }

    let ihl_words = usize::from(version_ihl & 0x0f);
    let ip_header_len = ihl_words * 4;
    if ihl_words < 5 || packet.len() < ip_header_len + 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid IPv4 IHL",
        ));
    }

    let proto = packet[9];
    if proto != 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not ICMP"));
    }

    let icmp = &packet[ip_header_len..];
    if icmp[0] != ICMP_ECHO_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not ICMP Echo Request",
        ));
    }

    if checksum(icmp) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ICMP checksum",
        ));
    }

    let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
    let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
    Ok(ParsedEchoRequest {
        meta: EchoMeta {
            identifier,
            sequence,
        },
        payload: icmp[8..].to_vec(),
    })
}

pub fn build_echo_reply(meta: EchoMeta, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.push(ICMP_ECHO_REPLY);
    out.push(0);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&meta.identifier.to_be_bytes());
    out.extend_from_slice(&meta.sequence.to_be_bytes());
    out.extend_from_slice(payload);
    let csum = checksum(&out).to_be_bytes();
    out[2] = csum[0];
    out[3] = csum[1];
    out
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

pub fn is_missing_cap_net_raw(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
    )
}

#[cfg(test)]
mod tests {
    use super::{EchoMeta, build_echo_reply, checksum, parse_echo_request_ipv4};

    fn build_ipv4_echo_request(meta: EchoMeta, payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 1;
        let total_len = (20 + 8 + payload.len()) as u16;
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());

        let mut icmp = vec![8, 0, 0, 0];
        icmp.extend_from_slice(&meta.identifier.to_be_bytes());
        icmp.extend_from_slice(&meta.sequence.to_be_bytes());
        icmp.extend_from_slice(payload);
        let csum = checksum(&icmp).to_be_bytes();
        icmp[2] = csum[0];
        icmp[3] = csum[1];

        ip.extend_from_slice(&icmp);
        ip
    }

    #[test]
    fn parse_request_preserves_identifier_sequence_and_payload() {
        let meta = EchoMeta {
            identifier: 0x1234,
            sequence: 0x00aa,
        };
        let packet = build_ipv4_echo_request(meta, b"hello");
        let parsed = parse_echo_request_ipv4(&packet).expect("must parse echo request");
        assert_eq!(parsed.meta, meta);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn build_reply_preserves_identifier_and_sequence() {
        let meta = EchoMeta {
            identifier: 0xabcd,
            sequence: 3,
        };
        let reply = build_echo_reply(meta, b"pong");
        assert_eq!(reply[0], 0);
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), meta.identifier);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), meta.sequence);
        assert_eq!(&reply[8..], b"pong");
        assert_eq!(checksum(&reply), 0);
    }
}
