use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoMeta {
    pub identifier: u16,
    pub sequence: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoReply {
    pub meta: EchoMeta,
    pub payload: Vec<u8>,
}

const ICMP_ECHO_REPLY: u8 = 0;

pub fn parse_echo_reply(packet: &[u8]) -> Result<EchoReply, io::Error> {
    if packet.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ICMP reply too short",
        ));
    }
    if packet[0] != ICMP_ECHO_REPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not ICMP Echo Reply",
        ));
    }

    let identifier = u16::from_be_bytes([packet[4], packet[5]]);
    let sequence = u16::from_be_bytes([packet[6], packet[7]]);

    Ok(EchoReply {
        meta: EchoMeta {
            identifier,
            sequence,
        },
        payload: packet[8..].to_vec(),
    })
}

pub fn is_related_reply(reply: &EchoReply, expected: EchoMeta) -> bool {
    reply.meta == expected
}

#[cfg(test)]
mod tests {
    use super::{EchoMeta, is_related_reply, parse_echo_reply};

    #[test]
    fn parse_reply_preserves_identifier_sequence_and_payload() {
        let raw = [0, 0, 0, 0, 0x12, 0x34, 0xab, 0xcd, b'p', b'o', b'n', b'g'];
        let parsed = parse_echo_reply(&raw).expect("must parse");
        assert_eq!(parsed.meta.identifier, 0x1234);
        assert_eq!(parsed.meta.sequence, 0xabcd);
        assert_eq!(parsed.payload, b"pong");
    }

    #[test]
    fn unrelated_reply_is_filtered() {
        let raw = [0, 0, 0, 0, 0x12, 0x34, 0x00, 0x09, 1, 2, 3];
        let parsed = parse_echo_reply(&raw).expect("must parse");
        assert!(is_related_reply(
            &parsed,
            EchoMeta {
                identifier: 0x1234,
                sequence: 0x0009
            }
        ));
        assert!(!is_related_reply(
            &parsed,
            EchoMeta {
                identifier: 0x4321,
                sequence: 0x0009
            }
        ));
    }
}
