#![forbid(unsafe_code)]
#![deny(warnings)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const MAGIC: [u8; 4] = *b"I2T1";
pub const VERSION: u8 = 1;
pub const PLAIN_HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer = 0,
    ServerToClient = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MuxOp {
    Hello = 0x01,
    HelloReply = 0x02,
    Open = 0x10,
    OpenOk = 0x11,
    OpenErr = 0x12,
    Data = 0x20,
    Ack = 0x21,
    Window = 0x22,
    Fin = 0x23,
    Rst = 0x24,
    Ping = 0x30,
    Pong = 0x31,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainHeader {
    pub version: u8,
    pub flags: u8,
    pub direction: Direction,
    pub session_id: u32,
    pub packet_number: u64,
    pub payload_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub op: MuxOp,
    pub stream_id: u32,
    pub window: u32,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum ProtoError {
    InvalidLength,
    InvalidMagic,
    InvalidVersion,
    InvalidDirection,
    InvalidOp,
    PayloadTooLarge,
    Crypto,
    Replay,
    KeyDerive,
}

pub fn encode_header(h: &PlainHeader) -> Result<[u8; PLAIN_HEADER_LEN], ProtoError> {
    if h.version != VERSION {
        return Err(ProtoError::InvalidVersion);
    }
    let mut out = [0_u8; PLAIN_HEADER_LEN];
    out[0..4].copy_from_slice(&MAGIC);
    out[4] = h.version;
    out[5] = h.flags;
    out[6] = h.direction as u8;
    out[7] = 0;
    out[8..12].copy_from_slice(&h.session_id.to_be_bytes());
    out[12..20].copy_from_slice(&h.packet_number.to_be_bytes());
    out[20..24].copy_from_slice(&h.payload_len.to_be_bytes());
    Ok(out)
}

pub fn decode_header(data: &[u8]) -> Result<PlainHeader, ProtoError> {
    if data.len() != PLAIN_HEADER_LEN {
        return Err(ProtoError::InvalidLength);
    }
    if data[0..4] != MAGIC {
        return Err(ProtoError::InvalidMagic);
    }
    if data[4] != VERSION {
        return Err(ProtoError::InvalidVersion);
    }
    let direction = match data[6] {
        0 => Direction::ClientToServer,
        1 => Direction::ServerToClient,
        _ => return Err(ProtoError::InvalidDirection),
    };
    Ok(PlainHeader {
        version: data[4],
        flags: data[5],
        direction,
        session_id: u32::from_be_bytes(
            data[8..12]
                .try_into()
                .map_err(|_| ProtoError::InvalidLength)?,
        ),
        packet_number: u64::from_be_bytes(
            data[12..20]
                .try_into()
                .map_err(|_| ProtoError::InvalidLength)?,
        ),
        payload_len: u32::from_be_bytes(
            data[20..24]
                .try_into()
                .map_err(|_| ProtoError::InvalidLength)?,
        ),
    })
}

pub fn encode_frame(frame: &MuxFrame) -> Result<Vec<u8>, ProtoError> {
    let body_len = u32::try_from(frame.body.len()).map_err(|_| ProtoError::PayloadTooLarge)?;
    let mut out = Vec::with_capacity(13 + frame.body.len());
    out.push(frame.op as u8);
    out.extend_from_slice(&frame.stream_id.to_be_bytes());
    out.extend_from_slice(&frame.window.to_be_bytes());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&frame.body);
    Ok(out)
}

pub fn decode_frame(data: &[u8]) -> Result<MuxFrame, ProtoError> {
    if data.len() < 13 {
        return Err(ProtoError::InvalidLength);
    }
    let op = decode_op(data[0])?;
    let stream_id = u32::from_be_bytes(
        data[1..5]
            .try_into()
            .map_err(|_| ProtoError::InvalidLength)?,
    );
    let window = u32::from_be_bytes(
        data[5..9]
            .try_into()
            .map_err(|_| ProtoError::InvalidLength)?,
    );
    let body_len = u32::from_be_bytes(
        data[9..13]
            .try_into()
            .map_err(|_| ProtoError::InvalidLength)?,
    ) as usize;
    if data.len() != 13 + body_len {
        return Err(ProtoError::InvalidLength);
    }
    Ok(MuxFrame {
        op,
        stream_id,
        window,
        body: data[13..].to_vec(),
    })
}

fn decode_op(v: u8) -> Result<MuxOp, ProtoError> {
    Ok(match v {
        0x01 => MuxOp::Hello,
        0x02 => MuxOp::HelloReply,
        0x10 => MuxOp::Open,
        0x11 => MuxOp::OpenOk,
        0x12 => MuxOp::OpenErr,
        0x20 => MuxOp::Data,
        0x21 => MuxOp::Ack,
        0x22 => MuxOp::Window,
        0x23 => MuxOp::Fin,
        0x24 => MuxOp::Rst,
        0x30 => MuxOp::Ping,
        0x31 => MuxOp::Pong,
        _ => return Err(ProtoError::InvalidOp),
    })
}

pub fn derive_key(psk: &[u8], salt: &[u8]) -> Result<[u8; 32], ProtoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), psk);
    let mut key = [0_u8; 32];
    hk.expand(b"icmp2tunnel-v1-key", &mut key)
        .map_err(|_| ProtoError::KeyDerive)?;
    Ok(key)
}

pub fn derive_nonce(session_id: u32, packet_number: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[0..4].copy_from_slice(&session_id.to_be_bytes());
    nonce[4..12].copy_from_slice(&packet_number.to_be_bytes());
    nonce
}

pub fn aead_seal(key: &[u8; 32], header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let parsed = decode_header(header)?;
    let nonce_bytes = derive_nonce(parsed.session_id, parsed.packet_number);
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| ProtoError::Crypto)?;
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: header,
            },
        )
        .map_err(|_| ProtoError::Crypto)
}

pub fn aead_open(key: &[u8; 32], header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let parsed = decode_header(header)?;
    let nonce_bytes = derive_nonce(parsed.session_id, parsed.packet_number);
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| ProtoError::Crypto)?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| ProtoError::Crypto)
}

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    max_seen: u64,
    bitmap: u128,
}

impl ReplayWindow {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_seen: 0,
            bitmap: 0,
        }
    }

    pub fn check_and_mark(&mut self, pn: u64) -> Result<(), ProtoError> {
        if pn > self.max_seen {
            let shift = (pn - self.max_seen).min(127) as u32;
            self.bitmap = (self.bitmap << shift) | 1;
            self.max_seen = pn;
            return Ok(());
        }
        let delta = self.max_seen - pn;
        if delta >= 128 {
            return Err(ProtoError::Replay);
        }
        let bit = 1_u128 << delta;
        if (self.bitmap & bit).ct_eq(&bit).into() {
            return Err(ProtoError::Replay);
        }
        self.bitmap |= bit;
        Ok(())
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> PlainHeader {
        PlainHeader {
            version: VERSION,
            flags: 0x5a,
            direction: Direction::ClientToServer,
            session_id: 7,
            packet_number: 42,
            payload_len: 5,
        }
    }

    #[test]
    fn header_roundtrip() {
        let h = header();
        let e = encode_header(&h).expect("encode header");
        let d = decode_header(&e).expect("decode header");
        assert_eq!(h, d);
    }

    #[test]
    fn frame_roundtrip() {
        let f = MuxFrame {
            op: MuxOp::Data,
            stream_id: 9,
            window: 100,
            body: b"hello".to_vec(),
        };
        let e = encode_frame(&f).expect("encode frame");
        let d = decode_frame(&e).expect("decode frame");
        assert_eq!(f, d);
    }

    #[test]
    fn malformed_input_never_panics() {
        for n in 0..32 {
            let buf = vec![0_u8; n];
            let _ = decode_header(&buf);
            let _ = decode_frame(&buf);
        }
    }

    #[test]
    fn aead_rejects_modified_header_and_ciphertext() {
        let key = derive_key(b"psk", b"salt").expect("derive key");
        let h = encode_header(&header()).expect("encode header");
        let ct = aead_seal(&key, &h, b"payload").expect("seal");

        let mut h2 = h;
        h2[5] ^= 0x1;
        assert!(aead_open(&key, &h2, &ct).is_err());

        let mut ct2 = ct.clone();
        ct2[0] ^= 0x1;
        assert!(aead_open(&key, &h, &ct2).is_err());
    }

    #[test]
    fn replay_window_rejects_duplicate() {
        let mut rw = ReplayWindow::new();
        assert!(rw.check_and_mark(1).is_ok());
        assert!(rw.check_and_mark(2).is_ok());
        assert!(rw.check_and_mark(1).is_err());
    }

    #[test]
    fn golden_vector_stable() {
        let h = encode_header(&header()).expect("encode header");
        assert_eq!(
            h,
            [73, 50, 84, 49, 1, 90, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 5]
        );
    }

    #[test]
    fn max_size_frame() {
        let f = MuxFrame {
            op: MuxOp::Data,
            stream_id: 1,
            window: 1,
            body: vec![1_u8; 1024 * 1024],
        };
        let encoded = encode_frame(&f).expect("encode frame");
        let decoded = decode_frame(&encoded).expect("decode frame");
        assert_eq!(decoded.body.len(), 1024 * 1024);
    }
}
