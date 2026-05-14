use std::fmt;

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

pub const MAGIC: [u8; 4] = *b"I2T2";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Hello = 1,
    Open = 2,
    OpenOk = 3,
    OpenErr = 4,
    Data = 5,
    Fin = 6,
    Rst = 7,
    Ping = 8,
    Pong = 9,
}

impl TryFrom<u8> for FrameType {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Open),
            3 => Ok(Self::OpenOk),
            4 => Ok(Self::OpenErr),
            5 => Ok(Self::Data),
            6 => Ok(Self::Fin),
            7 => Ok(Self::Rst),
            8 => Ok(Self::Ping),
            9 => Ok(Self::Pong),
            _ => Err(WireError::InvalidFrameType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameType,
    pub stream_id: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: FrameType, stream_id: u32, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            stream_id,
            payload: payload.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFrame {
    pub session_id: u64,
    pub packet_no: u64,
    pub frame: Frame,
}

#[derive(Debug)]
pub enum WireError {
    InvalidLength,
    InvalidMagic,
    InvalidVersion(u8),
    InvalidFrameType(u8),
    PayloadTooLarge,
    Crypto,
    KeyDerive,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid wire length"),
            Self::InvalidMagic => write!(f, "invalid magic"),
            Self::InvalidVersion(v) => write!(f, "invalid protocol version {v}"),
            Self::InvalidFrameType(v) => write!(f, "invalid frame type {v}"),
            Self::PayloadTooLarge => write!(f, "payload too large"),
            Self::Crypto => write!(f, "authentication/decryption failed"),
            Self::KeyDerive => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for WireError {}

fn derive_key(
    psk: &[u8],
    salt: &[u8],
    direction: Direction,
    session_id: u64,
) -> Result<[u8; 32], WireError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), psk);
    let mut key = [0_u8; 32];
    let mut info = Vec::with_capacity(28);
    info.extend_from_slice(b"icmp2tunnel-v1-aead");
    info.push(direction as u8);
    info.extend_from_slice(&session_id.to_be_bytes());
    hk.expand(&info, &mut key)
        .map_err(|_| WireError::KeyDerive)?;
    Ok(key)
}

fn nonce(packet_no: u64) -> [u8; 12] {
    let mut out = [0_u8; 12];
    out[0..8].copy_from_slice(&packet_no.to_be_bytes());
    out
}

fn encode_frame_plain(frame: &Frame) -> Result<Vec<u8>, WireError> {
    let len = u32::try_from(frame.payload.len()).map_err(|_| WireError::PayloadTooLarge)?;
    let mut out = Vec::with_capacity(9 + frame.payload.len());
    out.push(frame.kind as u8);
    out.extend_from_slice(&frame.stream_id.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&frame.payload);
    Ok(out)
}

fn decode_frame_plain(input: &[u8]) -> Result<Frame, WireError> {
    if input.len() < 9 {
        return Err(WireError::InvalidLength);
    }
    let kind = FrameType::try_from(input[0])?;
    let stream_id = u32::from_be_bytes(
        input[1..5]
            .try_into()
            .map_err(|_| WireError::InvalidLength)?,
    );
    let len = u32::from_be_bytes(
        input[5..9]
            .try_into()
            .map_err(|_| WireError::InvalidLength)?,
    ) as usize;
    if input.len() != 9 + len {
        return Err(WireError::InvalidLength);
    }
    Ok(Frame {
        kind,
        stream_id,
        payload: input[9..].to_vec(),
    })
}

fn encode_header(
    session_id: u64,
    packet_no: u64,
    ciphertext_len: usize,
) -> Result<[u8; HEADER_LEN], WireError> {
    let ciphertext_len = u32::try_from(ciphertext_len).map_err(|_| WireError::PayloadTooLarge)?;
    let mut out = [0_u8; HEADER_LEN];
    out[0..4].copy_from_slice(&MAGIC);
    out[4] = VERSION;
    out[5] = 0;
    out[6..8].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    out[8..16].copy_from_slice(&session_id.to_be_bytes());
    out[16..24].copy_from_slice(&packet_no.to_be_bytes());
    out[24..28].copy_from_slice(&ciphertext_len.to_be_bytes());
    out[28..32].copy_from_slice(&0_u32.to_be_bytes());
    Ok(out)
}

fn decode_header(input: &[u8]) -> Result<(u64, u64, usize), WireError> {
    if input.len() < HEADER_LEN {
        return Err(WireError::InvalidLength);
    }
    if input[0..4] != MAGIC {
        return Err(WireError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(WireError::InvalidVersion(input[4]));
    }
    let header_len = u16::from_be_bytes(
        input[6..8]
            .try_into()
            .map_err(|_| WireError::InvalidLength)?,
    ) as usize;
    if header_len != HEADER_LEN {
        return Err(WireError::InvalidLength);
    }
    let session_id = u64::from_be_bytes(
        input[8..16]
            .try_into()
            .map_err(|_| WireError::InvalidLength)?,
    );
    let packet_no = u64::from_be_bytes(
        input[16..24]
            .try_into()
            .map_err(|_| WireError::InvalidLength)?,
    );
    let ciphertext_len = u32::from_be_bytes(
        input[24..28]
            .try_into()
            .map_err(|_| WireError::InvalidLength)?,
    ) as usize;
    Ok((session_id, packet_no, ciphertext_len))
}

pub fn seal(
    psk: &[u8],
    salt: &[u8],
    direction: Direction,
    session_id: u64,
    packet_no: u64,
    frame: &Frame,
) -> Result<Vec<u8>, WireError> {
    let plain = encode_frame_plain(frame)?;
    let ciphertext_len = plain
        .len()
        .checked_add(TAG_LEN)
        .ok_or(WireError::PayloadTooLarge)?;
    let header = encode_header(session_id, packet_no, ciphertext_len)?;
    let key = derive_key(psk, salt, direction, session_id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| WireError::Crypto)?;
    let nonce = nonce(packet_no);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &header,
            },
        )
        .map_err(|_| WireError::Crypto)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(
    psk: &[u8],
    salt: &[u8],
    direction: Direction,
    input: &[u8],
) -> Result<OpenedFrame, WireError> {
    let (session_id, packet_no, ciphertext_len) = decode_header(input)?;
    if input.len() != HEADER_LEN + ciphertext_len {
        return Err(WireError::InvalidLength);
    }
    let header = &input[..HEADER_LEN];
    let ciphertext = &input[HEADER_LEN..];
    let key = derive_key(psk, salt, direction, session_id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| WireError::Crypto)?;
    let nonce = nonce(packet_no);
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| WireError::Crypto)?;
    let frame = decode_frame_plain(&plain)?;
    Ok(OpenedFrame {
        session_id,
        packet_no,
        frame,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let frame = Frame::new(FrameType::Data, 7, b"hello".to_vec());
        let sealed = seal(b"psk", b"salt", Direction::ClientToServer, 1, 2, &frame).expect("seal");
        let opened = open(b"psk", b"salt", Direction::ClientToServer, &sealed).expect("open");
        assert_eq!(opened.session_id, 1);
        assert_eq!(opened.packet_no, 2);
        assert_eq!(opened.frame, frame);
    }

    #[test]
    fn direction_keys_do_not_interoperate() {
        let frame = Frame::new(FrameType::Data, 7, b"hello".to_vec());
        let sealed = seal(b"psk", b"salt", Direction::ClientToServer, 1, 2, &frame).expect("seal");
        assert!(open(b"psk", b"salt", Direction::ServerToClient, &sealed).is_err());
    }
}
