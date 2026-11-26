use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce, Tag,
};
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAGIC: [u8; 2] = [0x53, 0x47]; // "SG"
pub const VERSION: u8 = 0x02;
pub const HEADER_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const PAD_BOUNDARY: usize = 256;
pub const KEY_ROTATE_INTERVAL_SECS: u64 = 15 * 60;
pub const KEY_ROTATE_MAX_BYTES: u64 = 1024 * 1024 * 1024; // 1 GB

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Challenge = 0x01,
    AuthProof = 0x02,
    SessionGrant = 0x03,
    OpenStream = 0x04,
    Data = 0x05,
    WindowUpdate = 0x06,
    KeyRotate = 0x07,
    PingPong = 0x08,
    CloseStream = 0x09,
    KillSwitch = 0x0A,
}

impl TryFrom<u8> for Opcode {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Opcode::Challenge),
            0x02 => Ok(Opcode::AuthProof),
            0x03 => Ok(Opcode::SessionGrant),
            0x04 => Ok(Opcode::OpenStream),
            0x05 => Ok(Opcode::Data),
            0x06 => Ok(Opcode::WindowUpdate),
            0x07 => Ok(Opcode::KeyRotate),
            0x08 => Ok(Opcode::PingPong),
            0x09 => Ok(Opcode::CloseStream),
            0x0A => Ok(Opcode::KillSwitch),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SMPv2 opcode: 0x{value:02x}"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub opcode: Opcode,
    pub stream_id: u32,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

pub struct SmpCipher {
    key: [u8; 32],
    direction: u8,
    next_seq: u64,
    bytes_processed: u64,
}

impl SmpCipher {
    pub fn new(key: [u8; 32], direction: u8) -> Self {
        Self {
            key,
            direction,
            next_seq: 1,
            bytes_processed: 0,
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_seq
    }

    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    pub fn should_rotate(&self) -> bool {
        self.bytes_processed >= KEY_ROTATE_MAX_BYTES
    }

    pub fn ratchet(&mut self, seq: u64) {
        let mut hasher = Sha3_256::new();
        hasher.update(self.key);
        hasher.update(b"signum-ratchet");
        hasher.update(seq.to_be_bytes());
        let derived = hasher.finalize();
        self.key.copy_from_slice(&derived);
        self.bytes_processed = 0;
    }

    pub fn zeroize(&mut self) {
        for b in &mut self.key {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }

    fn make_nonce(direction: u8, seq: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[0] = direction;
        n[4..12].copy_from_slice(&seq.to_be_bytes());
        Nonce::from(n)
    }

    pub fn seal(
        &mut self,
        opcode: Opcode,
        stream_id: u32,
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        if plaintext.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload exceeds 65535 bytes",
            ));
        }

        let seq = self.next_seq;
        self.next_seq = self
            .next_seq
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "sequence overflow"))?;

        let actual_len = plaintext.len();
        let padded_len = if actual_len == 0 {
            0
        } else {
            let rounded = ((actual_len + PAD_BOUNDARY - 1) / PAD_BOUNDARY) * PAD_BOUNDARY;
            rounded.min(u16::MAX as usize)
        };

        let mut buf = vec![0u8; HEADER_LEN + padded_len + TAG_LEN];
        buf[0..2].copy_from_slice(&MAGIC);
        buf[2] = VERSION;
        buf[3] = opcode as u8;
        buf[4..8].copy_from_slice(&stream_id.to_be_bytes());
        buf[8..16].copy_from_slice(&seq.to_be_bytes());
        buf[16..18].copy_from_slice(&(actual_len as u16).to_be_bytes());
        buf[18..20].copy_from_slice(&(padded_len as u16).to_be_bytes());

        if padded_len > 0 {
            buf[HEADER_LEN..HEADER_LEN + actual_len].copy_from_slice(plaintext);
            if padded_len > actual_len {
                rand::thread_rng().fill_bytes(&mut buf[HEADER_LEN + actual_len..HEADER_LEN + padded_len]);
            }
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = Self::make_nonce(self.direction, seq);
        let mut aad = [0u8; 20];
        aad.copy_from_slice(&buf[0..20]);

        let tag = cipher
            .encrypt_in_place_detached(
                &nonce,
                &aad,
                &mut buf[HEADER_LEN..HEADER_LEN + padded_len],
            )
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "AEAD encrypt failed"))?;

        buf[20..32].copy_from_slice(&tag[0..12]);
        buf[HEADER_LEN + padded_len..HEADER_LEN + padded_len + TAG_LEN].copy_from_slice(&tag);
        self.bytes_processed += (HEADER_LEN + padded_len + TAG_LEN) as u64;

        Ok(buf)
    }

    pub fn open_body(
        &mut self,
        header: &[u8; HEADER_LEN],
        body_and_tag: &mut [u8],
    ) -> io::Result<Frame> {
        if header[0..2] != MAGIC || header[2] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SMPv2 magic or version",
            ));
        }

        let opcode = Opcode::try_from(header[3])?;
        let stream_id = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let seq = u64::from_be_bytes(header[8..16].try_into().unwrap());
        let actual_len = u16::from_be_bytes(header[16..18].try_into().unwrap()) as usize;
        let padded_len = u16::from_be_bytes(header[18..20].try_into().unwrap()) as usize;

        if seq != self.next_seq {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("sequence mismatch: expected {}, got {seq}", self.next_seq),
            ));
        }
        if actual_len > padded_len || body_and_tag.len() != padded_len + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SMPv2 frame lengths",
            ));
        }

        let (payload_slice, tag_slice) = body_and_tag.split_at_mut(padded_len);
        if header[20..32] != tag_slice[0..12] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header auth tag prefix mismatch",
            ));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = Self::make_nonce(self.direction, seq);
        let tag = Tag::from_slice(tag_slice);

        cipher
            .decrypt_in_place_detached(&nonce, &header[0..20], payload_slice, tag)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "AEAD auth failed"))?;

        self.next_seq += 1;
        self.bytes_processed += (HEADER_LEN + padded_len + TAG_LEN) as u64;

        Ok(Frame {
            opcode,
            stream_id,
            sequence: seq,
            payload: payload_slice[..actual_len].to_vec(),
        })
    }
}

impl Drop for SmpCipher {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    cipher: &mut SmpCipher,
    opcode: Opcode,
    stream_id: u32,
    plaintext: &[u8],
) -> io::Result<()> {
    let encoded = cipher.seal(opcode, stream_id, plaintext)?;
    writer.write_all(&encoded).await?;
    writer.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &mut SmpCipher,
) -> io::Result<Frame> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    if header[0..2] != MAGIC || header[2] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SMPv2 magic or version",
        ));
    }
    let padded_len = u16::from_be_bytes(header[18..20].try_into().unwrap()) as usize;
    let mut body_and_tag = vec![0u8; padded_len + TAG_LEN];
    reader.read_exact(&mut body_and_tag).await?;
    cipher.open_body(&header, &mut body_and_tag)
}
