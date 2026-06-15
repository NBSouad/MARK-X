//! Wire encoding for $\mathsf{ctx}_1$ and the three MARK-X messages.
//!
//! The encoding is the implementation realisation of Definition 3.1
//! (Injective Encoding): every variable-length field is
//! preceded by its length in a fixed number of bytes, so the byte sequence
//! uniquely determines the tuple it encodes.
//!
//! This is the *only* place wire bytes are produced or consumed; both
//! `client.rs` and `server.rs` go through these functions exclusively.

use crate::error::{MarkXError, Result};

/// Big-endian encoding helpers.  We use `Vec<u8>` rather than a sink trait
/// because the messages are tiny and Vec keeps the code obvious.

pub(crate) trait WriteBE {
    fn push_u16(&mut self, v: u16);
    fn push_u32(&mut self, v: u32);
    fn push_lp16(&mut self, bytes: &[u8]);
}
impl WriteBE for Vec<u8> {
    fn push_u16(&mut self, v: u16) {
        self.extend_from_slice(&v.to_be_bytes());
    }
    fn push_u32(&mut self, v: u32) {
        self.extend_from_slice(&v.to_be_bytes());
    }
    /// Length-prefixed (u16) byte vector.  Length is in network byte order.
    fn push_lp16(&mut self, bytes: &[u8]) {
        assert!(bytes.len() <= u16::MAX as usize, "lp16 field too long");
        self.push_u16(bytes.len() as u16);
        self.extend_from_slice(bytes);
    }
}

/// Cursor-based reader producing a `MalformedMessage` error on any
/// truncation.
pub(crate) struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.buf.len() {
            return Err(MarkXError::MalformedMessage);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }
    pub fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.buf.len() {
            return Err(MarkXError::MalformedMessage);
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    pub fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.buf.len() {
            return Err(MarkXError::MalformedMessage);
        }
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
    pub fn read_fixed(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(MarkXError::MalformedMessage);
        }
        let v = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(v)
    }
    pub fn read_lp16(&mut self) -> Result<&'a [u8]> {
        let n = self.read_u16()? as usize;
        self.read_fixed(n)
    }
    pub fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(MarkXError::MalformedMessage);
        }
        Ok(())
    }
}

/// The structured form of `ctx_1` as produced by the server and consumed
/// by the client (§7).  We keep public-key bytes as a
/// `Vec<u8>` so that this codec is algorithm-agnostic.
#[derive(Clone, Debug)]
pub struct Ctx1 {
    pub alg_id: u16,
    pub param_id: u8,
    pub epoch: u32,
    pub counter: u32,
    pub policy_hash: [u8; 32],
    pub variant: u8,
    pub pq_public_key: Vec<u8>,
    /// ECDH share for variant A2.  Empty for A1.
    pub ecdh_share: Vec<u8>,
}

impl Ctx1 {
    /// Canonical injective encoding.  Field order matches Table 1 of
    /// the paper.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.pq_public_key.len() + self.ecdh_share.len());
        out.push_u16(self.alg_id);
        out.push(self.param_id);
        out.push_u32(self.epoch);
        out.push_u32(self.counter);
        out.extend_from_slice(&self.policy_hash);
        out.push(self.variant);
        out.push_lp16(&self.pq_public_key);
        out.push_lp16(&self.ecdh_share);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let alg_id = r.read_u16()?;
        let param_id = r.read_u8()?;
        let epoch = r.read_u32()?;
        let counter = r.read_u32()?;
        let mut policy_hash = [0u8; 32];
        policy_hash.copy_from_slice(r.read_fixed(32)?);
        let variant = r.read_u8()?;
        let pq_public_key = r.read_lp16()?.to_vec();
        let ecdh_share = r.read_lp16()?.to_vec();
        r.finish()?;
        Ok(Ctx1 {
            alg_id,
            param_id,
            epoch,
            counter,
            policy_hash,
            variant,
            pq_public_key,
            ecdh_share,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx1_roundtrip() {
        let c = Ctx1 {
            alg_id: 0x0301,
            param_id: 0x02,
            epoch: 7,
            counter: 3,
            policy_hash: [0xAB; 32],
            variant: 0x01,
            pq_public_key: vec![0xCC; 1184], // ML-KEM-768 pk size
            ecdh_share: vec![],
        };
        let bytes = c.encode();
        let c2 = Ctx1::decode(&bytes).unwrap();
        assert_eq!(c.alg_id, c2.alg_id);
        assert_eq!(c.param_id, c2.param_id);
        assert_eq!(c.epoch, c2.epoch);
        assert_eq!(c.counter, c2.counter);
        assert_eq!(c.policy_hash, c2.policy_hash);
        assert_eq!(c.variant, c2.variant);
        assert_eq!(c.pq_public_key, c2.pq_public_key);
        assert_eq!(c.ecdh_share, c2.ecdh_share);
    }

    #[test]
    fn ctx1_truncated_rejected() {
        let c = Ctx1 {
            alg_id: 0x0301,
            param_id: 0x02,
            epoch: 7,
            counter: 3,
            policy_hash: [0xAB; 32],
            variant: 0x01,
            pq_public_key: vec![0xCC; 100],
            ecdh_share: vec![],
        };
        let bytes = c.encode();
        // Truncate by one byte
        assert!(Ctx1::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn ctx1_trailing_garbage_rejected() {
        let c = Ctx1 {
            alg_id: 0x0301,
            param_id: 0x02,
            epoch: 7,
            counter: 3,
            policy_hash: [0xAB; 32],
            variant: 0x01,
            pq_public_key: vec![0xCC; 100],
            ecdh_share: vec![],
        };
        let mut bytes = c.encode();
        bytes.push(0xFF);
        assert!(Ctx1::decode(&bytes).is_err());
    }
}
