//! On-the-wire forms of `m_1`, `m_2`, `m_3` (Construction V.I).  
// In a TLS deployment these would be the bodies of the new
//! handshake messages `MarkXBootstrap`, `MarkXConfirm`, `MarkXPromote`
//! (§7).  Here we emit them as plain byte vectors.
//!
//! All three messages use the same big-endian, length-prefixed encoding
//! defined in [`crate::codec`].

use crate::codec::{Ctx1, Reader, WriteBE};
use crate::error::{MarkXError, Result};

/// `m_1 = (ctx_1, sigma_1)` — server-to-client bootstrap.
#[derive(Clone, Debug)]
pub struct MarkXBootstrap {
    pub ctx_1: Ctx1,
    pub signature: Vec<u8>, // DER-encoded ECDSA signature
}

impl MarkXBootstrap {
    pub fn encode(&self) -> Vec<u8> {
        let ctx_bytes = self.ctx_1.encode();
        let mut out = Vec::with_capacity(4 + ctx_bytes.len() + 4 + self.signature.len());
        out.push_u32(ctx_bytes.len() as u32);
        out.extend_from_slice(&ctx_bytes);
        out.push_lp16(&self.signature);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let ctx_len = r.read_u32()? as usize;
        let ctx_bytes = r.read_fixed(ctx_len)?;
        let ctx_1 = Ctx1::decode(ctx_bytes)?;
        let signature = r.read_lp16()?.to_vec();
        r.finish()?;
        Ok(MarkXBootstrap { ctx_1, signature })
    }
}

/// `m_2 = (ct_pq, X, tag_1)` — client-to-server confirmation.
/// `X` is empty for Variant A1.
#[derive(Clone, Debug)]
pub struct MarkXConfirm {
    pub kem_ciphertext: Vec<u8>,
    pub ecdh_share: Vec<u8>, // empty for A1
    pub tag1: [u8; 32],
}

impl MarkXConfirm {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.kem_ciphertext.len() + self.ecdh_share.len() + 36);
        out.push_lp16(&self.kem_ciphertext);
        out.push_lp16(&self.ecdh_share);
        out.extend_from_slice(&self.tag1);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let kem_ciphertext = r.read_lp16()?.to_vec();
        let ecdh_share = r.read_lp16()?.to_vec();
        let mut tag1 = [0u8; 32];
        tag1.copy_from_slice(r.read_fixed(32)?);
        r.finish()?;
        Ok(MarkXConfirm {
            kem_ciphertext,
            ecdh_share,
            tag1,
        })
    }
}

/// `m_3 = ("promote-to-PQ", e, ctr, tag_2)` — server-to-client promotion.
#[derive(Clone, Debug)]
pub struct MarkXPromote {
    pub label: [u8; 13], // ASCII "promote-to-PQ" (13 chars)
    pub epoch: u32,
    pub counter: u32,
    pub tag2: [u8; 32],
}

pub const PROMOTE_LABEL: [u8; 13] = *b"promote-to-PQ";

impl MarkXPromote {
    pub fn new(epoch: u32, counter: u32, tag2: [u8; 32]) -> Self {
        MarkXPromote {
            label: PROMOTE_LABEL,
            epoch,
            counter,
            tag2,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + 4 + 4 + 32);
        out.extend_from_slice(&self.label);
        out.push_u32(self.epoch);
        out.push_u32(self.counter);
        out.extend_from_slice(&self.tag2);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let mut label = [0u8; 13];
        label.copy_from_slice(r.read_fixed(13)?);
        if label != PROMOTE_LABEL {
            return Err(MarkXError::MalformedMessage);
        }
        let epoch = r.read_u32()?;
        let counter = r.read_u32()?;
        let mut tag2 = [0u8; 32];
        tag2.copy_from_slice(r.read_fixed(32)?);
        r.finish()?;
        Ok(MarkXPromote {
            label,
            epoch,
            counter,
            tag2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_ctx1() -> Ctx1 {
        Ctx1 {
            alg_id: 0x0301,
            param_id: 0x02,
            epoch: 1,
            counter: 1,
            policy_hash: [0xAB; 32],
            variant: 0x01,
            pq_public_key: vec![0xCC; 100],
            ecdh_share: vec![],
        }
    }

    #[test]
    fn bootstrap_roundtrip() {
        let m = MarkXBootstrap {
            ctx_1: dummy_ctx1(),
            signature: vec![0xDE; 71], // typical DER-encoded ECDSA P-256 sig
        };
        let b = m.encode();
        let m2 = MarkXBootstrap::decode(&b).unwrap();
        assert_eq!(m.signature, m2.signature);
    }

    #[test]
    fn confirm_roundtrip() {
        let m = MarkXConfirm {
            kem_ciphertext: vec![0xCC; 1088],
            ecdh_share: vec![],
            tag1: [0xEE; 32],
        };
        let b = m.encode();
        let m2 = MarkXConfirm::decode(&b).unwrap();
        assert_eq!(m.kem_ciphertext, m2.kem_ciphertext);
        assert_eq!(m.tag1, m2.tag1);
    }

    #[test]
    fn promote_roundtrip() {
        let m = MarkXPromote::new(5, 9, [0xFF; 32]);
        let b = m.encode();
        let m2 = MarkXPromote::decode(&b).unwrap();
        assert_eq!(m.epoch, m2.epoch);
        assert_eq!(m.counter, m2.counter);
        assert_eq!(m.tag2, m2.tag2);
    }

    #[test]
    fn promote_wrong_label_rejected() {
        let mut m = MarkXPromote::new(5, 9, [0xFF; 32]);
        m.label[0] ^= 1;
        let b = m.encode();
        assert!(MarkXPromote::decode(&b).is_err());
    }
}
