//! Trusted local migration policy $\pi^\mathsf{local}$ (Definition 3.8 of
//! MARK-X) and the policy-acceptance check (Equations (4)--(8) of
//! Construction V.I).
//!
//! Every honest client holds an authentic copy of `MarkXPolicy` provisioned
//! through a trust-anchor channel independent of any migration message
//! (Assumption 3).  The implementation enforces:
//!
//! 1. **Canonical encoding for hashing.**  `policy_hash` is computed over a
//!    byte sequence with a fixed field order so that an honest server and
//!    an honest client agree byte-for-byte on $H(\pi)$.  Without this the
//!    policy-hash check (Equation (4)) is ill-defined.
//!
//! 2. **Field-level allow-lists.**  Even if `policy_hash` matched (which it
//!    must), each of `alg_id`, `param_id`, and `variant` is re-checked
//!    against the allow-list, providing defence-in-depth against confusion
//!    attacks between two valid policy instances.
//!
//! 3. **Minimum epoch.**  The local policy carries a floor that the
//!    announcement must satisfy; this is *in addition to* the monotonicity
//!    check against persistent state in `state.rs`.

use crate::error::{MarkXError, Result};
use sha2::{Digest, Sha256};

/// Algorithm identifier byte assignments (§7, Table 1).
pub mod alg_id {
    pub const ML_KEM: u16 = 0x0301; // FIPS 203
    pub const ML_DSA: u16 = 0x0401; // FIPS 204 (signature; unused in current Mode-A bootstrap)
}

pub mod param_id {
    pub const MLKEM_512: u8 = 0x01;
    pub const MLKEM_768: u8 = 0x02;
    pub const MLKEM_1024: u8 = 0x03;
}

pub mod variant {
    /// Variant A1: pre-shared classical secret (§V.B).
    pub const A1: u8 = 0x01;
    /// Variant A2: explicit ECDH (§V.B).
    pub const A2: u8 = 0x02;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkXPolicy {
    pub allowed_algorithms: Vec<u16>,
    /// Each entry is a `(alg_id, param_id)` pair.
    pub allowed_parameter_sets: Vec<(u16, u8)>,
    pub allowed_variants: Vec<u8>,
    pub min_epoch: u32,
    /// Bitmask: bit 0 = HYBRID allowed, bit 1 = PQ_ONLY allowed.
    pub allowed_modes: u8,
}

impl MarkXPolicy {
    /// A conservative reference policy: ML-KEM-768 only, both variants
    /// allowed, hybrid mode permitted, minimum epoch 1.
    pub fn reference() -> Self {
        MarkXPolicy {
            allowed_algorithms: vec![alg_id::ML_KEM],
            allowed_parameter_sets: vec![(alg_id::ML_KEM, param_id::MLKEM_768)],
            allowed_variants: vec![variant::A1, variant::A2],
            min_epoch: 1,
            allowed_modes: 0b01, // HYBRID only
        }
    }

    /// Canonical byte encoding for hashing.  This is the *only* function
    /// that decides what $H(\pi)$ means; both client and server must call
    /// it identically.  The format is:
    ///
    /// ```text
    /// u32 len_algs ‖ (u16)^*               — sorted asc
    /// u32 len_params ‖ (u16‖u8)^*          — sorted lex
    /// u32 len_variants ‖ u8^*              — sorted asc
    /// u32 min_epoch
    /// u8 allowed_modes
    /// ```
    pub fn canonical_encode(&self) -> Vec<u8> {
        let mut algs: Vec<u16> = self.allowed_algorithms.clone();
        algs.sort_unstable();
        algs.dedup();

        let mut params: Vec<(u16, u8)> = self.allowed_parameter_sets.clone();
        params.sort_unstable();
        params.dedup();

        let mut variants: Vec<u8> = self.allowed_variants.clone();
        variants.sort_unstable();
        variants.dedup();

        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&(algs.len() as u32).to_be_bytes());
        for a in &algs {
            out.extend_from_slice(&a.to_be_bytes());
        }
        out.extend_from_slice(&(params.len() as u32).to_be_bytes());
        for (a, p) in &params {
            out.extend_from_slice(&a.to_be_bytes());
            out.push(*p);
        }
        out.extend_from_slice(&(variants.len() as u32).to_be_bytes());
        out.extend_from_slice(&variants);
        out.extend_from_slice(&self.min_epoch.to_be_bytes());
        out.push(self.allowed_modes);
        out
    }

    /// SHA-256 of the canonical encoding.  This is `policy_hash` of
    /// Equations (1)--(4) of Construction 4.4.
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.canonical_encode();
        let mut h = Sha256::new();
        h.update(&bytes);
        h.finalize().into()
    }

    /// Policy-acceptance check.  Returns `Ok(())` iff the announced fields
    /// in $m_1$ satisfy Equations (5)--(8) of Construction V.I with respect
    /// to `self`.  The caller (the MARK-X client driver) is responsible for
    /// also calling [`Self::hash`] and comparing against `m_1.policy_hash`
    /// (Equation (4)).
    pub fn accepts(&self, alg: u16, param: u8, var: u8, epoch: u32) -> Result<()> {
        if !self.allowed_algorithms.contains(&alg) {
            return Err(MarkXError::AlgorithmNotAllowed);
        }
        if !self.allowed_parameter_sets.contains(&(alg, param)) {
            return Err(MarkXError::AlgorithmNotAllowed);
        }
        if !self.allowed_variants.contains(&var) {
            return Err(MarkXError::AlgorithmNotAllowed);
        }
        if epoch < self.min_epoch {
            return Err(MarkXError::EpochRollback);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_is_stable() {
        // Permuted construction → same canonical bytes
        let p1 = MarkXPolicy {
            allowed_algorithms: vec![alg_id::ML_KEM, alg_id::ML_DSA],
            allowed_parameter_sets: vec![(alg_id::ML_KEM, 0x02), (alg_id::ML_DSA, 0x01)],
            allowed_variants: vec![variant::A2, variant::A1],
            min_epoch: 5,
            allowed_modes: 0b11,
        };
        let p2 = MarkXPolicy {
            allowed_algorithms: vec![alg_id::ML_DSA, alg_id::ML_KEM],
            allowed_parameter_sets: vec![(alg_id::ML_DSA, 0x01), (alg_id::ML_KEM, 0x02)],
            allowed_variants: vec![variant::A1, variant::A2],
            min_epoch: 5,
            allowed_modes: 0b11,
        };
        assert_eq!(p1.canonical_encode(), p2.canonical_encode());
        assert_eq!(p1.hash(), p2.hash());
    }

    #[test]
    fn accepts_happy_path() {
        let p = MarkXPolicy::reference();
        assert!(p.accepts(alg_id::ML_KEM, param_id::MLKEM_768, variant::A1, 1).is_ok());
    }

    #[test]
    fn rejects_disallowed_alg() {
        let p = MarkXPolicy::reference();
        assert_eq!(
            p.accepts(0x9999, param_id::MLKEM_768, variant::A1, 1),
            Err(MarkXError::AlgorithmNotAllowed)
        );
    }

    #[test]
    fn rejects_disallowed_param() {
        let p = MarkXPolicy::reference();
        assert_eq!(
            p.accepts(alg_id::ML_KEM, param_id::MLKEM_512, variant::A1, 1),
            Err(MarkXError::AlgorithmNotAllowed)
        );
    }

    #[test]
    fn rejects_disallowed_variant() {
        let mut p = MarkXPolicy::reference();
        p.allowed_variants = vec![variant::A1]; // remove A2
        assert_eq!(
            p.accepts(alg_id::ML_KEM, param_id::MLKEM_768, variant::A2, 1),
            Err(MarkXError::AlgorithmNotAllowed)
        );
    }

    #[test]
    fn rejects_low_epoch() {
        let mut p = MarkXPolicy::reference();
        p.min_epoch = 10;
        assert_eq!(
            p.accepts(alg_id::ML_KEM, param_id::MLKEM_768, variant::A1, 5),
            Err(MarkXError::EpochRollback)
        );
    }
}
