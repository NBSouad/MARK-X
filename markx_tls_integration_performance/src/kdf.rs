//! HKDF-SHA-256 wrappers using the domain-separated labels from §7 of
//!  MARK-X.  Modelled as a random oracle in the proofs
//! (Theorems 2--4 of the paper).
//!
//! All three derivations (`k_1`, `K_trans`, `K_chain`) extract a single
//! HKDF PRK from `K_pq ‖ K_class`, then expand under distinct info
//! strings.  Domain separation is provided by the leading ASCII label.

use crate::codec::WriteBE;
use hkdf::Hkdf;
use sha2::Sha256;

pub const KEY_LEN: usize = 32;

/// $k_1$ = HKDF($K_\mathsf{pq} \,\|\, K_\mathsf{class}$,
///   "MARK-X-Phase2" $\,\|\,$ transcript).
///
/// Used to MAC the client-to-server confirmation in Phase 2.
pub fn derive_k1(k_pq: &[u8], k_class: &[u8], transcript: &[u8; 32]) -> [u8; KEY_LEN] {
    let mut ikm = Vec::with_capacity(k_pq.len() + k_class.len());
    ikm.extend_from_slice(k_pq);
    ikm.extend_from_slice(k_class);
    let mut info = Vec::with_capacity(20 + 32);
    info.extend_from_slice(b"MARK-X-v2-Phase2");
    info.extend_from_slice(transcript);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm).expect("HKDF expand never fails for 32 bytes");
    okm
}

/// $K_\mathsf{trans}$ = HKDF($K_\mathsf{pq} \,\|\, K_\mathsf{class}$,
///   "MARK-X-Trans" $\,\|\, e \,\|\, \ctr \,\|\, \policy_\mathsf{hash}
///   \,\|\,$ transcript).
pub fn derive_k_trans(
    k_pq: &[u8],
    k_class: &[u8],
    epoch: u32,
    counter: u32,
    policy_hash: &[u8; 32],
    transcript: &[u8; 32],
) -> [u8; KEY_LEN] {
    let mut ikm = Vec::with_capacity(k_pq.len() + k_class.len());
    ikm.extend_from_slice(k_pq);
    ikm.extend_from_slice(k_class);
    let mut info: Vec<u8> = Vec::with_capacity(15 + 4 + 4 + 32 + 32);
    info.extend_from_slice(b"MARK-X-v2-Trans");
    info.push_u32(epoch);
    info.push_u32(counter);
    info.extend_from_slice(policy_hash);
    info.extend_from_slice(transcript);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm).expect("HKDF expand never fails for 32 bytes");
    okm
}

/// $K_\mathsf{chain}$ = HKDF($K_\mathsf{pq} \,\|\, K_\mathsf{class}$,
///   "MARK-X-Chain" $\,\|\, e \,\|\, \ctr \,\|\,$ transcript).
///
/// Note the absence of `policy_hash` from the info string here: this is
/// deliberate so that $K_\mathsf{chain}$ remains usable across epochs
/// whose policies differ slightly but compose monotonically (Mode B,
/// §6 of the v3 paper).
pub fn derive_k_chain(
    k_pq: &[u8],
    k_class: &[u8],
    epoch: u32,
    counter: u32,
    transcript: &[u8; 32],
) -> [u8; KEY_LEN] {
    let mut ikm = Vec::with_capacity(k_pq.len() + k_class.len());
    ikm.extend_from_slice(k_pq);
    ikm.extend_from_slice(k_class);
    let mut info: Vec<u8> = Vec::with_capacity(15 + 4 + 4 + 32);
    info.extend_from_slice(b"MARK-X-v2-Chain");
    info.push_u32(epoch);
    info.push_u32(counter);
    info.extend_from_slice(transcript);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm).expect("HKDF expand never fails for 32 bytes");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k1_is_deterministic() {
        let k_pq = [0xAA; 32];
        let k_class = [0xBB; 32];
        let tr = [0xCC; 32];
        let k1_a = derive_k1(&k_pq, &k_class, &tr);
        let k1_b = derive_k1(&k_pq, &k_class, &tr);
        assert_eq!(k1_a, k1_b);
    }

    #[test]
    fn domain_separation() {
        // Same inputs into k_trans and k_chain with same epoch/ctr/transcript
        // must produce different outputs (different info labels).
        let k_pq = [0xAA; 32];
        let k_class = [0xBB; 32];
        let tr = [0xCC; 32];
        let ph = [0xDD; 32];
        let kt = derive_k_trans(&k_pq, &k_class, 1, 1, &ph, &tr);
        let kc = derive_k_chain(&k_pq, &k_class, 1, 1, &tr);
        assert_ne!(kt, kc);
    }

    #[test]
    fn epoch_separation() {
        let k_pq = [0xAA; 32];
        let k_class = [0xBB; 32];
        let tr = [0xCC; 32];
        let ph = [0xDD; 32];
        let k1 = derive_k_trans(&k_pq, &k_class, 1, 1, &ph, &tr);
        let k2 = derive_k_trans(&k_pq, &k_class, 2, 1, &ph, &tr);
        assert_ne!(k1, k2);
    }
}
