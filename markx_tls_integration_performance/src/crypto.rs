//! Concrete cryptographic primitives.
//!
//! The MARK-X protocol is algorithm-agnostic at the abstract level: it
//! treats $\mathsf{KEM}$ and $\Sigma$ as opaque IND-CCA and EUF-CMA secure
//! schemes.  This module instantiates them with **real** primitives:
//!
//! * **PQ KEM** = ML-KEM-768 (FIPS 203)  via the `pqcrypto-mlkem` crate,
//!   which links to the PQClean reference C implementation.
//! * **Classical signature** = ECDSA-P256 (FIPS 186-5) via the `p256` and
//!   `ecdsa` crates (pure Rust, constant-time).
//! * **Hash** = SHA-256 via the `sha2` crate.
//! * **MAC** = HMAC-SHA-256 via the `hmac` crate.
//!
//! All keys generated here use the operating system's CSPRNG via
//! `rand::rngs::OsRng`.

use crate::error::{MarkXError, Result};
use ecdsa::signature::{Signer, Verifier};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature as EcdsaSig, SigningKey as EcdsaSk, VerifyingKey as EcdsaPk};
use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ---------- ML-KEM-768 ----------

pub const MLKEM768_PK_LEN: usize = 1184;
pub const MLKEM768_SK_LEN: usize = 2400;
pub const MLKEM768_CT_LEN: usize = 1088;
pub const MLKEM768_SS_LEN: usize = 32;

pub struct PqKemKeyPair {
    pub pk: Vec<u8>, // 1184 bytes
    pub sk: Vec<u8>, // 2400 bytes (kept opaque)
}

pub fn mlkem768_keypair() -> PqKemKeyPair {
    let (pk, sk) = mlkem768::keypair();
    PqKemKeyPair {
        pk: pk.as_bytes().to_vec(),
        sk: sk.as_bytes().to_vec(),
    }
}

pub fn mlkem768_encaps(pk_bytes: &[u8]) -> Result<(Vec<u8>, [u8; MLKEM768_SS_LEN])> {
    let pk = mlkem768::PublicKey::from_bytes(pk_bytes)
        .map_err(|_| MarkXError::MalformedMessage)?;
    let (ss, ct) = mlkem768::encapsulate(&pk);
    let mut k = [0u8; MLKEM768_SS_LEN];
    k.copy_from_slice(ss.as_bytes());
    Ok((ct.as_bytes().to_vec(), k))
}

pub fn mlkem768_decaps(sk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; MLKEM768_SS_LEN]> {
    let sk = mlkem768::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| MarkXError::DecryptError)?;
    let ct = mlkem768::Ciphertext::from_bytes(ct_bytes)
        .map_err(|_| MarkXError::DecryptError)?;
    let ss = mlkem768::decapsulate(&ct, &sk);
    let mut k = [0u8; MLKEM768_SS_LEN];
    k.copy_from_slice(ss.as_bytes());
    Ok(k)
}

// ---------- ECDSA-P256 ----------

/// Generate a fresh ECDSA-P256 signing keypair, returning DER-encoded
/// SEC1 forms.  In production these would live in an HSM or KMS.
pub fn ecdsa_p256_keypair() -> (EcdsaSk, EcdsaPk) {
    let sk = EcdsaSk::random(&mut rand::rngs::OsRng);
    let pk = *sk.verifying_key();
    (sk, pk)
}

/// Sign a message with ECDSA-P256.  The message MUST already be the hash
/// (32 bytes for SHA-256) per the convention used in the v3 paper.  We
/// hash internally for safety; if you pass a 32-byte message you'll get
/// `SHA-256(message)` signed, which matches the paper's
/// `H("MARK-X-v2-Bootstrap" || ctx_1)` construction.
pub fn ecdsa_p256_sign(sk: &EcdsaSk, message: &[u8]) -> Vec<u8> {
    // p256's ecdsa::SigningKey signs SHA-256 of the message by default.
    let sig: EcdsaSig = sk.sign(message);
    sig.to_der().as_bytes().to_vec()
}

pub fn ecdsa_p256_verify(pk: &EcdsaPk, message: &[u8], sig_der: &[u8]) -> Result<()> {
    let sig = EcdsaSig::from_der(sig_der).map_err(|_| MarkXError::BadSignature)?;
    pk.verify(message, &sig).map_err(|_| MarkXError::BadSignature)
}

// ---------- Hashing and MAC ----------

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Constant-time verification of a 32-byte HMAC-SHA-256 tag.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(expected_tag).map_err(|_| MarkXError::DecryptError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem768_endpoint_consistent() {
        let kp = mlkem768_keypair();
        assert_eq!(kp.pk.len(), MLKEM768_PK_LEN);
        assert_eq!(kp.sk.len(), MLKEM768_SK_LEN);
        let (ct, ss_a) = mlkem768_encaps(&kp.pk).unwrap();
        assert_eq!(ct.len(), MLKEM768_CT_LEN);
        let ss_b = mlkem768_decaps(&kp.sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn mlkem768_decaps_wrong_sk_yields_nonmatching_ss() {
        // ML-KEM uses implicit rejection: wrong sk does not error but
        // produces a different shared secret.
        let kp1 = mlkem768_keypair();
        let kp2 = mlkem768_keypair();
        let (ct, ss_a) = mlkem768_encaps(&kp1.pk).unwrap();
        let ss_b = mlkem768_decaps(&kp2.sk, &ct).unwrap();
        assert_ne!(ss_a, ss_b);
    }

    #[test]
    fn ecdsa_p256_roundtrip() {
        let (sk, pk) = ecdsa_p256_keypair();
        let msg = b"hello MARK-X";
        let sig = ecdsa_p256_sign(&sk, msg);
        assert!(ecdsa_p256_verify(&pk, msg, &sig).is_ok());
        assert!(ecdsa_p256_verify(&pk, b"different", &sig).is_err());
    }

    #[test]
    fn hmac_verify_constant_time() {
        let key = [0u8; 32];
        let data = b"some data";
        let tag = hmac_sha256(&key, data);
        assert!(hmac_sha256_verify(&key, data, &tag).is_ok());
        // Flip one bit
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(hmac_sha256_verify(&key, data, &bad).is_err());
    }
}
