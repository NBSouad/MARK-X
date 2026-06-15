//! Baseline: crypto-equivalent simulation of a TLS 1.3 hybrid handshake.
//!
//! This is the fair comparison point for MARK-X: a fresh full handshake
//! that establishes the same kind of post-quantum session key (an
//! ML-KEM-768 hybrid PSK + ECDSA-P256 authentication) using the
//! *same* underlying crates. Network framing, X.509 parsing, ALPN,
//! TCP, and TLS record layer are deliberately excluded because they
//! are not part of MARK-X either; this isolates the cryptographic
//! cost of a full re-handshake.
//!
//! The simulated handshake follows the canonical TLS 1.3 sequence,
//! crypto only:
//!
//!   Server side:
//!     1. ML-KEM-768 keygen                   -> (pk_pq, sk_pq)
//!     2. Build server_keyshare ||
//!        server_hello transcript hash        -> SHA-256 (~256 B)
//!     3. ECDSA-P256 sign (CertificateVerify) -> sig
//!     4. ML-KEM-768 decaps when m_kem rcvd   -> K_pq
//!     5. HKDF-Extract+Expand (handshake     )-> handshake_secret
//!     6. HKDF-Expand (master_secret labels  )-> master_secret + ats
//!     7. HMAC-SHA-256 Finished               -> server_finished
//!
//!   Client side:
//!     1. ECDSA-P256 verify (CertificateVerify)
//!     2. ML-KEM-768 encaps                   -> (ct_pq, K_pq)
//!     3. HKDF-Extract+Expand                 -> handshake_secret
//!     4. HKDF-Expand                          -> master_secret + ats
//!     5. HMAC-SHA-256 Finished               -> client_finished
//!     6. HMAC-SHA-256 verify (server_finished)
//!
//! This is what TLS 1.3 with a hybrid X25519+ML-KEM-768 group does
//! end-to-end, modulo (a) the classical ECDH (we drop it because
//! TLS-A1 already pre-shared a classical channel secret in the MARK-X
//! comparison) and (b) certificate-chain verification (one extra
//! signature verify per cert; we count one verify which is the
//! deepest-meaningful cost).
//!
//! Run with:  cargo bench --bench baseline_handshake

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hkdf::Hkdf;
use markx::crypto::{
    ecdsa_p256_keypair, ecdsa_p256_sign, ecdsa_p256_verify, hmac_sha256, hmac_sha256_verify,
    mlkem768_decaps, mlkem768_encaps, mlkem768_keypair, sha256,
};
use p256::ecdsa::{SigningKey as EcdsaSk, VerifyingKey as EcdsaPk};
use sha2::Sha256;

// ----------------------------------------------------------------------
// Crypto-only TLS 1.3 hybrid handshake (server + client roles inlined)
// ----------------------------------------------------------------------

/// Run one full crypto-equivalent TLS 1.3 hybrid handshake.
/// Both parties' work is done in this function for direct cost summing.
fn baseline_handshake(sk_sig: &EcdsaSk, pk_sig: &EcdsaPk) -> [u8; 32] {
    // --- Server: keygen + cert sign + transcript ---
    let kp = mlkem768_keypair();
    // Transcript so far: imagine ClientHello (~512 B) || ServerHello || keyshare.
    // We hash a representative 768-byte buffer (typical TLS 1.3 hello transcript).
    let transcript_so_far = vec![0u8; 768];
    let transcript_hash_1 = sha256(&transcript_so_far);
    // CertificateVerify: sign the handshake-context-bound transcript hash.
    let sig = ecdsa_p256_sign(sk_sig, &transcript_hash_1);

    // --- Client: cert verify + KEM encap ---
    ecdsa_p256_verify(pk_sig, &transcript_hash_1, &sig).unwrap();
    let (ct, ss_client) = mlkem768_encaps(&kp.pk).unwrap();

    // --- Server: KEM decap ---
    let ss_server = mlkem768_decaps(&kp.sk, &ct).unwrap();
    assert_eq!(ss_client, ss_server);

    // --- Both sides: TLS 1.3 key schedule (HKDF). ---
    // Early secret = HKDF-Extract(salt=0, ikm=0||PSK).  For ML-KEM hybrid,
    // ikm = derived_handshake_secret from prior schedule.
    let zero = [0u8; 32];
    let hk_early = Hkdf::<Sha256>::new(Some(&zero), &zero);
    let mut early = [0u8; 32];
    hk_early.expand(b"tls13 derived", &mut early).unwrap();

    // Handshake secret = HKDF-Extract(salt=derived, ikm=ECDHE||KEM).
    // We use the ML-KEM shared secret directly here (A1 absorbs the
    // classical ECDH into a pre-shared channel secret in the MARK-X
    // comparison; here we mirror the same shape: one 32-byte ikm).
    let hk_hs = Hkdf::<Sha256>::new(Some(&early), &ss_server);
    let mut server_hs_traffic = [0u8; 32];
    hk_hs.expand(b"tls13 s hs traffic", &mut server_hs_traffic).unwrap();
    let mut client_hs_traffic = [0u8; 32];
    hk_hs.expand(b"tls13 c hs traffic", &mut client_hs_traffic).unwrap();

    // Server Finished = HMAC(finished_key, transcript_hash_2).
    // Derive finished_key with one more HKDF-Expand and compute the MAC.
    let mut fin_key_s = [0u8; 32];
    hk_hs.expand(b"tls13 finished s", &mut fin_key_s).unwrap();
    let transcript_hash_2 = sha256(&[transcript_so_far.as_slice(), &ct].concat());
    let server_finished = hmac_sha256(&fin_key_s, &transcript_hash_2);

    // Client Finished = HMAC(finished_key_c, transcript_hash_3).
    let mut fin_key_c = [0u8; 32];
    hk_hs.expand(b"tls13 finished c", &mut fin_key_c).unwrap();
    let mut hh3 = transcript_hash_2.to_vec();
    hh3.extend_from_slice(&server_finished);
    let transcript_hash_3 = sha256(&hh3);
    let client_finished = hmac_sha256(&fin_key_c, &transcript_hash_3);

    // Both sides verify each other's Finished.
    hmac_sha256_verify(&fin_key_s, &transcript_hash_2, &server_finished).unwrap();
    hmac_sha256_verify(&fin_key_c, &transcript_hash_3, &client_finished).unwrap();

    // Master secret + application traffic secret (ats).
    let mut derived_for_master = [0u8; 32];
    hk_hs.expand(b"tls13 derived", &mut derived_for_master).unwrap();
    let hk_master = Hkdf::<Sha256>::new(Some(&derived_for_master), &zero);
    let mut ats = [0u8; 32];
    hk_master.expand(b"tls13 c ap traffic", &mut ats).unwrap();
    ats
}

// ----------------------------------------------------------------------
// Benches
// ----------------------------------------------------------------------

fn baseline_full(c: &mut Criterion) {
    let mut g = c.benchmark_group("baseline_tls13_hybrid");

    g.bench_function("full_handshake_crypto_only", |b| {
        b.iter_batched_ref(
            || ecdsa_p256_keypair(),
            |(sk, pk)| {
                let ats = baseline_handshake(sk, pk);
                black_box(ats);
            },
            BatchSize::SmallInput,
        )
    });

    // Break it down for completeness.
    g.bench_function("server_cert_sign", |b| {
        let (sk, _) = ecdsa_p256_keypair();
        let msg = sha256(&vec![0u8; 768]);
        b.iter(|| black_box(ecdsa_p256_sign(&sk, &msg)))
    });
    g.bench_function("client_cert_verify", |b| {
        let (sk, pk) = ecdsa_p256_keypair();
        let msg = sha256(&vec![0u8; 768]);
        let sig = ecdsa_p256_sign(&sk, &msg);
        b.iter(|| ecdsa_p256_verify(&pk, &msg, &sig).unwrap())
    });
    g.bench_function("key_schedule_hkdf_chain", |b| {
        let zero = [0u8; 32];
        let ss = [42u8; 32];
        b.iter(|| {
            let hk_early = Hkdf::<Sha256>::new(Some(&zero), &zero);
            let mut early = [0u8; 32];
            hk_early.expand(b"tls13 derived", &mut early).unwrap();
            let hk_hs = Hkdf::<Sha256>::new(Some(&early), &ss);
            let mut s_traffic = [0u8; 32];
            hk_hs.expand(b"tls13 s hs traffic", &mut s_traffic).unwrap();
            let mut c_traffic = [0u8; 32];
            hk_hs.expand(b"tls13 c hs traffic", &mut c_traffic).unwrap();
            let mut derived = [0u8; 32];
            hk_hs.expand(b"tls13 derived", &mut derived).unwrap();
            let hk_master = Hkdf::<Sha256>::new(Some(&derived), &zero);
            let mut ats = [0u8; 32];
            hk_master.expand(b"tls13 c ap traffic", &mut ats).unwrap();
            black_box(ats);
        })
    });

    g.finish();
}

criterion_group!(benches, baseline_full);
criterion_main!(benches);
