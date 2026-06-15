//! Direct side-by-side comparison: one full MARK-X migration vs. one
//! fresh TLS 1.3 hybrid handshake. Both establish a fresh
//! post-quantum-protected session key from the same set of primitives.
//!
//! The two BenchmarkGroup entries appear next to each other in
//! criterion's summary so the ratio is immediate.
//!
//! Run with:  cargo bench --bench compare_migration

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hkdf::Hkdf;
use markx::crypto::{
    ecdsa_p256_keypair, ecdsa_p256_sign, ecdsa_p256_verify, hmac_sha256, hmac_sha256_verify,
    mlkem768_decaps, mlkem768_encaps, mlkem768_keypair, sha256, sha256_concat,
};
use markx::{MarkXClient, MarkXPolicy, MarkXServer, StateStore};
use p256::ecdsa::{SigningKey as EcdsaSk, VerifyingKey as EcdsaPk};
use sha2::Sha256;

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

fn temp_state_path(tag: &str) -> std::path::PathBuf {
    let nonce: u64 = rand::random();
    std::env::temp_dir().join(format!("markx_cmp_{tag}_{nonce}.bin"))
}

fn fresh_markx_pair() -> (MarkXServer, MarkXClient, [u8; 32]) {
    let (sk_sig, pk_sig) = ecdsa_p256_keypair();
    let policy = MarkXPolicy::reference();
    let server_state = temp_state_path("server");
    let client_state = temp_state_path("client");
    let _ = std::fs::remove_file(&server_state);
    let _ = std::fs::remove_file(&client_state);
    let server = MarkXServer::new(sk_sig, policy.clone(), StateStore::new(&server_state));
    let client = MarkXClient::new(pk_sig, policy, StateStore::new(&client_state));
    let k_class: [u8; 32] = std::array::from_fn(|i| i as u8);
    (server, client, k_class)
}

/// Same crypto-equivalent TLS 1.3 hybrid handshake as in baseline_handshake.rs,
/// duplicated here so this bench is self-contained.
fn full_tls13_hybrid_handshake(sk_sig: &EcdsaSk, pk_sig: &EcdsaPk) -> [u8; 32] {
    let kp = mlkem768_keypair();
    let transcript_so_far = vec![0u8; 768];
    let transcript_hash_1 = sha256(&transcript_so_far);
    let sig = ecdsa_p256_sign(sk_sig, &transcript_hash_1);
    ecdsa_p256_verify(pk_sig, &transcript_hash_1, &sig).unwrap();
    let (ct, _ss_client) = mlkem768_encaps(&kp.pk).unwrap();
    let ss_server = mlkem768_decaps(&kp.sk, &ct).unwrap();
    let zero = [0u8; 32];
    let hk_early = Hkdf::<Sha256>::new(Some(&zero), &zero);
    let mut early = [0u8; 32];
    hk_early.expand(b"tls13 derived", &mut early).unwrap();
    let hk_hs = Hkdf::<Sha256>::new(Some(&early), &ss_server);
    let mut s_t = [0u8; 32];
    hk_hs.expand(b"tls13 s hs traffic", &mut s_t).unwrap();
    let mut c_t = [0u8; 32];
    hk_hs.expand(b"tls13 c hs traffic", &mut c_t).unwrap();
    let mut fin_key_s = [0u8; 32];
    hk_hs.expand(b"tls13 finished s", &mut fin_key_s).unwrap();
    let mut transcript_2 = transcript_so_far.clone();
    transcript_2.extend_from_slice(&ct);
    let th2 = sha256(&transcript_2);
    let server_finished = hmac_sha256(&fin_key_s, &th2);
    let mut fin_key_c = [0u8; 32];
    hk_hs.expand(b"tls13 finished c", &mut fin_key_c).unwrap();
    let mut transcript_3 = th2.to_vec();
    transcript_3.extend_from_slice(&server_finished);
    let th3 = sha256(&transcript_3);
    let client_finished = hmac_sha256(&fin_key_c, &th3);
    hmac_sha256_verify(&fin_key_s, &th2, &server_finished).unwrap();
    hmac_sha256_verify(&fin_key_c, &th3, &client_finished).unwrap();
    let mut derived = [0u8; 32];
    hk_hs.expand(b"tls13 derived", &mut derived).unwrap();
    let hk_master = Hkdf::<Sha256>::new(Some(&derived), &zero);
    let mut ats = [0u8; 32];
    hk_master.expand(b"tls13 c ap traffic", &mut ats).unwrap();
    ats
}

// ----------------------------------------------------------------------
// MARK-X crypto-only: same protocol logic as MarkXServer/MarkXClient
// but with NO durable state I/O. Apples-to-apples vs. the TLS 1.3
// hybrid baseline (which also has no state I/O).
// ----------------------------------------------------------------------

fn markx_crypto_only(sk_sig: &EcdsaSk, pk_sig: &EcdsaPk, k_class: &[u8; 32]) -> [u8; 32] {
    // Use markx::kdf for byte-exact equivalence with the reference impl.
    use markx::crypto::{hmac_sha256 as mac};
    use markx::policy::{alg_id, param_id, variant, MarkXPolicy};

    let policy = MarkXPolicy::reference();
    let policy_hash = policy.hash();
    let epoch: u32 = 1;
    let counter: u32 = 1;

    // ===== Phase 1 (server): keygen, ctx_1, sign m_1 =====
    let kp = mlkem768_keypair();
    let mut ctx1: Vec<u8> = Vec::with_capacity(1230);
    ctx1.extend_from_slice(&alg_id::ML_KEM.to_be_bytes());
    ctx1.extend_from_slice(&param_id::MLKEM_768.to_be_bytes());
    ctx1.extend_from_slice(&epoch.to_be_bytes());
    ctx1.extend_from_slice(&counter.to_be_bytes());
    ctx1.extend_from_slice(&policy_hash);
    ctx1.push(variant::A1);
    ctx1.extend_from_slice(&kp.pk);
    let to_sign = sha256_concat(&[b"MARK-X-v2-Bootstrap", &ctx1]);
    let sig = ecdsa_p256_sign(sk_sig, &to_sign);
    let mut m1 = ctx1.clone();
    m1.extend_from_slice(&sig);

    // ===== Phase 1' (client): verify sig =====
    let to_verify = sha256_concat(&[b"MARK-X-v2-Bootstrap", &ctx1]);
    ecdsa_p256_verify(pk_sig, &to_verify, &sig).unwrap();
    // (policy / monotonicity / variant checks: constant-time byte compares;
    //  measured separately as part of the protocol step bench in markx_phases.rs)

    // ===== Phase 2 (client): encap, derive k1, MAC tag1 =====
    let (ct, k_pq_c) = mlkem768_encaps(&kp.pk).unwrap();
    let no_ecdh: &[u8] = &[];
    let transcript = sha256_concat(&[&m1, &ct, no_ecdh]);
    let k1_c = markx::kdf::derive_k1(&k_pq_c, k_class, &transcript);
    let mut tag1_input = Vec::with_capacity(14 + 32);
    tag1_input.extend_from_slice(b"client-confirm");
    tag1_input.extend_from_slice(&transcript);
    let tag1 = mac(&k1_c, &tag1_input);

    // ===== Phase 2' (server): decap, verify tag1, derive K_trans/K_chain =====
    let k_pq_s = mlkem768_decaps(&kp.sk, &ct).unwrap();
    let k1_s = markx::kdf::derive_k1(&k_pq_s, k_class, &transcript);
    hmac_sha256_verify(&k1_s, &tag1_input, &tag1).unwrap();
    let k_trans_s = markx::kdf::derive_k_trans(&k_pq_s, k_class, epoch, counter, &policy_hash, &transcript);
    let _k_chain_s = markx::kdf::derive_k_chain(&k_pq_s, k_class, epoch, counter, &transcript);

    // ===== Phase 3 (server): build & send m_3 =====
    let mut tag2_input = Vec::with_capacity(13 + 4 + 4 + 2 + 32);
    tag2_input.extend_from_slice(b"promote-to-PQ");
    tag2_input.extend_from_slice(&epoch.to_be_bytes());
    tag2_input.extend_from_slice(&counter.to_be_bytes());
    tag2_input.extend_from_slice(&alg_id::ML_KEM.to_be_bytes());
    tag2_input.extend_from_slice(&policy_hash);
    let tag2 = mac(&k_trans_s, &tag2_input);
    // (no state commit -- crypto-only)

    // ===== Phase 3' (client): derive K_trans, verify tag2 =====
    let k_trans_c = markx::kdf::derive_k_trans(&k_pq_c, k_class, epoch, counter, &policy_hash, &transcript);
    hmac_sha256_verify(&k_trans_c, &tag2_input, &tag2).unwrap();

    k_trans_c
}

// ----------------------------------------------------------------------
// Side-by-side bench
// ----------------------------------------------------------------------

fn comparison(c: &mut Criterion) {
    let mut g = c.benchmark_group("migration_vs_rehandshake");

    // MARK-X migration (crypto-only, no durable state I/O).
    // Apples-to-apples vs. the TLS 1.3 baseline below, which also has
    // no state I/O. This isolates the cryptographic cost of the
    // protocol from the systems-level cost of persisting Assumption 2.13's
    // monotonic state.
    g.bench_function("markx_migration_crypto_only", |b| {
        let k_class: [u8; 32] = std::array::from_fn(|i| i as u8);
        b.iter_batched_ref(
            || ecdsa_p256_keypair(),
            |(sk, pk)| {
                let kt = markx_crypto_only(sk, pk, &k_class);
                black_box(kt);
            },
            BatchSize::SmallInput,
        )
    });

    // MARK-X migration (full, with durable file-backed state I/O).
    // This is what a deployment using a flat-file state store sees.
    // A TPM/Secure-Enclave deployment would replace each fsync (~ms
    // on APFS) with an NV-counter update (~10-100 us).
    g.bench_function("markx_migration_with_durable_state", |b| {
        b.iter_batched_ref(
            || fresh_markx_pair(),
            |(server, client, k_class)| {
                let m1 = server.initiate_migration(*k_class).unwrap();
                let m2 = client.handle_bootstrap(&m1, *k_class).unwrap();
                let m3 = server.handle_confirm_and_promote(&m2).unwrap();
                let k_trans = client.handle_promote(&m3).unwrap();
                black_box(k_trans);
            },
            BatchSize::SmallInput,
        )
    });

    // Full TLS 1.3 hybrid re-handshake: cost of starting a fresh
    // session every time the deployed algorithm changes.
    g.bench_function("full_tls13_hybrid_rehandshake", |b| {
        b.iter_batched_ref(
            || ecdsa_p256_keypair(),
            |(sk, pk)| {
                let ats = full_tls13_hybrid_handshake(sk, pk);
                black_box(ats);
            },
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

criterion_group!(benches, comparison);
criterion_main!(benches);
