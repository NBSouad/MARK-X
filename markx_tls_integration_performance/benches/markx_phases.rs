//! Microbenchmarks of the four MARK-X protocol steps, plus the
//! cryptographic primitives they use.
//!
//! Run with:
//!   cargo bench --bench markx_phases
//!
//! Each benchmark uses `iter_batched` to amortise setup outside the
//! timed body, so the reported time is the cost of the step itself, not
//! of constructing fresh keys. State stores are written to `$TMPDIR`,
//! which on macOS and modern Linux is RAM-backed; the file-I/O cost is
//! reported in `markx_full_migration` for transparency.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use markx::crypto::{
    ecdsa_p256_keypair, ecdsa_p256_sign, ecdsa_p256_verify, hmac_sha256, hmac_sha256_verify,
    mlkem768_decaps, mlkem768_encaps, mlkem768_keypair, sha256_concat,
};
use markx::{MarkXClient, MarkXPolicy, MarkXServer, StateStore};

// ----------------------------------------------------------------------
// Primitive-level benches (axis 1, raw)
// ----------------------------------------------------------------------

fn primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("primitives");

    // ML-KEM-768 (FIPS 203) via PQClean
    g.bench_function("mlkem768_keypair", |b| {
        b.iter(|| black_box(mlkem768_keypair()))
    });
    g.bench_function("mlkem768_encaps", |b| {
        let kp = mlkem768_keypair();
        b.iter(|| {
            let (ct, ss) = mlkem768_encaps(&kp.pk).unwrap();
            black_box((ct, ss))
        })
    });
    g.bench_function("mlkem768_decaps", |b| {
        let kp = mlkem768_keypair();
        let (ct, _) = mlkem768_encaps(&kp.pk).unwrap();
        b.iter(|| black_box(mlkem768_decaps(&kp.sk, &ct).unwrap()))
    });

    // ECDSA-P256 (FIPS 186-5)
    g.bench_function("ecdsa_p256_keypair", |b| {
        b.iter(|| black_box(ecdsa_p256_keypair()))
    });
    g.bench_function("ecdsa_p256_sign", |b| {
        let (sk, _) = ecdsa_p256_keypair();
        let msg = [0u8; 32];
        b.iter(|| black_box(ecdsa_p256_sign(&sk, &msg)))
    });
    g.bench_function("ecdsa_p256_verify", |b| {
        let (sk, pk) = ecdsa_p256_keypair();
        let msg = [0u8; 32];
        let sig = ecdsa_p256_sign(&sk, &msg);
        b.iter(|| ecdsa_p256_verify(&pk, &msg, &sig).unwrap())
    });

    // SHA-256 (typical ctx_1-sized input ~1280 bytes)
    g.bench_function("sha256_1280B", |b| {
        let buf = vec![0u8; 1280];
        b.iter(|| black_box(sha256_concat(&[&buf])))
    });

    // HMAC-SHA-256
    g.bench_function("hmac_sha256_64B", |b| {
        let key = [0u8; 32];
        let data = vec![0u8; 64];
        b.iter(|| black_box(hmac_sha256(&key, &data)))
    });
    g.bench_function("hmac_sha256_verify_64B", |b| {
        let key = [0u8; 32];
        let data = vec![0u8; 64];
        let tag = hmac_sha256(&key, &data);
        b.iter(|| hmac_sha256_verify(&key, &data, &tag).unwrap())
    });

    g.finish();
}

// ----------------------------------------------------------------------
// Protocol-step benches (axis 1, MARK-X four phases)
// ----------------------------------------------------------------------

fn temp_state_path(tag: &str) -> std::path::PathBuf {
    let nonce: u64 = rand::random();
    std::env::temp_dir().join(format!("markx_bench_{tag}_{nonce}.bin"))
}

/// Construct a fresh server and client pair, sharing one ECDSA keypair,
/// one policy, fresh state-store files in TMPDIR, and a deterministic
/// k_class. Returns server, client, and k_class.
fn fresh_pair() -> (MarkXServer, MarkXClient, [u8; 32]) {
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

fn protocol_steps(c: &mut Criterion) {
    let mut g = c.benchmark_group("markx_protocol");

    // Phase 1 (server side): initiate_migration produces m_1.
    g.bench_function("server_phase_1", |b| {
        b.iter_batched_ref(
            || fresh_pair(),
            |(server, _client, k_class)| {
                black_box(server.initiate_migration(*k_class).unwrap());
            },
            BatchSize::SmallInput,
        )
    });

    // Phase 1' + 2 (client side): handle_bootstrap verifies m_1, encapsulates,
    // and returns m_2. This is the "client verify+encap" step.
    g.bench_function("client_phase_1prime_and_2", |b| {
        b.iter_batched_ref(
            || {
                let (mut server, client, k_class) = fresh_pair();
                let m1 = server.initiate_migration(k_class).unwrap();
                (server, client, k_class, m1)
            },
            |(_server, client, k_class, m1)| {
                black_box(client.handle_bootstrap(m1, *k_class).unwrap());
            },
            BatchSize::SmallInput,
        )
    });

    // Phase 2' + 3 (server side): handle_confirm_and_promote decapsulates,
    // verifies tag_1, derives K_trans/K_chain, emits m_3.
    g.bench_function("server_phase_2prime_and_3", |b| {
        b.iter_batched_ref(
            || {
                let (mut server, mut client, k_class) = fresh_pair();
                let m1 = server.initiate_migration(k_class).unwrap();
                let m2 = client.handle_bootstrap(&m1, k_class).unwrap();
                (server, client, m2)
            },
            |(server, _client, m2)| {
                black_box(server.handle_confirm_and_promote(m2).unwrap());
            },
            BatchSize::SmallInput,
        )
    });

    // Phase 3' (client side): handle_promote verifies tag_2 and commits.
    g.bench_function("client_phase_3prime", |b| {
        b.iter_batched_ref(
            || {
                let (mut server, mut client, k_class) = fresh_pair();
                let m1 = server.initiate_migration(k_class).unwrap();
                let m2 = client.handle_bootstrap(&m1, k_class).unwrap();
                let m3 = server.handle_confirm_and_promote(&m2).unwrap();
                (client, m3)
            },
            |(client, m3)| {
                black_box(client.handle_promote(m3).unwrap());
            },
            BatchSize::SmallInput,
        )
    });

    // End-to-end: one complete migration (server + client work, in-process).
    // Wire size for reference: ~2.5 KB total.
    g.throughput(Throughput::Bytes(2487));
    g.bench_function("end_to_end_migration", |b| {
        b.iter_batched_ref(
            || fresh_pair(),
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

    g.finish();
}

criterion_group!(benches, primitives, protocol_steps);
criterion_main!(benches);
