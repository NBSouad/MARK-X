# Benchmark Results

**Hardware:** Apple Silicon (macOS, ARM64), single-threaded, release profile (`opt-level=3 lto=thin`).
**Cargo:** 1.95.0, **rustc:** 1.95.0.
**Statistical method:** criterion 0.5, 100 samples per bench, 3 s warm-up, 5 s measurement.
Values reported as `lower / median / upper` of the 95% confidence interval on the mean.

## Primitives

| Operation | Lower | Median | Upper |
|---|---:|---:|---:|
| ML-KEM-768 keygen (PQClean) | 8.44 µs | 8.53 µs | 8.62 µs |
| ML-KEM-768 encapsulate | 9.24 µs | 9.38 µs | 9.54 µs |
| ML-KEM-768 decapsulate | 10.91 µs | 10.95 µs | 11.00 µs |
| ECDSA-P256 keygen | 106.51 µs | 110.31 µs | 116.06 µs |
| ECDSA-P256 sign | 132.63 µs | 136.23 µs | 142.13 µs |
| ECDSA-P256 verify | 221.63 µs | 223.40 µs | 225.49 µs |
| SHA-256 of 1280 B | 3.97 µs | 4.07 µs | 4.22 µs |
| HMAC-SHA-256 (64 B input) | 938 ns | 941 ns | 944 ns |
| HMAC-SHA-256 verify (64 B) | 961 ns | 967 ns | 974 ns |

## MARK-X protocol steps (with file-backed StateStore)

| Step | Lower | Median | Upper | Notes |
|---|---:|---:|---:|---|
| Server Phase 1 (`initiate_migration`) | 148.32 µs | 150.68 µs | 154.36 µs | no fsync |
| Client Phase 1′+2 (`handle_bootstrap`) | 242.40 µs | 245.04 µs | 248.57 µs | no fsync |
| Server Phase 2′+3 (`handle_confirm_and_promote`) | 4.81 ms | 4.87 ms | 4.94 ms | **1× fsync** |
| Client Phase 3′ (`handle_promote`) | 4.82 ms | 4.96 ms | 5.12 ms | **1× fsync** |
| End-to-end migration (file-backed state) | 11.23 ms | 11.38 ms | 11.53 ms | 2× fsync |

## Side-by-side comparison

| Workload | Lower | Median | Upper |
|---|---:|---:|---:|
| MARK-X full migration (crypto only, no state I/O) | 405.81 µs | 414.69 µs | 427.99 µs |
| MARK-X full migration (with durable file-backed state) | 10.90 ms | 11.07 ms | 11.23 ms |
| TLS 1.3 hybrid full re-handshake (crypto only) | 387.48 µs | 390.91 µs | 395.05 µs |

## Wire size (from `cargo run --example demo_migration`)

| Message | Bytes |
|---|---:|
| `m_1` (ctx_1 + sig_1) | ~1310 |
| `m_2` (ct_pq + tag_1) | 1124 |
| `m_3` (label + e + ctr + tag_2) | 53 |
| **Total wire data** | **≈ 2487** |

## Headline comparison

**Pure-crypto cost (both exclude network and state I/O):**
- MARK-X full migration: **415 µs**
- TLS 1.3 hybrid full re-handshake: **391 µs**
- MARK-X overhead vs. baseline: **+6%** (24 µs)

**Why MARK-X is not faster crypto-wise:** it performs roughly the same primitive operations (1 sign + 1 verify + 1 KEM keygen/encap/decap + several HKDF expands + 2 HMACs), plus one additional HKDF for `K_chain`. The advantage of MARK-X over a fresh handshake is therefore not in pure-crypto CPU cost but in:

1. **No new TCP / TLS hello negotiation** — saves multiple round trips on WAN links.
2. **No certificate-chain verification** — a real TLS handshake performs 2–3 sign-verifies (our baseline counts 1).
3. **No interruption of application data** — the existing session continues.
4. **Smaller wire** — ~2.5 KB vs ~5–10 KB for a real TLS 1.3 hybrid handshake including extensions and certificate chain.

**Durable-state cost on this machine:** the two `fsync` calls (server state-commit, client state-commit) add ≈ 10 ms over APFS. In a deployment that backs the monotonic state with a TPM 2.0 NV counter or a Secure Enclave (the recommended production setup per the paper), each commit would replace the fsync with an NV-counter increment, typically 10–100 µs, bringing the end-to-end cost back down to roughly **600 µs**.
