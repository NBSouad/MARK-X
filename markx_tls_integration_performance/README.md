# MARK-X Reference Implementation and Performance benchmarks (benches)

This is the buildable reference implementation accompanying the MARK-X
paper (Migration-Aware Authenticated Re-Key Exchange).  It is the
artifact referenced in §VII (TLS 1.3 Migration) and §VIII, providing
a complete in-process realisation of **Mode A, Variant A1** with real
post-quantum cryptography.

## What this artifact demonstrates

* The full three-phase MARK-X protocol of Construction §V.B.
* Every check from Phase 1, including the **trusted
  local policy** check.
* Real cryptography: **ML-KEM-768** (FIPS 203) via `pqcrypto-mlkem` →
  PQClean, **ECDSA-P256** (FIPS 186-5) via the `p256` crate.
* Persistent monotonic state with strict rollback rejection, the
  software realisation of Assumption 3.13.
* Each of the five rejection branches matched 1-to-1 with the TLS alert
  subcodes proposed.

## What it is *not*

* Not Variant A2 (ECDH).  The architecture supports it; only A1 is
  implemented as the recommended TLS profile.
* Not Mode B (self-sustaining); the chain-key derivation is in place
  (`derive_k_chain` is called and committed) but no chain-bootstrap
  driver is exposed yet.
* Not a network library.  The drivers are pure state machines; the §7
  TLS extension is in the paper, the wire format is exact, but
  end-to-end TLS plumbing is left our for integrators.

## How to verify

Requires `cargo` (Rust 1.75 or later).  The crate has been pinned to
work on Rust 1.75 because of one transitive dependency (`base64ct`)
that began requiring Rust 1.85 in version 1.7+; the pin lives in
`Cargo.toml`.

```bash
cd markx
cargo build           # builds the library + dependencies
cargo test            # runs 23 unit tests + 11 integration tests
cargo run --example demo_migration
```

Expected `cargo test` output: `34 passed; 0 failed`.

Expected demo output:

```
=== MARK-X reference implementation — demo migration ===

[*] Policy hash:      <SHA-256 of canonical(pi)>
[*] Shared K_class:   <32-byte hex>

[1] Server: initiate_migration(k_class)
    m_1 wire size:    ~1310 bytes
[2] Client: handle_bootstrap(m_1)  — checks signature, policy, monotonicity
    m_2 wire size:    1124 bytes
[3] Server: handle_confirm_and_promote(m_2)  — decaps, derives K_trans, emits m_3
    m_3 wire size:    53 bytes
[4] Client: handle_promote(m_3)  — verifies tag_2, commits state
    K_trans:          <32-byte hex>

[OK] Server state:   epoch=1 counter=1 pk_pq_len=1184
[OK] Client state:   epoch=1 counter=1 pk_pq_len=1184

Total wire data: ~2487 bytes
```

The observed total wire data (≈ 2.5 KB) matches the §VIII of
"approximately 2.4 KB" within ECDSA-DER signature framing variability.

## What the tests prove

### Unit tests (23)

| Module | Test | What it proves |
|---|---|---|
| `codec` | `ctx1_roundtrip` | Injective encoding is bijective |
| `codec` | `ctx1_truncated_rejected` | Parser detects under-length input |
| `codec` | `ctx1_trailing_garbage_rejected` | Parser detects trailing bytes |
| `crypto` | `mlkem768_endpoint_consistent` | Real PQClean ML-KEM-768 encaps↔decaps agree |
| `crypto` | `mlkem768_decaps_wrong_sk_yields_nonmatching_ss` | ML-KEM implicit rejection |
| `crypto` | `ecdsa_p256_roundtrip` | ECDSA-P256 verifies what it signed |
| `crypto` | `hmac_verify_constant_time` | HMAC verify accepts/rejects correctly |
| `kdf` | `k1_is_deterministic` | HKDF is deterministic |
| `kdf` | `domain_separation` | K_trans ≠ K_chain on same inputs |
| `kdf` | `epoch_separation` | Different epoch produces different K_trans |
| `messages` | `bootstrap_roundtrip`, `confirm_roundtrip`, `promote_roundtrip` | All three wire formats are reversible |
| `messages` | `promote_wrong_label_rejected` | Promote-label tampering is caught |
| `policy` | `canonical_encoding_is_stable` | Permuted construction → same hash |
| `policy` | `accepts_happy_path` + 4 rejection tests | Equations (5)–(8) of Construction 1 |
| `state` | `encode_decode_roundtrip` | Persistent state codec |
| `state` | `corrupt_crc_rejected` | Storage integrity check |
| `state` | `rejects_non_advancing_commit` | Monotonicity in software (Assumption 4) |

### Integration tests (11)

| Test | Rejection branch (TLS alert) |
|---|---|
| `happy_path_mode_a_variant_a1` | (happy path) |
| `rejects_bad_signature` | `markx_bad_signature(120)` |
| `rejects_policy_hash_mismatch` | `markx_policy_mismatch(121)` |
| `rejects_low_epoch_via_min_epoch_floor` | `markx_epoch_rollback(123)` — local policy floor |
| `rejects_epoch_rollback_replay` | `markx_epoch_rollback(123)` — replay of stale m_1 |
| `rejects_tampered_tag1` | `markx_decrypt_error(124)` — Phase 2 MAC |
| `rejects_tampered_tag2` | `markx_decrypt_error(124)` — Phase 3 MAC |
| `rejects_tampered_ciphertext_via_mac` | `markx_decrypt_error(124)` — ML-KEM implicit reject |
| `rejects_malformed_m1_truncated` | parse error |
| `two_migrations_have_independent_keys` | K_trans freshness |
| `smoke_policy_constants` | registry constants distinct |

## Mapping to the paper

| Crate module | Paper artefact |
|---|---|
| `error.rs` | Five rejection branches of Construction 1 / §7/Appendix C |
| `policy.rs` | Definition 3.8, Equations (4)–(8), ECDH security |
| `state.rs` | Definition 7, Assumption 4 (software realisation) |
| `codec.rs` | Definition 1 (Injective Encoding), §VII wire formats |
| `kdf.rs` | §VII HKDF labels |
| `crypto.rs` | ML-KEM (FIPS 203), ECDSA (FIPS 186-5) |
| `messages.rs` | Wire forms of m_1, m_2, m_3 |
| `server.rs` | Server side of Construction V.I |
| `client.rs` | Client side of Construction V.I —  the local policy check |

## Dependencies

| Crate | Version | Purpose |
|---|---|---|
| `pqcrypto-mlkem` | =0.1.0 | ML-KEM-768 (FFI to PQClean) |
| `pqcrypto-traits` | 0.3 | KEM trait interfaces |
| `p256` | 0.13 | ECDSA-P256 (pure Rust, constant-time) |
| `ecdsa` | 0.16 | ECDSA wire framing (DER) |
| `sha2` | 0.10 | SHA-256 |
| `hmac` | 0.12 | HMAC-SHA-256 |
| `hkdf` | 0.12 | HKDF |
| `rand` | 0.8 | CSPRNG (OsRng) |
| `base64ct` | =1.6.0 | (pinned, indirect via p256) |

## License

Dual-licensed Apache-2.0 OR MIT, matching the conventions of the
RustCrypto ecosystem.
