//! # MARK-X reference implementation
//!
//! This crate is the reference implementation of the MARK-X
//! Migration-Aware Authenticated Re-Key protocol described in the v3
//! paper, **Mode A, Variant A1** (pre-shared classical channel secret).
//!
//! The implementation is intentionally minimal in surface area: every
//! module corresponds to a single concept from the paper, and the public
//! API is just two driver types plus their associated message buffers.
//!
//! ## Module map
//!
//! | Module | Concept in paper |
//! |---|---|
//! | [`error`] | Rejection branches of Construction V.I |
//! | [`policy`] | $\pi^\mathsf{local}$ (Definition 3.8) and acceptance check |
//! | [`state`] | $\state$ (Definition 3.11), discharge of Assumption 3.13 |
//! | [`codec`] | Injective encoding (Definition 3.1) |
//! | [`kdf`]   | HKDF labels of §7 |
//! | [`crypto`] | ML-KEM-768 + ECDSA-P256 + SHA-256 + HMAC |
//! | [`messages`] | Wire forms of $m_1, m_2, m_3$ (§VIII) |
//! | [`server`] | Server-side driver of Construction V.I |
//! | [`client`] | Client-side driver of Construction V.I (with all checks) |
//!
//! ## What this crate is and is not
//!
//! **It is** a buildable, testable artifact that exercises every check
//! and rejection branch of the paper.  Reviewers can run `cargo test` to
//! verify both the happy path and the five distinct failure modes.
//!
//! **It is not** a production-ready library.  It does not yet implement:
//! * Variant A2 (explicit ECDH); only A1 is covered.
//! * Mode B (self-sustaining); see §6 of the paper.
//! * Side-channel countermeasures beyond what the underlying crates
//!   provide (the `p256` crate is constant-time; ML-KEM via PQClean has
//!   reference-style C, which is constant-time for ML-KEM-768).
//! * Network transport; this is an in-process state machine.  TLS or
//!   CoAP integration would wrap [`server::MarkXServer`] and
//!   [`client::MarkXClient`] without changing their logic.

pub mod client;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod kdf;
pub mod messages;
pub mod policy;
pub mod server;
pub mod state;

pub use client::MarkXClient;
pub use error::{MarkXError, Result};
pub use policy::MarkXPolicy;
pub use server::MarkXServer;
pub use state::{MigrationState, StateStore};
