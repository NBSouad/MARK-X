//! Error types covering every rejection branch of Construction V.I of
//! MARK-X (see §V.B Phase 1 of the paper).
//!
//! Each variant corresponds to a specific check whose failure terminates the
//! protocol with an explicit, distinguishable error. The names match the TLS
//! alert subcodes proposed in §7 so that an integrator can
//! route them onto the wire one-to-one.

use core::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum MarkXError {
    /// $\sigma_1$ failed ECDSA verification under $\pksig$.
    /// Maps to `markx_bad_signature(120)` in §7.
    BadSignature,

    /// $H(\pi^\mathsf{local}) \neq \policy_\mathsf{hash}$ in $m_1$.
    /// Maps to `markx_policy_mismatch(121)`.
    PolicyMismatch,

    /// One of `alg_id`, `param_id`, or `variant` is not allowed under
    /// $\pi^\mathsf{local}$ (Equations (5)--(7) of Construction V.I).
    /// Maps to `markx_algorithm_not_allowed(122)`.
    AlgorithmNotAllowed,

    /// $e < \pi^\mathsf{local}.\mathsf{min\_epoch}$, or
    /// monotonicity check against stored state failed.
    /// Maps to `markx_epoch_rollback(123)`.
    EpochRollback,

    /// KEM `decapsulate` returned a zero shared secret, or
    /// $\mathsf{tag}_1$/$\mathsf{tag}_2$ MAC verification failed.
    /// Maps to `markx_decrypt_error(124)`.
    DecryptError,

    /// Wire-format parse error: malformed `MarkXBootstrap`,
    /// `MarkXConfirm`, or `MarkXPromote`. Length mismatch, truncation,
    /// or invalid variant byte.
    MalformedMessage,

    /// I/O failure when reading/writing the persistent monotonic state.
    /// Discharges Assumption 3.13 at the implementation layer; if this
    /// returns the protocol MUST abort without updating any state.
    StorageError(String),

    /// An internal invariant was violated.  Should be impossible if the
    /// state machine is driven correctly; surfaces as a defensive check.
    InvalidState(&'static str),
}

impl fmt::Display for MarkXError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MarkXError::BadSignature => write!(f, "MARK-X: classical signature did not verify"),
            MarkXError::PolicyMismatch => {
                write!(f, "MARK-X: announced policy_hash did not match local policy")
            }
            MarkXError::AlgorithmNotAllowed => {
                write!(f, "MARK-X: announced alg/param/variant not permitted by local policy")
            }
            MarkXError::EpochRollback => {
                write!(f, "MARK-X: epoch/counter violates monotonicity or min_epoch")
            }
            MarkXError::DecryptError => write!(f, "MARK-X: KEM decapsulation or MAC verify failed"),
            MarkXError::MalformedMessage => write!(f, "MARK-X: wire-format parse error"),
            MarkXError::StorageError(s) => write!(f, "MARK-X: persistent state I/O error: {s}"),
            MarkXError::InvalidState(s) => write!(f, "MARK-X: invalid state transition: {s}"),
        }
    }
}

impl std::error::Error for MarkXError {}

impl From<std::io::Error> for MarkXError {
    fn from(e: std::io::Error) -> Self {
        MarkXError::StorageError(e.to_string())
    }
}

pub type Result<T> = core::result::Result<T, MarkXError>;
