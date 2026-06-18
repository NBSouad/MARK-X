//! Client-side driver for MARK-X Mode A, Variant A1.
//!
//! Implements the client side of Construction V.I step-by-step, with
//! every check from §5.2 Phase 1 (a)--(e).  The check
//! order is significant: signature verification first, then policy
//! acceptance, then monotonicity against persistent state.
//! Any failure aborts with the corresponding `MarkXError` variant.

use crate::codec::Ctx1;
use crate::crypto::{
    ecdsa_p256_verify, hmac_sha256, hmac_sha256_verify, mlkem768_encaps, sha256_concat,
};
use crate::error::{MarkXError, Result};
use crate::kdf::{derive_k1, derive_k_chain, derive_k_trans};
use crate::messages::{MarkXBootstrap, MarkXConfirm, MarkXPromote, PROMOTE_LABEL};
use crate::policy::{alg_id, variant, MarkXPolicy};
use crate::state::{MigrationState, StateStore};
use p256::ecdsa::VerifyingKey as EcdsaPk;

/// Tentative client-side state held between sending $m_2$ and receiving $m_3$.
pub struct PendingClient {
    epoch: u32,
    counter: u32,
    pk_pq: Vec<u8>,
    transcript: [u8; 32],
    k_pq: [u8; 32],
    k_class: [u8; 32],
    /// We retain `ctx_1.policy_hash` so that we can include it in the
    /// `K_trans` derivation that matches the server's.
    policy_hash: [u8; 32],
}

pub struct MarkXClient {
    pk_sig: EcdsaPk,
    policy: MarkXPolicy,
    state_store: StateStore,
    pending: Option<PendingClient>,
}

impl MarkXClient {
    pub fn new(pk_sig: EcdsaPk, policy: MarkXPolicy, state_store: StateStore) -> Self {
        MarkXClient {
            pk_sig,
            policy,
            state_store,
            pending: None,
        }
    }

    /// Phase 1 (client side): run every check of Construction V.I step
    /// (c) on the received `m_1`.  On success, encapsulate to obtain
    /// $\mathit{ct}_\mathsf{pq}$, derive $k_1$, emit the encoded `m_2`,
    /// and store tentative state.  Does *not* yet update the persistent
    /// `state_store`: that happens only after successful `m_3` verify.
    ///
    /// `k_class` is the pre-shared classical secret for Variant A1 (e.g.
    /// the TLS application traffic secret in §7).
    pub fn handle_bootstrap(&mut self, m1_bytes: &[u8], k_class: [u8; 32]) -> Result<Vec<u8>> {
        // (a) Parse
        let m1 = MarkXBootstrap::decode(m1_bytes)?;
        let ctx_1: &Ctx1 = &m1.ctx_1;
        let ctx_1_bytes = ctx_1.encode();

        // (b) Signature
        let to_verify = sha256_concat_for_sig(&ctx_1_bytes);
        ecdsa_p256_verify(&self.pk_sig, &to_verify, &m1.signature)?;

        // (c) Local-policy acceptance
        let expected = self.policy.hash();
        if expected != ctx_1.policy_hash {
            return Err(MarkXError::PolicyMismatch);
        }
        self.policy
            .accepts(ctx_1.alg_id, ctx_1.param_id, ctx_1.variant, ctx_1.epoch)?;

        // We only implement Variant A1 in this reference; reject A2 here.
        if ctx_1.variant != variant::A1 {
            return Err(MarkXError::AlgorithmNotAllowed);
        }
        if !ctx_1.ecdh_share.is_empty() {
            // A1 must have no ECDH share
            return Err(MarkXError::MalformedMessage);
        }

        // (d) Monotonicity against persistent state
        let stored = self.state_store.load()?;
        if !stored.would_advance(ctx_1.epoch, ctx_1.counter) {
            return Err(MarkXError::EpochRollback);
        }

        // (e) Tentative install — encapsulate and prepare m_2
        let (ct_pq, k_pq) = mlkem768_encaps(&ctx_1.pq_public_key)?;
        let transcript = sha256_concat(&[m1_bytes, &ct_pq, &[]]); // X empty for A1

        let k1 = derive_k1(&k_pq, &k_class, &transcript);
        let mut tag1_input = Vec::with_capacity(14 + 32);
        tag1_input.extend_from_slice(b"client-confirm");
        tag1_input.extend_from_slice(&transcript);
        let tag1 = hmac_sha256(&k1, &tag1_input);

        let m2 = MarkXConfirm {
            kem_ciphertext: ct_pq,
            ecdh_share: vec![],
            tag1,
        };

        self.pending = Some(PendingClient {
            epoch: ctx_1.epoch,
            counter: ctx_1.counter,
            pk_pq: ctx_1.pq_public_key.clone(),
            transcript,
            k_pq,
            k_class,
            policy_hash: ctx_1.policy_hash,
        });

        Ok(m2.encode())
    }

    /// Phase 3 (client side): verify `m_3` and, on success, atomically
    /// commit the new migration state.  Returns $K_\mathsf{trans}$ for
    /// application use (in §7 this is the value exported
    /// to higher layers).
    pub fn handle_promote(&mut self, m3_bytes: &[u8]) -> Result<[u8; 32]> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(MarkXError::InvalidState("no pending bootstrap"))?;

        let m3 = MarkXPromote::decode(m3_bytes)?;
        if m3.epoch != pending.epoch || m3.counter != pending.counter {
            return Err(MarkXError::EpochRollback);
        }

        let k_trans = derive_k_trans(
            &pending.k_pq,
            &pending.k_class,
            pending.epoch,
            pending.counter,
            &pending.policy_hash,
            &pending.transcript,
        );
        let k_chain = derive_k_chain(
            &pending.k_pq,
            &pending.k_class,
            pending.epoch,
            pending.counter,
            &pending.transcript,
        );

        // Verify tag_2 = MAC(K_trans, "promote-to-PQ" || e || ctr || alg_id || policy_hash)
        let mut tag2_input = Vec::with_capacity(13 + 4 + 4 + 2 + 32);
        tag2_input.extend_from_slice(&PROMOTE_LABEL);
        tag2_input.extend_from_slice(&pending.epoch.to_be_bytes());
        tag2_input.extend_from_slice(&pending.counter.to_be_bytes());
        tag2_input.extend_from_slice(&alg_id::ML_KEM.to_be_bytes());
        tag2_input.extend_from_slice(&pending.policy_hash);
        hmac_sha256_verify(&k_trans, &tag2_input, &m3.tag2)?;

        // Atomically commit
        let new_state = MigrationState {
            epoch_accepted: pending.epoch,
            counter_current: pending.counter,
            pk_pq_active: pending.pk_pq.clone(),
            k_chain_active: k_chain.to_vec(),
        };
        self.state_store.commit(&new_state)?;
        self.pending = None;

        Ok(k_trans)
    }
}

fn sha256_concat_for_sig(ctx_1_bytes: &[u8]) -> [u8; 32] {
    sha256_concat(&[b"MARK-X-v2-Bootstrap", ctx_1_bytes])
}
