//! Server-side driver for MARK-X Mode A, Variant A1 (pre-shared $K_\mathsf{class}$).
//!
//! Implements the server side of Construction 1.  The
//! driver is stateful across the three messages: after sending $m_1$ it
//! stores the tentative migration in memory; after receiving $m_2$ it
//! verifies and emits $m_3$; on $m_3$ acknowledgement (in this in-process
//! model: as soon as the server has emitted $m_3$ successfully) the
//! persistent state is advanced.

use crate::codec::Ctx1;
use crate::crypto::{
    ecdsa_p256_sign, hmac_sha256, hmac_sha256_verify, mlkem768_decaps, mlkem768_keypair,
    sha256_concat, PqKemKeyPair,
};
use crate::error::{MarkXError, Result};
use crate::kdf::{derive_k1, derive_k_chain, derive_k_trans};
use crate::messages::{MarkXBootstrap, MarkXConfirm, MarkXPromote, PROMOTE_LABEL};
use crate::policy::{alg_id, param_id, variant, MarkXPolicy};
use crate::state::{MigrationState, StateStore};
use p256::ecdsa::SigningKey as EcdsaSk;

/// Tentative server-side state held in memory between sending $m_1$ and
/// receiving the corresponding $m_2$.
pub struct PendingMigration {
    epoch: u32,
    counter: u32,
    pq_keypair: PqKemKeyPair,
    /// The exact `ctx_1` bytes that the server signed; we keep this rather
    /// than reconstructing it so any divergence between `encode()` and
    /// the value transmitted is impossible.  Retained for audit; not used
    /// after `m_1` is sent in this reference implementation.
    #[allow(dead_code)]
    ctx_1_bytes: Vec<u8>,
    /// The `m_1` bytes that we sent; used to recompute the transcript
    /// hash when $m_2$ arrives.
    m1_bytes: Vec<u8>,
    /// Pre-shared classical channel secret (Variant A1).
    k_class: [u8; 32],
}

pub struct MarkXServer {
    sk_sig: EcdsaSk,
    policy: MarkXPolicy,
    state_store: StateStore,
    pending: Option<PendingMigration>,
}

impl MarkXServer {
    pub fn new(sk_sig: EcdsaSk, policy: MarkXPolicy, state_store: StateStore) -> Self {
        MarkXServer {
            sk_sig,
            policy,
            state_store,
            pending: None,
        }
    }

    /// Phase 1: generate a fresh PQ keypair, build `ctx_1`, sign it, and
    /// return the encoded `m_1`.  Stores the tentative migration in `self`.
    pub fn initiate_migration(&mut self, k_class: [u8; 32]) -> Result<Vec<u8>> {
        let st = self.state_store.load()?;
        let new_epoch = st.epoch_accepted.saturating_add(1);
        let new_counter = st.counter_current.saturating_add(1);

        let pq_keypair = mlkem768_keypair();
        let policy_hash = self.policy.hash();
        let ctx_1 = Ctx1 {
            alg_id: alg_id::ML_KEM,
            param_id: param_id::MLKEM_768,
            epoch: new_epoch,
            counter: new_counter,
            policy_hash,
            variant: variant::A1,
            pq_public_key: pq_keypair.pk.clone(),
            ecdh_share: vec![], // A1: no ECDH
        };
        let ctx_1_bytes = ctx_1.encode();

        let to_sign = sha256_concat(&[b"MARK-X-v2-Bootstrap", &ctx_1_bytes]);
        let signature = ecdsa_p256_sign(&self.sk_sig, &to_sign);

        let m1 = MarkXBootstrap {
            ctx_1: ctx_1.clone(),
            signature,
        };
        let m1_bytes = m1.encode();

        self.pending = Some(PendingMigration {
            epoch: new_epoch,
            counter: new_counter,
            pq_keypair,
            ctx_1_bytes,
            m1_bytes: m1_bytes.clone(),
            k_class,
        });
        Ok(m1_bytes)
    }

    /// Phase 2 (server side): consume `m_2`, decapsulate, derive
    /// $K_\mathsf{trans}, K_\mathsf{chain}$, verify $\mathsf{tag}_1$, then
    /// emit the encoded `m_3`.  On success, atomically commits the new
    /// migration state to persistent storage.
    pub fn handle_confirm_and_promote(&mut self, m2_bytes: &[u8]) -> Result<Vec<u8>> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(MarkXError::InvalidState("no pending migration"))?;

        let m2 = MarkXConfirm::decode(m2_bytes)?;
        // A1 must have no ECDH share
        if !m2.ecdh_share.is_empty() {
            return Err(MarkXError::MalformedMessage);
        }

        let k_pq = mlkem768_decaps(&pending.pq_keypair.sk, &m2.kem_ciphertext)?;

        // Transcript: H(m_1 || ct_pq || X)  where X is empty for A1.
        let transcript = sha256_concat(&[&pending.m1_bytes, &m2.kem_ciphertext, &m2.ecdh_share]);

        let k1 = derive_k1(&k_pq, &pending.k_class, &transcript);
        // Verify tag_1 = MAC(k_1, "client-confirm" || transcript)
        let mut tag1_input = Vec::with_capacity(14 + 32);
        tag1_input.extend_from_slice(b"client-confirm");
        tag1_input.extend_from_slice(&transcript);
        hmac_sha256_verify(&k1, &tag1_input, &m2.tag1)?;

        let policy_hash = self.policy.hash();
        let k_trans = derive_k_trans(
            &k_pq,
            &pending.k_class,
            pending.epoch,
            pending.counter,
            &policy_hash,
            &transcript,
        );
        let k_chain = derive_k_chain(
            &k_pq,
            &pending.k_class,
            pending.epoch,
            pending.counter,
            &transcript,
        );

        // Build m_3: tag_2 = MAC(K_trans, "promote-to-PQ" || e || ctr || alg_id || policy_hash)
        let mut tag2_input = Vec::with_capacity(13 + 4 + 4 + 2 + 32);
        tag2_input.extend_from_slice(&PROMOTE_LABEL);
        tag2_input.extend_from_slice(&pending.epoch.to_be_bytes());
        tag2_input.extend_from_slice(&pending.counter.to_be_bytes());
        tag2_input.extend_from_slice(&alg_id::ML_KEM.to_be_bytes());
        tag2_input.extend_from_slice(&policy_hash);
        let tag2 = hmac_sha256(&k_trans, &tag2_input);

        let m3 = MarkXPromote::new(pending.epoch, pending.counter, tag2);
        let m3_bytes = m3.encode();

        // Atomically commit the new state.  After this point the server
        // has irreversibly advanced its epoch.
        let new_state = MigrationState {
            epoch_accepted: pending.epoch,
            counter_current: pending.counter,
            pk_pq_active: pending.pq_keypair.pk.clone(),
            k_chain_active: k_chain.to_vec(),
        };
        self.state_store.commit(&new_state)?;

        self.pending = None;
        // Discard transition key from memory — not exported to the caller.
        // (In a real deployment K_trans would be passed up to the
        // application; here we drop it so it isn't accidentally reused.)
        let _ = k_trans;
        Ok(m3_bytes)
    }
}
