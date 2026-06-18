//! Persistent monotonic migration state $\state$ (Definition 3.11 of
//! MARK-X) is implemented as a file-backed counter.
//!
//! In a production deployment, Assumption 4 (monotonic state integrity)
//! would be discharged by hardware: a TPM 2.0 NV counter, a Secure Enclave
//! monotonic counter, or PSA Internal Trusted Storage on TF-M.  For the
//! reference implementation we use a plain JSON file with strict
//! monotonicity enforced in software.  The interface is the same as the
//! hardware backends would expose, so swapping in a real TPM later is a
//! local change to this module only.
//!
//! Atomicity guarantees:
//! * **Read-modify-write under `commit`.**  An advance from $(e, c)$ to
//!   $(e', c')$ is rejected unless $(e', c') > (e, c)$ lexicographically.
//! * **Crash-safe write.**  We write to a sibling tempfile and rename;
//!   POSIX `rename(2)` is atomic on the same filesystem.
//!
//! In all writes, the previous state remains on disk until the rename
//! completes, so a crash mid-write does not leave a partial state.

use crate::error::{MarkXError, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationState {
    pub epoch_accepted: u32,
    pub counter_current: u32,
    /// Active PQ public key for this party (encoded form).  Empty in the
    /// initial state.
    pub pk_pq_active: Vec<u8>,
    /// Active chaining key for Mode B (32 bytes when populated).  Empty in
    /// Mode A or before the first migration.
    pub k_chain_active: Vec<u8>,
}

impl MigrationState {
    pub fn fresh() -> Self {
        MigrationState {
            epoch_accepted: 0,
            counter_current: 0,
            pk_pq_active: Vec::new(),
            k_chain_active: Vec::new(),
        }
    }

    /// Compares $(e, c)$ lexicographically.  Returns `true` iff the new
    /// pair strictly exceeds the current state.
    pub fn would_advance(&self, e: u32, c: u32) -> bool {
        e > self.epoch_accepted || (e == self.epoch_accepted && c > self.counter_current)
    }
}

/// On-disk encoding of a migration state.  Plain bytes; we don't use a
/// general-purpose JSON crate to keep the dependency tree minimal.
///
/// Layout (big-endian):
/// ```text
/// u32  epoch_accepted
/// u32  counter_current
/// u32  len(pk_pq_active)
/// [u8] pk_pq_active
/// u32  len(k_chain_active)
/// [u8] k_chain_active
/// u32  CRC32 over the above
/// ```
fn encode(s: &MigrationState) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + s.pk_pq_active.len() + s.k_chain_active.len());
    out.extend_from_slice(&s.epoch_accepted.to_be_bytes());
    out.extend_from_slice(&s.counter_current.to_be_bytes());
    out.extend_from_slice(&(s.pk_pq_active.len() as u32).to_be_bytes());
    out.extend_from_slice(&s.pk_pq_active);
    out.extend_from_slice(&(s.k_chain_active.len() as u32).to_be_bytes());
    out.extend_from_slice(&s.k_chain_active);
    let crc = crc32_ieee(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

fn decode(bytes: &[u8]) -> Result<MigrationState> {
    if bytes.len() < 4 + 4 + 4 + 4 + 4 {
        return Err(MarkXError::StorageError("state file too short".into()));
    }
    let crc_offset = bytes.len() - 4;
    let body = &bytes[..crc_offset];
    let expected_crc = u32::from_be_bytes([
        bytes[crc_offset],
        bytes[crc_offset + 1],
        bytes[crc_offset + 2],
        bytes[crc_offset + 3],
    ]);
    if crc32_ieee(body) != expected_crc {
        return Err(MarkXError::StorageError("state CRC mismatch".into()));
    }

    let mut p = 0;
    let read_u32 = |p: &mut usize| -> Result<u32> {
        if *p + 4 > body.len() {
            return Err(MarkXError::StorageError("truncated state".into()));
        }
        let v = u32::from_be_bytes([body[*p], body[*p + 1], body[*p + 2], body[*p + 3]]);
        *p += 4;
        Ok(v)
    };
    let epoch_accepted = read_u32(&mut p)?;
    let counter_current = read_u32(&mut p)?;
    let pk_len = read_u32(&mut p)? as usize;
    if p + pk_len > body.len() {
        return Err(MarkXError::StorageError("pk_pq truncated".into()));
    }
    let pk_pq_active = body[p..p + pk_len].to_vec();
    p += pk_len;
    let kc_len = read_u32(&mut p)? as usize;
    if p + kc_len > body.len() {
        return Err(MarkXError::StorageError("k_chain truncated".into()));
    }
    let k_chain_active = body[p..p + kc_len].to_vec();
    p += kc_len;
    if p != body.len() {
        return Err(MarkXError::StorageError("trailing bytes in state".into()));
    }
    Ok(MigrationState {
        epoch_accepted,
        counter_current,
        pk_pq_active,
        k_chain_active,
    })
}

/// File-backed monotonic state store.  In production this would be
/// replaced by a TPM 2.0 NV counter or Secure Enclave.
pub struct StateStore {
    path: PathBuf,
}

impl StateStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        StateStore {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Load the current state from disk, or return a fresh state if the
    /// file does not exist.
    pub fn load(&self) -> Result<MigrationState> {
        if !self.path.exists() {
            return Ok(MigrationState::fresh());
        }
        let bytes = fs::read(&self.path)?;
        decode(&bytes)
    }

    /// Atomically commit a new state.  Returns `EpochRollback` if the new
    /// state does not strictly exceed the previously stored one.  This is
    /// the implementation-layer enforcement of Assumption 3.13: any
    /// attempt to overwrite with a stale or equal value is refused.
    pub fn commit(&self, new_state: &MigrationState) -> Result<()> {
        let current = self.load()?;
        if !current.would_advance(new_state.epoch_accepted, new_state.counter_current) {
            return Err(MarkXError::EpochRollback);
        }
        let bytes = encode(new_state);
        // Write to a sibling tempfile, then atomically rename.
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

// ---------- minimal CRC-32 IEEE (used only for storage integrity) ----------
fn crc32_ieee(data: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB88320;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let s = MigrationState {
            epoch_accepted: 7,
            counter_current: 42,
            pk_pq_active: vec![1, 2, 3, 4, 5],
            k_chain_active: vec![0xAA; 32],
        };
        let bytes = encode(&s);
        let s2 = decode(&bytes).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn corrupt_crc_rejected() {
        let s = MigrationState::fresh();
        let mut bytes = encode(&s);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_non_advancing_commit() {
        let tmp = std::env::temp_dir().join("markx_test_state_nonadvance.bin");
        let _ = std::fs::remove_file(&tmp);
        let store = StateStore::new(&tmp);

        let s1 = MigrationState {
            epoch_accepted: 5,
            counter_current: 1,
            pk_pq_active: vec![1, 2, 3],
            k_chain_active: vec![],
        };
        store.commit(&s1).unwrap();

        // Equal — must reject
        let s2 = s1.clone();
        assert_eq!(store.commit(&s2), Err(MarkXError::EpochRollback));

        // Lower epoch — must reject
        let s3 = MigrationState {
            epoch_accepted: 4,
            counter_current: 999,
            pk_pq_active: vec![],
            k_chain_active: vec![],
        };
        assert_eq!(store.commit(&s3), Err(MarkXError::EpochRollback));

        // Higher counter at same epoch — accepted
        let s4 = MigrationState {
            epoch_accepted: 5,
            counter_current: 2,
            pk_pq_active: vec![1, 2, 3],
            k_chain_active: vec![],
        };
        assert!(store.commit(&s4).is_ok());

        let _ = std::fs::remove_file(&tmp);
    }
}
