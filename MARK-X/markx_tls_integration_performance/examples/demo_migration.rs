//! Runnable example: one full MARK-X Mode A / Variant A1 migration with
//! verbose narration.  Run with:
//!
//! ```text
//! cargo run --example demo_migration
//! ```

use markx::crypto::ecdsa_p256_keypair;
use markx::{MarkXClient, MarkXPolicy, MarkXServer, MigrationState, StateStore};

fn main() {
    println!("=== MARK-X reference implementation — demo migration ===\n");

    // 0. Setup: server holds sk_sig, both share psk and policy
    let (sk_sig, pk_sig) = ecdsa_p256_keypair();
    let policy = MarkXPolicy::reference();

    let dir = std::env::temp_dir();
    let nonce: u64 = rand::random();
    let server_state = dir.join(format!("markx_demo_server_{nonce}.bin"));
    let client_state = dir.join(format!("markx_demo_client_{nonce}.bin"));
    let _ = std::fs::remove_file(&server_state);
    let _ = std::fs::remove_file(&client_state);

    let mut server = MarkXServer::new(sk_sig, policy.clone(), StateStore::new(&server_state));
    let mut client = MarkXClient::new(pk_sig, policy, StateStore::new(&client_state));

    let k_class: [u8; 32] = {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    };

    println!("[*] Policy hash:      {}", hex::encode(MarkXPolicy::reference().hash()));
    println!("[*] Shared K_class:   {}", hex::encode(k_class));
    println!();

    // 1. Server -> client: m_1
    println!("[1] Server: initiate_migration(k_class)");
    let m1 = server.initiate_migration(k_class).expect("server m1");
    println!("    m_1 wire size:    {} bytes", m1.len());

    // 2. Client -> server: m_2
    println!("[2] Client: handle_bootstrap(m_1)  — checks signature, policy, monotonicity");
    let m2 = client.handle_bootstrap(&m1, k_class).expect("client m2");
    println!("    m_2 wire size:    {} bytes", m2.len());

    // 3. Server -> client: m_3
    println!("[3] Server: handle_confirm_and_promote(m_2)  — decaps, derives K_trans, emits m_3");
    let m3 = server.handle_confirm_and_promote(&m2).expect("server m3");
    println!("    m_3 wire size:    {} bytes", m3.len());

    // 4. Client commits
    println!("[4] Client: handle_promote(m_3)  — verifies tag_2, commits state");
    let k_trans = client.handle_promote(&m3).expect("client commit");
    println!("    K_trans:          {}", hex::encode(k_trans));

    // Read back persistent state
    let ss: MigrationState = StateStore::new(&server_state).load().unwrap();
    let cs: MigrationState = StateStore::new(&client_state).load().unwrap();
    println!();
    println!("[OK] Server state:   epoch={} counter={} pk_pq_len={}",
        ss.epoch_accepted, ss.counter_current, ss.pk_pq_active.len());
    println!("[OK] Client state:   epoch={} counter={} pk_pq_len={}",
        cs.epoch_accepted, cs.counter_current, cs.pk_pq_active.len());

    let total = m1.len() + m2.len() + m3.len();
    println!();
    println!("Total wire data: {} bytes ({} m1 + {} m2 + {} m3)",
        total, m1.len(), m2.len(), m3.len());
    println!();

    let _ = std::fs::remove_file(&server_state);
    let _ = std::fs::remove_file(&client_state);
}
