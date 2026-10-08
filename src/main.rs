// Copyright (c) 2026 Andrii Dumitro
// SPDX-License-Identifier: MIT
//
// ACCUM v3.2+ - Fair Proof-of-Contribution Blockchain Protocol
// FULLY WORKING NODE WITH SOLO MINING + EQUIVOCATION SLASHING
// ============================================================

use bincode;
use dirs;
use hex;
use lazy_static;
use secp256k1::Secp256k1;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use tokio::signal;
use tokio::time::Duration;

mod constants;
use constants::*;
mod crypto;
mod types;
mod wallet;
use wallet::*;
mod block;
use block::*;
mod config;
mod difficulty;
use config::*;
mod storage;
use storage::*;
mod miner;
use miner::*;
mod consensus;
use consensus::*;
mod epoch_commit;
mod genesis;
mod network;
mod node;
mod p2p;
use node::*;
mod rpc;
use rpc::*;
use crate::crypto::Argon2Cache;
use crate::types::Hash32;
use crate::node::header_with_nonce_hash;

lazy_static::lazy_static! {
    pub static ref SECP: Secp256k1<secp256k1::All> = Secp256k1::new();
}


// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);
pub static SAVING_STATE: AtomicBool = AtomicBool::new(false);

pub fn should_shutdown() -> bool {
    SHUTDOWN.load(AtomicOrdering::Relaxed)
}

pub fn set_saving_state(saving: bool) {
    SAVING_STATE.store(saving, AtomicOrdering::Relaxed);
}

pub fn is_saving_state() -> bool {
    SAVING_STATE.load(AtomicOrdering::Relaxed)
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

pub fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

// ============================================================
// НОДА
// ============================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║    ACCUM v3.2+ - Fair Proof-of-Contribution Blockchain       ║");
    println!("║         WORKING NODE WITH SOLO MINING + SLASHING             ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    let genesis_mode = args.iter().any(|a| a == "--genesis");

    match args.get(1).map(|s| s.as_str()) {
        Some("wallet") => {
            handle_wallet_command(&args)?;
        }
        Some("node") => {
            run_node(genesis_mode).await?;
        }
        Some("backup") => {
            handle_backup_command(&args)?;
        }
        Some("restore") => {
            handle_restore_command(&args)?;
        }
        Some("info") => {
            handle_info_command()?;
        }
        _ => {
            println!("No command specified, starting node...\n");
            run_node(genesis_mode).await?;
        }
    }

    Ok(())
}

fn print_help() {
    println!("Usage: accum <command> [options]");
    println!("\nCommands:");
    println!("  node                    Start a full node");
    println!("  wallet create           Create a new wallet");
    println!("  wallet balance <addr>   Check wallet balance");
    println!("  wallet send <to> <amt>  Send coins");
    println!("  backup                  Create database backup");
    println!("  restore <timestamp>     Restore from backup");
    println!("  info                    Show node info");
}

fn handle_wallet_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.get(2).map(|s| s.as_str()) {
        Some("create") => {
            let wallet = Wallet::generate()?;
            println!("\n✅ Wallet created successfully!\n");
            println!("📫 Address:     {}", wallet.address);
            println!("🆔 Miner ID:    {}", hex::encode(&wallet.miner_id));
            println!("🔑 Public Key:  {}", hex::encode(&wallet.public_key));
            println!("\n⚠️  SAVE YOUR PRIVATE KEY SECURELY:");
            println!("📜 Private Key: {}", hex::encode(&wallet.secret_key));
        }
        Some("show") => {
            let wallet_path = dirs::home_dir()
                .ok_or("Cannot find home dir")?
                .join(".accum")
                .join("wallet.json");

            if !wallet_path.exists() {
                println!("❌ Wallet file not found at: {}", wallet_path.display());
                println!("   Create a wallet first with: accum wallet create");
                return Ok(());
            }

            let content = std::fs::read_to_string(&wallet_path)?;

            #[derive(serde::Deserialize)]
            struct WalletFile {
                private_key: String,
            }

            let wallet_data: WalletFile = serde_json::from_str(&content)?;

            println!("\n🔐 WARNING: PRIVATE KEY EXPOSURE!");
            println!("═══════════════════════════════════════════");
            println!("⚠️  Anyone with this key can STEAL your funds!");
            println!("⚠️  Only use this in a SECURE environment!");
            println!("⚠️  Close this window after copying the key!");
            println!("═══════════════════════════════════════════\n");
            println!("📜 Private Key: {}", wallet_data.private_key);
            println!("\n✅ Press ENTER to continue...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
        }
        Some("export") => {
            let wallet_path = dirs::home_dir()
                .ok_or("Cannot find home dir")?
                .join(".accum")
                .join("wallet.json");

            if !wallet_path.exists() {
                println!("❌ Wallet file not found at: {}", wallet_path.display());
                return Ok(());
            }

            let backup_path = dirs::home_dir()
                .ok_or("Cannot find home dir")?
                .join(".accum")
                .join(format!(
                    "wallet_backup_{}.json",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                ));

            std::fs::copy(&wallet_path, &backup_path)?;

            println!("\n✅ Wallet exported successfully!");
            println!("📁 Backup saved to: {}", backup_path.display());
        }
        Some("balance") => {
            let address = args.get(3).ok_or("Address required")?;

            println!("📊 Checking balance for {}...", address);

            let storage = match ProductionStorage::new("mainnet") {
                Ok(s) => s,
                Err(e) => {
                    println!("❌ Cannot open database: {}", e);
                    return Ok(());
                }
            };

            match storage.get_balance_by_address(address) {
                Ok((balance_lyt, utxo_count)) => {
                    let acm = balance_lyt as f64 / LYATORS_PER_ACM as f64;
                    println!("\n✅ Balance found:");
                    println!("   Address : {}", address);
                    println!("   Balance : {} LYT  ({:.8} ACM)", balance_lyt, acm);
                    println!("   UTXOs   : {}", utxo_count);
                }
                Err(e) => {
                    println!("❌ Error calculating balance: {}", e);
                }
            }
        }
        Some("send") => {
            let to = args.get(3).ok_or("Recipient address required")?;
            let amount_str = args.get(4).ok_or("Amount required")?;
            let amount: u64 = amount_str.parse().map_err(|_| "Invalid amount")?;

            let wallet_path = dirs::home_dir()
                .ok_or("Cannot find home dir")?
                .join(".accum")
                .join("wallet.json");

            if !wallet_path.exists() {
                println!("❌ Wallet not found. Create one first: accum wallet create");
                return Ok(());
            }

            let content = std::fs::read_to_string(&wallet_path)?;
            #[derive(serde::Deserialize)]
            struct WalletFile {
                private_key: String,
            }
            let wallet_data: WalletFile = serde_json::from_str(&content)?;
            let secret_bytes = hex::decode(&wallet_data.private_key)
                .map_err(|e| format!("Invalid private key hex: {}", e))?;
            let wallet = Wallet::from_secret_key(&secret_bytes)?;

            println!("💳 From:   {}", wallet.address);
            println!("📤 To:     {}", to);
            println!("💰 Amount: {} LYT", amount);

            let storage = ProductionStorage::new("mainnet")?;
            let utxos = storage.get_utxos_by_address(&wallet.address)?;

            if utxos.is_empty() {
                println!("❌ No UTXOs found for this address");
                return Ok(());
            }

            println!("📦 Found {} UTXO(s)", utxos.len());

            let fee = 1000u64;
            let tx = match wallet.create_simple_tx(&utxos, to, amount, fee) {
                Ok(tx) => tx,
                Err(e) => {
                    println!("❌ Failed to create transaction: {}", e);
                    return Ok(());
                }
            };

            let tx_bytes = bincode::serialize(&tx).map_err(|e| e.to_string())?;
            let tx_hex = hex::encode(&tx_bytes);

            println!("\n✅ Transaction created and signed");
            println!("   Fee: {} LYT", fee);
            println!("   Size: {} bytes", tx_bytes.len());

            println!(
                "\n📡 Trying to broadcast via RPC (localhost:{})...",
                RPC_PORT
            );

            let client = reqwest::blocking::Client::new();
            let url = format!("http://127.0.0.1:{}/transaction", RPC_PORT);

            match client
                .post(&url)
                .header("Content-Type", "text/plain")
                .body(tx_hex.clone())
                .send()
            {
                Ok(response) => {
                    if response.status().is_success() {
                        let body = response.text().unwrap_or_default();
                        println!("✅ Transaction successfully submitted to node!");
                        println!("   Response: {}", body);
                    } else {
                        println!("⚠️  Node returned error: {}", response.status());
                        println!("   Raw tx (hex):");
                        println!("{}", tx_hex);
                    }
                }
                Err(e) => {
                    println!("⚠️  Could not connect to node RPC: {}", e);
                    println!("\n   Raw tx (hex):");
                    println!("{}", tx_hex);
                }
            }
        }
        _ => {
            println!("╔═══════════════════════════════════════════╗");
            println!("║       ACCUM WALLET COMMANDS             ║");
            println!("╚═══════════════════════════════════════════╝");
            println!("\nUsage: accum wallet <command>");
            println!("\nCommands:");
            println!("  create  - Create a new wallet");
            println!("  show    - Show your private key");
            println!("  export  - Export wallet to backup file");
            println!("  balance - Check wallet balance");
            println!("  send    - Send coins to another address");
        }
    }
    Ok(())
}

fn handle_backup_command(_args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let _config = Config::load()?;
    let storage = ProductionStorage::new("mainnet")?;
    let backup_id = storage.backup()?;
    println!("✅ Backup created: {}", backup_id);
    Ok(())
}

fn handle_restore_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = args.get(2).ok_or("Backup timestamp required")?;
    let _config = Config::load()?;
    let storage = ProductionStorage::new("mainnet")?;
    storage.restore(timestamp)?;
    Ok(())
}

fn handle_info_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("📡 Reading local node information...\n");

    let storage = match ProductionStorage::new("mainnet") {
        Ok(s) => s,
        Err(e) => {
            println!("❌ Cannot open database: {}", e);
            return Ok(());
        }
    };

    match storage.get_node_info() {
        Ok((height, epoch, utxo_count)) => {
            println!("╔══════════════════════════════════════════╗");
            println!("║           ACCUM NODE INFO                ║");
            println!("╚══════════════════════════════════════════╝");
            println!();
            println!("  Height        : {}", height);
            println!("  Epoch         : {}", epoch);
            println!("  UTXO count    : {}", utxo_count);
            println!("  Network       : mainnet");
            println!("  RPC port      : {}", RPC_PORT);
            println!("  P2P port      : {}", P2P_PORT);
            println!();
            println!("💡 Database path: ~/.accum/mainnet");
        }
        Err(e) => {
            println!("❌ Failed to read node info: {}", e);
        }
    }

    Ok(())
}

async fn run_node(genesis_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    println!("📋 Loaded configuration from ~/.accum/config.toml");

    let node_arc = Node::new(config.clone())?;

    // ---- RPC in a separate OS thread with its own tokio runtime ----
    if config.rpc.enabled {
        let rpc_node = node_arc.clone();
        let rpc_port = config.rpc.port;
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("failed to build RPC runtime");
            rt.block_on(async move {
                let rpc = RpcServer::new(rpc_node, rpc_port);
                if let Err(e) = rpc.start().await {
                    eprintln!("❌ RPC server error: {}", e);
                }
            });
        });
        println!("📡 RPC server started on port {}", config.rpc.port);
    }

    // ---- Bond for the local miner ----
    {
        let mut node = node_arc.write();
        if config.mining.enabled && !node.bonds.contains_key(&node.miner_id) {
            let miner_id = node.miner_id;
            let bond_amount = config.mining.bond.max(MINIMUM_BOND_LYT);
            node.add_bond(miner_id, bond_amount);
            println!("💰 Bond added: {} LYT", bond_amount);
        }
    }

    println!("\n=== NODE STARTED ===");
    {
        let node = node_arc.read();
        println!("🔗 Height: {}", node.height);
        println!("📅 Epoch: {}", node.epoch);
        println!("😎 Miner ID: {}...", hex::encode(&node.miner_id[0..8]));
        println!(
            "💳 Address: {}",
            node.wallet
                .as_ref()
                .map(|w| w.address.clone())
                .unwrap_or_default()
        );
        if config.mining.enabled {
            println!(
                "⛏️  Solo mining ENABLED with {} threads",
                config.mining.threads
            );
            if genesis_mode {
                println!(" Solo genesis mode: ENABLED (--genesis)");
            } else {
                println!(" Solo genesis mode: disabled (require peers)");
            }
        } else {
            println!("⛏️  Solo mining DISABLED");
        }
    }
    println!("========================\n");

    // ---- Main loop in a separate OS thread, write-lock only during tick ----
    let node_for_loop = node_arc.clone();
    std::thread::spawn(move || {
        println!("🚀 Node loop starting...");
        let mut last_backup_height: u64 = u64::MAX;
        loop {
            if should_shutdown() {
                println!("\n⏳ Shutting down (node loop)...");
                let mut node = node_for_loop.write();
                node.shutdown();
                break;
            }

            {
                let mut node = node_for_loop.write();
                if let Err(e) = node.tick() {
                    eprintln!("⚠️ tick error: {}", e);
                }
            }

            // Backup only when height changed.
            {
                let node = node_for_loop.read();
                if node.height != last_backup_height {
                    let _ = node.storage.maybe_backup(
                        node.height,
                        node.config.advanced.backup_interval_blocks,
                    );
                    last_backup_height = node.height;
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    // ---- Mining thread ----
    //
    // Design:
    //   Phase 1 (write-lock): prepare_mining_job — build header, merkle, coinbase.
    //   Phase 2 (no lock):    mine_multithreaded — search for a nonce.
    //   Phase 3 (write-lock): commit_mining_result — validate & persist.
    //
    // The write-lock is NOT held during the PoW search, so `tick()` (P2P, RPC)
    // runs concurrently. If a block arrives during Phase 2, `chain_generation`
    // is bumped and `abort_mining` is set; the search exits early, and Phase 3
    // drops the stale job.
    if config.mining.enabled {
        let node_for_miner = node_arc.clone();
        std::thread::spawn(move || {
            println!("⛏️  Mining thread started");
            loop {
                if should_shutdown() {
                    println!("⏳ Shutting down (mining thread)...");
                    break;
                }

                // ---- Phase 1: prepare a job under a short write-lock. ----
                let job = {
                    let mut node = node_for_miner.write();

                    let peers = node.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);
                    let is_syncing = node.p2p.as_ref().map(|p| p.is_syncing()).unwrap_or(false);

                    let our_height = node.height;
                    let best_peer = node
                        .p2p
                        .as_ref()
                        .and_then(|p| p.best_peer_height())
                        .unwrap_or(our_height);
                    let behind = best_peer.saturating_sub(our_height);
                    let not_too_far_behind = behind <= 10;

                    let solo_ok = peers > 0
                        || genesis_mode
                        || config.mining.allow_solo_without_peers;

                    if !is_syncing && not_too_far_behind && solo_ok {
                        node.abort_mining
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        match node.prepare_mining_job() {
                            Ok(j) => Some(j),
                            Err(e) => {
                                eprintln!("⚠️ prepare_mining_job failed: {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    }
                };

                let job = match job {
                    Some(j) => j,
                    None => {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        continue;
                    }
                };

                // ---- Phase 2: mine WITHOUT holding the write-lock. ----
                let (best_nonce, best_hash, found_block) = mine_multithreaded(
                    &job,
                    &node_for_miner,
                    config.mining.threads.max(1) as u64,
                );

                // ---- Phase 3: commit under a short write-lock. ----
                {
                    let mut node = node_for_miner.write();
                    if let Err(e) =
                        node.commit_mining_result(&job, best_nonce, best_hash, found_block)
                    {
                        eprintln!("⚠️ commit_mining_result failed: {}", e);
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
    }

    // ---- main waits for Ctrl+C ----
    tokio::signal::ctrl_c().await?;
    println!("\n⚠️  Received Ctrl+C");
    SHUTDOWN.store(true, AtomicOrdering::SeqCst);

    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("🙋 Goodbye!");
    std::process::exit(0);
}

// ============================================================
// Mining helper: multi-threaded PoW search without holding any lock.
//
// Takes a `MiningJob` and a reference to `node_arc` for reading
// `abort_mining` and `chain_generation` atomics.
// Returns `(best_nonce, best_hash, found_block)`.
// ============================================================
fn mine_multithreaded(
    job: &node::MiningJob,
    node_arc: &std::sync::Arc<parking_lot::RwLock<node::Node>>,
    num_threads: u64,
) -> (u64, Hash32, bool) {
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};

    let difficulty = job.difficulty;
    let target_share = difficulty.share_target();
    let target_prefilter = difficulty.prefilter_target();
    let header_bytes = job.header.to_bytes();
    let gen_at_start = job.generation;

    let best_hash_shared = Arc::new(Mutex::new([0xffu8; 32]));
    let best_nonce_shared = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let block_found = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let num_threads = num_threads.max(1);
    let batch = MINING_BATCH_SIZE;

    std::thread::scope(|scope| {
        for t in 0..num_threads {
            let best_hash_ref = Arc::clone(&best_hash_shared);
            let best_nonce_ref = Arc::clone(&best_nonce_shared);
            let found_ref = Arc::clone(&block_found);
            let node_ref = Arc::clone(node_arc);
            let hb = &header_bytes;

            scope.spawn(move || {
                let mut local_argon2 = Argon2Cache::new(ARGON2_CACHE_SIZE);

                let mut nonce = t;
                while nonce < batch {
                    if found_ref.load(Ordering::Relaxed) {
                        break;
                    }

                    // Read abort + generation without holding the write-lock.
                    {
                        let node = node_ref.read();
                        if node.abort_mining.load(Ordering::Relaxed) {
                            break;
                        }
                        if node.chain_generation.load(Ordering::Relaxed) != gen_at_start {
                            break;
                        }
                    }

                    if !Argon2Cache::prefilter(hb, nonce, &target_prefilter) {
                        nonce += num_threads;
                        continue;
                    }

                    let hash = crate::node::header_with_nonce_hash(hb, nonce, &mut local_argon2);

                    // Block found?
                    if difficulty.is_met_by(&hash) {
                        best_nonce_ref.store(nonce, Ordering::Relaxed);
                        *best_hash_ref.lock().unwrap() = hash;
                        found_ref.store(true, Ordering::Relaxed);
                        break;
                    }

                    // Share found?
                    if target_share.is_met_by(&hash) {
                        let mut best = best_hash_ref.lock().unwrap();
                        if hash < *best {
                            *best = hash;
                            best_nonce_ref.store(nonce, Ordering::Relaxed);
                        }
                    }

                    nonce += num_threads;
                }
            });
        }
    });

    let best_hash = *best_hash_shared.lock().unwrap();
    let best_nonce = best_nonce_shared.load(Ordering::Relaxed);
    let found_block = block_found.load(Ordering::Relaxed);
    (best_nonce, best_hash, found_block)
}