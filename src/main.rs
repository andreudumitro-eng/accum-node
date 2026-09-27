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
        println!("👤 Miner ID: {}...", hex::encode(&node.miner_id[0..8]));
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

            // Backup outside the write-lock.
            {
                let node = node_for_loop.read();
                let _ = node
                    .storage
                    .maybe_backup(node.height, node.config.advanced.backup_interval_blocks);
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    // ---- Mining thread ----
    //
    // Design notes:
    //
    //   - TOCTOU fix: the `can_mine` check and the `mine_block()` call are
    //     done under the SAME write-lock, so no incoming block can land
    //     between the sync check and the mining start.
    //
    //   - solo_ok = peers > 0 || ALLOW_SOLO_GENESIS. If we have at least one
    //     peer, we are part of a network; otherwise, mining only proceeds
    //     when explicitly allowed (genesis day).
    //
    //   - `attempted` = true means "we passed the gate and ran one mining
    //     batch", NOT "we found a block". Finding a block or a share is
    //     reported inside `mine_block` itself.
    //
    //   - The write-lock is held for the entire batch. With
    //     MINING_BATCH_SIZE = 1000 and 8 threads this is ~125 ms — tolerable
    //     for now, but see the TODO below.
    //
    // TODO (long-term): refactor to snapshot + apply.
    //   1. Under read-lock: copy header, prev_hash, difficulty, targets.
    //   2. Release lock, mine in a thread pool WITHOUT the lock.
    //   3. If a block is found, re-acquire write-lock and verify
    //      `self.last_hash() == header.prev_hash`. If it still matches,
    //      apply; otherwise drop (someone beat us to it).
    //   This removes the write-lock from the hashing hot path entirely.
    if config.mining.enabled {
        let node_for_miner = node_arc.clone();
        std::thread::spawn(move || {
            println!("⛏️  Mining thread started");
            loop {
                if should_shutdown() {
                    println!("⏳ Shutting down (mining thread)...");
                    break;
                }

                // Take write-lock ONCE. Check and mine under the same lock.
                let attempted = {
                    let mut node = node_for_miner.write();

                    let peers = node.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);
                    let is_syncing = node.p2p.as_ref().map(|p| p.is_syncing()).unwrap_or(false);
                    let synced = node.sync_progress() >= 0.99;
                    let solo_ok = peers > 0 || genesis_mode;

                    if !is_syncing && synced && solo_ok {
                        node.mine_block();
                        true
                    } else {
                        false
                    }
                }; // write-lock released here

                if !attempted {
                    // Not ready — wait a bit and re-check.
                    std::thread::sleep(std::time::Duration::from_millis(500));
                } else {
                    // Mining batch finished quickly. Yield to other threads
                    // (tick / RPC / P2P) before taking the write-lock again.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        });
    }

    // ---- main waits for Ctrl+C ----
    tokio::signal::ctrl_c().await?;
    println!("\n⚠️  Received Ctrl+C");
    SHUTDOWN.store(true, AtomicOrdering::SeqCst);

    // Give threads time to save state.
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("👋 Goodbye!");
    std::process::exit(0);
}
