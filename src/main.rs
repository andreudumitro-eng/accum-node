// Copyright (c) 2026 Andrii Dumitro
// SPDX-License-Identifier: MIT
//
// ACCUM v3.2+ - Fair Proof-of-Contribution Blockchain Protocol
// FULLY WORKING NODE WITH SOLO MINING + EQUIVOCATION SLASHING
// ============================================================

use argon2::{Algorithm, Argon2, Params, Version};
use bincode;
use dirs;
use hex;
use lazy_static;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::{thread_rng, RngCore};
use ripemd::Ripemd160;
use rocksdb::checkpoint::Checkpoint as RocksdbCheckpoint;
use rocksdb::{IteratorMode, Options, DB};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::signal;
use tokio::time::Duration;
use toml;
use warp::Filter;

mod constants;
use constants::*;
mod types;
use types::*;
mod crypto;
use crypto::*;
mod wallet;
use wallet::*;
mod block;
use block::*;
mod difficulty;
use difficulty::*;
mod config;
use config::*;
mod storage;
use storage::*;
mod miner;
use miner::*;
mod consensus;
use consensus::*;
mod network;
use network::*;
mod p2p;
use p2p::*;
mod genesis;
use genesis::*;
mod node;
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

    match args.get(1).map(|s| s.as_str()) {
        Some("wallet") => {
            handle_wallet_command(&args)?;
        }
        Some("node") => {
            run_node().await?;
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
            // Если нет команды, запускаем ноду по умолчанию
            println!("No command specified, starting node...\n");
            run_node().await?;
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
    println!("\nExamples:");
    println!("  accum node");
    println!("  accum wallet create");
    println!("  accum wallet balance 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    println!("  accum backup");
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
            println!("\n💡 To use this wallet, save the private key and run:");
            println!(
                "   echo '{}' > ~/.accum/wallet.key",
                hex::encode(&wallet.secret_key)
            );
        }
        Some("show") => {
            // ПОКАЗАТЬ ПРИВАТНЫЙ КЛЮЧ
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
            println!("\n💡 To import this wallet, create wallet.json with:");
            println!("   {{\"private_key\": \"{}\"}}", wallet_data.private_key);
            println!("\n✅ Press ENTER to continue...");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
        }
        Some("export") => {
            // ЭКСПОРТ КОШЕЛЬКА В ФАЙЛ
            let wallet_path = dirs::home_dir()
                .ok_or("Cannot find home dir")?
                .join(".accum")
                .join("wallet.json");

            if !wallet_path.exists() {
                println!("❌ Wallet file not found at: {}", wallet_path.display());
                println!("   Create a wallet first with: accum wallet create");
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
            println!("\n💡 To restore, copy this file to:");
            println!("   {}", wallet_path.display());
            println!("\n📜 Private Key in the file:");
            let content = std::fs::read_to_string(&wallet_path)?;
            println!("   {}", content.trim());
        }
        Some("balance") => {
            let address = args.get(3).ok_or("Address required")?;

            println!("📊 Checking balance for {}...", address);

            // Пробуем открыть локальную базу mainnet
            let storage = match ProductionStorage::new("mainnet") {
                Ok(s) => s,
                Err(e) => {
                    println!("❌ Cannot open database: {}", e);
                    println!("   Make sure the node has been run at least once.");
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

            // 1. Загружаем кошелёк
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

            // 2. Открываем базу и получаем UTXO
            let storage = ProductionStorage::new("mainnet")?;
            let utxos = storage.get_utxos_by_address(&wallet.address)?;

            if utxos.is_empty() {
                println!("❌ No UTXOs found for this address");
                return Ok(());
            }

            println!("📦 Found {} UTXO(s)", utxos.len());

            // 3. Создаём и подписываем транзакцию
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

            // 4. Пытаемся отправить через RPC
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
                        println!("   Raw tx (hex) — you can submit it manually later:");
                        println!("{}", tx_hex);
                    }
                }
                Err(e) => {
                    println!("⚠️  Could not connect to node RPC: {}", e);
                    println!("   Make sure the node is running (`accum node`).");
                    println!("\n   Raw tx (hex) — save it and submit later:");
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
            println!("  show    - Show your private key (⚠️  BE CAREFUL!)");
            println!("  export  - Export wallet to backup file");
            println!("  balance - Check wallet balance");
            println!("  send    - Send coins to another address");
            println!("\nExamples:");
            println!("  accum wallet create");
            println!("  accum wallet show");
            println!("  accum wallet export");
            println!("  accum wallet balance 1J6dR35iWewSTNbhuTxX1SB5KxBcGD72qN");
            println!("  accum wallet send 1J6dR35iWewSTNbhuTxX1SB5KxBcGD72qN 1000");
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
            println!("   Run the node at least once: accum node");
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

async fn run_node() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    println!("📋 Loaded configuration from ~/.accum/config.toml");

    let node_arc = Node::new(config.clone())?;

    // RPC сервер
    if config.rpc.enabled {
        let rpc_node = node_arc.clone();
        tokio::spawn(async move {
            let rpc = RpcServer::new(rpc_node, config.rpc.port);
            if let Err(e) = rpc.start().await {
                eprintln!("❌ RPC server error: {}", e);
            }
        });
        println!("📡 RPC server started on port {}", config.rpc.port);
    }

    // Добавляем bond если майнинг включен
    {
        let mut node = node_arc.write();
        if config.mining.enabled {
            let miner_id = node.miner_id;
            node.add_bond(miner_id, config.mining.bond);
            println!("💰 Bond added: {} LYT", config.mining.bond);
        }
    }

    // Graceful shutdown handler
    let node_clone = node_arc.clone();
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        println!("\n\n⚠️  Received Ctrl+C");
        println!("⏳ Shutting down, please wait...");
        SHUTDOWN.store(true, AtomicOrdering::SeqCst);

        // Сохраняем состояние
        {
            let node = node_clone.write();
            set_saving_state(true);
            let _ = node.storage.save_mempool(&node.mempool);
            let _ = node.storage.flush();
            println!("✅ State saved");
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("👋 Goodbye!");
        std::process::exit(0);
    });

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
        } else {
            println!("⛏️  Solo mining DISABLED");
        }
    }
    println!("========================\n");

    let mut node = node_arc.write();
    node.run_with_graceful_shutdown()?;

    Ok(())
}