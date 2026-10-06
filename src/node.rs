//! Node: main node struct and impl

use crate::block::{Block, BlockHeader, Transaction, TxOut};
use crate::config::Config;
use crate::consensus::{calculate_poci, EquivocationProof, PoCIResult, SlashingPool};
use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::difficulty::adjust_difficulty;
use crate::epoch_commit::EpochCommit;
use crate::genesis::create_genesis_block;
use crate::miner::{LoyaltyData, MinerData, Share, SharePacket, SharePool};
use crate::network::{AttackDetection, DDoSProtection};
use crate::p2p::{
    validate_block_coinbase, validate_block_no_double_spend, P2PMessage, P2PNode, SyncManager,
    SyncStatus, MAX_BLOCKS_PER_REQUEST,
};
use crate::storage::{
    Bond, Checkpoint, ProductionStorage, CF_BONDS, CF_CHECKPOINTS, CF_MINERS, CF_STATE,
};
use crate::types::*;
use crate::wallet::Wallet;
use crate::{is_saving_state, set_saving_state, should_shutdown};
use parking_lot::RwLock;
use rocksdb::IteratorMode;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::sync::Mutex;
use secp256k1::PublicKey; 

/// Result of accepting a single block.
/// `AlreadyKnown` is not an error: it just means we have seen the block before.
#[derive(Debug)]
pub enum AcceptError {
    PrevHashMismatch { expected: Hash32, got: Hash32, height: Height },
    AlreadyKnown,
    BadPow,
    BadMerkle,
    BadSignature,
    BadTimestamp,
    BadCoinbase(String),
    BadDoubleSpend(String),
    Storage(String),
}

impl AcceptError {
    /// Returns `true` if this error indicates a misbehaving peer
    /// (should be banned), `false` for benign races or local errors.
    pub fn is_attack(&self) -> bool {
        match self {
            // Benign: a race, not an attack.
            AcceptError::PrevHashMismatch { .. } => false,
            // Already known — not an attack, just redundant.
            AcceptError::AlreadyKnown => false,
            // Local storage error — not the peer's fault.
            AcceptError::Storage(_) => false,
            // Everything else: invalid block → ban the peer.
            _ => true,
        }
    }

    /// Short human-readable description for logs.
    pub fn describe(&self) -> String {
        match self {
            AcceptError::PrevHashMismatch { expected, got, height } => format!(
                "Invalid prev_hash at height {} (expected {}..., got {}...)",
                height,
                hex::encode(&expected[0..8]),
                hex::encode(&got[0..8]),
            ),
            AcceptError::AlreadyKnown => "Block already known".to_string(),
            AcceptError::BadPow => "PoW check failed".to_string(),
            AcceptError::BadMerkle => "Invalid merkle root".to_string(),
            AcceptError::BadSignature => "Invalid block signature".to_string(),
            AcceptError::BadTimestamp => "Invalid block timestamp".to_string(),
            AcceptError::BadCoinbase(msg) => format!("Invalid coinbase: {}", msg),
            AcceptError::BadDoubleSpend(msg) => format!("Double spend: {}", msg),
            AcceptError::Storage(msg) => format!("Storage error: {}", msg),
        }
    }
}

/// A prepared mining job: everything needed to run the PoW search
/// without holding the Node write-lock.
pub struct MiningJob {
    pub prev_hash: Hash32,
    pub height: Height,
    pub epoch: u32,
    pub difficulty: Target,
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
    pub generation: u64,
}

/// How many recent heights we keep txids in `processed_txids` for dedup.
const PROCESSED_TXIDS_RETENTION: Height = 1_000;

/// Genesis emission (LYT).
const GENESIS_SUPPLY_LYT: u64 = 500_000_000;

/// Drop-guard: restores `sync_manager` into `node.p2p` even on panic.
struct SyncManagerRestore<'a> {
    node: &'a mut Node,
    sync_manager: Option<SyncManager>,
}

impl<'a> Drop for SyncManagerRestore<'a> {
    fn drop(&mut self) {
        if let (Some(p2p), Some(sm)) = (self.node.p2p.as_mut(), self.sync_manager.take()) {
            p2p.sync_manager = sm;
        }
    }
}

pub struct Node {
    pub height: Height,
    pub epoch: u32,
    pub blocks: Vec<BlockHeader>,
    pub block_hashes: HashMap<Hash32, Height>,
    pub timestamps: Vec<Timestamp>,
    pub storage: ProductionStorage,
    pub mempool: Vec<Transaction>,
    pub miners: HashMap<MinerId, MinerData>,
    pub bonds: HashMap<MinerId, Bond>,
    pub loyalty: HashMap<MinerId, LoyaltyData>,
    pub share_pool: SharePool,
    pub argon2: Argon2Cache,
    pub p2p: Option<P2PNode>,
    pub blocks_found: u64,
    pub shares_found: u64,
    pub start_time: Timestamp,
    pub miner_id: MinerId,
    pub last_hash_rate: u64,
    pub peak_hash_rate: u64,
    pub wallet: Option<Wallet>,
    pub config: Config,
    pub slashing_pool: SlashingPool,
    pub attack_detection: AttackDetection,
    pub checkpoints: Vec<Checkpoint>,
    pub ddos_protection: DDoSProtection,
    pub processed_txids: HashMap<Txid, Height>,
    pub sync_manager: SyncManager,
    pub total_emitted: u64,
    pub last_block_time_secs: u64,
    pub last_nonce: u64,
    pub last_stats_time: Timestamp,
    pub last_sync_request_time: Timestamp,
    pub last_share_time: Timestamp,
    pub last_reconnect_time: Timestamp,
    pub last_version_broadcast: Timestamp,
    pub last_register_broadcast: Timestamp,
    pub cached_difficulty: Option<(Height, Target)>,

    /// Set to `true` when a new block is accepted, so the mining
    /// thread can abort its current batch ASAP.
    pub abort_mining: Arc<AtomicBool>,

    /// Monotonic counter of chain version.
    /// Incremented whenever the tip changes.
    pub chain_generation: Arc<AtomicU64>,
    
    /// Alternative chain branches.
    /// Key: hash of the **parent** block (fork point).
    /// Value: blocks built on top of that parent.
    /// Used by the fork-choice logic to store competing branches.
    pub forks: HashMap<Hash32, Vec<Block>>,
    pub pending_rewards: HashMap<u32, Vec<(MinerId, u64)>>,
    pub last_resync_at: HashMap<u32, Timestamp>,
}

impl Node {
    // ------------------------------------------------------------------
    // Construction / bootstrap
    // ------------------------------------------------------------------

    pub fn new(config: Config) -> Result<Arc<RwLock<Self>>, String> {
        println!("🔧 [1] Creating storage...");
        let network = "mainnet";
        let storage = ProductionStorage::new(network)?;
        println!("🔧 [2] Storage created");

        println!("🔧 [3] Getting height...");
        let height = storage.get_height()?;
        println!("🔧 [4] Height: {}", height);

        println!("🔧 [5] Getting epoch...");
        let epoch = storage.get_state::<u32>("epoch")?.unwrap_or(1);
        println!("🔧 [6] Epoch: {}", epoch);

        println!("🔧 [7] Loading wallet...");
        let wallet = Self::load_or_create_wallet(&storage)?;
        let miner_id = wallet.miner_id;
        println!("🔧 [8] Wallet loaded: {}", wallet.address);

        let now = current_timestamp();
        println!("🔧 [9] Creating node struct...");
        let mut node = Self {
            height,
            epoch,
            blocks: Vec::new(),
            block_hashes: HashMap::new(),
            timestamps: Vec::new(),
            storage,
            mempool: Vec::new(),
            miners: HashMap::new(),
            bonds: HashMap::new(),
            loyalty: HashMap::new(),
            share_pool: SharePool::new(config.advanced.share_pool_memory_mb),
            argon2: Argon2Cache::new(ARGON2_CACHE_SIZE),
            p2p: None,
            blocks_found: 0,
            shares_found: 0,
            start_time: now,
            miner_id,
            last_hash_rate: 0,
            peak_hash_rate: 0,
            wallet: Some(wallet),
            config: config.clone(),
            slashing_pool: SlashingPool::new(),
            attack_detection: AttackDetection::new(),
            checkpoints: Vec::new(),
            ddos_protection: DDoSProtection::new(),
            processed_txids: HashMap::new(),
            sync_manager: SyncManager::new(),
            total_emitted: 0,
            last_block_time_secs: 0,
            last_nonce: 0,
            last_stats_time: now,
            last_sync_request_time: 0,
            last_share_time: now,
            last_reconnect_time: 0,
            last_version_broadcast: 0,
            last_register_broadcast: 0,
            cached_difficulty: None,
            abort_mining: Arc::new(AtomicBool::new(false)),
            chain_generation: Arc::new(AtomicU64::new(0)),
            forks: HashMap::new(),
            pending_rewards: HashMap::new(),
            last_resync_at: HashMap::new(),
        };
        println!("🔧 [10] Node struct created");

        println!("🔧 [11] Loading state...");
        if height == 0 {
            println!("🔧 [12] Initializing genesis...");
            node.init_genesis();
        } else {
            println!("🔧 [12] Loading state from DB...");
            node.load_state()?;
            println!("🔧 [13] Verifying genesis signature...");
            if !node.verify_genesis_signature() {
                return Err("Genesis block verification failed".to_string());
            }
        }
        node.share_pool.current_epoch = node.epoch;
        println!("🔧 [14] State loaded");

        println!("🔧 [15] Loading checkpoints...");
        node.load_checkpoints()?;
        println!("🔧 [16] Checkpoints loaded");

        println!("🔧 [17] Creating node_arc...");
        let node_arc = Arc::new(RwLock::new(node));
        println!("🔧 [18] Node_arc created");

        println!("🔧 [19] Creating P2P...");
        let mut p2p = P2PNode::new(
            config.network.port,
            config.network.bootnodes.clone(),
        )
        .map_err(|e| e.to_string())?;
        println!("🔧 [20] P2P created");

        {
            let mut node = node_arc.write();
            let height = node.height;
            let best_hash = node.last_hash();

            node.p2p = Some(p2p);

            if let Some(p2p) = &mut node.p2p {
                p2p.set_local_state(height, best_hash);
                p2p.connect_to_bootnodes();
            }
        
            // Broadcast RegisterMiner right after connect.
            node.broadcast_register_miner();
        }

        println!("🔧 [21] Node creation complete!");
        Ok(node_arc)
    }

    // ------------------------------------------------------------------
    // Wallet
    // ------------------------------------------------------------------

    fn load_or_create_wallet(storage: &ProductionStorage) -> Result<Wallet, String> {
        let wallet_path = dirs::home_dir()
            .ok_or("Cannot find home dir")?
            .join(".accum")
            .join("wallet.json");

        if wallet_path.exists() {
            println!("🔑 Loading wallet from {}", wallet_path.display());
            let content = fs::read_to_string(&wallet_path)
                .map_err(|e| format!("Failed to read wallet: {}", e))?;

            #[derive(serde::Deserialize)]
            struct WalletFile {
                private_key: String,
            }

            let wallet_data: WalletFile = serde_json::from_str(&content)
                .map_err(|e| format!("Invalid wallet file: {}", e))?;

            let secret_key = hex::decode(&wallet_data.private_key)
                .map_err(|_| "Invalid private key format".to_string())?;

            let wallet = Wallet::from_secret_key(&secret_key)?;
            println!("✅ Wallet loaded: {}", wallet.address);
            return Ok(wallet);
        }

        if let Some(wallet_data) = storage.get_state::<Vec<u8>>("wallet")? {
            println!("🔑 Loading wallet from database...");
            let secret_key: [u8; 32] = wallet_data
                .try_into()
                .map_err(|_| "Invalid wallet data".to_string())?;
            let wallet = Wallet::from_secret_key(&secret_key)?;

            let wallet_json = serde_json::json!({
                "private_key": hex::encode(&wallet.secret_key),
            });
            if let Some(parent) = wallet_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create .accum directory: {}", e))?;
            }
            fs::write(
                &wallet_path,
                serde_json::to_string_pretty(&wallet_json).unwrap(),
            )
            .map_err(|e| format!("Failed to save wallet: {}", e))?;
            println!("✅ Wallet saved to {}", wallet_path.display());

            return Ok(wallet);
        }

        println!("🆕 No wallet found, creating new wallet...");
        let wallet = Wallet::generate()?;

        let wallet_json = serde_json::json!({
            "private_key": hex::encode(&wallet.secret_key),
        });
        if let Some(parent) = wallet_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create .accum directory: {}", e))?;
        }
        fs::write(
            &wallet_path,
            serde_json::to_string_pretty(&wallet_json).unwrap(),
        )
        .map_err(|e| format!("Failed to save wallet: {}", e))?;

        storage.save_state("wallet", &wallet.secret_key.to_vec())?;

        println!("✅ New wallet created!");
        println!("📫 Address: {}", wallet.address);
        println!("🆔 Miner ID: {}", hex::encode(&wallet.miner_id));
        println!("📜 Private Key: {}", hex::encode(&wallet.secret_key));
        println!("⚠️  BACKUP YOUR WALLET FILE: ~/.accum/wallet.json");

        Ok(wallet)
    }

    // ------------------------------------------------------------------
    // State loading
    // ------------------------------------------------------------------

    fn load_state(&mut self) -> Result<(), String> {
        println!("📂 Loading blocks...");
        let denom = self.height.max(1) as f64;
        for h in 0..=self.height {
            if h % 10 == 0 || h == self.height {
                println!(
                    "   ⏳ Loading block {}/{} ({:.1}%)",
                    h,
                    self.height,
                    (h as f64 / denom) * 100.0
                );
            }
            if let Some(block) = self.storage.get_block(h)? {
                let hash = block.header.hash(&mut self.argon2);
                let header = block.header.clone();
                self.blocks.push(header);
                self.block_hashes.insert(hash, h);
                self.timestamps.push(block.header.timestamp);
            }
        }
        println!("   ✅ Blocks loaded: {}", self.blocks.len());

        println!("📂 Loading miners...");
        let mut miner_count = 0usize;
        let mut iter = self
            .storage
            .db
            .iterator_cf(self.storage.cf_handle(CF_MINERS), IteratorMode::Start);
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(miner) = bincode::deserialize::<MinerData>(&value) {
                self.miners.insert(miner.miner_id, miner);
                miner_count += 1;
            }
        }
        println!("   ✅ Miners loaded: {}", miner_count);

        println!("📂 Loading bonds...");
        let mut bond_count = 0usize;
        let mut iter = self
            .storage
            .db
            .iterator_cf(self.storage.cf_handle(CF_BONDS), IteratorMode::Start);
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(bond) = bincode::deserialize::<Bond>(&value) {
                self.bonds.insert(bond.miner_id, bond);
                bond_count += 1;
            }
        }
        println!("   ✅ Bonds loaded: {}", bond_count);

        println!("📂 Loading loyalty...");
        let mut loyalty_count = 0usize;
        let mut iter = self
            .storage
            .db
            .iterator_cf(self.storage.cf_handle(CF_STATE), IteratorMode::Start);
        while let Some(Ok((key, value))) = iter.next() {
            if let Ok(key_str) = std::str::from_utf8(&key) {
                if let Some(hex_part) = key_str.strip_prefix("loyalty_") {
                    if let Ok(loyalty) = bincode::deserialize::<LoyaltyData>(&value) {
                        if let Ok(bytes) = hex::decode(hex_part) {
                            if bytes.len() == 20 {
                                let mut miner_id = [0u8; 20];
                                miner_id.copy_from_slice(&bytes);
                                self.loyalty.insert(miner_id, loyalty);
                                loyalty_count += 1;
                            }
                        }
                    }
                }
            }
        }
        println!("   ✅ Loyalty loaded: {}", loyalty_count);

        println!("📂 Loading emission...");
        self.total_emitted = self.storage.get_state::<u64>("total_emitted")?.unwrap_or(0);
        println!("   ✅ Total emitted: {} LYT", self.total_emitted);

        // Check for incomplete epoch: if epoch_processing == N,
        // the previous process_epoch_end did not finish.
        if let Some(processing_epoch) = self.storage.get_state::<u32>("epoch_processing")? {
            if processing_epoch == self.epoch {
                println!(
                    "⚠️ Found incomplete epoch {} — rewards may have been partially paid",
                    processing_epoch
                );
                // Increment epoch so process_epoch_end never runs again.
                // Any double-payment damage is already done — this only
                // protects against a second run.
                self.epoch = self.epoch.saturating_add(1);
                let _ = self.storage.save_state("epoch", &self.epoch);
                let _ = self.storage.delete_state("epoch_processing");
                println!("   ✅ Epoch {} marked as completed (recovery)", processing_epoch);
            }
        }

        // Rebuild processed_txids from the last N blocks.
        // We only keep txids from the last PROCESSED_TXIDS_RETENTION blocks
        // to bound memory; the same window is used in prune_processed_txids.
        println!("📂 Rebuilding processed_txids...");
        let from_height = self.height.saturating_sub(PROCESSED_TXIDS_RETENTION);
        let mut txid_count = 0usize;
        for h in from_height..=self.height {
            if let Ok(Some(block)) = self.storage.get_block(h) {
                for tx in &block.transactions {
                    if !tx.is_coinbase() {
                        let txid = tx.txid(&mut self.argon2);
                        self.processed_txids.insert(txid, h);
                        txid_count += 1;
                    }
                }
            }
        }
        println!("   ✅ Processed txids rebuilt: {}", txid_count);

        println!("📂 Loading mempool...");
        self.mempool = self.storage.load_mempool()?;
        println!("   ✅ Mempool loaded: {}", self.mempool.len());
        println!("💾 ✅ State loaded successfully!");
        println!(
            "   Height: {}, Miners: {}, Bonds: {}, Loyalty: {}",
            self.height,
            self.miners.len(),
            self.bonds.len(),
            self.loyalty.len()
        );

        // Load share archives for the last EPOCH_ARCHIVE_DEPTH epochs.
        println!("📂 Loading share archives...");
        let min_epoch = self.epoch.saturating_sub(EPOCH_ARCHIVE_DEPTH);
        let mut archive_count = 0usize;
        for e in min_epoch..=self.epoch {
            if let Ok(shares) = self.storage.load_shares_archive(e) {
                if !shares.is_empty() {
                    let root_key = format!("epoch_share_root_{}", e);
                    if let Ok(Some(root)) = self.storage.get_state::<Hash32>(&root_key) {
                        self.share_pool.epoch_roots.insert(e, root);
                    }
                    self.share_pool.archive.insert(e, shares);
                    archive_count += 1;
                }
            }
        }
        println!("   ✅ Share archives loaded: {}", archive_count);

        Ok(())
    }

    fn load_checkpoints(&mut self) -> Result<(), String> {
        let mut iter = self
            .storage
            .db
            .iterator_cf(self.storage.cf_handle(CF_CHECKPOINTS), IteratorMode::Start);
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(checkpoint) = bincode::deserialize::<Checkpoint>(&value) {
                self.checkpoints.push(checkpoint);
            }
        }
        self.checkpoints.sort_by_key(|c| c.height);

        if let Some(last) = self.checkpoints.last() {
            println!(
                "📌 Loaded {} checkpoints, latest at height {}",
                self.checkpoints.len(),
                last.height
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Genesis
    // ------------------------------------------------------------------

    fn init_genesis(&mut self) {
        let genesis_block = create_genesis_block(self.wallet.as_ref().unwrap());
        let header = genesis_block.header.clone();
        let coinbase = genesis_block.transactions[0].clone();
        let txid = coinbase.txid(&mut self.argon2);

        let mut header = header;
        header.merkle_root = txid;

        let outpoint = (txid, 0);
        if let Err(e) = self.storage.save_utxo(&outpoint, &coinbase.outputs[0]) {
            println!("⚠️ Failed to save genesis UTXO: {}", e);
        }

        let hash = header.hash(&mut self.argon2);

        let (signature, pubkey) = if let Some(wallet) = &self.wallet {
            (
                wallet.sign_block(&hash).ok(),
                Some(wallet.public_key.clone()),
            )
        } else {
            (None, None)
        };

        let block = Block {
            header: header.clone(),
            transactions: vec![coinbase],
            signature: signature.clone(),
            pubkey,
        };

        self.blocks.push(header.clone());
        self.block_hashes.insert(hash, 0);
        self.timestamps.push(header.timestamp);

        

        if let Err(e) = self.storage.save_block(0, &block) {
            println!("⚠️ Failed to save genesis block: {}", e);
        }
        if let Err(e) = self.storage.save_state("height", &0u64) {
            println!("⚠️ Failed to save height: {}", e);
        }
        if let Err(e) = self.storage.save_state("epoch", &1u32) {
            println!("⚠️ Failed to save epoch: {}", e);
        }

        self.total_emitted = GENESIS_SUPPLY_LYT;
        if let Err(e) = self
            .storage
            .save_state("total_emitted", &self.total_emitted)
        {
            println!("⚠️ Failed to save total_emitted: {}", e);
        }

        println!("✅ Genesis block created");
        println!("   Hash: {}...", hex::encode(&hash[0..8]));
        if let Some(sig) = &signature {
            println!("   Signature: {}...", hex::encode(&sig[0..8]));
        }
        println!("   Height: 0\n");
    }

    fn verify_genesis_signature(&self) -> bool {
        let block = match self.storage.get_block(0) {
            Ok(Some(b)) => b,
            Ok(None) => {
                println!("⚠️ Genesis block not found!");
                return false;
            }
            Err(e) => {
                println!("❌ Error reading genesis block: {}", e);
                return false;
            }
        };

        // Genesis должен иметь ровно одну транзакцию (coinbase).
        if block.transactions.len() != 1 {
            println!(
                "❌ Genesis has {} transactions, expected 1",
                block.transactions.len()
            );
            return false;
        }

        // Проверяем, что merkle_root совпадает с txid coinbase.
        let mut argon2 = Argon2Cache::new(ARGON2_CACHE_SIZE);
        let coinbase_txid = block.transactions[0].txid(&mut argon2);
        if block.header.merkle_root != coinbase_txid {
            println!("❌ Genesis merkle_root does not match coinbase txid");
            return false;
        }

        // Проверяем, что prev_hash нулевой.
        if block.header.prev_hash != [0u8; 32] {
            println!("❌ Genesis prev_hash is not zero");
            return false;
        }

        println!("✅ Genesis block verified");
        true
    }

    // ------------------------------------------------------------------
    // Chain accessors
    // ------------------------------------------------------------------

    fn last_block(&self) -> Option<&BlockHeader> {
        self.blocks.last()
    }

    pub fn last_hash(&mut self) -> Hash32 {
        if let Some(last) = self.last_block().cloned() {
            last.hash(&mut self.argon2)
        } else {
            [0; 32]
        }
    }

        /// Compute Merkle root of a set of SharePackets.
    /// Shares must be sorted by (miner_id, hash) before calling — the
    /// canonical order is enforced by the caller.
    pub fn compute_share_merkle_root(shares: &[SharePacket]) -> Hash32 {
        if shares.is_empty() {
            return [0u8; 32];
        }

        let mut hashes: Vec<Hash32> = shares
            .iter()
            .map(|s| s.canonical_hash())
            .collect();

        while hashes.len() > 1 {
            let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let d = Sha256::digest(&data);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&d);
                next.push(arr);
            }
            hashes = next;
        }
        hashes[0]
    }

    /// Validate an incoming SharePacket against the current difficulty.
    /// Returns Ok(()) if the share is well-formed and its PoW is valid.
    pub fn validate_share_packet(
        &mut self,
        share: &SharePacket,
        expected_epoch: u32,
    ) -> Result<(), &'static str> {
        let target_share = self.last_difficulty().share_target();
        share.validate(&target_share, expected_epoch, &mut self.argon2)
    }

    fn last_difficulty(&self) -> Target {
        self.last_block()
            .map(|b| b.difficulty)
            .unwrap_or_else(Target::genesis)
    }
       /// Difficulty for the next block (height + 1).
    /// Retargeted every DIFFICULTY_ADJUSTMENT_INTERVAL blocks.
    ///
    /// Retarget triggers when the NEXT block is a multiple of the interval:
    /// (height + 1) % interval == 0.
    /// The window timestamps[len - window ..] contains exactly `window` real
    /// blocks (genesis is not pushed into self.timestamps).
    pub fn compute_difficulty_for_next_block(&mut self) -> Target {
        let interval = DIFFICULTY_ADJUSTMENT_INTERVAL;

        // Retarget for the NEXT block: check (height + 1) % interval == 0.
        if self.height == 0 || (self.height + 1) % interval != 0 {
            return self.last_difficulty();
        }

        // Cache: already computed for this height.
        if let Some((h, t)) = self.cached_difficulty {
            if h == self.height {
                return t;
            }
        }

        // Need `interval` timestamps: [len - interval ..].
        let window = interval as usize;
        if self.timestamps.len() < window {
            return self.last_difficulty();
        }

        let slice = &self.timestamps[self.timestamps.len() - window..];
        let current_target = self.last_difficulty();

        // ---- Diagnostic: log retarget window ----
        {
            let actual = slice
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_sub(slice.first().copied().unwrap_or(0));
            let expected = TARGET_BLOCK_TIME * (interval - 1);
            println!(
                "⚙️ Retarget at height {} (block {}): window={} blocks, actual={}s, expected={}s, avg={:.2}s",
                self.height,
                self.height + 1,
                window,
                actual,
                expected,
                actual as f64 / (interval - 1) as f64,
            );
        }

        let adjusted = adjust_difficulty(slice, &current_target);

        if adjusted != current_target {
            println!(
                "⚙️ Difficulty adjusted at height {} → new target for block {} (diff={:.6e}, nbits={:08x})",
                self.height,
                self.height + 1,
                adjusted.to_difficulty(),
                adjusted.compact(),
            );
        } else {
            println!(
                "⚙️ Retarget result: target unchanged (diff={:.6e}, nbits={:08x})",
                adjusted.to_difficulty(),
                adjusted.compact(),
            );
        }

        self.cached_difficulty = Some((self.height, adjusted));
        adjusted
    }

    pub fn sync_progress(&self) -> f64 {
        let our_height = self.height;

        let best_peer = match &self.p2p {
            None => return 1.0,
            Some(p2p) => match p2p.best_peer_height() {
                None => return 1.0,
                Some(0) => return 1.0,
                Some(h) => h,
            },
        };

        if best_peer <= our_height {
            return 1.0;
        }

        (our_height as f64 / best_peer as f64).min(1.0)
    }

    pub fn median_timestamp(&self) -> Option<Timestamp> {
        const MEDIAN_WINDOW: usize = 11;

        // Take a window of the last 11 timestamps.
        // If there are fewer — use whatever is available
        // (but not less than 3, otherwise the median is meaningless).
        let take = MEDIAN_WINDOW.min(self.timestamps.len());
        if take < 3 {
            return None;
        }

        let mut last: Vec<Timestamp> = self
            .timestamps
            .iter()
            .rev()
            .take(take)
            .copied()
            .collect();
        last.sort_unstable();
        Some(last[take / 2])
    }

    // ------------------------------------------------------------------
    // Epoch commit
    // ------------------------------------------------------------------

    pub fn build_epoch_commit(
        &self,
        completed_epoch: u32,
        previous_commit_hash: Hash32,
    ) -> EpochCommit {
        EpochCommit::build(
            completed_epoch,
            self.height,
            previous_commit_hash,
            &self.share_pool.share_count,
            &self.bonds,
            &self.loyalty,
        )
    }

    pub fn checkpoint_at(&self, height: Height) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.height == height)
    }

    // ------------------------------------------------------------------
    // Bonds / shares
    // ------------------------------------------------------------------

    pub fn add_bond(&mut self, miner_id: MinerId, amount: u64) {
        if amount < MINIMUM_BOND_LYT {
            println!(
                "⚠️ Bond below minimum: {} LYT (min: {} LYT)",
                amount, MINIMUM_BOND_LYT
            );
            return;
        }

        let bond = Bond::new(amount, self.height, miner_id);
        self.bonds.insert(miner_id, bond.clone());
        if let Err(e) = self.storage.save_bond(&miner_id, &bond) {
            println!("⚠️ Failed to save bond: {}", e);
        }

        if let Some(miner) = self.miners.get_mut(&miner_id) {
            miner.bond = amount;
            // Set payout address for the local miner from the wallet.
            if miner_id == self.miner_id {
                if let Some(wallet) = &self.wallet {
                    miner.payout_address = Some(wallet.address.clone());
                }
            }
            if let Err(e) = self.storage.save_miner(&miner_id, miner) {
                println!("⚠️ Failed to persist miner after bond: {}", e);
            }
        }

        println!(
            "💰 Bond added for {}...: {} LYT",
            hex::encode(&miner_id[0..8]),
            amount
        );
    }

    pub fn add_share(&mut self, share: Share) -> bool {
        let miner_id = share.miner_id;
        let now = share.timestamp;
        let current_epoch = self.epoch;

        if let Some(miner) = self.miners.get(&miner_id) {
            if miner.is_banned(now) {
                return false;
            }
        }

        let bond_active = self
            .bonds
            .get(&miner_id)
            .map(|b| b.is_active(self.height))
            .unwrap_or(false);
        if !bond_active {
            return false;
        }

        let bond_amount = self.bonds.get(&miner_id).map(|b| b.amount).unwrap_or(0);

        let target_share = self.last_difficulty().share_target();
        let expected_prev = self.last_hash();

        let is_valid = match share.validate(
            &target_share,
            &expected_prev,
            current_epoch,
            now,
            &mut self.argon2,
        ) {
            Ok(_) => true,
            Err(e) => {
                println!("Invalid share: {}", e);
                false
            }
        };

        match self.share_pool.add_share(share.clone(), is_valid) {
            Ok(true) => {
                {
                    let miner = self.miners.entry(miner_id).or_insert_with(|| {
                        MinerData::new(miner_id, bond_amount, current_epoch, now)
                    });
                    miner.add_share(now);
                }
                if let Some(miner) = self.miners.get(&miner_id) {
                    if let Err(e) = self.storage.save_miner(&miner_id, miner) {
                        println!(
                            "⚠️ Failed to save miner {}: {}",
                            hex::encode(&miner_id[0..6]),
                            e
                        );
                    }
                }

                {
                    let loyalty = self
                        .loyalty
                        .entry(miner_id)
                        .or_insert_with(LoyaltyData::new);
                    loyalty.update(current_epoch, true);
                }
                if let Some(loyalty) = self.loyalty.get(&miner_id) {
                    let key = format!("loyalty_{}", hex::encode(&miner_id));
                    if let Err(e) = self.storage.save_state(&key, loyalty) {
                        println!(
                            "⚠️ Failed to save loyalty {}: {}",
                            hex::encode(&miner_id[0..6]),
                            e
                        );
                    }
                }

                self.shares_found += 1;
                self.last_share_time = now;

                if self.shares_found % 100 == 0 {
                    print!(".");
                    let _ = std::io::stdout().flush();
                }
                true
            }
            Ok(false) => false,
            Err(_e) => {
                if let Some(miner) = self.miners.get_mut(&miner_id) {
                    let ratio = self.share_pool.invalid_ratio(&miner_id);
                    miner.update_invalid_ratio(ratio, now);
                    let _ = self.storage.save_miner(&miner_id, miner);
                }
                false
            }
        }
    }

    // ------------------------------------------------------------------
    // Mempool
    // ------------------------------------------------------------------

    fn sort_mempool_by_fee(&mut self) {
        let storage = &self.storage;
        self.mempool.sort_by(|a, b| {
            let fee_a = a.fee(storage).unwrap_or(0);
            let fee_b = b.fee(storage).unwrap_or(0);
            fee_b.cmp(&fee_a)
        });
    }

    fn prune_processed_txids(&mut self) {
        if self.processed_txids.is_empty() {
            return;
        }

        // Собираем txid из текущего mempool — их нельзя удалять из processed_txids,
        // иначе та же транзакция может быть принята повторно.
        let mempool_txids: HashSet<Txid> = self
            .mempool
            .iter()
            .map(|tx| tx.txid(&mut self.argon2))
            .collect();

        let cutoff = self.height.saturating_sub(PROCESSED_TXIDS_RETENTION);
        self.processed_txids
            .retain(|txid, h| *h > cutoff || mempool_txids.contains(txid));
    }

    pub fn add_transaction_to_mempool(&mut self, tx: Transaction) -> Result<(), String> {
        tx.validate_basic()
            .map_err(|e| format!("Invalid transaction: {}", e))?;
        tx.validate(&self.storage)
            .map_err(|e| format!("Transaction validation failed: {}", e))?;

        let txid = tx.txid(&mut self.argon2);

        if self.processed_txids.contains_key(&txid) {
            return Err("Transaction already processed".to_string());
        }

        for existing_tx in &self.mempool {
            if existing_tx.txid(&mut self.argon2) == txid {
                return Err("Transaction already in mempool".to_string());
            }
        }

        let mut used_inputs = HashSet::new();
        for existing_tx in &self.mempool {
            for input in &existing_tx.inputs {
                if !input.is_coinbase() {
                    used_inputs.insert(input.outpoint());
                }
            }
        }
        for input in &tx.inputs {
            if !input.is_coinbase() && used_inputs.contains(&input.outpoint()) {
                return Err("Input already used in mempool transaction".to_string());
            }
        }

        self.mempool.push(tx);
        self.processed_txids.insert(txid, self.height);
        self.sort_mempool_by_fee();

        while self.mempool.len() > self.config.advanced.max_mempool_size {
            if let Some(removed) = self.mempool.pop() {
                let removed_txid = removed.txid(&mut self.argon2);
                self.processed_txids.remove(&removed_txid);
            }
        }

        let _ = self.storage.save_mempool(&self.mempool);

        println!(
            "✅ Transaction added to mempool: {}",
            hex::encode(&txid[0..8])
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // Equivocation reporting
    // ------------------------------------------------------------------

    pub fn report_equivocation(&mut self, proof: EquivocationProof) {
        self.slashing_pool.add_proof(proof);
    }

    fn process_pending_slashes(&mut self) -> Result<usize, String> {
        let height = self.height;
        let records = {
            let pool = &mut self.slashing_pool;
            let storage = &self.storage;
            let argon2 = &mut self.argon2;
            pool.process_all(storage, argon2, height)?
        };

        let n = records.len();
        for record in &records {
            self.bonds.remove(&record.miner_id);

            // Remove miner from the active set — otherwise it stays
            // in PoCI with bond = 0 and may still receive rewards.
            self.miners.remove(&record.miner_id);

            // Remove from loyalty — miner is slashed, history is irrelevant.
            self.loyalty.remove(&record.miner_id);

            // Remove from storage.
            if let Err(e) = self.storage.delete_miner(&record.miner_id) {
                println!(
                    "   ⚠️ Failed to delete slashed miner {}: {}",
                    hex::encode(&record.miner_id[0..6]),
                    e
                );
            }
            let loyalty_key = format!("loyalty_{}", hex::encode(&record.miner_id));
            let _ = self.storage.delete_state(&loyalty_key);
        }
        Ok(n)
    }

    // ------------------------------------------------------------------
    // Main loop
    // ------------------------------------------------------------------

    pub fn tick(&mut self) -> Result<(), String> {
        // 1. Incoming P2P messages.
        //    process_messages only reads from sockets — it does NOT
        //    touch Node. Actual handling is done below under our write-lock.
        let incoming = if let Some(p2p) = self.p2p.as_mut() {
            match p2p.process_messages() {
                Ok(msgs) => msgs,
                Err(e) => {
                    println!("⚠️ P2P error: {}", e);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

               // Dispatch epoch-commit / share-sync messages to dedicated handlers.
        // All other messages go to handle_p2p_message.
        for (msg, addr) in incoming {
            match msg {
                P2PMessage::EpochCommit { epoch, commit_root, timestamp } => {
                    self.handle_epoch_commit(addr, epoch, commit_root, timestamp);
                }
                P2PMessage::GetShares { epoch, offset, max_count, miner_id } => {
                    self.handle_get_shares(addr, epoch, offset, max_count, miner_id);
                }
                P2PMessage::ShareReply { epoch, shares, total_available } => {
                    self.handle_share_reply(addr, epoch, shares, total_available);
                }
                P2PMessage::GetShareProof { epoch, share_hash } => {
                    self.handle_get_share_proof(addr, epoch, share_hash);
                }
                P2PMessage::ShareProof { epoch, share, merkle_path } => {
                    self.handle_share_proof(addr, epoch, share, merkle_path);
                }
                _ => {
                    self.handle_p2p_message(msg, addr);
                }
            }
        }

        // 2. Accept new connections.
        if let Some(p2p) = self.p2p.as_mut() {
            if let Err(e) = p2p.accept_connections() {
                println!("⚠️ Accept error: {}", e);
            }
        }

        // 3. Start sync if needed.
        if let Some(p2p) = self.p2p.as_mut() {
            if p2p.needs_sync() {
                if let Some(peer) = p2p.sync_manager.best_peer() {
                    p2p.sync_manager.start_sync(peer);
                }
            }
        }

                // 3c. Periodic Version broadcast so peers learn our height.
                {
                    let now = current_timestamp();
                    if now.saturating_sub(self.last_version_broadcast) >= 30 {
                        if let Some(p2p) = self.p2p.as_mut() {
                            p2p.broadcast_version();
                        }
                        self.last_version_broadcast = now;
                    }
                }

                // 3b. Auto-reconnect to bootnodes if we have no peers.
        // Handles the case where the internet drops and all peers
        // disconnect — the node tries to reconnect automatically.
        {
            let now = current_timestamp();
            let should_reconnect = self
                .p2p
                .as_ref()
                .map(|p| p.peers.is_empty())
                .unwrap_or(false);

            if should_reconnect && now.saturating_sub(self.last_reconnect_time) >= 30 {
                if let Some(p2p) = self.p2p.as_mut() {
                    println!("🔄 No peers — attempting to reconnect to bootnodes...");
                    p2p.connect_to_bootnodes();
                }
                self.last_reconnect_time = now;
            }
        }

                // 3d. Periodic RegisterMiner broadcast every 60 seconds.
                {
                    let now = current_timestamp();
                    if now.saturating_sub(self.last_register_broadcast) >= 60 {
                        self.broadcast_register_miner();
                        self.last_register_broadcast = now;
                    }
                }

        // 4. Handle sync timeouts.
        if let Some(p2p) = self.p2p.as_mut() {
            if let Some(_peer_id) = p2p.sync_manager.check_timeouts() {
                println!("⚠️ Sync timeout with peer");
                p2p.sync_manager.active_session = None;
                p2p.sync_manager.sync_in_progress = false;
            }
        }

                        // 5. Request blocks from peer.
        // Throttle is now handled entirely inside SyncManager
        // (last_request_time). Do not double-throttle here.
        if let Some(p2p) = self.p2p.as_mut() {
            let session_data = p2p.sync_manager.active_session.as_ref().map(|session| {
                (
                    session.peer_id,
                    session.current_height,
                    session.target_height,
                    session.status.clone(),
                )
            });

            if let Some((peer_id, current_height, target_height, status)) = session_data {
                if status == SyncStatus::Requesting {
                    let from_height = current_height + 1;
                    let to_height = (from_height + SYNC_BATCH_SIZE - 1).min(target_height);

                    if from_height <= to_height {
                        let now = current_timestamp();
                        match p2p
                            .sync_manager
                            .request_blocks_from_peer(&peer_id, from_height)
                        {
                            Ok(msg) => {
                                // Send message directly to the peer.
                                for (peer_addr, peer) in p2p.peers.iter_mut() {
                                    if peer.get_peer_id() == peer_id {
                                        let _ = peer.send_message(&msg);
                                        break;
                                    }
                                }
                                if let Some(session) = p2p.sync_manager.active_session.as_mut() {
                                    session.status = SyncStatus::Receiving;
                                    session.last_activity = now;
                                }
                            }
                            Err(e) if e.contains("Too frequent") => {
                                // Throttle. Do NOT reset the session —
                                // the next tick will retry automatically.
                            }
                            Err(e) => {
                                println!("⚠️ Failed to request blocks: {}", e);
                                p2p.sync_manager.active_session = None;
                                p2p.sync_manager.sync_in_progress = false;
                            }
                        }
                    } else {
                        if let Some(session) = p2p.sync_manager.active_session.as_mut() {
                            session.status = SyncStatus::Completed;
                            p2p.sync_manager.sync_in_progress = false;
                            println!("✅ Sync completed at height {}", session.current_height);
                        }
                    }
                }
            }
        }

        // 6. Mining is handled by a dedicated thread in main.rs.
        //    Do NOT call mine_block() here — it holds write-lock during the
        //    entire batch and would freeze RPC/P2P.

                // 7. Stats.
                let now = current_timestamp();
                if now.saturating_sub(self.last_stats_time) >= 1 {
                    use colored::Colorize;
        
                    let sync_progress = self.sync_progress();
                    let sync_status = if sync_progress < 0.99 {
                        format!(" syncing={:.1}%", sync_progress * 100.0)
                    } else {
                        String::new()
                    };
        
                    let peer_count = self.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);
        
                    let avg = if self.timestamps.len() >= 2 {
                        let take = 10.min(self.timestamps.len() - 1);
                        let start = self.timestamps[self.timestamps.len() - 1 - take];
                        let end = *self.timestamps.last().unwrap();
                        let diff = end.saturating_sub(start);
                        if diff > 0 && diff < 31_536_000 {
                            diff as f64 / take as f64
                        } else {
                            0.0
                        }
                    } else {
                        0.0
                    };
        
                    let current_diff = self
                        .blocks
                        .last()
                        .map(|b| b.difficulty.to_difficulty())
                        .unwrap_or(1.0);
        
                    let current_nbits = self
                        .blocks
                        .last()
                        .map(|b| b.difficulty.compact())
                        .unwrap_or(0);
        
                    print!(
                        "\r\x1b[K{tag} {h} {e} {p} {sh} {avg} {nonce} {diff}{sync}",
                        tag   = "[STATUS]".bright_black(),
                        h     = format!("height={}", self.height).cyan(),
                        e     = format!("epoch={}", self.epoch).cyan(),
                        p     = format!("peers={}", peer_count).cyan(),
                        sh    = format!("shares={}", self.shares_found).cyan(),
                        avg   = format!("avg={:.1}s", avg).cyan(),
                        nonce = format!("nonce={}", self.last_nonce).cyan(),
                        diff  = format!("diff={:.6e} nbits={:08x}", current_diff, current_nbits).yellow(),
                        sync  = sync_status.bright_black(),
                    );
                    let _ = std::io::stdout().flush();
                    self.last_stats_time = now;
                }
        
                Ok(())
            }

            fn handle_p2p_message(&mut self, msg: P2PMessage, addr: SocketAddr) {
                // Snapshot difficulty BEFORE borrowing self.p2p mutably.
                // Used by ShareReply / GetShareProof branches.
                let snapshot_target_share = self.last_difficulty().share_target();
                let snapshot_epoch = self.epoch;
        
                // Take a snapshot of data we may need while not holding a mutable
                // borrow on self.p2p. All node-side work uses `self` directly
                // because we are already under the write-lock in tick().
                let p2p = match self.p2p.as_mut() {
                    Some(p) => p,
                    None => return,
                };
        
                // Collect peer-list for GetPeers response before any mutable borrow.
                let peers_for_response: Option<Vec<SocketAddr>> = match &msg {
                    P2PMessage::GetPeers => Some(p2p.peers.keys().copied().collect()),
                    _ => None,
                };
        
                let peer = match p2p.peers.get_mut(&addr) {
                    Some(p) => p,
                    None => return,
                };
        
                match msg {
                    P2PMessage::Version {
                        version: _,
                        timestamp,
                        height,
                        best_hash,
                        peer_id,
                    } => {
                        let latency = current_timestamp().saturating_sub(timestamp);
                        p2p.sync_manager
                            .update_peer(peer_id, addr, height, best_hash, latency);
                        peer.update_state(height, best_hash);
                        let _ = peer.send_message(&P2PMessage::Verack);
                    }
                    P2PMessage::Verack => {}
                    P2PMessage::Ping(nonce) => {
                        let _ = peer.send_message(&P2PMessage::Pong(nonce));
                    }
                    P2PMessage::Pong(_) => {}
                    P2PMessage::GetBlocks {
                        from_height,
                        max_count,
                    } => {
                        println!("📥 GetBlocks: from={}, max_count={}", from_height, max_count);
                        let max_count = max_count.min(MAX_BLOCKS_PER_REQUEST);
                        let mut blocks = Vec::new();
                        let end = from_height.saturating_add(max_count as u64);
                        for h in from_height..end {
                            match self.storage.get_block(h) {
                                Ok(Some(block)) => blocks.push(block),
                                Ok(None) => {
                                    println!("📥 GetBlocks: block {} not found", h);
                                    break;
                                }
                                Err(e) => {
                                    println!("📥 GetBlocks: error on {}: {}", h, e);
                                    break;
                                }
                            }
                        }
                        println!("📥 GetBlocks: collected {} blocks", blocks.len());
                        if !blocks.is_empty() {
                            match peer.send_message(&P2PMessage::Blocks(blocks.clone())) {
                                Ok(()) => println!("📤 Sent {} blocks to peer", blocks.len()),
                                Err(e) => println!("📤 Failed to send {} blocks: {}", blocks.len(), e),
                            }
                        } else {
                            println!("📥 GetBlocks: no blocks to send");
                        }
                    }
                    P2PMessage::Blocks(blocks) => {
                        let peer_id = peer.get_peer_id();
                    
                        // Temporary take sync_manager out to avoid double mutable borrow.
                        // Use a drop-guard so that even if verify_and_accept_blocks panics,
                        // sync_manager is restored into p2p.
                        let mut sync_manager = match self.p2p.as_mut() {
                            Some(p) => std::mem::replace(&mut p.sync_manager, SyncManager::new()),
                            None => return,
                        };
                    
                        let verification_result = sync_manager
                            .verify_and_accept_blocks(&blocks, self);
                    
                        // Always put sync_manager back, even on panic.
                        let restore = SyncManagerRestore {
                            node: self,
                            sync_manager: Some(sync_manager),
                        };
                    
                        match verification_result {
                            Ok(new_height) => {
                                drop(restore); // restore sync_manager into p2p
                    
                                let p2p = self.p2p.as_mut().unwrap();
                                p2p.local_height = new_height;
                                p2p.sync_manager.local_height = new_height;
                                let mut argon2 = Argon2Cache::new(ARGON2_CACHE_SIZE);
                                if let Some(last) = blocks.last() {
                                    p2p.local_best_hash = last.header.hash(&mut argon2);
                                }
                                let _ = p2p.sync_manager.on_blocks_received(&blocks, &peer_id);
                    
                                println!(
                                    "✅ Synced and stored {} blocks, new height: {}",
                                    blocks.len(),
                                    new_height
                                );
                            }
                            Err(e) => {
                                let is_prev_hash_race = e.contains("Invalid prev_hash");
                    
                                // Restore sync_manager before touching p2p further.
                                drop(restore);
                    
                                if is_prev_hash_race {
                                    // Pull/push race: not an attack.
                                    // Do NOT reset the sync session — just retry shortly.
                                    println!(
                                        "⚠️ Invalid prev_hash from {} (pull/push race) — will retry in 2s",
                                        addr
                                    );
                    
                                    if let Some(p2p) = self.p2p.as_mut() {
                                        if let Some(session) = p2p.sync_manager.active_session.as_mut() {
                                            // Stay in Requesting — tick() will re-issue GetBlocks.
                                            session.status = SyncStatus::Requesting;
                                            session.last_activity = current_timestamp();
                                        }
                                        // Make sure tick() does not wait 2s before retrying.
                                        self.last_sync_request_time = 0;
                                    }
                                } else {
                                    eprintln!("❌ Failed to verify and store blocks: {}", e);
                                    if let Some(p2p) = self.p2p.as_mut() {
                                        if let Some(peer) = p2p.peers.get_mut(&addr) {
                                            peer.ban(&format!("Invalid blocks: {}", e));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    P2PMessage::Share(share) => {
                        let accepted = self.add_share(share.clone());
        
                        if accepted {
                            let msg = P2PMessage::Share(share);
                            let p2p = self.p2p.as_mut().unwrap();
                            for (peer_addr, peer) in p2p.peers.iter_mut() {
                                if *peer_addr != addr && !peer.is_banned() {
                                    let _ = peer.send_message(&msg);
                                }
                            }
                        }
                    }
                    P2PMessage::Block {
                        header,
                        transactions,
                        signature,
                        pubkey,
                    } => {
                        let block = Block {
                            header,
                            transactions,
                            signature,
                            pubkey,
                        };

                        match self.accept_block(&block) {
                            Ok(()) => {
                                // Update P2P state + broadcast.
                                let hash = block.header.hash(&mut self.argon2);
                                let new_height = self.height;

                                if let Some(p2p) = self.p2p.as_mut() {
                                    p2p.local_height = new_height;
                                    p2p.local_best_hash = hash;
                                    p2p.sync_manager.local_height = new_height;

                                    let msg = P2PMessage::Block {
                                        header: block.header.clone(),
                                        transactions: block.transactions.clone(),
                                        signature: block.signature.clone(),
                                        pubkey: block.pubkey.clone(),
                                    };

                                    for (peer_addr, peer) in p2p.peers.iter_mut() {
                                        if *peer_addr != addr && !peer.is_banned() {
                                            let _ = peer.send_message(&msg);
                                        }
                                    }
                                }

                                println!("📥 Received and accepted block #{}", new_height);
                            }
                            Err(AcceptError::AlreadyKnown) => {
                                // Silent — we already have it.
                            }
                            Err(AcceptError::PrevHashMismatch { .. }) => {
                                // Possible fork — try to switch.
                                match self.try_fork_switch(&block) {
                                    Ok(true) => {
                                        // Reorg succeeded.
                                        let hash = block.header.hash(&mut self.argon2);
                                        let new_height = self.height;

                                        if let Some(p2p) = self.p2p.as_mut() {
                                            p2p.local_height = new_height;
                                            p2p.local_best_hash = hash;
                                            p2p.sync_manager.local_height = new_height;

                                            let msg = P2PMessage::Block {
                                                header: block.header.clone(),
                                                transactions: block.transactions.clone(),
                                                signature: block.signature.clone(),
                                                pubkey: block.pubkey.clone(),
                                            };

                                            for (peer_addr, peer) in p2p.peers.iter_mut() {
                                                if *peer_addr != addr && !peer.is_banned() {
                                                    let _ = peer.send_message(&msg);
                                                }
                                            }
                                        }

                                        println!(
                                            "🔀 Reorg accepted block, new height: {}",
                                            new_height
                                        );
                                    }
                                    Ok(false) => {
                                        // Not a fork we can handle now — stashed.
                                    }
                                    Err(e) => {
                                        eprintln!("❌ Fork switch failed: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                let is_benign = !e.is_attack();
                                println!("⚠️ [accept_block] {}", e.describe());

                                if !is_benign {
                                    if let Some(p2p) = self.p2p.as_mut() {
                                        if let Some(peer) = p2p.peers.get_mut(&addr) {
                                            peer.ban(&format!("Invalid block: {}", e.describe()));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    P2PMessage::EpochCommit { .. } => {}
                    P2PMessage::GetMempool => {}
                    P2PMessage::Mempool(_txs) => {}
                    P2PMessage::Transaction(tx) => {
                        let accepted = self.add_transaction_to_mempool(tx.clone()).is_ok();
        
                        if accepted {
                            let msg = P2PMessage::Transaction(tx);
                            let p2p = self.p2p.as_mut().unwrap();
                            for (peer_addr, peer) in p2p.peers.iter_mut() {
                                if *peer_addr != addr && !peer.is_banned() {
                                    let _ = peer.send_message(&msg);
                                }
                            }
                        }
                    }
                    P2PMessage::GetPeers => {
                        if let Some(peers) = peers_for_response {
                            let _ = peer.send_message(&P2PMessage::Peers(peers));
                        }
                    }
                    P2PMessage::Peers(peers) => {
                        // Limit how many peers we accept from a single message.
                        // Otherwise a malicious peer can send a huge list and
                        // blow up known_peers / memory.
                        const MAX_PEERS_PER_MESSAGE: usize = 64;
                        const MAX_KNOWN_PEERS: usize = 1024;

                        let mut to_connect = Vec::new();
                        for p in peers.into_iter().take(MAX_PEERS_PER_MESSAGE) {
                            if p == addr {
                                continue;
                            }
                            if !p2p.known_peers.contains(&p) && !p2p.peers.contains_key(&p) {
                                if p2p.known_peers.len() >= MAX_KNOWN_PEERS {
                                    break;
                                }
                                p2p.known_peers.insert(p);
                                if p2p.peers.len() < MAX_PEERS {
                                    to_connect.push(p);
                                }
                            }
                        }
                        for p in to_connect {
                            let _ = p2p.connect_to(p);
                        }
                    }
                    P2PMessage::BanPeer { peer_id, reason } => {
                        if peer_id == peer.get_peer_id() {
                            peer.ban(&reason);
                        }
                    }
                    P2PMessage::SlashProof { miner_id, proof } => {
                        if proof.miner_id != miner_id {
                            peer.ban("SlashProof miner_id mismatch");
                            return;
                        }
                        match proof.verify(&mut self.argon2) {
                            Ok(true) => {
                                self.report_equivocation(*proof);
                                println!(
                                    "⚖️ Equivocation proof accepted for {}...",
                                    hex::encode(&miner_id[0..8])
                                );
                            }
                            Ok(false) => {
                                println!(
                                    "⚠️ Invalid equivocation proof for {}...",
                                    hex::encode(&miner_id[0..8])
                                );
                            }
                            Err(e) => {
                                peer.ban(&format!("Invalid SlashProof: {}", e));
                            }
                        }
                    }
                    P2PMessage::Checkpoint(_) => {}
                    P2PMessage::SyncRequest { .. } => {}
                    P2PMessage::SyncResponse(_blocks) => {}
                    P2PMessage::Heartbeat(nonce) => {
                        let _ = peer.send_message(&P2PMessage::Pong(nonce));
                    }
                    P2PMessage::RegisterMiner {
                        miner_id,
                        payout_address,
                        pubkey,
                        signature,
                        timestamp,
                    } => {
                        // 1. Reject if the timestamp is older than 300 seconds.
                        let now = current_timestamp();
                        if now.saturating_sub(timestamp) > 300 {
                            println!("⚠️ RegisterMiner: timestamp too old");
                            return;
                        }

                        // 2. Validate pubkey and check miner_id.
                        let pk = match PublicKey::from_slice(&pubkey) {
                            Ok(p) => p,
                            Err(e) => {
                                println!("⚠️ RegisterMiner: invalid pubkey: {}", e);
                                return;
                            }
                        };
                        let expected_miner_id = Wallet::miner_id_from_pubkey(&pk);
                        if expected_miner_id != miner_id {
                            println!("⚠️ RegisterMiner: miner_id mismatch with pubkey");
                            return;
                        }

                        // 3. Verify signature.
                        let mut msg = Vec::new();
                        msg.extend_from_slice(&miner_id);
                        msg.extend_from_slice(payout_address.as_bytes());
                        msg.extend_from_slice(&timestamp.to_le_bytes());
                        let digest: [u8; 32] = Sha256::digest(&msg).into();

                        if !Wallet::verify_signature(&pubkey, &signature, &digest) {
                            println!("⚠️ RegisterMiner: invalid signature");
                            return;
                        }

                        // 4. Validate payout address.
                        if TxOut::create_p2pkh(&payout_address).is_err() {
                            println!(
                                "⚠️ RegisterMiner: invalid payout address for {}",
                                hex::encode(&miner_id[0..8])
                            );
                            return;
                        }

                        // 5. Persist into miners map and storage.

                        // 6. Persist into miners map and storage.
                        let entry = self.miners.entry(miner_id).or_insert_with(|| {
                            MinerData::new(miner_id, 0, self.epoch, now)
                        });
                        entry.pubkey = pubkey.clone();
                        entry.payout_address = Some(payout_address.clone());

                        if let Err(e) = self.storage.save_miner(&miner_id, entry) {
                            println!("⚠️ RegisterMiner: failed to save miner: {}", e);
                        } else {
                            println!(
                                "📝 RegisterMiner: {} -> {}",
                                hex::encode(&miner_id[0..8]),
                                payout_address
                            );
                        }
                    }
                    P2PMessage::GetShares { epoch, offset, max_count, miner_id } => {
                        let max_count = max_count.min(MAX_SHARES_PER_REPLY);

                        let (shares, total) = match self.share_pool.archive.get(&epoch) {
                            Some(all) => {
                                let filtered: Vec<SharePacket> = if let Some(mid) = miner_id {
                                    all.iter().filter(|s| s.miner_id == mid).cloned().collect()
                                } else {
                                    all.clone()
                                };
                                let total = filtered.len() as u32;
                                let start = offset as usize;
                                let end = (start + max_count as usize).min(filtered.len());
                                let slice = if start < filtered.len() {
                                    filtered[start..end].to_vec()
                                } else {
                                    Vec::new()
                                };
                                (slice, total)
                            }
                            None => (Vec::new(), 0),
                        };

                        let _ = peer.send_message(&P2PMessage::ShareReply {
                            epoch,
                            shares,
                            total_available: total,
                        });
                    }
                    P2PMessage::ShareReply { epoch, shares, total_available } => {
                        println!(
                            "📥 ShareReply: {} shares for epoch {} (total available: {})",
                            shares.len(),
                            epoch,
                            total_available,
                        );

                        // Use local Argon2 and snapshotted target — no self borrow.
                        let mut argon2 = Argon2Cache::new(ARGON2_CACHE_SIZE);

                        // 1. Validate each incoming share.
                        let mut valid: Vec<SharePacket> = Vec::new();
                        for s in &shares {
                            match s.validate(&snapshot_target_share, epoch, &mut argon2) {
                                Ok(()) => valid.push(s.clone()),
                                Err(e) => {
                                    println!(
                                        "⚠️ Invalid share from {}: {}",
                                        hex::encode(&s.miner_id[0..6]),
                                        e
                                    );
                                }
                            }
                        }

                        // 2. Merge into archive with de-duplication.
                        let our_shares = self
                            .share_pool
                            .archive
                            .entry(epoch)
                            .or_insert_with(Vec::new);

                        let mut added = 0usize;
                        for s in valid {
                            let dup = our_shares.iter().any(|x| {
                                x.miner_id == s.miner_id && x.hash == s.hash
                            });
                            if !dup {
                                our_shares.push(s);
                                added += 1;
                            }
                        }

                        // 3. Canonical sort: (miner_id, hash).
                        our_shares.sort_by(|a, b| {
                            a.miner_id.cmp(&b.miner_id)
                                .then_with(|| a.hash.cmp(&b.hash))
                        });

                        // 4. Recompute Merkle root.
                        let new_root = Node::compute_share_merkle_root(our_shares);
                        let have = our_shares.len() as u32;
                        self.share_pool.epoch_roots.insert(epoch, new_root);

                        println!(
                            "✅ Epoch {}: added {} shares, total {}, root={}...",
                            epoch,
                            added,
                            have,
                            hex::encode(&new_root[0..8]),
                        );

                        // 5. If peer has more — request the next batch.
                        if have < total_available {
                            let msg = P2PMessage::GetShares {
                                epoch,
                                offset: have,
                                max_count: MAX_SHARES_PER_REPLY,
                                miner_id: None,
                            };
                            let _ = peer.send_message(&msg);
                        }
                    }
                    P2PMessage::GetShareProof { epoch, share_hash } => {
                        let _ = (epoch, share_hash);
                    }
                    P2PMessage::ShareProof { epoch, share, merkle_path } => {
                        let _ = (epoch, share, merkle_path);
                    }
                }
            }

                // ============================================================
    // Epoch commit + share sync (v3.2+)
    // ============================================================

    /// Handle an incoming EpochCommit message.
    ///
    /// - Records the peer's vote in `p2p.received_commits`.
    /// - If we don't have a root for this epoch, requests shares.
    /// - If our root differs, compares vote counts. If the peer has
    ///   more votes (by COMMIT_SWITCH_MARGIN), requests shares.
    fn handle_epoch_commit(
        &mut self,
        addr: SocketAddr,
        epoch: u32,
        commit_root: Hash32,
        _timestamp: Timestamp,
    ) {
        // 1. Ignore ancient epochs.
        if epoch + EPOCH_ARCHIVE_DEPTH < self.epoch {
            return;
        }

        // 2. Get the peer's peer_id.
        let peer_id = match self.p2p.as_ref() {
            Some(p2p) => match p2p.peers.get(&addr) {
                Some(peer) => peer.get_peer_id(),
                None => return,
            },
            None => return,
        };

        // 3. Record the vote.
        if let Some(p2p) = self.p2p.as_mut() {
            p2p.received_commits
                .entry((epoch, commit_root))
                .or_insert_with(HashSet::new)
                .insert(peer_id);
        }

        // 4. Do we have a root for this epoch?
        let our_root = self.share_pool.epoch_roots.get(&epoch).copied();

        // 5. No root — request shares.
        let our_root = match our_root {
            Some(r) => r,
            None => {
                println!(
                    "📥 EpochCommit #{} from {}: root={}... (we have none, requesting)",
                    epoch,
                    hex::encode(&peer_id[0..8]),
                    hex::encode(&commit_root[0..8]),
                );
                self.send_to_peer(addr, P2PMessage::GetShares {
                    epoch,
                    offset: 0,
                    max_count: MAX_SHARES_PER_REPLY,
                    miner_id: None,
                });
                return;
            }
        };

        // 6. Match?
        if our_root == commit_root {
            println!(
                "✅ EpochCommit #{} matches peer {}",
                epoch,
                hex::encode(&peer_id[0..8]),
            );
            return;
        }

        // 7. Mismatch — count votes.
        let (votes_us, votes_peer) = match self.p2p.as_ref() {
            Some(p2p) => {
                let vu = p2p.received_commits
                    .get(&(epoch, our_root))
                    .map(|s| s.len())
                    .unwrap_or(0);
                let vp = p2p.received_commits
                    .get(&(epoch, commit_root))
                    .map(|s| s.len())
                    .unwrap_or(0);
                (vu, vp)
            }
            None => (0, 0),
        };

        println!(
            "⚠️ EpochCommit #{} mismatch: ours={}... ({} votes), peer={}... ({} votes)",
            epoch,
            hex::encode(&our_root[0..8]),
            votes_us,
            hex::encode(&commit_root[0..8]),
            votes_peer,
        );

        // 8. If peer has more votes — request their shares.
        if votes_peer >= votes_us + COMMIT_SWITCH_MARGIN {
            println!(
                "🔄 Switching to peer commit for epoch {} (majority)",
                epoch,
            );
            self.send_to_peer(addr, P2PMessage::GetShares {
                epoch,
                offset: 0,
                max_count: MAX_SHARES_PER_REPLY,
                miner_id: None,
            });
        }
    }

    /// Handle a GetShares request from a peer.
    fn handle_get_shares(
        &mut self,
        addr: SocketAddr,
        epoch: u32,
        offset: u32,
        max_count: u32,
        miner_id: Option<MinerId>,
    ) {
        let max_count = max_count.min(MAX_SHARES_PER_REPLY);

        let (shares, total) = match self.share_pool.archive.get(&epoch) {
            Some(all) => {
                let filtered: Vec<SharePacket> = if let Some(mid) = miner_id {
                    all.iter().filter(|s| s.miner_id == mid).cloned().collect()
                } else {
                    all.clone()
                };
                let total = filtered.len() as u32;
                let start = offset as usize;
                let end = (start + max_count as usize).min(filtered.len());
                let slice = if start < filtered.len() {
                    filtered[start..end].to_vec()
                } else {
                    Vec::new()
                };
                (slice, total)
            }
            None => (Vec::new(), 0),
        };

        self.send_to_peer(addr, P2PMessage::ShareReply {
            epoch,
            shares,
            total_available: total,
        });
    }

    /// Handle a ShareReply from a peer.
    fn handle_share_reply(
        &mut self,
        addr: SocketAddr,
        epoch: u32,
        shares: Vec<SharePacket>,
        total_available: u32,
    ) {
        println!(
            "📥 ShareReply: {} shares for epoch {} (total available: {})",
            shares.len(),
            epoch,
            total_available,
        );

        let target_share = self.last_difficulty().share_target();

        // 1. Validate each incoming share.
        let mut valid: Vec<SharePacket> = Vec::new();
        for s in &shares {
            match s.validate(&target_share, epoch, &mut self.argon2) {
                Ok(()) => valid.push(s.clone()),
                Err(e) => {
                    println!(
                        "⚠️ Invalid share from {}: {}",
                        hex::encode(&s.miner_id[0..6]),
                        e
                    );
                }
            }
        }

        // 2. Merge into archive with de-duplication.
        let our_shares = self
            .share_pool
            .archive
            .entry(epoch)
            .or_insert_with(Vec::new);

        let mut added = 0usize;
        for s in valid {
            let dup = our_shares.iter().any(|x| {
                x.miner_id == s.miner_id && x.hash == s.hash
            });
            if !dup {
                our_shares.push(s);
                added += 1;
            }
        }

        // 3. Canonical sort: (miner_id, hash).
        our_shares.sort_by(|a, b| {
            a.miner_id.cmp(&b.miner_id)
                .then_with(|| a.hash.cmp(&b.hash))
        });

        // 4. Recompute Merkle root.
        let new_root = Node::compute_share_merkle_root(our_shares);
        let have = our_shares.len() as u32;
        self.share_pool.epoch_roots.insert(epoch, new_root);

        println!(
            "✅ Epoch {}: added {} shares, total {}, root={}...",
            epoch,
            added,
            have,
            hex::encode(&new_root[0..8]),
        );

        // 5. If peer has more — request the next batch.
        if have < total_available {
            self.send_to_peer(addr, P2PMessage::GetShares {
                epoch,
                offset: have,
                max_count: MAX_SHARES_PER_REPLY,
                miner_id: None,
            });
        }
    }

    /// Handle a GetShareProof request. Currently unused.
    fn handle_get_share_proof(&mut self, _addr: SocketAddr, _epoch: u32, _share_hash: Hash32) {
        // Not implemented — Merkle proofs are not required by the
        // current share sync protocol.
    }

    /// Handle a ShareProof message. Currently unused.
    fn handle_share_proof(
        &mut self,
        _addr: SocketAddr,
        _epoch: u32,
        _share: SharePacket,
        _merkle_path: Vec<Hash32>,
    ) {
        // Not implemented.
    }

    /// Send a message to a specific peer by address.
    /// Silently ignores missing peers.
    fn send_to_peer(&mut self, addr: SocketAddr, msg: P2PMessage) {
        if let Some(p2p) = self.p2p.as_mut() {
            if let Some(peer) = p2p.peers.get_mut(&addr) {
                let _ = peer.send_message(&msg);
            }
        }
    }

    pub fn shutdown(&mut self) {
        if !is_saving_state() {
            set_saving_state(true);
            println!("💾 Saving state...");
            let _ = self.storage.save_mempool(&self.mempool);
            let _ = self.storage.flush();
            println!("✅ State saved");
        }
    }
    
        /// Broadcast RegisterMiner — our miner_id + payout address.
        pub fn broadcast_register_miner(&mut self) {
            let wallet = match &self.wallet {
                Some(w) => w,
                None => return,
            };
    
            let timestamp = current_timestamp();
    
            // Signed message: sha256(miner_id || payout_address || timestamp_le).
            let mut msg = Vec::new();
            msg.extend_from_slice(&wallet.miner_id);
            msg.extend_from_slice(wallet.address.as_bytes());
            msg.extend_from_slice(&timestamp.to_le_bytes());
            let digest: [u8; 32] = Sha256::digest(&msg).into();
    
            let signature = match wallet.sign(&digest) {
                Ok(s) => s,
                Err(e) => {
                    println!("⚠️ RegisterMiner: cannot sign: {}", e);
                    return;
                }
            };
    
            let msg = P2PMessage::RegisterMiner {
                miner_id: wallet.miner_id,
                payout_address: wallet.address.clone(),
                pubkey: wallet.public_key.clone(),
                signature,
                timestamp,
            };
    
            if let Some(p2p) = &mut self.p2p {
                p2p.broadcast(&msg);
                println!("📝 Broadcast RegisterMiner ({})", wallet.address);
            }
        }

    // ------------------------------------------------------------------
    // Mining
    // ------------------------------------------------------------------
        /// Prepare a mining job under a short write-lock.
    /// Returns everything needed to run the PoW search without holding
    /// the write-lock. The `generation` field records the current
    /// chain generation so the caller can detect a chain move.
        /// Accept a single block into the chain.
    ///
    /// This is the ONLY path for adding a block — both `P2PMessage::Block`
    /// and `P2PMessage::Blocks` go through here. It validates the block,
    /// persists it, updates the chain state, and signals the mining thread.
    ///
    /// Returns:
    /// - `Ok(())` — block accepted.
    /// - `Err(AcceptError::AlreadyKnown)` — block already in the chain (not an error).
    /// - `Err(other)` — block rejected.
    pub fn accept_block(&mut self, block: &Block) -> Result<(), AcceptError> {
        let expected_height = self.height + 1;

        // Compute hash first — used for multiple checks.
        let hash = block.header.hash(&mut self.argon2);

        // Already known?
        if self.block_hashes.contains_key(&hash) {
            return Err(AcceptError::AlreadyKnown);
        }

        // prev_hash must match our current tip.
        let expected_prev = self.last_hash();
        if block.header.prev_hash != expected_prev {
            return Err(AcceptError::PrevHashMismatch {
                expected: expected_prev,
                got: block.header.prev_hash,
                height: expected_height,
            });
        }

        // PoW.
        if !block.header.difficulty.is_met_by(&hash) {
            return Err(AcceptError::BadPow);
        }

        // Checkpoint (if any).
        if let Some(cp) = self.checkpoint_at(expected_height) {
            if hash != cp.block_hash {
                return Err(AcceptError::BadPow);
            }
        }

        // Signature.
        match (&block.signature, &block.pubkey) {
            (Some(sig), Some(pk)) => {
                if !Wallet::verify_signature(pk, sig, &hash) {
                    return Err(AcceptError::BadSignature);
                }
            }
            _ => return Err(AcceptError::BadSignature),
        }

        // Timestamp.
        let prev_timestamp = if self.height > 0 {
            self.blocks.last().map(|b| b.timestamp)
        } else {
            None
        };
        let median = self.median_timestamp();
        if !block.header.validate_timestamp(prev_timestamp, median) {
            return Err(AcceptError::BadTimestamp);
        }

        // Merkle root.
        let computed_root =
            SyncManager::compute_merkle_root(&block.transactions, &mut self.argon2);
        if block.header.merkle_root != computed_root {
            return Err(AcceptError::BadMerkle);
        }

        // Coinbase.
        if let Err(e) = validate_block_coinbase(block, &self.storage) {
            return Err(AcceptError::BadCoinbase(e));
        }

        // Double spend.
        if let Err(e) = validate_block_no_double_spend(block) {
            return Err(AcceptError::BadDoubleSpend(e));
        }

        // ---- Persist ----
        if let Err(e) = self.storage.save_block(expected_height, block) {
            return Err(AcceptError::Storage(e));
        }

        self.blocks.push(block.header.clone());
        self.block_hashes.insert(hash, expected_height);
        self.timestamps.push(block.header.timestamp);
        self.height = expected_height;
        self.cached_difficulty = None;

        // Signal the mining thread: chain moved.
        self.chain_generation.fetch_add(1, AtomicOrdering::Relaxed);
        self.abort_mining.store(true, AtomicOrdering::Relaxed);

        // Apply to UTXO set.
        self.update_utxo_set(block);

        // Persist height.
        let _ = self.storage.save_state("height", &self.height);

        // Epoch transition.
        if expected_height % EPOCH_BLOCKS == 0 {
            if let Err(e) = self.process_epoch_end() {
                println!("⚠️ Epoch processing failed: {}", e);
            }
        }
        let _ = self.storage.save_state("epoch", &self.epoch);

        // Prune txids.
        self.prune_processed_txids();

        // Track txids in this block.
        let mut txids_in_block = HashSet::new();
        for tx in &block.transactions {
            if !tx.is_coinbase() {
                let txid = tx.txid(&mut self.argon2);
                txids_in_block.insert(txid);
                self.processed_txids.insert(txid, expected_height);
            }
        }

        // Remove included txns from mempool.
        let old_mempool = std::mem::take(&mut self.mempool);
        let mut new_mempool = Vec::with_capacity(old_mempool.len());
        for tx in old_mempool {
            let txid = tx.txid(&mut self.argon2);
            if !txids_in_block.contains(&txid) {
                new_mempool.push(tx);
            }
        }
        self.mempool = new_mempool;
        let _ = self.storage.save_mempool(&self.mempool);

        Ok(())
    }

        /// Find the deepest common block between our chain and the given
    /// sequence of foreign blocks.
    ///
    /// `foreign_blocks` should be ordered from the fork point upward —
    /// i.e. the first element is the block immediately after the fork.
    /// We walk through them and check if any of their `prev_hash` values
    /// correspond to a block already in our chain.
    ///
    /// Returns `(height, hash)` of the common ancestor, or `None` if no
    /// common ancestor exists in our chain.
        /// Find the deepest common block between our chain and the given
    /// sequence of foreign blocks.
    ///
    /// `foreign_blocks` should be ordered from the fork point upward —
    /// i.e. the first element is the block immediately after the fork.
    ///
    /// We build a set of foreign block hashes, then walk OUR chain
    /// backward from the current tip to genesis. The first block whose
    /// hash appears in the foreign set is the deepest common ancestor.
    ///
    /// Returns `(height, hash)` of the common ancestor, or `None`.
    pub fn find_common_ancestor(
        &mut self,
        foreign_blocks: &[Block],
    ) -> Option<(Height, Hash32)> {
        if foreign_blocks.is_empty() {
            return None;
        }

        // 1. prev_hash первого foreign-блока — потенциальный fork point.
        let first = &foreign_blocks[0];
        if let Some(h) = self.block_hashes.get(&first.header.prev_hash) {
            return Some((*h, first.header.prev_hash));
        }

        // 2. Идём по foreign_blocks, ищем совпадение с нашей цепочкой.
        for b in foreign_blocks {
            let foreign_hash = b.header.hash(&mut self.argon2);
            if let Some(h) = self.block_hashes.get(&foreign_hash) {
                return Some((*h, foreign_hash));
            }
        }

        // 3. Общего предка не нашли.
        None
    }
    
        /// Roll back our chain to the given height.
    ///
    /// Removes all blocks above `target_height`, applies reverse UTXO
    /// changes, and updates in-memory state. Persists the new height.
    ///
    /// Returns `Ok(())` on success, or `Err` if a block is missing.
    ///
    /// NOTE: this uses `rollback_utxo_set`, which currently cannot
    /// fully restore spent outputs (no undo data). For the purposes of
    /// reorg between two well-behaved nodes this is acceptable — the
    /// alternative is that the reorg cannot happen at all. Full undo
    /// support is a future improvement.
    pub fn rollback_to(&mut self, target_height: Height) -> Result<(), String> {
        if target_height >= self.height {
            return Ok(());
        }

        while self.height > target_height {
            // Fetch the block we are about to roll back.
            let block = self
                .storage
                .get_block(self.height)?
                .ok_or_else(|| format!("block {} not found for rollback", self.height))?;

            // Delete from storage.
            self.storage.delete_block(self.height)?;

            // Reverse UTXO changes.
            self.rollback_utxo_set(&block);

            // Remove from in-memory state.
            let hash = block.header.hash(&mut self.argon2);
            self.blocks.pop();
            self.timestamps.pop();
            self.block_hashes.remove(&hash);
            self.height -= 1;
        }

        // Persist new height.
        let _ = self.storage.save_state("height", &self.height);
        self.cached_difficulty = None;

        // Signal mining thread.
        self.chain_generation.fetch_add(1, AtomicOrdering::Relaxed);
        self.abort_mining.store(true, AtomicOrdering::Relaxed);

        println!("🔙 Rolled back to height {}", self.height);
        Ok(())
    }

        /// Apply a foreign branch starting from the given common ancestor.
    ///
    /// `foreign_blocks` should be ordered from the fork point upward —
    /// i.e. the first element is the block immediately after the fork.
    ///
    /// Each block is applied via `accept_block`. Blocks already known
    /// to us are skipped. Returns the number of newly applied blocks.
    pub fn apply_foreign_branch(
        &mut self,
        foreign_blocks: &[Block],
    ) -> Result<usize, String> {
        let mut applied = 0usize;

        for block in foreign_blocks {
            // Skip already-known blocks.
            let hash = block.header.hash(&mut self.argon2);
            if self.block_hashes.contains_key(&hash) {
                continue;
            }

            // Validate and apply.
            match self.accept_block(block) {
                Ok(()) => {
                    applied += 1;
                }
                Err(AcceptError::AlreadyKnown) => {
                    // Race — someone else applied it. Fine.
                }
                Err(e) => {
                    return Err(format!(
                        "apply_foreign_branch failed at height {}: {}",
                        self.height + 1,
                        e.describe()
                    ));
                }
            }
        }

        Ok(applied)
    }

        /// Handle a multi-block fork: find the common ancestor, roll back
    /// our chain, and apply the foreign branch.
    ///
    /// `block` is the tip of a foreign branch that does not extend our
    /// current chain. We only have one block from the peer here, so
    /// we work with what we can: if the block's `prev_hash` is a known
    /// ancestor, we roll back to it and apply the block.
    ///
    /// Returns `Ok(true)` if a reorg happened, `Ok(false)` otherwise.
    pub fn try_multi_block_reorg(&mut self, block: &Block) -> Result<bool, String> {
        let block_hash = block.header.hash(&mut self.argon2);

        // Already known — nothing to do.
        if self.block_hashes.contains_key(&block_hash) {
            return Ok(false);
        }

        // Find where `block.prev_hash` lives in our chain.
        let fork_height = match self.block_hashes.get(&block.header.prev_hash) {
            Some(h) => *h,
            None => {
                // Unknown ancestor. Stash for later.
                self.forks
                    .entry(block.header.prev_hash)
                    .or_default()
                    .push(block.clone());
                return Ok(false);
            }
        };

        // If fork height is already our tip, this is not a fork.
        if fork_height >= self.height {
            return Ok(false);
        }

        // Compare chain difficulty: only reorg if the foreign branch is
        // heavier. For a single block we compare against our block at
        // `fork_height + 1`. For deeper forks we would need the full
        // branch — for now we only have one block.
        //
        // This means: we reorg only when the incoming block alone
        // represents a heavier chain than ours from the fork point.
        // That's the common case for a two-node network.
        let our_block = match self.storage.get_block(fork_height + 1)? {
            Some(b) => b,
            None => return Ok(false),
        };
        let our_diff = our_block.header.difficulty.to_difficulty();
        let new_diff = block.header.difficulty.to_difficulty();

        // Only switch if the incoming block is strictly heavier.
        if new_diff <= our_diff {
            return Ok(false);
        }

        println!(
            "🔀 [reorg] Multi-block reorg: rolling back from {} to {}, then applying foreign block",
            self.height, fork_height
        );

        // 1. Roll back our chain to the fork point.
        self.rollback_to(fork_height)?;

        // 2. Apply the foreign block.
        match self.accept_block(block) {
            Ok(()) => {
                println!(
                    "🔀 [reorg] Complete. New height: {}",
                    self.height
                );
                Ok(true)
            }
            Err(e) => {
                eprintln!(
                    "❌ [reorg] Rolled back but failed to apply foreign block: {}",
                    e.describe()
                );
                Err(format!("Reorg failed: {}", e.describe()))
            }
        }
    }

    /// Try to switch to a competing branch when a block does not extend
    /// our current tip.
    ///
    /// Currently handles **single-block reorg** only:
    /// - `block.prev_hash` must be a known block in our chain.
    /// - The competing branch must be exactly one block longer than ours
    ///   from the fork point.
    /// - We compare block difficulty; if the competing block is heavier,
    ///   we roll back our fork-point+1 block and apply the new one.
    ///
    /// For deeper forks (multi-block), returns `Ok(false)` — the block is
    /// stashed in `self.forks` for later processing (P9.3).
    pub fn try_fork_switch(&mut self, block: &Block) -> Result<bool, String> {
        // 1. Compute the hash of the incoming block.
        let block_hash = block.header.hash(&mut self.argon2);

        // 2. Already known?
        if self.block_hashes.contains_key(&block_hash) {
            return Ok(false);
        }

        // 3. Find the fork point — the height of `block.prev_hash` in our chain.
        let fork_height = match self.block_hashes.get(&block.header.prev_hash) {
            Some(h) => *h,
            None => {
                // Fork point unknown — deeper than we can handle now.
                // Stash and return.
                self.forks
                    .entry(block.header.prev_hash)
                    .or_default()
                    .push(block.clone());
                return Ok(false);
            }
        };

        // 4. If the fork point is our tip — it's not a fork, just a normal block.
        if fork_height == self.height {
            return Ok(false);
        }

               // 5. If the fork point is not our immediate parent, this is a
        //    deeper (multi-block) fork. Handle it via the multi-block path.
        if fork_height + 1 != self.height {
            return self.try_multi_block_reorg(block);
        }

        // 6. Get our block at `height` to compare against.
        let our_block = self
            .storage
            .get_block(self.height)?
            .ok_or_else(|| "Our block at tip not found".to_string())?;
        let our_hash = our_block.header.hash(&mut self.argon2);
        let our_diff = our_block.header.difficulty.to_difficulty();
        let new_diff = block.header.difficulty.to_difficulty();

        // 7. Is the new block heavier? If not — ignore.
        if new_diff <= our_diff {
            return Ok(false);
        }

        println!(
            "🔀 [fork] Reorg: replacing block {} ({}) with new block ({})",
            self.height,
            hex::encode(&our_hash[0..8]),
            hex::encode(&block_hash[0..8]),
        );

        // ---- Roll back our tip ----

        // 7a. Remove block from storage.
        if let Err(e) = self.storage.delete_block(self.height) {
            return Err(format!("delete_block({}) failed: {}", self.height, e));
        }

        // 7b. Undo UTXO changes for our block.
        self.rollback_utxo_set(&our_block);

        // 7c. Remove from in-memory chain state.
        self.blocks.pop();
        self.timestamps.pop();
        self.block_hashes.remove(&our_hash);
        self.height -= 1;
        self.cached_difficulty = None;

        // 7d. Persist height.
        let _ = self.storage.save_state("height", &self.height);

        // ---- Apply the new block ----
        match self.accept_block(block) {
            Ok(()) => {
                println!(
                    "🔀 [fork] Reorg complete. New height: {}",
                    self.height
                );
                Ok(true)
            }
            Err(e) => {
                // If the new block fails, we've already rolled back our block.
                // This is a critical inconsistency — log loudly.
                eprintln!(
                    "❌ [fork] Rolled back our block but failed to apply new one: {}",
                    e.describe()
                );
                Err(format!("Reorg failed: {}", e.describe()))
            }
        }
    }

    /// Undo UTXO changes made by a block.
    /// Used during chain rollback.
    /// - Spend: re-create the UTXOs that were consumed.
    /// - Outputs: delete the UTXOs that were created.
    fn rollback_utxo_set(&mut self, block: &Block) {
        for tx in &block.transactions {
            let txid = tx.txid(&mut self.argon2);

            // Delete outputs created by this tx.
            for (i, _output) in tx.outputs.iter().enumerate() {
                let outpoint = (txid, i as u32);
                if let Err(e) = self.storage.delete_utxo(&outpoint) {
                    eprintln!(
                        "⚠️ rollback: delete_utxo({}) failed: {}",
                        hex::encode(&txid[0..8]),
                        e
                    );
                }
            }

            // Re-create inputs consumed by this tx.
            for input in &tx.inputs {
                if input.is_coinbase() {
                    continue;
                }
                // We do not have the original TxOut here in general.
                // For bond inputs this is impossible to restore exactly
                // without the original output data.
                //
                // NOTE: full UTXO rollback requires storing spent outputs
                // alongside blocks. For now we log a warning. A production
                // implementation must persist undo data per block.
                //
                // This is a known limitation of P9.2.
                eprintln!(
                    "⚠️ rollback: cannot restore spent UTXO {}:{} (no undo data)",
                    hex::encode(&input.prev_txid[0..8]),
                    input.prev_index,
                );
            }
        }
    }


    pub fn prepare_mining_job(&mut self) -> Result<MiningJob, String> {
        let generation = self.chain_generation.load(AtomicOrdering::Relaxed);

        // ---- 1. Collect non-coinbase txs from mempool. ----
        let mut non_coinbase_txs: Vec<Transaction> = Vec::new();
        let mut total_fees: u64 = 0;
        let mut total_size = 0usize;

        for tx in &self.mempool {
            let tx_size = tx.serialize().len();
            if total_size + tx_size > 1_000_000 {
                break;
            }
            match tx.fee(&self.storage) {
                Ok(f) => {
                    total_fees = total_fees.saturating_add(f);
                    non_coinbase_txs.push(tx.clone());
                    total_size += tx_size;
                }
                Err(e) => {
                    println!("⚠️ Skipping tx with fee error: {}", e);
                }
            }
        }

        // ---- 2. Build coinbase. ----
        let coinbase_total = BLOCK_REWARD_LYT.saturating_add(total_fees);
        let mut outputs = Vec::new();
        if let Some(wallet) = &self.wallet {
            if let Ok(mut txout) = TxOut::create_p2pkh(&wallet.address) {
                txout.value = coinbase_total;
                outputs.push(txout);
            }
        }
        if outputs.is_empty() {
            return Err("Unable to create block reward output".to_string());
        }

        let coinbase = Transaction::coinbase(outputs, self.height + 1);
        let mut txs = vec![coinbase];
        txs.extend(non_coinbase_txs);

        // ---- 3. Header + merkle. ----
        let prev_hash = self.last_hash();
        let difficulty = self.compute_difficulty_for_next_block();
        let mut header = BlockHeader::new(prev_hash, self.epoch, difficulty);

        let mut hashes: Vec<Hash32> = txs.iter().map(|tx| tx.txid(&mut self.argon2)).collect();
        while hashes.len() > 1 {
            let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&Sha256::digest(&data));
                next.push(arr);
            }
            hashes = next;
        }
        header.merkle_root = hashes.first().copied().unwrap_or([0; 32]);

        Ok(MiningJob {
            prev_hash,
            height: self.height + 1,
            epoch: self.epoch,
            difficulty,
            header,
            txs,
            generation,
        })
    }


    pub fn mine_block(&mut self) {
        // Snapshot chain generation; if it changes during mining,
        // the chain has moved and our work is stale.
        let gen_at_start = self.chain_generation.load(AtomicOrdering::Relaxed);
        self.abort_mining.store(false, AtomicOrdering::Relaxed);

        // ---- 1. Collect non-coinbase txs from mempool. ----
        let mut non_coinbase_txs: Vec<Transaction> = Vec::new();
        let mut total_fees: u64 = 0;
        let mut total_size = 0usize;

        for tx in &self.mempool {
            let tx_size = tx.serialize().len();
            if total_size + tx_size > 1_000_000 {
                break;
            }
            match tx.fee(&self.storage) {
                Ok(f) => {
                    total_fees = total_fees.saturating_add(f);
                    non_coinbase_txs.push(tx.clone());
                    total_size += tx_size;
                }
                Err(e) => {
                    println!("⚠️ Skipping tx with fee error: {}", e);
                }
            }
        }

        // ---- 2. Build coinbase. ----
        let coinbase_total = BLOCK_REWARD_LYT.saturating_add(total_fees);
        let mut outputs = Vec::new();
        if let Some(wallet) = &self.wallet {
            if let Ok(mut txout) = TxOut::create_p2pkh(&wallet.address) {
                txout.value = coinbase_total;
                outputs.push(txout);
            }
        }
        if outputs.is_empty() {
            println!("⚠️ Unable to create block reward output");
            return;
        }

        let coinbase = Transaction::coinbase(outputs, self.height + 1);
        let mut txs = vec![coinbase];
        txs.extend(non_coinbase_txs);

        // ---- 3. Header + merkle. ----
        let prev_hash = self.last_hash();
        let difficulty = self.compute_difficulty_for_next_block();
        let mut header = BlockHeader::new(prev_hash, self.epoch, difficulty);

        let mut hashes: Vec<Hash32> = txs.iter().map(|tx| tx.txid(&mut self.argon2)).collect();
        while hashes.len() > 1 {
            let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&Sha256::digest(&data));
                next.push(arr);
            }
            hashes = next;
        }
        header.merkle_root = hashes.first().copied().unwrap_or([0; 32]);

                // ---- 4. Mine (multi-threaded). ----
                let target_share = difficulty.share_target();
                let target_prefilter = difficulty.prefilter_target();
                let header_bytes = header.to_bytes();
        
                let best_hash_shared = Arc::new(Mutex::new([0xffu8; 32]));
                let best_nonce_shared = Arc::new(AtomicU64::new(0));
                let block_found = Arc::new(AtomicBool::new(false));
        
                // Clones for the mining threads.
                let abort_shared = Arc::clone(&self.abort_mining);
                let gen_shared = Arc::clone(&self.chain_generation);
        
                let num_threads = self.config.mining.threads.max(1) as u64;
                let batch = MINING_BATCH_SIZE;
        
                let start_time = std::time::Instant::now();
        
                std::thread::scope(|scope| {
                    for t in 0..num_threads {
                        let best_hash_ref = Arc::clone(&best_hash_shared);
                        let best_nonce_ref = Arc::clone(&best_nonce_shared);
                        let found_ref = Arc::clone(&block_found);
                        let abort_ref = Arc::clone(&abort_shared);
                        let gen_ref = Arc::clone(&gen_shared);
                        let hb = &header_bytes;
        
                        scope.spawn(move || {
                            let mut local_argon2 = Argon2Cache::new(ARGON2_CACHE_SIZE);
        
                            let mut nonce = t;
                            while nonce < batch {
                                if found_ref.load(AtomicOrdering::Relaxed) {
                                    break;
                                }
        
                                // Abort if chain moved — our work is stale.
                                if abort_ref.load(AtomicOrdering::Relaxed) {
                                    break;
                                }
                                if gen_ref.load(AtomicOrdering::Relaxed) != gen_at_start {
                                    break;
                                }
        
                                if !Argon2Cache::prefilter(hb, nonce, &target_prefilter) {
                                    nonce += num_threads;
                                    continue;
                                }
        
                                let hash = header_with_nonce_hash(hb, nonce, &mut local_argon2);
        
                                // Проверка: найден ли БЛОК (полный target).
                                if difficulty.is_met_by(&hash) {
                                    best_nonce_ref.store(nonce, AtomicOrdering::Relaxed);
                                    *best_hash_ref.lock().unwrap() = hash;
                                    found_ref.store(true, AtomicOrdering::Relaxed);
                                    break;
                                }
        
                                // Проверка: найдена ли ШАРА (облегчённый target).
                                if target_share.is_met_by(&hash) {
                                    let mut best = best_hash_ref.lock().unwrap();
                                    if hash < *best {
                                        *best = hash;
                                        best_nonce_ref.store(nonce, AtomicOrdering::Relaxed);
                                    }
                                }
        
                                nonce += num_threads;
                            }
                        });
                    }
                });
        
                let best_hash = *best_hash_shared.lock().unwrap();
                let best_nonce = best_nonce_shared.load(AtomicOrdering::Relaxed);
                let found_block = block_found.load(AtomicOrdering::Relaxed);
        
                if found_block {
                    header.nonce = best_nonce;
                }
        
                let _elapsed = start_time.elapsed();
                
               // ---- 5. Persist. ----
               if found_block {
                // header.nonce was already set right after mining completes.
    
                // Race protection: while we were mining, tick() may have
                // accepted a block from a peer. If so — drop our block.
                if self.block_hashes.contains_key(&best_hash) {
                    println!(
                        "⚠️ [mine] Block {} already known, skipping",
                        hex::encode(&best_hash[0..8])
                    );
                    return;
                }
                let new_height = self.height + 1;
                if new_height <= self.height {
                    println!(
                        "⚠️ [mine] Stale block: new_height={} <= height={}",
                        new_height, self.height
                    );
                    return;
                }
                if header.prev_hash != self.last_hash() {
                    println!("⚠️ [mine] Chain moved while mining, skipping");
                    return;
                }
    
                // Collect non-coinbase txids to detect duplicates.
                let mut block_txids = HashSet::new();
                for tx in &txs {
                    if tx.is_coinbase() {
                        continue;
                    }
                    let txid = tx.txid(&mut self.argon2);
                    if !block_txids.insert(txid) {
                        println!("⚠️ Duplicate transaction in block, skipping");
                        return;
                    }
                }
    
                // Pre-validate no double spend.
                let block_preview = Block {
                    header: header.clone(),
                    transactions: txs.clone(),
                    signature: None,
                    pubkey: None,
                };
                if let Err(e) = crate::p2p::validate_block_no_double_spend(&block_preview) {
                    println!("⚠️ Double spend in block, skipping: {}", e);
                    return;
                }
    
                // Sign the block with our wallet.
                let (signature, pubkey) = if let Some(wallet) = &self.wallet {
                    let block_hash = header.hash(&mut self.argon2);
                    (
                        wallet.sign_block(&block_hash).ok(),
                        Some(wallet.public_key.clone()),
                    )
                } else {
                    (None, None)
                };
    
                let block = Block {
                    header: header.clone(),
                    transactions: txs,
                    signature,
                    pubkey,
                };
    
                // Save the share silently — visible in [STATUS] as shares=N.
                let share = Share::new(self.miner_id, header.clone(), best_nonce, best_hash);
                let _ = self.add_share(share);
    
                // Persist the block.
                if let Err(e) = self.storage.save_block(new_height, &block) {
                    println!("⚠️ Failed to save block {}: {}", new_height, e);
                }
    
                // Update in-memory chain state.
                let prev_ts = self
                    .blocks
                    .last()
                    .map(|b| b.timestamp)
                    .unwrap_or(header.timestamp);
                self.last_block_time_secs = header.timestamp.saturating_sub(prev_ts);
                self.last_nonce = best_nonce;
    
                self.blocks.push(header.clone());
                self.block_hashes.insert(best_hash, new_height);
                self.timestamps.push(header.timestamp);
                self.height = new_height;
                self.cached_difficulty = None;
                self.blocks_found += 1;

                // Signal: our own chain has moved.
                self.chain_generation.fetch_add(1, AtomicOrdering::Relaxed);
                self.abort_mining.store(true, AtomicOrdering::Relaxed);

                // Keep P2P state in sync.
                if let Some(p2p) = self.p2p.as_mut() {
                    p2p.local_height = new_height;
                    p2p.local_best_hash = best_hash;
                    p2p.sync_manager.local_height = new_height;
                }
    
                // Update emission counter.
                self.total_emitted = self.total_emitted.saturating_add(BLOCK_REWARD_LYT);
                let _ = self
                    .storage
                    .save_state("total_emitted", &self.total_emitted);
    
                // Apply the block to the UTXO set.
                self.update_utxo_set(&block);
    
                // Track txids included in this block.
                let included_txids: HashSet<Txid> = block
                    .transactions
                    .iter()
                    .filter(|tx| !tx.is_coinbase())
                    .map(|tx| tx.txid(&mut self.argon2))
                    .collect();
    
                for txid in &included_txids {
                    self.processed_txids.insert(*txid, self.height);
                }
    
                // Drop included txs from the mempool.
                let old_mempool = std::mem::take(&mut self.mempool);
                let mut new_mempool = Vec::with_capacity(old_mempool.len());
                for tx in old_mempool {
                    let txid = tx.txid(&mut self.argon2);
                    if included_txids.contains(&txid) {
                        // included — drop from mempool
                    } else {
                        self.processed_txids.remove(&txid);
                        new_mempool.push(tx);
                    }
                }
                self.mempool = new_mempool;
                let _ = self.storage.save_mempool(&self.mempool);
    
                self.prune_processed_txids();
    
                // Epoch transition.
                if new_height % EPOCH_BLOCKS == 0 {
                    if let Err(e) = self.process_epoch_end() {
                        println!("⚠️ Epoch processing failed: {}", e);
                    }
                }
    
                let _ = self.storage.save_state("height", &self.height);
                let _ = self.storage.save_state("epoch", &self.epoch);
    
                // Checkpoint (if configured).
                let interval = self.config.advanced.checkpoint_interval;
                if interval > 0 && self.height % interval == 0 {
                    self.create_checkpoint();
                }
    
                // Backup is handled outside the write-lock in main.rs.
                use colored::Colorize;
                println!(
                    "\r\x1b[K{} {} {} {} {}",
                    "[BLOCK]".green().bold(),
                    format!("height={}", new_height).cyan(),
                    format!("hash={}", hex::encode(&best_hash[0..8])).yellow(),
                    format!("epoch={}", self.epoch).cyan(),
                    format!("nonce={}", best_nonce).cyan(),
                );
    
                               // Broadcast the block to all peers.
                               if let Some(p2p) = &mut self.p2p {
                                p2p.broadcast(&P2PMessage::Block {
                                    header: header.clone(),
                                    transactions: block.transactions.clone(),
                                    signature: block.signature.clone(),
                                    pubkey: block.pubkey.clone(),
                                });
                            }
                        }
                    }
            
                /// Commit a mining result under a short write-lock.
               /// Commit a mining result under a short write-lock.
    /// If the chain has moved since the job was prepared, the result is
    /// discarded and `Ok(false)` is returned.
    /// Returns `Ok(true)` if the block/share was accepted.
    pub fn commit_mining_result(
        &mut self,
        job: &MiningJob,
        best_nonce: u64,
        best_hash: Hash32,
        found_block: bool,
    ) -> Result<bool, String> {
        // Guard: chain moved during mining → discard.
        if self.chain_generation.load(AtomicOrdering::Relaxed) != job.generation {
            return Ok(false);
        }
        if job.prev_hash != self.last_hash() {
            return Ok(false);
        }
        if job.height != self.height + 1 {
            return Ok(false);
        }
        if self.block_hashes.contains_key(&best_hash) {
            return Ok(false);
        }

        // ---- Not a block: just record the share. ----
        if !found_block {
            if best_hash != [0xffu8; 32] {
                let mut header = job.header.clone();
                header.nonce = best_nonce;
                let share = Share::new(self.miner_id, header, best_nonce, best_hash);
                let _ = self.add_share(share);
            }
            return Ok(true);
        }

        // ---- Block found: build and persist. ----
        let mut header = job.header.clone();
        header.nonce = best_nonce;

        let txs = job.txs.clone();

        // Collect non-coinbase txids to detect duplicates.
        let mut block_txids = HashSet::new();
        for tx in &txs {
            if tx.is_coinbase() {
                continue;
            }
            let txid = tx.txid(&mut self.argon2);
            if !block_txids.insert(txid) {
                return Err("Duplicate transaction in block".to_string());
            }
        }

        // Pre-validate no double spend.
        let block_preview = Block {
            header: header.clone(),
            transactions: txs.clone(),
            signature: None,
            pubkey: None,
        };
        if let Err(e) = crate::p2p::validate_block_no_double_spend(&block_preview) {
            return Err(format!("Double spend in block: {}", e));
        }

        // Sign the block with our wallet.
        let (signature, pubkey) = if let Some(wallet) = &self.wallet {
            let block_hash = header.hash(&mut self.argon2);
            (
                wallet.sign_block(&block_hash).ok(),
                Some(wallet.public_key.clone()),
            )
        } else {
            (None, None)
        };

        let block = Block {
            header: header.clone(),
            transactions: txs,
            signature,
            pubkey,
        };

        // Save the share silently — visible in [STATUS] as shares=N.
        let share = Share::new(self.miner_id, header.clone(), best_nonce, best_hash);
        let _ = self.add_share(share);

        let new_height = job.height;

        // Persist the block.
        if let Err(e) = self.storage.save_block(new_height, &block) {
            return Err(format!("Failed to save block {}: {}", new_height, e));
        }

        // Update in-memory chain state.
        let prev_ts = self
            .blocks
            .last()
            .map(|b| b.timestamp)
            .unwrap_or(header.timestamp);
        self.last_block_time_secs = header.timestamp.saturating_sub(prev_ts);
        self.last_nonce = best_nonce;

        self.blocks.push(header.clone());
        self.block_hashes.insert(best_hash, new_height);
        self.timestamps.push(header.timestamp);
        self.height = new_height;
        self.cached_difficulty = None;
        self.blocks_found += 1;

        // Signal: our own chain has moved.
        self.chain_generation.fetch_add(1, AtomicOrdering::Relaxed);
        self.abort_mining.store(true, AtomicOrdering::Relaxed);

        // Keep P2P state in sync.
        if let Some(p2p) = self.p2p.as_mut() {
            p2p.local_height = new_height;
            p2p.local_best_hash = best_hash;
            p2p.sync_manager.local_height = new_height;
        }

        // Update emission counter.
        self.total_emitted = self.total_emitted.saturating_add(BLOCK_REWARD_LYT);
        let _ = self.storage.save_state("total_emitted", &self.total_emitted);

        // Apply the block to the UTXO set.
        self.update_utxo_set(&block);

        // Track txids included in this block.
        let included_txids: HashSet<Txid> = block
            .transactions
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .map(|tx| tx.txid(&mut self.argon2))
            .collect();

        for txid in &included_txids {
            self.processed_txids.insert(*txid, self.height);
        }

        // Drop included txs from the mempool.
        let old_mempool = std::mem::take(&mut self.mempool);
        let mut new_mempool = Vec::with_capacity(old_mempool.len());
        for tx in old_mempool {
            let txid = tx.txid(&mut self.argon2);
            if included_txids.contains(&txid) {
                // included — drop from mempool
            } else {
                self.processed_txids.remove(&txid);
                new_mempool.push(tx);
            }
        }
        self.mempool = new_mempool;
        let _ = self.storage.save_mempool(&self.mempool);

        self.prune_processed_txids();

        // Epoch transition.
        if new_height % EPOCH_BLOCKS == 0 {
            if let Err(e) = self.process_epoch_end() {
                println!("⚠️ Epoch processing failed: {}", e);
            }
        }

        let _ = self.storage.save_state("height", &self.height);
        let _ = self.storage.save_state("epoch", &self.epoch);

        // Checkpoint (if configured).
        let interval = self.config.advanced.checkpoint_interval;
        if interval > 0 && self.height % interval == 0 {
            self.create_checkpoint();
        }

        // Log.
        use colored::Colorize;
        println!(
            "\r\x1b[K{} {} {} {} {}",
            "[BLOCK]".green().bold(),
            format!("height={}", new_height).cyan(),
            format!("hash={}", hex::encode(&best_hash[0..8])).yellow(),
            format!("epoch={}", self.epoch).cyan(),
            format!("nonce={}", best_nonce).cyan(),
        );

        // Broadcast the block to all peers.
        if let Some(p2p) = &mut self.p2p {
            p2p.broadcast(&P2PMessage::Block {
                header: header.clone(),
                transactions: block.transactions.clone(),
                signature: block.signature.clone(),
                pubkey: block.pubkey.clone(),
            });
        }

        Ok(true)
    }

    pub fn update_utxo_set(&mut self, block: &Block) {
        for tx in &block.transactions {
            let txid = tx.txid(&mut self.argon2);

            for (i, output) in tx.outputs.iter().enumerate() {
                let outpoint = (txid, i as u32);
                if let Err(e) = self.storage.save_utxo(&outpoint, output) {
                    println!(
                        "⚠️ Failed to save UTXO {}:{}: {}",
                        hex::encode(&txid[0..8]),
                        i,
                        e
                    );
                }
            }

            for input in &tx.inputs {
                if !input.is_coinbase() {
                    if let Err(e) = self.storage.delete_utxo(&input.outpoint()) {
                        println!(
                            "⚠️ Failed to delete UTXO {}: {}",
                            hex::encode(&input.outpoint().0[0..8]),
                            e
                        );
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Epoch end
    // ------------------------------------------------------------------

    fn current_epoch_reward(&self) -> u64 {
        let blocks_per_year = EPOCH_BLOCKS.saturating_mul(365);
        let year = (self.height / blocks_per_year.max(1)) + 1;
        match year {
            1 => EPOCH_REWARD_YEAR_1,
            2 => EPOCH_REWARD_YEAR_2,
            3 => EPOCH_REWARD_YEAR_3,
            4 => EPOCH_REWARD_YEAR_4,
            _ => EPOCH_REWARD_YEAR_5_PLUS,
        }
    }

    pub fn process_epoch_end(&mut self) -> Result<(), String> {
        println!("\n📅 Processing epoch {} end...", self.epoch);

        let completed_epoch = self.epoch;
                // Marker: epoch is being closed. If the node crashes, load_state
                // will see this marker on restart and will not pay rewards twice.
        let _ = self.storage.save_state("epoch_processing", &completed_epoch);

        match self.process_pending_slashes() {
            Ok(0) => {}
            Ok(n) => println!("   ⚖️ Executed {} slash(es) this epoch", n),
            Err(e) => println!("   ⚠️ Slashing failed: {}", e),
        }

        let mut poci_results =
            calculate_poci(&self.miners, &self.bonds, &self.loyalty, self.height);

        let epoch_reward = self.current_epoch_reward();
        let year = (self.height / (EPOCH_BLOCKS.saturating_mul(365)).max(1)) + 1;
        println!(
            "   📆 Year {} — epoch reward: {} LYT ({} ACM)",
            year,
            epoch_reward,
            epoch_reward / LYATORS_PER_ACM
        );

        let available: u64 = if self.total_emitted >= MAX_SUPPLY_LYT {
            0
        } else {
            MAX_SUPPLY_LYT - self.total_emitted
        };
        let effective_epoch_reward = epoch_reward.min(available);
        if effective_epoch_reward < epoch_reward {
            println!(
                "   ⚠️ Epoch reward trimmed: {} → {} LYT (supply cap)",
                epoch_reward, effective_epoch_reward
            );
        }

        let treasury_cut = effective_epoch_reward.saturating_mul(TREASURY_FRACTION_BPS) / 10_000;
        let miners_pool = effective_epoch_reward.saturating_sub(treasury_cut);

        println!(
            "   🏦 Treasury (7%): {} LYT | Miners pool: {} LYT",
            treasury_cut, miners_pool
        );

        if treasury_cut > 0 {
            match TxOut::create_p2pkh(TREASURY_ADDRESS) {
                Ok(mut txout) => {
                    txout.value = treasury_cut;
                    let mut hasher = Sha256::new();
                    hasher.update(b"ACCUM-TREASURY");
                    hasher.update(completed_epoch.to_le_bytes());
                    let txid: Txid = hasher.finalize().into();
                    let outpoint = (txid, 0u32);
                    if let Err(e) = self.storage.save_utxo(&outpoint, &txout) {
                        println!("   ⚠️ Failed to save treasury UTXO: {}", e);
                    } else {
                        println!("   🏦 Treasury UTXO created");
                    }
                }
                Err(e) => println!("   ⚠️ Treasury output failed: {}", e),
            }
        }

        let total_poci: u128 = poci_results.iter().map(|r| r.poci as u128).sum();
        if total_poci == 0 {
            println!("   ⚠️ Total PoCI is 0 — no rewards to distribute");
        } else {
            for r in poci_results.iter_mut() {
                let reward_u128 = (r.poci as u128 * miners_pool as u128) / total_poci;
                r.reward = u64::try_from(reward_u128).unwrap_or(u64::MAX);
            }
        }

        Self::trim_rewards_to_max_supply(&mut poci_results, self.total_emitted);

        let (total_rewards, rewarded_miners) = self.pay_epoch_rewards(&poci_results);

        println!("   Total epoch rewards: {} LYT", total_rewards);
        println!("   Rewarded miners: {}", rewarded_miners);

        let previous_commit_hash: Hash32 = self
            .storage
            .get_state::<Hash32>(&format!(
                "epoch_commit_root_{}",
                completed_epoch.saturating_sub(1)
            ))
            .ok()
            .flatten()
            .unwrap_or([0u8; 32]);

                // Archive current-epoch shares and compute the share-set Merkle root.
        // `SharePool::new_epoch` snapshots shares into `archive` and stores
        // the root in `epoch_roots[completed_epoch]` BEFORE clearing.
        self.share_pool.new_epoch();
                // Persist the archive to disk so it survives restarts.
                if let Some(shares) = self.share_pool.archive.get(&completed_epoch) {
                    if let Err(e) = self.storage.save_shares_archive(completed_epoch, shares) {
                        println!("   ⚠️ Failed to save shares archive: {}", e);
                    }
                }

        let share_root = self
            .share_pool
            .epoch_roots
            .get(&completed_epoch)
            .copied()
            .unwrap_or([0u8; 32]);

        println!(
            "   🧾 Share root for epoch {}: {}...",
            completed_epoch,
            hex::encode(&share_root[0..8]),
        );

        // Persist the share root for this epoch so it survives restarts
        // and can be served to peers via GetShares.
        let _ = self.storage.save_state(
            &format!("epoch_share_root_{}", completed_epoch),
            &share_root,
        );

        // Save the full EpochCommit record (existing).
        self.save_epoch_commit(completed_epoch, previous_commit_hash);

        self.epoch = self.epoch.saturating_add(1);
        self.update_loyalty_for_epoch(completed_epoch, &poci_results);
        self.reset_miner_shares();

        self.total_emitted = self
            .total_emitted
            .saturating_add(total_rewards)
            .saturating_add(treasury_cut);
        let _ = self
            .storage
            .save_state("total_emitted", &self.total_emitted);
        if let Err(e) = self.storage.save_state("epoch", &self.epoch) {
            println!("   ⚠️ Failed to save epoch: {}", e);
        }

        println!("✅ Epoch {} completed", completed_epoch);
        println!("🚀 Epoch {} started", self.epoch);

        // Remove marker — epoch closed successfully.
        let _ = self.storage.delete_state("epoch_processing");

        Ok(())
    }

    fn trim_rewards_to_max_supply(results: &mut [PoCIResult], total_emitted: u64) {
        let total_requested: u128 = results.iter().map(|r| r.reward as u128).sum();
        let available: u128 = if total_emitted >= MAX_SUPPLY_LYT {
            0
        } else {
            (MAX_SUPPLY_LYT - total_emitted) as u128
        };

        if total_requested <= available {
            return;
        }

        println!(
            "⚠️ Epoch reward {} LYT exceeds available supply {} LYT — trimming",
            total_requested, available
        );

        if available == 0 {
            for r in results.iter_mut() {
                r.reward = 0;
            }
            return;
        }

        for r in results.iter_mut() {
            r.reward = ((r.reward as u128 * available) / total_requested) as u64;
        }
    }

    fn pay_epoch_rewards(&mut self, results: &[PoCIResult]) -> (u64, u32) {
        let mut total_rewards = 0u64;
        let mut rewarded_miners = 0u32;

        for result in results {
            if result.reward == 0 {
                continue;
            }

            total_rewards = total_rewards.saturating_add(result.reward);
            rewarded_miners += 1;

            let mut hasher = Sha256::new();
            hasher.update(b"ACCUM-EPOCH-REWARD");
            hasher.update(self.height.to_le_bytes());
            hasher.update(self.epoch.to_le_bytes());
            hasher.update(&result.miner_id);
            let txid: Txid = hasher.finalize().into();

            let (payout_addr, is_local) = if result.miner_id == self.miner_id {
                match &self.wallet {
                    Some(w) => (Some(w.address.clone()), true),
                    None => (None, true),
                }
            } else {
                match self.miners.get(&result.miner_id) {
                    Some(m) => (m.payout_address.clone(), false),
                    None => {
                        println!(
                            "   ⚠️ Miner {}... not found in local state",
                            hex::encode(&result.miner_id[0..6])
                        );
                        (None, false)
                    }
                }
            };

            match payout_addr {
                Some(addr) => match TxOut::create_p2pkh(&addr) {
                    Ok(mut txout) => {
                        txout.value = result.reward;
                        let outpoint = (txid, 0u32);
                        match self.storage.save_utxo(&outpoint, &txout) {
                            Ok(_) => {
                                if is_local {
                                    println!(
                                        "   💰 Reward to self: {} LYT (shares={}, poci={})",
                                        result.reward, result.shares, result.poci
                                    );
                                } else {
                                    println!(
                                        "   💰 Reward to {}...: {} LYT",
                                        hex::encode(&result.miner_id[0..6]),
                                        result.reward
                                    );
                                }
                            }
                            Err(e) => {
                                println!("   ❌ Failed to save reward UTXO: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("   ❌ Failed to create reward output: {}", e);
                    }
                },
                None => {
                    if is_local {
                        println!(
                            "   ⚠️ Local miner has no wallet; reward {} LYT was not created",
                            result.reward
                        );
                    } else {
                        println!(
                            "   ⚠️ Miner {}... has no payout address, reward {} LYT lost",
                            hex::encode(&result.miner_id[0..6]),
                            result.reward
                        );
                    }
                }
            }

            if let Some(miner) = self.miners.get_mut(&result.miner_id) {
                miner.total_rewards = miner.total_rewards.saturating_add(result.reward);
                if let Err(e) = self.storage.save_miner(&result.miner_id, miner) {
                    println!(
                        "   ⚠️ Failed to save miner {}: {}",
                        hex::encode(&result.miner_id[0..6]),
                        e
                    );
                }
            }
        }

        (total_rewards, rewarded_miners)
    }

    fn save_epoch_commit(&mut self, completed_epoch: u32, previous_commit_hash: Hash32) -> Hash32 {
        let epoch_commit = self.build_epoch_commit(completed_epoch, previous_commit_hash);
        let commit_hash = epoch_commit.hash();

        if let Err(e) = self
            .storage
            .save_state(&format!("epoch_commit_{}", completed_epoch), &epoch_commit)
        {
            println!("   ⚠️ Failed to save epoch commit: {}", e);
        }
        if let Err(e) = self.storage.save_state(
            &format!("epoch_commit_root_{}", completed_epoch),
            &commit_hash,
        ) {
            println!("   ⚠️ Failed to save epoch commit root: {}", e);
        }

        println!(
            "   🔐 Epoch commit #{}: hash={}... shares={} miners={}",
            completed_epoch,
            hex::encode(&commit_hash[0..8]),
            epoch_commit.total_shares,
            epoch_commit.miners_count,
        );

        if let Some(p2p) = &mut self.p2p {
            p2p.broadcast(&P2PMessage::EpochCommit {
                epoch: completed_epoch,
                commit_root: commit_hash,
                timestamp: current_timestamp(),
            });
        }

        commit_hash
    }

    fn update_loyalty_for_epoch(&mut self, completed_epoch: u32, results: &[PoCIResult]) {
        let miner_ids: Vec<MinerId> = self.miners.keys().copied().collect();

        for miner_id in miner_ids {
            let participated = results
                .iter()
                .any(|r| r.miner_id == miner_id && r.shares > 0);

            let loyalty = self
                .loyalty
                .entry(miner_id)
                .or_insert_with(LoyaltyData::new);
            loyalty.update(completed_epoch, participated);

            let key = format!("loyalty_{}", hex::encode(&miner_id));
            if let Err(e) = self.storage.save_state(&key, loyalty) {
                println!(
                    "   ⚠️ Failed to save loyalty for {}: {}",
                    hex::encode(&miner_id[0..6]),
                    e
                );
            }
        }
    }

    fn reset_miner_shares(&mut self) {
        for miner in self.miners.values_mut() {
            miner.shares = 0;
            if let Err(e) = self.storage.save_miner(&miner.miner_id, miner) {
                println!(
                    "   ⚠️ Failed to reset shares for {}: {}",
                    hex::encode(&miner.miner_id[0..6]),
                    e
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Checkpoints
    // ------------------------------------------------------------------

    fn create_checkpoint(&mut self) {
        let last_block = match self.last_block() {
            Some(b) => b.clone(),
            None => return,
        };

        let block_hash = last_block.hash(&mut self.argon2);
        let state_root = self.calculate_state_root();

        let signature = if let Some(wallet) = &self.wallet {
            let mut data = Vec::new();
            data.extend_from_slice(&self.height.to_le_bytes());
            data.extend_from_slice(&block_hash);
            data.extend_from_slice(&state_root);
            let digest: [u8; 32] = Sha256::digest(&data).into();
            wallet.sign(&digest).ok()
        } else {
            None
        };

        let checkpoint = Checkpoint {
            height: self.height,
            block_hash,
            state_root,
            timestamp: current_timestamp(),
            signature: signature.unwrap_or_default(),
            verified: false,
        };

        self.checkpoints.push(checkpoint.clone());
        if let Err(e) = self.storage.save_checkpoint(self.height, &checkpoint) {
            println!("⚠️ Failed to save checkpoint: {}", e);
        }

        while self.checkpoints.len() > self.config.advanced.max_checkpoints {
            self.checkpoints.remove(0);
        }

        println!("📌 Checkpoint created at height {}", self.height);
    }

    fn calculate_state_root(&self) -> Hash32 {
        let mut data = Vec::new();

        let mut miner_ids: Vec<&MinerId> = self.miners.keys().collect();
        miner_ids.sort();
        for id in &miner_ids {
            let miner = &self.miners[*id];
            data.extend_from_slice(*id);
            data.extend_from_slice(&miner.shares.to_le_bytes());
            data.extend_from_slice(&miner.bond.to_le_bytes());
        }

        let mut bond_ids: Vec<&MinerId> = self.bonds.keys().collect();
        bond_ids.sort();
        for id in &bond_ids {
            let bond = &self.bonds[*id];
            data.extend_from_slice(*id);
            data.extend_from_slice(&bond.amount.to_le_bytes());
            data.extend_from_slice(&bond.lock_until.to_le_bytes());
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&Sha256::digest(&data));
        result
    }
}

// ============================================================
// Helper: compute header hash for a given nonce.
// BlockHeader::to_bytes layout (120 bytes):
//   [0..4]     version
//   [4..36]    prev_hash
//   [36..68]   merkle_root
//   [68..76]   timestamp
//   [76..108]  difficulty
//   [108..116] nonce
//   [116..120] epoch_index
// ============================================================
pub fn header_with_nonce_hash(
    header_bytes: &[u8; 120],
    nonce: u64,
    argon2: &mut Argon2Cache,
) -> Hash32 {
    let mut buf = *header_bytes;
    buf[108..116].copy_from_slice(&nonce.to_le_bytes());
    argon2.hash(&buf)
}
