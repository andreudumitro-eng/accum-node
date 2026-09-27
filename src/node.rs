//! Node: main node struct and impl

use crate::block::{Block, BlockHeader, Transaction, TxOut};
use crate::config::Config;
use crate::consensus::{calculate_poci, EquivocationProof, PoCIResult, SlashingPool};
use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::difficulty::adjust_difficulty;
use crate::epoch_commit::EpochCommit;
use crate::genesis::create_genesis_block;
use crate::miner::{LoyaltyData, MinerData, Share, SharePool};
use crate::network::{AttackDetection, DDoSProtection};
use crate::p2p::{
    validate_block_coinbase, validate_block_no_double_spend, P2PMessage, P2PNode, SyncManager,
    SyncStatus,
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

/// How many recent heights we keep txids in `processed_txids` for dedup.
const PROCESSED_TXIDS_RETENTION: Height = 1_000;

/// Genesis emission (LYT).
const GENESIS_SUPPLY_LYT: u64 = 500_000_000;

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
    pub cached_difficulty: Option<(Height, Target)>,
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
            cached_difficulty: None,
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
        let adjusted = adjust_difficulty(slice, &current_target);

        if adjusted != current_target {
            println!(
                "⚙️ Difficulty adjusted at height {} → new target for block {} (diff={:.6e}, nbits={:08x})",
                self.height,
                self.height + 1,
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
                Some(0) => return if our_height == 0 { 1.0 } else { 0.0 },
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

        // Handle incoming messages under our own write-lock.
        for (msg, addr) in incoming {
            self.handle_p2p_message(msg, addr);
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

        // 4. Handle sync timeouts.
        if let Some(p2p) = self.p2p.as_mut() {
            if let Some(_peer_id) = p2p.sync_manager.check_timeouts() {
                println!("⚠️ Sync timeout with peer");
                p2p.sync_manager.active_session = None;
                p2p.sync_manager.sync_in_progress = false;
            }
        }

        // 5. Request blocks from peer.
        if let Some(p2p) = self.p2p.as_mut() {
            let now = current_timestamp();
            if now - self.last_sync_request_time >= 2 {
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
                            match p2p
                                .sync_manager
                                .request_blocks_from_peer(&peer_id, from_height)
                            {
                                Ok(msg) => {
                                    self.last_sync_request_time = now;
                                    // Send message directly to the peer.
                                    for (peer_addr, peer) in p2p.peers.iter_mut() {
                                        if peer.get_peer_id() == peer_id {
                                            let _ = peer.send_message(&msg);
                                            break;
                                        }
                                    }
                                    if let Some(session) = p2p.sync_manager.active_session.as_mut()
                                    {
                                        session.status = SyncStatus::Receiving;
                                        session.last_activity = now;
                                    }
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
                        let mut blocks = Vec::new();
                        let end = from_height.saturating_add(max_count as u64);
                        for h in from_height..end {
                            if let Ok(Some(block)) = self.storage.get_block(h) {
                                blocks.push(block);
                            } else {
                                break;
                            }
                        }
                        if !blocks.is_empty() {
                            let _ = peer.send_message(&P2PMessage::Blocks(blocks));
                        }
                    }
                    P2PMessage::Blocks(blocks) => {
                        let peer_id = peer.get_peer_id();
        
                        // Temporary take sync_manager out to avoid double mutable borrow.
                        let mut sync_manager = self
                            .p2p
                            .as_mut()
                            .map(|p| std::mem::replace(&mut p.sync_manager, SyncManager::new()))
                            .unwrap();
        
                        let verification_result = sync_manager
                            .verify_and_accept_blocks(&blocks, self);
        
                        // Put sync_manager back.
                        if let Some(p2p) = self.p2p.as_mut() {
                            p2p.sync_manager = sync_manager;
                        }
        
                        match verification_result {
                            Ok(new_height) => {
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
                                eprintln!("❌ Failed to verify and store blocks: {}", e);
                                let p2p = self.p2p.as_mut().unwrap();
                                if let Some(peer) = p2p.peers.get_mut(&addr) {
                                    peer.ban(&format!("Invalid blocks: {}", e));
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
                        let expected_height = self.height + 1;
                        let prev_hash = self.last_hash();
        
                        if header.prev_hash != prev_hash {
                            return;
                        }
        
                        let hash = header.hash(&mut self.argon2);
                        if !header.difficulty.is_met_by(&hash) {
                            println!("⚠️ Received invalid block (PoW failed)");
                            return;
                        }
        
                        if let Some(cp) = self.checkpoint_at(expected_height) {
                            if hash != cp.block_hash {
                                println!(
                                    "⚠️ Block hash conflicts with checkpoint at height {}",
                                    expected_height
                                );
                                return;
                            }
                        }
        
                        if let (Some(sig), Some(pk)) = (&signature, &pubkey) {
                            if !Wallet::verify_signature(pk, sig, &hash) {
                                println!("⚠️ Received block with invalid signature");
                                return;
                            }
                        } else {
                            println!("⚠️ Received block without signature");
                            return;
                        }
        
                        let prev_timestamp = if self.height > 0 {
                            self.blocks.last().map(|b| b.timestamp)
                        } else {
                            None
                        };
                        let median = self.median_timestamp();
                        if !header.validate_timestamp(prev_timestamp, median) {
                            println!("⚠️ Received block with invalid timestamp");
                            return;
                        }
        
                        let computed_root =
                            SyncManager::compute_merkle_root(&transactions, &mut self.argon2);
                        if header.merkle_root != computed_root {
                            println!("⚠️ Received block with invalid merkle root");
                            return;
                        }
        
                        let block = Block {
                            header: header.clone(),
                            transactions: transactions.clone(),
                            signature,
                            pubkey,
                        };
        
                        if let Err(e) = validate_block_coinbase(&block, &self.storage) {
                            println!("⚠️ Received block with invalid coinbase: {}", e);
                            return;
                        }
        
                        if let Err(e) = validate_block_no_double_spend(&block) {
                            println!("⚠️ Received block with double spend: {}", e);
                            return;
                        }
        
                        let new_height = expected_height;
                        if let Err(e) = self.storage.save_block(new_height, &block) {
                            println!("❌ Failed to save received block: {}", e);
                            return;
                        }
        
                        self.blocks.push(header.clone());
                        self.block_hashes.insert(hash, new_height);
                        self.timestamps.push(header.timestamp);
                        self.height = new_height;
                        self.cached_difficulty = None;
        
                        self.update_utxo_set(&block);

                                                // Height сохраняем ДО process_epoch_end — если оно упадёт,
                        // height всё равно уже зафиксирован.
                        let _ = self.storage.save_state("height", &self.height);

                        // Epoch transition when syncing via P2P.
                        if new_height % EPOCH_BLOCKS == 0 {
                            if let Err(e) = self.process_epoch_end() {
                                println!("⚠️ Epoch processing failed: {}", e);
                            }
                        }

                        // Epoch сохраняем ПОСЛЕ process_epoch_end — epoch мог измениться.
                        let _ = self.storage.save_state("epoch", &self.epoch);

                        // Чистим processed_txids, иначе растёт неограниченно.
                        self.prune_processed_txids();

                        let mut txids_in_block = HashSet::new();
                        for tx in &block.transactions {
                            if !tx.is_coinbase() {
                                let txid = tx.txid(&mut self.argon2);
                                txids_in_block.insert(txid);
                                self.processed_txids.insert(txid, new_height);
                            }
                        }
        
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
        
                        let p2p = self.p2p.as_mut().unwrap();
                        p2p.local_height = new_height;
                        p2p.local_best_hash = hash;
                        p2p.sync_manager.local_height = new_height;
        
                        println!("📥 Received and accepted block #{}", new_height);
        
                        let msg = P2PMessage::Block {
                            header: header.clone(),
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

    // ------------------------------------------------------------------
    // Mining
    // ------------------------------------------------------------------

    pub fn mine_block(&mut self) {
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
        
                let num_threads = self.config.mining.threads.max(1) as u64;
                let batch = MINING_BATCH_SIZE;
        
                let start_time = std::time::Instant::now();
        
                std::thread::scope(|scope| {
                    for t in 0..num_threads {
                        let best_hash_ref = Arc::clone(&best_hash_shared);
                        let best_nonce_ref = Arc::clone(&best_nonce_shared);
                        let found_ref = Arc::clone(&block_found);
                        let hb = &header_bytes;
        
                        scope.spawn(move || {
                            let mut local_argon2 = Argon2Cache::new(ARGON2_CACHE_SIZE);
        
                            let mut nonce = t;
                            while nonce < batch {
                                if found_ref.load(AtomicOrdering::Relaxed) {
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

            // Шару всё равно сохраняем, но без печати на экран.
            let share = Share::new(self.miner_id, header.clone(), best_nonce, best_hash);
            let _ = self.add_share(share);

            let new_height = self.height + 1;
            if let Err(e) = self.storage.save_block(new_height, &block) {
                println!("⚠️ Failed to save block {}: {}", new_height, e);
            }

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

                        // Keep P2P state in sync.
                        if let Some(p2p) = self.p2p.as_mut() {
                            p2p.local_height = new_height;
                            p2p.local_best_hash = best_hash;
                            p2p.sync_manager.local_height = new_height;
                        }

            self.total_emitted = self.total_emitted.saturating_add(BLOCK_REWARD_LYT);
            let _ = self
                .storage
                .save_state("total_emitted", &self.total_emitted);

            self.update_utxo_set(&block);

            let included_txids: HashSet<Txid> = block
                .transactions
                .iter()
                .filter(|tx| !tx.is_coinbase())
                .map(|tx| tx.txid(&mut self.argon2))
                .collect();

            for txid in &included_txids {
                self.processed_txids.insert(*txid, self.height);
            }

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

            if new_height % EPOCH_BLOCKS == 0 {
                if let Err(e) = self.process_epoch_end() {
                    println!("⚠️ Epoch processing failed: {}", e);
                }
            }

            let _ = self.storage.save_state("height", &self.height);
            let _ = self.storage.save_state("epoch", &self.epoch);

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

            if let Some(p2p) = &mut self.p2p {
                p2p.broadcast(&P2PMessage::Block {
                    header: header.clone(),
                    transactions: block.transactions.clone(),
                    signature: block.signature.clone(),
                    pubkey: block.pubkey.clone(),
                });
            }
        } else if best_hash != [0xffu8; 32] {
            header.nonce = best_nonce;
            let share = Share::new(self.miner_id, header, best_nonce, best_hash);
            let _ = self.add_share(share);
            // Do not print [SHARE] — it is visible in [STATUS] as shares=...
        }
        // If neither block nor share — stay silent to avoid spam.
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

        self.save_epoch_commit(completed_epoch, previous_commit_hash);

        self.share_pool.new_epoch();
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
fn header_with_nonce_hash(
    header_bytes: &[u8; 120],
    nonce: u64,
    argon2: &mut Argon2Cache,
) -> Hash32 {
    let mut buf = *header_bytes;
    buf[108..116].copy_from_slice(&nonce.to_le_bytes());
    argon2.hash(&buf)
}
