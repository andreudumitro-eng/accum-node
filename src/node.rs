//! Node: main node struct and impl

use crate::block::{Block, BlockHeader, Transaction, TxIn, TxOut};
use crate::config::Config;
use crate::consensus::{calculate_poci, EquivocationProof};
use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::genesis::create_genesis_block;
use crate::miner::{LoyaltyData, MinerData, Share, SharePool};
use crate::network::{AttackDetection, DDoSProtection};
use crate::p2p::{P2PMessage, P2PNode, SyncManager, SyncStatus};
use crate::storage::{Bond, Checkpoint, ProductionStorage, CF_BONDS, CF_CHECKPOINTS, CF_MINERS, CF_STATE};
use crate::difficulty::adjust_difficulty;
use std::io::Write;
use crate::types::*;
use crate::wallet::Wallet;
use crate::{is_saving_state, set_saving_state, should_shutdown};
use parking_lot::RwLock;
use rocksdb::IteratorMode;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::Arc;
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
    pub equivocation_proofs: HashMap<MinerId, Vec<EquivocationProof>>,
    pub attack_detection: AttackDetection,
    pub checkpoints: Vec<Checkpoint>,
    pub ddos_protection: DDoSProtection,
    pub processed_txids: HashSet<Txid>,
    pub sync_manager: SyncManager,
    pub total_emitted: u64,
}

impl Node {
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
            start_time: current_timestamp(),
            miner_id,
            last_hash_rate: 0,
            peak_hash_rate: 0,
            wallet: Some(wallet),
            config: config.clone(),
            equivocation_proofs: HashMap::new(),
            attack_detection: AttackDetection::new(),
            checkpoints: Vec::new(),
            ddos_protection: DDoSProtection::new(),
            processed_txids: HashSet::new(),
            sync_manager: SyncManager::new(),
            total_emitted: 0,
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
            node.verify_genesis_signature();
        }
        // Синхронизируем эпоху share_pool с эпохой ноды (важно после перезапуска)
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
            node_arc.clone(),
        )
        .map_err(|e| e.to_string())?;
        println!("🔧 [20] P2P created");

        // Настраиваем callback для отправки сообщений через P2P
        {
            let node_ref = node_arc.clone();
            p2p.sync_manager.send_message_callback =
                Some(Box::new(move |peer_id: &PeerId, msg: P2PMessage| {
                    let mut node = node_ref.write();
                    if let Some(p2p) = node.p2p.as_mut() {
                        for peer in p2p.peers.values_mut() {
                            if &peer.peer_id == peer_id {
                                return peer.send_message(&msg).map_err(|e| e.to_string());
                            }
                        }
                    }
                    Err("Peer not found".to_string())
                }));
        }

        // Сохраняем P2P в ноду и инициализируем состояние
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

    fn load_or_create_wallet(storage: &ProductionStorage) -> Result<Wallet, String> {
        let wallet_path = dirs::home_dir()
            .ok_or("Cannot find home dir")?
            .join(".accum")
            .join("wallet.json");

        // 1. Пытаемся загрузить из файла
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

            let secret_key =
                hex::decode(&wallet_data.private_key).map_err(|_| "Invalid private key format")?;

            let wallet = Wallet::from_secret_key(&secret_key)?;
            println!("✅ Wallet loaded: {}", wallet.address);
            return Ok(wallet);
        }

        // 2. Пытаемся загрузить из базы
        if let Some(wallet_data) = storage.get_state::<Vec<u8>>("wallet")? {
            println!("🔑 Loading wallet from database...");
            let secret_key: [u8; 32] = wallet_data.try_into().map_err(|_| "Invalid wallet data")?;
            let wallet = Wallet::from_secret_key(&secret_key)?;

            // Сохраняем в файл для будущих запусков
            let wallet_json = serde_json::json!({
                "private_key": hex::encode(&wallet.secret_key),
            });
            fs::create_dir_all(wallet_path.parent().unwrap())
                .map_err(|e| format!("Failed to create .accum directory: {}", e))?;
            fs::write(
                &wallet_path,
                serde_json::to_string_pretty(&wallet_json).unwrap(),
            )
            .map_err(|e| format!("Failed to save wallet: {}", e))?;
            println!("✅ Wallet saved to {}", wallet_path.display());

            return Ok(wallet);
        }

        // 3. Создаем новый кошелек
        println!("🆕 No wallet found, creating new wallet...");
        let wallet = Wallet::generate()?;

        // Сохраняем в файл
        let wallet_json = serde_json::json!({
            "private_key": hex::encode(&wallet.secret_key),
        });
        fs::create_dir_all(wallet_path.parent().unwrap())
            .map_err(|e| format!("Failed to create .accum directory: {}", e))?;
        fs::write(
            &wallet_path,
            serde_json::to_string_pretty(&wallet_json).unwrap(),
        )
        .map_err(|e| format!("Failed to save wallet: {}", e))?;

        // Сохраняем в базу
        let _ = storage.save_state("wallet", &wallet.secret_key.to_vec());

        println!("✅ New wallet created!");
        println!("📫 Address: {}", wallet.address);
        println!("🆔 Miner ID: {}", hex::encode(&wallet.miner_id));
        println!("📜 Private Key: {}", hex::encode(&wallet.secret_key));
        println!("⚠️  BACKUP YOUR WALLET FILE: ~/.accum/wallet.json");

        Ok(wallet)
    }
    fn load_state(&mut self) -> Result<(), String> {
        println!("📂 Loading blocks...");
        let total_blocks = self.height + 1;
        for h in 0..=self.height {
            if h % 10 == 0 || h == self.height {
                println!(
                    "   ⏳ Loading block {}/{} ({:.1}%)",
                    h,
                    self.height,
                    (h as f64 / self.height as f64) * 100.0
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
        let mut miner_count = 0;
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
        let mut bond_count = 0;
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
        let mut loyalty_count = 0;
        let mut iter = self
            .storage
            .db
            .iterator_cf(self.storage.cf_handle(CF_STATE), IteratorMode::Start);
        while let Some(Ok((key, value))) = iter.next() {
            if let Ok(key_str) = std::str::from_utf8(&key) {
                if key_str.starts_with("loyalty_") {
                    if let Ok(loyalty) = bincode::deserialize::<LoyaltyData>(&value) {
                        let miner_id_str = &key_str[8..];
                        if let Ok(miner_id_bytes) = hex::decode(miner_id_str) {
                            let mut miner_id = [0u8; 20];
                            miner_id.copy_from_slice(&miner_id_bytes);
                            self.loyalty.insert(miner_id, loyalty);
                            loyalty_count += 1;
                        }
                    }
                }
            }
        }
        println!("   ✅ Loyalty loaded: {}", loyalty_count);
        println!("📂 Loading emission...");
        self.total_emitted = self.storage.get_state::<u64>("total_emitted")?.unwrap_or(0);
        println!("   ✅ Total emitted: {} LYT", self.total_emitted);

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

        if let Some(last) = self.checkpoints.last() {
            println!(
                "📌 Loaded {} checkpoints, latest at height {}",
                self.checkpoints.len(),
                last.height
            );
        }
        Ok(())
    }

    fn init_genesis(&mut self) {
        let (header, coinbase) = create_genesis_block();
        let txid = coinbase.txid(&mut self.argon2);

        let mut header = header;
        header.merkle_root = txid;

        let outpoint = (txid, 0);
        let _ = self.storage.save_utxo(&outpoint, &coinbase.outputs[0]);

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
        self.timestamps.push(GENESIS_TIMESTAMP);

        let _ = self.storage.save_block(0, &block);
        let _ = self.storage.save_state("height", &0u64);
        let _ = self.storage.save_state("epoch", &1u32);

                // Genesis output = 500_000_000 LYT, считаем как стартовую эмиссию
                self.total_emitted = 500_000_000;
                let _ = self.storage.save_state("total_emitted", &self.total_emitted);

        println!("✅ Genesis block created");
        println!("   Hash: {}...", hex::encode(&hash[0..8]));
        if signature.is_some() {
            println!(
                "   Signature: {}...",
                hex::encode(&signature.unwrap()[0..8])
            );
        }
        println!("   Height: 0\n");
    }

    fn verify_genesis_signature(&self) -> bool {
        // ✅ ACCUM v3.2+ - Genesis block does not require signature
        // The genesis block is the root of trust by definition

        match self.storage.get_block(0) {
            Ok(Some(_block)) => {
                println!("✅ Genesis block verified (ACCUM v3.2+ spec)");
                println!("   No signature required - this is by design");
                true
            }
            Ok(None) => {
                println!("⚠️ Genesis block not found!");
                false
            }
            Err(e) => {
                println!("❌ Error reading genesis block: {}", e);
                false
            }
        }
    }

    fn last_block(&self) -> Option<&BlockHeader> {
        self.blocks.last()
    }

    pub fn last_hash(&mut self) -> Hash32 {
        if let Some(last) = self.last_block() {
            let header = last.clone();
            header.hash(&mut self.argon2)
        } else {
            [0; 32]
        }
    }

    fn last_difficulty(&self) -> Target {
        // Пересчёт на блоках 120, 240, 360, ...
        if self.height >= DIFFICULTY_ADJUSTMENT_INTERVAL
            && self.height % DIFFICULTY_ADJUSTMENT_INTERVAL == 0
        {
            let current_target = self
                .last_block()
                .map(|b| b.difficulty)
                .unwrap_or_else(Target::genesis);

            let start_idx = (self.height - DIFFICULTY_ADJUSTMENT_INTERVAL) as usize;
            let end_idx = self.height as usize;
            let recent_timestamps = &self.timestamps[start_idx..=end_idx];

            return adjust_difficulty(recent_timestamps, &current_target);
        }

        self.last_block()
            .map(|b| b.difficulty)
            .unwrap_or_else(Target::genesis)
    }

    pub fn sync_progress(&self) -> f64 {
        let best_peer = self
            .p2p
            .as_ref()
            .and_then(|p| p.best_peer_height())
            .unwrap_or(self.height);
        if best_peer == 0 {
            return 1.0;
        }
        self.height as f64 / best_peer as f64
    }

    pub fn median_timestamp(&self) -> Option<Timestamp> {
        if self.timestamps.len() < 11 {
            return None;
        }

        let mut last = self
            .timestamps
            .iter()
            .rev()
            .take(11)
            .cloned()
            .collect::<Vec<_>>();
        last.sort();
        Some(last[5])
    }
    
    pub fn checkpoint_at(&self, height: Height) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.height == height)
    }

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
        let _ = self.storage.save_bond(&miner_id, &bond);

        if let Some(miner) = self.miners.get_mut(&miner_id) {
            miner.bond = amount;
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
                let miner = self
                    .miners
                    .entry(miner_id)
                    .or_insert_with(|| MinerData::new(miner_id, bond_amount, current_epoch, now));

                miner.add_share(now);

                let loyalty = self
                    .loyalty
                    .entry(miner_id)
                    .or_insert_with(LoyaltyData::new);
                loyalty.update(current_epoch, true);

                self.shares_found += 1;

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
                }
                false
            }
        }
    }

    fn sort_mempool_by_fee(&mut self) {
        self.mempool.sort_by(|a, b| {
            let fee_a = a.fee(&self.storage).unwrap_or(0);
            let fee_b = b.fee(&self.storage).unwrap_or(0);
            fee_b.cmp(&fee_a)
        });
    }

    pub fn add_transaction_to_mempool(&mut self, tx: Transaction) -> Result<(), String> {
        // 1. Базовая валидация
        tx.validate_basic()
            .map_err(|e| format!("Invalid transaction: {}", e))?;

        // 2. Проверяем валидацию с UTXO
        tx.validate(&self.storage)
            .map_err(|e| format!("Transaction validation failed: {}", e))?;

        let txid = tx.txid(&mut self.argon2);

        // 3. Проверяем, не обработана ли уже эта транзакция
        if self.processed_txids.contains(&txid) {
            return Err("Transaction already processed".to_string());
        }

        // 4. Проверяем, нет ли уже такой транзакции в мемпуле
        for existing_tx in &self.mempool {
            if existing_tx.txid(&mut self.argon2) == txid {
                return Err("Transaction already in mempool".to_string());
            }
        }

        // 5. Проверяем, что входы не используются в других транзакциях мемпула
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

        // 6. Добавляем в мемпул
        self.mempool.push(tx);
        self.processed_txids.insert(txid);

        // 7. Сортируем по fee
        self.sort_mempool_by_fee();

        // 8. Ограничиваем размер мемпула
        while self.mempool.len() > self.config.advanced.max_mempool_size {
            if let Some(removed) = self.mempool.pop() {
                let removed_txid = removed.txid(&mut self.argon2);
                self.processed_txids.remove(&removed_txid);
            }
        }

        // 9. Сохраняем в базу
        let _ = self.storage.save_mempool(&self.mempool);

        println!(
            "✅ Transaction added to mempool: {}",
            hex::encode(&txid[0..8])
        );
        Ok(())
    }

    pub fn run_with_graceful_shutdown(&mut self) -> Result<(), String> {
        // ✅ Автоматически создаём bond для локального майнера, если его нет
        if !self.bonds.contains_key(&self.miner_id) {
            let bond_amount = self.config.mining.bond.max(MINIMUM_BOND_LYT);
            self.add_bond(self.miner_id, bond_amount);
            println!("💰 Auto-created bond: {} LYT", bond_amount);
        }

        println!("\n🚀 Node starting...");
        println!("   Height: {}", self.height);
        println!("   Epoch: {}", self.epoch);
        // ✅ Получаем количество пиров через Option
        let peer_count = self.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);
        println!("   Peers: {}", peer_count);

        let mining_enabled = self.config.mining.enabled;

        if mining_enabled {
            println!(
                "⛏️  Solo mining enabled with {} threads",
                self.config.mining.threads
            );
        }

        println!("\n🔄 Starting main loop...");

        let mut last_stats_time = current_timestamp();
        let mut last_sync_request_time = 0u64;

        loop {
            if should_shutdown() {
                println!("\n⏳ Shutting down...");

                if !is_saving_state() {
                    set_saving_state(true);
                    println!("💾 Saving state...");
                    let _ = self.storage.save_mempool(&self.mempool);
                    let _ = self.storage.flush();
                    println!("✅ State saved");
                }

                break;
            }

            // 1. Обработка входящих P2P сообщений
            if let Some(p2p) = self.p2p.as_mut() {
                if let Err(e) = p2p.process_messages() {
                    println!("⚠️ P2P error: {}", e);
                }
            }

            // 2. Приём новых соединений
            if let Some(p2p) = self.p2p.as_mut() {
                if let Err(e) = p2p.accept_connections() {
                    println!("⚠️ Accept error: {}", e);
                }
            }

            // 3. Проверка необходимости синхронизации (старт сессии)
            if let Some(p2p) = self.p2p.as_mut() {
                if p2p.needs_sync() {
                    if let Some(peer) = p2p.sync_manager.best_peer() {
                        p2p.sync_manager.start_sync(peer);
                    }
                }
            }

            // 4. Проверка таймаутов синхронизации
            if let Some(p2p) = self.p2p.as_mut() {
                if let Some(_peer_id) = p2p.sync_manager.check_timeouts() {
                    println!("⚠️ Sync timeout with peer");
                    // Сбрасываем сессию, чтобы выбрать нового пира
                    p2p.sync_manager.active_session = None;
                    p2p.sync_manager.sync_in_progress = false;
                }
            }

            // 5. Запрос блоков у пира
            if let Some(p2p) = self.p2p.as_mut() {
                let now = current_timestamp();

                // Запрашиваем блоки не чаще чем раз в 2 секунды
                if now - last_sync_request_time >= 2 {
                    // Забираем данные из сессии ДО mutable borrow
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
                                // ✅ ПРАВИЛЬНЫЙ ВЫЗОВ - без передачи p2p
                                match p2p
                                    .sync_manager
                                    .request_blocks_from_peer(&peer_id, from_height)
                                {
                                    Ok(_) => {
                                        last_sync_request_time = now;
                                        if let Some(session) =
                                            p2p.sync_manager.active_session.as_mut()
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
                                    println!(
                                        "✅ Sync completed at height {}",
                                        session.current_height
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // 7. Майнинг (только когда синхронизированы)
            let is_syncing = self.p2p.as_ref().map(|p| p.is_syncing()).unwrap_or(true);
            if mining_enabled && !is_syncing && self.sync_progress() >= 0.99 {
                self.mine_block();
            }

            // 8. Статистика
            let now = current_timestamp();
            if now - last_stats_time >= STATS_UPDATE_INTERVAL_MS / 1000 {
                let sync_progress = self.sync_progress();
                let sync_status = if sync_progress < 0.99 {
                    format!(" (syncing: {:.1}%)", sync_progress * 100.0)
                } else {
                    String::new()
                };

                // ✅ Получаем количество пиров через Option
                let peer_count = self.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);
                print!(
                    "\r📊 Height: {} | Epoch: {} | Peers: {} | Shares: {}{}",
                    self.height, self.epoch, peer_count, self.shares_found, sync_status
                );
                let _ = std::io::stdout().flush();

                last_stats_time = now;
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        Ok(())
    }

    fn mine_block(&mut self) {
        // Проверяем время с последнего блока
        if let Some(last) = self.last_block() {
            let now = current_timestamp();
            if now - last.timestamp < TARGET_BLOCK_TIME {
                return;
            }
        }

                // Сначала собираем не-coinbase транзакции из mempool,
        // проверяя fee каждой
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

        let prev_hash = self.last_hash();
        let difficulty = self.last_difficulty();
        let mut header = BlockHeader::new(prev_hash, self.epoch, difficulty);

        let mut hashes: Vec<Hash32> = txs.iter().map(|tx| tx.txid(&mut self.argon2)).collect();

        while hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let hash = Sha256::digest(&data);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                next.push(arr);
            }
            hashes = next;
        }

        header.merkle_root = if hashes.is_empty() {
            [0; 32]
        } else {
            hashes[0]
        };

        let target_share = difficulty.share_target();
        let target_prefilter = difficulty.prefilter_target();
        let mut best_nonce = 0u64;
        let mut best_hash = [0xff; 32];
        let mut found_block = false;

        // ✅ ОТЛАДКА
        println!(
            "⛏️  Mining block #{} with difficulty: {:.2}",
            self.height + 1,
            difficulty.to_difficulty()
        );
        println!("   🔍 Prefilter DISABLED - testing all nonces");
        println!(
            "   📊 Target[0] = {:02x}, Target[1] = {:02x}",
            difficulty.0[0], difficulty.0[1]
        );

        // Тестируем первые 10 nonce вручную
        for test_nonce in 0..10 {
            let test_hash = header.hash_with_nonce(test_nonce, &mut self.argon2);
            let meets = difficulty.is_met_by(&test_hash);
            println!(
                "   Nonce {}: hash[0]={:02x} {}",
                test_nonce,
                test_hash[0],
                if meets { "✅ MEETS!" } else { "" }
            );
        }

        let start_time = std::time::Instant::now();
        let mut last_progress = 0;

        for nonce in 0..MINING_BATCH_SIZE {
            // ✅ Показываем прогресс каждые 100к nonce
            if nonce % 100_000 == 0 && nonce > 0 {
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = nonce as f64 / elapsed;
                if nonce / 100_000 > last_progress {
                    last_progress = nonce / 100_000;
                    print!(
                        "\r   Nonce: {}/{} ({:.1}%) [{:.0} h/s]",
                        nonce,
                        MINING_BATCH_SIZE,
                        (nonce as f64 / MINING_BATCH_SIZE as f64) * 100.0,
                        rate
                    );
                    let _ = std::io::stdout().flush();
                }
            }

            // ✅ Prefilter проверка - ВКЛЮЧЕНА!
            if !Argon2Cache::prefilter(&header.to_bytes(), nonce, &target_prefilter) {
                continue;
            }

            let hash = header.hash_with_nonce(nonce, &mut self.argon2);

            // Проверка на блок
            if difficulty.is_met_by(&hash) {
                header.nonce = nonce;
                best_hash = hash;
                best_nonce = nonce;
                found_block = true;
                println!("\n✅ BLOCK FOUND! Nonce: {}", nonce);
                break;
            }

            // Сохраняем лучший share
            if target_share.is_met_by(&hash) && hash < best_hash {
                best_hash = hash;
                best_nonce = nonce;
            }
        }

        let elapsed = start_time.elapsed();
        if !found_block {
            println!("\n   Mining time: {:.2}s", elapsed.as_secs_f64());
            println!(
                "   Best nonce: {}, best hash: {}...",
                best_nonce,
                hex::encode(&best_hash[0..8])
            );
        }

        if found_block {
            // Нашли блок!
            header.nonce = best_nonce;

                        // ✅ ПРОВЕРЯЕМ ДУБЛИКАТЫ ТРАНЗАКЦИЙ В БЛОКЕ
                        let mut block_txids = HashSet::new();
                        for tx in &txs {
                            if tx.is_coinbase() {
                                continue;
                            }
                            let txid = tx.txid(&mut self.argon2);
                            if block_txids.contains(&txid) {
                                println!("⚠️ Duplicate transaction in block, skipping");
                                return;
                            }
                            block_txids.insert(txid);
                        }
            
                        // ✅ ПРОВЕРЯЕМ ДУБЛИ OUTPOINT (double-spend внутри блока)
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

            let share = Share::new(self.miner_id, header.clone(), best_nonce, best_hash);
            if self.add_share(share) {
                println!("📤 Share from block saved");
            }

            // 2. Потом обновляем состояние
            let new_height = self.height + 1;
            let _ = self.storage.save_block(new_height, &block);

            self.blocks.push(header.clone());
            self.block_hashes.insert(best_hash, new_height);
            self.timestamps.push(header.timestamp);
            self.height = new_height;
            self.blocks_found += 1;
            let coinbase_out: u64 = block.transactions[0]
            .outputs
            .iter()
            .map(|o| o.value)
            .sum();
            self.total_emitted = self.total_emitted.saturating_add(coinbase_out);
            let _ = self.storage.save_state("total_emitted", &self.total_emitted);

            self.update_utxo_set(&block);

            // ✅ ПОСЛЕ СОХРАНЕНИЯ БЛОКА - добавляем txid в processed
            for tx in &block.transactions {
                if !tx.is_coinbase() {
                    let txid = tx.txid(&mut self.argon2);
                    self.processed_txids.insert(txid);
                }
            }

            self.mempool.clear();
            let _ = self.storage.save_mempool(&self.mempool);

            if new_height % EPOCH_BLOCKS == 0 {
                self.process_epoch_end();
            }

            let _ = self.storage.save_state("height", &self.height);
            let _ = self.storage.save_state("epoch", &self.epoch);

            if self.height % self.config.advanced.checkpoint_interval == 0 {
                self.create_checkpoint();
            }

            let _ = self
                .storage
                .maybe_backup(self.height, self.config.advanced.backup_interval_blocks);

            // share уже сохранён выше (до обновления height)

            println!(
                "\n⛏️  BLOCK MINED! Height: {}, Hash: {}...",
                new_height,
                hex::encode(&best_hash[0..8])
            );

            if let Some(p2p) = &mut self.p2p {
                p2p.broadcast(&P2PMessage::Block {
                    header: header.clone(),
                    transactions: block.transactions.clone(),
                    signature: block.signature.clone(),
                    pubkey: block.pubkey.clone(),
                });
            }
            
        } else if best_hash != [0xff; 32] {
            // Сохраняем share (когда блок не найден)
            let share = Share::new(self.miner_id, header, best_nonce, best_hash);
            if self.add_share(share) {
                println!("📤 Share saved: {}...", hex::encode(&best_hash[0..8]));
            }
        } else {
            println!("⚠️ No valid share found in this batch");
        }
    }

    pub fn update_utxo_set(&mut self, block: &Block) {
        for tx in &block.transactions {
            for (i, output) in tx.outputs.iter().enumerate() {
                let txid = tx.txid(&mut self.argon2);
                let outpoint = (txid, i as u32);
                let _ = self.storage.save_utxo(&outpoint, output);
            }

            for input in &tx.inputs {
                if !input.is_coinbase() {
                    let _ = self.storage.delete_utxo(&input.outpoint());
                }
            }
        }
    }

    fn process_epoch_end(&mut self) {
        println!("\n📅 Processing epoch {} end...", self.epoch);

        // Сохраняем номер завершённой эпохи
        let completed_epoch = self.epoch;

        // Рассчитываем PoCI и награды
                // Рассчитываем PoCI и награды
                let mut poci_results = calculate_poci(&self.miners, &self.bonds, &self.loyalty, self.height);

                // Проверка MAX_SUPPLY: обрезаем награды, если эмиссия превысит лимит
                let total_requested: u128 = poci_results.iter().map(|r| r.reward as u128).sum();
                let available: u128 = if self.total_emitted >= MAX_SUPPLY_LYT {
                    0
                } else {
                    (MAX_SUPPLY_LYT - self.total_emitted) as u128
                };
        
                if total_requested > available {
                    println!(
                        "⚠️ Epoch reward {} LYT exceeds available supply {} LYT — trimming",
                        total_requested, available
                    );
        
                    if available == 0 {
                        for r in poci_results.iter_mut() {
                            r.reward = 0;
                        }
                    } else {
                        for r in poci_results.iter_mut() {
                            let trimmed = (r.reward as u128 * available) / total_requested;
                            r.reward = trimmed as u64;
                        }
                    }
                }
        
                let mut total_rewards = 0u64;
                let mut rewarded_miners = 0u32;
        
                for result in &poci_results {
            if result.reward == 0 {
                continue;
            }

            total_rewards = total_rewards.saturating_add(result.reward);
            rewarded_miners += 1;

            // ✅ Генерируем детерминированный txid через SHA-256
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"ACCUM-EPOCH-REWARD");
            hasher.update(&self.height.to_le_bytes());
            hasher.update(&completed_epoch.to_le_bytes());
            hasher.update(&result.miner_id);
            let txid: [u8; 32] = hasher.finalize().into();

            // Выплата награды
            if result.miner_id == self.miner_id {
                // Награда себе
                if let Some(wallet) = &self.wallet {
                    match TxOut::create_p2pkh(&wallet.address) {
                        Ok(mut txout) => {
                            txout.value = result.reward;
                            let outpoint = (txid, 0u32);

                            match self.storage.save_utxo(&outpoint, &txout) {
                                Ok(_) => {
                                    println!(
                                        "   💰 Reward to self: {} LYT (shares={}, poci={:.4})",
                                        result.reward, result.shares, result.poci
                                    );
                                }
                                Err(e) => {
                                    println!("   ❌ Failed to save reward UTXO: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            println!("   ❌ Failed to create reward output: {}", e);
                        }
                    }
                } else {
                    println!(
                        "   ⚠️ Local miner has no wallet; reward {} LYT was not created as UTXO",
                        result.reward
                    );
                }
            } else {
                // Награда другому майнеру
                if let Some(miner) = self.miners.get(&result.miner_id) {
                    if let Some(ref payout_addr) = miner.payout_address {
                        match TxOut::create_p2pkh(payout_addr) {
                            Ok(mut txout) => {
                                txout.value = result.reward;
                                let outpoint = (txid, 0u32);

                                match self.storage.save_utxo(&outpoint, &txout) {
                                    Ok(_) => {
                                        println!(
                                            "   💰 Reward to {}...: {} LYT",
                                            hex::encode(&result.miner_id[0..6]),
                                            result.reward
                                        );
                                    }
                                    Err(e) => {
                                        println!("   ❌ Failed to save reward UTXO: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("   ❌ Failed to create reward output: {}", e);
                            }
                        }
                    } else {
                        println!(
                            "   ⚠️ Miner {}... has no payout address, reward {} LYT lost",
                            hex::encode(&result.miner_id[0..6]),
                            result.reward
                        );
                    }
                } else {
                    println!(
                        "   ⚠️ Miner {}... not found in local state",
                        hex::encode(&result.miner_id[0..6])
                    );
                }
            }

            // Обновляем статистику майнера
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

        println!("   Total epoch rewards: {} LYT", total_rewards);
        println!("   Rewarded miners: {}", rewarded_miners);

        // ========================================
        // ЗАВЕРШАЕМ ЭПОХУ
        // ========================================

        self.share_pool.new_epoch();

        // ⚠️ ВАЖНО: увеличиваем эпоху ПОСЛЕ использования completed_epoch
        self.epoch = self.epoch.saturating_add(1);

        // ========================================
        // ОБНОВЛЯЕМ LOYALTY
        // ========================================

        let miners_to_update: Vec<MinerId> = self.miners.keys().copied().collect();

        for miner_id in miners_to_update {
            let participated = poci_results
                .iter()
                .any(|r| r.miner_id == miner_id && r.shares > 0);

            let loyalty = self
                .loyalty
                .entry(miner_id)
                .or_insert_with(LoyaltyData::new);

            // ✅ Используем completed_epoch, а не новую эпоху
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

        // ========================================
        // ОБНУЛЯЕМ SHARES
        // ========================================

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

        // ========================================
        // СОХРАНЯЕМ НОВУЮ ЭПОХУ
        // ========================================
                         // Учёт эмиссии эпохи (после обрезания выше — гарантированно ≤ MAX_SUPPLY)
                         self.total_emitted = self.total_emitted.saturating_add(total_rewards);
                         let _ = self.storage.save_state("total_emitted", &self.total_emitted);                       
        if let Err(e) = self.storage.save_state("epoch", &self.epoch) {
            println!("   ⚠️ Failed to save epoch: {}", e);
        }

        println!("✅ Epoch {} completed", completed_epoch);
        println!("🚀 Epoch {} started", self.epoch);
    }

    fn create_checkpoint(&mut self) {
        let last_block = match self.last_block() {
            Some(block) => block.clone(),
            None => return,
        };

        let block_hash = last_block.hash(&mut self.argon2);
        let state_root = self.calculate_state_root();

        let (signature, _pubkey) = if let Some(wallet) = &self.wallet {
            let message = {
                let mut data = Vec::new();
                data.extend_from_slice(&self.height.to_le_bytes());
                data.extend_from_slice(&block_hash);
                data.extend_from_slice(&state_root);
                Sha256::digest(&data)
            };
            (
                wallet.sign(&message.into()).ok(),
                Some(wallet.public_key.clone()),
            )
        } else {
            (None, None)
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
        let _ = self.storage.save_checkpoint(self.height, &checkpoint);

        if self.checkpoints.len() > self.config.advanced.max_checkpoints {
            self.checkpoints.remove(0);
        }

        println!("📌 Checkpoint created at height {}", self.height);
    }

    fn calculate_state_root(&self) -> Hash32 {
        let mut data = Vec::new();

        for (id, miner) in &self.miners {
            data.extend_from_slice(id);
            data.extend_from_slice(&miner.shares.to_le_bytes());
            data.extend_from_slice(&miner.bond.to_le_bytes());
        }

        for (id, bond) in &self.bonds {
            data.extend_from_slice(id);
            data.extend_from_slice(&bond.amount.to_le_bytes());
            data.extend_from_slice(&bond.lock_until.to_le_bytes());
        }

        let hash = Sha256::digest(&data);
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }
}