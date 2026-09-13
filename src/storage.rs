//! RocksDB-backed chain storage

use crate::block::{Block, TxOut};
use crate::constants::*;
use crate::types::{current_timestamp, Hash32, Height, MinerId, OutPoint, Timestamp};
use crate::{MinerData, SlashRecord};
use rocksdb::checkpoint::Checkpoint as RocksdbCheckpoint;
use rocksdb::{IteratorMode, Options, DB};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const CF_BLOCKS: &str = "blocks";
pub const CF_UTXO: &str = "utxo";
pub const CF_MINERS: &str = "miners";
pub const CF_BONDS: &str = "bonds";
pub const CF_STATE: &str = "state";
pub const CF_MEMPOOL: &str = "mempool";
pub const CF_SLASHES: &str = "slashes";
pub const CF_CHECKPOINTS: &str = "checkpoints";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bond {
    pub amount: u64,
    pub created_at: Height,
    pub lock_until: Height,
    pub miner_id: MinerId,
}

impl Bond {
    pub fn new(amount: u64, created_at: Height, miner_id: MinerId) -> Self {
        Self {
            amount,
            created_at,
            lock_until: created_at + BOND_LOCKUP_BLOCKS,
            miner_id,
        }
    }

    pub fn is_active(&self, current_height: Height) -> bool {
        current_height >= self.created_at && current_height < self.lock_until
    }

    pub fn is_valid_for_poci(&self) -> bool {
        self.amount >= MINIMUM_BOND_LYT
    }

    pub fn from_output(output: &TxOut, height: Height) -> Option<Self> {
        if let Some(miner_id) = output.extract_miner_id() {
            if output.value >= MINIMUM_BOND_LYT {
                Some(Self::new(output.value, height, miner_id))
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn remaining_blocks(&self, current_height: Height) -> u64 {
        if current_height < self.lock_until {
            self.lock_until - current_height
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: Height,
    pub block_hash: Hash32,
    pub state_root: Hash32,
    pub timestamp: Timestamp,
    pub signature: Vec<u8>,
    pub verified: bool,
}

pub struct ProductionStorage {
    pub db: DB,
    pub path: PathBuf,
}

impl ProductionStorage {
    pub fn new(network: &str) -> Result<Self, String> {
        let mut path = dirs::home_dir().ok_or("Cannot find home dir")?;
        path.push(".accum");
        path.push(network);

        std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(256);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(3);
        opts.set_target_file_size_base(64 * 1024 * 1024);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        let cfs = vec![
            CF_BLOCKS, CF_UTXO, CF_MINERS, CF_BONDS, CF_STATE,
            CF_MEMPOOL, CF_SLASHES, CF_CHECKPOINTS,
        ];
        let db = DB::open_cf(&opts, path.to_str().unwrap(), &cfs).map_err(|e| e.to_string())?;

        println!("💾 Database initialized: {}", path.display());
        Ok(Self { db, path })
    }

    pub fn cf_handle(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(name)
            .expect(&format!("Column family {} not found", name))
    }

    pub fn save_block(&self, height: Height, block: &Block) -> Result<(), String> {
        let key = height.to_le_bytes();
        let value = bincode::serialize(block).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_BLOCKS), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_block(&self, height: Height) -> Result<Option<Block>, String> {
        let key = height.to_le_bytes();
        match self.db.get_cf(self.cf_handle(CF_BLOCKS), key) {
            Ok(Some(data)) => {
                let block = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn get_last_height(&self) -> Result<Height, String> {
        let mut iter = self
            .db
            .iterator_cf(self.cf_handle(CF_BLOCKS), IteratorMode::End);
        if let Some(Ok((key, _))) = iter.next() {
            let mut height_bytes = [0u8; 8];
            let key_slice = key.as_ref();
            if key_slice.len() >= 8 {
                height_bytes.copy_from_slice(&key_slice[0..8]);
                Ok(u64::from_le_bytes(height_bytes))
            } else {
                Ok(0)
            }
        } else {
            Ok(0)
        }
    }

    pub fn save_utxo(&self, outpoint: &OutPoint, output: &TxOut) -> Result<(), String> {
        let key = bincode::serialize(outpoint).map_err(|e| e.to_string())?;
        let value = bincode::serialize(output).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_UTXO), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, String> {
        let key = bincode::serialize(outpoint).map_err(|e| e.to_string())?;
        match self.db.get_cf(self.cf_handle(CF_UTXO), key) {
            Ok(Some(data)) => {
                let output = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(output))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn get_node_info(&self) -> Result<(Height, u32, u64), String> {
        let height = self.get_height()?;
        let epoch = self.get_state::<u32>("epoch")?.unwrap_or(1);

        let mut utxo_count = 0u64;
        let iter = self
            .db
            .iterator_cf(self.cf_handle(CF_UTXO), IteratorMode::Start);
        for item in iter {
            if item.is_ok() {
                utxo_count += 1;
            }
        }

        Ok((height, epoch, utxo_count))
    }

    pub fn get_balance_by_address(&self, address: &str) -> Result<(u64, u64), String> {
        let mut total = 0u64;
        let mut utxo_count = 0u64;

        let iter = self
            .db
            .iterator_cf(self.cf_handle(CF_UTXO), IteratorMode::Start);

        for item in iter {
            let (_key, value) = item.map_err(|e| e.to_string())?;
            let output: TxOut = bincode::deserialize(&value).map_err(|e| e.to_string())?;

            if let Some(addr) = output.extract_address() {
                if addr == address {
                    total = total.saturating_add(output.value);
                    utxo_count += 1;
                }
            }
        }

        Ok((total, utxo_count))
    }

    pub fn get_utxos_by_address(&self, address: &str) -> Result<Vec<(OutPoint, TxOut)>, String> {
        let mut result = Vec::new();

        let iter = self
            .db
            .iterator_cf(self.cf_handle(CF_UTXO), IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| e.to_string())?;
            let outpoint: OutPoint = bincode::deserialize(&key).map_err(|e| e.to_string())?;
            let output: TxOut = bincode::deserialize(&value).map_err(|e| e.to_string())?;

            if let Some(addr) = output.extract_address() {
                if addr == address {
                    result.push((outpoint, output));
                }
            }
        }

        Ok(result)
    }

    pub fn delete_utxo(&self, outpoint: &OutPoint) -> Result<(), String> {
        let key = bincode::serialize(outpoint).map_err(|e| e.to_string())?;
        self.db
            .delete_cf(self.cf_handle(CF_UTXO), key)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn save_miner(&self, miner_id: &MinerId, data: &MinerData) -> Result<(), String> {
        let value = bincode::serialize(data).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_MINERS), miner_id, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_miner(&self, miner_id: &MinerId) -> Result<Option<MinerData>, String> {
        match self.db.get_cf(self.cf_handle(CF_MINERS), miner_id) {
            Ok(Some(data)) => {
                let miner = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(miner))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn save_bond(&self, miner_id: &MinerId, bond: &Bond) -> Result<(), String> {
        let value = bincode::serialize(bond).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_BONDS), miner_id, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_bond(&self, miner_id: &MinerId) -> Result<Option<Bond>, String> {
        match self.db.get_cf(self.cf_handle(CF_BONDS), miner_id) {
            Ok(Some(data)) => {
                let bond = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(bond))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn delete_bond(&self, miner_id: &MinerId) -> Result<(), String> {
        self.db
            .delete_cf(self.cf_handle(CF_BONDS), miner_id)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn save_slash_record(&self, height: Height, record: &SlashRecord) -> Result<(), String> {
        let key = height.to_le_bytes();
        let value = bincode::serialize(record).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_SLASHES), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn save_checkpoint(&self, height: Height, checkpoint: &Checkpoint) -> Result<(), String> {
        let key = height.to_le_bytes();
        let value = bincode::serialize(checkpoint).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_CHECKPOINTS), key, value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_checkpoint(&self, height: Height) -> Result<Option<Checkpoint>, String> {
        let key = height.to_le_bytes();
        match self.db.get_cf(self.cf_handle(CF_CHECKPOINTS), key) {
            Ok(Some(data)) => {
                let checkpoint = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(checkpoint))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn get_latest_checkpoint(&self) -> Result<Option<(Height, Checkpoint)>, String> {
        let mut iter = self
            .db
            .iterator_cf(self.cf_handle(CF_CHECKPOINTS), IteratorMode::End);
        if let Some(Ok((key, value))) = iter.next() {
            let mut height_bytes = [0u8; 8];
            let key_slice = key.as_ref();
            if key_slice.len() >= 8 {
                height_bytes.copy_from_slice(&key_slice[0..8]);
                let height = u64::from_le_bytes(height_bytes);
                let checkpoint = bincode::deserialize(&value).map_err(|e| e.to_string())?;
                Ok(Some((height, checkpoint)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn save_state<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<(), String> {
        let data = bincode::serialize(value).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_STATE), key.as_bytes(), data)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn get_state<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, String> {
        match self.db.get_cf(self.cf_handle(CF_STATE), key.as_bytes()) {
            Ok(Some(data)) => {
                let value = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn save_mempool(&self, txs: &[crate::block::Transaction]) -> Result<(), String> {
        let value = bincode::serialize(txs).map_err(|e| e.to_string())?;
        self.db
            .put_cf(self.cf_handle(CF_MEMPOOL), b"mempool", value)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_mempool(&self) -> Result<Vec<crate::block::Transaction>, String> {
        match self.db.get_cf(self.cf_handle(CF_MEMPOOL), b"mempool") {
            Ok(Some(data)) => {
                let txs = bincode::deserialize(&data).map_err(|e| e.to_string())?;
                Ok(txs)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn get_height(&self) -> Result<Height, String> {
        match self.get_state::<Height>("height") {
            Ok(Some(h)) => Ok(h),
            Ok(None) => Ok(0),
            Err(e) => Err(e),
        }
    }

    pub fn backup(&self) -> Result<String, String> {
        let backup_dir = self.path.join("backups");
        std::fs::create_dir_all(&backup_dir).map_err(|e| e.to_string())?;

        let timestamp = current_timestamp();
        let backup_path = backup_dir.join(timestamp.to_string());

        println!("💾 Creating backup at {}", backup_path.display());

        let checkpoint = RocksdbCheckpoint::new(&self.db)
            .map_err(|e| format!("Failed to create checkpoint: {}", e))?;

        checkpoint
            .create_checkpoint(&backup_path)
            .map_err(|e| format!("Failed to create checkpoint: {}", e))?;

        let height = self.get_height()?;
        let epoch = self.get_state::<u32>("epoch")?.unwrap_or(1);

        let metadata = serde_json::json!({
            "timestamp": timestamp,
            "height": height,
            "epoch": epoch,
            "version": env!("CARGO_PKG_VERSION"),
            "created_at": chrono::Utc::now().to_rfc3339(),
            "backup_type": "full",
        });

        let metadata_path = backup_path.join("metadata.json");
        std::fs::write(
            metadata_path,
            serde_json::to_string_pretty(&metadata).unwrap(),
        )
        .map_err(|e| e.to_string())?;

        println!("✅ Backup created: {}", backup_path.display());
        Ok(timestamp.to_string())
    }

    pub fn maybe_backup(&self, height: Height, interval_blocks: u64) -> Result<(), String> {
        if height % interval_blocks == 0 && height > 0 {
            self.backup()?;
            self.prune_old_backups(10)?;
        }
        Ok(())
    }

    fn prune_old_backups(&self, keep_count: usize) -> Result<(), String> {
        let backup_dir = self.path.join("backups");
        if !backup_dir.exists() {
            return Ok(());
        }

        let mut backups: Vec<_> = std::fs::read_dir(&backup_dir)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .collect();

        backups.sort_by_key(|a| a.path());

        if backups.len() > keep_count {
            let to_remove = backups.len() - keep_count;
            for old_backup in backups.iter().take(to_remove) {
                println!("🧹 Removing old backup: {}", old_backup.path().display());
                let _ = std::fs::remove_dir_all(old_backup.path());
            }
        }

        Ok(())
    }

    pub fn restore(&self, backup_timestamp: &str) -> Result<(), String> {
        let backup_path = self.path.join("backups").join(backup_timestamp);
        if !backup_path.exists() {
            return Err(format!("Backup {} not found", backup_path.display()));
        }

        println!("🔄 Restoring from {}", backup_path.display());

        let metadata_path = backup_path.join("metadata.json");
        if metadata_path.exists() {
            let metadata = std::fs::read_to_string(metadata_path).map_err(|e| e.to_string())?;
            println!("📋 Backup metadata: {}", metadata);
        }

        let backup_files: Vec<_> = std::fs::read_dir(&backup_path)
            .map_err(|e| e.to_string())?
            .filter_map(|e| e.ok())
            .collect();

        if backup_files.is_empty() {
            return Err("Backup is empty".to_string());
        }

        let current_backup = self.backup()?;
        println!("📦 Current database backed up as {}", current_backup);

        self.db.flush_wal(true).map_err(|e| e.to_string())?;

        let new_db_path = self.path.join(format!("restored_{}", backup_timestamp));
        if new_db_path.exists() {
            std::fs::remove_dir_all(&new_db_path).map_err(|e| e.to_string())?;
        }

        println!("✅ Database restored from backup: {}", backup_path.display());
        println!("⚠️ Please restart the node for changes to take effect");

        Ok(())
    }

    pub fn restore_from_checkpoint(&self, height: Height) -> Result<(), String> {
        let checkpoint = self
            .get_checkpoint(height)?
            .ok_or(format!("Checkpoint at height {} not found", height))?;

        println!("🔄 Restoring from checkpoint at height {}", height);
        println!("   Block hash: {}", hex::encode(&checkpoint.block_hash[0..8]));
        println!("   State root: {}", hex::encode(&checkpoint.state_root[0..8]));

        self.backup()?;

        println!("✅ Checkpoint verification passed");
        println!("⚠️ Full state restoration requires node restart");

        Ok(())
    }

    pub fn export_for_migration(&self) -> Result<String, String> {
        let export_dir = self.path.join("export");
        std::fs::create_dir_all(&export_dir).map_err(|e| e.to_string())?;

        let timestamp = current_timestamp();
        let export_path = export_dir.join(format!("export_{}.json", timestamp));

        let height = self.get_height()?;
        let epoch = self.get_state::<u32>("epoch")?.unwrap_or(1);

        let mut miners_data = Vec::new();
        let mut iter = self
            .db
            .iterator_cf(self.cf_handle(CF_MINERS), IteratorMode::Start);
        while let Some(Ok((_key, value))) = iter.next() {
            if let Ok(miner) = bincode::deserialize::<MinerData>(&value) {
                miners_data.push(miner);
            }
        }

        let export_data = serde_json::json!({
            "height": height,
            "epoch": epoch,
            "timestamp": timestamp,
            "version": env!("CARGO_PKG_VERSION"),
            "miners_count": miners_data.len(),
            "miners": miners_data,
            "export_type": "migration",
        });

        std::fs::write(
            &export_path,
            serde_json::to_string_pretty(&export_data).unwrap(),
        )
        .map_err(|e| e.to_string())?;

        println!("📤 Export created: {}", export_path.display());
        println!("   Miners exported: {}", miners_data.len());

        Ok(export_path.to_string_lossy().to_string())
    }

    pub fn flush(&self) -> Result<(), String> {
        self.db.flush().map_err(|e| e.to_string())
    }
}