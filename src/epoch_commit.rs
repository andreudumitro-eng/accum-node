//! Epoch commit — канонический снимок состояния эпохи.
//!
//! Коммит покрывает ВСЕ три входа PoCI:
//!   - shares  (вес 0.6)
//!   - loyalty (вес 0.2)
//!   - bonds   (вес 0.2)
//! Это делает возможной полную независимую проверку наград
//! любым узлом после завершения эпохи.

use crate::miner::LoyaltyData;
use crate::storage::Bond;
use crate::types::{Hash32, Height, MinerId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Канонический коммит эпохи. Кладётся в блок на границе эпохи.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochCommit {
    pub epoch: u32,
    pub block_height: Height,
    pub shares_merkle_root: Hash32,
    pub bonds_merkle_root: Hash32,
    pub loyalty_merkle_root: Hash32,
    pub total_shares: u64,
    pub miners_count: u32,
    pub previous_commit_hash: Hash32, // [0;32] для первой эпохи
}

impl EpochCommit {
    /// Стабильный хеш коммита. НЕ через bincode — только явные поля
    /// с префиксом версии.
    pub fn hash(&self) -> Hash32 {
        let mut h = Sha256::new();
        h.update(b"ACCUM-EPOCH-COMMIT-v1");
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.block_height.to_le_bytes());
        h.update(&self.shares_merkle_root);
        h.update(&self.bonds_merkle_root);
        h.update(&self.loyalty_merkle_root);
        h.update(&self.total_shares.to_le_bytes());
        h.update(&self.miners_count.to_le_bytes());
        h.update(&self.previous_commit_hash);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// Собрать коммит из текущего состояния узла.
    pub fn build(
        epoch: u32,
        block_height: Height,
        previous_commit_hash: Hash32,
        share_count: &HashMap<MinerId, u64>,
        bonds: &HashMap<MinerId, Bond>,
        loyalty: &HashMap<MinerId, LoyaltyData>,
    ) -> Self {
        let share_entries = collect_sorted_share_entries(share_count);
        let bond_entries = collect_sorted_bond_entries(bonds);
        let loyalty_entries = collect_sorted_loyalty_entries(loyalty);

        let shares_merkle_root = compute_shares_merkle_root(&share_entries);
        let bonds_merkle_root = compute_bonds_merkle_root(&bond_entries);
        let loyalty_merkle_root = compute_loyalty_merkle_root(&loyalty_entries);

        let total_shares: u64 = share_entries.iter().map(|e| e.shares).sum();
        let miners_count: u32 = share_entries.len() as u32;

        Self {
            epoch,
            block_height,
            shares_merkle_root,
            bonds_merkle_root,
            loyalty_merkle_root,
            total_shares,
            miners_count,
            previous_commit_hash,
        }
    }
}

/// Запись майнера по шарам.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerShareEntry {
    pub miner_id: MinerId,
    pub shares: u64,
}

/// Запись майнера по bond.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerBondEntry {
    pub miner_id: MinerId,
    pub amount: u64,
    pub created_at: u64,
    pub lock_until: u64,
}

/// Запись майнера по loyalty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerLoyaltyEntry {
    pub miner_id: MinerId,
    pub value: u64,
}

// ============================================================
// Merkle-хелперы
// ============================================================

/// Универсальный merkle-root по списку листьев.
pub fn merkle_root_from_leaves(mut leaves: Vec<Hash32>) -> Hash32 {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for chunk in leaves.chunks(2) {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&chunk[0]);
            if chunk.len() > 1 {
                data.extend_from_slice(&chunk[1]);
            } else {
                data.extend_from_slice(&chunk[0]);
            }
            let d = Sha256::digest(&data);
            let mut h = [0u8; 32];
            h.copy_from_slice(&d);
            next.push(h);
        }
        leaves = next;
    }
    leaves[0]
}

/// Merkle root по шарам: лист = SHA256(miner_id || shares_le).
pub fn compute_shares_merkle_root(entries: &[MinerShareEntry]) -> Hash32 {
    let leaves: Vec<Hash32> = entries
        .iter()
        .map(|e| {
            let mut data = Vec::with_capacity(28);
            data.extend_from_slice(&e.miner_id);
            data.extend_from_slice(&e.shares.to_le_bytes());
            let d = Sha256::digest(&data);
            let mut h = [0u8; 32];
            h.copy_from_slice(&d);
            h
        })
        .collect();
    merkle_root_from_leaves(leaves)
}

/// Merkle root по bonds.
/// Лист = SHA256(miner_id || amount_le || created_at_le || lock_until_le).
pub fn compute_bonds_merkle_root(entries: &[MinerBondEntry]) -> Hash32 {
    let leaves: Vec<Hash32> = entries
        .iter()
        .map(|e| {
            let mut data = Vec::with_capacity(44);
            data.extend_from_slice(&e.miner_id);
            data.extend_from_slice(&e.amount.to_le_bytes());
            data.extend_from_slice(&e.created_at.to_le_bytes());
            data.extend_from_slice(&e.lock_until.to_le_bytes());
            let d = Sha256::digest(&data);
            let mut h = [0u8; 32];
            h.copy_from_slice(&d);
            h
        })
        .collect();
    merkle_root_from_leaves(leaves)
}

/// Merkle root по loyalty: лист = SHA256(miner_id || value_le).
pub fn compute_loyalty_merkle_root(entries: &[MinerLoyaltyEntry]) -> Hash32 {
    let leaves: Vec<Hash32> = entries
        .iter()
        .map(|e| {
            let mut data = Vec::with_capacity(28);
            data.extend_from_slice(&e.miner_id);
            data.extend_from_slice(&e.value.to_le_bytes());
            let d = Sha256::digest(&data);
            let mut h = [0u8; 32];
            h.copy_from_slice(&d);
            h
        })
        .collect();
    merkle_root_from_leaves(leaves)
}

// ============================================================
// Сборщики с гарантированной сортировкой
// ============================================================

pub fn collect_sorted_share_entries(share_count: &HashMap<MinerId, u64>) -> Vec<MinerShareEntry> {
    let mut v: Vec<MinerShareEntry> = share_count
        .iter()
        .map(|(id, count)| MinerShareEntry {
            miner_id: *id,
            shares: *count,
        })
        .collect();
    v.sort_by_key(|e| e.miner_id);
    v
}

pub fn collect_sorted_bond_entries(bonds: &HashMap<MinerId, Bond>) -> Vec<MinerBondEntry> {
    let mut v: Vec<MinerBondEntry> = bonds
        .iter()
        .map(|(id, b)| MinerBondEntry {
            miner_id: *id,
            amount: b.amount,
            created_at: b.created_at,
            lock_until: b.lock_until,
        })
        .collect();
    v.sort_by_key(|e| e.miner_id);
    v
}

pub fn collect_sorted_loyalty_entries(
    loyalty: &HashMap<MinerId, LoyaltyData>,
) -> Vec<MinerLoyaltyEntry> {
    let mut v: Vec<MinerLoyaltyEntry> = loyalty
        .iter()
        .map(|(id, l)| MinerLoyaltyEntry {
            miner_id: *id,
            value: l.value,
        })
        .collect();
    v.sort_by_key(|e| e.miner_id);
    v
}
