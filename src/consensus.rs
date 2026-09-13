//! Consensus: PoCI calculation, slashing, equivocation

use crate::block::Block;
use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::miner::{LoyaltyData, MinerData};
use crate::storage::{Bond, ProductionStorage};
use crate::types::{current_timestamp, Hash32, Height, MinerId, Timestamp};
use crate::wallet::Wallet;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashRecord {
    pub miner_id: MinerId,
    pub amount: u64,
    pub height: Height,
    pub timestamp: Timestamp,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProof {
    pub miner_id: MinerId,
    pub block_height: Height,
    pub block_hash_1: Hash32,
    pub block_hash_2: Hash32,
    pub signature_1: Vec<u8>,
    pub signature_2: Vec<u8>,
    pub timestamp: Timestamp,
    pub proven: bool,
}

impl EquivocationProof {
    pub fn block_height_2(&self) -> Height {
        self.block_height
    }

    pub fn verify(
        &self,
        storage: &ProductionStorage,
        argon2: &mut Argon2Cache,
    ) -> Result<bool, String> {
        let block1_height = self.block_height;
        let block2_height = self.block_height;

        let block1 = storage.get_block(block1_height)?.ok_or("Block 1 not found")?;
        let block2 = storage.get_block(block2_height)?.ok_or("Block 2 not found")?;

        if block1.header.hash(argon2) == block2.header.hash(argon2) {
            return Ok(false);
        }

        let hash1 = block1.header.hash(argon2);
        let hash2 = block2.header.hash(argon2);

        let sig1_ok = if let (Some(sig), Some(pubkey)) = (&block1.signature, &block1.pubkey) {
            Wallet::verify_signature(pubkey, sig, &hash1)
        } else {
            false
        };

        let sig2_ok = if let (Some(sig), Some(pubkey)) = (&block2.signature, &block2.pubkey) {
            Wallet::verify_signature(pubkey, sig, &hash2)
        } else {
            false
        };

        if !sig1_ok || !sig2_ok {
            return Ok(false);
        }

        let miner_id_from_block1 = Self::extract_miner_id_from_block(&block1)?;
        let miner_id_from_block2 = Self::extract_miner_id_from_block(&block2)?;

        if miner_id_from_block1 != miner_id_from_block2 {
            return Ok(false);
        }

        if miner_id_from_block1 != self.miner_id {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn extract_miner_id_from_block(block: &Block) -> Result<MinerId, String> {
        if let Some(coinbase) = block.transactions.first() {
            if coinbase.is_coinbase() {
                for output in &coinbase.outputs {
                    if let Some(miner_id) = output.extract_miner_id() {
                        return Ok(miner_id);
                    }
                }
            }
        }

        if let Some(pubkey) = &block.pubkey {
            if let Ok(pk) = PublicKey::from_slice(pubkey) {
                return Ok(Wallet::miner_id_from_pubkey(&pk));
            }
        }

        Err("Cannot extract miner_id from block".to_string())
    }

    pub fn execute_slash(
        &self,
        storage: &ProductionStorage,
        height: Height,
    ) -> Result<SlashRecord, String> {
        let bond = storage
            .get_bond(&self.miner_id)?
            .ok_or("No bond found for miner")?;

        let amount = bond.amount;

        storage.delete_bond(&self.miner_id)?;

        let slash_record = SlashRecord {
            miner_id: self.miner_id,
            amount,
            height,
            timestamp: current_timestamp(),
            proof: bincode::serialize(self).map_err(|e| e.to_string())?,
        };

        storage.save_slash_record(height, &slash_record)?;

        println!(
            "🔥 SLASHED: Miner {}... lost {} LYT for equivocation",
            hex::encode(&self.miner_id[0..8]),
            amount
        );

        Ok(slash_record)
    }

    pub fn from_blocks(block1: &Block, block2: &Block, height: Height) -> Result<Self, String> {
        let miner_id = Self::extract_miner_id_from_block(block1)?;

        let mut argon2 = Argon2Cache::new(100);
        let hash1 = block1.header.hash(&mut argon2);
        let hash2 = block2.header.hash(&mut argon2);

        Ok(Self {
            miner_id,
            block_height: height,
            block_hash_1: hash1,
            block_hash_2: hash2,
            signature_1: block1.signature.clone().unwrap_or_default(),
            signature_2: block2.signature.clone().unwrap_or_default(),
            timestamp: current_timestamp(),
            proven: false,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SlashingPool {
    pub pending_slashes: Vec<EquivocationProof>,
    pub processed_slashes: HashSet<MinerId>,
    pub slash_height: Height,
}

impl SlashingPool {
    pub fn new() -> Self {
        Self {
            pending_slashes: Vec::new(),
            processed_slashes: HashSet::new(),
            slash_height: 0,
        }
    }

    pub fn add_proof(&mut self, proof: EquivocationProof) {
        if !self.processed_slashes.contains(&proof.miner_id) {
            self.pending_slashes.push(proof);
        }
    }

    pub fn process_all(
        &mut self,
        storage: &ProductionStorage,
        argon2: &mut Argon2Cache,
        current_height: Height,
    ) -> Result<Vec<SlashRecord>, String> {
        let mut results = Vec::new();

        for proof in &self.pending_slashes {
            if self.processed_slashes.contains(&proof.miner_id) {
                continue;
            }

            if proof.verify(storage, argon2)? {
                let record = proof.execute_slash(storage, current_height)?;
                self.processed_slashes.insert(proof.miner_id);
                results.push(record);
            }
        }

        self.pending_slashes.clear();
        self.slash_height = current_height;

        Ok(results)
    }

    pub fn is_slashed(&self, miner_id: &MinerId) -> bool {
        self.processed_slashes.contains(miner_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCIResult {
    pub miner_id: MinerId,
    pub poci: u64,
    pub shares: u64,
    pub loyalty: u64,
    pub bond: u64,
    pub reward: u64,
}

pub fn calculate_poci(
    miners: &HashMap<MinerId, MinerData>,
    bonds: &HashMap<MinerId, Bond>,
    loyalty: &HashMap<MinerId, LoyaltyData>,
    current_height: Height,
) -> Vec<PoCIResult> {
    if miners.is_empty() {
        return Vec::new();
    }

    fn isqrt(n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let mut x = n;
        let mut y = (x + 1) / 2;
        while y < x {
            x = y;
            y = (x + n / x) / 2;
        }
        x
    }

    // ---- shares ----
    let shares_sqrt: Vec<u64> = miners.values().map(|m| isqrt(m.shares)).collect();
    let max_shares_sqrt = shares_sqrt.iter().copied().max().unwrap_or(0).max(1);

    // ---- loyalty (пока f64, фиксируем *1000) ----
    let loyalty_values: Vec<u64> = miners
        .values()
        .map(|m| {
            loyalty
                .get(&m.miner_id)
                .map(|l| l.value)
                .unwrap_or(0)
        })
        .collect();
    let max_loyalty = loyalty_values.iter().copied().max().unwrap_or(0).max(1);

    // ---- bond (только валидные для PoCI) ----
    // ВАЖНО: источник истины — bonds.get(&miner_id).amount,
    // а не MinerData.bond, чтобы не было рассинхрона.
    let bond_sqrt: Vec<u64> = miners
        .values()
        .filter_map(|m| {
            bonds.get(&m.miner_id).and_then(|b| {
                if b.is_active(current_height) && b.amount >= MINIMUM_BOND_LYT {
                    Some(isqrt(b.amount))
                } else {
                    None
                }
            })
        })
        .collect();
    let max_bond_sqrt = bond_sqrt.iter().copied().max().unwrap_or(0).max(1);

    let mut results: Vec<PoCIResult> = Vec::new();
    let mut total_poci: u128 = 0;

    for (miner_id, data) in miners {
        // bond берём из bonds, а не из MinerData.bond
        let bond_amount = bonds
            .get(miner_id)
            .map(|b| b.amount)
            .unwrap_or(0);

        let is_bond_valid = bonds
            .get(miner_id)
            .map(|b| b.is_active(current_height) && b.amount >= MINIMUM_BOND_LYT)
            .unwrap_or(false);

        let share_norm: u64 = if data.shares > 0 {
            ((isqrt(data.shares) as u128 * POCI_SCALE as u128) / max_shares_sqrt as u128) as u64
        } else {
            0
        };

        let loyalty_val_u: u64 = loyalty
            .get(miner_id)
            .map(|l| l.value)
            .unwrap_or(0);

        let loyalty_norm: u64 =
            ((loyalty_val_u as u128 * POCI_SCALE as u128) / max_loyalty as u128) as u64;

        let bond_norm: u64 = if is_bond_valid {
            ((isqrt(bond_amount) as u128 * POCI_SCALE as u128) / max_bond_sqrt as u128) as u64
        } else {
            0
        };

        let poci_val: u64 = ((
            POCI_WEIGHT_SHARES as u128 * share_norm as u128
                + POCI_WEIGHT_LOYALTY as u128 * loyalty_norm as u128
                + POCI_WEIGHT_BOND as u128 * bond_norm as u128
        ) / POCI_SCALE as u128) as u64;

        total_poci += poci_val as u128;

        results.push(PoCIResult {
            miner_id: *miner_id,
            poci: poci_val,
            shares: data.shares,
            loyalty: loyalty_val_u,
            bond: bond_amount,
            reward: 0, // заполним ниже
        });
    }

    // ---- rewards ----
    if total_poci == 0 {
        return results;
    }

    for r in results.iter_mut() {
        r.reward = ((r.poci as u128 * EPOCH_REWARD_LYT as u128) / total_poci) as u64;
    }

    results
}