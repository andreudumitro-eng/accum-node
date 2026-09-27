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
    // Оба блока, участвующие в доказательстве, хранятся внутри.
    // Это позволяет верифицировать proof без обращения к side-chain хранилищу.
    #[serde(default)]
    pub block_1: Option<Block>,
    #[serde(default)]
    pub block_2: Option<Block>,
}

impl EquivocationProof {
    pub fn block_height_2(&self) -> Height {
        self.block_height
    }

    pub fn verify(&self, argon2: &mut Argon2Cache) -> Result<bool, String> {
        let block1 = self.block_1.as_ref().ok_or("Block 1 missing in proof")?;
        let block2 = self.block_2.as_ref().ok_or("Block 2 missing in proof")?;
    
        // 1. Оба блока должны быть на одной высоте → одинаковый prev_hash.
        if block1.header.prev_hash != block2.header.prev_hash {
            return Ok(false);
        }
    
        // 2. Оба блока должны быть из одной эпохи.
        if block1.header.epoch_index != block2.header.epoch_index {
            return Ok(false);
        }
    
        // 3. Хеши должны совпадать с полями proof.
        let hash1 = block1.header.hash(argon2);
        let hash2 = block2.header.hash(argon2);
    
        if hash1 != self.block_hash_1 || hash2 != self.block_hash_2 {
            return Ok(false);
        }
    
        // 4. Блоки должны быть разными.
        if hash1 == hash2 {
            return Ok(false);
        }
    
        // 5. PoW обоих блоков должен быть валиден.
        if !block1.header.difficulty.is_met_by(&hash1) {
            return Ok(false);
        }
        if !block2.header.difficulty.is_met_by(&hash2) {
            return Ok(false);
        }
    
        // 6. extract_miner_id_from_block проверяет pubkey, signature и подпись.
        let miner_id_from_block1 = Self::extract_miner_id_from_block(block1, argon2)?;
        let miner_id_from_block2 = Self::extract_miner_id_from_block(block2, argon2)?;
    
        if miner_id_from_block1 != miner_id_from_block2 {
            return Ok(false);
        }
    
        if miner_id_from_block1 != self.miner_id {
            return Ok(false);
        }
    
        Ok(true)
    }

    pub fn extract_miner_id_from_block(
        block: &Block,
        argon2: &mut Argon2Cache,
    ) -> Result<MinerId, String> {
        let pk_bytes = block.pubkey.as_ref()
            .ok_or("Block has no pubkey")?;
        let sig = block.signature.as_ref()
            .ok_or("Block has no signature")?;
        let pk = PublicKey::from_slice(pk_bytes)
            .map_err(|e| format!("Invalid pubkey: {}", e))?;
    
        let hash = block.header.hash(argon2);
        if !Wallet::verify_signature(pk_bytes, sig, &hash) {
            return Err("Invalid block signature".to_string());
        }
    
        Ok(Wallet::miner_id_from_pubkey(&pk))
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
        let mut argon2 = Argon2Cache::new(100);
        let miner_id = Self::extract_miner_id_from_block(block1, &mut argon2)?;
    
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
            block_1: Some(block1.clone()),
            block_2: Some(block2.clone()),
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
        if self.processed_slashes.contains(&proof.miner_id) {
            return;
        }

        // №5: дедупликация по (miner_id, block_hash_1, block_hash_2).
        let duplicate = self.pending_slashes.iter().any(|p| {
            p.miner_id == proof.miner_id
                && p.block_hash_1 == proof.block_hash_1
                && p.block_hash_2 == proof.block_hash_2
        });

        if !duplicate {
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

        // Забираем pending, чтобы не держать заимствование self.
        let proofs = std::mem::take(&mut self.pending_slashes);

        for proof in proofs {
            if self.processed_slashes.contains(&proof.miner_id) {
                continue;
            }

            // №4: ошибка на одном доказательстве не должна рвать весь цикл.
            match proof.verify(argon2) {
                Ok(true) => match proof.execute_slash(storage, current_height) {
                    Ok(record) => {
                        self.processed_slashes.insert(proof.miner_id);
                        results.push(record);
                    }
                    Err(e) => {
                        eprintln!(
                            "[slashing] execute_slash failed for {}: {}",
                            hex::encode(&proof.miner_id[0..8]),
                            e
                        );
                    }
                },
                Ok(false) => {
                    // Доказательство не подтвердилось — просто отбрасываем.
                }
                Err(e) => {
                    eprintln!(
                        "[slashing] verify failed for {}: {}",
                        hex::encode(&proof.miner_id[0..8]),
                        e
                    );
                }
            }
        }

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

    // ---- loyalty ----
    let loyalty_values: Vec<u64> = miners
        .values()
        .map(|m| loyalty.get(&m.miner_id).map(|l| l.value).unwrap_or(0))
        .collect();
    let max_loyalty = loyalty_values.iter().copied().max().unwrap_or(0).max(1);

    // ---- bond (только валидные для PoCI) ----
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
        let bond_amount = bonds.get(miner_id).map(|b| b.amount).unwrap_or(0);

        let is_bond_valid = bonds
            .get(miner_id)
            .map(|b| b.is_active(current_height) && b.amount >= MINIMUM_BOND_LYT)
            .unwrap_or(false);

        let share_norm: u64 = if data.shares > 0 {
            ((isqrt(data.shares) as u128 * POCI_SCALE as u128) / max_shares_sqrt as u128) as u64
        } else {
            0
        };

        let loyalty_val_u: u64 = loyalty.get(miner_id).map(|l| l.value).unwrap_or(0);

        let loyalty_norm: u64 =
            ((loyalty_val_u as u128 * POCI_SCALE as u128) / max_loyalty as u128) as u64;

        let bond_norm: u64 = if is_bond_valid {
            ((isqrt(bond_amount) as u128 * POCI_SCALE as u128) / max_bond_sqrt as u128) as u64
        } else {
            0
        };

        let poci_val: u64 = ((POCI_WEIGHT_SHARES as u128 * share_norm as u128
            + POCI_WEIGHT_LOYALTY as u128 * loyalty_norm as u128
            + POCI_WEIGHT_BOND as u128 * bond_norm as u128)
            / POCI_SCALE as u128) as u64;

        total_poci += poci_val as u128;

        results.push(PoCIResult {
            miner_id: *miner_id,
            poci: poci_val,
            shares: data.shares,
            loyalty: loyalty_val_u,
            bond: bond_amount,
            reward: 0,
        });
    }

    // ---- rewards ----
    // ---- rewards ----
    // NOTE: Расчёт reward перенесён в node.rs::process_epoch_end.
    // Здесь считаем только PoCI. Поле reward остаётся 0 — его заполнит caller.
    results
}
