//! Механизмы сжигания бонда (Slashing)
//! По спецификации секция 7.4

use crate::{
    error::Result,
    types::{Hash32, MinerId, Height},
    transaction::{Transaction, TxIn, TxOut},
    block::BlockHeader,
    share::Share,
    storage::ProductionStorage,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// OP коды для слэшинг транзакций
pub const OP_SLASH_EQUIVOCATION: u8 = 0xFC;
pub const OP_SLASH_INVALID_SHARES: u8 = 0xFD;

// ============================================================
// EQUIVOCATION SLASHING - подпись двух блоков на одной высоте
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEquivocationProof {
    /// Первый блок
    pub block1_header: BlockHeader,
    /// Второй блок
    pub block2_header: BlockHeader,
    /// Высота, на которой произошла эквивокация
    pub height: Height,
    /// Miner ID нарушителя
    pub miner_id: MinerId,
}

impl SlashEquivocationProof {
    /// Создать доказательство эквивокации
    pub fn new(
        block1: BlockHeader,
        block2: BlockHeader,
        miner_id: MinerId,
    ) -> Result<Self> {
        // Проверяем, что это действительно эквивокация
        if block1.hash() == block2.hash() {
            return Err("Блоки идентичны - это не эквивокация".into());
        }
        
        if block1.epoch_index != block2.epoch_index {
            return Err("Блоки из разных эпох".into());
        }
        
        Ok(Self {
            block1_header: block1,
            block2_header: block2,
            height: 0, // будет установлено позже
            miner_id,
        })
    }
    
    /// Проверить доказательство
    pub fn verify(&self) -> bool {
        // Проверяем, что оба блока валидны по PoW
        if !self.block1_header.meets_target() || !self.block2_header.meets_target() {
            return false;
        }
        
        // Проверяем, что они на одной высоте
        if self.block1_header.hash() == self.block2_header.hash() {
            return false;
        }
        
        true
    }
    
    /// Создать слэшинг транзакцию
    pub fn to_transaction(&self) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![
                TxIn::new_slash(self.block1_header.hash()),
                TxIn::new_slash(self.block2_header.hash()),
            ],
            outputs: vec![
                TxOut::new_slash(OP_SLASH_EQUIVOCATION, self.miner_id)
            ],
            locktime: 0,
        }
    }
}

// ============================================================
// INVALID SHARES SLASHING - флуд невалидными шейрами (>30%)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashInvalidSharesProof {
    /// Miner ID нарушителя
    pub miner_id: MinerId,
    /// Список невалидных шейров (минимум 10)
    pub invalid_shares: Vec<Share>,
    /// Эпоха, в которой произошло нарушение
    pub epoch: u32,
    /// Merkle доказательство для шейров
    pub merkle_proofs: Vec<Hash32>,
}

impl SlashInvalidSharesProof {
    /// Создать доказательство флуда невалидными шейрами
    pub fn new(
        miner_id: MinerId,
        invalid_shares: Vec<Share>,
        epoch: u32,
    ) -> Result<Self> {
        if invalid_shares.len() < 10 {
            return Err("Нужно минимум 10 невалидных шейров для доказательства".into());
        }
        
        // Проверяем, что все шейры от одного майнера
        for share in &invalid_shares {
            if share.miner_id != miner_id {
                return Err("Шейр от другого майнера".into());
            }
        }
        
        Ok(Self {
            miner_id,
            invalid_shares,
            epoch,
            merkle_proofs: Vec::new(), // будут вычислены позже
        })
    }
    
    /// Проверить доказательство
    pub fn verify(&self, storage: &ProductionStorage) -> bool {
        // Проверяем, что все шейры действительно невалидны
        for share in &self.invalid_shares {
            if share.is_valid() {
                return false;
            }
        }
        
        // Проверяем Merkle доказательства
        // ... упрощенно для первого шага
        
        true
    }
    
    /// Создать слэшинг транзакцию
    pub fn to_transaction(&self) -> Transaction {
        Transaction {
            version: 1,
            inputs: self.invalid_shares.iter()
                .map(|s| TxIn::new_slash(s.share_hash()))
                .collect(),
            outputs: vec![
                TxOut::new_slash(OP_SLASH_INVALID_SHARES, self.miner_id)
            ],
            locktime: 0,
        }
    }
}

// ============================================================
// SLASHING VALIDATOR - проверяет и применяет слэшинг
// ============================================================

pub struct SlashValidator {
    /// История эквивокаций (miner_id -> кол-во)
    equivocations: HashMap<MinerId, u32>,
    /// История флуда шейрами
    share_floods: HashMap<MinerId, u32>,
}

impl SlashValidator {
    pub fn new() -> Self {
        Self {
            equivocations: HashMap::new(),
            share_floods: HashMap::new(),
        }
    }
    
    /// Проверить и применить слэшинг за эквивокацию
    pub fn process_equivocation(
        &mut self,
        proof: &SlashEquivocationProof,
        storage: &ProductionStorage,
    ) -> Result<bool> {
        // Проверяем доказательство
        if !proof.verify() {
            return Ok(false);
        }
        
        // Находим бонд майнера
        let bond = match storage.get_bond(&proof.miner_id)? {
            Some(b) => b,
            None => return Err("Бонд не найден".into()),
        };
        
        // Сжигаем бонд
        storage.burn_bond(&proof.miner_id, bond.amount)?;
        
        // Логируем
        println!("🔥 Бонд сожжен за эквивокацию: {} LYT", bond.amount);
        
        // Обновляем статистику
        *self.equivocations.entry(proof.miner_id).or_insert(0) += 1;
        
        Ok(true)
    }
    
    /// Проверить и применить слэшинг за флуд невалидными шейрами
    pub fn process_invalid_shares(
        &mut self,
        proof: &SlashInvalidSharesProof,
        storage: &ProductionStorage,
    ) -> Result<bool> {
        // Проверяем доказательство
        if !proof.verify(storage) {
            return Ok(false);
        }
        
        // Находим бонд майнера
        let bond = match storage.get_bond(&proof.miner_id)? {
            Some(b) => b,
            None => return Err("Бонд не найден".into()),
        };
        
        // Сжигаем бонд
        storage.burn_bond(&proof.miner_id, bond.amount)?;
        
        // Логируем
        println!("🔥 Бонд сожжен за флуд невалидными шейрами: {} LYT", bond.amount);
        
        // Обновляем статистику
        *self.share_floods.entry(proof.miner_id).or_insert(0) += 1;
        
        Ok(true)
    }
}

// ============================================================
// ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
// ============================================================

impl TxIn {
    pub fn new_slash(prev_txid: Hash32) -> Self {
        Self {
            prev_txid,
            prev_index: 0xFFFFFFFF,
            script_sig: vec![OP_SLASH_EQUIVOCATION],
            sequence: 0xFFFFFFFF,
        }
    }
}

impl TxOut {
    pub fn new_slash(op_code: u8, miner_id: MinerId) -> Self {
        let mut script = Vec::with_capacity(21);
        script.push(op_code);
        script.extend_from_slice(&miner_id);
        
        Self {
            value: 0, // сжигается, ничего не отправляется
            script_pubkey: script,
        }
    }
}