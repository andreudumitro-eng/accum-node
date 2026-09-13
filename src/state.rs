//! Minimal chain state for ACCUM

use crate::transaction::{TxOut, UTXOSet};
use crate::types::{Amount, MinerId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Minimal chain state
#[derive(Debug, Default)]
pub struct ChainState {
    pub utxo: UTXOSet,
    pub height: u64,
    pub total_supply: Amount,
}

impl ChainState {
    pub fn new() -> Self {
        Self {
            utxo: UTXOSet::default(),
            height: 0,
            total_supply: 0,
        }
    }

    /// Apply epoch rewards to miners
    pub fn apply_epoch_rewards(
        &mut self,
        rewards: &HashMap<MinerId, Amount>,
        epoch_index: u32,
    ) {
        for (miner_id, &amount) in rewards {
            if amount == 0 {
                continue;
            }

            // Создаём детерминированный txid для epoch reward
            let mut data = Vec::new();
            data.extend_from_slice(b"epoch_reward");
            data.extend_from_slice(&epoch_index.to_le_bytes());
            data.extend_from_slice(miner_id);

            let hash = Sha256::digest(&data);
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&hash);

            let output = TxOut {
                value: amount,
                script_pubkey: miner_id.to_vec(),
            };

            self.utxo.add_output(txid, 0, output);
            self.total_supply = self.total_supply.saturating_add(amount);
        }
    }

    pub fn get_balance(&self, miner_id: &MinerId) -> Amount {
        self.utxo.get_balance(miner_id)
    }
}