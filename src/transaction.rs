//! Transaction and UTXO logic for ACCUM v3.2 (Section 12 of SPEC.md).
//!
//! This module implements Bitcoin-style transactions and a simple in-memory
//! UTXO set, with validation rules adapted from the ACCUM specification:
//! - All amounts are in LYT (u64)
//! - Minimum fee: 50 LYT
//! - Dust limit: 100 LYT (outputs below this are non-standard and rejected
//!   by `validate`)
//! - Coinbase transactions identified by prev_txid = [0;32] and
//!   prev_index = 0xFFFFFFFF.

use crate::constants::{DUST_LIMIT_LYT, MINIMUM_FEE_LYT};
use crate::error::Error;
use crate::types::Hash32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::HashSet;

/// Transaction output (Section 12.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxOut {
    /// Amount in LYT.
    pub value: u64,
    /// Locking script.
    pub script_pubkey: Vec<u8>,
}

/// Transaction input (Section 12.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxIn {
    /// Previous transaction id (hash).
    pub prev_txid: Hash32,
    /// Index of the output in the previous transaction.
    pub prev_index: u32,
    /// Unlocking script.
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/// Transaction structure (Section 12.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Transaction {
    /// Compute transaction id (txid) as SHA256 over a canonical serialization.
    ///
    /// The serialization is intentionally simple and self-contained; wire
    /// compatibility with Bitcoin is not required, only determinism across
    /// ACCUM nodes.
    pub fn txid(&self) -> Hash32 {
        let mut hasher = Sha256::new();

        hasher.update(&self.version.to_le_bytes());

        // Encode inputs
        hasher.update(&(self.inputs.len() as u64).to_le_bytes());
        for inp in &self.inputs {
            hasher.update(&inp.prev_txid);
            hasher.update(&inp.prev_index.to_le_bytes());
            hasher.update(&(inp.script_sig.len() as u64).to_le_bytes());
            hasher.update(&inp.script_sig);
            hasher.update(&inp.sequence.to_le_bytes());
        }

        // Encode outputs
        hasher.update(&(self.outputs.len() as u64).to_le_bytes());
        for out in &self.outputs {
            hasher.update(&out.value.to_le_bytes());
            hasher.update(&(out.script_pubkey.len() as u64).to_le_bytes());
            hasher.update(&out.script_pubkey);
        }

        hasher.update(&self.locktime.to_le_bytes());

        let digest = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&digest);
        result
    }

    /// Returns true if this is a coinbase transaction as defined in the spec:
    /// - Exactly one input
    /// - prev_txid = [0;32]
    /// - prev_index = 0xFFFFFFFF
    pub fn is_coinbase(&self) -> bool {
        if self.inputs.len() != 1 {
            return false;
        }
        let inp = &self.inputs[0];
        inp.prev_txid == [0u8; 32] && inp.prev_index == u32::MAX
    }

    /// Validate a transaction against the given UTXO set.
    ///
    /// Returns the transaction fee in LYT on success.
    ///
    /// Rules (Section 12.5):
    /// - No double-spend within this transaction
    /// - Sum(inputs) >= Sum(outputs) + fee
    /// - fee >= MINIMUM_FEE_LYT (except coinbase, which has implicit fee)
    /// - All outputs must be >= DUST_LIMIT_LYT (dust outputs are rejected)
    ///
    /// Note: this function does **not** mutate the UTXO set; it only reads from
    /// it. The caller is responsible for applying spends/additions if the
    /// transaction is accepted into a block.
    pub fn validate(&self, utxo_set: &UTXOSet) -> Result<u64, Error> {
        // Coinbase transactions are validated separately at block-level
        if self.is_coinbase() {
            // Basic sanity: at least one output and all outputs non-dust.
            if self.outputs.is_empty() {
                return Err(Error::InvalidCoinbase);
            }
            for out in &self.outputs {
                if out.value < DUST_LIMIT_LYT {
                    return Err(Error::InvalidCoinbase);
                }
            }
            // Coinbase has no fee in the usual sense; the effective "fee" is
            // part of block reward accounting, so we return 0 here.
            return Ok(0);
        }

        // Track seen inputs within this transaction to prevent intra-tx
        // double-spends of the same UTXO.
        let mut seen_inputs: HashSet<(Hash32, u32)> = HashSet::new();

        let mut input_sum: u64 = 0;
        for inp in &self.inputs {
            let key = (inp.prev_txid, inp.prev_index);
            if !seen_inputs.insert(key) {
                // Same outpoint referenced more than once in this tx.
                return Err(Error::DoubleSpend);
            }

            let prev_out = utxo_set
                .utxos
                .get(&key)
                .ok_or(Error::KeyNotFound)?;

            input_sum = input_sum
                .checked_add(prev_out.value)
                .ok_or(Error::InsufficientInput)?;
        }

        let mut output_sum: u64 = 0;
        for out in &self.outputs {
            if out.value < DUST_LIMIT_LYT {
                // Dust outputs are considered non-standard and rejected.
                return Err(Error::Other(format!(
                    "Dust output below {} LYT",
                    DUST_LIMIT_LYT
                )));
            }
            output_sum = output_sum
                .checked_add(out.value)
                .ok_or(Error::InsufficientInput)?;
        }

        if input_sum < output_sum {
            return Err(Error::InsufficientInput);
        }

        let fee = input_sum - output_sum;
        if fee < MINIMUM_FEE_LYT {
            return Err(Error::Other(format!(
                "Fee below minimum: {} < {}",
                fee, MINIMUM_FEE_LYT
            )));
        }

        Ok(fee)
    }
}

/// Simple in-memory UTXO set mapping `(txid, index)` to `TxOut`.
#[derive(Debug, Default)]
pub struct UTXOSet {
    pub(crate) utxos: HashMap<(Hash32, u32), TxOut>,
}

impl UTXOSet {
    /// Add a new unspent output to the set.
    pub fn add_output(&mut self, txid: Hash32, index: u32, output: TxOut) {
        self.utxos.insert((txid, index), output);
    }

    /// Spend an existing output, removing it from the set and returning it.
    ///
    /// Returns `Error::KeyNotFound` if the referenced UTXO does not exist.
    pub fn spend_input(&mut self, txid: Hash32, index: u32) -> Result<TxOut, Error> {
        self.utxos
            .remove(&(txid, index))
            .ok_or(Error::KeyNotFound)
    }

    /// Compute total balance for all UTXOs whose script_pubkey matches the
    /// given address (raw script bytes or address representation, depending
    /// on higher-level conventions).
    pub fn get_balance(&self, address: &[u8]) -> u64 {
        self.utxos
            .values()
            .filter(|out| out.script_pubkey == address)
            .map(|out| out.value)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_txout(value: u64) -> TxOut {
        TxOut {
            value,
            script_pubkey: b"addr1".to_vec(),
        }
    }

    #[test]
    fn txid_is_deterministic() {
        let tx = Transaction {
            version: 1,
            inputs: vec![],
            outputs: vec![dummy_txout(1_000)],
            locktime: 0,
        };

        let id1 = tx.txid();
        let id2 = tx.txid();
        assert_eq!(id1, id2);
    }

    #[test]
    fn detect_coinbase() {
        let cb = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: [0u8; 32],
                prev_index: u32::MAX,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            outputs: vec![dummy_txout(50_000)],
            locktime: 0,
        };
        assert!(cb.is_coinbase());

        let non_cb = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid: [1u8; 32],
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            outputs: vec![dummy_txout(50_000)],
            locktime: 0,
        };
        assert!(!non_cb.is_coinbase());
    }

    #[test]
    fn validate_standard_tx_with_fee() {
        let mut utxo = UTXOSet::default();
        let prev_txid = [1u8; 32];
        utxo.add_output(prev_txid, 0, dummy_txout(1_000));

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid,
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            outputs: vec![dummy_txout(900)],
            locktime: 0,
        };

        let fee = tx.validate(&utxo).expect("tx should be valid");
        assert_eq!(fee, 100);
    }

    #[test]
    fn reject_dust_output() {
        let mut utxo = UTXOSet::default();
        let prev_txid = [2u8; 32];
        utxo.add_output(prev_txid, 0, dummy_txout(1_000));

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid,
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            outputs: vec![dummy_txout(DUST_LIMIT_LYT - 1)],
            locktime: 0,
        };

        let res = tx.validate(&utxo);
        assert!(res.is_err());
    }

    #[test]
    fn reject_insufficient_input() {
        let mut utxo = UTXOSet::default();
        let prev_txid = [3u8; 32];
        utxo.add_output(prev_txid, 0, dummy_txout(100));

        let tx = Transaction {
            version: 1,
            inputs: vec![TxIn {
                prev_txid,
                prev_index: 0,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            outputs: vec![dummy_txout(100)],
            locktime: 0,
        };

        // No room for minimum fee.
        let res = tx.validate(&utxo);
        assert!(res.is_err());
    }

    #[test]
    fn utxo_balance_works() {
        let mut utxo = UTXOSet::default();
        let txid1 = [4u8; 32];
        let txid2 = [5u8; 32];

        utxo.add_output(txid1, 0, dummy_txout(1_000));
        utxo.add_output(txid2, 0, dummy_txout(2_000));

        let balance = utxo.get_balance(b"addr1");
        assert_eq!(balance, 3_000);
    }
}

