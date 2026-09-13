//! Block, block header, transactions

use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::types::{current_timestamp, Hash32, Height, MinerId, OutPoint, Target, Timestamp, Txid};
use crate::wallet::Wallet;
use crate::{ProductionStorage, SECP};
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_hash: Hash32,
    pub merkle_root: Hash32,
    pub timestamp: Timestamp,
    pub difficulty: Target,
    pub nonce: u64,
    pub epoch_index: u32,
}

impl BlockHeader {
    pub fn new(prev_hash: Hash32, epoch: u32, difficulty: Target) -> Self {
        Self {
            version: 1,
            prev_hash,
            merkle_root: [0; 32],
            timestamp: current_timestamp(),
            difficulty,
            nonce: 0,
            epoch_index: epoch,
        }
    }

    pub fn to_bytes(&self) -> [u8; 120] {
        let mut bytes = [0u8; 120];
        let mut offset = 0;

        bytes[offset..offset + 4].copy_from_slice(&self.version.to_le_bytes());
        offset += 4;
        bytes[offset..offset + 32].copy_from_slice(&self.prev_hash);
        offset += 32;
        bytes[offset..offset + 32].copy_from_slice(&self.merkle_root);
        offset += 32;
        bytes[offset..offset + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 8;
        bytes[offset..offset + 32].copy_from_slice(&self.difficulty.0);
        offset += 32;
        bytes[offset..offset + 8].copy_from_slice(&self.nonce.to_le_bytes());
        offset += 8;
        bytes[offset..offset + 4].copy_from_slice(&self.epoch_index.to_le_bytes());

        bytes
    }

    pub fn hash(&self, argon2: &mut Argon2Cache) -> Hash32 {
        argon2.hash(&self.to_bytes())
    }

    pub fn hash_with_nonce(&self, nonce: u64, argon2: &mut Argon2Cache) -> Hash32 {
        let mut header = self.clone();
        header.nonce = nonce;
        header.hash(argon2)
    }

    pub fn meets_target(&self, argon2: &mut Argon2Cache) -> bool {
        let hash = self.hash(argon2);
        self.difficulty.is_met_by(&hash)
    }

    pub fn validate_timestamp(
        &self,
        prev_timestamp: Option<Timestamp>,
        median: Option<Timestamp>,
    ) -> bool {
        let now = current_timestamp();

        if self.timestamp > now + 7200 {
            return false;
        }

        if let Some(prev) = prev_timestamp {
            if self.timestamp <= prev {
                return false;
            }
        }

        if let Some(m) = median {
            if self.timestamp <= m {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
    #[serde(default)]
    pub pubkey: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

impl TxOut {
    pub fn is_bond(&self) -> bool {
        self.script_pubkey.len() == 21 && self.script_pubkey[0] == OP_BOND
    }

    pub fn extract_miner_id(&self) -> Option<MinerId> {
        if self.is_bond() && self.script_pubkey.len() >= 21 {
            let mut id = [0u8; 20];
            id.copy_from_slice(&self.script_pubkey[1..21]);
            Some(id)
        } else {
            None
        }
    }

    pub fn is_dust(&self) -> bool {
        self.value < DUST_LIMIT_LYT
    }

    pub fn is_p2pkh(&self) -> bool {
        self.script_pubkey.len() == 25
            && self.script_pubkey[0] == 0x76
            && self.script_pubkey[1] == 0xA9
            && self.script_pubkey[2] == 0x14
            && self.script_pubkey[23] == 0x88
            && self.script_pubkey[24] == 0xAC
    }

    pub fn extract_address(&self) -> Option<String> {
        if self.is_p2pkh() && self.script_pubkey.len() >= 23 {
            let pubkey_hash = &self.script_pubkey[3..23];
            let mut with_version = vec![0x00];
            with_version.extend_from_slice(pubkey_hash);
            let checksum = &Sha256::digest(&Sha256::digest(&with_version))[0..4];
            with_version.extend_from_slice(checksum);
            Some(bs58::encode(with_version).into_string())
        } else {
            None
        }
    }

    pub fn create_p2pkh(address: &str) -> Result<Self, String> {
        let decoded = bs58::decode(address)
            .into_vec()
            .map_err(|e| e.to_string())?;
        if decoded.len() != 25 {
            return Err("Invalid address length".to_string());
        }

        let pubkey_hash = &decoded[1..21];
        let mut script = Vec::with_capacity(25);
        script.push(0x76);
        script.push(0xA9);
        script.push(0x14);
        script.extend_from_slice(pubkey_hash);
        script.push(0x88);
        script.push(0xAC);

        Ok(TxOut {
            value: 0,
            script_pubkey: script,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIn {
    pub prev_txid: Txid,
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TxIn {
    pub fn coinbase() -> Self {
        Self {
            prev_txid: [0; 32],
            prev_index: 0xFFFFFFFF,
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.prev_txid == [0; 32] && self.prev_index == 0xFFFFFFFF
    }

    pub fn outpoint(&self) -> OutPoint {
        (self.prev_txid, self.prev_index)
    }

    pub fn sign(
        &mut self,
        wallet: &Wallet,
        tx: &Transaction,
        input_index: usize,
    ) -> Result<(), String> {
        let sighash = tx.sighash(input_index);
        let signature = wallet.sign(&sighash)?;

        let mut script_sig = Vec::new();
        let sig_der = signature;
        script_sig.push(sig_der.len() as u8);
        script_sig.extend_from_slice(&sig_der);

        let pubkey = wallet.public_key_bytes();
        script_sig.push(pubkey.len() as u8);
        script_sig.extend_from_slice(pubkey);

        self.script_sig = script_sig;
        Ok(())
    }

    pub fn verify(&self, tx: &Transaction, input_index: usize, utxo: &TxOut) -> bool {
        if self.is_coinbase() {
            return true;
        }

        let (sig_bytes, pubkey_bytes) = match self.parse_script_sig() {
            Some((sig, key)) => (sig, key),
            None => return false,
        };

        if utxo.is_p2pkh() {
            self.verify_p2pkh(tx, input_index, utxo, pubkey_bytes, sig_bytes)
        } else if utxo.is_bond() {
            self.verify_bond(tx, input_index, utxo, pubkey_bytes, sig_bytes)
        } else {
            false
        }
    }

    pub fn parse_script_sig(&self) -> Option<(&[u8], &[u8])> {
        if self.script_sig.len() < 2 {
            return None;
        }

        let mut pos = 0;

        if self.script_sig[pos] == 0x00 {
            pos += 1;
        }

        if pos >= self.script_sig.len() {
            return None;
        }
        let sig_len = self.script_sig[pos] as usize;
        if pos + 1 + sig_len > self.script_sig.len() {
            return None;
        }
        let sig_bytes = &self.script_sig[pos + 1..pos + 1 + sig_len];
        pos += 1 + sig_len;

        if pos >= self.script_sig.len() {
            return None;
        }
        let key_len = self.script_sig[pos] as usize;
        if pos + 1 + key_len != self.script_sig.len() {
            return None;
        }
        let pubkey_bytes = &self.script_sig[pos + 1..];

        Some((sig_bytes, pubkey_bytes))
    }

    pub fn verify_p2pkh(
        &self,
        tx: &Transaction,
        input_index: usize,
        utxo: &TxOut,
        pubkey_bytes: &[u8],
        sig_bytes: &[u8],
    ) -> bool {
        let pubkey_hash = Ripemd160::digest(&Sha256::digest(pubkey_bytes));
        let expected_hash = &utxo.script_pubkey[3..23];

        if &pubkey_hash[..] != expected_hash {
            return false;
        }

        let sighash = tx.sighash(input_index);
        Self::verify_ecdsa(pubkey_bytes, sig_bytes, &sighash)
    }

    pub fn verify_bond(
        &self,
        tx: &Transaction,
        input_index: usize,
        utxo: &TxOut,
        pubkey_bytes: &[u8],
        sig_bytes: &[u8],
    ) -> bool {
        let expected_miner_id = match utxo.extract_miner_id() {
            Some(id) => id,
            None => return false,
        };

        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let actual_miner_id = Wallet::miner_id_from_pubkey(&pubkey);

        if actual_miner_id != expected_miner_id {
            return false;
        }

        let sighash = tx.sighash(input_index);
        Self::verify_ecdsa(pubkey_bytes, sig_bytes, &sighash)
    }

    pub fn verify_ecdsa(pubkey_bytes: &[u8], sig_bytes: &[u8], msg: &[u8; 32]) -> bool {
        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let message = match Message::from_digest_slice(msg) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let signature = match Signature::from_compact(sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        SECP.verify_ecdsa(&message, &signature, &pubkey).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

impl Transaction {
    pub fn coinbase(outputs: Vec<TxOut>, height: Height) -> Self {
        let mut tx = Self {
            version: 1,
            inputs: vec![TxIn::coinbase()],
            outputs,
            locktime: 0,
        };

        tx.inputs[0].script_sig = height.to_le_bytes().to_vec();
        tx
    }

    pub fn txid(&self, _argon2: &mut Argon2Cache) -> Txid {
        let mut data = Vec::new();

        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());

        for input in &self.inputs {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_index.to_le_bytes());
            data.extend_from_slice(&(input.script_sig.len() as u32).to_le_bytes());
            data.extend_from_slice(&input.script_sig);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.extend_from_slice(&(output.script_pubkey.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.script_pubkey);
        }

        data.extend_from_slice(&self.locktime.to_le_bytes());

        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(&hash1);

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&hash2);
        txid
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].is_coinbase()
    }

    pub fn sighash(&self, input_index: usize) -> [u8; 32] {
        let mut data = Vec::new();

        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());

        for (i, input) in self.inputs.iter().enumerate() {
            data.extend_from_slice(&input.prev_txid);
            data.extend_from_slice(&input.prev_index.to_le_bytes());

            if i == input_index {
                data.extend_from_slice(&(0u32).to_le_bytes());
            } else {
                data.extend_from_slice(&(input.script_sig.len() as u32).to_le_bytes());
                data.extend_from_slice(&input.script_sig);
            }

            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_le_bytes());
            data.extend_from_slice(&(output.script_pubkey.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.script_pubkey);
        }

        data.extend_from_slice(&self.locktime.to_le_bytes());
        data.extend_from_slice(&0x01u32.to_le_bytes());

        let hash = Sha256::digest(&Sha256::digest(&data));
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    pub fn validate_basic(&self) -> Result<(), &'static str> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err("Empty transaction");
        }

        let mut seen = HashSet::new();
        for input in &self.inputs {
            if !input.is_coinbase() {
                let outpoint = input.outpoint();
                if seen.contains(&outpoint) {
                    return Err("Double spend within transaction");
                }
                seen.insert(outpoint);
            }
        }

        for output in &self.outputs {
            if output.is_dust() {
                return Err("Dust output");
            }
        }

        let total_out: u64 = self.outputs.iter().map(|o| o.value).sum();
        if total_out > MAX_SUPPLY_LYT {
            return Err("Output sum exceeds max supply");
        }

        Ok(())
    }

    pub fn validate(&self, storage: &ProductionStorage) -> Result<u64, &'static str> {
        self.validate_basic()?;

        if self.is_coinbase() {
            return Ok(0);
        }

        let mut input_sum = 0u64;

        for (i, input) in self.inputs.iter().enumerate() {
            let utxo = storage
                .get_utxo(&input.outpoint())
                .map_err(|_| "DB error")?
                .ok_or("UTXO not found")?;

            input_sum = input_sum.checked_add(utxo.value).ok_or("Overflow")?;

            if !input.verify(self, i, &utxo) {
                return Err("Invalid signature");
            }
        }

        let output_sum: u64 = self
            .outputs
            .iter()
            .try_fold(0u64, |acc, out| acc.checked_add(out.value))
            .ok_or("Overflow")?;

        if output_sum > input_sum {
            return Err("Outputs exceed inputs");
        }

        let fee = input_sum - output_sum;

        if fee < MINIMUM_FEE_LYT {
            return Err("Fee below minimum");
        }

        Ok(fee)
    }

    pub fn fee(&self, storage: &ProductionStorage) -> Result<u64, String> {
        if self.is_coinbase() {
            return Ok(0);
        }

        let mut input_sum = 0u64;
        for input in &self.inputs {
            let outpoint = input.outpoint();
            if let Some(output) = storage.get_utxo(&outpoint)? {
                input_sum += output.value;
            } else {
                return Err("UTXO not found".to_string());
            }
        }

        let mut output_sum = 0u64;
        for output in &self.outputs {
            output_sum += output.value;
        }

        if input_sum < output_sum {
            return Err("Insufficient input sum".to_string());
        }

        Ok(input_sum - output_sum)
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }

    pub fn create_p2pkh(
        from: &Wallet,
        to: &str,
        amount: u64,
        fee: u64,
        utxos: Vec<(OutPoint, TxOut)>,
    ) -> Result<Self, String> {
        let mut inputs = Vec::new();
        let mut input_sum = 0u64;

        for (outpoint, utxo) in utxos {
            inputs.push(TxIn {
                prev_txid: outpoint.0,
                prev_index: outpoint.1,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            });
            input_sum += utxo.value;

            if input_sum >= amount + fee {
                break;
            }
        }

        if input_sum < amount + fee {
            return Err("Insufficient funds".to_string());
        }

        let mut outputs = Vec::new();

        let mut to_output = TxOut::create_p2pkh(to)?;
        to_output.value = amount;
        outputs.push(to_output);

        let change = input_sum - amount - fee;
        if change > DUST_LIMIT_LYT {
            let mut change_output = TxOut::create_p2pkh(&from.address)?;
            change_output.value = change;
            outputs.push(change_output);
        }

        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs,
            locktime: 0,
        };

        let tx_clone = tx.clone();
        for (i, input) in tx.inputs.iter_mut().enumerate() {
            input.sign(from, &tx_clone, i)?;
        }
        Ok(tx)
    }
}