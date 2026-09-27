//! Genesis block configuration

use crate::block::{Block, BlockHeader, Transaction, TxIn, TxOut};
use crate::constants::*;
use crate::crypto::argon2id_hash;
use crate::types::current_timestamp;
use crate::types::{Hash32, Target};
use sha2::{Digest, Sha256};


/// Genesis block difficulty (minimum difficulty)
pub const GENESIS_DIFFICULTY: [u8; 32] = [
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Genesis output value (50 ACM)
pub const GENESIS_OUTPUT_VALUE: u64 = 500_000_000;

/// Genesis output script (unspendable)
pub const GENESIS_OUTPUT_SCRIPT: [u8; 25] = [
    0x76, 0xa9, 0x14, 0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6,
    0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18, 0x88, 0xac,
];

/// Genesis block prev_hash (all zeros)
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// Genesis coinbase transaction
pub fn create_genesis_coinbase() -> Transaction {
    // Coinbase input
    let tx_in = TxIn {
        prev_txid: [0u8; 32],
        prev_index: 0xFFFFFFFF,
        script_sig: vec![], // Empty for genesis
        sequence: 0xFFFFFFFF,
    };

    // Genesis output (unspendable)
    let tx_out = TxOut {
        value: GENESIS_OUTPUT_VALUE,
        script_pubkey: GENESIS_OUTPUT_SCRIPT.to_vec(),
    };

    Transaction {
        version: 1,
        inputs: vec![tx_in],
        outputs: vec![tx_out],
        locktime: 0,
    }
}

/// Calculate genesis merkle root
pub fn calculate_genesis_merkle_root() -> Hash32 {
    let coinbase = create_genesis_coinbase();
    let coinbase_bytes = bincode::serialize(&coinbase).unwrap();
    let coinbase_hash = Sha256::digest(&coinbase_bytes);

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&coinbase_hash);
    hash
}

/// Create genesis block header
pub fn create_genesis_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: GENESIS_PREV_HASH,
        merkle_root: calculate_genesis_merkle_root(),
        timestamp: GENESIS_TIMESTAMP,
        difficulty: Target(GENESIS_DIFFICULTY),
        nonce: 0,
        epoch_index: 1,
    }
}

/// Create complete genesis block
pub fn create_genesis_block(wallet: &crate::wallet::Wallet) -> Block {
    let header = create_genesis_header();
    let coinbase = create_genesis_coinbase();
    let hash = argon2id_hash(&header.to_bytes());
    let signature = wallet.sign_block(&hash).ok();
    let pubkey = Some(wallet.public_key.clone());

    Block {
        header,
        transactions: vec![coinbase],
        signature,
        pubkey,
    }
}
/// Verify genesis block
pub fn verify_genesis_block(block: &Block) -> bool {
    // Check version
    if block.header.version != 1 {
        return false;
    }

    // Check prev_hash (must be zero)
    if block.header.prev_hash != GENESIS_PREV_HASH {
        return false;
    }

    // Check timestamp
    if block.header.timestamp != GENESIS_TIMESTAMP {
        return false;
    }

    // Check difficulty
    if block.header.difficulty.0 != GENESIS_DIFFICULTY {
        return false;
    }

    // Check epoch index
    if block.header.epoch_index != 1 {
        return false;
    }

    // Check nonce
    if block.header.nonce != 0 {
        return false;
    }

    // Check merkle root
    let calculated_root = calculate_genesis_merkle_root();
    if block.header.merkle_root != calculated_root {
        return false;
    }

    // Check transaction count
    if block.transactions.len() != 1 {
        return false;
    }

    // Check coinbase output
    let tx = &block.transactions[0];
    if tx.outputs.len() != 1 {
        return false;
    }

    let output = &tx.outputs[0];
    if output.value != GENESIS_OUTPUT_VALUE {
        return false;
    }

    if output.script_pubkey != GENESIS_OUTPUT_SCRIPT.to_vec() {
        return false;
    }

    true
}

/// Get genesis block hash
pub fn genesis_block_hash() -> Hash32 {
    let header = create_genesis_header();
    argon2id_hash(&header.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_creation() {
        let wallet = crate::wallet::Wallet::generate().unwrap();
        let block = create_genesis_block(&wallet);
        assert!(verify_genesis_block(&block));
    }

    #[test]
    fn test_genesis_hash() {
        let hash = genesis_block_hash();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_genesis_merkle_root() {
        let root = calculate_genesis_merkle_root();
        assert_ne!(root, [0u8; 32]);
    }
}
