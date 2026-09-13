//! Genesis block

use crate::block::{BlockHeader, Transaction, TxIn, TxOut};
use crate::constants::GENESIS_TIMESTAMP;
use crate::types::Target;

pub const GENESIS_OUTPUT_SCRIPT: [u8; 25] = [
    0x76, 0xa9, 0x14, 0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6,
    0xf0, 0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18, 0x88, 0xac,
];

pub fn create_genesis_block() -> (BlockHeader, Transaction) {
    let header = BlockHeader {
        version: 1,
        prev_hash: [0; 32],
        merkle_root: [0; 32],
        timestamp: GENESIS_TIMESTAMP,
        difficulty: Target([0xFF; 32]),
        nonce: 0,
        epoch_index: 1,
    };

    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxIn::coinbase()],
        outputs: vec![TxOut {
            value: 500_000_000,
            script_pubkey: GENESIS_OUTPUT_SCRIPT.to_vec(),
        }],
        locktime: 0,
    };

    (header, coinbase)
}