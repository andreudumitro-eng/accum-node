//! Wallet: key management, signing, transaction creation

use crate::constants::*;
use crate::types::{Hash32, MinerId, OutPoint};
use crate::{Transaction, TxIn, TxOut, SECP};
use rand::rngs::OsRng;
use ripemd::Ripemd160;
use secp256k1::{ecdsa::Signature, Message, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub miner_id: MinerId,
    pub address: String,
}

#[derive(Serialize, Deserialize)]
pub struct WalletFile {
    pub private_key: String,
}

impl Wallet {
    pub fn generate() -> Result<Self, String> {
        let mut rng = OsRng;
        let (secret_key, public_key) = SECP.generate_keypair(&mut rng);

        let miner_id = Self::miner_id_from_pubkey(&public_key);
        let address = Self::address_from_miner_id(&miner_id);

        Ok(Self {
            secret_key: secret_key.secret_bytes().to_vec(),
            public_key: public_key.serialize().to_vec(),
            miner_id,
            address,
        })
    }

    pub fn from_secret_key(secret_bytes: &[u8]) -> Result<Self, String> {
        if secret_bytes.len() != 32 {
            return Err("Invalid secret key length".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(secret_bytes);
        let secret_key = SecretKey::from_slice(&arr).map_err(|_| "Invalid secret key")?;
        let public_key = PublicKey::from_secret_key(&SECP, &secret_key);

        let miner_id = Self::miner_id_from_pubkey(&public_key);
        let address = Self::address_from_miner_id(&miner_id);

        Ok(Self {
            secret_key: secret_key.secret_bytes().to_vec(),
            public_key: public_key.serialize().to_vec(),
            miner_id,
            address,
        })
    }

    pub fn miner_id_from_pubkey(pubkey: &PublicKey) -> MinerId {
        let compressed = pubkey.serialize();
        let sha256 = Sha256::digest(&compressed);
        let ripemd160 = Ripemd160::digest(&sha256);

        let mut miner_id = [0u8; 20];
        miner_id.copy_from_slice(&ripemd160);
        miner_id
    }

    pub fn address_from_miner_id(miner_id: &MinerId) -> String {
        let mut with_version = vec![0x00];
        with_version.extend_from_slice(miner_id);

        let checksum = &Sha256::digest(&Sha256::digest(&with_version))[0..4];
        with_version.extend_from_slice(checksum);

        bs58::encode(with_version).into_string()
    }

    pub fn verify_signature(pubkey_bytes: &[u8], signature: &[u8], message: &[u8]) -> bool {
        if pubkey_bytes.len() != 33 && pubkey_bytes.len() != 65 {
            return false;
        }

        let pubkey = match PublicKey::from_slice(pubkey_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let msg_hash = Sha256::digest(message);
        let msg = match Message::from_digest_slice(&msg_hash) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let sig = match Signature::from_compact(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        SECP.verify_ecdsa(&msg, &sig, &pubkey).is_ok()
    }

    pub fn sign_block(&self, block_hash: &Hash32) -> Result<Vec<u8>, String> {
        self.sign(block_hash)
    }

    pub fn sign(&self, message: &[u8; 32]) -> Result<Vec<u8>, String> {
        if self.secret_key.len() != 32 {
            return Err("Invalid secret key".to_string());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.secret_key);
        let secret_key = SecretKey::from_slice(&arr).map_err(|e| e.to_string())?;
        let msg = Message::from_digest_slice(message).map_err(|e| e.to_string())?;
        let sig = SECP.sign_ecdsa(&msg, &secret_key);
        Ok(sig.serialize_compact().to_vec())
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    pub fn create_simple_tx(
        &self,
        utxos: &[(OutPoint, TxOut)],
        to_address: &str,
        amount: u64,
        fee: u64,
    ) -> Result<Transaction, String> {
        if amount == 0 {
            return Err("Amount must be greater than 0".to_string());
        }

        let mut selected = Vec::new();
        let mut total_in = 0u64;

        for (outpoint, output) in utxos {
            selected.push((outpoint.clone(), output.clone()));
            total_in += output.value;
            if total_in >= amount + fee {
                break;
            }
        }

        if total_in < amount + fee {
            return Err(format!(
                "Insufficient funds. Need {} LYT, have {} LYT",
                amount + fee,
                total_in
            ));
        }

        let change = total_in - amount - fee;

        let mut inputs = Vec::new();
        for (outpoint, _) in &selected {
            inputs.push(TxIn {
                prev_txid: outpoint.0,
                prev_index: outpoint.1,
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            });
        }

        let mut outputs = Vec::new();

        let mut recipient = TxOut::create_p2pkh(to_address)?;
        recipient.value = amount;
        outputs.push(recipient);

        if change > DUST_LIMIT_LYT {
            let mut change_out = TxOut::create_p2pkh(&self.address)?;
            change_out.value = change;
            outputs.push(change_out);
        }

        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs,
            locktime: 0,
        };

        for i in 0..tx.inputs.len() {
            let tx_clone = tx.clone();
            tx.inputs[i].sign(self, &tx_clone, i)?;
        }

        Ok(tx)
    }
}