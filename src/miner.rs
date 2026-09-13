//! Miner identity, bonds, and loyalty for ACCUM protocol
//! Strictly following ACCUM v3.2+ specification

//! Miner data, loyalty tracking, share accounting

use crate::block::BlockHeader;
use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::types::{current_timestamp, Hash32, MinerId, Target, Timestamp};
use crate::wallet::Wallet;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoyaltyData {
    pub value: u64,
    pub last_epoch: u32,
    pub missed_epochs: u32,
    pub consecutive_epochs: u32,
    pub grace_remaining: u32,
}

impl LoyaltyData {
    pub fn new() -> Self {
        Self {
            value: 0,
            last_epoch: 0,
            missed_epochs: 0,
            consecutive_epochs: 0,
            grace_remaining: 0,
        }
    }

    pub fn update(&mut self, current_epoch: u32, participated: bool) {
        if current_epoch <= self.last_epoch {
            return;
        }

        let epochs_passed = current_epoch - self.last_epoch;

        if participated {
            if epochs_passed > 1 {
                for i in 0..(epochs_passed - 1) {
                    self.apply_decay(i == 0 && self.grace_remaining > 0);
                }
            }

            self.value += 1;
            self.consecutive_epochs += 1;
            self.missed_epochs = 0;

            if self.grace_remaining < LOYALTY_GRACE_PERIOD {
                self.grace_remaining = LOYALTY_GRACE_PERIOD;
            }
        } else {
            for i in 0..epochs_passed {
                self.apply_decay(i == 0 && self.grace_remaining > 0);
            }

            self.missed_epochs += epochs_passed;
            self.consecutive_epochs = 0;

            if self.grace_remaining > 0 {
                self.grace_remaining -= 1;
            }
        }

        self.last_epoch = current_epoch;
    }

    fn apply_decay(&mut self, use_grace: bool) {
        if use_grace {
            // value * 0.5
            self.value /= 2;
        } else {
            // max(value * 0.7, value / 2)
            let decayed_70 = self.value * 7 / 10;
            let decayed_50 = self.value / 2;
            self.value = decayed_70.max(decayed_50);
        }
    }

    pub fn get_loyalty_score(&self) -> u64 {
        self.value
    }

    pub fn is_active(&self) -> bool {
        self.missed_epochs < LOYALTY_GRACE_PERIOD * 2
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerData {
    pub miner_id: MinerId,
    pub pubkey: Vec<u8>,
    pub shares: u64,
    pub bond: u64,
    pub loyalty: u64,
    pub last_epoch: u32,
    pub invalid_ratio: f64,
    pub banned_until: Option<Timestamp>,
    pub last_share_time: Timestamp,
    pub total_shares_historical: u64,
    pub blocks_found: u64,
    pub total_rewards: u64,
    pub payout_address: Option<String>,
    pub first_seen: Timestamp,
}

impl MinerData {
    pub fn new(miner_id: MinerId, bond: u64, epoch: u32, time: Timestamp) -> Self {
        Self {
            miner_id,
            pubkey: Vec::new(),
            shares: 0,
            bond,
            loyalty: 0,
            last_epoch: epoch,
            invalid_ratio: 0.0,
            banned_until: None,
            last_share_time: time,
            total_shares_historical: 0,
            blocks_found: 0,
            total_rewards: 0,
            payout_address: None,
            first_seen: time,
        }
    }

    pub fn is_banned(&self, now: Timestamp) -> bool {
        self.banned_until.map_or(false, |until| now < until)
    }

    pub fn update_invalid_ratio(&mut self, ratio: f64, now: Timestamp) {
        self.invalid_ratio = ratio;

        if ratio > INVALID_SHARE_BAN_THRESHOLD {
            self.banned_until = Some(now + PEER_BAN_DURATION_SECS * 3);
        } else if ratio > INVALID_SHARE_WARNING_THRESHOLD {
            self.banned_until = Some(now + PEER_BAN_DURATION_SECS);
        }
    }

    pub fn can_add_share(&self) -> bool {
        self.shares < MAX_SHARES_PER_MINER_PER_EPOCH
    }

    pub fn add_share(&mut self, timestamp: Timestamp) {
        self.shares += 1;
        self.total_shares_historical += 1;
        self.last_share_time = timestamp;
    }

    pub fn add_block(&mut self, reward: u64) {
        self.blocks_found += 1;
        self.total_rewards += reward;
    }

    pub fn get_hash_rate_estimate(&self, now: Timestamp) -> f64 {
        let time_diff = now - self.first_seen;
        if time_diff == 0 {
            return 0.0;
        }
        self.total_shares_historical as f64 / time_diff as f64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub miner_id: MinerId,
    pub header: BlockHeader,
    pub nonce: u64,
    pub hash: Hash32,
    pub timestamp: Timestamp,
}

impl Share {
    pub fn new(miner_id: MinerId, header: BlockHeader, nonce: u64, hash: Hash32) -> Self {
        Self {
            miner_id,
            header,
            nonce,
            hash,
            timestamp: current_timestamp(),
        }
    }

    pub fn share_hash(&self) -> Hash32 {
        let mut hasher = Sha256::new();
        hasher.update(&self.miner_id);
        hasher.update(&self.header.to_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.hash);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    pub fn validate(
        &self,
        target_share: &Target,
        expected_prev_hash: &Hash32,
        expected_epoch: u32,
        now: Timestamp,
        argon2: &mut Argon2Cache,
    ) -> Result<(), &'static str> {
        if self.header.prev_hash != *expected_prev_hash {
            return Err("Stale prev_hash");
        }

        if self.header.epoch_index != expected_epoch {
            return Err("Wrong epoch");
        }

        if self.timestamp < now - 7200 {
            return Err("Share too old");
        }
        if self.timestamp > now + 7200 {
            return Err("Share too far in future");
        }

        if !Argon2Cache::prefilter(&self.header.to_bytes(), self.nonce, target_share) {
            return Err("Prefilter rejected");
        }

        let computed_hash = self.header.hash_with_nonce(self.nonce, argon2);
        if computed_hash != self.hash {
            return Err("Hash mismatch");
        }

        if !target_share.is_met_by(&self.hash) {
            return Err("Target not met");
        }

        Ok(())
    }

    pub fn to_p2p_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_p2p_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedShare {
    pub miner_id: MinerId,
    pub share_count: u32,
    pub merkle_root: Hash32,
    pub signature: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub timestamp: Timestamp,
    pub epoch: u32,
}

impl AggregatedShare {
    pub fn aggregate(shares: &[Share], wallet: &Wallet, epoch: u32) -> Result<Self, String> {
        if shares.is_empty() {
            return Err("No shares to aggregate".to_string());
        }

        let miner_id = shares[0].miner_id;

        for share in shares {
            if share.miner_id != miner_id {
                return Err("Shares from different miners".to_string());
            }
        }

        let share_count = shares.len() as u32;
        let merkle_root = Self::build_merkle_root(shares);
        let timestamp = current_timestamp();

        let message = Self::build_message(&miner_id, share_count, &merkle_root, epoch, timestamp);
        let signature = wallet.sign(&message)?;

        Ok(Self {
            miner_id,
            share_count,
            merkle_root,
            signature,
            pubkey: wallet.public_key_bytes().to_vec(),
            timestamp,
            epoch,
        })
    }

    fn build_merkle_root(shares: &[Share]) -> Hash32 {
        let mut hashes: Vec<Hash32> = shares.iter().map(|s| s.share_hash()).collect();

        while hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let hash = Sha256::digest(&data);
                next.push(hash.into());
            }
            hashes = next;
        }
        hashes[0]
    }

    fn build_message(
        miner_id: &MinerId,
        share_count: u32,
        merkle_root: &Hash32,
        epoch: u32,
        timestamp: Timestamp,
    ) -> Hash32 {
        let mut data = Vec::new();
        data.extend_from_slice(miner_id);
        data.extend_from_slice(&share_count.to_le_bytes());
        data.extend_from_slice(merkle_root);
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());

        let hash = Sha256::digest(&data);
        hash.into()
    }

    pub fn verify(&self, shares: &[Share]) -> Result<bool, String> {
        if shares.len() as u32 != self.share_count {
            return Ok(false);
        }

        for share in shares {
            if share.miner_id != self.miner_id {
                return Ok(false);
            }
        }

        let computed_root = Self::build_merkle_root(shares);
        if computed_root != self.merkle_root {
            return Ok(false);
        }

        let pubkey = match PublicKey::from_slice(&self.pubkey) {
            Ok(pk) => pk,
            Err(_) => return Ok(false),
        };

        let expected_miner_id = Wallet::miner_id_from_pubkey(&pubkey);
        if expected_miner_id != self.miner_id {
            return Ok(false);
        }

        let message = Self::build_message(
            &self.miner_id,
            self.share_count,
            &self.merkle_root,
            self.epoch,
            self.timestamp,
        );

        if !Wallet::verify_signature(&self.pubkey, &self.signature, &message) {
            return Ok(false);
        }

        Ok(true)
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<MinerId>()
            + 4
            + 32
            + self.signature.len()
            + self.pubkey.len()
            + 8
            + 4
    }
}

pub struct AggregatedSharePool {
    pub aggregates: HashMap<MinerId, AggregatedShare>,
    pub share_counts: HashMap<MinerId, u32>,
    pub verified_roots: HashSet<Hash32>,
    pub max_aggregates: usize,
}

impl AggregatedSharePool {
    pub fn new(max_aggregates: usize) -> Self {
        Self {
            aggregates: HashMap::new(),
            share_counts: HashMap::new(),
            verified_roots: HashSet::new(),
            max_aggregates,
        }
    }

    pub fn add_aggregate(&mut self, agg: AggregatedShare, shares: &[Share]) -> Result<bool, String> {
        if self.verified_roots.contains(&agg.merkle_root) {
            return Ok(false);
        }

        if !agg.verify(shares)? {
            return Ok(false);
        }

        self.aggregates.insert(agg.miner_id, agg.clone());
        self.share_counts.insert(agg.miner_id, agg.share_count);
        self.verified_roots.insert(agg.merkle_root);

        if self.aggregates.len() > self.max_aggregates {
            if let Some(oldest) = self.aggregates.keys().next().copied() {
                if let Some(removed) = self.aggregates.remove(&oldest) {
                    self.verified_roots.remove(&removed.merkle_root);
                    self.share_counts.remove(&oldest);
                }
            }
        }

        Ok(true)
    }

    pub fn get_share_count(&self, miner_id: &MinerId) -> u32 {
        *self.share_counts.get(miner_id).unwrap_or(&0)
    }

    pub fn new_epoch(&mut self) {
        self.aggregates.clear();
        self.share_counts.clear();
        self.verified_roots.clear();
    }

    pub fn active_miners(&self) -> usize {
        self.aggregates.len()
    }

    pub fn total_shares(&self) -> u32 {
        self.share_counts.values().sum()
    }
}

pub struct SharePool {
    pub shares: HashMap<MinerId, Vec<Share>>,
    pub share_count: HashMap<MinerId, u64>,
    pub share_hashes: HashSet<Hash32>,
    pub invalid_shares: HashMap<MinerId, u64>,
    pub total_shares: HashMap<MinerId, u64>,
    pub current_epoch: u32,
    pub max_memory_bytes: usize,
    pub memory_used: usize,
    pub created_at: Timestamp,
}

impl SharePool {
    pub fn new(max_memory_mb: usize) -> Self {
        Self {
            shares: HashMap::new(),
            share_count: HashMap::new(),
            share_hashes: HashSet::new(),
            invalid_shares: HashMap::new(),
            total_shares: HashMap::new(),
            current_epoch: 1,
            max_memory_bytes: max_memory_mb * 1024 * 1024,
            memory_used: 0,
            created_at: current_timestamp(),
        }
    }

    pub fn add_share(&mut self, share: Share, is_valid: bool) -> Result<bool, &'static str> {
        let miner_id = share.miner_id;
        let share_hash = share.share_hash();

        if share.header.epoch_index != self.current_epoch {
            return Err("Wrong epoch");
        }

        if self.share_hashes.contains(&share_hash) {
            return Ok(false);
        }

        let total = self.total_shares.entry(miner_id).or_insert(0);
        *total += 1;

        if !is_valid {
            let invalid = self.invalid_shares.entry(miner_id).or_insert(0);
            *invalid += 1;
            return Ok(false);
        }

        let share_size = std::mem::size_of::<Share>();
        if self.memory_used + share_size > self.max_memory_bytes {
            self.evict_oldest()?;
        }

        let count = self.share_count.entry(miner_id).or_insert(0);
        if *count >= MAX_SHARES_PER_MINER_PER_EPOCH {
            return Err("Max shares per miner exceeded");
        }

        self.shares
            .entry(miner_id)
            .or_insert_with(Vec::new)
            .push(share);
        self.share_hashes.insert(share_hash);
        self.memory_used += share_size;
        *count += 1;

        Ok(true)
    }

    fn evict_oldest(&mut self) -> Result<(), &'static str> {
        let mut target_miner = None;
        let mut max_shares = 0;

        for (miner_id, shares) in &self.shares {
            if shares.len() > max_shares {
                max_shares = shares.len();
                target_miner = Some(*miner_id);
            }
        }

        if let Some(miner_id) = target_miner {
            if let Some(shares) = self.shares.get_mut(&miner_id) {
                if let Some(oldest) = shares.first() {
                    self.share_hashes.remove(&oldest.share_hash());
                    self.memory_used -= std::mem::size_of::<Share>();
                    shares.remove(0);

                    let count = self.share_count.entry(miner_id).or_insert(0);
                    *count -= 1;
                }
            }
        }

        Ok(())
    }

    pub fn miners(&self) -> Vec<MinerId> {
        self.shares.keys().copied().collect()
    }

    pub fn get_shares(&self, miner_id: &MinerId) -> u64 {
        *self.share_count.get(miner_id).unwrap_or(&0)
    }

    pub fn calculate_merkle_root(&self) -> Hash32 {
        if self.share_hashes.is_empty() {
            return [0; 32];
        }

        let mut hashes: Vec<Hash32> = self.share_hashes.iter().copied().collect();
        hashes.sort();

        let mut current = hashes;
        while current.len() > 1 {
            let mut next = Vec::new();
            for chunk in current.chunks(2) {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(&chunk[0]);
                if chunk.len() > 1 {
                    data.extend_from_slice(&chunk[1]);
                } else {
                    data.extend_from_slice(&chunk[0]);
                }
                let hash = Sha256::digest(&data);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                next.push(arr);
            }
            current = next;
        }
        current[0]
    }

    pub fn new_epoch(&mut self) {
        self.shares.clear();
        self.share_count.clear();
        self.share_hashes.clear();
        self.invalid_shares.clear();
        self.total_shares.clear();
        self.memory_used = 0;
        self.current_epoch += 1;
        self.created_at = current_timestamp();
    }

    pub fn invalid_ratio(&self, miner_id: &MinerId) -> f64 {
        let total = self.total_shares.get(miner_id).unwrap_or(&0);
        if *total == 0 {
            return 0.0;
        }
        let invalid = self.invalid_shares.get(miner_id).unwrap_or(&0);
        *invalid as f64 / *total as f64
    }

    pub fn total_shares_count(&self) -> u64 {
        self.share_count.values().sum()
    }

    pub fn active_miners_count(&self) -> usize {
        self.shares.len()
    }

    pub fn memory_usage_mb(&self) -> f64 {
        self.memory_used as f64 / (1024.0 * 1024.0)
    }
}