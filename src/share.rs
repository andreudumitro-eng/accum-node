//! Share structures and validation for ACCUM protocol
//! Strictly following ACCUM v3.2+ specification

use crate::block::BlockHeader;
use crate::crypto::miner_id_from_pubkey;
use crate::types::Target;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use libp2p::PeerId;

/// Compare if hash is below target (byte-by-byte)
/// Returns true if hash < target
fn hash_below_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true // equal is also valid per spec
}

/// Share Packet (180 bytes, little-endian) as per specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharePacket {
    pub miner_id: [u8; 20],      // RIPEMD160(SHA256(pubkey))
    pub header: BlockHeader,      // 120 bytes
    pub nonce: u64,               // Nonce that produced valid share
    pub hash: [u8; 32],           // Argon2id hash
}

impl SharePacket {
    /// Create new share packet
    pub fn new(miner_id: [u8; 20], header: BlockHeader, nonce: u64) -> Self {
        let hash = header.hash_with_nonce(nonce);
        
        Self {
            miner_id,
            header,
            nonce,
            hash,
        }
    }

    /// Уникальный хеш шейра (для HashSet)
    pub fn share_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.miner_id);
        hasher.update(&self.header.serialize());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.hash);
        
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Validate share according to specification
    pub fn validate(
        &self,
        target_block: &Target,
        current_prev_hash: &[u8; 32],
        pubkey: &[u8; 33],
    ) -> Result<(), ShareError> {
        // 1. Check prev_hash is current
        if self.header.prev_hash != *current_prev_hash {
            return Err(ShareError::StalePrevHash);
        }

        // 2. Verify miner_id matches pubkey
        let expected_miner_id = miner_id_from_pubkey(pubkey);
        if self.miner_id != expected_miner_id {
            return Err(ShareError::InvalidMinerId);
        }

        // 3. Verify header is exactly 120 bytes
        let header_bytes = self.header.serialize();
        if header_bytes.len() != 120 {
            return Err(ShareError::InvalidHeaderLength);
        }

        // 4. Calculate target_share = target_block << 8
        let target_share = target_block.shift_left(8);

        // 5. Prefilter: SHA256(header || nonce)
        let mut preimage = header_bytes;
        preimage.extend_from_slice(&self.nonce.to_le_bytes());
        let prefilter = Sha256::digest(&preimage);
        
        let mut prefilter_arr = [0u8; 32];
        prefilter_arr.copy_from_slice(&prefilter);

        if !hash_below_target(&prefilter_arr, &target_share.0) {
            return Err(ShareError::PrefilterRejected);
        }

        // 6. Recompute and verify hash
        let computed_hash = self.header.hash_with_nonce(self.nonce);
        if computed_hash != self.hash {
            return Err(ShareError::InvalidHash);
        }

        // 7. Final check: hash < target_share
        if !hash_below_target(&self.hash, &target_share.0) {
            return Err(ShareError::TargetNotMet);
        }

        Ok(())
    }

    /// Serialize to bytes (180 bytes, little-endian)
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(180);
        bytes.extend_from_slice(&self.miner_id);
        bytes.extend_from_slice(&self.header.serialize());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.hash);
        bytes
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ShareError> {
        if bytes.len() != 180 {
            return Err(ShareError::InvalidLength);
        }

        let mut miner_id = [0u8; 20];
        miner_id.copy_from_slice(&bytes[0..20]);

        let header = BlockHeader::deserialize(&bytes[20..140])
            .map_err(|_| ShareError::DeserializationFailed)?;

        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&bytes[140..148]);
        let nonce = u64::from_le_bytes(nonce_bytes);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[148..180]);

        Ok(Self {
            miner_id,
            header,
            nonce,
            hash,
        })
    }

    /// Roundtrip serialization test
    pub fn roundtrip_test(&self) -> Result<(), ShareError> {
        let bytes = self.serialize();
        let decoded = SharePacket::deserialize(&bytes)?;
        
        if *self != decoded {
            return Err(ShareError::RoundtripFailed);
        }
        Ok(())
    }
}

/// Temporary storage for shares in current epoch (from spec)
#[derive(Debug, Default)]
pub struct EpochShares {
    shares: HashMap<[u8; 20], Vec<SharePacket>>,
    share_count: usize,
    share_hashes: std::collections::HashSet<[u8; 32]>,
}

impl EpochShares {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add share to epoch storage
    pub fn add_share(&mut self, share: SharePacket) -> Result<(), ShareError> {
        let share_hash = share.share_hash();
        
        // Проверяем дубликаты
        if self.share_hashes.contains(&share_hash) {
            return Ok(()); // дубликат игнорируем
        }
        
        let miner_shares = self.shares.entry(share.miner_id).or_default();
        
        // Limit from spec: MAX_SHARES_PER_MINER_PER_EPOCH = 5000
        if miner_shares.len() >= 5000 {
            return Err(ShareError::TooManyShares);
        }

        miner_shares.push(share);
        self.share_hashes.insert(share_hash);
        self.share_count += 1;
        Ok(())
    }

    /// Проверить, есть ли шейр в пуле
    pub fn has_share(&self, share: &SharePacket) -> bool {
        self.share_hashes.contains(&share.share_hash())
    }

    /// Get shares for a miner
    pub fn get_miner_shares(&self, miner_id: &[u8; 20]) -> Option<&Vec<SharePacket>> {
        self.shares.get(miner_id)
    }

    /// Get share count for a miner
    pub fn miner_share_count(&self, miner_id: &[u8; 20]) -> usize {
        self.shares.get(miner_id).map(|v| v.len()).unwrap_or(0)
    }

    /// Get total shares in epoch
    pub fn total_shares(&self) -> usize {
        self.share_count
    }

    /// Get all miners in epoch
    pub fn miners(&self) -> Vec<[u8; 20]> {
        self.shares.keys().copied().collect()
    }

    /// Clear for new epoch
    pub fn clear(&mut self) {
        self.shares.clear();
        self.share_hashes.clear();
        self.share_count = 0;
    }
    
    /// Calculate Merkle root of all shares
    pub fn calculate_merkle_root(&self) -> [u8; 32] {
        if self.share_hashes.is_empty() {
            return [0; 32];
        }
        
        let mut hashes: Vec<[u8; 32]> = self.share_hashes.iter().copied().collect();
        hashes.sort();
        
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in hashes.chunks(2) {
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
                next_level.push(arr);
            }
            
            hashes = next_level;
        }
        
        hashes[0]
    }
}

/// Rate limiter for peers (100 shares/minute)
pub struct PeerRateLimiter {
    peer_shares: HashMap<PeerId, (u32, Instant)>,
    banned_peers: HashMap<PeerId, Instant>,
}

impl PeerRateLimiter {
    pub fn new() -> Self {
        Self {
            peer_shares: HashMap::new(),
            banned_peers: HashMap::new(),
        }
    }

    pub fn check_rate(&mut self, peer_id: PeerId) -> Result<(), RateLimitError> {
        // Check if banned
        if let Some(until) = self.banned_peers.get(&peer_id) {
            if Instant::now() < *until {
                return Err(RateLimitError::Banned);
            } else {
                self.banned_peers.remove(&peer_id);
            }
        }

        let now = Instant::now();
        let entry = self.peer_shares.entry(peer_id).or_insert((0, now));

        // Reset every minute
        if now.duration_since(entry.1) > Duration::from_secs(60) {
            *entry = (1, now);
            return Ok(());
        }

        // Limit: 100 per minute
        if entry.0 >= 100 {
            self.banned_peers.insert(peer_id, now + Duration::from_secs(300)); // 5 min ban
            return Err(RateLimitError::RateExceeded);
        }

        entry.0 += 1;
        Ok(())
    }
}

/// Invalid share monitor (10% warning, 30% ban)
pub struct InvalidShareMonitor {
    miner_stats: HashMap<[u8; 20], (u32, u32)>, // (invalid, total)
    epoch: u32,
}

impl InvalidShareMonitor {
    pub fn new() -> Self {
        Self {
            miner_stats: HashMap::new(),
            epoch: 0,
        }
    }

    pub fn record_share(
        &mut self,
        miner_id: [u8; 20],
        is_valid: bool,
        current_epoch: u32,
    ) -> Option<MinerStatus> {
        // New epoch - reset stats
        if current_epoch != self.epoch {
            self.miner_stats.clear();
            self.epoch = current_epoch;
        }

        let entry = self.miner_stats.entry(miner_id).or_insert((0, 0));
        
        if !is_valid {
            entry.0 += 1; // invalid
        }
        entry.1 += 1; // total

        let ratio = entry.0 as f64 / entry.1 as f64;

        if ratio >= 0.3 {
            Some(MinerStatus::Banned)
        } else if ratio >= 0.1 {
            Some(MinerStatus::Warning)
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MinerStatus {
    Warning,
    Banned,
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("Invalid share length: expected 180 bytes")]
    InvalidLength,
    #[error("Invalid header length: expected 120 bytes")]
    InvalidHeaderLength,
    #[error("Stale prev_hash - not at chain tip")]
    StalePrevHash,
    #[error("Invalid miner_id - does not match pubkey")]
    InvalidMinerId,
    #[error("Prefilter rejected")]
    PrefilterRejected,
    #[error("Invalid hash - does not match computed")]
    InvalidHash,
    #[error("Target not met - hash >= target_share")]
    TargetNotMet,
    #[error("Too many shares per miner (max 5000)")]
    TooManyShares,
    #[error("Roundtrip serialization failed")]
    RoundtripFailed,
    #[error("Deserialization failed")]
    DeserializationFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate exceeded (100/min)")]
    RateExceeded,
    #[error("Peer banned for 5 minutes")]
    Banned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::types::Target;

    #[test]
    fn test_target_shift() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xFF;
        bytes[1] = 0xFF;
        bytes[2] = 0xFF;
        bytes[3] = 0xFF;

        let target = Target(bytes);
        let shifted = target.shift_left(8);

        assert_eq!(shifted.0[0], 0xFF);
        assert_eq!(shifted.0[1], 0xFF);
        assert_eq!(shifted.0[2], 0xFF);
        assert_eq!(shifted.0[3], 0x00);
    }

    #[test]
    fn test_share_roundtrip() {
        let pubkey = [2u8; 33];
        let miner_id = miner_id_from_pubkey(&pubkey);

        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]),
            nonce: 0,
            epoch_index: 1,
        };

        let share = SharePacket::new(miner_id, header, 12345);
        assert!(share.roundtrip_test().is_ok());
    }

    #[test]
    fn test_epoch_shares_limit() {
        let mut epoch_shares = EpochShares::new();
        let miner_id = [1u8; 20];
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]),
            nonce: 0,
            epoch_index: 1,
        };

        // Add 5000 shares (limit)
        for i in 0..5000 {
            let share = SharePacket::new(miner_id, header.clone(), i as u64);
            assert!(epoch_shares.add_share(share).is_ok());
        }

        // 5001st should fail
        let share = SharePacket::new(miner_id, header, 5000);
        assert!(matches!(epoch_shares.add_share(share), Err(ShareError::TooManyShares)));
    }

    #[test]
    fn test_invalid_share_monitor() {
        let mut monitor = InvalidShareMonitor::new();
        let miner_id = [1u8; 20];
        let epoch = 1;

        // 10% invalid - should warn
        for _ in 0..9 {
            assert!(monitor.record_share(miner_id, true, epoch).is_none());
        }
        let status = monitor.record_share(miner_id, false, epoch);
        assert_eq!(status, Some(MinerStatus::Warning));

        // 30% invalid - should ban
        for _ in 0..20 {
            monitor.record_share(miner_id, false, epoch);
        }
        let status = monitor.record_share(miner_id, false, epoch);
        assert_eq!(status, Some(MinerStatus::Banned));
    }
}