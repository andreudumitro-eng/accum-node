//! Share pool management, Merkle trees, and synchronization

use crate::constants::*;
use crate::error::Error;
use crate::share::SharePacket;
use crate::types::{Hash32, MinerId};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};

/// Merkle tree root calculation
pub fn merkle_root(hashes: &[Hash32]) -> Hash32 {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    
    if hashes.len() == 1 {
        return hashes[0];
    }
    
    let mut next_level = Vec::new();
    
    for chunk in hashes.chunks(2) {
        if chunk.len() == 2 {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&chunk[0]);
            combined.extend_from_slice(&chunk[1]);
            let hash = Sha256::digest(&combined);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            next_level.push(arr);
        } else {
            next_level.push(chunk[0]);
        }
    }
    
    merkle_root(&next_level)
}

/// Epoch commit message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochCommit {
    pub epoch_index: u32,
    pub root: Hash32,
    pub timestamp: u64,
}

/// Request for missing shares
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSharesRequest {
    pub epoch_index: u32,
    pub miner_id_list: Vec<MinerId>,
    pub offset: u32,
}

/// Reply with shares batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharesReply {
    pub shares_batch: Vec<SharePacket>,
}

/// Share pool with disk spill support
#[derive(Debug)]
pub struct PersistentSharePool {
    // In-memory shares for current epoch
    shares: HashMap<MinerId, Vec<SharePacket>>,
    share_hashes: HashSet<Hash32>,
    share_count: usize,
    memory_usage: usize,
    
    // Epoch tracking
    current_epoch: u32,
    epoch_commits: HashMap<u32, EpochCommit>,
    
    // Configuration
    max_memory_bytes: usize,
}

impl PersistentSharePool {
    /// Create new persistent share pool
    pub fn new(max_memory_mb: usize) -> Self {
        Self {
            shares: HashMap::new(),
            share_hashes: HashSet::new(),
            share_count: 0,
            memory_usage: 0,
            current_epoch: 1,
            epoch_commits: HashMap::new(),
            max_memory_bytes: max_memory_mb * 1024 * 1024,
        }
    }
    
    /// Add share to pool
    pub fn add_share(&mut self, share: SharePacket) -> Result<(), Error> {
        // Check epoch
        if share.header.epoch_index != self.current_epoch {
            return Err(Error::InvalidShare);
        }
        
        // Check duplicate
        if self.share_hashes.contains(&share.hash) {
            return Err(Error::InvalidShare);
        }
        
        // Estimate memory usage (rough)
        let share_size = std::mem::size_of::<SharePacket>();
        
        // Check total memory limit BEFORE borrowing
        if self.memory_usage + share_size > self.max_memory_bytes {
            // Spill oldest shares first
            self.spill_oldest()?;
        }
        
        // Now borrow after potential spill
        let miner_shares = self.shares.entry(share.miner_id).or_insert_with(Vec::new);
        
        // Check per-miner limit
        if miner_shares.len() >= MAX_SHARES_PER_MINER_PER_EPOCH as usize {
            return Err(Error::InvalidShare);
        }
        
        // Add share
        miner_shares.push(share.clone());
        self.share_hashes.insert(share.hash);
        self.share_count += 1;
        self.memory_usage += share_size;
        
        Ok(())
    }
    
    /// Spill oldest shares to disk (simplified)
    fn spill_oldest(&mut self) -> Result<(), Error> {
        // Find miner with most shares
        let mut target_miner = None;
        let mut max_shares = 0;
        
        for (miner_id, shares) in &self.shares {
            if shares.len() > max_shares {
                max_shares = shares.len();
                target_miner = Some(*miner_id);
            }
        }
        
        // Remove oldest share from that miner
        if let Some(miner_id) = target_miner {
            if let Some(shares) = self.shares.get_mut(&miner_id) {
                if let Some(oldest) = shares.first() {
                    self.share_hashes.remove(&oldest.hash);
                    self.share_count -= 1;
                    self.memory_usage -= std::mem::size_of::<SharePacket>();
                    shares.remove(0);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get shares for a miner
    pub fn get_miner_shares(&self, miner_id: &MinerId) -> Option<&Vec<SharePacket>> {
        self.shares.get(miner_id)
    }
    
    /// Get share count for miner
    pub fn miner_share_count(&self, miner_id: &MinerId) -> usize {
        self.shares.get(miner_id).map(|v| v.len()).unwrap_or(0)
    }
    
    /// Get total shares
    pub fn total_shares(&self) -> usize {
        self.share_count
    }
    
    /// Get all miner IDs
    pub fn miners(&self) -> Vec<MinerId> {
        self.shares.keys().copied().collect()
    }
    
    /// Compute Merkle root for current epoch
    pub fn compute_merkle_root(&self) -> Hash32 {
        if self.share_count == 0 {
            return [0u8; 32];
        }
        
        // Collect all share hashes
        let mut hashes = Vec::with_capacity(self.share_count);
        for shares in self.shares.values() {
            for share in shares {
                hashes.push(share.hash);
            }
        }
        
        // Sort for determinism
        hashes.sort();
        
        merkle_root(&hashes)
    }
    
    /// Create epoch commit for current epoch
    pub fn create_epoch_commit(&mut self) -> EpochCommit {
        let commit = EpochCommit {
            epoch_index: self.current_epoch,
            root: self.compute_merkle_root(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        self.epoch_commits.insert(self.current_epoch, commit.clone());
        commit
    }
    
    /// Clear for new epoch
    pub fn new_epoch(&mut self) {
        self.shares.clear();
        self.share_hashes.clear();
        self.share_count = 0;
        self.memory_usage = 0;
        self.current_epoch += 1;
    }
    
    /// Get epoch commit
    pub fn get_epoch_commit(&self, epoch: u32) -> Option<&EpochCommit> {
        self.epoch_commits.get(&epoch)
    }
    
    /// Check if local root matches peer's
    pub fn check_consistency(&self, peer_root: &Hash32) -> bool {
        let local_root = self.compute_merkle_root();
        local_root == *peer_root
    }
    
    /// Get shares batch for resync
    pub fn get_shares_batch(&self, miner_ids: &[MinerId], offset: usize, limit: usize) -> Vec<SharePacket> {
        let mut result = Vec::new();
        
        for miner_id in miner_ids {
            if let Some(shares) = self.shares.get(miner_id) {
                let start = offset.min(shares.len());
                let end = (offset + limit).min(shares.len());
                
                for i in start..end {
                    result.push(shares[i].clone());
                }
            }
        }
        
        result
    }
    
    /// Statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            current_epoch: self.current_epoch,
            total_shares: self.share_count,
            total_miners: self.shares.len(),
            memory_usage_mb: self.memory_usage / (1024 * 1024),
        }
    }
}

/// Pool statistics
#[derive(Debug)]
pub struct PoolStats {
    pub current_epoch: u32,
    pub total_shares: usize,
    pub total_miners: usize,
    pub memory_usage_mb: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::crypto::argon2id_hash;
    use crate::types::Target;
    
    #[test]
    fn test_merkle_root() {
        let hash1 = [1u8; 32];
        let hash2 = [2u8; 32];
        let hash3 = [3u8; 32];
        
        let root = merkle_root(&[hash1, hash2, hash3]);
        assert_ne!(root, [0u8; 32]);
    }
    
    #[test]
    fn test_pool_operations() {
        let mut pool = PersistentSharePool::new(500);
        
        // Create dummy share
        let header = BlockHeader {
            version: 1,
            prev_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 1741353600,
            difficulty: Target([0xFF; 32]),
            nonce: 0,
            epoch_index: 1,
        };
        
        let share = SharePacket {
            miner_id: [1u8; 20],
            header,
            nonce: 0,
            hash: argon2id_hash(b"test"),
        };
        
        // Add share
        assert!(pool.add_share(share).is_ok());
        assert_eq!(pool.total_shares(), 1);
        
        // Create epoch commit
        let commit = pool.create_epoch_commit();
        assert_eq!(commit.epoch_index, 1);
        
        // New epoch
        pool.new_epoch();
        assert_eq!(pool.total_shares(), 0);
    }
}