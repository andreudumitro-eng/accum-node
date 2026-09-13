//! Epoch lifecycle management for ACCUM protocol
//! Strictly following ACCUM v3.2+ specification

use crate::block::BlockHeader;
use crate::constants::*;
use crate::consensus::PoCICalculator;
use crate::difficulty::adjust_difficulty;
use crate::error::Error;
use crate::miner::MinerRegistry;
use crate::share::EpochShares;  // ← ИСПРАВЛЕНО
use crate::types::{Amount, EpochIndex, MinerId, Target};
use std::collections::HashMap;

/// Epoch state as per specification
#[derive(Debug)]
pub struct Epoch {
    pub index: EpochIndex,
    pub start_block: u64,
    pub end_block: u64,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub target_block: Target,
    pub target_share: Target,
    pub total_shares: u64,
    pub active_miners: usize,
}

impl Epoch {
    /// Create new epoch with target_share = target_block << 8
    pub fn new(index: EpochIndex, start_block: u64, start_time: u64, target_block: Target) -> Self {
        let target_share = target_block.shift_left(8);  // ← ИСПРАВЛЕНО (убрана функция)
        
        Self {
            index,
            start_block,
            end_block: start_block + EPOCH_BLOCKS - 1,
            start_time,
            end_time: None,
            target_block,
            target_share,
            total_shares: 0,
            active_miners: 0,
        }
    }

    /// Check if block belongs to this epoch
    pub fn contains_block(&self, height: u64) -> bool {
        height >= self.start_block && height <= self.end_block
    }

    /// Mark epoch as ended
    pub fn end(&mut self, end_time: u64) {
        self.end_time = Some(end_time);
    }

    /// Update stats from share pool
    pub fn update_stats(&mut self, epoch_shares: &EpochShares) {
        self.total_shares = epoch_shares.total_shares() as u64;
        self.active_miners = epoch_shares.miners().len();
    }
}

/// Epoch manager
#[derive(Debug)]
pub struct EpochManager {
    epochs: HashMap<EpochIndex, Epoch>,
    current_epoch: EpochIndex,
    block_timestamps: Vec<u64>,
    block_heights: Vec<u64>,
    epoch_shares: EpochShares,
    miner_registry: MinerRegistry,
}

impl EpochManager {
    /// Create new epoch manager
    pub fn new(initial_target: Target) -> Self {
        let mut manager = Self {
            epochs: HashMap::new(),
            current_epoch: 1,
            block_timestamps: Vec::new(),
            block_heights: Vec::new(),
            epoch_shares: EpochShares::new(),  // ← ИСПРАВЛЕНО
            miner_registry: MinerRegistry::new(),
        };
        
        // Create genesis epoch
        let genesis_epoch = Epoch::new(1, 0, GENESIS_TIMESTAMP, initial_target);
        manager.epochs.insert(1, genesis_epoch);
        
        manager
    }

    /// Get current epoch
    pub fn current(&self) -> Option<&Epoch> {
        self.epochs.get(&self.current_epoch)
    }

    /// Get current epoch mutably
    pub fn current_mut(&mut self) -> Option<&mut Epoch> {
        self.epochs.get_mut(&self.current_epoch)
    }

    /// Add a new block to the chain
    pub fn add_block(&mut self, header: &BlockHeader, height: u64) -> Result<(), Error> {
        // Verify epoch matches
        if header.epoch_index != self.current_epoch {
            return Err(Error::InvalidEpoch);
        }
        
        // Verify timestamp against median of last 11 blocks
        if !self.verify_timestamp(header.timestamp) {
            return Err(Error::InvalidTimestamp);
        }
        
        // Store block info
        self.block_timestamps.push(header.timestamp);
        self.block_heights.push(height);
        
        // Check if epoch ended (we have EPOCH_BLOCKS blocks)
        let blocks_in_epoch = self.block_heights.len() as u64 % EPOCH_BLOCKS;
        if blocks_in_epoch == 0 && self.block_heights.len() > 0 {
            self.end_current_epoch()?;
        }
        
        Ok(())
    }

    /// Add a share to current epoch
    pub fn add_share(&mut self, share: crate::share::SharePacket) -> Result<(), Error> {
        // Verify share belongs to current epoch
        if share.header.epoch_index != self.current_epoch {
            return Err(Error::InvalidEpoch);
        }
        
        // Add to epoch shares
        self.epoch_shares.add_share(share)
            .map_err(|e| Error::ShareError(e.to_string()))?;
        
        Ok(())
    }

    /// Verify timestamp against median of last 11 blocks
    fn verify_timestamp(&self, timestamp: u64) -> bool {
        if self.block_timestamps.len() < 11 {
            return true;
        }
        
        let mut last_11 = self.block_timestamps[self.block_timestamps.len() - 11..].to_vec();
        last_11.sort();
        let median = last_11[5];
        
        timestamp > median && timestamp < std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 7200
    }

    /// End current epoch and start next
    fn end_current_epoch(&mut self) -> Result<(), Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Mark current epoch as ended and update stats
        if let Some(epoch) = self.epochs.get_mut(&self.current_epoch) {
            epoch.end(now);
            epoch.update_stats(&self.epoch_shares);
        }
        
        // Calculate PoCI and rewards for ending epoch
        let rewards = self.calculate_epoch_rewards()?;
        
        // Adjust difficulty for next epoch
        let new_target = self.calculate_next_target()?;
        
        // Create next epoch
        let next_epoch_index = self.current_epoch + 1;
        let next_start_block = self.block_heights.last().unwrap_or(&0) + 1;
        let next_epoch = Epoch::new(next_epoch_index, next_start_block, now, new_target);
        self.epochs.insert(next_epoch_index, next_epoch);
        
        // Clear share pool for next epoch
        self.epoch_shares.clear();
        
        // Update miner registry for next epoch
        self.miner_registry.next_epoch();
        
        self.current_epoch = next_epoch_index;
        
        println!("✅ Epoch {} ended, {} started", self.current_epoch - 1, self.current_epoch);
        println!("   Rewards calculated for {} miners", rewards.len());
        
        Ok(())
    }

    /// Calculate PoCI and rewards for current epoch
    fn calculate_epoch_rewards(&self) -> Result<HashMap<MinerId, Amount>, Error> {
        let calculator = PoCICalculator::new(
            &self.epoch_shares,
            &self.miner_registry,
        );
        
        Ok(calculator.calculate_epoch_rewards(0))  // tx_fees = 0 for now
    }

    /// Calculate next epoch target based on last 120 blocks
    fn calculate_next_target(&self) -> Result<Target, Error> {
        if self.block_timestamps.len() < 120 {
            // Not enough blocks, use current target
            return Ok(self.current().unwrap().target_block);
        }
        
        let start_idx = self.block_timestamps.len() - 120;
        let start = self.block_timestamps[start_idx];
        let end = self.block_timestamps.last().unwrap();
        let time_span = end - start;
        
        let current_target = self.current().unwrap().target_block;
        Ok(adjust_difficulty(&current_target, time_span))
    }

    /// Get epoch by index
    pub fn get_epoch(&self, index: EpochIndex) -> Option<&Epoch> {
        self.epochs.get(&index)
    }

    /// Get reference to epoch shares
    pub fn epoch_shares(&self) -> &EpochShares {
        &self.epoch_shares
    }

    /// Get mutable reference to epoch shares
    pub fn epoch_shares_mut(&mut self) -> &mut EpochShares {
        &mut self.epoch_shares
    }

    /// Get miner registry
    pub fn miner_registry(&self) -> &MinerRegistry {
        &self.miner_registry
    }

    /// Get miner registry mutably
    pub fn miner_registry_mut(&mut self) -> &mut MinerRegistry {
        &mut self.miner_registry
    }
}