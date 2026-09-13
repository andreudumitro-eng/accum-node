//! Error types for ACCUM protocol

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    // Block errors
    #[error("Invalid header length: expected 120 bytes")]
    InvalidHeaderLength,
    
    #[error("Invalid block hash - PoW not met")]
    InvalidPoW,
    
    #[error("Invalid timestamp")]
    InvalidTimestamp,
    
    #[error("Invalid previous hash")]
    InvalidPrevHash,
    
    #[error("Invalid merkle root")]
    InvalidMerkleRoot,
    
    #[error("Invalid coinbase transaction")]
    InvalidCoinbase,
    
    #[error("Invalid epoch")]
    InvalidEpoch,
    
    // Share errors
    #[error("Invalid share")]
    InvalidShare,
    
    #[error("Invalid share length: expected 180 bytes")]
    InvalidShareLength,
    
    #[error("Invalid miner ID")]
    InvalidMinerId,
    
    #[error("Stale share - prev_hash mismatch")]
    StaleShare,
    
    #[error("Too many shares per miner")]
    TooManyShares,
    
    #[error("Prefilter rejected")]
    PrefilterRejected,
    
    #[error("Share target not met")]
    ShareTargetNotMet,
    
    #[error("Share error: {0}")]
    ShareError(String),
    
    // Miner errors
    #[error("Insufficient bond - minimum {0} LYT required")]
    InsufficientBond(u64),
    
    #[error("Bond not found")]
    BondNotFound,
    
    #[error("Bond still locked")]
    BondLocked,
    
    // Transaction errors
    #[error("Insufficient input")]
    InsufficientInput,
    
    #[error("Double spend")]
    DoubleSpend,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    // Network errors
    #[error("P2P error")]
    P2p,
    
    #[error("Peer banned")]
    PeerBanned,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    // Storage errors
    #[error("Storage error")]
    Storage,
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Key not found")]
    KeyNotFound,
    
    // Serialization errors
    #[error("Serialization error")]
    Serialization,
    
    #[error("Deserialization failed")]
    DeserializationFailed,
    
    // IO errors
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    // Other
    #[error("Other error: {0}")]
    Other(String),
}