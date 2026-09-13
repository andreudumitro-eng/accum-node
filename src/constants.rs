//! ACCUM constants

pub const LYATORS_PER_ACM: u64 = 10_000_000;
pub const MAX_SUPPLY_ACM: u64 = 150_000_000;
pub const MAX_SUPPLY_LYT: u64 = 1_500_000_000_000_000;
pub const BLOCK_REWARD_LYT: u64 = 500_000;
pub const EPOCH_REWARD_LYT: u64 = 720_000_000;
pub const TARGET_BLOCK_TIME: u64 = 60;
pub const EPOCH_BLOCKS: u64 = 1440;  
pub const GENESIS_TIMESTAMP: u64 = 1741353600;
pub const MINIMUM_FEE_LYT: u64 = 50;
pub const DUST_LIMIT_LYT: u64 = 100;

pub const ARGON2_MEMORY_KB: u32 = 262_144;
pub const ARGON2_ITERATIONS: u32 = 2;
pub const ARGON2_PARALLELISM: u32 = 4;
pub const ARGON2_HASH_LEN: usize = 32;
pub const ARGON2_SALT: &[u8; 16] = b"ACCUMPOWv3.2+!!!";
pub const ARGON2_CACHE_SIZE: usize = 10000;

pub const MINIMUM_BOND_LYT: u64 = 10_000_000;
pub const BOND_LOCKUP_BLOCKS: u64 = 20_160;
pub const OP_BOND: u8 = 0xBA;

pub const MAX_SHARES_PER_MINER_PER_EPOCH: u64 = 5000;
pub const SHARE_DIFFICULTY_RATIO: u64 = 256;
pub const SHARE_PACKET_SIZE: usize = 180;
pub const MAX_SHARES_PER_MINUTE_PER_PEER: u32 = 100;
pub const PEER_BAN_DURATION_SECS: u64 = 300;
pub const INVALID_SHARE_WARNING_THRESHOLD: f64 = 0.1;
pub const INVALID_SHARE_BAN_THRESHOLD: f64 = 0.3;
pub const SHARE_PREFILTER_RATIO: u64 = 65536;

// PoCI ВЕСА (fixed-point)
pub const POCI_SCALE: u64 = 1_000_000_000;          // 1e9
pub const POCI_WEIGHT_SHARES: u64 = 600_000_000;    // 0.6
pub const POCI_WEIGHT_LOYALTY: u64 = 200_000_000;   // 0.2
pub const POCI_WEIGHT_BOND: u64 = 200_000_000;      // 0.2

pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 120;
pub const TARGET_ADJUSTMENT_TIME: u64 = 7200;
pub const MAX_DIFFICULTY_CHANGE: f64 = 0.25;

pub const LOYALTY_DECAY_FACTOR: f64 = 0.7;
pub const LOYALTY_GRACE_PERIOD: u32 = 3;
pub const LOYALTY_GRACE_DECAY_FACTOR: f64 = 0.5;

pub const MAX_PEERS: usize = 125;
pub const MAX_MESSAGES_PER_HOUR_PER_PEER: u32 = 1000;
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
pub const P2P_PORT: u16 = 30333;
pub const RPC_PORT: u16 = 8545;
pub const SYNC_TIMEOUT_SECS: u64 = 60;
pub const PEER_TIMEOUT_SECS: u64 = 300;
pub const STATS_UPDATE_INTERVAL_MS: u64 = 100;
pub const MINING_BATCH_SIZE: u64 = 5000000;

pub const SYNC_BATCH_SIZE: u64 = 500;
pub const SYNC_MAX_RETRIES: u32 = 3;
pub const SYNC_RETRY_DELAY_SECS: u64 = 10;
pub const MAX_BLOCKS_IN_RESPONSE: u32 = 500;
pub const BLOCK_REQUEST_TIMEOUT_SECS: u64 = 30;