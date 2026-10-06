//! ACCUM constants

pub const LYATORS_PER_ACM: u64 = 10_000_000;
pub const MAX_SUPPLY_ACM: u64 = 150_000_000;
pub const MAX_SUPPLY_LYT: u64 = 1_500_000_000_000_000;
pub const BLOCK_REWARD_LYT: u64 = 500_000;

// Emission per year (halvings). Year = height / (EPOCH_BLOCKS * 365) + 1
pub const EPOCH_REWARD_YEAR_1: u64 = 720_000_000; // 72 ACM
pub const EPOCH_REWARD_YEAR_2: u64 = 288_000_000; // 28.8 ACM
pub const EPOCH_REWARD_YEAR_3: u64 = 144_000_000; // 14.4 ACM
pub const EPOCH_REWARD_YEAR_4: u64 = 72_000_000;  // 7.2 ACM
pub const EPOCH_REWARD_YEAR_5_PLUS: u64 = 7_200_000; // 0.72 ACM

pub const TARGET_BLOCK_TIME: u64 = 60;
pub const EPOCH_BLOCKS: u64 = 100;
pub const GENESIS_TIMESTAMP: u64 = 1790184787;
pub const MINIMUM_FEE_LYT: u64 = 50;
pub const DUST_LIMIT_LYT: u64 = 100;

// Treasury (7% of epoch reward)
pub const TREASURY_FRACTION_BPS: u64 = 700; // 700 / 10000 = 7%
pub const TREASURY_ADDRESS: &str = "1PlaceholderTreasuryAddressReplaceLater";

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
pub const SHARE_PREFILTER_RATIO: u64 = 16;

// PoCI weights (fixed-point)
pub const POCI_SCALE: u64 = 1_000_000_000; // 1e9
pub const POCI_WEIGHT_SHARES: u64 = 600_000_000;  // 0.6
pub const POCI_WEIGHT_LOYALTY: u64 = 200_000_000; // 0.2
pub const POCI_WEIGHT_BOND: u64 = 200_000_000;    // 0.2

// ============================================================
// PoCI normalization constants
// ============================================================
//
// These maxima are used in `calculate_poci` for normalization.
// They MUST be constants (not derived from the miner set),
// otherwise different nodes will compute different norms
// and produce different rewards -> chain fork.

/// Maximum theoretical loyalty value.
///
/// One year = 365 epochs. Doubled with a safety margin.
/// Used to normalize `loyalty` in PoCI.
pub const MAX_LOYALTY_VALUE: u64 = 730;

/// Maximum bond amount for normalization (in LYT).
///
/// Bonds above this value are clamped to 1.0 in PoCI.
/// 1000 ACM = 10_000_000_000 LYT — a reasonable mainnet maximum.
pub const MAX_BOND_LYT: u64 = 10_000_000_000;

pub const LOYALTY_DECAY_FACTOR: f64 = 0.7;
pub const LOYALTY_GRACE_PERIOD: u32 = 3;
pub const LOYALTY_GRACE_DECAY_FACTOR: f64 = 0.5;

// Difficulty adjustment
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 120;
pub const TARGET_ADJUSTMENT_TIME: u64 = 7200;

// Bounds for target change per retarget: ±25%.
// min_actual_time = expected * 75/100  -> target * 0.75 (difficulty goes up)
// max_actual_time = expected * 125/100 -> target * 1.25 (difficulty goes down)
pub const MIN_TARGET_NUMERATOR: u64 = 75;
pub const MIN_TARGET_DENOMINATOR: u64 = 100;
pub const MAX_TARGET_NUMERATOR: u64 = 125;
pub const MAX_TARGET_DENOMINATOR: u64 = 100;

// Network
pub const MAX_PEERS: usize = 125;
pub const MAX_MESSAGES_PER_HOUR_PER_PEER: u32 = 1000;
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
pub const P2P_PORT: u16 = 30333;
pub const RPC_PORT: u16 = 8545;
pub const SYNC_TIMEOUT_SECS: u64 = 60;
pub const PEER_TIMEOUT_SECS: u64 = 300;
pub const STATS_UPDATE_INTERVAL_MS: u64 = 100;
pub const MINING_BATCH_SIZE: u64 = 100_000;

pub const SYNC_BATCH_SIZE: u64 = 10;
pub const SYNC_MAX_RETRIES: u32 = 3;
pub const SYNC_RETRY_DELAY_SECS: u64 = 10;
pub const MAX_BLOCKS_IN_RESPONSE: u32 = 500;
pub const BLOCK_REQUEST_TIMEOUT_SECS: u64 = 30;

// ============================================================
// Epoch commit + share sync (v3.2+)
// ============================================================

/// How many past epochs of shares to keep in the archive.
pub const EPOCH_ARCHIVE_DEPTH: u32 = 10;

/// Maximum shares per single ShareReply message.
pub const MAX_SHARES_PER_REPLY: u32 = 500;

/// Minimum number of peer votes needed to treat a commit root as valid.
pub const MIN_COMMIT_VOTES: usize = 3;

/// How many more votes a peer root must have than ours to switch.
pub const COMMIT_SWITCH_MARGIN: usize = 1;

/// Maximum resync requests per peer per epoch.
pub const MAX_RESYNC_REQUESTS_PER_PEER: u32 = 10;

/// Timeout for a pending GetShares request (seconds).
pub const SHARE_REQUEST_TIMEOUT_SECS: u64 = 30;