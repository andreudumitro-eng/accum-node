//! Configuration management for ACCUM node

use crate::constants::*;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub mining: MiningConfig,
    pub rpc: RpcConfig,
    pub storage: StorageConfig,
    pub advanced: AdvancedConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub port: u16,
    pub bootnodes: Vec<String>,
    pub max_peers: usize,
    pub seed_nodes: Vec<String>,
    pub dns_seeds: Vec<String>,
    pub enable_seed_discovery: bool,
    pub seed_connection_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningConfig {
    pub enabled: bool,
    pub bond: u64,
    pub threads: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub enabled: bool,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub path: String,
    pub prune: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    pub max_mempool_size: usize,
    pub checkpoint_interval: u64,
    pub enable_attack_detection: bool,
    pub enable_ddos_protection: bool,
    pub max_checkpoints: usize,
    pub share_pool_memory_mb: usize,
    pub backup_interval_blocks: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                port: P2P_PORT,
                bootnodes: vec!["seed.accum.network:30333".to_string()],
                max_peers: MAX_PEERS,
                seed_nodes: vec![
                    "seed1.accum.network:30333".to_string(),
                    "seed2.accum.network:30333".to_string(),
                    "seed3.accum.network:30333".to_string(),
                    "seed4.accum.network:30333".to_string(),
                    "seed5.accum.network:30333".to_string(),
                ],
                dns_seeds: vec![
                    "dnsseed.accum.network".to_string(),
                    "dnsseed.accum.org".to_string(),
                ],
                enable_seed_discovery: true,
                seed_connection_timeout_secs: 10,
            },
            mining: MiningConfig {
                enabled: true,
                bond: MINIMUM_BOND_LYT,
                threads: 4,
            },
            rpc: RpcConfig {
                enabled: true,
                port: RPC_PORT,
            },
            storage: StorageConfig {
                path: "~/.accum".to_string(),
                prune: false,
            },
            advanced: AdvancedConfig {
                max_mempool_size: 10000,
                checkpoint_interval: 1000,
                enable_attack_detection: true,
                enable_ddos_protection: true,
                max_checkpoints: 100,
                share_pool_memory_mb: 500,
                backup_interval_blocks: 100,
            },
        }
    }
}

impl Config {
    pub fn load() -> Result<Self, String> {
        let mut path = dirs::home_dir().ok_or("Cannot find home dir")?;
        path.push(".accum");
        path.push("config.toml");

        if !path.exists() {
            println!("📝 Config not found, creating default");
            let default = Self::default();
            default.save()?;
            return Ok(default);
        }

        let contents = fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str(&contents).map_err(|e| e.to_string())
    }

    pub fn save(&self) -> Result<(), String> {
        let mut path = dirs::home_dir().ok_or("Cannot find home dir")?;
        path.push(".accum");
        fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        path.push("config.toml");

        let contents = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, contents).map_err(|e| e.to_string())?;
        Ok(())
    }
}