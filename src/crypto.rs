//! Cryptographic functions: Argon2id, hashing, miner ID

use crate::constants::*;
use crate::types::{current_timestamp, Hash32, Target};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;


pub struct Argon2Cache {
    argon2: Argon2<'static>,
    cache: HashMap<Vec<u8>, (Hash32, u64)>,
    max_size: usize,
    hits: u64,
    misses: u64,
    total_time: u64,
    total_hashes: u64,
}

impl Argon2Cache {
    pub fn new(max_size: usize) -> Self {
        let params = Params::new(
            ARGON2_MEMORY_KB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
            Some(ARGON2_HASH_LEN),
        )
        .expect("Invalid Argon2 parameters");

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        Self {
            argon2,
            cache: HashMap::with_capacity(max_size),
            max_size,
            hits: 0,
            misses: 0,
            total_time: 0,
            total_hashes: 0,
        }
    }

    pub fn hash(&mut self, data: &[u8]) -> Hash32 {
        let now = current_timestamp();
        let start = std::time::Instant::now();

        let key = data.to_vec();

        if let Some((hash, time)) = self.cache.get(&key) {
            if now - *time < 60 {
                self.hits += 1;
                return *hash;
            }
        }

        self.misses += 1;
        let mut output = [0u8; 32];

        let mut salt = [0u8; 16];
        let mut combined = Vec::with_capacity(16 + data.len());
        combined.extend_from_slice(b"ACCUMPOWv3.2+!!!");
        combined.extend_from_slice(data);
        let salt_hash = Sha256::digest(&combined);
        salt.copy_from_slice(&salt_hash[0..16]);

        self.argon2
            .hash_password_into(data, &salt, &mut output)
            .expect("Argon2 hashing failed");

        if self.cache.len() >= self.max_size {
            self.cache.retain(|_, (_, t)| now - *t < 60);
        }

        self.cache.insert(key, (output, now));

        let elapsed = start.elapsed().as_millis() as u64;
        self.total_time += elapsed;
        self.total_hashes += 1;

        output
    }

    pub fn prefilter(header: &[u8; 120], nonce: u64, target: &Target) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(header);
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();

        for i in 0..8 {
            match hash[i].cmp(&target.0[i]) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                Ordering::Equal => continue,
            }
        }
        true
    }

    pub fn stats(&self) -> (u64, u64, f64) {
        let avg_time = if self.total_hashes > 0 {
            self.total_time as f64 / self.total_hashes as f64
        } else {
            0.0
        };
        (self.hits, self.misses, avg_time)
    }
}