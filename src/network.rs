//! Network protection: DDoS, rate limits, attack detection

use crate::constants::*;
use crate::types::{current_timestamp, PeerId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackDetection {
    pub hash_rate_history: VecDeque<(Timestamp, f64)>,
    pub block_interval_history: VecDeque<(Timestamp, u64)>,
    pub suspicious_peers: HashSet<PeerId>,
    pub attack_detected: bool,
    pub attack_type: Option<String>,
    pub detection_time: Option<Timestamp>,
}

impl AttackDetection {
    pub fn new() -> Self {
        Self {
            hash_rate_history: VecDeque::with_capacity(1000),
            block_interval_history: VecDeque::with_capacity(1000),
            suspicious_peers: HashSet::new(),
            attack_detected: false,
            attack_type: None,
            detection_time: None,
        }
    }

    pub fn record_hash_rate(&mut self, hash_rate: f64) {
        self.hash_rate_history
            .push_back((current_timestamp(), hash_rate));
        while self.hash_rate_history.len() > 1000 {
            self.hash_rate_history.pop_front();
        }
    }

    pub fn record_block_interval(&mut self, interval_secs: u64) {
        self.block_interval_history
            .push_back((current_timestamp(), interval_secs));
        while self.block_interval_history.len() > 1000 {
            self.block_interval_history.pop_front();
        }
    }

    pub fn detect_51_percent_attack(&mut self, _node_total_hash_rate: f64) -> bool {
        if self.hash_rate_history.len() < 100 {
            return false;
        }

        let recent: Vec<f64> = self
            .hash_rate_history
            .iter()
            .rev()
            .take(100)
            .map(|(_, hr)| *hr)
            .collect();
        let previous: Vec<f64> = self
            .hash_rate_history
            .iter()
            .rev()
            .skip(100)
            .take(100)
            .map(|(_, hr)| *hr)
            .collect();

        if previous.is_empty() {
            return false;
        }

        let recent_avg = recent.iter().sum::<f64>() / recent.len() as f64;
        let previous_avg = previous.iter().sum::<f64>() / previous.len() as f64;

        if recent_avg > previous_avg * 5.0 && previous_avg > 0.0 {
            self.attack_detected = true;
            self.attack_type = Some("hash_rate_spike".to_string());
            self.detection_time = Some(current_timestamp());
            return true;
        }

        let recent_intervals: Vec<u64> = self
            .block_interval_history
            .iter()
            .rev()
            .take(50)
            .map(|(_, i)| *i)
            .collect();
        if !recent_intervals.is_empty() {
            let avg_interval =
                recent_intervals.iter().sum::<u64>() as f64 / recent_intervals.len() as f64;
            if avg_interval < TARGET_BLOCK_TIME as f64 * 0.3 {
                self.attack_detected = true;
                self.attack_type = Some("block_time_anomaly".to_string());
                self.detection_time = Some(current_timestamp());
                return true;
            }
        }

        false
    }

    pub fn mark_peer_suspicious(&mut self, peer_id: PeerId) {
        self.suspicious_peers.insert(peer_id);
    }

    pub fn is_peer_suspicious(&self, peer_id: &PeerId) -> bool {
        self.suspicious_peers.contains(peer_id)
    }

    pub fn clear(&mut self) {
        self.attack_detected = false;
        self.attack_type = None;
        self.detection_time = None;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub requests: u32,
    pub last_hour: Timestamp,
    pub last_minute: Timestamp,
    pub minute_requests: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionLimit {
    pub connections: u32,
    pub last_reset: Timestamp,
    pub failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DDoSProtection {
    pub ip_blacklist: HashSet<SocketAddr>,
    pub ip_whitelist: HashSet<SocketAddr>,
    pub rate_limits: HashMap<SocketAddr, RateLimit>,
    pub connection_limits: HashMap<SocketAddr, ConnectionLimit>,
    pub global_request_count: u64,
    pub last_reset: Timestamp,
    pub attack_mode: bool,
}

impl DDoSProtection {
    pub fn new() -> Self {
        Self {
            ip_blacklist: HashSet::new(),
            ip_whitelist: HashSet::new(),
            rate_limits: HashMap::new(),
            connection_limits: HashMap::new(),
            global_request_count: 0,
            last_reset: current_timestamp(),
            attack_mode: false,
        }
    }

    pub fn check_rate_limit(&mut self, addr: SocketAddr) -> bool {
        let now = current_timestamp();

        if self.ip_whitelist.contains(&addr) {
            return true;
        }

        if self.ip_blacklist.contains(&addr) {
            return false;
        }

        let limit = self.rate_limits.entry(addr).or_insert(RateLimit {
            requests: 0,
            last_hour: now,
            last_minute: now,
            minute_requests: 0,
        });

        if now - limit.last_hour > 3600 {
            limit.requests = 0;
            limit.last_hour = now;
        }

        if now - limit.last_minute > 60 {
            limit.minute_requests = 0;
            limit.last_minute = now;
        }

        limit.requests += 1;
        limit.minute_requests += 1;
        self.global_request_count += 1;

        let max_per_hour = if self.attack_mode { 100 } else { 1000 };
        let max_per_minute = if self.attack_mode { 10 } else { 100 };

        if limit.requests > max_per_hour || limit.minute_requests > max_per_minute {
            self.ip_blacklist.insert(addr);
            return false;
        }

        true
    }

    pub fn check_connection_limit(&mut self, addr: SocketAddr) -> bool {
        let now = current_timestamp();

        if self.ip_blacklist.contains(&addr) {
            return false;
        }

        let limit = self
            .connection_limits
            .entry(addr)
            .or_insert(ConnectionLimit {
                connections: 0,
                last_reset: now,
                failures: 0,
            });

        if now - limit.last_reset > 60 {
            limit.connections = 0;
            limit.last_reset = now;
        }

        let max_connections = if self.attack_mode { 5 } else { 50 };

        if limit.connections >= max_connections {
            return false;
        }

        limit.connections += 1;
        true
    }

    pub fn record_failure(&mut self, addr: SocketAddr) {
        if let Some(limit) = self.connection_limits.get_mut(&addr) {
            limit.failures += 1;
            if limit.failures > 10 {
                self.ip_blacklist.insert(addr);
            }
        }
    }

    pub fn whitelist_ip(&mut self, addr: SocketAddr) {
        self.ip_whitelist.insert(addr);
        self.ip_blacklist.remove(&addr);
    }

    pub fn blacklist_ip(&mut self, addr: SocketAddr) {
        self.ip_blacklist.insert(addr);
        self.ip_whitelist.remove(&addr);
    }

    pub fn enable_attack_mode(&mut self) {
        self.attack_mode = true;
    }

    pub fn disable_attack_mode(&mut self) {
        self.attack_mode = false;
    }

    pub fn global_rate(&self) -> f64 {
        let now = current_timestamp();
        let elapsed = now - self.last_reset;
        if elapsed == 0 {
            0.0
        } else {
            self.global_request_count as f64 / elapsed as f64
        }
    }

    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        self.ip_blacklist.contains(addr)
    }
}