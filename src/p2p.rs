//! P2P networking over TCP

use crate::block::{Block, BlockHeader, Transaction};
use crate::consensus::EquivocationProof;
use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::miner::{Share, SharePacket};
use crate::network::DDoSProtection;
use crate::storage::{Checkpoint, ProductionStorage};
use crate::node::Node;
use crate::node::AcceptError;
use crate::types::{current_timestamp, Hash32, Height, MinerId, OutPoint, PeerId, Timestamp};
use crate::wallet::Wallet;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering; 

/// Проверка coinbase: сумма выходов coinbase ≤ block_reward + сумма fees.
pub fn validate_block_coinbase(block: &Block, storage: &ProductionStorage) -> Result<(), String> {
    if block.transactions.is_empty() {
        return Err("Empty block".to_string());
    }

    let coinbase = &block.transactions[0];
    if !coinbase.is_coinbase() {
        return Err("First transaction is not coinbase".to_string());
    }

    let coinbase_out: u64 = coinbase.outputs.iter().map(|o| o.value).sum();

    let mut total_fees: u64 = 0;
    for tx in &block.transactions[1..] {
        let fee = tx.fee(storage).map_err(|e| format!("Fee error: {}", e))?;
        total_fees = total_fees.saturating_add(fee);
    }

    let max_reward = BLOCK_REWARD_LYT.saturating_add(total_fees);

    if coinbase_out > max_reward {
        return Err(format!(
            "Coinbase {} exceeds max reward {}",
            coinbase_out, max_reward
        ));
    }

    Ok(())
}

/// Проверка: внутри блока нет двойной траты одного UTXO.
pub fn validate_block_no_double_spend(block: &Block) -> Result<(), String> {
    let mut seen: HashSet<OutPoint> = HashSet::new();

    for tx in &block.transactions {
        if tx.is_coinbase() {
            continue;
        }
        for input in &tx.inputs {
            let outpoint = input.outpoint();
            if seen.contains(&outpoint) {
                return Err(format!("Double spend detected: {:?}", outpoint));
            }
            seen.insert(outpoint);
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2PMessage {
    Version {
        version: u32,
        timestamp: Timestamp,
        height: Height,
        best_hash: Hash32,
        peer_id: PeerId,
    },
    Verack,
    Ping(u64),
    Pong(u64),
    Share(Share),
    Block {
        header: BlockHeader,
        transactions: Vec<Transaction>,
        #[serde(default)]
        signature: Option<Vec<u8>>,
        #[serde(default)]
        pubkey: Option<Vec<u8>>,
    },
    EpochCommit {
        epoch: u32,
        commit_root: Hash32,
        timestamp: Timestamp,
    },
    GetBlocks {
        from_height: Height,
        max_count: u32,
    },
    Blocks(Vec<Block>),
    GetMempool,
    Mempool(Vec<Transaction>),
    Transaction(Transaction),
    GetPeers,
    Peers(Vec<SocketAddr>),
    BanPeer {
        peer_id: PeerId,
        reason: String,
    },
    SlashProof {
        miner_id: MinerId,
        proof: Box<EquivocationProof>,
    },
    Checkpoint(Box<Checkpoint>),
    SyncRequest {
        from_height: Height,
        to_height: Height,
    },
    SyncResponse(Vec<Block>),
    Heartbeat(u64),
    RegisterMiner {
        miner_id: MinerId,
        payout_address: String,
        pubkey: Vec<u8>,
        signature: Vec<u8>,
        timestamp: Timestamp,
    },

    // ============================================================
    // Epoch commit + share sync messages (v3.2+)
    // ============================================================

    /// Request shares for a specific epoch.
    /// Used during epoch commit resolution when the local node
    /// detects a mismatch between its own Merkle root and the peer's.
    GetShares {
        /// Epoch number the shares belong to.
        epoch: u32,
        /// Index of the first share to return (for pagination).
        offset: u32,
        /// Maximum number of shares to return (capped at MAX_SHARES_PER_REPLY).
        max_count: u32,
        /// Optional filter: only return shares from this miner.
        miner_id: Option<MinerId>,
    },

    /// Response to GetShares containing a batch of shares.
    ShareReply {
        /// Epoch number the shares belong to.
        epoch: u32,
        /// The shares being returned (at most MAX_SHARES_PER_REPLY).
        shares: Vec<SharePacket>,
        /// Total number of shares available for this epoch on the peer.
        /// Used by the requester to know how many more to fetch.
        total_available: u32,
    },

    /// Request a Merkle proof for a specific share.
    /// Used to verify a single share without downloading the whole epoch.
    GetShareProof {
        /// Epoch number the share belongs to.
        epoch: u32,
        /// Canonical hash of the share (SharePacket::canonical_hash).
        share_hash: Hash32,
    },

    /// Merkle proof for a single share.
    ShareProof {
        /// Epoch number the share belongs to.
        epoch: u32,
        /// The share itself.
        share: SharePacket,
        /// Merkle path from the share's leaf to the epoch root.
        /// Empty if the share is the only one (root == leaf).
        merkle_path: Vec<Hash32>,
    },
}

pub const MAX_MESSAGES_PER_HOUR: u32 = 100_000;
pub const MAX_BLOCKS_PER_REQUEST: u32 = 500;
pub const MIN_VERSION: u32 = 1;
pub const MAX_VERSION: u32 = 1;

#[derive(Debug)]
pub struct PeerConnection {
    pub peer_id: PeerId,
    pub address: SocketAddr,
    pub stream: TcpStream,
    pub read_buffer: Vec<u8>,
    pub last_message_time: Timestamp,
    pub last_heartbeat: Timestamp,
    pub last_hour_reset: Timestamp,
    pub messages_this_hour: u32,
    pub version: Option<u32>,
    pub height: Option<Height>,
    pub best_hash: Option<Hash32>,
    pub connected_at: Timestamp,
    pub messages_sent: u32,
    pub messages_received: u32,
    pub invalid_messages: u32,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ping_nonce: Option<u64>,
    pub ping_time: Option<u64>,
}
impl PeerConnection {
    pub fn new(stream: TcpStream, address: SocketAddr) -> Self {
        let now = current_timestamp();

        let mut peer_id = [0u8; 32];
        thread_rng().fill_bytes(&mut peer_id);

        Self {
            peer_id,
            address,
            stream,
            read_buffer: Vec::new(),
            last_message_time: now,
            last_heartbeat: now,
            last_hour_reset: now,
            messages_this_hour: 0,
            version: None,
            height: None,
            best_hash: None,
            connected_at: now,
            messages_sent: 0,
            messages_received: 0,
            invalid_messages: 0,
            banned: false,
            ban_reason: None,
            ping_nonce: None,
            ping_time: None,
        }
    }

    pub fn check_rate_limit(&mut self, current_time: Timestamp) -> bool {
        if current_time.saturating_sub(self.last_hour_reset) > 3600 {
            self.messages_this_hour = 0;
            self.last_hour_reset = current_time;
        }

        if self.messages_this_hour >= MAX_MESSAGES_PER_HOUR {
            self.ban("Rate limit exceeded");
            return false;
        }

        self.messages_this_hour += 1;
        true
    }

    pub fn check_version(&self) -> Result<(), &'static str> {
        match self.version {
            Some(v) if v >= MIN_VERSION && v <= MAX_VERSION => Ok(()),
            Some(v) => {
                println!("Peer {} has incompatible version: {}", self.address, v);
                Err("Incompatible version")
            }
            None => Err("No version received"),
        }
    }

    pub fn is_stale(&self, current_time: Timestamp) -> bool {
        current_time.saturating_sub(self.last_message_time) > PEER_TIMEOUT_SECS
    }

    pub fn needs_heartbeat(&self, current_time: Timestamp) -> bool {
        current_time.saturating_sub(self.last_heartbeat) > 30
    }

    pub fn send_message(&mut self, msg: &P2PMessage) -> Result<(), std::io::Error> {
        if self.banned {
            if !matches!(msg, P2PMessage::BanPeer { .. }) {
                return Ok(());
            }
        }

        let data = bincode::serialize(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        if data.len() > MAX_MESSAGE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too large",
            ));
        }

        let len = (data.len() as u32).to_le_bytes();

        self.stream.write_all(&len)?;
        self.stream.write_all(&data)?;

        self.messages_sent += 1;
        self.last_message_time = current_timestamp();

        Ok(())
    }

    pub fn receive_message(&mut self) -> Result<Option<P2PMessage>, std::io::Error> {
        use std::io::Read;

        let mut chunk = [0u8; 8192];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed connection",
                    ));
                }
                Ok(n) => {
                    self.read_buffer.extend_from_slice(&chunk[..n]);
                    if n < chunk.len() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if self.read_buffer.len() < 4 {
            return Ok(None);
        }

        let len = u32::from_le_bytes([
            self.read_buffer[0],
            self.read_buffer[1],
            self.read_buffer[2],
            self.read_buffer[3],
        ]) as usize;

        if len > MAX_MESSAGE_SIZE {
            self.invalid_messages += 1;
            self.ban("Message too large");
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Message too large",
            ));
        }

        if self.read_buffer.len() < 4 + len {
            return Ok(None);
        }

        let data: Vec<u8> = self.read_buffer[4..4 + len].to_vec();
        self.read_buffer.drain(..4 + len);

        let msg: P2PMessage = bincode::deserialize(&data).map_err(|e| {
            self.invalid_messages += 1;
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;

        let now = current_timestamp();

        if !self.check_rate_limit(now) {
            return Ok(None);
        }

        self.messages_received += 1;
        self.last_message_time = now;

        match &msg {
            P2PMessage::Heartbeat(_nonce) => {
                self.last_heartbeat = now;
            }
            P2PMessage::Pong(nonce) => {
                if let Some(ping_nonce) = self.ping_nonce {
                    if *nonce == ping_nonce {
                        self.ping_time = Some(now);
                    }
                }
                self.last_heartbeat = now;
            }
            P2PMessage::Version {
                height,
                best_hash,
                version,
                peer_id,
                ..
            } => {
                self.peer_id = *peer_id;
                self.height = Some(*height);
                self.best_hash = Some(*best_hash);
                self.version = Some(*version);

                if let Err(e) = self.check_version() {
                    self.ban(e);
                    return Ok(None);
                }
            }
            P2PMessage::GetBlocks { max_count, .. } => {
                if *max_count > MAX_BLOCKS_PER_REQUEST {
                    self.ban("Requested too many blocks");
                    return Ok(None);
                }
            }
            P2PMessage::BanPeer { peer_id, reason } => {
                if peer_id == &self.peer_id {
                    self.ban(reason);
                }
            }
            _ => {}
        }

        Ok(Some(msg))
    }

    pub fn send_ping(&mut self) -> Result<(), std::io::Error> {
        let nonce = thread_rng().next_u64();
        self.ping_nonce = Some(nonce);
        self.send_message(&P2PMessage::Ping(nonce))
    }

    pub fn update_state(&mut self, height: Height, hash: Hash32) {
        self.height = Some(height);
        self.best_hash = Some(hash);
    }

    pub fn ban(&mut self, reason: &str) {
        if self.banned {
            return;
        }

        self.banned = true;
        self.ban_reason = Some(reason.to_string());
        println!("🚫 Peer {} banned: {}", self.address, reason);

        let _ = self.send_message(&P2PMessage::BanPeer {
            peer_id: self.peer_id,
            reason: reason.to_string(),
        });
    }

    pub fn is_banned(&self) -> bool {
        self.banned
    }

    pub fn get_score(&self) -> f64 {
        if self.messages_received == 0 {
            return 0.0;
        }
        let valid_ratio = 1.0 - (self.invalid_messages as f64 / self.messages_received as f64);
        let message_ratio = (self.messages_sent as f64 / self.messages_received as f64).min(1.0);
        valid_ratio * message_ratio
    }

    pub fn get_height(&self) -> Option<Height> {
        self.height
    }

    pub fn get_best_hash(&self) -> Option<Hash32> {
        self.best_hash
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn get_address(&self) -> SocketAddr {
        self.address
    }
}

pub struct P2PNode {
    pub peers: HashMap<SocketAddr, PeerConnection>,
    pub listener: TcpListener,
    pub port: u16,
    pub ddos_protection: DDoSProtection,
    pub known_peers: HashSet<SocketAddr>,
    pub banned_peers: HashSet<PeerId>,
    pub sync_manager: SyncManager,
    pub local_height: Height,
    pub local_best_hash: Hash32,
    pub local_peer_id: PeerId,
    pub bootnodes: Vec<String>,
    pub received_commits: HashMap<(u32, Hash32), HashSet<PeerId>>,
    pub agreed_commits: HashMap<u32, Hash32>,
    pub pending_share_requests: HashMap<(PeerId, u32), u32>,
}

impl P2PNode {
    pub fn new(
        port: u16,
        bootnodes: Vec<String>,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
        listener.set_nonblocking(true)?;

        let mut local_peer_id = [0u8; 32];
        thread_rng().fill_bytes(&mut local_peer_id);

        Ok(Self {
            peers: HashMap::new(),
            listener,
            port,
            ddos_protection: DDoSProtection::new(),
            known_peers: HashSet::new(),
            banned_peers: HashSet::new(),
            sync_manager: SyncManager::new(),
            local_height: 0,
            local_best_hash: [0; 32],
            local_peer_id,
            bootnodes,
            received_commits: HashMap::new(),
            agreed_commits: HashMap::new(),
            pending_share_requests: HashMap::new(),
        })
    }

    pub fn set_local_state(&mut self, height: Height, best_hash: Hash32) {
        self.local_height = height;
        self.local_best_hash = best_hash;
        self.sync_manager.local_height = height;
        self.sync_manager.local_chain.clear();
        self.sync_manager.local_hashes.clear();
        self.broadcast_version();
    }

    pub fn broadcast_version(&mut self) {
        for peer in self.peers.values_mut() {
            let msg = P2PMessage::Version {
                version: 1,
                timestamp: current_timestamp(),
                height: self.local_height,
                best_hash: self.local_best_hash,
                peer_id: self.local_peer_id,
            };
            let _ = peer.send_message(&msg);
        }
    }

    pub fn accept_connections(&mut self) -> Result<(), std::io::Error> {
        match self.listener.accept() {
            Ok((stream, addr)) => {
                if !self.ddos_protection.check_connection_limit(addr) {
                    return Ok(());
                }

                if self.peers.len() >= MAX_PEERS {
                    return Ok(());
                }

                let mut peer = PeerConnection::new(stream, addr);

                if self.banned_peers.contains(&peer.get_peer_id()) {
                    return Ok(());
                }

                let version_msg = P2PMessage::Version {
                    version: 1,
                    timestamp: current_timestamp(),
                    height: self.local_height,
                    best_hash: self.local_best_hash,
                    peer_id: self.local_peer_id,
                };
                peer.send_message(&version_msg)?;

                peer.stream.set_nonblocking(true)?;

                println!("✅ New peer connected: {}", addr);
                self.peers.insert(addr, peer);
                self.known_peers.insert(addr);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }

    pub fn process_messages(&mut self) -> Result<Vec<(P2PMessage, SocketAddr)>, std::io::Error> {
        let now = current_timestamp();
        let mut disconnected = Vec::new();
        let mut messages_to_return = Vec::new();

        for (addr, peer) in self.peers.iter_mut() {
            if peer.is_banned() || peer.is_stale(now) {
                disconnected.push(*addr);
                continue;
            }

            if peer.needs_heartbeat(now) {
                let _ = peer.send_ping();
            }

            loop {
                match peer.receive_message() {
                    Ok(Some(msg)) => {
                        if !self.ddos_protection.check_rate_limit(*addr) {
                            peer.ban("Rate limit exceeded");
                            disconnected.push(*addr);
                            break;
                        }
                        messages_to_return.push((msg, *addr));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                        println!("🔍 [{}] process_messages error: {:?}", addr, e);
                        self.ddos_protection.record_failure(*addr);
                        disconnected.push(*addr);
                        break;
                    }
                }
            }
        }

        for addr in disconnected {
            if let Some(peer) = self.peers.remove(&addr) {
                self.sync_manager.remove_peer(&peer.get_peer_id());
                println!("❌ Peer disconnected: {}", addr);
            }
        }

        Ok(messages_to_return)
    }

    pub fn broadcast(&mut self, msg: &P2PMessage) {
        let now = current_timestamp();
        self.peers.retain(|_, peer| !peer.is_stale(now));

        for peer in self.peers.values_mut() {
            if !peer.is_banned() {
                let _ = peer.send_message(msg);
            }
        }
    }

    pub fn connect_to(&mut self, addr: SocketAddr) -> Result<(), std::io::Error> {
        if self.peers.contains_key(&addr) {
            return Ok(());
        }

        if !self.ddos_protection.check_connection_limit(addr) {
            return Ok(());
        }

        let stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))?;
        let mut peer = PeerConnection::new(stream, addr);

        let version_msg = P2PMessage::Version {
            version: 1,
            timestamp: current_timestamp(),
            height: self.local_height,
            best_hash: self.local_best_hash,
            peer_id: self.local_peer_id,
        };
        peer.send_message(&version_msg)?;

        peer.stream.set_nonblocking(true)?;

        self.peers.insert(addr, peer);
        self.known_peers.insert(addr);

        Ok(())
    }

    pub fn connect_to_bootnodes(&mut self) {
        let bootnodes = self.bootnodes.clone();
        if bootnodes.is_empty() {
            println!("⚠️ No bootnodes configured");
            return;
        }
        for bootnode in &bootnodes {
            match bootnode.parse::<SocketAddr>() {
                Ok(addr) => match self.connect_to(addr) {
                    Ok(_) => println!("✅ Connected to bootnode {}", addr),
                    Err(e) => println!("❌ Failed to connect to bootnode {}: {}", addr, e),
                },
                Err(e) => println!("❌ Invalid bootnode address '{}': {}", bootnode, e),
            }
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn get_peers_info(&self) -> Vec<(SocketAddr, Option<Height>, f64)> {
        self.peers
            .iter()
            .map(|(addr, peer)| (*addr, peer.get_height(), peer.get_score()))
            .collect()
    }

    pub fn best_peer_height(&self) -> Option<Height> {
        self.sync_manager.best_peer_height()
    }

    pub fn sync_progress(&self) -> f64 {
        self.sync_manager.sync_progress()
    }

    pub fn is_syncing(&self) -> bool {
        self.sync_manager.is_syncing()
    }

    pub fn needs_sync(&self) -> bool {
        self.sync_manager.needs_sync()
    }
}

#[derive(Debug, Clone)]
pub struct SyncPeer {
    pub peer_id: PeerId,
    pub address: SocketAddr,
    pub height: Height,
    pub best_hash: Hash32,
    pub latency_ms: u64,
    pub last_sync_time: Timestamp,
    pub retries: u32,
    pub banned: bool,
}

#[derive(Debug, Clone)]
pub struct SyncSession {
    pub peer_id: PeerId,
    pub from_height: Height,
    pub target_height: Height,
    pub current_height: Height,
    pub started_at: Timestamp,
    pub last_activity: Timestamp,
    pub blocks_received: u32,
    pub status: SyncStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyncStatus {
    Idle,
    Requesting,
    Receiving,
    Verifying,
    Completed,
    Failed(String),
}

pub struct SyncManager {
    pub peers: HashMap<PeerId, SyncPeer>,
    pub active_session: Option<SyncSession>,
    /// DEPRECATED: source of truth is Node::blocks. Оставлено для совместимости.
    #[allow(dead_code)]
    pub local_chain: Vec<BlockHeader>,
    /// DEPRECATED: source of truth is Node::block_hashes. Оставлено для совместимости.
    #[allow(dead_code)]
    pub local_hashes: HashMap<Hash32, Height>,
    /// Local chain height — updated from Node::height.
    pub local_height: Height,
    pub sync_in_progress: bool,
    pub last_sync_attempt: Timestamp,
    pub pending_blocks: Vec<Block>,
    pub last_request_time: Timestamp,
    pub retry_count: HashMap<PeerId, u32>,
    pub sync_complete_height: Height,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            active_session: None,
            local_chain: Vec::new(),
            local_hashes: HashMap::new(),
            local_height: 0,
            sync_in_progress: false,
            last_sync_attempt: 0,
            pending_blocks: Vec::new(),
            last_request_time: 0,
            retry_count: HashMap::new(),
            sync_complete_height: 0,
        }
    }

    pub fn set_chain(&mut self, chain: Vec<BlockHeader>, hashes: HashMap<Hash32, Height>) {
        self.local_chain = chain;
        self.local_hashes = hashes;
    }

    pub fn update_peer(
        &mut self,
        peer_id: PeerId,
        address: SocketAddr,
        height: Height,
        best_hash: Hash32,
        latency_ms: u64,
    ) {
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.height = height;
            peer.best_hash = best_hash;
            peer.latency_ms = latency_ms;
            peer.last_sync_time = current_timestamp();
        } else {
            self.peers.insert(
                peer_id,
                SyncPeer {
                    peer_id,
                    address,
                    height,
                    best_hash,
                    latency_ms,
                    last_sync_time: current_timestamp(),
                    retries: 0,
                    banned: false,
                },
            );
        }
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    pub fn best_peer(&self) -> Option<SyncPeer> {
        let current_height = self.current_height();

        self.peers
            .values()
            .filter(|p| !p.banned && p.height > current_height)
            .max_by(|a, b| {
                let score_a = (a.height - current_height) as f64 / (a.latency_ms as f64 + 1.0);
                let score_b = (b.height - current_height) as f64 / (b.latency_ms as f64 + 1.0);
                score_a.partial_cmp(&score_b).unwrap()
            })
            .cloned()
    }

    pub fn needs_sync(&self) -> bool {
        // Already syncing — no need to start a new session.
        if self.sync_in_progress {
            return false;
        }

        let current_height = self.current_height();
        let best_peer_height = self
            .peers
            .values()
            .filter(|p| !p.banned)
            .map(|p| p.height)
            .max()
            .unwrap_or(current_height);

        let now = current_timestamp();
        let sync_timeout = now.saturating_sub(self.last_sync_attempt) > SYNC_TIMEOUT_SECS;

        best_peer_height > current_height && (self.active_session.is_none() || sync_timeout)
    }

    pub fn start_sync(&mut self, peer: SyncPeer) -> bool {
        if self.sync_in_progress {
            return false;
        }

        let current_height = self.current_height();

        if peer.height <= current_height {
            return false;
        }

        self.active_session = Some(SyncSession {
            peer_id: peer.peer_id,
            from_height: current_height,
            target_height: peer.height,
            current_height,
            started_at: current_timestamp(),
            last_activity: current_timestamp(),
            blocks_received: 0,
            status: SyncStatus::Requesting,
        });

        self.sync_in_progress = true;
        self.last_sync_attempt = current_timestamp();
        
        // Reset the throttle so the new session can issue its first
        // GetBlocks request immediately.
        self.last_request_time = 0;

        println!(
            "🔄 Starting sync from height {} to {} with peer {}...",
            current_height, peer.height, peer.address
        );

        true
    }

    pub fn on_blocks_received(
        &mut self,
        blocks: &[Block],
        peer_id: &PeerId,
    ) -> Result<Height, String> {
        let (session_height, session_target) = {
            let session = self
                .active_session
                .as_ref()
                .ok_or_else(|| "No active sync session".to_string())?;

            if session.peer_id != *peer_id {
                return Err("Wrong peer".to_string());
            }

            (session.current_height, session.target_height)
        };

        if blocks.is_empty() {
            if let Some(session) = self.active_session.as_mut() {
                session.status = SyncStatus::Completed;
            }
            self.sync_in_progress = false;
            self.active_session = None;
            return Ok(session_height);
        }

        let new_height = {
            let session = self
                .active_session
                .as_mut()
                .ok_or_else(|| "No active sync session".to_string())?;

            session.blocks_received += blocks.len() as u32;
            session.last_activity = current_timestamp();
            session.status = SyncStatus::Receiving;

            session.current_height = session
                .current_height
                .saturating_add(blocks.len() as u64)
                .min(session.target_height);

            session.current_height
        };

        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.retries = 0;
        }

        if new_height >= session_target {
            println!("✅ Sync completed! Height: {}", new_height);
            if let Some(session) = self.active_session.as_mut() {
                session.status = SyncStatus::Completed;
            }
            self.sync_in_progress = false;
            self.active_session = None;
            return Ok(new_height);
        }

        if let Some(session) = self.active_session.as_mut() {
            session.status = SyncStatus::Requesting;
        }

        Ok(new_height)
    }

    pub fn check_timeouts(&mut self) -> Option<PeerId> {
        let now = current_timestamp();

        let is_completed = self
            .active_session
            .as_ref()
            .map(|s| s.status == SyncStatus::Completed)
            .unwrap_or(false);

        if is_completed {
            self.active_session = None;
            return None;
        }

        let timeout_peer = {
            let session = match self.active_session.as_ref() {
                Some(s) => s,
                None => return None,
            };
            if now.saturating_sub(session.last_activity) > SYNC_TIMEOUT_SECS {
                Some(session.peer_id)
            } else {
                None
            }
        };

        if let Some(peer_id) = timeout_peer {
            println!("⚠️ Sync timeout with peer");
            if let Some(peer) = self.peers.get_mut(&peer_id) {
                peer.retries += 1;
                if peer.retries >= 3 {
                    peer.banned = true;
                    println!("🚫 Peer {} banned due to sync failures", peer.address);
                }
            }
            // Полностью очищаем сессию, иначе sync_progress вернёт мусор.
            self.active_session = None;
            self.sync_in_progress = false;
            return Some(peer_id);
        }

        None
    }

    pub fn best_peer_height(&self) -> Option<Height> {
        self.peers
            .values()
            .filter(|p| !p.banned)
            .map(|p| p.height)
            .max()
    }

    pub fn sync_progress(&self) -> f64 {
        if let Some(session) = self.active_session.as_ref() {
            let total = session.target_height.saturating_sub(session.from_height);
            let current = session.current_height.saturating_sub(session.from_height);
            if total > 0 {
                return (current as f64 / total as f64).min(1.0);
            }
        }
        let best = match self.best_peer_height() {
            Some(h) if h > self.local_height => h,
            _ => return 1.0,
        };
        (self.local_height as f64 / best as f64).min(1.0)
    }

    pub fn is_syncing(&self) -> bool {
        self.sync_in_progress
    }

    pub fn current_height(&self) -> Height {
        self.local_height
    }

    pub fn request_blocks(
        &mut self,
        peer_id: &PeerId,
        from: Height,
        to: Height,
    ) -> Result<P2PMessage, String> {
        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| "Peer not found".to_string())?;

        if peer.banned {
            return Err("Peer is banned".to_string());
        }

        let max_count = to
            .saturating_sub(from)
            .min(MAX_BLOCKS_PER_REQUEST as u64) as u32;

        println!(
            "📤 Requested blocks {}..{} from peer {}",
            from,
            from + max_count as u64,
            peer.address
        );

        Ok(P2PMessage::GetBlocks {
            from_height: from,
            max_count,
        })
    }

    pub fn request_blocks_from_peer(
        &mut self,
        peer_id: &PeerId,
        from_height: Height,
    ) -> Result<P2PMessage, String> {
        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| "Peer not found in sync manager".to_string())?;

        if peer.banned {
            return Err("Peer is banned".to_string());
        }

        let now = current_timestamp();
        // Согласовано с интервалом SYNC_REQUEST_INTERVAL_SECS в Node::tick.
        if now.saturating_sub(self.last_request_time) < 2 && self.sync_in_progress {
            return Err("Too frequent requests".to_string());
        }

        let max_height = peer.height;
        let to_height = (from_height + SYNC_BATCH_SIZE - 1).min(max_height);
        let count = to_height
            .saturating_sub(from_height)
            .saturating_add(1)
            .min(MAX_BLOCKS_PER_REQUEST as u64) as u32;

        if count == 0 {
            return Err("No blocks to request".to_string());
        }

        let retries = self.retry_count.entry(*peer_id).or_insert(0);
        if *retries >= SYNC_MAX_RETRIES {
            return Err("Peer has too many retries".to_string());
        }

        if let Some(session) = self.active_session.as_mut() {
            session.status = SyncStatus::Receiving;
            session.last_activity = now;
        }

        self.last_request_time = now;
        self.last_sync_attempt = now;

        println!(
            "📤 Requested {} blocks from height {} from peer {}",
            count, from_height, peer.address
        );

        Ok(P2PMessage::GetBlocks {
            from_height,
            max_count: count,
        })
    }

    pub fn verify_and_accept_blocks(
        &mut self,
        blocks: &[Block],
        node: &mut Node,
    ) -> Result<Height, String> {
        let mut accepted = 0u64;
        let mut last_error: Option<AcceptError> = None;

        for block in blocks {
            match node.accept_block(block) {
                Ok(()) => {
                    accepted += 1;
                }
                Err(AcceptError::AlreadyKnown) => {
                    // Not an error: we've seen it.
                    accepted += 1;
                }
                Err(AcceptError::PrevHashMismatch { .. }) => {
                    // Possible fork — try to switch to the competing branch.
                    match node.try_fork_switch(block) {
                        Ok(true) => {
                            // Reorg succeeded — the block is now part of our chain.
                            accepted += 1;
                        }
                        Ok(false) => {
                            // Not a fork we can handle now (deeper than 1 block).
                            // Stop the batch and let the caller decide.
                            last_error = Some(AcceptError::PrevHashMismatch {
                                expected: node.last_hash(),
                                got: block.header.prev_hash,
                                height: node.height + 1,
                            });
                            break;
                        }
                        Err(e) => {
                            // Reorg failed — record and stop.
                            last_error = Some(AcceptError::Storage(format!(
                                "fork switch failed: {}",
                                e
                            )));
                            break;
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                    break;
                }
            }
        }

        let new_height = node.height;
        self.local_height = new_height;

        // Mirror into deprecated fields for backward-compat.
        if accepted > 0 {
            for block in &blocks[..accepted as usize] {
                let h = block.header.hash(&mut node.argon2);
                self.local_chain.push(block.header.clone());
                self.local_hashes.insert(h, node.block_hashes[&h]);
            }
        }

        if let Some(e) = last_error {
            // Return info for the caller to decide whether to ban.
            return Err(format!("{}: {}", accepted, e.describe()));
        }

        Ok(new_height)
    }

    pub fn compute_merkle_root(txs: &[Transaction], argon2: &mut Argon2Cache) -> Hash32 {
        if txs.is_empty() {
            return [0; 32];
        }

        let mut hashes: Vec<Hash32> = txs.iter().map(|tx| tx.txid(argon2)).collect();

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
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash);
                next.push(arr);
            }
            hashes = next;
        }
        hashes[0]
    }

    pub fn select_best_peer(&self) -> Option<(PeerId, Height, u64)> {
        let current_height = self.current_height();

        self.peers
            .iter()
            .filter(|(_, p)| !p.banned && p.height > current_height)
            .map(|(id, p)| (*id, p.height, p.latency_ms))
            .min_by_key(|(_, _, latency)| *latency)
            .or_else(|| {
                self.peers
                    .iter()
                    .filter(|(_, p)| !p.banned)
                    .map(|(id, p)| (*id, p.height, p.latency_ms))
                    .max_by_key(|(_, height, _)| *height)
            })
    }

    pub fn start_active_sync(
        &mut self,
        _storage: &ProductionStorage,
        _argon2: &mut Argon2Cache,
    ) -> Result<bool, String> {
        if self.sync_in_progress {
            return Ok(false);
        }

        let current_height = self.current_height();

        if let Some((peer_id, peer_height, _)) = self.select_best_peer() {
            if peer_height <= current_height {
                return Ok(false);
            }

            let from = current_height + 1;
            let to = peer_height.min(current_height + MAX_BLOCKS_PER_REQUEST as u64);

            self.active_session = Some(SyncSession {
                peer_id,
                from_height: from,
                target_height: peer_height,
                current_height,
                started_at: current_timestamp(),
                last_activity: current_timestamp(),
                blocks_received: 0,
                status: SyncStatus::Requesting,
            });

            self.sync_in_progress = true;
            self.last_sync_attempt = current_timestamp();

            println!(
                "🔄 Starting sync from height {} to {} via peer {:?}",
                from, to, peer_id
            );

            let _max_count = (to - from + 1) as u32;
            println!("   Would request {} blocks from peer", _max_count);

            return Ok(true);
        }

        Ok(false)
    }
}