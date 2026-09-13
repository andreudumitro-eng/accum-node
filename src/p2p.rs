//! P2P networking over TCP

use crate::block::{Block, BlockHeader, Transaction};
use crate::consensus::EquivocationProof;
use crate::constants::*;
use crate::crypto::Argon2Cache;
use crate::miner::Share;
use crate::network::DDoSProtection;
use crate::storage::{Checkpoint, ProductionStorage};
use crate::types::{current_timestamp, Hash32, Height, MinerId, OutPoint, PeerId, Timestamp};
use crate::wallet::Wallet;
use crate::node::Node;
use parking_lot::RwLock;
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

/// Проверка coinbase: сумма выходов coinbase ≤ block_reward + сумма fees.
fn validate_block_coinbase(block: &Block, storage: &ProductionStorage) -> Result<(), String> {
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
                return Err(format!(
                    "Double spend detected: {:?}",
                    outpoint
                ));
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
}

pub const MAX_MESSAGES_PER_HOUR: u32 = 1000;
pub const MAX_BLOCKS_PER_REQUEST: u32 = 500;
pub const MIN_VERSION: u32 = 1;
pub const MAX_VERSION: u32 = 1;

#[derive(Debug)]
pub struct PeerConnection {
    pub peer_id: PeerId,
    pub address: SocketAddr,
    pub stream: TcpStream,
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
        if current_time - self.last_hour_reset > 3600 {
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
        current_time - self.last_message_time > PEER_TIMEOUT_SECS
    }

    pub fn needs_heartbeat(&self, current_time: Timestamp) -> bool {
        current_time - self.last_heartbeat > 30
    }

    pub fn send_message(&mut self, msg: &P2PMessage) -> Result<(), std::io::Error> {
        if self.banned {
            return Ok(());
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
        let mut len_buf = [0u8; 4];

        match self.stream.read_exact(&mut len_buf) {
            Ok(()) => {
                let len = u32::from_le_bytes(len_buf) as usize;
                if len > MAX_MESSAGE_SIZE {
                    self.invalid_messages += 1;
                    self.ban("Message too large");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Message too large",
                    ));
                }

                let mut data = vec![0u8; len];
                self.stream.read_exact(&mut data)?;

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
                    P2PMessage::Heartbeat(nonce) => {
                        self.last_heartbeat = now;
                        let _ = self.send_message(&P2PMessage::Pong(*nonce));
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
                        ..
                    } => {
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
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn send_ping(&mut self) -> Result<(), std::io::Error> {
        let nonce = thread_rng().next_u64();
        self.ping_nonce = Some(nonce);
        self.send_message(&P2PMessage::Ping(nonce))
    }

    pub fn update_state(&mut self, height: Height, hash: Hash32) {
        self.height = Some(height);
        self.best_hash = Some(hash);
        self.last_message_time = current_timestamp();
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
    pub bootnodes: Vec<String>,
    pub node: Arc<RwLock<Node>>,
}

impl P2PNode {
    pub fn new(
        port: u16,
        bootnodes: Vec<String>,
        node: Arc<RwLock<Node>>,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
        listener.set_nonblocking(true)?;

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
            bootnodes,
            node,
        })
    }

    pub fn set_local_state(&mut self, height: Height, best_hash: Hash32) {
        self.local_height = height;
        self.local_best_hash = best_hash;
        self.sync_manager.set_chain(Vec::new(), HashMap::new());
        self.broadcast_version();
    }

    pub fn broadcast_version(&mut self) {
        for peer in self.peers.values_mut() {
            let msg = P2PMessage::Version {
                version: 1,
                timestamp: current_timestamp(),
                height: self.local_height,
                best_hash: self.local_best_hash,
                peer_id: peer.get_peer_id(),
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

                stream.set_nonblocking(true)?;
                let mut peer = PeerConnection::new(stream, addr);

                if self.banned_peers.contains(&peer.get_peer_id()) {
                    return Ok(());
                }

                let version_msg = P2PMessage::Version {
                    version: 1,
                    timestamp: current_timestamp(),
                    height: self.local_height,
                    best_hash: self.local_best_hash,
                    peer_id: peer.get_peer_id(),
                };
                let _ = peer.send_message(&version_msg);

                println!("✅ New peer connected: {}", addr);
                self.peers.insert(addr, peer);
                self.known_peers.insert(addr);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }

    pub fn process_messages(&mut self) -> Result<(), std::io::Error> {
        let now = current_timestamp();
        let mut disconnected = Vec::new();
        let mut messages_to_handle = Vec::new();

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
                        messages_to_handle.push((msg, *addr));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                        self.ddos_protection.record_failure(*addr);
                        disconnected.push(*addr);
                        break;
                    }
                }
            }
        }

        for (msg, addr) in messages_to_handle {
            self.handle_message(msg, addr);
        }

        for addr in disconnected {
            if let Some(peer) = self.peers.remove(&addr) {
                self.sync_manager.remove_peer(&peer.get_peer_id());
                println!("❌ Peer disconnected: {}", addr);
            }
        }

        Ok(())
    }

    pub fn handle_message(&mut self, msg: P2PMessage, addr: SocketAddr) {
        let peers_for_response = match &msg {
            P2PMessage::GetPeers => Some(self.peers.keys().copied().collect()),
            _ => None,
        };

        let peer = match self.peers.get_mut(&addr) {
            Some(p) => p,
            None => return,
        };

        match msg {
            P2PMessage::Version {
                version: _,
                timestamp,
                height,
                best_hash,
                peer_id,
            } => {
                let latency = (current_timestamp() - timestamp) as u64;
                self.sync_manager
                    .update_peer(peer_id, addr, height, best_hash, latency);
                peer.update_state(height, best_hash);
                let _ = peer.send_message(&P2PMessage::Verack);
            }
            P2PMessage::Verack => {}
            P2PMessage::Ping(nonce) => {
                let _ = peer.send_message(&P2PMessage::Pong(nonce));
            }
            P2PMessage::Pong(_) => {}
            P2PMessage::GetBlocks {
                from_height,
                max_count,
            } => {
                let mut node = self.node.write();
                let mut blocks = Vec::new();
                let end = from_height.saturating_add(max_count as u64);
                for h in from_height..end {
                    if let Ok(Some(block)) = node.storage.get_block(h) {
                        blocks.push(block);
                    } else {
                        break;
                    }
                }
                if !blocks.is_empty() {
                    let _ = peer.send_message(&P2PMessage::Blocks(blocks));
                }
            }
            P2PMessage::Blocks(blocks) => {
                let peer_id = peer.get_peer_id();

                let verification_result = {
                    let mut node = self.node.write();
                    self.sync_manager
                        .verify_and_accept_blocks(&blocks, &mut node)
                };

                match verification_result {
                    Ok(new_height) => {
                        let mut node = self.node.write();
                        node.height = new_height;
                        self.local_height = new_height;
                        if let Some(last) = blocks.last() {
                            self.local_best_hash = last.header.hash(&mut node.argon2);
                        }

                        let _ = self.sync_manager.on_blocks_received(&blocks, &peer_id);

                        println!(
                            "✅ Synced and stored {} blocks, new height: {}",
                            blocks.len(),
                            new_height
                        );
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to verify and store blocks: {}", e);
                        peer.ban(&format!("Invalid blocks: {}", e));
                    }
                }
            }
            P2PMessage::Share(share) => {
                let accepted = {
                    let mut node = self.node.write();
                    node.add_share(share.clone())
                };

                if accepted {
                    let msg = P2PMessage::Share(share);
                    for (peer_addr, peer) in self.peers.iter_mut() {
                        if *peer_addr != addr && !peer.is_banned() {
                            let _ = peer.send_message(&msg);
                        }
                    }
                }
            }
            P2PMessage::Block {
                header,
                transactions,
                signature,
                pubkey,
            } => {
                let mut node = self.node.write();

                let expected_height = node.height + 1;
                let prev_hash = node.last_hash();

                if header.prev_hash != prev_hash {
                    return;
                }

                let hash = header.hash(&mut node.argon2);
                if !header.difficulty.is_met_by(&hash) {
                    println!("⚠️ Received invalid block (PoW failed)");
                    return;
                }
                
                if let Some(cp) = node.checkpoint_at(expected_height) {
                    if hash != cp.block_hash {
                        println!(
                            "⚠️ Block hash conflicts with checkpoint at height {}",
                            expected_height
                        );
                        return;
                    }
                }
                                // Long-range protection
                                if let Some(cp) = node.checkpoint_at(expected_height) {
                                    if hash != cp.block_hash {
                                        println!(
                                            "⚠️ Block hash conflicts with checkpoint at height {}",
                                            expected_height
                                        );
                                        return;
                                    }
                                }                

                // Проверка подписи (если она есть — обязательна)
                if let (Some(sig), Some(pk)) = (&signature, &pubkey) {
                    if !Wallet::verify_signature(pk, sig, &hash) {
                        println!("⚠️ Received block with invalid signature");
                        return;
                    }
                } else {
                    println!("⚠️ Received block without signature");
                    return;
                }
                
                                // Проверка timestamp с median
                                let prev_timestamp = if node.height > 0 {
                                    node.blocks.last().map(|b| b.timestamp)
                                } else {
                                    None
                                };
                                let median = node.median_timestamp();
                                if !header.validate_timestamp(prev_timestamp, median) {
                                    println!("⚠️ Received block with invalid timestamp");
                                    return;
                                }
                

                                // Проверка merkle root
                                let computed_root =
                                SyncManager::compute_merkle_root(&transactions, &mut node.argon2);
                            if header.merkle_root != computed_root {
                                println!("⚠️ Received block with invalid merkle root");
                                return;
                            }
            
                            let block = Block {
                                header: header.clone(),
                                transactions: transactions.clone(),
                                signature,
                                pubkey,
                            };
            
                            // Проверка coinbase ≤ reward + fees
                            if let Err(e) = validate_block_coinbase(&block, &node.storage) {
                                println!("⚠️ Received block with invalid coinbase: {}", e);
                                return;
                            }

                            // Проверка double-spend
                if let Err(e) = validate_block_no_double_spend(&block) {
                    println!("⚠️ Received block with double spend: {}", e);
                    return;
                }

                let new_height = expected_height;
                if let Err(e) = node.storage.save_block(new_height, &block) {
                    println!("❌ Failed to save received block: {}", e);
                    return;
                }

                node.blocks.push(header.clone());
                node.block_hashes.insert(hash, new_height);
                node.timestamps.push(header.timestamp);
                node.height = new_height;

                node.update_utxo_set(&block);

                let mut txids_in_block = HashSet::new();
                for tx in &block.transactions {
                    if !tx.is_coinbase() {
                        let txid = tx.txid(&mut node.argon2);
                        txids_in_block.insert(txid);
                        node.processed_txids.insert(txid);
                    }
                }

                node.mempool.retain(|tx| {
                    let mut argon2 = Argon2Cache::new(10);
                    let txid = tx.txid(&mut argon2);
                    !txids_in_block.contains(&txid)
                });

                let _ = node.storage.save_state("height", &node.height);
                let _ = node.storage.save_mempool(&node.mempool);

                self.local_height = new_height;
                self.local_best_hash = hash;

                println!("📥 Received and accepted block #{}", new_height);

                let msg = P2PMessage::Block {
                    header: header.clone(),
                    transactions: block.transactions.clone(),
                    signature: block.signature.clone(),
                    pubkey: block.pubkey.clone(),
                };

                for (peer_addr, peer) in self.peers.iter_mut() {
                    if *peer_addr != addr && !peer.is_banned() {
                        let _ = peer.send_message(&msg);
                    }
                }
            }
            P2PMessage::EpochCommit { .. } => {}
            P2PMessage::GetMempool => {}
            P2PMessage::Mempool(_txs) => {}
            P2PMessage::Transaction(tx) => {
                let accepted = {
                    let mut node = self.node.write();
                    match node.add_transaction_to_mempool(tx.clone()) {
                        Ok(()) => true,
                        Err(_) => false,
                    }
                };

                if accepted {
                    let msg = P2PMessage::Transaction(tx);
                    for (peer_addr, peer) in self.peers.iter_mut() {
                        if *peer_addr != addr && !peer.is_banned() {
                            let _ = peer.send_message(&msg);
                        }
                    }
                }
            }
            P2PMessage::GetPeers => {
                if let Some(peers) = peers_for_response {
                    let _ = peer.send_message(&P2PMessage::Peers(peers));
                }
            }
            P2PMessage::Peers(peers) => {
                for p in peers {
                    if !self.known_peers.contains(&p) && !self.peers.contains_key(&p) {
                        self.known_peers.insert(p);
                        if self.peers.len() < MAX_PEERS {
                            let _ = self.connect_to(p);
                        }
                    }
                }
            }
            P2PMessage::BanPeer { peer_id, reason } => {
                if peer_id == peer.get_peer_id() {
                    peer.ban(&reason);
                }
            }
            P2PMessage::SlashProof { .. } => {}
            P2PMessage::Checkpoint(_) => {}
            P2PMessage::SyncRequest { .. } => {}
            P2PMessage::SyncResponse(_blocks) => {}
            P2PMessage::Heartbeat(nonce) => {
                let _ = peer.send_message(&P2PMessage::Pong(nonce));
            }
        }
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
        stream.set_nonblocking(true)?;
        let mut peer = PeerConnection::new(stream, addr);

        let version_msg = P2PMessage::Version {
            version: 1,
            timestamp: current_timestamp(),
            height: self.local_height,
            best_hash: self.local_best_hash,
            peer_id: peer.get_peer_id(),
        };

        let _ = peer.send_message(&version_msg);

        self.peers.insert(addr, peer);
        self.known_peers.insert(addr);

        Ok(())
    }

    pub fn connect_to_bootnodes(&mut self) {
        let bootnodes = self.bootnodes.clone();
        for bootnode in bootnodes {
            if let Ok(addr) = bootnode.parse() {
                let _ = self.connect_to(addr);
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
    pub local_chain: Vec<BlockHeader>,
    pub local_hashes: HashMap<Hash32, Height>,
    pub sync_in_progress: bool,
    pub last_sync_attempt: Timestamp,
    pub pending_blocks: Vec<Block>,
    pub last_request_time: Timestamp,
    pub retry_count: HashMap<PeerId, u32>,
    pub sync_complete_height: Height,
    pub send_message_callback:
        Option<Box<dyn FnMut(&PeerId, P2PMessage) -> Result<(), String> + Send + Sync>>,
}

impl SyncManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            active_session: None,
            local_chain: Vec::new(),
            local_hashes: HashMap::new(),
            sync_in_progress: false,
            last_sync_attempt: 0,
            pending_blocks: Vec::new(),
            last_request_time: 0,
            retry_count: HashMap::new(),
            sync_complete_height: 0,
            send_message_callback: None,
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
        let current_height = self.local_chain.len() as Height;

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
        let current_height = self.local_chain.len() as Height;
        let best_peer_height = self
            .peers
            .values()
            .filter(|p| !p.banned)
            .map(|p| p.height)
            .max()
            .unwrap_or(current_height);

        let now = current_timestamp();
        let sync_timeout = now - self.last_sync_attempt > SYNC_TIMEOUT_SECS;

        best_peer_height > current_height && (self.active_session.is_none() || sync_timeout)
    }

    pub fn start_sync(&mut self, peer: SyncPeer) -> bool {
        if self.sync_in_progress {
            return false;
        }

        let current_height = self.local_chain.len() as Height;

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

        println!(
            "🔄 Starting sync from height {} to {} with peer {}...",
            current_height, peer.height, peer.address
        );

        true
    }

    pub fn on_blocks_received(&mut self, blocks: &[Block], peer_id: &PeerId) -> Result<Height, String> {
        if let Some(session) = self.active_session.as_mut() {
            if session.peer_id != *peer_id {
                return Err("Wrong peer".to_string());
            }

            if blocks.is_empty() {
                session.status = SyncStatus::Completed;
                self.sync_in_progress = false;
                return Ok(session.current_height);
            }

            session.blocks_received += blocks.len() as u32;
            session.last_activity = current_timestamp();
            session.status = SyncStatus::Receiving;

            for block in blocks {
                session.current_height += 1;
                self.local_chain.push(block.header.clone());
                let mut argon2 = Argon2Cache::new(100);
                self.local_hashes
                    .insert(block.header.hash(&mut argon2), session.current_height);
            }

            if session.current_height >= session.target_height {
                session.status = SyncStatus::Completed;
                self.sync_in_progress = false;
                println!("✅ Sync completed! Height: {}", session.current_height);
            } else {
                session.status = SyncStatus::Requesting;
            }

            return Ok(session.current_height);
        }

        Err("No active sync session".to_string())
    }

    pub fn check_timeouts(&mut self) -> Option<PeerId> {
        let now = current_timestamp();

        if let Some(session) = self.active_session.as_mut() {
            if now - session.last_activity > SYNC_TIMEOUT_SECS {
                println!("⚠️ Sync timeout with peer");
                session.status = SyncStatus::Failed("Timeout".to_string());

                if let Some(peer) = self.peers.get_mut(&session.peer_id) {
                    peer.retries += 1;
                    if peer.retries >= 3 {
                        peer.banned = true;
                        println!("🚫 Peer {} banned due to sync failures", peer.address);
                    }
                }

                self.sync_in_progress = false;
                return Some(session.peer_id);
            }
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
            let total = session.target_height - session.from_height;
            let current = session.current_height - session.from_height;
            if total > 0 {
                return current as f64 / total as f64;
            }
        }
        self.best_peer_height().map_or(1.0, |best| {
            let current = self.local_chain.len() as Height;
            if best > current {
                current as f64 / best as f64
            } else {
                1.0
            }
        })
    }

    pub fn is_syncing(&self) -> bool {
        self.sync_in_progress
    }

    pub fn current_height(&self) -> Height {
        self.local_chain.len() as Height
    }

    pub fn request_blocks(
        &mut self,
        peer_id: &PeerId,
        from: Height,
        to: Height,
    ) -> Result<(), String> {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            if peer.banned {
                return Err("Peer is banned".to_string());
            }

            let max_count = (to - from).min(MAX_BLOCKS_PER_REQUEST as u64) as u32;

            if let Some(callback) = &mut self.send_message_callback {
                let msg = P2PMessage::GetBlocks {
                    from_height: from,
                    max_count: max_count,
                };
                callback(peer_id, msg)?;
            }

            println!(
                "📤 Requested blocks {}..{} from peer {}",
                from,
                from + max_count as u64,
                peer.address
            );
            Ok(())
        } else {
            Err("Peer not found".to_string())
        }
    }

    pub fn request_blocks_from_peer(
        &mut self,
        peer_id: &PeerId,
        from_height: Height,
    ) -> Result<(), String> {
        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| "Peer not found in sync manager".to_string())?;

        if peer.banned {
            return Err("Peer is banned".to_string());
        }

        let now = current_timestamp();
        if now - self.last_request_time < 5 && self.sync_in_progress {
            return Err("Too frequent requests".to_string());
        }

        let max_height = peer.height;
        let to_height = (from_height + SYNC_BATCH_SIZE - 1).min(max_height);
        let count = (to_height - from_height + 1) as u32;

        if count == 0 {
            return Err("No blocks to request".to_string());
        }

        let retries = self.retry_count.entry(*peer_id).or_insert(0);
        if *retries >= SYNC_MAX_RETRIES {
            return Err("Peer has too many retries".to_string());
        }

        if let Some(callback) = &mut self.send_message_callback {
            let msg = P2PMessage::GetBlocks {
                from_height,
                max_count: count,
            };

            callback(peer_id, msg)?;

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

            Ok(())
        } else {
            Err("No send callback configured".to_string())
        }
    }

    pub fn verify_and_accept_blocks(
        &mut self,
        blocks: &[Block],
        node: &mut Node,
    ) -> Result<Height, String> {
        let mut new_height = self.current_height();

        for (idx, block) in blocks.iter().enumerate() {
            let expected_height = new_height + 1;

            let expected_prev = if expected_height == 1 {
                [0; 32]
            } else {
                let prev_block = node
                    .storage
                    .get_block(expected_height - 1)?
                    .ok_or("Previous block not found")?;
                prev_block.header.hash(&mut node.argon2)
            };

            if block.header.prev_hash != expected_prev {
                return Err(format!("Invalid prev_hash at height {}", expected_height));
            }

            let block_hash = block.header.hash(&mut node.argon2);
            if !block.header.difficulty.is_met_by(&block_hash) {
                return Err(format!(
                    "Block hash doesn't meet difficulty at height {}",
                    expected_height
                ));
            }

            if let Some(cp) = node.checkpoint_at(expected_height) {
                if block_hash != cp.block_hash {
                    return Err(format!(
                        "Block hash at height {} conflicts with checkpoint",
                        expected_height
                    ));
                }
            }

            let prev_timestamp = if expected_height > 1 {
                let prev_block = node
                    .storage
                    .get_block(expected_height - 1)?
                    .ok_or("Previous block not found")?;
                Some(prev_block.header.timestamp)
            } else {
                None
            };

            let median = node.median_timestamp();

            if !block.header.validate_timestamp(prev_timestamp, median) {
                return Err(format!("Invalid timestamp at height {}", expected_height));
            }

            let computed_root = Self::compute_merkle_root(&block.transactions, &mut node.argon2);
            if block.header.merkle_root != computed_root {
                return Err(format!("Invalid merkle root at height {}", expected_height));
            }

            validate_block_coinbase(block, &node.storage)?;
            validate_block_no_double_spend(block)?;

            match (&block.signature, &block.pubkey) {
                (Some(sig), Some(pubkey)) => {
                    if !Wallet::verify_signature(pubkey, sig, &block_hash) {
                        return Err(format!(
                            "Invalid block signature at height {}",
                            expected_height
                        ));
                    }
                }
                _ => {
                    return Err(format!(
                        "Missing block signature at height {}",
                        expected_height
                    ));
                }
            }

            node.storage.save_block(expected_height, block)?;
            Self::update_utxo_set(&node.storage, block, &mut node.argon2)?;

            // Обновляем состояние ноды — критично для median timestamp
            // и для корректного last_hash() после sync.
            node.blocks.push(block.header.clone());
            node.block_hashes.insert(block_hash, expected_height);
            node.timestamps.push(block.header.timestamp);

            self.local_chain.push(block.header.clone());
            self.local_hashes.insert(block_hash, expected_height);

            new_height = expected_height;

            if idx == blocks.len() - 1 {
                println!(
                    "✅ Verified and accepted {} blocks, new height: {}",
                    blocks.len(),
                    new_height
                );
            }
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

    pub fn update_utxo_set(
        storage: &ProductionStorage,
        block: &Block,
        argon2: &mut Argon2Cache,
    ) -> Result<(), String> {
        for tx in &block.transactions {
            let txid = tx.txid(argon2);

            for (i, output) in tx.outputs.iter().enumerate() {
                let outpoint = (txid, i as u32);
                storage.save_utxo(&outpoint, output)?;
            }

            for input in &tx.inputs {
                if !input.is_coinbase() {
                    storage.delete_utxo(&input.outpoint())?;
                }
            }
        }
        Ok(())
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

            if let Some(_peer) = self.peers.get_mut(&peer_id) {
                let max_count = (to - from + 1) as u32;
                println!("   Would request {} blocks from peer", max_count);
            }

            return Ok(true);
        }

        Ok(false)
    }
}