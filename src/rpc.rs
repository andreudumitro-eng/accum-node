//! RPC server (HTTP/JSON)

use crate::block::Transaction;
use crate::crypto::Argon2Cache;
use crate::format_duration;
use crate::node::Node;
use crate::p2p::P2PMessage;
use crate::types::current_timestamp;
use bytes::Bytes;
use parking_lot::RwLock;
use std::sync::Arc;
use warp::Filter;

pub struct RpcServer {
    pub node: Arc<RwLock<Node>>,
    pub port: u16,
}

impl RpcServer {
    pub fn new(node: Arc<RwLock<Node>>, port: u16) -> Self {
        Self { node, port }
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let node_info = self.node.clone();
        let node_block = self.node.clone();
        let node_send = self.node.clone();
        let node_peers = self.node.clone();
        let node_miners = self.node.clone();

        let cors = warp::cors()
            .allow_any_origin()
            .allow_methods(vec!["GET", "POST"])
            .allow_headers(vec!["Content-Type"]);

        let info_node = node_info.clone();
        let info = warp::path("info").and(warp::get()).map(move || {
            let node = info_node.read();
            let uptime = current_timestamp() - node.start_time;
            let (cache_hits, cache_misses, avg_time) = node.argon2.stats();
            let cache_hit_rate = if cache_hits + cache_misses > 0 {
                (cache_hits as f64 / (cache_hits + cache_misses) as f64 * 100.0) as u64
            } else {
                0
            };

            // Среднее время блока за последние 10
            let avg = if node.timestamps.len() >= 2 {
                let take = 10.min(node.timestamps.len() - 1);
                let start = node.timestamps[node.timestamps.len() - 1 - take];
                let end = *node.timestamps.last().unwrap();
                (end.saturating_sub(start)) as f64 / take as f64
            } else {
                0.0
            };

            let now = crate::types::current_timestamp();
            let since_last =
                now.saturating_sub(node.blocks.last().map(|b| b.timestamp).unwrap_or(now));

            let difficulty = node
                .blocks
                .last()
                .map(|b| b.difficulty.to_difficulty())
                .unwrap_or(1.0);

            warp::reply::json(&serde_json::json!({
                "height": node.height,
                "epoch": node.epoch,
                "blocks_found": node.blocks_found,
                "shares_found": node.shares_found,
                "miners": node.miners.len(),
                "peers": node.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0),
                "hash_rate": node.last_hash_rate,
                "peak_hash_rate": node.peak_hash_rate,
                "uptime_secs": uptime,
                "uptime_formatted": format_duration(uptime),
                "cache_hit_rate": cache_hit_rate,
                "mempool_size": node.mempool.len(),
                "bond": node.miners.get(&node.miner_id).map(|m| m.bond).unwrap_or(0),
                "argon2_avg_ms": avg_time,
                // НОВЫЕ ПОЛЯ:
                "last_block_nonce": node.last_nonce,
                "last_block_time_secs": node.last_block_time_secs,
                "avg_block_time_secs": (avg * 100.0).round() / 100.0,
                "seconds_since_last_block": since_last,
                "difficulty": (difficulty * 100.0).round() / 100.0,
            }))
        });

        let block_node = node_block.clone();
        let block = warp::path("block")
            .and(warp::path::param::<u64>())
            .and(warp::get())
            .map(move |height: u64| {
                let mut node = block_node.write();
                if let Ok(Some(block)) = node.storage.get_block(height) {
                    let hash = block.header.hash(&mut node.argon2);
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({
                            "height": height,
                            "hash": hex::encode(&hash[0..16]),
                            "timestamp": block.header.timestamp,
                            "difficulty": block.header.difficulty.to_difficulty(),
                            "transactions": block.transactions.len(),
                            "nonce": block.header.nonce,
                            "prev_hash": hex::encode(&block.header.prev_hash[0..16]),
                        })),
                        warp::http::StatusCode::OK,
                    )
                } else {
                    warp::reply::with_status(
                        warp::reply::json(&serde_json::json!({ "error": "Block not found" })),
                        warp::http::StatusCode::NOT_FOUND,
                    )
                }
            });

        let send_node = node_send.clone();
        let send_tx = warp::path("transaction")
                .and(warp::post())
                .and(warp::body::bytes())
                .and_then(move |body: bytes::Bytes| {
                    let node = send_node.clone();
                    async move {
                        let tx_hex = match std::str::from_utf8(&body) {
                            Ok(s) => s.trim().to_string(),
                            Err(e) => {
                                return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({ "error": format!("Invalid UTF-8: {}", e) })),
                                    warp::http::StatusCode::BAD_REQUEST,
                                ));
                            }
                        };
    
                        let tx_data = match hex::decode(&tx_hex) {
                            Ok(d) => d,
                            Err(e) => {
                                return Ok::<_, warp::Rejection>(warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({ "error": format!("Invalid hex: {}", e) })),
                                    warp::http::StatusCode::BAD_REQUEST,
                                ));
                            }
                        };
    
                        let mut node = node.write();
    
                        match bincode::deserialize::<Transaction>(&tx_data) {
                            Ok(tx) => {
                                let txid = tx.txid(&mut node.argon2);
                                let tx_clone = tx.clone();
    
                                match node.add_transaction_to_mempool(tx) {
                                    Ok(()) => {
                                        if let Some(p2p) = &mut node.p2p {
                                            p2p.broadcast(&P2PMessage::Transaction(tx_clone));
                                        }
                                        Ok(warp::reply::with_status(
                                            warp::reply::json(&serde_json::json!({
                                                "status": "ok",
                                                "txid": hex::encode(txid),
                                            })),
                                            warp::http::StatusCode::OK,
                                        ))
                                    }
                                    Err(e) => {
                                        Ok(warp::reply::with_status(
                                            warp::reply::json(&serde_json::json!({ "error": e })),
                                            warp::http::StatusCode::BAD_REQUEST,
                                        ))
                                    }
                                }
                            }
                            Err(e) => {
                                Ok(warp::reply::with_status(
                                    warp::reply::json(&serde_json::json!({ "error": format!("Invalid transaction data: {}", e) })),
                                    warp::http::StatusCode::BAD_REQUEST,
                                ))
                            }
                        }
                    }
                });

        let peers_node = node_peers.clone();
        let peers = warp::path("peers").and(warp::get()).map(move || {
            let node = peers_node.read();
            let peers_info: Vec<_> = node
                .p2p
                .as_ref()
                .map(|p| p.get_peers_info())
                .unwrap_or_default();
            warp::reply::json(&serde_json::json!({
                "peers": peers_info,
                "total": peers_info.len(),
            }))
        });

        let miners_node = node_miners.clone();
        let miners = warp::path("miners").and(warp::get()).map(move || {
            let node = miners_node.read();
            let miners_list: Vec<_> = node
                .miners
                .iter()
                .map(|(id, data)| {
                    serde_json::json!({
                        "miner_id": hex::encode(id),
                        "shares": data.shares,
                        "bond": data.bond,
                        "loyalty": data.loyalty,
                        "blocks_found": data.blocks_found,
                        "invalid_ratio": data.invalid_ratio,
                        "last_share": data.last_share_time,
                    })
                })
                .collect();

            warp::reply::json(&serde_json::json!({
                "miners": miners_list,
                "total": miners_list.len(),
            }))
        });

        let balance_node = self.node.clone();
        let utxos_node = self.node.clone();
        let utxos = warp::path!("utxos" / String)
            .and(warp::get())
            .map(move |address: String| {
                let node = utxos_node.read();
                match node.storage.get_utxos_by_address(&address) {
                    Ok(list) => {
                        let json_list: Vec<_> = list.iter().map(|((txid, index), txout)| {
                            serde_json::json!({
                                "txid": hex::encode(txid),
                                "index": index,
                                "value": txout.value,
                                "script_pubkey": hex::encode(&txout.script_pubkey),
                            })
                        }).collect();
                        warp::reply::json(&serde_json::json!({ "utxos": json_list }))
                    }
                    Err(e) => warp::reply::json(&serde_json::json!({ "error": e })),
                }
            });

        let balance = warp::path("balance")
            .and(warp::path::param::<String>())
            .and(warp::get())
            .map(move |address: String| {
                let node = balance_node.read();
                match node.storage.get_utxos_by_address(&address) {
                    Ok(utxos) => {
                        let total: u64 = utxos.iter().map(|(_, txout)| txout.value).sum();
                        warp::reply::json(&serde_json::json!({
                            "address": address,
                            "balance": total,
                            "utxo_count": utxos.len(),
                        }))
                    }
                    Err(e) => warp::reply::json(&serde_json::json!({
                        "address": address,
                        "error": e,
                        "balance": 0,
                        "utxo_count": 0,
                    })),
                }
            });

        let mempool_node = self.node.clone();
        let mempool = warp::path("mempool").and(warp::get()).map(move || {
            let node = mempool_node.read();
            let txs: Vec<_> = node
                .mempool
                .iter()
                .map(|tx: &Transaction| {
                    let mut argon2 = Argon2Cache::new(100);
                    serde_json::json!({
                        "txid": hex::encode(tx.txid(&mut argon2)),
                        "size": tx.serialize().len(),
                        "fee": tx.fee(&node.storage).unwrap_or(0),
                    })
                })
                .collect();

            warp::reply::json(&serde_json::json!({
                "transactions": txs,
                "total": txs.len(),
            }))
        });

        let health_node = node_info.clone();
        let health = warp::path("health").and(warp::get()).map(move || {
            let node = health_node.read();
            let is_synced = node.sync_progress() >= 0.99;
            warp::reply::json(&serde_json::json!({
                "status": if is_synced { "ok" } else { "syncing" },
                "height": node.height,
                "peers": node.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0),
                "sync_progress": node.sync_progress(),
            }))
        });

        let stop_node = node_info.clone();
        let mining_stop = warp::path!("mining" / "stop")
            .and(warp::post())
            .map(move || {
                let node = stop_node.read();
                node.mining_paused
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                println!("⏹️  Mining stopped via RPC");
                warp::reply::json(&serde_json::json!({
                    "status": "stopped",
                }))
            });

        let pause_node = node_info.clone();
        let mining_pause = warp::path!("mining" / "pause")
            .and(warp::post())
            .map(move || {
                let node = pause_node.read();
                node.mining_paused
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                println!("⏸️  Mining paused via RPC");
                warp::reply::json(&serde_json::json!({
                    "status": "paused",
                }))
            });

        let start_node = node_info.clone();
        let mining_start = warp::path!("mining" / "start")
            .and(warp::post())
            .map(move || {
                let node = start_node.read();
                node.mining_paused
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                println!("▶️  Mining resumed via RPC");
                warp::reply::json(&serde_json::json!({
                    "status": "running",
                }))
            });

                    // /attacks — real attack-detection telemetry
        let attacks_node = self.node.clone();
        let attacks = warp::path("attacks").and(warp::get()).map(move || {
            let node = attacks_node.read();
            let now = current_timestamp();

            let (banned_ips, rate_limit_entries, global_req, attack_mode, global_rate) =
                if let Some(p2p) = node.p2p.as_ref() {
                    let d = &p2p.ddos_protection;
                    (d.ip_blacklist.len(),
                     d.rate_limits.len(),
                     d.global_request_count,
                     d.attack_mode,
                     d.global_rate())
                } else {
                    (0, 0, 0, false, 0.0)
                };

            let ad = &node.attack_detection;
            let attack_detected = ad.attack_detected;
            let attack_type = ad.attack_type.clone().unwrap_or_else(|| "none".to_string());
            let suspicious_peers = ad.suspicious_peers.len();
            let hash_history_len = ad.hash_rate_history.len();

            let mut total_invalid_ratio = 0.0f64;
            let mut banned_miners = 0usize;
            for m in node.miners.values() {
                total_invalid_ratio += m.invalid_ratio;
                if m.is_banned(now) { banned_miners += 1; }
            }
            let avg_invalid = if node.miners.is_empty() { 0.0 } else { total_invalid_ratio / node.miners.len() as f64 };

            let (peers, known_peers, banned_peer_ids) = if let Some(p2p) = node.p2p.as_ref() {
                (p2p.peer_count(), p2p.known_peers.len(), p2p.banned_peers.len())
            } else {
                (0, 0, 0)
            };

            let miners_cnt = node.miners.len().max(1) as f64;
            let sybil_score = ((peers as f64 / miners_cnt) / 5.0).min(1.0);

            warp::reply::json(&serde_json::json!({
                "attack_detected": attack_detected,
                "attack_type": attack_type,
                "banned_ips": banned_ips,
                "rate_limit_entries": rate_limit_entries,
                "global_request_count": global_req,
                "global_rate_per_sec": (global_rate * 100.0).round() / 100.0,
                "attack_mode": attack_mode,
                "peers": peers,
                "known_peers": known_peers,
                "banned_peer_ids": banned_peer_ids,
                "suspicious_peers": suspicious_peers,
                "avg_invalid_ratio": (avg_invalid * 10000.0).round() / 10000.0,
                "banned_miners": banned_miners,
                "sybil_score": (sybil_score * 100.0).round() / 100.0,
                "hash_history_points": hash_history_len,
                "timestamp": now,
            }))
        });

        let routes = info
            .or(block)
            .or(send_tx)
            .or(peers)
            .or(miners)
            .or(balance)
            .or(utxos)
            .or(mempool)
            .or(health)
            .or(attacks)
            .or(mining_pause)
            .or(mining_start)
            .or(mining_stop);

        println!("📡 RPC endpoints on port {}:", self.port);
        println!("   GET  /info       - node information");
        println!("   GET  /block/{{height}} - get block");
        println!("   POST /transaction - send transaction (hex)");
        println!("   GET  /peers      - list peers");
        println!("   GET  /miners     - list active miners");
        println!("   GET  /mempool    - list pending transactions");
        println!("   GET  /health     - health check");
        println!("   POST /mining/pause - pause mining");
        println!("   POST /mining/start - resume mining");

        warp::serve(routes).run(([0, 0, 0, 0], self.port)).await;

        Ok(())
    }
}






