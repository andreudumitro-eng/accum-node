//! RPC server (HTTP/JSON)

use crate::block::Transaction;
use crate::crypto::Argon2Cache;
use crate::format_duration;
use crate::p2p::P2PMessage;
use crate::types::current_timestamp;
use crate::node::Node;
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
            .and(warp::body::json())
            .and_then(move |tx_hex: String| {
                let node = send_node.clone();
                async move {
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

        let routes = info
            .or(block)
            .or(send_tx)
            .or(peers)
            .or(miners)
            .or(mempool)
            .or(health)
            .with(cors);

        println!("📡 RPC endpoints on port {}:", self.port);
        println!("   GET  /info       - node information");
        println!("   GET  /block/{{height}} - get block");
        println!("   POST /transaction - send transaction (hex)");
        println!("   GET  /peers      - list peers");
        println!("   GET  /miners     - list active miners");
        println!("   GET  /mempool    - list pending transactions");
        println!("   GET  /health     - health check");

        warp::serve(routes).run(([0, 0, 0, 0], self.port)).await;

        Ok(())
    }
}