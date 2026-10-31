//! Web dashboard for ACCUM node.

use crate::node::Node;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use parking_lot::RwLock;
use serde_json::json;
use std::sync::Arc;

pub type SharedNode = Arc<RwLock<Node>>;

pub fn start(node: SharedNode, port: u16) {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(index))
            .route("/api/info", get(api_info))
            .route("/api/logs", get(api_logs))
            .route("/api/mining/pause", post(proxy_mining_pause))
            .route("/api/mining/stop", post(proxy_mining_stop))
            .route("/api/mining/start", post(proxy_mining_start))
            .with_state(node);

        let addr = format!("0.0.0.0:{}", port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                println!("🌐 Dashboard started on http://{}", addr);
                if let Err(e) = axum::serve(listener, app).await {
                    eprintln!("❌ Dashboard server error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("❌ Failed to bind dashboard on {}: {}", addr, e);
            }
        }
    });
}

async fn index() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn api_info(State(node): State<SharedNode>) -> impl IntoResponse {
    let n = node.read();

    let peers = n.p2p.as_ref().map(|p| p.peer_count()).unwrap_or(0);
    let is_syncing = n.p2p.as_ref().map(|p| p.is_syncing()).unwrap_or(false);

    let miners_count = n.miners.len();
    let bonds_count = n.bonds.len();

    let (wallet_address, wallet_miner_id) = match &n.wallet {
        Some(w) => (w.address.clone(), hex::encode(&w.miner_id[0..8])),
        None => (String::new(), String::new()),
    };

    let (balance, utxo_count) = if !wallet_address.is_empty() {
        n.storage
            .get_balance_by_address(&wallet_address)
            .unwrap_or((0, 0))
    } else {
        (0, 0)
    };

    let own_bond = n
        .bonds
        .get(&n.miner_id)
        .map(|b| b.amount)
        .unwrap_or(0);

        let sync_progress = n.p2p.as_ref().map(|p| p.sync_progress()).unwrap_or(1.0);
    let is_syncing = n.p2p.as_ref().map(|p| p.is_syncing()).unwrap_or(false);

    Json(json!({
                "height": n.height,
        "epoch": n.epoch,
        "peers": peers,
        "is_syncing": is_syncing,
        "uptime_formatted": "—",
        "last_block_time": n.last_block_time_secs,
        "blocks_mined": n.blocks_found,
        "contribution": n.share_pool.total_shares_count(),
        "difficulty": n.last_difficulty().to_difficulty(),
        "hash_rate": n.last_hash_rate,
        "peak_hash_rate": n.peak_hash_rate,
        "miners": miners_count,
        "bonds": bonds_count,
        "shares_found": n.share_pool.total_shares_count(),
        "mining_paused": n.mining_paused.load(std::sync::atomic::Ordering::Relaxed),
                "sync_progress": sync_progress,
        "is_syncing": is_syncing,
        "wallet": {
            "address": wallet_address,
            "miner_id": wallet_miner_id,
            "balance": balance,
            "utxo_count": utxo_count,
            "bond": own_bond,
        },
    }))
}

async fn api_logs(State(node): State<SharedNode>) -> impl IntoResponse {
    let n = node.read();
    Json(n.recent_logs.clone())
}

// ---- Proxies to the RPC on port 8545 ----

async fn proxy_mining_pause() -> impl IntoResponse {
    proxy_post("http://127.0.0.1:8545/mining/pause").await
}

async fn proxy_mining_stop() -> impl IntoResponse {
    proxy_post("http://127.0.0.1:8545/mining/stop").await
}

async fn proxy_mining_start() -> impl IntoResponse {
    proxy_post("http://127.0.0.1:8545/mining/start").await
}

async fn proxy_post(url: &str) -> Json<serde_json::Value> {
    match reqwest::Client::new().post(url).send().await {
        Ok(resp) => {
            match resp.json::<serde_json::Value>().await {
                Ok(v) => Json(v),
                Err(e) => Json(json!({ "error": format!("parse: {}", e) })),
            }
        }
        Err(e) => Json(json!({ "error": format!("request: {}", e) })),
    }
}


