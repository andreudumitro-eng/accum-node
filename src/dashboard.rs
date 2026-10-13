//! Web dashboard for ACCUM node.

use crate::node::Node;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
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

    Json(json!({
        "height": n.height,
        "epoch": n.epoch,
        "peers": peers,
        "is_syncing": is_syncing,
        "difficulty": n.last_difficulty().to_difficulty(),
        "hash_rate": n.last_hash_rate,
        "peak_hash_rate": n.peak_hash_rate,
        "miners": miners_count,
        "bonds": bonds_count,
        "shares_found": n.share_pool.total_shares_count(),
        "wallet": {
            "address": wallet_address,
            "miner_id": wallet_miner_id,
            "balance": balance,
            "utxo_count": utxo_count,
            "bond": own_bond,
        },
    }))
}