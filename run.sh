#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PORT="${ACCUM_DASHBOARD_PORT:-8555}"
echo "🔨 Building ACCUM (release)..."
cargo build --release
BIN="./target/release/accum-node"
if [ ! -x "$BIN" ]; then
  echo "❌ Не найден бинарник в ./target/release"
  exit 1
fi
echo "🚀 Starting node with dashboard on http://127.0.0.1:${PORT}"
exec "$BIN" node --dashboard --dashboard-port "$PORT"