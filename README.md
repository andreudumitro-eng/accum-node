<div align="center">

# ACCUM
### Fair Proof-of-Contribution (F-PoC) Blockchain Protocol

[![Version](https://img.shields.io/badge/version-3.2%2B-blueviolet?style=for-the-badge)](https://github.com/andreudumitro-eng/accum-node/releases)
[![Language](https://img.shields.io/badge/Rust-1.75%2B-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**A decentralized, CPU-friendly network engineered to eliminate the structural inequalities of classical Proof-of-Work.**

[🚀 Download Installer](https://github.com/andreudumitro-eng/accum-node/releases/latest) &nbsp;•&nbsp; [📖 Whitepaper](WHITEPAPER.md) &nbsp;•&nbsp; [🌐 RPC API](#rpc-api)

</div>

---

## 🌟 The Vision

Classical Proof-of-Work networks, while secure, force miners into a "winner-takes-all" lottery. This structure inevitably leads to extreme hardware centralization (ASIC monopolies), massive energy waste, and "mercenary mining," where participants jump between networks based solely on momentary profitability. 

**ACCUM was built to fix this.** 

We introduce **Fair Proof-of-Contribution (F-PoC)** — a consensus mechanism that values long-term commitment and economic alignment just as much as raw computational power. By using the **Proof-of-Contribution Index (PoCI)**, ACCUM creates a truly decentralized environment where solo CPU miners can compete fairly and profitably.

---

## ⚖️ Tokenomics & Reward Distribution

ACCUM eliminates lottery variance. Instead of rewarding only the block finder, rewards are distributed fairly across three independent axes over 1,440-block epochs (24 hours).

| 🧩 Contribution Axis | ⚖️ Weight | ⚙️ Protocol Mechanism |
| :--- | :---: | :--- |
| **Computational Work** | **60%** | Valid Argon2id shares submitted per epoch. |
| **Network Loyalty** | **20%** | Continuous participation across consecutive epochs. |
| **Economic Bond** | **20%** | Capital locked in a smart contract for ~14 days. |

**Key Economic Metrics:**
*   **Total Supply:** Fixed at exactly 150,000,000 ACM.
*   **Block Reward:** 0.05 ACM.
*   **Epoch Reward:** 72 ACM (distributed every 24 hours).
*   **Inflation Rate:** Ultra-low, fixed at ~0.0175% annually.
*   **No Premine:** Genesis coins are permanently unspendable. 100% of circulating supply is generated through fair mining.

---

## 🏗️ Core Architecture

### 🛡️ ASIC-Resistance by Design
ACCUM utilizes **Argon2id** (RFC 9106) with a memory hardness of **256 MiB** per hash. 
*   Building a specialized ASIC for memory-hard functions is economically unviable. Commodity CPUs remain highly competitive, ensuring true hardware decentralization and a level playing field.

### ⚖️ Slashing & Economic Security
Malicious behavior is financially suicidal. ACCUM enforces a strict **Bond Lockup** mechanism (~14 days). 
*   Any attempt at **Equivocation** (double-signing blocks) or **Invalid Share Flooding** (>30% invalid shares) results in a **100% slashing of the miner's bond**.

---

## 🚀 Quick Start

### Option A: Pre-built Installer (Recommended)
The easiest way to run an ACCUM node is to use the official installer. It includes the Node, the Wallet, and automatic startup scripts.

1. Go to the **[Releases](https://github.com/andreudumitro-eng/accum-node/releases/latest)** page.
2. Download **`ACCUM_Setup.exe`**.
3. Run the installer.
4. Launch **ACCUM Node** from your Desktop or Start Menu.

> ⚠️ **Dashboard Note:** The Web UI runs locally and is only accessible while the node is running. It fetches data from the local RPC API at `http://127.0.0.1:8545`. Once the node is started, open your browser at **`http://127.0.0.1:8555`**.

### Option B: Build from Source (For Developers)

**Prerequisites:** Rust (Stable Toolchain), 4GB+ RAM.

```bash
# Clone the repository
git clone https://github.com/andreudumitro-eng/accum-node.git
cd accum-node

# Build the node in release mode
cargo build --release

# Start the node and P2P networking
./target/release/accum-node node
📡 <a id="rpc-api"></a>RPC API Reference
ACCUM provides a high-performance JSON-RPC interface for exchanges, pools, and block explorers. The RPC server listens on port 8545.

Endpoint	Method	Description
/info	GET	Node telemetry: height, epoch, peers, difficulty, wallet balance, UTXOs.
/logs	GET	Real-time node logs (JSON array).
/block/{height}	GET	Retrieve full block metadata by height.
/peers	GET	List connected P2P peers.
/miners	GET	List active network miners.
/mining/start	POST	Resume the local mining thread.
/mining/pause	POST	Pause mining without terminating the node process.
<div align="center"> <i>Built with Rust. Engineered for fairness.</i> </div> ```
