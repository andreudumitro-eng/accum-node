<div align="center">

# ACCUM
### Fair Proof-of-Contribution (F-PoC) Blockchain Protocol

[![Version](https://img.shields.io/badge/version-3.2%2B-blue?style=for-the-badge)](https://github.com/andreudumitro-eng/accum-node/releases)
[![Language](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**A decentralized, CPU-friendly network engineered to eliminate the structural inequalities of classical Proof-of-Work.**

[Download Installer](https://github.com/andreudumitro-eng/accum-node/releases/latest) • [Whitepaper](WHITEPAPER.md) • [RPC API](#rpc-api)

</div>

---

## 1. The Problem with Traditional Consensus

Classical Proof-of-Work (PoW) networks, while secure, suffer from a fundamental flaw: **the "winner-takes-all" incentive structure**. 

This design forces individual participants into centralized mining pools, leads to extreme hardware centralization (ASIC monopolies), and wastes enormous amounts of energy on a lottery system where the smallest miners rarely see a return. 

Furthermore, classical PoW offers no economic or historical incentive for long-term network stability—miners are incentivized to jump between networks based on momentary profitability, often referred to as "mercenary mining."

---

## 2. The ACCUM Solution

ACCUM introduces **Fair Proof-of-Contribution (F-PoC)**. Instead of relying on a single, one-dimensional metric (raw hash power), ACCUM evaluates a miner's overall value to the network using the **Proof-of-Contribution Index (PoCI)**.

The PoCI distributes block rewards across three independent, weighted axes:

| Contribution Axis | Weight | Protocol Mechanism |
| :--- | :---: | :--- |
| **Computational Work** | **60%** | Valid Argon2id shares submitted per epoch. |
| **Network Loyalty** | **20%** | Continuous participation across consecutive epochs. |
| **Economic Bond** | **20%** | Capital locked in a smart contract for ~14 days. |

> **Economic Implication:** ACCUM structurally neutralizes Sybil attacks, 51% attacks, and "mercenary mining." It guarantees that long-term, honest participation is mathematically more profitable than short-term exploitation.

---

## 3. Core Architecture & Cryptographic Design

### 3.1 ASIC-Resistance
ACCUM utilizes **Argon2id** (RFC 9106) with a memory hardness of **256 MiB** per hash. 
*   **Why it matters:** The cost of developing and manufacturing a specialized ASIC for 256 MiB memory-hard functions is economically unviable. Commodity CPUs remain highly competitive, ensuring true hardware decentralization.

### 3.2 No Premine & Fair Launch
*   **Genesis Supply:** 50 ACM (Unspendable, private key destroyed).
*   **Total Supply:** Fixed at 150,000,000 ACM.
*   **Emission:** All circulating coins are generated exclusively through network consensus (mining).

### 3.3 Slashing & Economic Security
To prevent malicious behavior, ACCUM enforces a strict **Bond Lockup** mechanism (~14 days). Any attempt at **Equivocation** (double-signing blocks) or **Invalid Share Flooding** (>30% invalid shares) results in a **100% slashing of the miner's bond**. This makes attacks financially suicidal.

---

## 4. Installation & Quick Start

### Option A: Pre-built Installer (Recommended)
The easiest way to run an ACCUM node is to use the official Windows installer, which includes the Node, the Wallet, and automatic startup scripts.

1. Go to the **[Releases](https://github.com/andreudumitro-eng/accum-node/releases/latest)** page.
2. Download **`ACCUM_Setup.exe`**.
3. Run the installer and follow the on-screen instructions.
4. Launch **ACCUM Node** from your Desktop or Start Menu.
   * The node will start syncing, and the web dashboard will automatically open at `http://127.0.0.1:8555`.

### Option B: Build from Source (For Developers)

**Prerequisites:** Rust (Stable Toolchain), 4GB+ RAM.

```bash
# 1. Clone the repository
git clone https://github.com/andreudumitro-eng/accum-node.git
cd accum-node

# 2. Build the node in release mode
cargo build --release

# 3. Start the node and P2P networking
./target/release/accum-node node
5. <a id="rpc-api"></a>RPC API Reference
ACCUM provides a high-performance JSON-RPC interface for exchanges, pools, and block explorers.

Endpoint	Method	Description
/info	GET	Node telemetry: height, epoch, peers, difficulty, wallet balance, UTXOs.
/logs	GET	Real-time node logs (JSON array).
/block/{height}	GET	Retrieve full block metadata by height.
/peers	GET	List connected P2P peers.
/miners	GET	List active network miners.
/mining/start	POST	Resume the local mining thread.
/mining/pause	POST	Pause mining without terminating the node process.
<div align="center"> <i>Built with Rust. Engineered for fairness.</i> </div> ```
