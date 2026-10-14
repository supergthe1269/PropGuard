# PropGuard: Graph-Propagated Zero-Trust SDN Security

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![SDN Controller](https://img.shields.io/badge/SDN-Ryu%20OF1.3-orange.svg)](https://ryu-sdn.org/)
[![Graph Framework](https://img.shields.io/badge/GNN-PyTorch%20Geometric-red.svg)](https://pytorch-geometric.readthedocs.io/)
[![Network Emulation](https://img.shields.io/badge/Emulation-Mininet-green.svg)](http://mininet.org/)
[![License](https://img.shields.io/badge/License-Academic%20%2F%20MIT-lightgrey.svg)](LICENSE)

**PropGuard** is an explainable, graph-native Software-Defined Networking (SDN) security framework. It combines Graph Neural Networks (GraphSAGE) for node-level behavioral trust modeling with iterative neighborhood risk propagation and Shapley-inspired feature attribution (XAI).

Instead of relying on static perimeter firewalls or blunt binary isolation, PropGuard dynamically computes relational risk across enterprise network topologies and deploys graduated OpenFlow 1.3 enforcement rules (Rate-Limiting, Soft-Quarantine, Full Isolation, SOC Flagging) in sub-millisecond control loops.

---

## Table of Contents

- [Key Capabilities](#key-capabilities)
- [Architecture Overview](#architecture-overview)
- [Network Topology & Zones](#network-topology--zones)
- [Mathematical Formulation](#mathematical-formulation)
  - [1. Behavioral Trust Estimation (T_own)](#1-behavioral-trust-estimation-t_own)
  - [2. Relational Risk Propagation (T_effective)](#2-relational-risk-propagation-t_effective)
  - [3. Feature Attribution & Graduated Mitigation Mapping](#3-feature-attribution--graduated-mitigation-mapping)
- [Repository Structure](#repository-structure)
- [Prerequisites & Installation](#prerequisites--installation)
  - [System Requirements](#system-requirements)
  - [Step 1: Install System Dependencies](#step-1-install-system-dependencies)
  - [Step 2: Configure Python Virtual Environment](#step-2-configure-python-virtual-environment)
- [Execution & Quick Start](#execution--quick-start)
  - [Method A: Automated Multi-Pane Launch (Recommended)](#method-a-automated-multi-pane-launch-recommended)
  - [Method B: Manual Multi-Terminal Launch](#method-b-manual-multi-terminal-launch)
  - [Teardown & Cleanup](#teardown--cleanup)
- [Attack Emulation & Interactive Verification](#attack-emulation--interactive-verification)
- [Real-Time D3.js Defense Console](#real-time-d3js-defense-console)
- [REST API Reference](#rest-api-reference)
- [Benchmarking & Evaluation](#benchmarking--evaluation)
- [Configuration Settings](#configuration-settings)
- [Troubleshooting & FAQ](#troubleshooting--faq)

---

## Key Capabilities

- **Relational Risk Propagation**: Quantifies and halts multi-hop lateral contagion across dynamic communication graphs before threats reach critical core infrastructure.
- **GraphSAGE Inductive Learning**: Aggregates local behavioral flow statistics (packet rates, port entropy, SYN/ACK ratios, duration, byte asymmetries) into continuous trust embeddings.
- **Explainable Anomaly Attribution (XAI)**: Calculates marginal feature attribution relative to clean baselines to determine root cause rather than treating the neural network as an opaque black box.
- **Graduated SDN Defense**: Deploys proportionate OpenFlow 1.3 flow modifications (TCP rate limiting, honeypot sink rerouting, or ingress packet dropping) instead of indiscriminate port disconnection.
- **Real-Time SOC Console**: Built-in D3.js force-directed graph streaming live trust degradation, active communication edges, and OpenFlow enforcement events.

---

## Architecture Overview

```text
+-----------------------------------------------------------------------------+
|                            Mininet Data Plane                               |
|        DMZ Switch (s1)    <--->    Corp Switch (s2)    <--->    Core (s3)   |
|         h1 (Web Server)             h3 (Workstation 1)           h5 (DB)    |
|         h2 (DNS Server)             h4 (Workstation 2)           h6 (Sink)  |
+--------------------------------------+--------------------------------------+
                                       ^
                        OpenFlow 1.3   | Flow Statistics &
                        Flow Mods      v Packet-Ins
+--------------------------------------+--------------------------------------+
|                     Ryu SDN Controller (Port :6653)                         |
|   - L2/L3 Learning Switch Pipeline                                          |
|   - Periodic Flow Telemetry Poller                                          |
|   - REST Enforcement WSGI Service (Port :8080)                              |
+--------------------------------------+--------------------------------------+
                                       ^
                         HTTP REST     | Telemetry Polling
                         Enforcement   v & Flow Stats
+--------------------------------------+--------------------------------------+
|                           PropGuard Core Engine                             |
|                                                                             |
|  +---------------------+     +--------------------------+                   |
|  | Telemetry Collector | --> | 2-Layer GraphSAGE GNN    |                   |
|  | Feature Extraction  |     | Computes Own Trust (T_own|                   |
|  +---------------------+     +--------------------------+                   |
|                                           |                                 |
|                                           v                                 |
|  +---------------------+     +--------------------------+                   |
|  | OpenFlow Dispatcher | <-- | Policy Decision Engine   |                   |
|  | RateLimit/Quar/Drop |     | Feature-to-Tier Mapping  |                   |
|  +---------------------+     +--------------------------+                   |
|                                           ^                                 |
|                                           |                                 |
|  +---------------------+     +--------------------------+                   |
|  | Relational Engine   | --> | Attribution Engine (XAI) |                   |
|  | Computes T_effective|     | Root Cause Explanation   |                   |
|  +---------------------+     +--------------------------+                   |
+--------------------------------------+--------------------------------------+
                                       | Live State Sync (:5000)
                                       v
+-----------------------------------------------------------------------------+
|                          D3.js Security Dashboard                           |
|       Topology Graph Visualizer | Dynamic Risk Waves | Audit Event Log      |
+-----------------------------------------------------------------------------+
```

---

## Network Topology & Zones

The emulated network fabric consists of 3 segmented OpenFlow 1.3 switches organized into security zones:

| Zone | Switch | Subnet | Host | IP Address | Role / Description |
|---|---|---|---|---|---|
| **DMZ** | `s1` | `10.0.1.0/16` | `h1` | `10.0.1.10` | Public Web Server |
| **DMZ** | `s1` | `10.0.1.0/16` | `h2` | `10.0.1.20` | Public DNS Resolver |
| **Corp** | `s2` | `10.0.2.0/16` | `h3` | `10.0.2.10` | Corporate Workstation 1 (Simulated Attacker) |
| **Corp** | `s2` | `10.0.2.0/16` | `h4` | `10.0.2.20` | Corporate Workstation 2 (Adjacent Neighbor) |
| **Core** | `s3` | `10.0.3.0/16` | `h5` | `10.0.3.10` | Critical Production Database |
| **Core** | `s3` | `10.0.3.0/16` | `h6` | `10.0.3.99` | Honeypot Quarantine Sink |

Switches `s1` (DMZ) and `s2` (Corp) are interconnected through `s3` (Core aggregation fabric).

---

## Mathematical Formulation

### 1. Behavioral Trust Estimation (T_own)

Each active network entity $v \in \mathcal{V}$ is characterized by a dynamic telemetry feature vector $\mathbf{x}_v \in \mathbb{R}^6$:

$$\mathbf{x}_v = \left[ \text{packet rate}, \, \text{byte rate}, \, \text{SYN/ACK ratio}, \, \text{port diversity}, \, \text{flow duration}, \, \text{out/in ratio} \right]$$

Where each component corresponds to normalized real-time telemetry metrics:
* **packet rate** (`packet_rate`): Transmission packet frequency ($\text{pkts/sec}$)
* **byte rate** (`byte_rate`): Aggregate traffic throughput ($\text{bytes/sec}$)
* **SYN/ACK ratio** (`syn_ack_ratio`): Ratio of TCP SYN to ACK packets (reconnaissance / flood indicator)
* **port diversity** (`dst_port_diversity`): Target destination port entropy (horizontal / vertical scanning)
* **flow duration** (`flow_duration_avg`): Average lifetime of active connections ($\text{sec}$)
* **out/in ratio** (`out_in_byte_ratio`): Ratio of egress to ingress volume (data exfiltration indicator)

Inputs are normalized against the calibrated enterprise baseline distribution:

$$\tilde{\mathbf{x}}_v = \frac{\mathbf{x}_v - \boldsymbol{\mu}}{\boldsymbol{\sigma}}$$

A two-layer GraphSAGE inductive network aggregates localized topological structures across communication edges $\mathcal{E}$:

$$\mathbf{h}_v^{(k)} = \operatorname{ReLU}\left( \mathbf{W}^{(k)} \cdot \left[ \mathbf{h}_v^{(k-1)} \,\|\, \frac{1}{|\mathcal{N}(v)|} \sum_{u \in \mathcal{N}(v)} \mathbf{h}_u^{(k-1)} \right] \right)$$

The final linear projection and sigmoid readout maps node embeddings to an intrinsic behavioral trust score:

$$T_{\text{own}}(v) = \sigma\left( \mathbf{W}_{\text{out}} \mathbf{h}_v^{(2)} + b \right) \in (0, 1)$$

---

### 2. Relational Risk Propagation (T_effective)

Host compromise does not exist in isolation. When host $u$ exhibits malicious behavior, adjacent communicating hosts face lateral contagion. Risk propagates across weighted communication edges $w(u, v)$ over $K$ convergence steps:

$$T_{\text{effective}}^{(k+1)}(v) = \max\left(0, \, \min\left(1, \, \alpha \cdot T_{\text{own}}(v) - \beta \sum_{u \in \mathcal{N}(v)} \tilde{w}(u, v) \cdot \max\left(0, \, 1 - T_{\text{effective}}^{(k)}(u)\right) \right)\right)$$

Where:
* **$\alpha = 1.0$**: Baseline conservation parameter (preserves clean host baselines).
* **$\beta = 0.50$**: Contagion transmission factor for neighboring risk.
* **$\tilde{w}(u, v) = \frac{w(u, v)}{\sum_{z \in \mathcal{N}(v)} w(z, v)}$**: Normalized edge communication weight based on active flow volume ($\Delta\text{bytes}$).

---

### 3. Feature Attribution & Graduated Mitigation Mapping

When $T_{\text{effective}}(v) < \tau$ (default $\tau = 0.60$), the root cause is extracted via relative marginal feature deviation against the benign reference profile $\mathbf{b}$:

$$\phi_i(v) = w_i \cdot \frac{\max(0, \, x_{v,i} - b_i)}{b_i + \epsilon}, \quad d^* = \operatorname{argmax}_i \phi_i(v)$$

The policy engine executes a proportionate OpenFlow response based on the dominant factor $d^*$:

| Trigger Condition | Dominant Factor ($d^*$) | Enforcement Tier | OpenFlow 1.3 Pipeline Action |
|---|---|---|---|
| $T_{\text{own}} \ge 0.70 \land T_{\text{effective}} < 0.60$ | `neighborhood_contagion` | **QUARANTINE** | Set `ipv4_dst = 10.0.3.99` (Reroute flows to Honeypot Sink) |
| $T_{\text{effective}} < 0.60$ | `syn_ack_ratio` / `dst_port_diversity` / `packet_rate` | **RATE_LIMIT** | Match `ipv4_src`, `ip_proto=6` $\rightarrow$ Drop burst TCP flows |
| $T_{\text{effective}} < 0.25$ | `byte_rate` / `out_in_byte_ratio` / `flow_duration_avg` | **ISOLATE** | Drop all bidirectional IPv4 traffic on switch ingress table |
| $T_{\text{effective}} < 0.60$ | Deviations below noise floor | **REVIEW** | Telemetry alert dispatched to SOC audit log |

---

## Repository Structure

```text
propguard/
├── benchmarks/
│   ├── benchmark_results.csv    # Exported validation benchmark metrics
│   ├── benchmarks.py            # Comparative evaluation suite (PropGuard vs Baseline)
│   ├── evaluation_metrics.png   # Generated comparative visualization bar chart
│   └── export_results.py        # Automated benchmarking and plot generation script
├── config/
│   └── settings.yaml            # Central configuration (ports, thresholds, weights, zones)
├── dashboard/
│   └── index.html               # Real-time D3.js + Tailwind CSS security console
├── explainability/
│   ├── __init__.py
│   ├── explainer.py             # Marginal feature attribution engine (SHAP-inspired)
│   └── mapper.py                # Explanation-to-OpenFlow graduated policy engine
├── graph_model/
│   ├── __init__.py
│   ├── collector.py             # OpenFlow telemetry flow statistics graph builder
│   ├── gnn.py                   # PyTorch Geometric 2-layer GraphSAGE architecture
│   └── propagation.py           # Relational risk propagation engine
├── sdn/
│   ├── attack_sim.py            # Traffic & attack emulation suite (benign, scan, exfil)
│   ├── controller.py            # Ryu OpenFlow 1.3 L2/L3 switch & REST API (:8080)
│   └── topo.py                  # Mininet 3-zone topology definition (DMZ, Corp, Core)
├── requirements.txt             # Python dependencies
├── run_pipeline.py              # Closed-loop defense pipeline & HTTP state server (:5000)
├── start.sh                     # Orchestrated multi-pane tmux launcher
├── stop.sh                      # Clean environment teardown script
└── readme.md                    # Project documentation
```

---

## Prerequisites & Installation

### System Requirements

* **Operating System**: Ubuntu 22.04 LTS or Debian-based Linux distribution (native or WSL2)
* **Python**: Python 3.10+
* **SDN Tools**: Mininet, Open vSwitch, tmux, net-tools

### Step 1: Install System Dependencies

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch tmux net-tools
```

Ensure Open vSwitch service is running:
```bash
sudo service openvswitch-switch status || sudo service openvswitch-switch start
```

### Step 2: Configure Python Virtual Environment

Clone the repository and set up a clean Python virtual environment. It is strongly recommended to use the lightweight CPU-only PyTorch build to avoid unnecessary CUDA runtime overhead in virtualized network environments:

```bash
git clone https://github.com/supergthe1269/PropGuard.git
cd PropGuard

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install CPU-only PyTorch
pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install PropGuard requirements
pip install -r requirements.txt
```

---

## Execution & Quick Start

### Method A: Automated Multi-Pane Launch (Recommended)

PropGuard includes an automated tmux launcher (`start.sh`) that checks dependencies, cleans lingering network namespaces, sets up an organized 3-pane workspace, and manages staggered service initialization:

```bash
chmod +x start.sh stop.sh
./start.sh
```

#### Tmux Layout & Panes:

```text
+------------------------------+------------------------------+
| Pane 0 (Top-Left):           | Pane 2 (Right):              |
| Ryu SDN Controller           | PropGuard Closed-Loop        |
| - OpenFlow 1.3 listener :6653|   Defense Pipeline           |
| - REST API service :8080     | - Live State Server :5000    |
+------------------------------+                              |
| Pane 1 (Bottom-Left):        |                              |
| Mininet Interactive CLI      |                              |
| mininet>                     |                              |
+------------------------------+------------------------------+
```

#### Tmux Navigation:
* **Switch between panes**: Press `Ctrl + B`, then press an **Arrow Key** ($\uparrow, \downarrow, \leftarrow, \rightarrow$).
* **Detach from session**: Press `Ctrl + B`, then press `D`.
* **Re-attach to session**:
  ```bash
  tmux attach -t propguard
  ```

---

### Method B: Manual Multi-Terminal Launch

If running without tmux, open **three separate terminal shells** in the project directory:

#### Terminal 1 — Ryu SDN Controller
```bash
source venv/bin/activate
ryu-manager sdn/controller.py --ofp-tcp-listen-port 6653
```

#### Terminal 2 — Mininet Multi-Zone Topology
*(Wait 3 seconds for Ryu to bind)*
```bash
sudo python3 sdn/topo.py
```
*(Leave the `mininet>` prompt open to issue network commands)*

#### Terminal 3 — PropGuard Core Pipeline & Web Server
*(Wait 3 seconds for switches to register with Ryu)*
```bash
source venv/bin/activate
python3 run_pipeline.py
```

---

### Teardown & Cleanup

To terminate all running components, kill orphaned Python controllers, and flush Open vSwitch datapaths:

```bash
./stop.sh
```

Or manually flush Mininet:
```bash
sudo mn -c
```

---

## Attack Emulation & Interactive Verification

Once the stack is running, you can generate benign cross-zone traffic or trigger simulated attack vectors to observe PropGuard's graduated response in real time.

### Option 1: Using the Traffic Emulation Suite

In a separate terminal (with `venv` active):

```bash
# 1. Generate benign baseline traffic across zones
python3 sdn/attack_sim.py --mode benign

# 2. Simulate lateral reconnaissance scan from h3 toward h4
python3 sdn/attack_sim.py --mode scan

# 3. Simulate high-volume data exfiltration from h3 toward core
python3 sdn/attack_sim.py --mode exfil

# 4. Run full sequence
python3 sdn/attack_sim.py --mode all
```

### Option 2: Directly in Mininet CLI (`mininet>`)

You can execute commands directly on emulated hosts from the Mininet console:

```bash
# Baseline connectivity test
mininet> h1 ping -c 2 h5

# Lateral communication between corporate workstations
mininet> h3 ping -c 3 h4

# Simulate port scan from h3 to h4
mininet> h3 nc -z -w 1 10.0.2.20 20-80

# Observe enforcement behavior
# - When h3 is RATE_LIMITED: burst TCP connections are dropped.
# - When h4 is QUARANTINED: traffic destined for h4 is rerouted to sink h6 (10.0.3.99).
# - When h3 is ISOLATED: all ingress and egress packets are dropped.
```

---

## Real-Time D3.js Defense Console

Once `run_pipeline.py` is initialized, open your web browser to:

👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

### Dashboard Features:
1. **Dynamic Network Topology**: Force-directed D3.js graph rendering active switches and hosts. Nodes dynamically update colors based on trust status:
   - 🟢 **Green (Healthy)**: $T_{\text{effective}} \ge 0.60$ — Normal authorized activity.
   - 🟡 **Amber (Contagion Exposure)**: $0.30 \le T_{\text{effective}} < 0.60$ — Risk inherited from neighbors.
   - 🔴 **Red (Compromised)**: $T_{\text{effective}} < 0.30$ — Active anomalous behavior.
2. **Node Telemetry Inspector**: Click on any node in the topology to view its IP address, security zone, intrinsic trust ($T_{\text{own}}$), effective trust ($T_{\text{effective}}$), current enforcement tier, and dominant explanation reason.
3. **SDN OpenFlow Enforcement Stream**: Chronological audit trail showing timestamped OpenFlow rule updates dispatched to the switches.

---

## REST API Reference

### 1. Ryu SDN Controller API (`http://127.0.0.1:8080`)

#### Get Active Switches
```bash
curl -s http://127.0.0.1:8080/propguard/topology
```
**Response:**
```json
{"active_switches": [1, 2, 3]}
```

#### Get Switch Flow Statistics
```bash
curl -s http://127.0.0.1:8080/propguard/stats/flows/1
```

#### Apply Graduated Defense Rule
```bash
curl -X POST http://127.0.0.1:8080/propguard/enforce \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "10.0.2.10", "tier": "rate_limit", "reason": "syn_ack_ratio"}'
```
**Supported Tiers:** `"rate_limit"`, `"quarantine"`, `"isolate"`

### 2. PropGuard State Server API (`http://127.0.0.1:5000`)

#### Get Current Dashboard State
```bash
curl -s http://127.0.0.1:5000/api/state
```
**Response:**
```json
{
  "nodes": [
    {
      "id": "10.0.2.10",
      "label": "h3_ws1",
      "zone": "Corp",
      "own_trust": 0.15,
      "effective_trust": 0.15,
      "tier": "rate_limit",
      "reason": "syn_ack_ratio"
    }
  ],
  "edges": [{"source": "10.0.2.10", "target": "10.0.2.20", "weight": 4.5}],
  "logs": [],
  "last_updated": 1728900000.0
}
```

---

## Benchmarking & Evaluation

PropGuard includes a comprehensive benchmarking suite that evaluates **PropGuard (Relational XAI)** against a **Static Baseline (Per-Node Scoring without Propagation + Binary Isolation)** across 100 simulation cycles.

### Run Benchmarks

```bash
# Run 100 evaluation trials and view formatted comparison table
python3 benchmarks/benchmarks.py

# Run simulation, export metrics to CSV, and generate high-res plot
python3 benchmarks/export_results.py
```

### Empirical Results Summary

| Evaluation Metric | Static Baseline (No Propagation) | PropGuard (Relational XAI) | Advantage / Impact |
|---|---|---|---|
| **Containment Rate (2nd-Hop Pre-emption)** | **0.0%** | **100.0%** | **+100.0%** (Proactively contains lateral neighbor before breach) |
| **Response Precision (Proportionate Tier)** | **0.0%** | **100.0%** | **+100.0%** (Matches enforcement to specific attack vector) |
| **Avg Enforcement Latency (calc $\rightarrow$ rule)** | **3.12 ms** | **0.30 ms** | **Sub-millisecond** real-time control loop |
| **False Positive Rate (Benign Hosts)** | **0.0%** | **0.0%** | Preserves normal business operations without disruption |

The generated figure is saved to `benchmarks/evaluation_metrics.png` and trial data to `benchmarks/benchmark_results.csv`.

---

## Configuration Settings

Global parameters are defined in [`config/settings.yaml`](config/settings.yaml):

```yaml
controller:
  host: "127.0.0.1"
  ofp_port: 6653
  rest_port: 8080
  api_prefix: "/propguard"
  poll_interval_sec: 2.0

dashboard:
  host: "0.0.0.0"
  port: 5000

propagation:
  alpha: 1.0              # Baseline trust conservation (prevents decay on unexposed hosts)
  beta: 0.50              # Neighbor risk transmission weight
  max_iterations: 10      # Convergence limit
  convergence_tol: 0.0001 # Convergence delta threshold

policy:
  trust_threshold: 0.60          # Mitigation trigger threshold
  high_severity_threshold: 0.25  # Severe compromise isolation threshold
  quarantine_sink_ip: "10.0.3.99"
```

---

## Troubleshooting & FAQ

### 1. `Address already in use` error
- **Cause**: A previous instance of Ryu (ports 6653/8080) or the PropGuard web server (port 5000) is still running.
- **Solution**: Run `./stop.sh` or kill processes manually:
  ```bash
  sudo fuser -k 6653/tcp 8080/tcp 5000/tcp
  ```

### 2. Mininet fails to start (`Cannot find switch` or `Node already exists`)
- **Cause**: Mininet exited uncleanly, leaving virtual interfaces or Open vSwitch bridge namespaces active.
- **Solution**:
  ```bash
  sudo mn -c
  ```

### 3. Ryu crashes with `eventlet` or `dnspython` warnings
- **Cause**: Newer versions of eventlet require `dnspython` or have deprecated monkey-patching syntax.
- **Solution**: Ensure your virtual environment contains the pinned compatible versions specified in `requirements.txt`:
  ```bash
  pip install -r requirements.txt
  ```

### 4. Tmux session was detached or lost
- **Solution**: List active sessions and reattach:
  ```bash
  tmux ls
  tmux attach -t propguard
  ```

---

## Citation & Academic Context

If you utilize PropGuard in academic research, educational demonstrations, or SDN security evaluations, please cite:

```bibtex
@misc{propguard2026,
  author = {Gaurav Gopichand Nanhe},
  title = {PropGuard: Graph-Propagated Zero-Trust SDN Security},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/supergthe1269/PropGuard}}
}
```
