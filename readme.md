# PropGuard: Graph-Propagated Zero-Trust SDN Security

PropGuard is an explainable, graph-native Software-Defined Networking (SDN) security framework. It combines Graph Neural Networks (GNNs) for node-level behavioral trust modeling with iterative neighborhood risk propagation and Shapley-inspired feature attribution. Instead of relying on static perimeter firewalls or blunt binary isolation, PropGuard dynamically computes relational risk across enterprise network topologies and deploys graduated OpenFlow 1.3 enforcement rules in sub-millisecond control loops.

---

## Architecture Overview
+---------------------------------------+
                      |        Mininet Data Plane             |
                      |  DMZ (s1) <-> Corp (s2) <-> Core (s3) |
                      +-------------------+-------------------+
                                          ^
                           OpenFlow 1.3   | Flow Stats &
                           Flow Rules     v Packet-Ins
                      +-------------------+-------------------+
                      |      Ryu SDN Controller (:6653)       |
                      |  - L2/L3 Learning Switch              |
                      |  - Flow Telemetry Poller              |
                      |  - REST Enforcement API (:8080)       |
                      +-------------------+-------------------+
                                          ^
                           HTTP REST      | Telemetry
                           Payloads       v Polling
                           +---------------------------------------------+---------------------------------------------+
|                                    PropGuard Core Engine                                  |
|                                                                                           |
|  +---------------------+     +--------------------------+     +------------------------+  |
|  | Telemetry Collector | --> | 2-Layer GraphSAGE GNN    | --> | Relational Propagation |  |
|  | Feature Extraction  |     | Computes Own Trust (T_own)|    | Computes T_effective   |  |
|  +---------------------+     +--------------------------+     +------------------------+  |
|                                                                            |              |
|  +---------------------+     +--------------------------+                  |              |
|  | OpenFlow Dispatcher | <-- | Policy Decision Engine   | <----------------+              |
|  | RateLimit/Quar/Drop |     | Feature-to-Tier Mapping  | <--- SHAP Attribution Engine    |
|  +---------------------+     +--------------------------+                                 |
+---------------------------------------------+---------------------------------------------+
| Live State Sync (:5000)
v
+---------------------------------------+
|       D3.js Security Dashboard        |
|  Topology Graph, Risk Waves, Audit Log|
+---------------------------------------+
---

## Mathematical Formulation

### 1. Behavioral Trust Estimation ($T_{\text{own}}$)

Each active network entity $v \in \mathcal{V}$ is characterized by a dynamic telemetry feature vector $\mathbf{x}_v \in \mathbb{R}^6$:

$$\mathbf{x}_v = \left[ \text{packet\_rate}, \, \text{byte\_rate}, \, \text{syn\_ack\_ratio}, \, \text{port\_entropy}, \, \text{duration\_avg}, \, \text{out\_in\_ratio} \right]$$

Inputs are normalized against the enterprise baseline distribution:

$$\tilde{\mathbf{x}}_v = \frac{\mathbf{x}_v - \boldsymbol{\mu}}{\boldsymbol{\sigma}}$$

A two-layer GraphSAGE network aggregates localized topological structures across communication edges $\mathcal{E}$:

$$\mathbf{h}_v^{(k)} = \text{ReLU}\left( \mathbf{W}^{(k)} \cdot \left[ \mathbf{h}_v^{(k-1)} \,\Vert{}\, \frac{1}{\vert{}\mathcal{N}(v)\vert{}} \sum_{u \in \mathcal{N}(v)} \mathbf{h}_u^{(k-1)} \right] \right)$$

The final linear layer maps node embeddings to an intrinsic behavioral trust score:

$$T_{\text{own}}(v) = \sigma\left( \mathbf{W}_{\text{out}} \mathbf{h}_v^{(2)} + b \right) \in (0, 1)$$

---

### 2. Relational Risk Propagation ($T_{\text{effective}}$)

Host compromise does not exist in isolation. If host $u$ exhibits malicious activity, adjacent communicating hosts face lateral contagion. Risk propagates across weighted edges $w(u, v)$ over $K$ convergence steps:

$$T_{\text{effective}}^{(k+1)}(v) = \max\left(0, \, \min\left(1, \, \alpha \cdot T_{\text{own}}(v) - \beta \sum_{u \in \mathcal{N}(v)} \tilde{w}(u, v) \cdot \max\left(0, \, 1 - T_{\text{effective}}^{(k)}(u)\right) \right)\right)$$

Where:
* $\alpha = 1.0$: Baseline conservation parameter (prevents unprovoked trust decay).
* $\beta = 0.50$: Contagion transmission factor.
* $\tilde{w}(u, v) = \frac{w(u, v)}{\sum_{z \in \mathcal{N}(v)} w(z, v)}$: Normalized edge communication weight based on active flow volume.

---

### 3. Feature Attribution & Graduated Mitigation Mapping

When $T_{\text{effective}}(v) < \tau$ (where $\tau = 0.60$), the root cause is extracted via relative marginal feature deviation against the reference profile $\mathbf{b}$:

$$\phi_i(v) = w_i \cdot \frac{\max(0, x_{v,i} - b_i)}{b_i + \epsilon}, \quad d^* = \arg\max_i \phi_i(v)$$

The policy engine executes a proportionate OpenFlow response based on the dominant feature $d^*$:

| Trigger Condition | Dominant Factor ($d^*$) | Enforcement Tier | OpenFlow 1.3 Pipeline Action |
|---|---|---|---|
| $T_{\text{own}} \ge 0.70 \land T_{\text{effective}} < 0.60$ | `neighborhood_contagion` | **QUARANTINE** | Set `ipv4_dst = 10.0.3.99` (Honeypot Sink reroute) |
| $T_{\text{effective}} < 0.60$ | `syn_ack_ratio` / `port_entropy` | **RATE_LIMIT** | Match `ipv4_src`, `ip_proto=6` $\rightarrow$ Drop burst TCP flows |
| $T_{\text{effective}} < 0.25$ | `byte_rate` / `out_in_ratio` | **ISOLATE** | Drop all bidirectional IPv4 traffic on ingress table |
| $T_{\text{effective}} < 0.60$ | Deviations below noise floor | **REVIEW** | Telemetry alert dispatched to SOC audit log |

---

## Repository Structure
propguard/
├── benchmarks/
│   ├── benchmark_results.csv    # Exported validation data
│   ├── benchmarks.py            # Comparative evaluation suite
│   ├── evaluation_metrics.png   # Generated comparative visualization
│   └── export_results.py        # Automated plotting pipeline
├── dashboard/
│   └── index.html               # D3.js + Tailwind real-time visualizer
├── explainability/
│   ├── explainer.py             # Marginal attribution engine
│   └── mapper.py                # Explanation-to-OpenFlow policy mapper
├── graph_model/
│   ├── collector.py             # OpenFlow flow statistics graph extractor
│   ├── gnn.py                   # PyTorch Geometric GraphSAGE architecture
│   └── propagation.py           # Relational risk propagation engine
├── sdn/
│   ├── controller.py            # Ryu OpenFlow 1.3 L2/L3 switch + REST API
│   └── topo.py                  # Mininet 3-zone topology definition
├── run_pipeline.py              # Closed-loop defense loop & embedded HTTP server
├── start.sh                     # Orchestrated multi-pane tmux launcher
└── stop.sh                      # Clean environment teardown script
---

## Prerequisites & Installation

### System Requirements
* Ubuntu 22.04 LTS or Debian-based Linux environment
* Python 3.10+
* Open vSwitch & Mininet

### 1. Install System Dependencies
```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch tmux net-tools
2. Configure Python Virtual EnvironmentUse the lightweight CPU-only PyTorch build to avoid unnecessary CUDA runtime overhead in virtualized environments:Bashcd ~/propguard
python3 -m venv venv
source venv/bin/activate

# Install CPU-only PyTorch
pip install --no-cache-dir torch --index-url [https://download.pytorch.org/whl/cpu](https://download.pytorch.org/whl/cpu)

# Install Graph, SDN, and Visualization dependencies
pip install --no-cache-dir torch_geometric networkx requests eventlet dnspython webob tabulate matplotlib
#Execution
Automated Launch (Recommended)PropGuard includes a launcher that verifies dependencies, cleans lingering network namespaces, sets up a 3-pane tmux session, and handles staggered service initialization:
```bash
chmod +x start.sh stop.sh
./start.sh
This starts:Top-Left Pane: Ryu SDN controller (:6653, REST API on :8080).Bottom-Left Pane: Mininet network emulation CLI (mininet>).Right Pane: PropGuard security pipeline and local HTTP state server (:5000).To detach from tmux, press Ctrl + B, then D. To re-attach:Bashtmux attach -t propguard
To tear down all processes and flush virtual switches:
```bash./stop.sh
Manual ExecutionIf running without tmux, run each component in a dedicated shell:
*Terminal 1 (Ryu SDN Controller):
```bash
	source venv/bin/activate
	ryu-manager sdn/controller.py --ofp-tcp-listen-port 6653
Terminal 2 (Mininet Topology):
```bash
	sudo python3 sdn/topo.py
Terminal 3 (PropGuard Core Pipeline):
```bash
	source venv/bin/activate
	python3 run_pipeline.py
Real-Time D3.js DashboardOnce run_pipeline.py is running, open a browser to access the control plane:[http://127.0.0.1:5000](http://127.0.0.1:5000)

Dynamic Network Topology: Renders active nodes colored by trust status (Green = Verified $\ge 0.60$, Amber = Contagion Risk, Red = Compromised $< 0.30$).
Node Telemetry Inspector: Click any host to inspect own trust, effective trust, and the dominant feature attribution.
SDN Enforcement Stream: Displays timestamped OpenFlow rule updates pushed by the policy engine.
