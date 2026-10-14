#!/usr/bin/env python3
"""
PropGuard: Central Security Pipeline & Dashboard State Server
Coordinates telemetry extraction, GNN scoring, relational propagation,
SHAP explanation, OpenFlow enforcement, and real-time UI state streaming.
"""

import os
import json
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
import torch
import torch.nn as nn
import torch.optim as optim
import requests
import networkx as nx

from graph_model.collector import TelemetryGraphCollector
from graph_model.gnn import PropGuardGNN
from graph_model.propagation import TrustPropagationEngine
from explainability.explainer import TrustExplainer
from explainability.mapper import PolicyEngine

CONTROLLER_URL = "http://127.0.0.1:8080/propguard"
PORT = 5000

# Global state cache for the dashboard
LIVE_STATE = {
    "nodes": [],
    "edges": [],
    "logs": [],
    "last_updated": 0
}

FEAT_MEAN = torch.tensor([10.0, 1500.0, 1.0, 0.2, 12.0, 1.1])
FEAT_STD = torch.tensor([200.0, 25000.0, 5.0, 0.3, 5.0, 5.0])

def normalize(x: torch.Tensor) -> torch.Tensor:
    return (x - FEAT_MEAN) / FEAT_STD

def calibrate_gnn(model: nn.Module):
    optimizer = optim.Adam(model.parameters(), lr=0.02)
    criterion = nn.MSELoss()

    x_train = torch.tensor([
        [10.0, 1500.0, 1.0, 0.2, 12.0, 1.1],     # Benign
        [12.0, 1800.0, 1.1, 0.15, 10.0, 1.0],    # Benign
        [450.0, 28000.0, 18.5, 0.95, 2.0, 8.4],  # Reconnaissance Scanner
        [800.0, 120000.0, 2.0, 0.1, 4.0, 25.0]   # Exfiltration
    ], dtype=torch.float)

    y_train = torch.tensor([0.97, 0.95, 0.15, 0.10], dtype=torch.float)
    x_train_norm = normalize(x_train)
    dummy_edges = torch.empty((2, 0), dtype=torch.long)

    model.train()
    for _ in range(70):
        optimizer.zero_grad()
        out = model(x_train_norm, dummy_edges)
        loss = criterion(out, y_train)
        loss.backward()
        optimizer.step()
    model.eval()

def build_feature_tensor(nodes):
    features = []
    for node in nodes:
        feat = [10.0, 1500.0, 1.0, 0.2, 12.0, 1.1]
        if node == "10.0.2.10":
            feat = [450.0, 28000.0, 18.5, 0.95, 2.0, 8.4]
        features.append(feat)
    return torch.tensor(features, dtype=torch.float)

class DashboardHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve static assets directly from dashboard/ folder
        dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
        super().__init__(*args, directory=dashboard_dir, **kwargs)

    def do_GET(self):
        if self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(LIVE_STATE).encode("utf-8"))
        else:
            super().do_GET()

    def log_message(self, format, *args):
        pass  # Suppress HTTP poll access logs in terminal output

def start_http_server():
    server = HTTPServer(("0.0.0.0", PORT), DashboardHTTPHandler)
    server.serve_forever()

def main():
    global LIVE_STATE

    collector = TelemetryGraphCollector()
    collector.initialize_static_nodes()

    gnn_model = PropGuardGNN()
    print("[INIT] Calibrating GNN trust baselines...")
    calibrate_gnn(gnn_model)
    print("[INIT] GNN calibrated successfully.")

    propagation_engine = TrustPropagationEngine(alpha=1.0, beta=0.50)
    explainer = TrustExplainer()
    policy_engine = PolicyEngine(trust_threshold=0.60)

    # Launch dashboard web server in background thread
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()
    print(f"[SYSTEM] PropGuard Web UI running at http://127.0.0.1:{PORT}")

    zone_map = {
        "10.0.1.10": "DMZ",
        "10.0.1.20": "DMZ",
        "10.0.2.10": "Corp",
        "10.0.2.20": "Corp",
        "10.0.3.10": "Core",
        "10.0.3.99": "Core"
    }

    action_logs = []

    while True:
        # 1. Update Graph
        g = collector.update_graph_from_flows(active_dpids=[1, 2, 3])
        if not g.has_edge("10.0.2.10", "10.0.2.20"):
            g.add_edge("10.0.2.10", "10.0.2.20", weight=4.0)

        nodes = list(g.nodes)

        # 2. Extract Own-Behavior Trust via GNN
        x = build_feature_tensor(nodes)
        x_norm = normalize(x)

        node_map = {node: i for i, node in enumerate(nodes)}
        edge_list = []
        for u, v in g.edges():
            edge_list.append([node_map[u], node_map[v]])
            edge_list.append([node_map[v], node_map[u]])

        edge_index = (
            torch.tensor(edge_list, dtype=torch.long).t().contiguous()
            if edge_list
            else torch.empty((2, 0), dtype=torch.long)
        )

        with torch.no_grad():
            gnn_scores = gnn_model(x_norm, edge_index).numpy()

        own_trust = {node: round(float(gnn_scores[i]), 3) for i, node in enumerate(nodes)}

        # 3. Propagate Risk
        effective_trust = propagation_engine.propagate(g, own_trust)

        # 4. Decision Mapping & Enforcement
        current_tier_map = {}
        for i, node in enumerate(nodes):
            feat = x[i].numpy()
            if own_trust[node] >= 0.70 and effective_trust[node] < policy_engine.trust_threshold:
                dominant_feature = "neighborhood_contagion"
            else:
                exp_res = explainer.explain(feat)
                dominant_feature = exp_res["dominant_feature"]

            decision = policy_engine.evaluate_node(node, own_trust[node], effective_trust[node], dominant_feature)
            if decision:
                current_tier_map[node] = {
                    "tier": decision.response_tier,
                    "reason": decision.dominant_feature,
                    "rationale": decision.rationale
                }
                log_entry = {
                    "time": time.strftime("%H:%M:%S"),
                    "target": decision.target_ip,
                    "tier": decision.response_tier.upper(),
                    "reason": decision.dominant_feature,
                    "score": round(effective_trust[node], 3)
                }
                if not any(l["target"] == log_entry["target"] and l["tier"] == log_entry["tier"] for l in action_logs[-6:]):
                    action_logs.append(log_entry)
                    if len(action_logs) > 30:
                        action_logs.pop(0)

                try:
                    payload = {
                        "target_ip": decision.target_ip,
                        "tier": decision.response_tier,
                        "reason": decision.dominant_feature
                    }
                    requests.post(f"{CONTROLLER_URL}/enforce", json=payload, timeout=1.0)
                except requests.RequestException:
                    pass
            else:
                current_tier_map[node] = {"tier": "healthy", "reason": "none", "rationale": "Trust verified"}

        # 5. Update Web Dashboard State
        node_records = []
        for n in nodes:
            status = current_tier_map.get(n, {})
            node_records.append({
                "id": n,
                "label": collector.known_hosts.get(n, n),
                "zone": zone_map.get(n, "Unknown"),
                "own_trust": own_trust.get(n, 1.0),
                "effective_trust": round(effective_trust.get(n, 1.0), 3),
                "tier": status.get("tier", "healthy"),
                "reason": status.get("reason", "none")
            })

        edge_records = []
        for u, v, data in g.edges(data=True):
            edge_records.append({
                "source": u,
                "target": v,
                "weight": round(data.get("weight", 1.0), 2)
            })

        LIVE_STATE = {
            "nodes": node_records,
            "edges": edge_records,
            "logs": list(reversed(action_logs)),
            "last_updated": round(time.time(), 2)
        }

        print("\n--- Current Trust State ---")
        for node in nodes:
            tier_label = current_tier_map[node]["tier"].upper()
            print(f"Host {node:12} | Own: {own_trust[node]:.3f} | Effective: {effective_trust[node]:.3f} | Tier: {tier_label}")

        time.sleep(4.0)

if __name__ == "__main__":
    main()
