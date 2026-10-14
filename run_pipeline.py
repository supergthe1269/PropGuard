#!/usr/bin/env python3
"""
PropGuard: Central Security Pipeline & Dashboard State Server
Coordinates telemetry extraction, GNN scoring, relational propagation,
SHAP explanation, OpenFlow enforcement, and real-time interactive UI state streaming.
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
    "kpis": {
        "total_hosts": 6,
        "healthy_hosts": 6,
        "contagion_hosts": 0,
        "compromised_hosts": 0,
        "avg_trust": 1.0,
        "active_mitigations": 0,
        "simulation_mode": "scan",
        "simulation_target": "10.0.2.10",
        "last_updated": 0
    },
    "last_updated": 0
}

# Dynamic interactive simulation controls
CURRENT_SIMULATION = {
    "mode": "scan",          # "scan", "exfil", "contagion", "benign"
    "target": "10.0.2.10",
    "overrides": {}          # { ip: tier }
}

ACTION_LOGS = []

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
    mode = CURRENT_SIMULATION.get("mode", "scan")
    target_host = CURRENT_SIMULATION.get("target", "10.0.2.10")

    for node in nodes:
        # Default benign profile
        feat = [10.0, 1500.0, 1.0, 0.2, 12.0, 1.1]

        if mode == "scan" and node == target_host:
            # Reconnaissance port scan profile
            feat = [450.0, 28000.0, 18.5, 0.95, 2.0, 8.4]
        elif mode == "exfil" and node == target_host:
            # Data exfiltration profile (massive byte throughput & out/in ratio)
            feat = [850.0, 145000.0, 2.1, 0.15, 55.0, 28.5]
        elif mode == "contagion" and node == target_host:
            # Heavy scan that spreads lateral infection
            feat = [520.0, 34000.0, 16.0, 0.92, 3.5, 9.2]
        elif mode == "benign":
            # All hosts clean with subtle normal variances
            feat = [10.0 + (hash(node) % 3), 1500.0 + (hash(node) % 300), 1.0, 0.2, 12.0, 1.1]

        features.append(feat)
    return torch.tensor(features, dtype=torch.float)

class DashboardHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve static assets directly from dashboard/ folder
        dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
        super().__init__(*args, directory=dashboard_dir, **kwargs)

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(LIVE_STATE).encode("utf-8"))
        elif self.path == "/api/simulation":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(CURRENT_SIMULATION).encode("utf-8"))
        else:
            super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body = json.loads(post_data.decode("utf-8")) if post_data else {}
        except Exception:
            body = {}

        if self.path == "/api/simulate":
            mode = body.get("mode", "scan")
            target = body.get("target", "10.0.2.10")
            CURRENT_SIMULATION["mode"] = mode
            CURRENT_SIMULATION["target"] = target
            if mode == "benign":
                CURRENT_SIMULATION["overrides"].clear()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "mode": mode, "target": target}).encode("utf-8"))

        elif self.path == "/api/override":
            target_ip = body.get("target_ip")
            tier = body.get("tier", "rate_limit")

            if target_ip:
                CURRENT_SIMULATION["overrides"][target_ip] = tier
                try:
                    payload = {"target_ip": target_ip, "tier": tier, "reason": "manual_operator_override"}
                    requests.post(f"{CONTROLLER_URL}/enforce", json=payload, timeout=0.8)
                except requests.RequestException:
                    pass

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success", "target_ip": target_ip, "tier": tier}).encode("utf-8"))
            else:
                self.send_response(400)
                self._send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing target_ip"}).encode("utf-8"))

        elif self.path == "/api/clear-logs":
            global ACTION_LOGS
            ACTION_LOGS.clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "cleared"}).encode("utf-8"))
        else:
            self.send_response(404)
            self._send_cors_headers()
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress HTTP poll access logs in terminal output

def start_http_server():
    server = HTTPServer(("0.0.0.0", PORT), DashboardHTTPHandler)
    server.serve_forever()

def main():
    global LIVE_STATE, ACTION_LOGS

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

    while True:
        # 1. Update Graph
        g = collector.update_graph_from_flows(active_dpids=[1, 2, 3])

        # Ensure lateral communication edge between corporate hosts
        lateral_weight = 4.5 if CURRENT_SIMULATION["mode"] in ("scan", "contagion") else 1.2
        g.add_edge("10.0.2.10", "10.0.2.20", weight=lateral_weight)

        # In exfil mode, add heavy egress communication to Core DB
        if CURRENT_SIMULATION["mode"] == "exfil":
            g.add_edge("10.0.2.10", "10.0.3.10", weight=8.0)
        elif g.has_edge("10.0.2.10", "10.0.3.10") and CURRENT_SIMULATION["mode"] == "benign":
            g.remove_edge("10.0.2.10", "10.0.3.10")

        # Baseline DMZ to DB link
        if not g.has_edge("10.0.1.10", "10.0.3.10"):
            g.add_edge("10.0.1.10", "10.0.3.10", weight=1.5)

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
        node_explanations = {}

        for i, node in enumerate(nodes):
            feat = x[i].numpy()
            exp_res = explainer.explain(feat)

            if own_trust[node] >= 0.70 and effective_trust[node] < policy_engine.trust_threshold:
                dominant_feature = "neighborhood_contagion"
            else:
                dominant_feature = exp_res["dominant_feature"]

            node_explanations[node] = {
                "dominant_feature": dominant_feature,
                "dominant_score": exp_res.get("dominant_score", 0.0),
                "attributions": exp_res.get("attributions", {})
            }

            # Check if manual operator override exists for this node
            if node in CURRENT_SIMULATION["overrides"]:
                override_tier = CURRENT_SIMULATION["overrides"][node]
                current_tier_map[node] = {
                    "tier": override_tier,
                    "reason": "manual_override",
                    "rationale": f"Operator manually set enforcement to {override_tier.upper()}"
                }
                decision = None
            else:
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
                    "score": round(effective_trust[node], 3),
                    "rationale": decision.rationale
                }
                if not any(l["target"] == log_entry["target"] and l["tier"] == log_entry["tier"] for l in ACTION_LOGS[-6:]):
                    ACTION_LOGS.append(log_entry)
                    if len(ACTION_LOGS) > 40:
                        ACTION_LOGS.pop(0)

                try:
                    payload = {
                        "target_ip": decision.target_ip,
                        "tier": decision.response_tier,
                        "reason": decision.dominant_feature
                    }
                    requests.post(f"{CONTROLLER_URL}/enforce", json=payload, timeout=0.8)
                except requests.RequestException:
                    pass
            elif node not in CURRENT_SIMULATION["overrides"]:
                current_tier_map[node] = {"tier": "healthy", "reason": "none", "rationale": "Trust verified within safe baseline"}

        # 5. Assemble Enriched Dashboard State
        node_records = []
        for i, n in enumerate(nodes):
            status = current_tier_map.get(n, {})
            feat = x[i].numpy()
            exp = node_explanations.get(n, {})

            node_records.append({
                "id": n,
                "label": collector.known_hosts.get(n, n),
                "zone": zone_map.get(n, "Unknown"),
                "own_trust": own_trust.get(n, 1.0),
                "effective_trust": round(effective_trust.get(n, 1.0), 3),
                "tier": status.get("tier", "healthy"),
                "reason": status.get("reason", "none"),
                "rationale": status.get("rationale", ""),
                "features": {
                    "packet_rate": round(float(feat[0]), 1),
                    "byte_rate": round(float(feat[1]), 1),
                    "syn_ack_ratio": round(float(feat[2]), 2),
                    "dst_port_diversity": round(float(feat[3]), 2),
                    "flow_duration_avg": round(float(feat[4]), 1),
                    "out_in_byte_ratio": round(float(feat[5]), 2)
                },
                "attributions": {k: round(float(v), 2) for k, v in exp.get("attributions", {}).items()},
                "dominant_score": round(float(exp.get("dominant_score", 0.0)), 2)
            })

        edge_records = []
        for u, v, data in g.edges(data=True):
            edge_records.append({
                "source": u,
                "target": v,
                "weight": round(data.get("weight", 1.0), 2)
            })

        avg_trust_val = round(sum(effective_trust.values()) / max(1, len(nodes)), 3)
        healthy_cnt = sum(1 for n in nodes if effective_trust.get(n, 1.0) >= 0.60)
        contagion_cnt = sum(1 for n in nodes if 0.25 <= effective_trust.get(n, 1.0) < 0.60)
        compromised_cnt = sum(1 for n in nodes if effective_trust.get(n, 1.0) < 0.25)
        active_mitigations_cnt = sum(1 for n in nodes if current_tier_map.get(n, {}).get("tier") not in ("healthy", "ALLOW"))

        LIVE_STATE = {
            "nodes": node_records,
            "edges": edge_records,
            "logs": list(reversed(ACTION_LOGS)),
            "kpis": {
                "total_hosts": len(nodes),
                "healthy_hosts": healthy_cnt,
                "contagion_hosts": contagion_cnt,
                "compromised_hosts": compromised_cnt,
                "avg_trust": avg_trust_val,
                "active_mitigations": active_mitigations_cnt,
                "simulation_mode": CURRENT_SIMULATION["mode"],
                "simulation_target": CURRENT_SIMULATION["target"],
                "last_updated": round(time.time(), 2)
            },
            "last_updated": round(time.time(), 2)
        }

        print(f"[{time.strftime('%H:%M:%S')}] Simulation: {CURRENT_SIMULATION['mode'].upper()} | Avg Trust: {avg_trust_val} | Mitigations: {active_mitigations_cnt}")
        time.sleep(3.0)

if __name__ == "__main__":
    main()
