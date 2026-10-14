#!/usr/bin/env python3
"""
PropGuard: Network Telemetry & Dynamic Graph Builder
Extracts active flow statistics to construct weighted communication graphs.
"""

import requests
import networkx as nx
from collections import defaultdict

class TelemetryGraphCollector:
    def __init__(self, controller_url="http://127.0.0.1:8080", poll_interval=2.0):
        self.controller_url = controller_url
        self.poll_interval = poll_interval
        self.graph = nx.Graph()
        self.history = defaultdict(int)
        self.known_hosts = {
            "10.0.1.10": "h1_web",
            "10.0.1.20": "h2_dns",
            "10.0.2.10": "h3_ws1",
            "10.0.2.20": "h4_ws2",
            "10.0.3.10": "h5_db",
            "10.0.3.99": "h6_sink"
        }

    def initialize_static_nodes(self):
        for ip, label in self.known_hosts.items():
            self.graph.add_node(ip, label=label, packet_count=0, byte_count=0)

    def fetch_switch_stats(self, dpid: int):
        try:
            url = f"{self.controller_url}/propguard/stats/flows/{dpid}"
            res = requests.get(url, timeout=1.5)
            if res.status_code == 200:
                return res.json().get(str(dpid), [])
        except requests.RequestException:
            pass
        return []

    def update_graph_from_flows(self, active_dpids=[1, 2, 3]) -> nx.Graph:
        self.initialize_static_nodes()
        flow_aggregates = defaultdict(lambda: {"packets": 0, "bytes": 0})

        for dpid in active_dpids:
            flows = self.fetch_switch_stats(dpid)
            for f in flows:
                match = f.get("match", {})
                src_ip = match.get("ipv4_src")
                dst_ip = match.get("ipv4_dst")
                if src_ip and dst_ip and src_ip != dst_ip:
                    edge_key = tuple(sorted([src_ip, dst_ip]))
                    flow_aggregates[edge_key]["packets"] += f.get("packet_count", 0)
                    flow_aggregates[edge_key]["bytes"] += f.get("byte_count", 0)

        for (src, dst), stats in flow_aggregates.items():
            current_bytes = stats["bytes"]
            prev_bytes = self.history[(src, dst)]
            delta_bytes = max(0, current_bytes - prev_bytes)
            self.history[(src, dst)] = current_bytes

            weight = 1.0 + (delta_bytes / 1024.0)
            self.graph.add_edge(src, dst, weight=weight, last_bytes=delta_bytes)

        return self.graph
