#!/usr/bin/env python3
"""
PropGuard: Neighborhood Trust Propagation Engine
Computes effective trust scores using relational neighbor exposure.
"""

import numpy as np
import networkx as nx

class TrustPropagationEngine:
    def __init__(self, alpha=1.0, beta=0.50, max_iter=10, convergence_tol=1e-4):
        """
        alpha: Weight for node's own trust score (1.0 preserves clean baseline)
        beta: Weight for neighbor-propagated risk penalty
        """
        self.alpha = alpha
        self.beta = beta
        self.max_iter = max_iter
        self.tol = convergence_tol

    def propagate(self, graph: nx.Graph, own_trust: dict) -> dict:
        nodes = list(graph.nodes)
        if not nodes:
            return {}

        t_effective = {v: float(own_trust.get(v, 1.0)) for v in nodes}

        for iteration in range(self.max_iter):
            t_next = {}
            max_delta = 0.0

            for v in nodes:
                neighbors = list(graph.neighbors(v))
                if not neighbors:
                    t_next[v] = t_effective[v]
                    continue

                total_weight = sum(graph[v][u].get('weight', 1.0) for u in neighbors)
                if total_weight == 0:
                    total_weight = 1.0

                neighborhood_risk_sum = 0.0
                for u in neighbors:
                    w_uv = graph[v][u].get('weight', 1.0) / total_weight
                    # Calculate risk strictly as positive trust deficit
                    risk_u = max(0.0, 1.0 - t_effective[u])
                    neighborhood_risk_sum += w_uv * risk_u

                # PropGuard propagation equation
                score = (self.alpha * own_trust.get(v, 1.0)) - (self.beta * neighborhood_risk_sum)
                score_clamped = max(0.0, min(1.0, score))

                delta = abs(score_clamped - t_effective[v])
                if delta > max_delta:
                    max_delta = delta

                t_next[v] = score_clamped

            t_effective = t_next
            if max_delta < self.tol:
                break

        return t_effective
