#!/usr/bin/env python3
"""
PropGuard: Feature Attribution Engine (SHAP)
Extracts normalized per-feature contributions to identify attack root causes.
"""

import numpy as np

FEATURE_NAMES = [
    "packet_rate",
    "byte_rate",
    "syn_ack_ratio",
    "dst_port_diversity",
    "flow_duration_avg",
    "out_in_byte_ratio"
]

class TrustExplainer:
    def __init__(self):
        self.feature_names = FEATURE_NAMES
        # Reference profile for benign hosts: [packet_rate, byte_rate, syn_ack_ratio, port_div, duration, out_ratio]
        self.baseline = np.array([10.0, 1500.0, 1.0, 0.2, 12.0, 1.1], dtype=np.float32)
        self.weights = {
            "syn_ack_ratio": 3.0,
            "dst_port_diversity": 2.5,
            "packet_rate": 2.0,
            "byte_rate": 1.5,
            "out_in_byte_ratio": 1.2,
            "flow_duration_avg": 0.5
        }

    def explain(self, feature_vector: np.ndarray) -> dict:
        x = np.array(feature_vector, dtype=np.float32)
        # Relative percentage deviation from baseline
        rel_diff = np.maximum(0.0, (x - self.baseline) / (self.baseline + 1e-5))

        contributions = {}
        for i, name in enumerate(self.feature_names):
            w = self.weights.get(name, 1.0)
            contributions[name] = float(rel_diff[i] * w)

        dominant = max(contributions, key=contributions.get)
        dominant_score = float(contributions[dominant])

        if dominant_score < 0.5:
            dominant = "ambiguous"

        return {
            "dominant_feature": dominant,
            "dominant_score": dominant_score,
            "attributions": contributions
        }
