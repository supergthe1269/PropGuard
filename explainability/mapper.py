#!/usr/bin/env python3
"""
PropGuard: Explanation-Guided Graduated Response Mapping
Maps dominant SHAP explanation features to precise SDN mitigation tiers.
"""

from dataclasses import dataclass
from typing import Optional

@dataclass
class MitigationDecision:
    target_ip: str
    effective_trust: float
    dominant_feature: str
    response_tier: str       # 'isolate', 'quarantine', 'rate_limit', 'review'
    rationale: str

class PolicyEngine:
    def __init__(self, trust_threshold=0.60, high_severity_threshold=0.25):
        self.trust_threshold = trust_threshold
        self.high_severity_threshold = high_severity_threshold

    def evaluate_node(self, node_ip: str, own_trust: float, effective_trust: float, dominant_shap_feature: str) -> Optional[MitigationDecision]:
        if effective_trust >= self.trust_threshold:
            return None

        # Case 1: Contagion Dominates (Risk inherited from neighbors)
        if dominant_shap_feature == "neighborhood_contagion" or (own_trust >= 0.70 and effective_trust < self.trust_threshold):
            return MitigationDecision(
                target_ip=node_ip,
                effective_trust=effective_trust,
                dominant_feature="neighborhood_contagion",
                response_tier="quarantine",
                rationale="Risk inherited from compromised neighbors. Soft quarantine with active packet mirroring."
            )

        # Case 2: Port Scanning / Reconnaissance Features
        if any(k in dominant_shap_feature.lower() for k in ["syn", "port", "packet_rate", "scan"]):
            return MitigationDecision(
                target_ip=node_ip,
                effective_trust=effective_trust,
                dominant_feature=dominant_shap_feature,
                response_tier="rate_limit",
                rationale=f"Reconnaissance detected via anomalous '{dominant_shap_feature}'. Outbound traffic throttled."
            )

        # Case 3: High Volume / Data Exfiltration
        if any(k in dominant_shap_feature.lower() for k in ["byte", "duration", "out_in", "exfiltration"]):
            return MitigationDecision(
                target_ip=node_ip,
                effective_trust=effective_trust,
                dominant_feature=dominant_shap_feature,
                response_tier="isolate",
                rationale=f"Data exfiltration detected via anomalous '{dominant_shap_feature}'. Full network isolation enforced."
            )

        # Case 4: Ambiguous / Low Confidence Drop
        return MitigationDecision(
            target_ip=node_ip,
            effective_trust=effective_trust,
            dominant_feature="ambiguous",
            response_tier="review",
            rationale="Trust dropped below threshold with no dominant root cause. Flagged for human review."
        )
