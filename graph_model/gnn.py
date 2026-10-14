#!/usr/bin/env python3
"""
PropGuard: Graph Neural Network for Own-Behavior Trust Embedding
Uses GraphSAGE to generate node trust scores from local behavior.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv

class PropGuardGNN(nn.Module):
    def __init__(self, in_channels=6, hidden_channels=16, out_channels=1):
        super(PropGuardGNN, self).__init__()
        self.conv1 = SAGEConv(in_channels, hidden_channels, aggr='mean')
        self.conv2 = SAGEConv(hidden_channels, hidden_channels, aggr='mean')
        self.fc_trust = nn.Linear(hidden_channels, out_channels)

    def forward(self, x, edge_index, edge_weight=None):
        h = self.conv1(x, edge_index)
        h = F.relu(h)
        h = F.dropout(h, p=0.1, training=self.training)

        h = self.conv2(h, edge_index)
        h = F.relu(h)

        trust_logits = self.fc_trust(h)
        trust_scores = torch.sigmoid(trust_logits).squeeze(-1)
        return trust_scores
