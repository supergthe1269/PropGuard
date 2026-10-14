#!/usr/bin/env bash
SESSION="propguard"

echo "[*] Tearing down PropGuard stack..."
tmux kill-session -t "$SESSION" 2>/dev/null || true

# Terminate orphaned Python controller or pipeline processes
pkill -f "ryu-manager" 2>/dev/null || true
pkill -f "run_pipeline.py" 2>/dev/null || true

# Purge Open vSwitch datapaths and reset Mininet interfaces
sudo mn -c > /dev/null 2>&1 || true

echo "[+] All services and OpenFlow switches stopped cleanly."
