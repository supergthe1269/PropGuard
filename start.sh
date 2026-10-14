#!/usr/bin/env bash
set -e

SESSION="propguard"
PROJECT_DIR="$HOME/propguard"

# 1. Check for tmux installation
if ! command -v tmux &> /dev/null; then
    echo "[!] tmux is not installed. Installing..."
    sudo apt-get update && sudo apt-get install -y tmux
fi

# 2. Kill existing sessions & clean stale Mininet instances
echo "[*] Cleaning network namespace and previous sessions..."
tmux kill-session -t "$SESSION" 2>/dev/null || true
sudo mn -c > /dev/null 2>&1 || true

# 3. Initialize detached tmux session
# Layout: Left side split vertically (Ryu on top, Mininet on bottom); Right side full height (Pipeline)
tmux new-session -d -s "$SESSION" -n 'console'

# Split horizontally -> creates Pane 0 (left) and Pane 1 (right)
tmux split-window -h -t "$SESSION:0.0"

# Split left pane vertically -> Pane 0 (top-left), Pane 1 (bottom-left), Pane 2 (right)
tmux split-window -v -t "$SESSION:0.0"

# 4. Pane 0 (Top-Left): Launch Ryu SDN Controller
echo "[*] Launching Ryu Controller on port 6653 / 8080..."
tmux send-keys -t "$SESSION:0.0" "cd $PROJECT_DIR && source venv/bin/activate" C-m
tmux send-keys -t "$SESSION:0.0" "ryu-manager sdn/controller.py --ofp-tcp-listen-port 6653" C-m

# Wait for Ryu WSGI and OpenFlow listener to bind
sleep 2.5

# 5. Pane 1 (Bottom-Left): Launch Mininet Multi-Zone Topology
echo "[*] Initializing Mininet topology..."
tmux send-keys -t "$SESSION:0.1" "cd $PROJECT_DIR" C-m
tmux send-keys -t "$SESSION:0.1" "sudo python3 sdn/topo.py" C-m

# Wait for switches s1, s2, s3 to complete handshake with controller
sleep 3.5

# 6. Pane 2 (Right): Launch PropGuard Security Pipeline & State Server
echo "[*] Starting PropGuard evaluation pipeline & web server..."
tmux send-keys -t "$SESSION:0.2" "cd $PROJECT_DIR && source venv/bin/activate" C-m
tmux send-keys -t "$SESSION:0.2" "python3 run_pipeline.py" C-m

# Select Mininet CLI pane by default for interactive traffic commands
tmux select-pane -t "$SESSION:0.1"

echo "[+] Stack initialized. Attaching to tmux workspace..."
tmux attach-session -t "$SESSION"
