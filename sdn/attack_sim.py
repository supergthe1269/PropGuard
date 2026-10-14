#!/usr/bin/env python3
"""
PropGuard: Attack & Traffic Emulation
Simulates lateral port scans and exfiltration from corporate hosts.
"""

import time
import os
import subprocess

def run_cmd(host, cmd):
    subprocess.Popen(f"sudo m {host} {cmd}", shell=True)

def simulate_benign_traffic():
    print("[*] Generating baseline cross-zone traffic...")
    # h1 (Web) -> h5 (DB) query simulation
    os.system("sudo ip netns exec $(ps aux | grep 'mininet:h1' | awk 'NR==1{print $2}') ping -c 2 10.0.3.10 > /dev/null 2>&1")
    # h3 (WS1) -> h4 (WS2) normal file sync
    os.system("sudo ip netns exec $(ps aux | grep 'mininet:h3' | awk 'NR==1{print $2}') ping -c 2 10.0.2.20 > /dev/null 2>&1")

if __name__ == "__main__":
    simulate_benign_traffic()
