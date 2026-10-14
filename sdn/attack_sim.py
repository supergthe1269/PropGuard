#!/usr/bin/env python3
"""
PropGuard: Attack & Traffic Emulation Suite
Simulates baseline cross-zone flows, lateral port scans, and data exfiltration.
"""

import sys
import time
import os
import subprocess
import argparse

def get_host_pid(host_name: str):
    """Retrieve process PID of a Mininet host namespace."""
    cmd = f"ps aux | grep 'mininet:{host_name}' | grep -v grep | awk 'NR==1{{print $2}}'"
    try:
        pid = subprocess.check_output(cmd, shell=True).decode().strip()
        return pid if pid else None
    except Exception:
        return None

def exec_in_host(host_name: str, command: str):
    """Execute command inside host's network namespace."""
    pid = get_host_pid(host_name)
    if pid:
        full_cmd = f"sudo ip netns exec {pid} {command}"
        return os.system(full_cmd)
    else:
        # Fallback if running via mininet mx or standard CLI wrapper
        return os.system(f"sudo m {host_name} {command} 2>/dev/null || true")

def simulate_benign_traffic():
    """Generates normal baseline traffic between DMZ and DB, and between workstations."""
    print("[*] Generating baseline benign cross-zone traffic...")
    # h1 (DMZ Web) -> h5 (Core DB)
    print("    -> h1 (Web) querying h5 (Database)...")
    exec_in_host("h1", "ping -c 2 10.0.3.10 > /dev/null 2>&1")
    # h3 (WS1) -> h4 (WS2) normal file transfer/sync
    print("    -> h3 (WS1) communicating with h4 (WS2)...")
    exec_in_host("h3", "ping -c 2 10.0.2.20 > /dev/null 2>&1")
    print("[+] Baseline benign traffic injected successfully.")

def simulate_recon_scan():
    """Simulates reconnaissance port scan from compromised workstation h3 toward lateral host h4."""
    print("[*] Simulating lateral reconnaissance scan from h3 (10.0.2.10) -> h4 (10.0.2.20)...")
    exec_in_host("h3", "nc -z -w 1 10.0.2.20 20-80 > /dev/null 2>&1 || ping -c 5 -i 0.2 10.0.2.20 > /dev/null 2>&1")
    print("[+] Scan activity dispatched. Check PropGuard dashboard for RATE_LIMIT tier enforcement.")

def simulate_exfiltration():
    """Simulates high-volume data exfiltration from h3 toward core or external destination."""
    print("[*] Simulating data exfiltration attempt from h3 (10.0.2.10)...")
    exec_in_host("h3", "ping -c 10 -s 1400 -i 0.1 10.0.3.10 > /dev/null 2>&1")
    print("[+] Exfiltration burst dispatched. Check PropGuard dashboard for ISOLATE tier enforcement.")

def main():
    parser = argparse.ArgumentParser(description="PropGuard Traffic & Attack Emulation")
    parser.add_argument("--mode", choices=["benign", "scan", "exfil", "all"], default="benign",
                        help="Traffic mode to generate (default: benign)")
    args = parser.parse_args()

    if args.mode == "benign":
        simulate_benign_traffic()
    elif args.mode == "scan":
        simulate_recon_scan()
    elif args.mode == "exfil":
        simulate_exfiltration()
    elif args.mode == "all":
        simulate_benign_traffic()
        time.sleep(1)
        simulate_recon_scan()
        time.sleep(1)
        simulate_exfiltration()

if __name__ == "__main__":
    main()
