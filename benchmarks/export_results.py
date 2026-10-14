#!/usr/bin/env python3
"""
PropGuard: Benchmark Exporter & Plot Generator
Saves trial metrics to CSV and produces a comparative evaluation figure.
"""

import os
import sys
import csv
import numpy as np
import matplotlib.pyplot as plt

# Ensure repository root and benchmarks folder are in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
for path in [SCRIPT_DIR, ROOT_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

# Support running both directly and as a module
try:
    from benchmarks import run_simulation
except ImportError:
    from benchmarks.benchmarks import run_simulation

def export_csv(pg_metrics, bl_metrics, filename=os.path.join(SCRIPT_DIR, "benchmark_results.csv")):
    with open(filename, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["System", "Containment_Rate_Pct", "Precision_Pct", "Avg_Latency_ms", "False_Positive_Rate_Pct"])
        
        # Baseline row
        writer.writerow([
            "Static Baseline",
            bl_metrics["containment_success"],
            bl_metrics["correct_tier"],
            round(float(np.mean(bl_metrics["latencies"])), 3),
            0.0
        ])
        
        # PropGuard row
        writer.writerow([
            "PropGuard",
            pg_metrics["containment_success"],
            pg_metrics["correct_tier"],
            round(float(np.mean(pg_metrics["latencies"])), 3),
            round((pg_metrics["false_positives"] / (pg_metrics["trials"] * 4)) * 100, 2)
        ])
    print(f"[+] Saved metrics CSV to: {filename}")

def generate_figure(pg_metrics, bl_metrics, output_img=os.path.join(SCRIPT_DIR, "evaluation_metrics.png")):
    categories = ["2nd-Hop Containment", "Response Precision", "False Positive Rate"]
    
    baseline_vals = [
        bl_metrics["containment_success"],
        bl_metrics["correct_tier"],
        0.0
    ]
    propguard_vals = [
        pg_metrics["containment_success"],
        pg_metrics["correct_tier"],
        (pg_metrics["false_positives"] / (pg_metrics["trials"] * 4)) * 100
    ]

    x = np.arange(len(categories))
    width = 0.35

    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)

    rects1 = ax.bar(x - width/2, baseline_vals, width, label="Static Baseline (Isolated)", color="#94a3b8", edgecolor="#475569")
    rects2 = ax.bar(x + width/2, propguard_vals, width, label="PropGuard (Graph XAI)", color="#0ea5e9", edgecolor="#0369a1")

    ax.set_ylabel("Rate (%)", fontsize=11, fontweight="bold")
    ax.set_title("PropGuard vs. Static Policy SDN Defense", fontsize=13, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=10, fontweight="bold")
    ax.set_ylim(0, 115)
    ax.legend(frameon=True, facecolor="white", edgecolor="#cbd5e1", loc="upper right")

    def autolabel(rects):
        for rect in rects:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%",
                        xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha="center", va="bottom", fontsize=9, fontweight="bold")

    autolabel(rects1)
    autolabel(rects2)

    fig.tight_layout()
    plt.savefig(output_img)
    plt.close()
    print(f"[+] Saved evaluation figure to: {output_img}")

def main():
    print("[*] Running 100 simulation cycles for evaluation export...")
    pg, bl = run_simulation(trials=100)
    export_csv(pg, bl)
    generate_figure(pg, bl)

if __name__ == "__main__":
    main()
