"""
Graph Engine
=============
Generates research-ready benchmark visualizations for the
adaptive post-quantum secure communication framework.
"""

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for headless environments
import matplotlib.pyplot as plt
import statistics
import os
from typing import Optional

try:
    plt.style.use("seaborn-v0_8-whitegrid")
except Exception:
    pass

try:
    from config import LOW_THRESHOLD, HIGH_THRESHOLD
except Exception:
    LOW_THRESHOLD, HIGH_THRESHOLD = 0.4, 0.75

DEFAULT_OUTPUT_DIR = "results"


def _ensure_output_dir(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)


def plot_mode_distribution(modes_used, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    modes = list(modes_used.keys())
    counts = list(modes_used.values())
    colors = ['#2ecc71', '#f39c12', '#e74c3c']

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(modes, counts, color=colors[:len(modes)], edgecolor='black')

    total = sum(counts) if sum(counts) else 1
    for bar, count in zip(bars, counts):
        pct = (count / total) * 100
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                f"{count} ({pct:.1f}%)", ha='center', va='bottom', fontweight='bold', fontsize=10)

    ax.set_title("Adaptive Mode Distribution", fontsize=14, fontweight='bold')
    ax.set_xlabel("Encryption Mode")
    ax.set_ylabel("Number of Sessions")
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    path = os.path.join(output_dir, "mode_distribution.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_threat_distribution(threat_scores, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(threat_scores, bins=16, color="#34495e", edgecolor="black", alpha=0.85)
    ax.axvline(LOW_THRESHOLD, color="#2ecc71", linestyle="--", linewidth=2, label=f"LOW<{LOW_THRESHOLD}")
    ax.axvline(HIGH_THRESHOLD, color="#e74c3c", linestyle="--", linewidth=2, label=f"HIGH≥{HIGH_THRESHOLD}")
    ax.set_title("Threat Score Distribution (QTI)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Threat Score")
    ax.set_ylabel("Sessions")
    ax.legend()
    fig.tight_layout()
    path = os.path.join(output_dir, "threat_distribution.png")
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_mode_by_threat_band(threat_scores, modes_list, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    bands = ["LOW", "MEDIUM", "HIGH"]
    modes = ["PQC_ONLY", "PQC_QKD", "PQC_QKD_MAX"]
    counts = {b: {m: 0 for m in modes} for b in bands}

    for score, mode in zip(threat_scores, modes_list):
        if score < LOW_THRESHOLD:
            band = "LOW"
        elif score < HIGH_THRESHOLD:
            band = "MEDIUM"
        else:
            band = "HIGH"
        if mode in counts[band]:
            counts[band][mode] += 1

    fig, ax = plt.subplots(figsize=(9, 5))
    x = range(len(bands))
    bottom = [0] * len(bands)
    colors = {"PQC_ONLY": "#2ecc71", "PQC_QKD": "#f39c12", "PQC_QKD_MAX": "#e74c3c"}

    for mode in modes:
        vals = [counts[b][mode] for b in bands]
        ax.bar(x, vals, bottom=bottom, label=mode, color=colors[mode], edgecolor="black", alpha=0.9)
        bottom = [b + v for b, v in zip(bottom, vals)]

    ax.set_xticks(list(x))
    ax.set_xticklabels(bands)
    ax.set_title("Mode Usage by Threat Band", fontsize=14, fontweight="bold")
    ax.set_xlabel("Threat Band")
    ax.set_ylabel("Sessions")
    ax.legend(title="Mode")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    path = os.path.join(output_dir, "mode_by_threat_band.png")
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_latency_by_mode(latencies, modes_list, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    modes = ["PQC_ONLY", "PQC_QKD", "PQC_QKD_MAX"]
    data = []
    labels = []
    for mode in modes:
        vals = [lat for lat, m in zip(latencies, modes_list) if m == mode]
        if vals:
            data.append(vals)
            labels.append(mode)

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.boxplot(data, labels=labels, showmeans=True)
    ax.set_title("Latency by Mode (Boxplot)", fontsize=14, fontweight="bold")
    ax.set_xlabel("Mode")
    ax.set_ylabel("Latency (seconds)")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    path = os.path.join(output_dir, "latency_by_mode.png")
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_qber_distribution(qkd_qbers, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    qbers = [q for q in qkd_qbers if isinstance(q, (int, float))]
    if not qbers:
        return None
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(qbers, bins=12, color="#9b59b6", edgecolor="black", alpha=0.85)
    ax.set_title("QKD QBER Distribution (QKD Sessions Only)", fontsize=14, fontweight="bold")
    ax.set_xlabel("QBER")
    ax.set_ylabel("Sessions")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    path = os.path.join(output_dir, "qber_distribution.png")
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_avg_time_by_mode(pqc_times, qkd_times, modes_list, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    modes = ["PQC_ONLY", "PQC_QKD", "PQC_QKD_MAX"]
    avg_pqc = []
    avg_qkd = []

    for mode in modes:
        idx = [i for i, m in enumerate(modes_list) if m == mode]
        if not idx:
            avg_pqc.append(0.0)
            avg_qkd.append(0.0)
            continue
        avg_pqc.append(statistics.mean([pqc_times[i] for i in idx]))
        avg_qkd.append(statistics.mean([qkd_times[i] for i in idx]))

    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(modes))
    ax.bar(x, avg_pqc, label="Avg PQC Time", color="#3498db", edgecolor="black", alpha=0.85)
    ax.bar(x, avg_qkd, bottom=avg_pqc, label="Avg QKD Time", color="#9b59b6", edgecolor="black", alpha=0.85)
    ax.set_xticks(list(x))
    ax.set_xticklabels(modes)
    ax.set_title("Average Key Establishment Time by Mode", fontsize=14, fontweight="bold")
    ax.set_xlabel("Mode")
    ax.set_ylabel("Seconds")
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    path = os.path.join(output_dir, "avg_time_by_mode.png")
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return path


def plot_security_vs_latency(latencies, security_scores, modes=None, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    fig, ax = plt.subplots(figsize=(9, 6))

    if modes:
        color_map = {"PQC_ONLY": '#2ecc71', "PQC_QKD": '#f39c12', "PQC_QKD_MAX": '#e74c3c'}
        for lat, sec, mode in zip(latencies, security_scores, modes):
            ax.scatter(lat, sec, c=color_map.get(mode, '#3498db'),
                       label=mode, s=50, alpha=0.7, edgecolors='black', linewidth=0.5)
        # Deduplicate legend
        handles, labels = ax.get_legend_handles_labels()
        by_label = dict(zip(labels, handles))
        ax.legend(by_label.values(), by_label.keys(), title="Mode")
    else:
        ax.scatter(latencies, security_scores, c='#3498db', s=50, alpha=0.7,
                   edgecolors='black', linewidth=0.5)

    ax.set_title("Security Score vs Latency", fontsize=14, fontweight='bold')
    ax.set_xlabel("Latency (seconds)")
    ax.set_ylabel("Security Score (equivalent bits)")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    path = os.path.join(output_dir, "security_vs_latency.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_latency_distribution(latencies, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(latencies, bins=15, color='#3498db', edgecolor='black', alpha=0.8)

    mean_lat = statistics.mean(latencies)
    ax.axvline(mean_lat, color='red', linestyle='--', linewidth=2,
               label=f'Mean = {mean_lat:.4f}s')

    ax.set_title("Latency Distribution", fontsize=14, fontweight='bold')
    ax.set_xlabel("Latency (seconds)")
    ax.set_ylabel("Frequency")
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    path = os.path.join(output_dir, "latency_distribution.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_average_metrics(latencies, security_scores, output_dir: str = DEFAULT_OUTPUT_DIR):
    _ensure_output_dir(output_dir)
    avg_latency = statistics.mean(latencies)
    avg_security = statistics.mean(security_scores)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    ax1.bar(["Avg Latency"], [avg_latency], color='#e67e22', edgecolor='black')
    ax1.set_ylabel("Seconds")
    ax1.set_title(f"Average Latency\n{avg_latency:.4f}s")
    ax1.grid(axis='y', alpha=0.3)

    ax2.bar(["Avg Security"], [avg_security], color='#27ae60', edgecolor='black')
    ax2.set_ylabel("Equivalent Bits")
    ax2.set_title(f"Average Security Score\n{avg_security:.1f} bits")
    ax2.grid(axis='y', alpha=0.3)

    fig.suptitle("Average Performance Metrics", fontsize=14, fontweight='bold')
    fig.tight_layout()
    path = os.path.join(output_dir, "average_metrics.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_threat_vs_security(threat_scores, security_scores, output_dir: str = DEFAULT_OUTPUT_DIR):
    """New graph: shows how security adapts to threat level."""
    _ensure_output_dir(output_dir)
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.scatter(threat_scores, security_scores, c=threat_scores,
               cmap='RdYlGn_r', s=60, alpha=0.8, edgecolors='black', linewidth=0.5)
    ax.set_title("Threat Score vs Security Response", fontsize=14, fontweight='bold')
    ax.set_xlabel("Quantum Threat Index (QTI)")
    ax.set_ylabel("Security Score (equivalent bits)")
    cbar = plt.colorbar(ax.collections[0], ax=ax)
    cbar.set_label("Threat Level")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    path = os.path.join(output_dir, "threat_vs_security.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def plot_pqc_vs_qkd_time(pqc_times, qkd_times, output_dir: str = DEFAULT_OUTPUT_DIR):
    """New graph: PQC vs QKD latency breakdown."""
    _ensure_output_dir(output_dir)
    sessions = list(range(1, len(pqc_times) + 1))

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(sessions, pqc_times, label='PQC Key Exchange', color='#3498db', alpha=0.8)
    ax.bar(sessions, qkd_times, bottom=pqc_times, label='QKD BB84',
           color='#9b59b6', alpha=0.8)

    ax.set_title("PQC vs QKD Latency per Session", fontsize=14, fontweight='bold')
    ax.set_xlabel("Session #")
    ax.set_ylabel("Time (seconds)")
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    fig.tight_layout()
    path = os.path.join(output_dir, "pqc_vs_qkd_time.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def generate_all_graphs(benchmark_data, output_dir: str = DEFAULT_OUTPUT_DIR):
    """Generate all graphs from benchmark results."""
    latencies = benchmark_data["latencies"]
    security_scores = benchmark_data["security_scores"]
    modes_used = benchmark_data["modes_used"]
    modes_list = benchmark_data.get("modes_list", None)
    threat_scores = benchmark_data.get("threat_scores", None)
    qkd_qbers = benchmark_data.get("qkd_qbers", [])
    pqc_times = benchmark_data.get("pqc_times", [])
    qkd_times = benchmark_data.get("qkd_times", [])

    paths = []
    paths.append(plot_mode_distribution(modes_used, output_dir=output_dir))
    paths.append(plot_security_vs_latency(latencies, security_scores, modes_list, output_dir=output_dir))
    paths.append(plot_average_metrics(latencies, security_scores, output_dir=output_dir))
    paths.append(plot_latency_distribution(latencies, output_dir=output_dir))

    paths.append(plot_latency_by_mode(latencies, modes_list, output_dir=output_dir))

    if threat_scores:
        paths.append(plot_threat_vs_security(threat_scores, security_scores, output_dir=output_dir))
        paths.append(plot_threat_distribution(threat_scores, output_dir=output_dir))
        paths.append(plot_mode_by_threat_band(threat_scores, modes_list, output_dir=output_dir))

    if pqc_times and qkd_times:
        paths.append(plot_pqc_vs_qkd_time(pqc_times, qkd_times, output_dir=output_dir))
        paths.append(plot_avg_time_by_mode(pqc_times, qkd_times, modes_list, output_dir=output_dir))

    qber_path = plot_qber_distribution(qkd_qbers, output_dir=output_dir)
    if qber_path:
        paths.append(qber_path)

    print(f"\nGraphs generated in '{output_dir}/':")
    for p in [p for p in paths if p]:
        print(f"  - {p}")

    return paths