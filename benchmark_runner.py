"""
Benchmark Runner
=================
Runs multiple adaptive secure sessions with real cryptographic operations.
Collects performance, security, and cryptographic verification statistics.
Generates research-grade visualizations and exports results.
"""

import statistics
from datetime import datetime
from pathlib import Path
from main_controller import run_secure_session
from analytics.graph_engine import generate_all_graphs
from analytics.performance_monitor import PerformanceMonitor
from config import QKD_MODE, BENCHMARK_SESSIONS
from encryption_layer.pqc_engine import PQC_ALGORITHM


def _create_timestamped_results_dir(base_dir: str = "results") -> str:
    base_path = Path(base_dir)
    base_path.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    candidate = base_path / f"run_{ts}"
    if not candidate.exists():
        candidate.mkdir(parents=True, exist_ok=False)
        return str(candidate)

    for idx in range(1, 1000):
        candidate = base_path / f"run_{ts}_{idx}"
        if not candidate.exists():
            candidate.mkdir(parents=True, exist_ok=False)
            return str(candidate)

    raise RuntimeError("Could not create a unique timestamped results directory")


def run_benchmark(num_sessions: int = None):
    total = num_sessions or BENCHMARK_SESSIONS

    output_dir = _create_timestamped_results_dir("results")

    print(f"\n{'=' * 60}")
    print(f"  BENCHMARK START | {total} sessions | {QKD_MODE} mode")
    print(f"  PQC Algorithm: {PQC_ALGORITHM}")
    print(f"  Output Folder: {output_dir}")
    print(f"{'=' * 60}\n")

    monitor = PerformanceMonitor()

    latencies = []
    security_scores = []
    threat_scores = []
    threat_levels = []
    pqc_times = []
    qkd_times = []
    qkd_qbers = []
    qkd_secure_flags = []
    modes_list = []
    modes_used = {"PQC_ONLY": 0, "PQC_QKD": 0, "PQC_QKD_MAX": 0}

    # Force a small number of sessions to cover all modes for graphs.
    forced_modes = []
    if total >= 3:
        forced_modes.extend(["PQC_ONLY", "PQC_QKD", "PQC_QKD_MAX"])
    # Ensure PQC_QKD_MAX appears more than once in typical runs.
    target_max = 2 if total >= 10 else 1
    while forced_modes.count("PQC_QKD_MAX") < target_max and len(forced_modes) < total:
        forced_modes.append("PQC_QKD_MAX")

    verified_count = 0
    sig_valid_count = 0

    for i in range(total):
        print(f"\n--- Session {i + 1}/{total} ---")

        forced_mode = forced_modes[i] if i < len(forced_modes) else None

        result = run_secure_session(
            "Quantum Adaptive Benchmark – Real Crypto Session",
            verbose=(i == 0),  # Full output only for first session
            force_mode=forced_mode,
        )

        # Collect metrics
        latencies.append(result["latency"])
        security_scores.append(result["security_score"])
        threat_scores.append(result["threat_score"])
        threat_levels.append(result.get("threat_level"))
        pqc_times.append(result["pqc_time"])
        qkd_times.append(result["qkd_time"])
        qkd_qbers.append(result.get("qkd_qber"))
        qkd_secure_flags.append(result.get("qkd_secure"))
        modes_list.append(result["mode"])
        modes_used[result["mode"]] += 1

        if result.get("decrypt_verified"):
            verified_count += 1
        if result.get("signature_valid"):
            sig_valid_count += 1

        monitor.record_session(result)

        if i > 0:  # Compact output for subsequent sessions
            print(f"  Mode={result['mode']} | "
                  f"Security={result['security_score']} | "
                  f"Latency={result['latency']:.4f}s | "
                  f"Verified={result['decrypt_verified']}")

    # ---- Summary ----
    print(f"\n{'=' * 60}")
    print(f"  BENCHMARK COMPLETE")
    print(f"{'=' * 60}")
    print(f"  Total Sessions:       {total}")
    print(f"  PQC Algorithm:        {PQC_ALGORITHM}")
    print(f"  Average Latency:      {statistics.mean(latencies):.4f}s")
    print(f"  Std Dev Latency:      {statistics.stdev(latencies):.4f}s" if total > 1 else "")
    print(f"  Average Security:     {statistics.mean(security_scores):.1f} bits")
    print(f"  Avg PQC Time:         {statistics.mean(pqc_times):.4f}s")
    if any(t > 0 for t in qkd_times):
        active_qkd = [t for t in qkd_times if t > 0]
        print(f"  Avg QKD Time:         {statistics.mean(active_qkd):.4f}s "
              f"({len(active_qkd)} sessions)")
    print(f"  Decryptions Verified: {verified_count}/{total}")
    print(f"  Signatures Valid:     {sig_valid_count}/{total}")
    print(f"\n  Mode Distribution:")
    for mode, count in modes_used.items():
        pct = (count / total) * 100
        print(f"    {mode}: {count} ({pct:.1f}%)")

    # ---- Build graph data ----
    benchmark_data = {
        "latencies": latencies,
        "security_scores": security_scores,
        "modes_used": modes_used,
        "modes_list": modes_list,
        "threat_scores": threat_scores,
        "threat_levels": threat_levels,
        "pqc_times": pqc_times,
        "qkd_times": qkd_times,
        "qkd_qbers": qkd_qbers,
        "qkd_secure_flags": qkd_secure_flags,
        "forced_modes_count": len(forced_modes),
    }

    # Generate graphs
    generate_all_graphs(benchmark_data, output_dir=output_dir)

    # Export JSON results
    monitor.print_summary()
    monitor.export_json(output_dir=output_dir)

    return benchmark_data


if __name__ == "__main__":
    run_benchmark()