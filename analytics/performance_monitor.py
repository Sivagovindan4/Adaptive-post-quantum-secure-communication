"""
Performance Monitoring Module
==============================
Tracks detailed session metrics for analysis, including
cryptographic operation timings, threat data, and verification status.
"""

import statistics
import json
import os
from datetime import datetime
from typing import Optional


class PerformanceMonitor:

    def __init__(self):
        self.session_records = []

    def record_session(self, result: dict):
        """Record a full session result from run_secure_session()."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "mode": result.get("mode"),
            "threat_level": result.get("threat_level"),
            "threat_score": result.get("threat_score"),
            "security_score": result.get("security_score"),
            "latency": result.get("latency"),
            "pqc_time": result.get("pqc_time"),
            "qkd_time": result.get("qkd_time"),
            "pqc_algorithm": result.get("pqc_algorithm"),
            "key_method": result.get("key_combination_method"),
            "signature_algorithm": result.get("signature_algorithm"),
            "signature_valid": result.get("signature_valid"),
            "decrypt_verified": result.get("decrypt_verified"),
            "qkd_secure": result.get("qkd_secure"),
            "qkd_qber": result.get("qkd_qber"),
        }
        self.session_records.append(record)

    def get_records(self) -> list[dict]:
        return self.session_records

    def summary(self) -> dict:
        """Compute summary statistics."""
        if not self.session_records:
            return {"error": "No sessions recorded"}

        latencies = [r["latency"] for r in self.session_records]
        scores = [r["security_score"] for r in self.session_records]
        pqc_times = [r["pqc_time"] for r in self.session_records]
        qkd_times = [r["qkd_time"] for r in self.session_records if r["qkd_time"]]

        modes = {}
        for r in self.session_records:
            modes[r["mode"]] = modes.get(r["mode"], 0) + 1

        sig_ok = sum(1 for r in self.session_records if r.get("signature_valid"))
        dec_ok = sum(1 for r in self.session_records if r.get("decrypt_verified"))

        s = {
            "total_sessions": len(self.session_records),
            "avg_latency": round(statistics.mean(latencies), 4),
            "max_latency": round(max(latencies), 4),
            "min_latency": round(min(latencies), 4),
            "std_latency": round(statistics.stdev(latencies), 4) if len(latencies) > 1 else 0,
            "avg_security_score": round(statistics.mean(scores), 1),
            "avg_pqc_time": round(statistics.mean(pqc_times), 4),
            "avg_qkd_time": round(statistics.mean(qkd_times), 4) if qkd_times else 0,
            "mode_distribution": modes,
            "signatures_valid": sig_ok,
            "decryptions_verified": dec_ok,
            "pqc_algorithm": self.session_records[0].get("pqc_algorithm", "unknown"),
        }
        return s

    def print_summary(self):
        s = self.summary()
        print("\n" + "=" * 55)
        print("  PERFORMANCE SUMMARY")
        print("=" * 55)
        for key, val in s.items():
            print(f"  {key}: {val}")
        print("=" * 55)

    def export_json(self, filepath: Optional[str] = None, output_dir: str = "results", filename: str = "benchmark_results.json"):
        if filepath is None:
            filepath = os.path.join(output_dir, filename)

        dir_name = os.path.dirname(filepath)
        if dir_name:
            os.makedirs(dir_name, exist_ok=True)
        data = {
            "summary": self.summary(),
            "sessions": self.session_records,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[ANALYTICS] Results exported to {filepath}")