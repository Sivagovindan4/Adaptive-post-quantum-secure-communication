"""
End-to-End Network Demo
=========================
Demonstrates the FULL real cryptographic protocol over TCP:

  1. Server starts listening (background thread)
  2. Client evaluates quantum threat
  3. Client + Server perform real PQC key exchange over the network
  4. Client runs QKD BB84 (if threat warrants it)
  5. Keys are combined via HKDF
  6. Message encrypted with AES-256-GCM + signed with Ed25519
  7. Server decrypts, verifies signature, sends ACK
  8. Full round-trip verified

This proves the system works as a REAL communication protocol,
not just a local simulation.
"""

import time
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from transport.server import SecureServer
from transport.client import SecureClient
from config import TRANSPORT_HOST, TRANSPORT_PORT


def run_network_demo(num_sessions: int = 5):
    print("=" * 65)
    print("  ADAPTIVE POST-QUANTUM SECURE COMMUNICATION")
    print("  End-to-End Network Demo (Real Cryptography)")
    print("=" * 65)

    # ---- Start server in background ----
    server = SecureServer(host=TRANSPORT_HOST, port=TRANSPORT_PORT,
                          identity_name="QuantumServer")
    server.start(blocking=False)
    time.sleep(0.5)  # Give server time to bind

    client = SecureClient(host=TRANSPORT_HOST, port=TRANSPORT_PORT,
                          identity_name="QuantumClient")

    results = []

    try:
        for i in range(num_sessions):
            print(f"\n{'─' * 50}")
            print(f"  Network Session {i + 1}/{num_sessions}")
            print(f"{'─' * 50}")

            message = f"Classified message #{i+1} – quantum-safe encrypted"
            result = client.send_secure_message(message)
            results.append(result)

            time.sleep(0.3)  # Small gap between sessions

    finally:
        server.stop()

    # ---- Summary ----
    print(f"\n{'=' * 65}")
    print(f"  NETWORK DEMO COMPLETE – {len(results)} sessions")
    print(f"{'=' * 65}")

    for i, r in enumerate(results):
        print(f"\n  Session {i+1}:")
        print(f"    Mode:       {r['mode']}")
        print(f"    Threat:     {r['threat_score']} ({r['threat_level']})")
        print(f"    Security:   {r['security_score']} bits")
        print(f"    Latency:    {r['latency']:.4f}s")
        print(f"    PQC:        {r['pqc_algorithm']}")
        print(f"    Signature:  {r['signature_algorithm']}")
        print(f"    Server ACK: {r['server_ack']}")

    return results


if __name__ == "__main__":
    sessions = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    run_network_demo(sessions)
