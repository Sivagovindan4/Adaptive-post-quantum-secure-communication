"""
Global Configuration Parameters
================================
Adaptive Post-Quantum Secure Communication Framework
"""

# ===== THREAT THRESHOLDS =====
LOW_THRESHOLD = 0.4       # Below this → LOW threat → PQC_ONLY
HIGH_THRESHOLD = 0.75     # Above this → HIGH threat → PQC_QKD_MAX

# ===== QKD SETTINGS =====
QKD_MODE = "RESEARCH"     # "RESEARCH" (64 qubits, realistic) or "BENCHMARK" (16 qubits, fast)
QKD_QUBITS_RESEARCH = 64
QKD_QUBITS_BENCHMARK = 16
QBER_THRESHOLD = 0.11     # BB84 security limit (theoretical max ~11%)

# ===== SECURITY SCORES (equivalent symmetric bits) =====
# PQC_ONLY: Kyber-1024 = NIST Level 5 ≈ AES-256 ≈ 256 bits classic, ~140 bits quantum
SECURITY_PQC = 140
# QKD (assuming information-theoretic security from one-time pad properties)
SECURITY_QKD = 256
# Total PQC+QKD = 396, PQC+QKD_MAX = 446

# ===== PQC SETTINGS =====
PQC_KEM_ALGORITHM = "Kyber1024"          # CRYSTALS-Kyber-1024 (if liboqs available)
PQC_FALLBACK_ALGORITHM = "X25519-ECDH"   # Classical fallback
PQC_SIGNATURE_ALGORITHM = "Ed25519"      # Digital signature (Ed25519 or Dilithium5)

# ===== AES SETTINGS =====
AES_MODE = "GCM"          # Authenticated encryption (AEAD)
AES_KEY_BITS = 256
AES_NONCE_BYTES = 12      # GCM recommended nonce size

# ===== KEY MANAGEMENT =====
KEY_POOL_SIZE = 20
KEY_TTL_SECONDS = 3600    # 1 hour key lifetime
KEY_POOL_LOW_THRESHOLD = 5

# ===== NETWORK TRANSPORT =====
TRANSPORT_HOST = "127.0.0.1"
TRANSPORT_PORT = 9876

# Optional: Server public key pinning (hex-encoded Ed25519 raw public key).
# When set (non-empty), the client will reject servers whose public key differs.
# Leave empty to disable pinning.
PINNED_SERVER_PUBLIC_KEY_HEX = ""

# ===== BENCHMARK =====
BENCHMARK_SESSIONS = 50
MAX_LATENCY = 0.5         # seconds (warning threshold)