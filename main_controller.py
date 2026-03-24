"""
Main Adaptive Controller
Post-Quantum Secure Communication Framework
=============================================
Orchestrates:
  1. Threat evaluation (QTI)
  2. Adaptive mode selection
  3. Real PQC key exchange (Kyber / X25519)
  4. Optional QKD BB84 via Qiskit
  5. Hybrid key combination (HKDF)
  6. AES-256-GCM authenticated encryption
  7. Ed25519 digital signature
  8. End-to-end encrypt → decrypt verification
"""

import time
from threat_model.quantum_threat_index import ThreatEnvironment, evaluate_qti, evaluate_qti_detailed
from encryption_layer.aes_engine import aes_encrypt, aes_decrypt
from encryption_layer.pqc_engine import pqc_key_exchange, PQC_ALGORITHM
from encryption_layer.qkd_bb84_qiskit import bb84_qkd
from encryption_layer.hybrid_combiner import combine_keys, combine_keys_max_security
from authentication import Identity, sign_message, verify_message
from config import SECURITY_PQC, SECURITY_QKD


def compute_security_score(mode):
    if mode == "PQC_ONLY":
        return SECURITY_PQC
    elif mode == "PQC_QKD":
        return SECURITY_PQC + SECURITY_QKD
    elif mode == "PQC_QKD_MAX":
        return SECURITY_PQC + SECURITY_QKD + 50
    return SECURITY_PQC


def adaptive_mode_selection(threat_level):
    if threat_level == "LOW":
        return "PQC_ONLY"
    elif threat_level == "MEDIUM":
        return "PQC_QKD"
    else:
        return "PQC_QKD_MAX"


def run_secure_session(
    message: str,
    verbose: bool = True,
    force_mode: str = None,
    env: ThreatEnvironment = None,
    qkd_params: dict | None = None,
):
    """
    Execute one complete adaptive secure communication session.

    Performs real cryptographic operations:
      - PQC key exchange (Kyber-1024 or X25519 ECDH)
      - Optional QKD BB84 (Qiskit simulation)
      - Hybrid key combination via HKDF
      - AES-256-GCM authenticated encryption
      - Ed25519 digital signature on ciphertext
      - Full decrypt + verify round-trip

    Returns: dict with mode, threat info, security score, timing, crypto metadata
    """
    session_start = time.perf_counter()

    # ---- 1. Threat evaluation ----
    threat_details = evaluate_qti_detailed(env)
    threat_score = threat_details["score"]
    threat_level = threat_details["level"]
    mode = force_mode or adaptive_mode_selection(threat_level)

    if verbose:
        print(f"\n[THREAT] Score={threat_score:.4f} Level={threat_level}")
        print(f"[MODE]   {mode} (PQC algorithm: {PQC_ALGORITHM})")

    # ---- 2. PQC key exchange (real cryptographic operation) ----
    pqc_key, pqc_time, pqc_meta = pqc_key_exchange()

    if verbose:
        print(f"[PQC]    {pqc_meta['algorithm']} | "
              f"pk={pqc_meta['public_key_bytes']}B | "
              f"ct={pqc_meta['ciphertext_bytes']}B | "
              f"time={pqc_time:.4f}s")

    # ---- 3. Optional QKD ----
    qkd_time = 0.0
    qkd_key = None
    qkd_result = None

    if mode in ("PQC_QKD", "PQC_QKD_MAX"):
        params = dict(qkd_params or {})
        # Avoid returning large detail payloads in normal sessions.
        params.pop("return_details", None)
        qkd_result = bb84_qkd(**params)
        qkd_time = qkd_result["time"]

        if verbose:
            print(f"[QKD]    Secure={qkd_result['secure']} | "
                  f"QBER={qkd_result['qber']:.4f} | "
                  f"Raw bits={qkd_result['raw_key_bits']} | "
                  f"Qubits={qkd_result['qubits_sent']} | "
                  f"time={qkd_time:.4f}s")

        if qkd_result["secure"] and qkd_result["key"] is not None:
            qkd_key = qkd_result["key"]

    # ---- 4. Hybrid key combination ----
    if mode == "PQC_QKD_MAX" and qkd_key is not None:
        session_key = combine_keys_max_security(
            pqc_key, qkd_key,
            session_context=f"session-{time.time_ns()}".encode()
        )
        key_method = "HKDF-XOR-double-pass"
    elif qkd_key is not None:
        session_key = combine_keys(
            pqc_key, qkd_key,
            session_context=f"session-{time.time_ns()}".encode()
        )
        key_method = "HKDF-concat"
    else:
        session_key = pqc_key
        key_method = "PQC-direct"

    if verbose:
        print(f"[KEY]    Method={key_method} | "
              f"Session key={session_key[:4].hex()}...{session_key[-4:].hex()} "
              f"({len(session_key)*8} bits)")

    # ---- 5. Create identity + sign ----
    sender = Identity(name="Alice")
    aad = f"mode={mode},ts={time.time_ns()}".encode()

    # ---- 6. AES-256-GCM authenticated encryption ----
    encrypted = aes_encrypt(message.encode("utf-8"), session_key, aad)

    if verbose:
        print(f"[ENC]    AES-256-GCM | nonce={encrypted['nonce'][:16]}... | "
              f"ct_len={len(encrypted['ciphertext'])//2}B")

    # ---- 7. Digital signature on ciphertext ----
    sig_data = sign_message(sender, encrypted["ciphertext"].encode())

    if verbose:
        print(f"[SIG]    {sig_data['algorithm']} | "
              f"sig={sig_data['signature'][:32]}... | "
              f"time={sig_data['sign_time']:.6f}s")

    # ---- 8. Decrypt + verify round-trip (proof of correctness) ----
    decrypted = aes_decrypt(
        encrypted["nonce"], encrypted["ciphertext"], session_key, aad
    )
    if decrypted.decode("utf-8") != message:
        raise ValueError("Decryption verification FAILED")

    sig_valid = verify_message(
        encrypted["ciphertext"].encode(),
        sig_data["signature"],
        sig_data["public_key"],
        sig_data["algorithm"],
    )
    assert sig_valid, "Signature verification FAILED"

    total_time = time.perf_counter() - session_start
    security_score = compute_security_score(mode)

    if verbose:
        print(f"[VERIFY] Decrypt=OK | Signature=VALID")
        print(f"[SCORE]  {security_score} bits equivalent security")
        print(f"[TIME]   Total={total_time:.4f}s "
              f"(PQC={pqc_time:.4f} QKD={qkd_time:.4f})")

    return {
        "mode": mode,
        "threat_level": threat_level,
        "threat_score": round(threat_score, 4),
        "threat_details": threat_details,
        "security_score": security_score,
        "latency": total_time,
        "pqc_time": pqc_time,
        "qkd_time": qkd_time,
        "pqc_algorithm": PQC_ALGORITHM,
        "pqc_metadata": pqc_meta,
        "key_combination_method": key_method,
        "qkd_secure": qkd_result["secure"] if qkd_result else None,
        "qkd_qber": round(qkd_result["qber"], 4) if qkd_result else None,
        "qkd_raw_bits": qkd_result["raw_key_bits"] if qkd_result else None,
        "signature_algorithm": sig_data["algorithm"],
        "signature_valid": sig_valid,
        "decrypt_verified": True,
        "encrypted_payload": encrypted,
    }


if __name__ == "__main__":
    print("=" * 60)
    print("  Adaptive Post-Quantum Secure Communication Framework")
    print("=" * 60)
    message = "Quantum Adaptive Secure Communication – Real Crypto!"
    result = run_secure_session(message)
    print(f"\nSession Result Summary:")
    for k in ("mode", "threat_level", "security_score", "latency",
              "pqc_algorithm", "key_combination_method",
              "decrypt_verified", "signature_valid"):
        print(f"  {k}: {result[k]}")