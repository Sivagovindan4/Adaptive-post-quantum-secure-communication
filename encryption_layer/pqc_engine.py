"""
Post-Quantum Cryptography Engine
Real CRYSTALS-Kyber Key Encapsulation Mechanism (KEM)

Uses liboqs-python for NIST-standardized PQC.
Fallback: X25519 ECDH (classical but real key exchange) if liboqs unavailable.
"""

import time
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try to load liboqs (CRYSTALS-Kyber). Fall back to X25519 from 'cryptography'.
# ---------------------------------------------------------------------------
_USE_LIBOQS = False
try:
    import oqs
    # Force-load the native library now so failures are caught here
    oqs.KeyEncapsulation("Kyber1024")
    _USE_LIBOQS = True
    logger.info("liboqs loaded – using CRYSTALS-Kyber1024 for PQC KEM")
except Exception:
    # Catches ImportError, RuntimeError ("No oqs shared libraries found"),
    # OSError, and any other load-time failure.
    _USE_LIBOQS = False
    logger.warning(
        "liboqs not available. Falling back to X25519 ECDH. "
        "For real PQC (Kyber-1024), install liboqs C library + liboqs-python."
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

PQC_ALGORITHM = "Kyber1024" if _USE_LIBOQS else "X25519-ECDH"


# ============================================================================
# Kyber KEM via liboqs (NIST Level 5)
# ============================================================================
class KyberKEM:
    """Real CRYSTALS-Kyber-1024 Key Encapsulation Mechanism."""

    KEM_ALG = "Kyber1024"

    @staticmethod
    def generate_keypair():
        kem = oqs.KeyEncapsulation(KyberKEM.KEM_ALG)
        public_key = kem.generate_keypair()
        return public_key, kem

    @staticmethod
    def encapsulate(public_key_bytes: bytes):
        kem = oqs.KeyEncapsulation(KyberKEM.KEM_ALG)
        ciphertext, shared_secret = kem.encap_secret(public_key_bytes)
        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(kem_obj, ciphertext: bytes):
        shared_secret = kem_obj.decap_secret(ciphertext)
        return shared_secret


# ============================================================================
# X25519 ECDH fallback (classical, real key exchange)
# ============================================================================
class X25519KeyExchange:
    """Elliptic-Curve Diffie-Hellman on Curve25519 (classical fallback)."""

    @staticmethod
    def generate_keypair():
        private_key = X25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return public_key_bytes, private_key

    @staticmethod
    def derive_shared_secret(private_key, peer_public_key_bytes: bytes) -> bytes:
        peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        return private_key.exchange(peer_public_key)


# ============================================================================
# Unified PQC interface used by the rest of the framework
# ============================================================================
def pqc_keygen():
    """Generate a PQC keypair. Returns (public_key_bytes, secret_key_handle)."""
    if _USE_LIBOQS:
        return KyberKEM.generate_keypair()
    else:
        return X25519KeyExchange.generate_keypair()


def pqc_key_exchange():
    """
    Full key exchange between Alice and Bob.

    Kyber path:
        Alice keygen → Bob encapsulate(pk) → Alice decapsulate(ct)
    X25519 path:
        Both keygen → ECDH derive

    Returns: (derived_key: bytes, duration: float, metadata: dict)
    """
    start = time.perf_counter()

    if _USE_LIBOQS:
        alice_pk, alice_kem = KyberKEM.generate_keypair()
        ciphertext, bob_secret = KyberKEM.encapsulate(alice_pk)
        alice_secret = KyberKEM.decapsulate(alice_kem, ciphertext)
        assert alice_secret == bob_secret, "Kyber KEM shared-secret mismatch"
        raw_secret = alice_secret
        pk_size, ct_size = len(alice_pk), len(ciphertext)
    else:
        alice_pk, alice_sk = X25519KeyExchange.generate_keypair()
        bob_pk, bob_sk = X25519KeyExchange.generate_keypair()
        alice_shared = X25519KeyExchange.derive_shared_secret(alice_sk, bob_pk)
        bob_shared = X25519KeyExchange.derive_shared_secret(bob_sk, alice_pk)
        assert alice_shared == bob_shared, "ECDH shared-secret mismatch"
        raw_secret = alice_shared
        pk_size, ct_size = len(alice_pk), len(bob_pk)

    # Derive a clean AES-256 key through HKDF-SHA256
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pqc-session-key-v1",
    ).derive(raw_secret)

    duration = time.perf_counter() - start

    metadata = {
        "algorithm": PQC_ALGORITHM,
        "raw_secret_len": len(raw_secret),
        "derived_key_len": len(derived_key),
        "public_key_bytes": pk_size,
        "ciphertext_bytes": ct_size,
        "is_post_quantum": _USE_LIBOQS,
    }
    return derived_key, duration, metadata