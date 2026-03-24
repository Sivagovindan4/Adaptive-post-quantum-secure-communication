"""
Authentication Module
=====================
Ed25519 digital signatures for message authentication, key exchange
authentication, and identity verification.

Ed25519 provides:
  - 128-bit security level (equivalent to ~3000-bit RSA)
  - Deterministic signatures (no random nonce needed)
  - Very fast sign + verify
  - Small signatures (64 bytes) and keys (32 bytes)

For post-quantum signature resistance, the framework also supports
optional Dilithium via liboqs (if installed).
"""

import time
import logging
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

# Optional: Dilithium via liboqs for PQ signatures
_HAS_DILITHIUM = False
try:
    import oqs
    # Verify the native library actually loads
    oqs.Signature("Dilithium5")
    _HAS_DILITHIUM = True
except Exception:
    # ImportError, RuntimeError (missing .so/.dll), OSError, etc.
    _HAS_DILITHIUM = False


class Identity:
    """
    Represents a participant's cryptographic identity.
    Holds signing key (private) and verification key (public).
    """

    def __init__(self, name: str = "anonymous", use_pq: bool = False):
        self.name = name
        self.use_pq = use_pq and _HAS_DILITHIUM
        self._created_at = time.time()

        if self.use_pq:
            self._init_dilithium()
        else:
            self._init_ed25519()

    # ---- Ed25519 ----
    def _init_ed25519(self):
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self.algorithm = "Ed25519"
        self.public_key_bytes = self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    # ---- Dilithium (post-quantum) ----
    def _init_dilithium(self):
        self._sig = oqs.Signature("Dilithium5")
        self.public_key_bytes = self._sig.generate_keypair()
        self.algorithm = "Dilithium5"
        self._private_key = self._sig  # holds secret key internally

    def sign(self, data: bytes) -> bytes:
        """Sign arbitrary data. Returns signature bytes."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        if self.use_pq:
            return self._sig.sign(data)
        else:
            return self._private_key.sign(data)

    def verify(self, data: bytes, signature: bytes,
               peer_public_key_bytes: bytes = None) -> bool:
        """
        Verify a signature.
        If peer_public_key_bytes is None, verifies against own public key.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        try:
            if self.use_pq:
                verifier = oqs.Signature("Dilithium5")
                pk = peer_public_key_bytes or self.public_key_bytes
                return verifier.verify(data, signature, pk)
            else:
                if peer_public_key_bytes:
                    pk = Ed25519PublicKey.from_public_bytes(peer_public_key_bytes)
                else:
                    pk = self._public_key
                pk.verify(signature, data)
                return True
        except Exception:
            return False

    def export_public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def __repr__(self):
        return (f"Identity(name={self.name!r}, algo={self.algorithm}, "
                f"pk={self.public_key_bytes[:8].hex()}...)")


def create_identity(name: str, post_quantum: bool = False) -> Identity:
    """Factory function to create a new cryptographic identity."""
    return Identity(name=name, use_pq=post_quantum)


def sign_message(identity: Identity, message: bytes) -> dict:
    """Sign a message and return signature metadata."""
    start = time.perf_counter()
    signature = identity.sign(message)
    duration = time.perf_counter() - start

    return {
        "signature": signature.hex(),
        "signer": identity.name,
        "algorithm": identity.algorithm,
        "public_key": identity.export_public_key_hex(),
        "sign_time": duration,
    }


def verify_message(message: bytes, signature_hex: str,
                   public_key_hex: str, algorithm: str = "Ed25519") -> bool:
    """Verify a signature given hex-encoded signature and public key."""
    signature = bytes.fromhex(signature_hex)
    public_key_bytes = bytes.fromhex(public_key_hex)

    try:
        if algorithm == "Ed25519":
            pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pk.verify(signature, message)
            return True
        elif algorithm.startswith("Dilithium") and _HAS_DILITHIUM:
            verifier = oqs.Signature(algorithm)
            return verifier.verify(message, signature, public_key_bytes)
        else:
            logger.error(f"Unsupported signature algorithm: {algorithm}")
            return False
    except Exception:
        return False
