"""
Key Derivation Module
======================
Provides HKDF-based key derivation functions used throughout the framework.
Replaces the naive SHA-256 hashing that was previously used.

Standard: RFC 5869 (HKDF using HMAC-SHA256)
"""

import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes


def derive_session_key(input_key_material: bytes,
                       salt: bytes = None,
                       info: bytes = b"session-key",
                       length: int = 32) -> bytes:
    """
    Derive a fixed-length key from arbitrary input keying material (IKM).
    Uses HKDF extract-and-expand (RFC 5869).

    Parameters
    ----------
    input_key_material : bytes
        Raw key material (e.g. from key exchange).
    salt : bytes, optional
        Random value to strengthen extraction (recommended 32 bytes).
    info : bytes
        Context / application-specific info string.
    length : int
        Desired output key length in bytes (default 32 = 256 bits).

    Returns
    -------
    bytes of the requested length.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(input_key_material)


def derive_subkeys(master_key: bytes, num_keys: int = 3) -> list[bytes]:
    """
    Derive multiple independent sub-keys from a single master key.
    Useful for separating encryption key, MAC key, and IV material.

    Uses HKDF-Expand with distinct info labels.
    """
    subkeys = []
    for i in range(num_keys):
        prk = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"subkey-{i}".encode(),
        ).derive(master_key)
        subkeys.append(prk)
    return subkeys


def generate_salt(length: int = 32) -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(length)
