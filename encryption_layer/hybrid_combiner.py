"""
Hybrid Key Combiner
====================
Cryptographically combines keys from multiple sources (PQC + QKD)
using HKDF so that the final session key is secure even if ONE
source is compromised.

Design principle: defense-in-depth – the combined key is at least
as strong as the strongest input.
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def _salt_from_context(session_context: bytes, label: bytes) -> bytes:
    if session_context is None:
        return None
    h = hashes.Hash(hashes.SHA256())
    h.update(b"hybrid-salt-v1|")
    h.update(label)
    h.update(b"|")
    h.update(session_context)
    return h.finalize()


def combine_keys(pqc_key: bytes, qkd_key: bytes = None,
                 session_context: bytes = None) -> bytes:
    """
    Combine PQC and (optional) QKD keys into a single 256-bit session key.

    Uses HKDF with the concatenation of all key material as input.
    An optional session_context (e.g. timestamp, session-id) is bound
    into the derivation as HKDF 'info'.

    Parameters
    ----------
    pqc_key : bytes
        32-byte key from PQC key exchange.
    qkd_key : bytes, optional
        32-byte key from QKD BB84 (None if QKD not used / insecure).
    session_context : bytes, optional
        Additional data to bind into the key (session ID, timestamp).

    Returns
    -------
    bytes – 32-byte combined session key.
    """
    if pqc_key is None:
        raise ValueError("PQC key must not be None")

    # Concatenate all available key material
    ikm = pqc_key
    if qkd_key is not None:
        ikm = pqc_key + qkd_key  # 64 bytes of input keying material

    info = b"hybrid-adaptive-session-key-v1" + (b"|" + session_context if session_context else b"")

    salt = _salt_from_context(session_context, b"combine")

    combined = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(ikm)

    return combined


def combine_keys_max_security(pqc_key: bytes, qkd_key: bytes,
                              session_context: bytes = None) -> bytes:
    """
    Maximum security combination: two separate HKDF passes with
    different info strings, XOR'd together.

    Even if HKDF itself were somehow weakened, the XOR of two
    independent derivations remains secure.
    """
    if pqc_key is None or qkd_key is None:
        raise ValueError("Both PQC and QKD keys required for MAX security")

    info_base = b"hybrid-max-security-v2" + (b"|" + session_context if session_context else b"")

    # Independent derivations: one from PQC-only, one from QKD-only.
    # Use different hash functions to reduce shared assumptions.
    key_a = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_salt_from_context(session_context, b"pass-A"),
        info=info_base + b"|pass-A|PQC",
    ).derive(pqc_key)

    key_b = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=_salt_from_context(session_context, b"pass-B"),
        info=info_base + b"|pass-B|QKD",
    ).derive(qkd_key)

    # XOR both derivations
    combined = bytes(a ^ b for a, b in zip(key_a, key_b))
    return combined
