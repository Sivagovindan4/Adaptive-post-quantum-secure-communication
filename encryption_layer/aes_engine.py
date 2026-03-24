"""
AES-256-GCM Authenticated Encryption Engine
============================================
- Uses AES-256 in GCM mode (AEAD – Authenticated Encryption with Associated Data)
- Provides confidentiality + integrity + authenticity in one pass
- Immune to padding-oracle attacks (unlike CBC)
- Quantum-safe effective security: 128 bits (Grover halves symmetric keys)

Key input: raw 32-byte key (from HKDF in key_derivation module)
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# GCM recommended nonce size is 96 bits (12 bytes)
NONCE_SIZE = 12
# GCM tag length in bytes
TAG_SIZE = 16


def aes_encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> dict:
    """
    Encrypt with AES-256-GCM.

    Parameters
    ----------
    plaintext : bytes
        Data to encrypt.
    key : bytes
        32-byte (256-bit) symmetric key.
    associated_data : bytes, optional
        Additional authenticated data (AAD) – authenticated but NOT encrypted.
        Useful for headers, session IDs, metadata.

    Returns
    -------
    dict with 'nonce', 'ciphertext' (includes GCM tag), both hex-encoded.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes (256 bits), got {len(key)}")

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    # GCM appends the authentication tag to the ciphertext
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext_with_tag.hex(),
        "aad": associated_data.hex() if associated_data else None,
        "algorithm": "AES-256-GCM",
        "tag_bits": TAG_SIZE * 8,
    }


def aes_decrypt(nonce_hex: str, ciphertext_hex: str, key: bytes,
                associated_data: bytes = None) -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.

    Raises cryptography.exceptions.InvalidTag if tampering is detected.
    """
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes (256 bits), got {len(key)}")

    nonce = bytes.fromhex(nonce_hex)
    ciphertext_with_tag = bytes.fromhex(ciphertext_hex)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
    return plaintext