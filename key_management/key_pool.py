"""
Key Pool Management Module
============================
Production-grade key lifecycle management:
  - Pre-generated key pool for low-latency session start
  - Key expiry and rotation
  - Secure key destruction (zeroing memory)
  - Thread-safe operations
  - Key usage tracking for audit
"""

import os
import time
import threading
import hashlib
from collections import deque
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


@dataclass
class ManagedKey:
    """A key with metadata for lifecycle tracking."""
    key: bytes                          # 32-byte raw key
    key_id: str = ""                    # Unique identifier (hex of SHA-256)
    created_at: float = 0.0            # Unix timestamp
    expires_at: float = 0.0            # Unix timestamp
    used: bool = False
    source: str = "pool"               # 'pool', 'pqc', 'qkd', 'hybrid'

    def __post_init__(self):
        if not self.key_id:
            self.key_id = hashlib.sha256(self.key).hexdigest()[:16]
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + 3600  # 1 hour default TTL

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class KeyPoolManager:
    """
    Thread-safe key pool with automatic replenishment,
    expiry management, and secure destruction.
    """

    def __init__(self, max_capacity: int = 20, key_ttl: int = 3600,
                 low_threshold: int = 5, initial_count: int = 10):
        self._pool: deque[ManagedKey] = deque()
        self._lock = threading.Lock()
        self.max_capacity = max_capacity
        self.key_ttl = key_ttl  # seconds
        self.low_threshold = low_threshold
        self._keys_issued = 0
        self._keys_expired = 0

        self._initialize_pool(initial_count)

    # ---- Initialization ----
    def _initialize_pool(self, count: int):
        for _ in range(count):
            self._pool.append(self._generate_managed_key())
        print(f"[KEY POOL] Initialized with {len(self._pool)} keys "
              f"(TTL={self.key_ttl}s)")

    # ---- Key generation (cryptographically secure) ----
    @staticmethod
    def _generate_raw_key() -> bytes:
        """Generate 32-byte key from OS CSPRNG."""
        return os.urandom(32)

    def _generate_managed_key(self, source: str = "pool") -> ManagedKey:
        raw = self._generate_raw_key()
        return ManagedKey(
            key=raw,
            created_at=time.time(),
            expires_at=time.time() + self.key_ttl,
            source=source,
        )

    # ---- Get a key ----
    def get_key(self) -> ManagedKey:
        """
        Return the next valid (non-expired) key from the pool.
        Generates an emergency key if pool is empty.
        """
        with self._lock:
            # Purge expired keys
            self._purge_expired()

            if len(self._pool) == 0:
                print("[KEY POOL] EMPTY – generating emergency key")
                mk = self._generate_managed_key(source="emergency")
            else:
                mk = self._pool.popleft()

            mk.used = True
            self._keys_issued += 1

            # Replenish if below threshold
            if len(self._pool) < self.low_threshold:
                deficit = self.low_threshold - len(self._pool)
                for _ in range(min(deficit, self.max_capacity - len(self._pool))):
                    self._pool.append(self._generate_managed_key())

            return mk

    # ---- Store an externally-generated key ----
    def store_key(self, key: bytes, source: str = "external") -> ManagedKey:
        """Store a PQC or QKD derived key in the pool for reuse."""
        mk = ManagedKey(
            key=key,
            created_at=time.time(),
            expires_at=time.time() + self.key_ttl,
            source=source,
        )
        with self._lock:
            if len(self._pool) < self.max_capacity:
                self._pool.append(mk)
        return mk

    # ---- Expiry management ----
    def _purge_expired(self):
        before = len(self._pool)
        self._pool = deque(mk for mk in self._pool if not mk.is_expired)
        purged = before - len(self._pool)
        if purged > 0:
            self._keys_expired += purged
            print(f"[KEY POOL] Purged {purged} expired keys")

    # ---- Secure key destruction ----
    @staticmethod
    def destroy_key(mk: ManagedKey):
        """Overwrite key material in memory (best-effort in Python)."""
        if mk.key and isinstance(mk.key, (bytearray, memoryview)):
            for i in range(len(mk.key)):
                mk.key[i] = 0
        # For immutable bytes we can't zero, but we dereference
        mk.key = b'\x00' * 32
        mk.used = True

    # ---- Status ----
    def status(self) -> dict:
        with self._lock:
            return {
                "pool_size": len(self._pool),
                "max_capacity": self.max_capacity,
                "keys_issued": self._keys_issued,
                "keys_expired": self._keys_expired,
                "key_ttl_sec": self.key_ttl,
            }

    def __repr__(self):
        s = self.status()
        return (f"KeyPool(size={s['pool_size']}/{s['max_capacity']}, "
                f"issued={s['keys_issued']}, expired={s['keys_expired']})")