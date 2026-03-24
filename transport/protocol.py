"""
Secure Transport Protocol
==========================
Defines the wire protocol for the adaptive quantum-safe communication system.

Message format (JSON over TCP):
  {
    "type": "HANDSHAKE" | "KEY_EXCHANGE" | "DATA" | "ACK" | "CLOSE",
    "session_id": "<uuid>",
    "timestamp": <float>,
    "payload": { ... },
    "signature": "<hex>",
    "signer_pk": "<hex>",
    "sig_algorithm": "Ed25519"
  }

Handshake flow:
  1. Client → HANDSHAKE (public key, identity)
  2. Server → HANDSHAKE_ACK (public key, identity)
  3. Client → KEY_EXCHANGE (PQC public key or ciphertext)
  4. Server → KEY_EXCHANGE_ACK (PQC ciphertext or confirmation)
  5. Both derive session key
  6. Client → DATA (AES-256-GCM encrypted payload)
  7. Server → ACK
"""

import json
import uuid
import time
import struct
from dataclasses import dataclass, field
from enum import Enum


class ProtocolError(Exception):
    """Raised when a protocol invariant is violated."""


class MessageType(str, Enum):
    HANDSHAKE = "HANDSHAKE"
    HANDSHAKE_ACK = "HANDSHAKE_ACK"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_EXCHANGE_ACK = "KEY_EXCHANGE_ACK"
    KEY_MATERIAL = "KEY_MATERIAL"
    KEY_MATERIAL_ACK = "KEY_MATERIAL_ACK"
    DATA = "DATA"
    ACK = "ACK"
    CLOSE = "CLOSE"
    ERROR = "ERROR"


@dataclass
class ProtocolMessage:
    """Structured protocol message."""
    msg_type: MessageType
    session_id: str = ""
    timestamp: float = 0.0
    payload: dict = field(default_factory=dict)
    signature: str = ""
    signer_pk: str = ""
    sig_algorithm: str = "Ed25519"

    def __post_init__(self):
        if not self.session_id:
            self.session_id = str(uuid.uuid4())
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_json(self) -> str:
        return json.dumps({
            "type": self.msg_type.value if isinstance(self.msg_type, MessageType)
                   else self.msg_type,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "signature": self.signature,
            "signer_pk": self.signer_pk,
            "sig_algorithm": self.sig_algorithm,
        })

    def signable_dict(self) -> dict:
        """Dictionary of fields covered by the signature (excludes signature)."""
        return {
            "type": self.msg_type.value if isinstance(self.msg_type, MessageType)
            else self.msg_type,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "signer_pk": self.signer_pk,
            "sig_algorithm": self.sig_algorithm,
        }

    def signable_bytes(self) -> bytes:
        """Canonical bytes for signing/verifying protocol messages."""
        return json.dumps(
            self.signable_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def to_bytes(self) -> bytes:
        """Serialize to length-prefixed bytes for TCP."""
        data = self.to_json().encode("utf-8")
        return struct.pack("!I", len(data)) + data

    @classmethod
    def from_json(cls, json_str: str) -> "ProtocolMessage":
        d = json.loads(json_str)
        return cls(
            msg_type=MessageType(d["type"]),
            session_id=d.get("session_id", ""),
            timestamp=d.get("timestamp", 0.0),
            payload=d.get("payload", {}),
            signature=d.get("signature", ""),
            signer_pk=d.get("signer_pk", ""),
            sig_algorithm=d.get("sig_algorithm", "Ed25519"),
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "ProtocolMessage":
        return cls.from_json(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# TCP framing helpers
# ---------------------------------------------------------------------------
HEADER_SIZE = 4  # 4 bytes for uint32 length prefix
MAX_FRAME_SIZE = 1024 * 1024  # 1 MiB safety limit


def frame_message(msg: ProtocolMessage) -> bytes:
    """Create a length-prefixed TCP frame."""
    return msg.to_bytes()


def read_frame(sock) -> ProtocolMessage:
    """Read a length-prefixed message from a TCP socket."""
    header = _recv_exact(sock, HEADER_SIZE)
    if not header:
        raise ConnectionError("Connection closed while reading header")
    length = struct.unpack("!I", header)[0]
    if length <= 0 or length > MAX_FRAME_SIZE:
        raise ProtocolError(f"Invalid frame length: {length}")
    data = _recv_exact(sock, length)
    if not data:
        raise ConnectionError("Connection closed while reading payload")
    return ProtocolMessage.from_bytes(data)


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
