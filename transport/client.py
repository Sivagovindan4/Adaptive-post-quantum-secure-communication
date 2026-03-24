"""
Secure Communication Client
==============================
TCP client implementing the adaptive quantum-safe protocol.

Performs:
  1. Connect + Handshake (exchange identities)
  2. PQC key exchange (Kyber KEM or X25519 ECDH)
  3. Optional QKD key integration
  4. Encrypt message with AES-256-GCM
  5. Sign and send encrypted data
  6. Receive acknowledgment
"""

import socket
import time
import logging
from authentication import Identity
from encryption_layer.pqc_engine import pqc_keygen, _USE_LIBOQS, PQC_ALGORITHM
from encryption_layer.aes_engine import aes_encrypt
from encryption_layer.hybrid_combiner import combine_keys, combine_keys_max_security
from encryption_layer.qkd_bb84_qiskit import bb84_qkd
from key_management.key_derivation import derive_session_key
from threat_model.quantum_threat_index import evaluate_qti
from transport.protocol import (
    ProtocolMessage, MessageType, frame_message, read_frame, ProtocolError
)
from config import SECURITY_PQC, SECURITY_QKD

try:
    from config import PINNED_SERVER_PUBLIC_KEY_HEX
except Exception:
    PINNED_SERVER_PUBLIC_KEY_HEX = ""

logger = logging.getLogger(__name__)


class SecureClient:
    """
    TCP client that performs adaptive quantum-safe encrypted communication.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9876,
                 identity_name: str = "Client"):
        self.host = host
        self.port = port
        self.identity = Identity(name=identity_name)

    def send_secure_message(self, message: str) -> dict:
        """
        Full protocol execution:
          1. Threat evaluation → mode selection
          2. Handshake
          3. PQC key exchange
          4. Optional QKD
          5. Encrypt + sign + send
          6. Receive ACK

        Returns session metrics dict.
        """
        session_start = time.perf_counter()

        # ---- Threat evaluation ----
        threat_score, threat_level = evaluate_qti()
        mode = self._select_mode(threat_level)

        print(f"\n[CLIENT] Threat: {threat_score:.4f} ({threat_level}) → Mode: {mode}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))

        try:
            # ---- Step 1: HANDSHAKE ----
            handshake = ProtocolMessage(
                msg_type=MessageType.HANDSHAKE,
                payload={
                    "public_key": self.identity.export_public_key_hex(),
                    "name": self.identity.name,
                },
            )

            handshake.signer_pk = self.identity.export_public_key_hex()
            handshake.sig_algorithm = self.identity.algorithm
            handshake.signature = self.identity.sign(handshake.signable_bytes()).hex()
            sock.sendall(frame_message(handshake))

            # ---- Step 2: Receive HANDSHAKE_ACK ----
            hs_ack = read_frame(sock)
            if hs_ack.msg_type != MessageType.HANDSHAKE_ACK:
                raise ProtocolError(f"Expected HANDSHAKE_ACK, got {hs_ack.msg_type}")

            # Verify server signature + identity binding
            server_pk_hex = hs_ack.payload.get("public_key", "")
            if not hs_ack.signature or not hs_ack.signer_pk:
                raise ProtocolError("Missing server signature in HANDSHAKE_ACK")
            if server_pk_hex and hs_ack.signer_pk and server_pk_hex != hs_ack.signer_pk:
                raise ProtocolError("Server public key mismatch (payload vs signer_pk)")
            if PINNED_SERVER_PUBLIC_KEY_HEX and hs_ack.signer_pk != PINNED_SERVER_PUBLIC_KEY_HEX:
                raise ProtocolError("Server public key does not match pinned key")
            if not self.identity.verify(hs_ack.signable_bytes(), bytes.fromhex(hs_ack.signature), bytes.fromhex(hs_ack.signer_pk)):
                raise ProtocolError("Invalid server signature on HANDSHAKE_ACK")

            server_name = hs_ack.payload.get("name", "Server")
            print(f"[CLIENT] Handshake with {server_name} complete")

            # ---- Step 3: PQC Key Exchange ----
            pqc_start = time.perf_counter()

            if _USE_LIBOQS:
                from encryption_layer.pqc_engine import KyberKEM
                client_pk, client_kem = KyberKEM.generate_keypair()

                ke_payload = {
                    "pqc_public_key": client_pk.hex(),
                    "mode": mode,
                    "algorithm": PQC_ALGORITHM,
                }
            else:
                from encryption_layer.pqc_engine import X25519KeyExchange
                client_pk, client_sk = X25519KeyExchange.generate_keypair()

                ke_payload = {
                    "pqc_public_key": client_pk.hex(),
                    "mode": mode,
                    "algorithm": PQC_ALGORITHM,
                }

            ke_msg = ProtocolMessage(
                msg_type=MessageType.KEY_EXCHANGE,
                session_id=handshake.session_id,
                payload=ke_payload,
            )

            ke_msg.signer_pk = self.identity.export_public_key_hex()
            ke_msg.sig_algorithm = self.identity.algorithm
            ke_msg.signature = self.identity.sign(ke_msg.signable_bytes()).hex()
            sock.sendall(frame_message(ke_msg))

            # ---- Step 4: Receive KEY_EXCHANGE_ACK ----
            ke_ack = read_frame(sock)
            if ke_ack.msg_type != MessageType.KEY_EXCHANGE_ACK:
                raise ProtocolError(f"Expected KEY_EXCHANGE_ACK, got {ke_ack.msg_type}")

            # Verify server signature on key exchange ack
            if not ke_ack.signature or not ke_ack.signer_pk:
                raise ProtocolError("Missing server signature in KEY_EXCHANGE_ACK")
            if PINNED_SERVER_PUBLIC_KEY_HEX and ke_ack.signer_pk != PINNED_SERVER_PUBLIC_KEY_HEX:
                raise ProtocolError("Server public key does not match pinned key")
            if not self.identity.verify(ke_ack.signable_bytes(), bytes.fromhex(ke_ack.signature), bytes.fromhex(ke_ack.signer_pk)):
                raise ProtocolError("Invalid server signature on KEY_EXCHANGE_ACK")

            if _USE_LIBOQS:
                ciphertext = bytes.fromhex(ke_ack.payload["pqc_ciphertext"])
                shared_secret = KyberKEM.decapsulate(client_kem, ciphertext)
                pqc_key = derive_session_key(shared_secret, info=b"pqc-session-key-v1")
            else:
                server_ecdh_pk = bytes.fromhex(ke_ack.payload["ecdh_public_key"])
                shared_secret = X25519KeyExchange.derive_shared_secret(
                    client_sk, server_ecdh_pk
                )
                pqc_key = derive_session_key(shared_secret, info=b"pqc-session-key-v1")

            pqc_time = time.perf_counter() - pqc_start

            # ---- Optional QKD (wrapped under PQC key; never sent in plaintext) ----
            qkd_time = 0.0
            qkd_key = None
            qkd_result = None

            if mode in ("PQC_QKD", "PQC_QKD_MAX"):
                qkd_result = bb84_qkd()
                qkd_time = qkd_result["time"]
                print(f"[CLIENT] QKD: secure={qkd_result['secure']} "
                      f"QBER={qkd_result['qber']:.4f} "
                      f"raw_bits={qkd_result['raw_key_bits']}")

                if qkd_result["secure"] and qkd_result["key"] is not None:
                    qkd_key = qkd_result["key"]

                    aad_qkd = (handshake.session_id + ":qkd").encode("utf-8")
                    wrapped_qkd = aes_encrypt(qkd_key, pqc_key, aad_qkd)

                    # Sign wrapped key material (nonce+ciphertext)
                    sig_payload = (wrapped_qkd["nonce"] + ":" + wrapped_qkd["ciphertext"]).encode("utf-8")
                    km_sig = self.identity.sign(sig_payload)

                    km_msg = ProtocolMessage(
                        msg_type=MessageType.KEY_MATERIAL,
                        session_id=handshake.session_id,
                        payload={
                            "material_type": "QKD_KEY_WRAPPED",
                            "wrapped": wrapped_qkd,
                            "qkd_secure": True,
                            "qkd_qber": qkd_result.get("qber"),
                        },
                        signer_pk=self.identity.export_public_key_hex(),
                        sig_algorithm=self.identity.algorithm,
                    )

                    km_msg.signature = self.identity.sign(km_msg.signable_bytes()).hex()
                    sock.sendall(frame_message(km_msg))

                    km_ack = read_frame(sock)
                    if km_ack.msg_type != MessageType.KEY_MATERIAL_ACK:
                        raise ProtocolError(f"Expected KEY_MATERIAL_ACK, got {km_ack.msg_type}")

                    if not km_ack.signature or not km_ack.signer_pk:
                        raise ProtocolError("Missing server signature in KEY_MATERIAL_ACK")
                    if PINNED_SERVER_PUBLIC_KEY_HEX and km_ack.signer_pk != PINNED_SERVER_PUBLIC_KEY_HEX:
                        raise ProtocolError("Server public key does not match pinned key")
                    if not self.identity.verify(km_ack.signable_bytes(), bytes.fromhex(km_ack.signature), bytes.fromhex(km_ack.signer_pk)):
                        raise ProtocolError("Invalid server signature on KEY_MATERIAL_ACK")

            # ---- Combine keys (bind to session id) ----
            session_ctx = handshake.session_id.encode("utf-8")
            if mode == "PQC_QKD_MAX" and qkd_key:
                session_key = combine_keys_max_security(pqc_key, qkd_key, session_context=session_ctx)
            elif qkd_key:
                session_key = combine_keys(pqc_key, qkd_key, session_context=session_ctx)
            else:
                session_key = combine_keys(pqc_key, None, session_context=session_ctx)

            # ---- Step 5: Encrypt + Sign + Send ----
            aad = handshake.session_id.encode("utf-8")
            encrypted = aes_encrypt(message.encode("utf-8"), session_key, aad)

            # Sign the ciphertext
            data_msg = ProtocolMessage(
                msg_type=MessageType.DATA,
                session_id=handshake.session_id,
                payload=encrypted,
                signer_pk=self.identity.export_public_key_hex(),
                sig_algorithm=self.identity.algorithm,
            )
            data_msg.signature = self.identity.sign(data_msg.signable_bytes()).hex()
            sock.sendall(frame_message(data_msg))

            # ---- Step 6: Receive ACK ----
            ack = read_frame(sock)
            if ack.msg_type != MessageType.ACK:
                raise ProtocolError(f"Expected ACK, got {ack.msg_type}")

            if not ack.signature or not ack.signer_pk:
                raise ProtocolError("Missing server signature in ACK")
            if PINNED_SERVER_PUBLIC_KEY_HEX and ack.signer_pk != PINNED_SERVER_PUBLIC_KEY_HEX:
                raise ProtocolError("Server public key does not match pinned key")
            if not self.identity.verify(ack.signable_bytes(), bytes.fromhex(ack.signature), bytes.fromhex(ack.signer_pk)):
                raise ProtocolError("Invalid server signature on ACK")

            total_time = time.perf_counter() - session_start
            security_score = self._compute_security_score(mode)

            print(f"[CLIENT] Server ACK: {ack.payload}")
            print(f"[CLIENT] Security: {security_score} bits | "
                  f"Latency: {total_time:.4f}s")

            return {
                "mode": mode,
                "threat_level": threat_level,
                "threat_score": round(threat_score, 4),
                "security_score": security_score,
                "latency": total_time,
                "pqc_time": pqc_time,
                "qkd_time": qkd_time,
                "pqc_algorithm": PQC_ALGORITHM,
                "signature_algorithm": self.identity.algorithm,
                "qkd_secure": qkd_result["secure"] if qkd_result else None,
                "qkd_qber": qkd_result["qber"] if qkd_result else None,
                "server_ack": ack.payload,
            }

        finally:
            sock.close()

    @staticmethod
    def _select_mode(threat_level: str) -> str:
        if threat_level == "LOW":
            return "PQC_ONLY"
        elif threat_level == "MEDIUM":
            return "PQC_QKD"
        return "PQC_QKD_MAX"

    @staticmethod
    def _compute_security_score(mode: str) -> int:
        if mode == "PQC_ONLY":
            return SECURITY_PQC
        elif mode == "PQC_QKD":
            return SECURITY_PQC + SECURITY_QKD
        return SECURITY_PQC + SECURITY_QKD + 50
