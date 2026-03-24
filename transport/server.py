"""
Secure Communication Server
=============================
TCP server implementing the adaptive quantum-safe protocol.

Flow:
  1. Accept connection
  2. Handshake (exchange identities + public keys)
  3. Key exchange (PQC Kyber KEM + optional QKD)
  4. Receive encrypted data (AES-256-GCM)
  5. Decrypt and verify
"""

import socket
import threading
import time
import logging
from authentication import Identity
from encryption_layer.pqc_engine import pqc_keygen, PQC_ALGORITHM, _USE_LIBOQS
from encryption_layer.aes_engine import aes_decrypt
from encryption_layer.hybrid_combiner import combine_keys, combine_keys_max_security
from key_management.key_derivation import derive_session_key
from transport.protocol import (
    ProtocolMessage, MessageType, frame_message, read_frame, ProtocolError
)

logger = logging.getLogger(__name__)


class SecureServer:
    """
    TCP server that performs the full adaptive quantum-safe handshake,
    key exchange, and encrypted data reception.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9876,
                 identity_name: str = "Server"):
        self.host = host
        self.port = port
        self.identity = Identity(name=identity_name)
        self._running = False
        self._socket = None
        self._seen_sessions = {}
        self._seen_lock = threading.Lock()
        self._replay_window_secs = 120

    def _check_and_mark_session(self, session_id: str, timestamp: float):
        now = time.time()
        if abs(now - timestamp) > self._replay_window_secs:
            raise ProtocolError("Stale or future timestamp")

        with self._seen_lock:
            # prune
            cutoff = now - self._replay_window_secs
            stale = [sid for sid, ts in self._seen_sessions.items() if ts < cutoff]
            for sid in stale:
                self._seen_sessions.pop(sid, None)

            if session_id in self._seen_sessions:
                raise ProtocolError("Replay detected: session_id already seen")
            self._seen_sessions[session_id] = timestamp

    def start(self, blocking: bool = True):
        """Start the server. If blocking=False, runs in a background thread."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self.host, self.port))
        self._socket.listen(5)
        self._running = True

        print(f"[SERVER] Listening on {self.host}:{self.port} "
              f"(identity={self.identity.name}, algo={self.identity.algorithm})")

        if blocking:
            self._accept_loop()
        else:
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()

    def _accept_loop(self):
        while self._running:
            try:
                self._socket.settimeout(1.0)
                conn, addr = self._socket.accept()
                print(f"[SERVER] Connection from {addr}")
                threading.Thread(
                    target=self._handle_client, args=(conn, addr), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, conn, addr):
        """Handle one client through the full protocol."""
        try:
            session_start = time.perf_counter()

            # ---- Step 1: Receive HANDSHAKE ----
            msg = read_frame(conn)
            if msg.msg_type != MessageType.HANDSHAKE:
                raise ProtocolError(f"Expected HANDSHAKE, got {msg.msg_type}")
            self._check_and_mark_session(msg.session_id, msg.timestamp)
            client_pk_hex = msg.payload.get("public_key", "")
            client_name = msg.payload.get("name", "Client")
            print(f"[SERVER] Handshake from {client_name}")

            # Verify client handshake signature and binding
            if not msg.signature or not msg.signer_pk:
                raise ProtocolError("Missing client signature in HANDSHAKE")
            if client_pk_hex and msg.signer_pk and client_pk_hex != msg.signer_pk:
                raise ProtocolError("Client public key mismatch (payload vs signer_pk)")
            if not self.identity.verify(msg.signable_bytes(), bytes.fromhex(msg.signature), bytes.fromhex(msg.signer_pk)):
                raise ProtocolError("Invalid client signature on HANDSHAKE")

            # ---- Step 2: Send HANDSHAKE_ACK ----
            ack = ProtocolMessage(
                msg_type=MessageType.HANDSHAKE_ACK,
                session_id=msg.session_id,
                payload={
                    "public_key": self.identity.export_public_key_hex(),
                    "name": self.identity.name,
                    "pqc_algorithm": PQC_ALGORITHM,
                },
            )
            ack.signer_pk = self.identity.export_public_key_hex()
            ack.sig_algorithm = self.identity.algorithm
            ack.signature = self.identity.sign(ack.signable_bytes()).hex()
            conn.sendall(frame_message(ack))

            # ---- Step 3: Receive KEY_EXCHANGE ----
            ke_msg = read_frame(conn)
            if ke_msg.msg_type != MessageType.KEY_EXCHANGE:
                raise ProtocolError(f"Expected KEY_EXCHANGE, got {ke_msg.msg_type}")
            if ke_msg.session_id != msg.session_id:
                raise ProtocolError("Session ID mismatch")

            # Verify client signature on key exchange
            if not ke_msg.signature or not ke_msg.signer_pk:
                raise ProtocolError("Missing client signature in KEY_EXCHANGE")
            if client_pk_hex and ke_msg.signer_pk and client_pk_hex != ke_msg.signer_pk:
                raise ProtocolError("Client public key mismatch (KEY_EXCHANGE)")
            if not self.identity.verify(ke_msg.signable_bytes(), bytes.fromhex(ke_msg.signature), bytes.fromhex(ke_msg.signer_pk)):
                raise ProtocolError("Invalid client signature on KEY_EXCHANGE")

            mode = ke_msg.payload.get("mode", "PQC_ONLY")

            if _USE_LIBOQS:
                # Kyber KEM: client sent public key, we encapsulate
                from encryption_layer.pqc_engine import KyberKEM
                client_pqc_pk = bytes.fromhex(ke_msg.payload["pqc_public_key"])
                ciphertext, shared_secret = KyberKEM.encapsulate(client_pqc_pk)

                # Derive PQC key
                pqc_key = derive_session_key(shared_secret, info=b"pqc-session-key-v1")

                # Send ciphertext back
                ke_ack = ProtocolMessage(
                    msg_type=MessageType.KEY_EXCHANGE_ACK,
                    session_id=msg.session_id,
                    payload={"pqc_ciphertext": ciphertext.hex()},
                )
            else:
                # X25519 ECDH: client sent public key, we send ours
                from encryption_layer.pqc_engine import X25519KeyExchange
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
                server_pk, server_sk = X25519KeyExchange.generate_keypair()
                client_ecdh_pk = bytes.fromhex(ke_msg.payload["pqc_public_key"])
                shared_secret = X25519KeyExchange.derive_shared_secret(
                    server_sk, client_ecdh_pk
                )
                pqc_key = derive_session_key(shared_secret, info=b"pqc-session-key-v1")

                ke_ack = ProtocolMessage(
                    msg_type=MessageType.KEY_EXCHANGE_ACK,
                    session_id=msg.session_id,
                    payload={"ecdh_public_key": server_pk.hex()},
                )

            # Sign KEY_EXCHANGE_ACK (after payload ready) and send once
            ke_ack.signer_pk = self.identity.export_public_key_hex()
            ke_ack.sig_algorithm = self.identity.algorithm
            ke_ack.signature = self.identity.sign(ke_ack.signable_bytes()).hex()

            conn.sendall(frame_message(ke_ack))

            # ---- Optional KEY_MATERIAL (wrapped QKD key) ----
            qkd_key = None
            if mode in ("PQC_QKD", "PQC_QKD_MAX"):
                km = read_frame(conn)
                if km.msg_type != MessageType.KEY_MATERIAL:
                    raise ProtocolError(f"Expected KEY_MATERIAL, got {km.msg_type}")
                if km.session_id != msg.session_id:
                    raise ProtocolError("Session ID mismatch")

                if not km.signature or not km.signer_pk:
                    raise ProtocolError("Missing client signature in KEY_MATERIAL")
                if client_pk_hex and km.signer_pk and client_pk_hex != km.signer_pk:
                    raise ProtocolError("Client public key mismatch (KEY_MATERIAL)")
                if not self.identity.verify(km.signable_bytes(), bytes.fromhex(km.signature), bytes.fromhex(km.signer_pk)):
                    raise ProtocolError("Invalid client signature on KEY_MATERIAL")

                if km.payload.get("material_type") != "QKD_KEY_WRAPPED":
                    raise ProtocolError("Unsupported key material")

                wrapped = km.payload.get("wrapped") or {}
                nonce = wrapped.get("nonce")
                ciphertext = wrapped.get("ciphertext")
                aad_hex = wrapped.get("aad")
                if not nonce or not ciphertext:
                    raise ProtocolError("Invalid wrapped key material")

                aad_qkd = (msg.session_id + ":qkd").encode("utf-8")
                # Decrypt QKD key (associated_data must match client)
                qkd_key = aes_decrypt(nonce, ciphertext, pqc_key, aad_qkd)

                km_ack = ProtocolMessage(
                    msg_type=MessageType.KEY_MATERIAL_ACK,
                    session_id=msg.session_id,
                    payload={"status": "ok"},
                )
                km_ack.signer_pk = self.identity.export_public_key_hex()
                km_ack.sig_algorithm = self.identity.algorithm
                km_ack.signature = self.identity.sign(km_ack.signable_bytes()).hex()
                conn.sendall(frame_message(km_ack))

            # ---- Combine keys (bind to session id) ----
            session_ctx = msg.session_id.encode("utf-8")
            if mode == "PQC_QKD_MAX" and qkd_key:
                session_key = combine_keys_max_security(pqc_key, qkd_key, session_context=session_ctx)
            elif qkd_key:
                session_key = combine_keys(pqc_key, qkd_key, session_context=session_ctx)
            else:
                session_key = combine_keys(pqc_key, None, session_context=session_ctx)

            # ---- Step 4: Receive DATA ----
            data_msg = read_frame(conn)
            if data_msg.msg_type != MessageType.DATA:
                raise ProtocolError(f"Expected DATA, got {data_msg.msg_type}")
            if data_msg.session_id != msg.session_id:
                raise ProtocolError("Session ID mismatch")

            nonce = data_msg.payload["nonce"]
            ciphertext_hex = data_msg.payload["ciphertext"]
            aad_hex = data_msg.payload.get("aad")
            aad = bytes.fromhex(aad_hex) if aad_hex else None

            plaintext = aes_decrypt(nonce, ciphertext_hex, session_key, aad)

            # Verify signature on DATA (canonical message signing)
            if not data_msg.signature or not data_msg.signer_pk:
                raise ProtocolError("Missing client signature in DATA")
            if client_pk_hex and data_msg.signer_pk and client_pk_hex != data_msg.signer_pk:
                raise ProtocolError("Client public key mismatch (DATA)")
            sig_valid = self.identity.verify(
                data_msg.signable_bytes(),
                bytes.fromhex(data_msg.signature),
                bytes.fromhex(data_msg.signer_pk),
            )

            session_time = time.perf_counter() - session_start

            print(f"[SERVER] Decrypted: {plaintext.decode('utf-8')[:80]}...")
            print(f"[SERVER] Signature valid: {sig_valid}")
            print(f"[SERVER] Session time: {session_time:.4f}s")

            # ---- Step 5: Send ACK ----
            ack_msg = ProtocolMessage(
                msg_type=MessageType.ACK,
                session_id=msg.session_id,
                payload={
                    "status": "received",
                    "signature_valid": sig_valid,
                    "decrypted_length": len(plaintext),
                },
            )
            ack_msg.signer_pk = self.identity.export_public_key_hex()
            ack_msg.sig_algorithm = self.identity.algorithm
            ack_msg.signature = self.identity.sign(ack_msg.signable_bytes()).hex()
            conn.sendall(frame_message(ack_msg))

        except Exception as e:
            logger.error(f"[SERVER] Error handling client {addr}: {e}")
            try:
                err = ProtocolMessage(
                    msg_type=MessageType.ERROR,
                    payload={"error": str(e)},
                )
                conn.sendall(frame_message(err))
            except Exception:
                pass
        finally:
            conn.close()

    def stop(self):
        self._running = False
        if self._socket:
            self._socket.close()
