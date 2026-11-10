"""
SecureVault LAN - Network Node (Server / Client Core)
Provides robust TCP socket networking, RSA-2048 handshake,
AES-256-GCM chunked file streaming, live telemetry, and Wireshark demo mode.

Fixes Applied:
  BUG-017: Added Tuple import (NameError fix for Python <3.10)
  BUG-018: Server socket kept alive and re-listens after client disconnect
  BUG-019: _server_accept_loop uses while True to accept multiple connections
  BUG-020: _incoming_file_handle safely closed on connection drop / disconnect
  BUG-021: Removed time.sleep(0.002) blocking call in file send loop
  BUG-023: Socket timeout set (30s) on accepted connections to prevent infinite block
  BUG-024: AES key ValueError caught during handshake with proper error log
"""

import socket
import threading
import os
import time
import json
from typing import Optional, Callable, Dict, Any, Tuple
from backend.crypto_engine import CryptoEngine
from backend.protocol import ProtocolFrame, FrameType, SecurityMode


class LanNode:
    CHUNK_SIZE = 32 * 1024  # 32 KB chunk for smooth file streaming
    SOCKET_TIMEOUT = 30.0   # Seconds before blocking read gives up

    def __init__(self, downloads_dir: str = "received_files"):
        self.downloads_dir = downloads_dir
        os.makedirs(self.downloads_dir, exist_ok=True)

        self.crypto = CryptoEngine()
        self.role: Optional[str] = None  # 'server' or 'client'
        self.sock: Optional[socket.socket] = None
        self.conn: Optional[socket.socket] = None  # Active peer socket
        self.peer_address: Optional[Tuple[str, int]] = None

        self.is_running = False
        self.is_connected = False
        self.active_mode = SecurityMode.ENCRYPTED  # Default to Secure Mode

        # Active incoming file transfer state
        self._incoming_file_meta: Optional[Dict[str, Any]] = None
        self._incoming_file_handle = None
        self._incoming_bytes_received = 0
        self._last_rx_pct = -1.0

        # Thread lock for send operations
        self._send_lock = threading.Lock()

        # Event Callbacks
        self.on_log: Optional[Callable[[str, str, Dict[str, Any]], None]] = None
        self.on_status_change: Optional[Callable[[str, Optional[str]], None]] = None
        self.on_message: Optional[Callable[[str, str, bool, str], None]] = None
        self.on_file_progress: Optional[Callable[[str, str, int, int, float], None]] = None
        self.on_file_complete: Optional[Callable[[str, str, bool, str], None]] = None
        self.on_packet_event: Optional[Callable[[str, str, str, int, str], None]] = None

    def log(self, level: str, msg: str, details: Optional[Dict[str, Any]] = None):
        if self.on_log:
            self.on_log(level, msg, details or {})

    def trigger_packet_event(self, direction: str, frame_type: FrameType, mode: SecurityMode, length: int, raw_hex: str):
        if self.on_packet_event:
            self.on_packet_event(
                direction,
                frame_type.name,
                "ENCRYPTED" if mode == SecurityMode.ENCRYPTED else "PLAINTEXT",
                length,
                raw_hex
            )

    # -------------------------------------------------------------------------
    # Server Lifecycle (FIX BUG-018, BUG-019)
    # -------------------------------------------------------------------------
    def start_server(self, host: str = "0.0.0.0", port: int = 5500):
        """Starts TCP Server listener and prepares RSA keypair."""
        if self.is_running:
            self.log("WARNING", "Server is already running. Stop it first.")
            return

        self.role = "server"
        self.is_running = True
        self.is_connected = False
        self.peer_address = None
        self.log("INFO", f"Starting SecureVault Server on {host}:{port}...")

        # 1. Generate RSA-2048 keypair
        self.log("CRYPTO", "Generating ephemeral RSA-2048 Key Pair for session negotiation...")
        self.crypto.generate_rsa_keypair()
        self.log("SUCCESS", "RSA-2048 Key Pair ready. Private key stored in memory.")

        # 2. Bind TCP Socket (FIX BUG-018: keep server socket alive)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(5)  # backlog of 5

        if self.on_status_change:
            self.on_status_change("LISTENING", f"Listening on {host}:{port}")

        threading.Thread(target=self._server_accept_loop, daemon=True).start()

    def _server_accept_loop(self):
        """FIX BUG-019: Loop to accept multiple sequential connections."""
        self.log("INFO", "Server listening for incoming LAN connections...")
        while self.is_running:
            try:
                self.sock.settimeout(1.0)  # Allow checking is_running
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    continue  # Check is_running again

                self.conn = conn
                self.peer_address = addr
                # FIX BUG-023: set a timeout so read never blocks indefinitely
                self.conn.settimeout(self.SOCKET_TIMEOUT)
                self.log("SUCCESS", f"TCP Connection accepted from {addr[0]}:{addr[1]}")

                # Initiate Server-Side Handshake
                try:
                    self._execute_server_handshake()
                    # Start continuous read loop (blocks until disconnect)
                    self._read_loop()
                except Exception as e:
                    self.log("ERROR", f"Session error: {str(e)}")

                # After client disconnects, reset connection state but keep server alive
                self._reset_connection_state()
                self.log("INFO", "Session ended. Server still listening for new connections...")
                if self.on_status_change:
                    self.on_status_change("LISTENING", f"Waiting for new connection...")

            except Exception as e:
                if self.is_running:
                    self.log("ERROR", f"Server accept loop error: {str(e)}")
                break

    def _reset_connection_state(self):
        """Reset per-connection state without closing the server socket."""
        self.is_connected = False
        self.peer_address = None
        # FIX BUG-020: close any open file handle on disconnect
        if self._incoming_file_handle:
            try:
                self._incoming_file_handle.close()
            except Exception:
                pass
            self._incoming_file_handle = None
        self._incoming_file_meta = None
        self._incoming_bytes_received = 0
        self._last_rx_pct = -1.0
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def _execute_server_handshake(self):
        """
        Server Handshake:
        1. Send Server RSA Public Key (Plaintext).
        2. Receive Client's RSA-Encrypted AES-256 Session Key.
        3. Decrypt Session Key using Server Private Key.
        4. Send Handshake ACK.
        """
        self.log("HANDSHAKE", "Step 1/3: Transmitting Server RSA-2048 Public Key to Client...")
        pub_pem = self.crypto.get_public_pem()
        pub_frame = ProtocolFrame(
            frame_type=FrameType.HANDSHAKE_PUBKEY,
            mode=SecurityMode.PLAINTEXT,
            payload=pub_pem
        )
        self._send_raw_frame(pub_frame)
        self.trigger_packet_event("TX", FrameType.HANDSHAKE_PUBKEY, SecurityMode.PLAINTEXT, len(pub_pem), pub_pem[:32].hex())

        self.log("HANDSHAKE", "Step 2/3: Awaiting encrypted AES-256 Session Key from Client...")
        resp_frame = ProtocolFrame.read_from_socket(self.conn)
        if not resp_frame or resp_frame.frame_type != FrameType.HANDSHAKE_SESSIONKEY:
            raise ConnectionError("Invalid handshake response from Client.")

        self.trigger_packet_event("RX", resp_frame.frame_type, resp_frame.mode, len(resp_frame.payload), resp_frame.payload[:32].hex())
        self.log("CRYPTO", f"Received RSA-encrypted payload ({len(resp_frame.payload)} bytes). Decrypting with RSA Private Key...")

        # FIX BUG-024: catch AES key ValueError
        try:
            session_key = self.crypto.rsa_decrypt_session_key(resp_frame.payload)
        except (ValueError, Exception) as crypto_err:
            raise ConnectionError(f"RSA session key decryption failed: {str(crypto_err)}")

        self.log("SUCCESS", f"AES-256 Session Key successfully decrypted! Key Fingerprint: {self.crypto.compute_sha256(session_key)[:16]}...")

        # Step 3: Send ACK
        self.log("HANDSHAKE", "Step 3/3: Transmitting Handshake ACK...")
        ack_frame = ProtocolFrame(
            frame_type=FrameType.HANDSHAKE_ACK,
            mode=SecurityMode.ENCRYPTED,
            payload=b"SECURE_SESSION_ESTABLISHED"
        )
        self._send_raw_frame(ack_frame)
        self.trigger_packet_event("TX", FrameType.HANDSHAKE_ACK, SecurityMode.ENCRYPTED, len(ack_frame.payload), ack_frame.payload.hex())

        self.is_connected = True
        if self.on_status_change:
            self.on_status_change("CONNECTED", f"{self.peer_address[0]}:{self.peer_address[1]}")
        self.log("SUCCESS", "Secure Handshake Complete! Channel is now protected with AES-256-GCM.")

    # -------------------------------------------------------------------------
    # Client Lifecycle
    # -------------------------------------------------------------------------
    def connect_to_server(self, host: str, port: int):
        """Connects to remote server and executes Client-side Handshake."""
        if self.is_connected or self.is_running:
            self.log("WARNING", "Already connected or running. Disconnect first.")
            return

        self.role = "client"
        self.is_running = True
        self.log("INFO", f"Connecting to SecureVault Server at {host}:{port}...")

        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # FIX BUG-023: timeout on client side too
        self.conn.settimeout(10.0)
        try:
            self.conn.connect((host, port))
        except socket.timeout:
            self.log("ERROR", f"Connection to {host}:{port} timed out.")
            self.is_running = False
            self.conn = None
            return
        except Exception as e:
            self.log("ERROR", f"Connection failed: {str(e)}")
            self.is_running = False
            self.conn = None
            return

        # Set longer timeout for data exchange
        self.conn.settimeout(self.SOCKET_TIMEOUT)
        self.peer_address = (host, port)
        self.log("SUCCESS", "TCP 3-Way Handshake ACK received. Starting Cryptographic Exchange...")

        threading.Thread(target=self._execute_client_handshake_and_listen, daemon=True).start()

    def _execute_client_handshake_and_listen(self):
        try:
            # 1. Receive Server Public Key
            self.log("HANDSHAKE", "Step 1/3: Receiving Server RSA-2048 Public Key...")
            pub_frame = ProtocolFrame.read_from_socket(self.conn)
            if not pub_frame or pub_frame.frame_type != FrameType.HANDSHAKE_PUBKEY:
                raise ConnectionError("Failed to receive Server Public Key.")

            self.trigger_packet_event("RX", pub_frame.frame_type, pub_frame.mode, len(pub_frame.payload), pub_frame.payload[:32].hex())
            server_pub_key = CryptoEngine.load_public_key_from_pem(pub_frame.payload)
            self.log("SUCCESS", "Server RSA-2048 Public Key verified.")

            # 2. Generate AES-256 Session Key and Encrypt with Server Pubkey
            self.log("CRYPTO", "Generating fresh ephemeral AES-256 Session Key (32 bytes)...")
            client_session_key = CryptoEngine.generate_aes_key()
            self.crypto.set_session_key(client_session_key)
            self.log("SUCCESS", f"AES-256 Key generated. Key Fingerprint: {self.crypto.compute_sha256(client_session_key)[:16]}...")

            self.log("HANDSHAKE", "Step 2/3: Encrypting Session Key with Server RSA Public Key (OAEP-SHA256)...")
            encrypted_session_key = CryptoEngine.rsa_encrypt_session_key(server_pub_key, client_session_key)

            key_frame = ProtocolFrame(
                frame_type=FrameType.HANDSHAKE_SESSIONKEY,
                mode=SecurityMode.PLAINTEXT,  # The envelope itself carries RSA ciphertext
                payload=encrypted_session_key
            )
            self._send_raw_frame(key_frame)
            self.trigger_packet_event("TX", FrameType.HANDSHAKE_SESSIONKEY, SecurityMode.PLAINTEXT, len(encrypted_session_key), encrypted_session_key[:32].hex())

            # 3. Receive Handshake ACK
            self.log("HANDSHAKE", "Step 3/3: Awaiting Server Handshake ACK...")
            ack_frame = ProtocolFrame.read_from_socket(self.conn)
            if not ack_frame or ack_frame.frame_type != FrameType.HANDSHAKE_ACK:
                raise ConnectionError("Failed to receive Handshake ACK.")

            self.trigger_packet_event("RX", ack_frame.frame_type, ack_frame.mode, len(ack_frame.payload), ack_frame.payload.hex())
            self.is_connected = True
            if self.on_status_change:
                self.on_status_change("CONNECTED", f"{self.peer_address[0]}:{self.peer_address[1]}")
            self.log("SUCCESS", "Secure Handshake Complete! Ready for encrypted communication.")

            # Start reading messages/files
            self._read_loop()
        except Exception as e:
            self.log("ERROR", f"Client Handshake failed: {str(e)}")
            self.disconnect()

    # -------------------------------------------------------------------------
    # Core Read Loop (Handles Inbound Data & Integrity)
    # -------------------------------------------------------------------------
    def _read_loop(self):
        while self.is_running and self.is_connected and self.conn:
            try:
                frame = ProtocolFrame.read_from_socket(self.conn)
                if not frame:
                    self.log("WARNING", "Remote peer disconnected.")
                    break

                # Telemetry event for incoming packet (skip spamming on every raw file chunk)
                if frame.frame_type != FrameType.FILE_CHUNK:
                    preview_hex = frame.payload[:32].hex() if frame.payload else ""
                    self.trigger_packet_event("RX", frame.frame_type, frame.mode, len(frame.payload), preview_hex)
                else:
                    preview_hex = ""

                # Process payload according to security mode
                decrypted_bytes: bytes = b""
                is_secure = (frame.mode == SecurityMode.ENCRYPTED)

                if is_secure:
                    try:
                        decrypted_bytes = self.crypto.decrypt_aes_gcm(frame.nonce, frame.payload)
                    except Exception as crypto_err:
                        self.log("ALERT", f"INTEGRITY VIOLATION DETECTED! Tampered packet received: {str(crypto_err)}")
                        continue
                else:
                    # Insecure mode (Plaintext Demonstration)
                    decrypted_bytes = frame.payload
                    self.log("WARNING", f"[WIRESHARK DEMO] Received Insecure Plaintext Frame ({len(decrypted_bytes)} bytes)")

                # Handle specific Frame Types
                if frame.frame_type == FrameType.MSG_TEXT:
                    msg_text = decrypted_bytes.decode("utf-8", errors="replace")
                    self.log("MSG", f"Received message: '{msg_text}' (Security: {'[SECURE] AES-256-GCM' if is_secure else '[PLAINTEXT]'})")
                    if self.on_message:
                        self.on_message("Remote", msg_text, is_secure, preview_hex)

                elif frame.frame_type == FrameType.FILE_START:
                    meta = json.loads(decrypted_bytes.decode("utf-8"))
                    self._incoming_file_meta = meta
                    save_path = os.path.join(self.downloads_dir, meta["filename"])
                    self._incoming_file_handle = open(save_path, "wb")
                    self._incoming_bytes_received = 0
                    self._last_rx_pct = -1.0
                    self.log("FILE", f"Incoming file transfer: '{meta['filename']}' ({meta['filesize']} bytes). Expected SHA-256: {meta['sha256']}")

                elif frame.frame_type == FrameType.FILE_CHUNK:
                    if self._incoming_file_handle:
                        self._incoming_file_handle.write(decrypted_bytes)
                        self._incoming_bytes_received += len(decrypted_bytes)
                        total = self._incoming_file_meta["filesize"] if self._incoming_file_meta else 1
                        pct = round((self._incoming_bytes_received / total) * 100, 1)
                        if (pct - self._last_rx_pct >= 2.0) or (self._incoming_bytes_received >= total):
                            self._last_rx_pct = pct
                            self.trigger_packet_event("RX", FrameType.FILE_CHUNK, frame.mode, len(frame.payload), "")
                            if self.on_file_progress:
                                self.on_file_progress("RX", self._incoming_file_meta["filename"], self._incoming_bytes_received, total, pct)

                elif frame.frame_type == FrameType.FILE_END:
                    if self._incoming_file_handle:
                        self._incoming_file_handle.close()
                        self._incoming_file_handle = None

                        filename = self._incoming_file_meta["filename"]
                        expected_hash = self._incoming_file_meta["sha256"]
                        file_path = os.path.join(self.downloads_dir, filename)

                        # Compute and verify SHA-256 Integrity
                        computed_hash = CryptoEngine.compute_file_sha256(file_path)
                        is_intact = (computed_hash.lower() == expected_hash.lower())

                        if is_intact:
                            self.log("SUCCESS", f"FILE INTEGRITY VERIFIED! SHA-256 Checksum Match: {computed_hash}")
                        else:
                            self.log("ALERT", f"FILE INTEGRITY FAILED! Expected: {expected_hash}, Got: {computed_hash}")

                        if self.on_file_complete:
                            self.on_file_complete(filename, file_path, is_intact, computed_hash)
                        self._incoming_file_meta = None

                elif frame.frame_type == FrameType.DISCONNECT:
                    self.log("INFO", "Disconnect signal received.")
                    break

            except socket.timeout:
                # Timeout is normal — just check is_running and loop
                continue
            except Exception as e:
                if self.is_running and self.is_connected:
                    self.log("ERROR", f"Error in read loop: {str(e)}")
                break

        # On exit from read loop, clean up connection
        if self.role == "client":
            # Client fully disconnects
            self.disconnect()
        else:
            # Server: reset connection but keep server socket open (handled by accept loop)
            pass

    # -------------------------------------------------------------------------
    # Outbound Transmission (Messages & Chunked Files)
    # -------------------------------------------------------------------------
    def set_security_mode(self, mode: SecurityMode):
        """Switches between AES-256 Secure Mode and Plaintext Wireshark Demo Mode."""
        self.active_mode = mode
        mode_str = "[SECURE] (AES-256-GCM)" if mode == SecurityMode.ENCRYPTED else "[INSECURE] PLAINTEXT (Wireshark Demo)"
        self.log("MODE", f"Security Mode switched to: {mode_str}")

    def send_message(self, text: str) -> bool:
        if not self.conn or not self.is_connected:
            self.log("ERROR", "Cannot send message: Not connected.")
            return False

        payload_bytes = text.encode("utf-8")
        frame = self._build_frame(FrameType.MSG_TEXT, payload_bytes)
        success = self._send_raw_frame(frame)
        if success:
            preview_hex = frame.payload[:32].hex()
            self.trigger_packet_event("TX", FrameType.MSG_TEXT, self.active_mode, len(frame.payload), preview_hex)
            if self.on_message:
                self.on_message("Me", text, (self.active_mode == SecurityMode.ENCRYPTED), preview_hex)
        return success

    def send_file(self, file_path: str) -> bool:
        """Streams a file in chunks with AES-256 encryption and SHA-256 hash."""
        if not self.conn or not self.is_connected:
            self.log("ERROR", "Cannot send file: Not connected.")
            return False

        if not os.path.exists(file_path):
            self.log("ERROR", f"File not found: {file_path}")
            return False

        def _worker():
            try:
                filename = os.path.basename(file_path)
                filesize = os.path.getsize(file_path)
                self.log("FILE", f"Computing SHA-256 checksum for '{filename}' ({filesize} bytes)...")
                file_hash = CryptoEngine.compute_file_sha256(file_path)
                self.log("SUCCESS", f"Computed SHA-256: {file_hash}")

                # 1. Send FILE_START with Metadata
                meta = {
                    "filename": filename,
                    "filesize": filesize,
                    "sha256": file_hash
                }
                meta_frame = self._build_frame(FrameType.FILE_START, json.dumps(meta).encode("utf-8"))
                self._send_raw_frame(meta_frame)
                self.trigger_packet_event("TX", FrameType.FILE_START, self.active_mode, len(meta_frame.payload), meta_frame.payload[:32].hex())

                # 2. Stream Chunks (FIX BUG-021: removed time.sleep blocking)
                bytes_sent = 0
                last_reported_pct = -1.0
                with open(file_path, "rb") as f:
                    while chunk := f.read(self.CHUNK_SIZE):
                        if not self.is_connected:
                            self.log("WARNING", "File transfer aborted: connection lost.")
                            break
                        chunk_frame = self._build_frame(FrameType.FILE_CHUNK, chunk)
                        if not self._send_raw_frame(chunk_frame):
                            self.log("ERROR", "File chunk send failed.")
                            break
                        bytes_sent += len(chunk)
                        pct = round((bytes_sent / filesize) * 100, 1)
                        if (pct - last_reported_pct >= 2.0) or (bytes_sent >= filesize):
                            last_reported_pct = pct
                            self.trigger_packet_event("TX", FrameType.FILE_CHUNK, self.active_mode, len(chunk_frame.payload), chunk_frame.payload[:16].hex())
                            if self.on_file_progress:
                                self.on_file_progress("TX", filename, bytes_sent, filesize, pct)

                # 3. Send FILE_END
                if self.is_connected:
                    end_frame = self._build_frame(FrameType.FILE_END, b"EOF")
                    self._send_raw_frame(end_frame)
                    self.trigger_packet_event("TX", FrameType.FILE_END, self.active_mode, len(end_frame.payload), end_frame.payload.hex())
                    self.log("SUCCESS", f"File '{filename}' transmitted completely.")
            except Exception as e:
                self.log("ERROR", f"File transfer failed: {str(e)}")

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _build_frame(self, frame_type: FrameType, payload: bytes) -> ProtocolFrame:
        if self.active_mode == SecurityMode.ENCRYPTED:
            if not self.crypto.session_key:
                # Fallback to plaintext if no session key (shouldn't happen in normal flow)
                return ProtocolFrame(frame_type=frame_type, mode=SecurityMode.PLAINTEXT, nonce=b"", payload=payload)
            nonce, ciphertext_and_tag = self.crypto.encrypt_aes_gcm(payload)
            return ProtocolFrame(
                frame_type=frame_type,
                mode=SecurityMode.ENCRYPTED,
                nonce=nonce,
                payload=ciphertext_and_tag
            )
        else:
            # Plaintext Mode (Cleartext for Wireshark inspection)
            return ProtocolFrame(
                frame_type=frame_type,
                mode=SecurityMode.PLAINTEXT,
                nonce=b"",
                payload=payload
            )

    def _send_raw_frame(self, frame: ProtocolFrame) -> bool:
        if not self.conn:
            return False
        try:
            packed_bytes = frame.pack()
            with self._send_lock:  # Thread-safe send
                self.conn.sendall(packed_bytes)
            return True
        except Exception as e:
            self.log("ERROR", f"Socket sendall error: {str(e)}")
            return False

    def disconnect(self):
        """Full disconnection — resets all state including server socket."""
        was_connected = self.is_connected
        self.is_connected = False
        self.is_running = False
        self.role = None
        self.peer_address = None

        # FIX BUG-020: close open file handle
        if self._incoming_file_handle:
            try:
                self._incoming_file_handle.close()
            except Exception:
                pass
            self._incoming_file_handle = None
        self._incoming_file_meta = None

        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        if self.on_status_change:
            self.on_status_change("DISCONNECTED", None)
        self.log("INFO", "Node disconnected and sockets cleared.")
