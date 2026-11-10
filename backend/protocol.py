"""
SecureVault LAN - Binary Framing & Network Protocol
Handles framing, serialization, deserialization, and stream reconstruction
across TCP socket boundaries for both Encrypted and Plaintext modes.
"""

import struct
import json
import socket
from enum import IntEnum
from typing import Optional, Dict, Any, Tuple


class SecurityMode(IntEnum):
    PLAINTEXT = 0x00  # Exposed for Wireshark inspection
    ENCRYPTED = 0x01  # AES-256-GCM Secure


class FrameType(IntEnum):
    # Handshake Frames
    HANDSHAKE_PUBKEY = 0x01
    HANDSHAKE_SESSIONKEY = 0x02
    HANDSHAKE_ACK = 0x03

    # Data Frames
    MSG_TEXT = 0x10
    FILE_START = 0x20
    FILE_CHUNK = 0x21
    FILE_END = 0x22

    # Control Frames
    PING = 0x30
    PONG = 0x31
    DISCONNECT = 0xFF


MAGIC_BYTES = b"SV"
# Header format: 
# 2 bytes Magic ('SV')
# 1 byte Mode (0=Plaintext, 1=Encrypted)
# 1 byte Frame Type
# 1 byte Nonce Length (0 to 12)
# 4 bytes Payload Length (unsigned 32-bit big endian)
HEADER_FORMAT = "!2sBBB I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 2 + 1 + 1 + 1 + 4 = 9 bytes


class ProtocolFrame:
    def __init__(
        self,
        frame_type: FrameType,
        mode: SecurityMode = SecurityMode.ENCRYPTED,
        nonce: bytes = b"",
        payload: bytes = b""
    ):
        self.frame_type = FrameType(frame_type)
        self.mode = SecurityMode(mode)
        self.nonce = nonce
        self.payload = payload

    def pack(self) -> bytes:
        """Serializes the frame into binary bytes ready for TCP socket transmission."""
        nonce_len = len(self.nonce)
        payload_len = len(self.payload)
        header = struct.pack(
            HEADER_FORMAT,
            MAGIC_BYTES,
            int(self.mode),
            int(self.frame_type),
            nonce_len,
            payload_len
        )
        return header + self.nonce + self.payload

    @classmethod
    def read_from_socket(cls, sock) -> Optional["ProtocolFrame"]:
        """
        Reads exactly one full ProtocolFrame from a TCP socket.
        Returns ProtocolFrame or None if socket closed.
        """
        # 1. Read fixed header
        header_data = cls._recv_exact(sock, HEADER_SIZE)
        if not header_data:
            return None
        
        magic, mode_val, frame_type_val, nonce_len, payload_len = struct.unpack(HEADER_FORMAT, header_data)
        
        if magic != MAGIC_BYTES:
            raise ValueError(f"Invalid frame magic: {magic}. Expected {MAGIC_BYTES}")

        # 2. Read nonce if present
        nonce = b""
        if nonce_len > 0:
            nonce = cls._recv_exact(sock, nonce_len)
            if not nonce:
                return None

        # 3. Read payload
        payload = b""
        if payload_len > 0:
            payload = cls._recv_exact(sock, payload_len)
            if not payload:
                return None

        return cls(
            frame_type=FrameType(frame_type_val),
            mode=SecurityMode(mode_val),
            nonce=nonce,
            payload=payload
        )

    @staticmethod
    def _recv_exact(sock, num_bytes: int) -> Optional[bytes]:
        """Reads exactly num_bytes from a streaming socket or file-like object."""
        buf = bytearray()
        while len(buf) < num_bytes:
            try:
                if hasattr(sock, "recv"):
                    chunk = sock.recv(num_bytes - len(buf))
                else:
                    chunk = sock.read(num_bytes - len(buf))
                if not chunk:
                    return None
                buf.extend(chunk)
            except (socket.timeout, TimeoutError):
                if len(buf) == 0:
                    # Idle timeout at start of frame - re-raise so caller loop checks is_running
                    raise
                # Timeout midway through frame packet
                return None
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                return None
        return bytes(buf)


    def to_json_dict(self) -> Dict[str, Any]:
        """Helper to decode JSON payload if frame contains json string."""
        return json.loads(self.payload.decode("utf-8"))

    @staticmethod
    def create_json_payload(data: Dict[str, Any]) -> bytes:
        return json.dumps(data).encode("utf-8")
