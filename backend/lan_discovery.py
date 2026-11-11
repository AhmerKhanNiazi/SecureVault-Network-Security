"""
SecureVault LAN - Zero-Config LAN Peer Discovery Engine (Phase 3)
AirShare / LocalSend Style UDP Broadcast Beacon Service.
Enables automatic discovery across 50-300 lab PCs on the same LAN subnet
without requiring users to manually enter IP addresses.
"""

import socket
import threading
import time
import json
import uuid
from typing import Dict, Any, Optional, Callable, List


class LanDiscovery:
    DEFAULT_UDP_PORT = 5555
    BEACON_INTERVAL = 3.0  # seconds between heartbeat broadcasts
    PEER_TTL = 10.0        # seconds before inactive peer is purged

    def __init__(
        self,
        local_ip: str,
        tcp_port: int = 5500,
        udp_port: int = DEFAULT_UDP_PORT,
        hostname: Optional[str] = None
    ):
        self.local_ip = local_ip
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.hostname = hostname or socket.gethostname()
        self.node_id = f"SV-{str(uuid.uuid4())[:6].upper()}"

        self.is_running = False
        self.active_peers: Dict[str, Dict[str, Any]] = {}  # key -> {peer_info, last_seen}
        self._lock = threading.Lock()

        # Callbacks
        self.on_peer_discovered: Optional[Callable[[Dict[str, Any]], None]] = None
        self.on_peer_lost: Optional[Callable[[str], None]] = None

        self._rx_sock: Optional[socket.socket] = None
        self._tx_sock: Optional[socket.socket] = None

    def start(self):
        """Starts discovery broadcast beacon and receiver listener."""
        if self.is_running:
            return
        self.is_running = True

        # Start RX listener thread
        threading.Thread(target=self._listen_loop, daemon=True).start()
        # Start TX beacon thread
        threading.Thread(target=self._broadcast_loop, daemon=True).start()
        # Start peer TTL cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def stop(self):
        """Stops discovery service and closes sockets."""
        self.is_running = False
        if self._rx_sock:
            try:
                self._rx_sock.close()
            except Exception:
                pass
            self._rx_sock = None
        if self._tx_sock:
            try:
                self._tx_sock.close()
            except Exception:
                pass
            self._tx_sock = None

    def get_discovered_peers(self) -> List[Dict[str, Any]]:
        """Returns a snapshot list of currently active LAN peers."""
        with self._lock:
            return [v["info"] for v in self.active_peers.values()]

    def _broadcast_loop(self):
        """Transmits periodic UDP heartbeat to local subnet."""
        try:
            self._tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            return

        while self.is_running:
            try:
                beacon_data = {
                    "service": "SecureVault",
                    "version": "2.0",
                    "node_id": self.node_id,
                    "hostname": self.hostname,
                    "ip": self.local_ip,
                    "tcp_port": self.tcp_port,
                    "status": "READY",
                    "timestamp": time.time()
                }
                payload = json.dumps(beacon_data).encode("utf-8")
                # Broadcast to subnet
                self._tx_sock.sendto(payload, ("<broadcast>", self.udp_port))
            except Exception:
                pass
            time.sleep(self.BEACON_INTERVAL)

    def _listen_loop(self):
        """Listens for UDP heartbeats from other SecureVault nodes."""
        try:
            self._rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # On Windows, binding to '' or '0.0.0.0' receives broadcast
            self._rx_sock.bind(("", self.udp_port))
            self._rx_sock.settimeout(2.0)
        except Exception as e:
            # If port 5555 is blocked or restricted, discovery degrades gracefully
            return

        while self.is_running:
            try:
                data, addr = self._rx_sock.recvfrom(2048)
                msg = json.loads(data.decode("utf-8", errors="ignore"))

                # Validate beacon schema
                if msg.get("service") != "SecureVault":
                    continue

                peer_node_id = msg.get("node_id")
                # Ignore self-beacons
                if peer_node_id == self.node_id:
                    continue

                peer_ip = msg.get("ip") or addr[0]
                peer_port = int(msg.get("tcp_port", 5500))
                peer_key = f"{peer_ip}:{peer_port}"

                peer_info = {
                    "node_id": peer_node_id,
                    "hostname": msg.get("hostname", "Unknown Host"),
                    "ip": peer_ip,
                    "tcp_port": peer_port,
                    "status": msg.get("status", "READY"),
                    "last_seen": time.time()
                }

                is_new = False
                with self._lock:
                    if peer_key not in self.active_peers:
                        is_new = True
                    self.active_peers[peer_key] = {
                        "info": peer_info,
                        "last_seen": time.time()
                    }

                if is_new and self.on_peer_discovered:
                    self.on_peer_discovered(peer_info)

            except socket.timeout:
                continue
            except Exception:
                continue

    def _cleanup_loop(self):
        """Purges stale peers that haven't sent a heartbeat within PEER_TTL."""
        while self.is_running:
            time.sleep(2.0)
            now = time.time()
            expired_keys = []

            with self._lock:
                for key, val in list(self.active_peers.items()):
                    if now - val["last_seen"] > self.PEER_TTL:
                        expired_keys.append(key)
                for key in expired_keys:
                    del self.active_peers[key]

            for key in expired_keys:
                if self.on_peer_lost:
                    self.on_peer_lost(key)
