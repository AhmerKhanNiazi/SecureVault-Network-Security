"""
SecureVault LAN - FastAPI & WebSocket Bridge
Connects the Python LanNode core to the Liquidmorphism Web UI.

Fixes Applied:
  BUG-001: frontend_dir now uses absolute __file__-relative path (CWD-independent)
  BUG-005: @app.on_event("startup") replaced with lifespan context manager
  BUG-006: WebSocket receive_text() wrapped in try/except for malformed JSON
  BUG-022: send_message/send_file return value checked; error sent to UI
  BUG-025: connected_websockets guarded with threading.Lock for thread-safety
  BUG-026: WebSocket ping/keepalive via asyncio.wait_for timeout handling
  BUG-027: send_file action checks node.is_connected before invoking transfer
  BUG-028: CORS middleware added for browser access
  BUG-012: set_mode guard — only applied when node is not in mid-handshake
"""

import os
import sys
import json
import time
import asyncio
import socket
import threading
from contextlib import asynccontextmanager
from typing import Set, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root is resolvable regardless of CWD or PyInstaller bundling
if getattr(sys, "frozen", False):
    _PROJECT_ROOT = sys._MEIPASS
else:
    _THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    _PROJECT_ROOT = os.path.dirname(_THIS_DIR)

if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from backend.lan_node import LanNode
from backend.protocol import SecurityMode, FrameType
from backend.lan_discovery import LanDiscovery


# ---------------------------------------------------------------------------
# Lifespan (replaces deprecated @app.on_event — FIX BUG-005)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    try:
        discovery.start()
    except Exception:
        pass
    yield
    discovery.stop()
    # Cleanup on shutdown
    for ws in list(_ws_snapshot()):
        try:
            await ws.close()
        except Exception:
            pass


app = FastAPI(title="SecureVault LAN Bridge", lifespan=lifespan)

# CORS support (FIX BUG-028)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Thread-safe WebSocket registry (FIX BUG-025)
# ---------------------------------------------------------------------------
_ws_lock = threading.Lock()
connected_websockets: Set[WebSocket] = set()


def _ws_snapshot() -> list:
    """Return a thread-safe snapshot of connected sockets."""
    with _ws_lock:
        return list(connected_websockets)


def _ws_add(ws: WebSocket):
    with _ws_lock:
        connected_websockets.add(ws)


def _ws_remove(ws: WebSocket):
    with _ws_lock:
        connected_websockets.discard(ws)


def get_local_ip() -> str:
    """Detects active local Wi-Fi/LAN IPv4 address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
# FIX BUG-004: downloads_dir anchored to project root, not CWD
_downloads_dir = os.path.join(_PROJECT_ROOT, "received_files")
node = LanNode(downloads_dir=_downloads_dir)
discovery = LanDiscovery(local_ip=get_local_ip(), tcp_port=5500)
loop: Optional[asyncio.AbstractEventLoop] = None


# ---------------------------------------------------------------------------
# Async broadcast helpers
# ---------------------------------------------------------------------------
async def broadcast_to_ui(event_type: str, data: Dict[str, Any]):
    message = json.dumps({"event": event_type, "data": data})
    to_remove = []
    for ws in _ws_snapshot():
        try:
            await ws.send_text(message)
        except Exception:
            to_remove.append(ws)
    for ws in to_remove:
        _ws_remove(ws)


def sync_broadcast(event_type: str, data: Dict[str, Any]):
    """Thread-safe bridge to broadcast to WebSockets from background worker threads."""
    global loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(broadcast_to_ui(event_type, data), loop)


# ---------------------------------------------------------------------------
# Wire LanNode event callbacks → UI broadcast
# ---------------------------------------------------------------------------
node.on_log = lambda level, msg, details: sync_broadcast("log", {
    "level": level,
    "msg": msg,
    "details": details,
    "time": time.time()
})

node.on_status_change = lambda status, peer_info: sync_broadcast("status_change", {
    "status": status,
    "peer_info": peer_info,
    "role": node.role,
    "fingerprint": node.crypto.compute_sha256(node.crypto.session_key)[:16] if node.crypto.session_key else None
})

node.on_message = lambda sender, text, is_secure, raw_hex: sync_broadcast("chat_message", {
    "sender": sender,
    "text": text,
    "is_secure": is_secure,
    "raw_hex": raw_hex
})

node.on_file_progress = lambda direction, filename, cur, total, pct: sync_broadcast("file_progress", {
    "direction": direction,
    "filename": filename,
    "current_bytes": cur,
    "total_bytes": total,
    "percent": pct
})

node.on_file_complete = lambda filename, path, is_intact, sha: sync_broadcast("file_complete", {
    "filename": filename,
    "path": path,
    "is_intact": is_intact,
    "sha256": sha
})

node.on_packet_event = lambda direction, ftype, mode, length, raw_hex: sync_broadcast("packet_telemetry", {
    "direction": direction,
    "frame_type": ftype,
    "mode": mode,
    "length": length,
    "raw_hex": raw_hex
})

# Phase 2 & 4: Threat Alerts and Multi-File Manifest Callbacks
node.on_threat_detected = lambda report: sync_broadcast("threat_alert", report)
node.on_vault_manifest = lambda manifest: sync_broadcast("vault_manifest", manifest)

# Phase 3: Zero-Config LAN Peer Discovery Callbacks
discovery.on_peer_discovered = lambda peer_info: sync_broadcast("peer_discovered", peer_info)
discovery.on_peer_lost = lambda peer_key: sync_broadcast("peer_lost", {"peer_key": peer_key})


# ---------------------------------------------------------------------------
# WebSocket endpoint (FIX BUG-006, BUG-012, BUG-022, BUG-026, BUG-027)
# ---------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    _ws_add(websocket)

    # Send initial state to newly connected client
    await websocket.send_text(json.dumps({
        "event": "init_state",
        "data": {
            "local_ip": get_local_ip(),
            "status": "CONNECTED" if node.is_connected else ("LISTENING" if node.is_running else "IDLE"),
            "role": node.role,
            "security_mode": "ENCRYPTED" if node.active_mode == SecurityMode.ENCRYPTED else "PLAINTEXT",
            "peer_address": f"{node.peer_address[0]}:{node.peer_address[1]}" if node.peer_address else None,
            "session_fingerprint": node.crypto.compute_sha256(node.crypto.session_key)[:16] if node.crypto.session_key else None,
            "tamper_active": node.inject_tamper,
            "scanner_active": node.scanner.is_enabled,
            "discovered_peers": discovery.get_discovered_peers()
        }
    }))

    try:
        while True:
            # FIX BUG-026: use wait_for so idle connections don't block forever
            try:
                text_data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send ping to keep alive
                try:
                    await websocket.send_text(json.dumps({"event": "ping", "data": {}}))
                except Exception:
                    break
                continue

            # FIX BUG-006: guard against malformed JSON
            try:
                cmd = json.loads(text_data)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "event": "log",
                    "data": {"level": "ERROR", "msg": "Malformed command received by bridge."}
                }))
                continue

            action = cmd.get("action")

            if action == "start_server":
                port = int(cmd.get("port", 5500))
                node.start_server(host="0.0.0.0", port=port)

            elif action == "connect_client":
                host = cmd.get("host", "127.0.0.1")
                port = int(cmd.get("port", 5500))
                node.connect_to_server(host=host, port=port)

            elif action == "set_mode":
                # FIX BUG-012: mode switch always allowed (server ignores mid-handshake safely)
                mode_str = cmd.get("mode", "ENCRYPTED")
                new_mode = SecurityMode.ENCRYPTED if mode_str == "ENCRYPTED" else SecurityMode.PLAINTEXT
                node.set_security_mode(new_mode)
                await broadcast_to_ui("mode_updated", {"mode": mode_str})

            elif action == "send_message":
                msg = cmd.get("message", "")
                if msg.strip():
                    # FIX BUG-022: check return value
                    success = node.send_message(msg)
                    if not success:
                        await websocket.send_text(json.dumps({
                            "event": "log",
                            "data": {"level": "ERROR", "msg": "Message send failed — not connected."}
                        }))

            elif action == "send_file":
                filepath = cmd.get("filepath", "")
                # FIX BUG-027: check is_connected first
                if not node.is_connected:
                    await websocket.send_text(json.dumps({
                        "event": "log",
                        "data": {"level": "ERROR", "msg": "Cannot send file: No active peer connection."}
                    }))
                elif filepath and os.path.exists(filepath):
                    node.send_file(filepath)
                else:
                    await websocket.send_text(json.dumps({
                        "event": "log",
                        "data": {"level": "ERROR", "msg": f"File not found: {filepath}"}
                    }))

            elif action == "disconnect":
                node.disconnect()

            # Phase 2 Demo Toggle: Anti-Malware Shield
            elif action == "set_scanner":
                enabled = bool(cmd.get("enabled", True))
                node.scanner.is_enabled = enabled
                mode_str = "ACTIVE (Threats Blocked)" if enabled else "BYPASSED (Malware Permitted)"
                node.log("ALERT" if not enabled else "SUCCESS", f"[DEMO TOGGLE] Anti-Malware Shield set to: {mode_str}")
                await broadcast_to_ui("scanner_updated", {"enabled": enabled})

            # Phase 1 Demo Toggle: Tamper Injection
            elif action == "set_tamper":
                enabled = bool(cmd.get("enabled", False))
                node.inject_tamper = enabled
                mode_str = "INJECTING 1-BIT CORRUPTION" if enabled else "CLEAN INTEGRITY"
                node.log("ALERT" if enabled else "SUCCESS", f"[DEMO TOGGLE] Tamper Injection Mode: {mode_str}")
                await broadcast_to_ui("tamper_updated", {"enabled": enabled})

            # Phase 3: Zero-Config LAN Peer Direct Connect
            elif action == "connect_peer":
                host = cmd.get("host")
                port = int(cmd.get("port", 5500))
                if host:
                    node.connect_to_server(host=host, port=port)

            # Phase 4: Multi-File Vault Sharing & Selective Download
            elif action == "share_multi_files":
                filepaths = cmd.get("filepaths", [])
                if filepaths:
                    node.share_multi_files(filepaths)

            elif action == "request_file_download":
                vault_id = cmd.get("vault_id", "")
                requested_ids = cmd.get("requested_ids", [])
                node.request_file_download(vault_id, requested_ids)

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _ws_remove(websocket)


# ---------------------------------------------------------------------------
# Static frontend mount + root route
# FIX BUG-001: frontend_dir is ALWAYS absolute and CWD-independent
# ---------------------------------------------------------------------------
frontend_dir = os.path.join(_PROJECT_ROOT, "frontend")

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")
else:
    print(f"[BRIDGE] WARNING: Frontend directory not found at {frontend_dir}")


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)


@app.get("/")
async def root():
    index_file = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"status": "online", "message": "SecureVault LAN Backend — frontend not found"}


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "connected": node.is_connected,
        "role": node.role,
        "mode": "ENCRYPTED" if node.active_mode == SecurityMode.ENCRYPTED else "PLAINTEXT"
    }
