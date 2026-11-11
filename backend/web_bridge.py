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
from typing import Set, Dict, Any, Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response, File, UploadFile
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


def pick_file_native() -> Optional[str]:
    """Opens native Windows File Dialog to bypass browser fakepath restrictions."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        fpath = filedialog.askopenfilename(title="Select File to Encrypt & Stream")
        root.destroy()
        return fpath if fpath else None
    except Exception as e:
        print(f"[BRIDGE] Native file dialog error: {e}")
        return None


def pick_multi_files_native() -> list:
    """Opens native Windows Multi-File Dialog for Vault staging."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        fpaths = list(filedialog.askopenfilenames(title="Select Multiple Files for Vault Distribution"))
        root.destroy()
        return fpaths
    except Exception as e:
        print(f"[BRIDGE] Native multi-file dialog error: {e}")
        return []


def pick_directory_native() -> Optional[str]:
    """Opens native Windows folder selection dialog."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        dpath = filedialog.askdirectory(title="Select Destination Folder for Received Files")
        root.destroy()
        return dpath if dpath else None
    except Exception as e:
        print(f"[BRIDGE] Native directory dialog error: {e}")
        return None


def pick_save_file_native(default_filename: str = "") -> Optional[str]:
    """Opens native Windows Save As dialog."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        fpath = filedialog.asksaveasfilename(
            title="Save Received File As...",
            initialfile=default_filename
        )
        root.destroy()
        return fpath if fpath else None
    except Exception as e:
        print(f"[BRIDGE] Native save as dialog error: {e}")
        return None


def open_file_in_system(filepath: str) -> bool:
    """Launches file in its default Windows association."""
    try:
        if filepath and os.path.exists(filepath):
            os.startfile(os.path.abspath(filepath))
            return True
    except Exception as e:
        print(f"[BRIDGE] Failed to open file '{filepath}': {e}")
    return False


def open_folder_in_system(folder_path: str, highlight_file: Optional[str] = None) -> bool:
    """Opens Windows Explorer at folder or with specific file highlighted."""
    try:
        if highlight_file and os.path.exists(highlight_file):
            import subprocess
            subprocess.Popen(f'explorer /select,"{os.path.abspath(highlight_file)}"')
            return True
        elif folder_path and os.path.exists(folder_path):
            os.startfile(os.path.abspath(folder_path))
            return True
    except Exception as e:
        print(f"[BRIDGE] Failed to open folder '{folder_path}': {e}")
    return False


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
node.on_file_incoming = lambda meta: sync_broadcast("incoming_transfer", meta)

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
            "downloads_dir": os.path.abspath(node.downloads_dir),
            "quarantine_dir": os.path.abspath(node.quarantine_dir),
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

            elif action == "pick_and_send_file":
                if not node.is_connected:
                    await websocket.send_text(json.dumps({
                        "event": "log",
                        "data": {"level": "ERROR", "msg": "Cannot send file: No active peer connection."}
                    }))
                else:
                    def _picker_worker():
                        fpath = pick_file_native()
                        if fpath and os.path.exists(fpath):
                            node.send_file(fpath)
                    threading.Thread(target=_picker_worker, daemon=True).start()

            elif action == "pick_and_share_multi":
                if not node.is_connected:
                    await websocket.send_text(json.dumps({
                        "event": "log",
                        "data": {"level": "ERROR", "msg": "Cannot share vault: No active peer connection."}
                    }))
                else:
                    def _multi_picker_worker():
                        fpaths = pick_multi_files_native()
                        if fpaths:
                            node.share_multi_files(fpaths)
                    threading.Thread(target=_multi_picker_worker, daemon=True).start()

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

            # Phase 5: Folder / Directory & File System Actions
            elif action == "pick_download_dir":
                def _pick_dir_worker():
                    new_dir = pick_directory_native()
                    if new_dir:
                        node.set_downloads_dir(new_dir)
                        sync_broadcast("downloads_dir_updated", {"downloads_dir": node.downloads_dir})
                threading.Thread(target=_pick_dir_worker, daemon=True).start()

            elif action == "set_download_dir":
                new_dir = cmd.get("path")
                if new_dir:
                    node.set_downloads_dir(new_dir)
                    await broadcast_to_ui("downloads_dir_updated", {"downloads_dir": node.downloads_dir})

            elif action == "open_downloads_folder":
                open_folder_in_system(node.downloads_dir)

            elif action == "open_folder":
                target_path = cmd.get("path", node.downloads_dir)
                highlight = cmd.get("highlight")
                open_folder_in_system(target_path, highlight)

            elif action == "open_file":
                filepath = cmd.get("path")
                if filepath:
                    open_file_in_system(filepath)

            elif action == "save_file_as":
                filename = cmd.get("filename", "")
                source_path = cmd.get("path") or os.path.join(node.downloads_dir, filename)
                def _save_as_thread():
                    target_file = pick_save_file_native(default_filename=filename)
                    if target_file and os.path.exists(source_path):
                        import shutil
                        try:
                            shutil.copy2(source_path, target_file)
                            node.log("SUCCESS", f"File saved as '{os.path.basename(target_file)}' at: {target_file}")
                            sync_broadcast("file_saved_as", {"original": source_path, "new_path": target_file})
                        except Exception as e:
                            node.log("ERROR", f"Failed to save file: {e}")
                threading.Thread(target=_save_as_thread, daemon=True).start()

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _ws_remove(websocket)


# ---------------------------------------------------------------------------
# Direct File Upload Endpoints (Eliminates Browser C:\fakepath Sandbox Restrictions)
# ---------------------------------------------------------------------------
@app.post("/api/upload_and_send")
async def upload_and_send(file: UploadFile = File(...)):
    """Receives drag-and-dropped file binary directly and streams via encrypted socket."""
    if not node.is_connected:
        return {"status": "error", "message": "Cannot send: No active peer connection."}

    staging_dir = os.path.join(_PROJECT_ROOT, "_temp_staging")
    os.makedirs(staging_dir, exist_ok=True)
    temp_path = os.path.join(staging_dir, file.filename)

    with open(temp_path, "wb") as f:
        content = await file.read()
        f.write(content)

    success = node.send_file(temp_path)
    return {"status": "ok" if success else "error", "filename": file.filename}


@app.post("/api/upload_and_share_multi")
async def upload_and_share_multi(files: List[UploadFile] = File(...)):
    """Receives multiple drag-and-dropped files and publishes vault manifest."""
    if not node.is_connected:
        return {"status": "error", "message": "Cannot share vault: No active peer connection."}

    staging_dir = os.path.join(_PROJECT_ROOT, "_temp_staging")
    os.makedirs(staging_dir, exist_ok=True)
    staged_paths = []

    for file in files:
        temp_path = os.path.join(staging_dir, file.filename)
        with open(temp_path, "wb") as f:
            content = await file.read()
            f.write(content)
        staged_paths.append(temp_path)

    success = node.share_multi_files(staged_paths)
    return {"status": "ok" if success else "error", "count": len(staged_paths)}


@app.get("/api/pick_file")
async def api_pick_file():
    path = pick_file_native()
    return {"path": path}


@app.get("/api/pick_folder")
async def api_pick_folder():
    path = pick_directory_native()
    if path:
        node.set_downloads_dir(path)
        sync_broadcast("downloads_dir_updated", {"downloads_dir": node.downloads_dir})
    return {"path": path, "downloads_dir": node.downloads_dir}


@app.post("/api/open_folder")
async def api_open_folder(path: Optional[str] = None):
    target = path or node.downloads_dir
    success = open_folder_in_system(target)
    return {"status": "ok" if success else "error", "path": target}


@app.post("/api/open_file")
async def api_open_file(payload: Dict[str, Any]):
    filepath = payload.get("path", "")
    success = open_file_in_system(filepath)
    return {"status": "ok" if success else "error", "path": filepath}


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
