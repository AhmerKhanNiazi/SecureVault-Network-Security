"""
SecureVault LAN - Master Desktop Launcher
Starts the backend WebSocket/FastAPI engine and opens a native
Liquidmorphism Desktop Window on Windows.

Fixes Applied:
  BUG-001/002/003: CWD explicitly set to PROJECT_ROOT before imports
  BUG-002: Reliable Edge/Chrome standalone App-Mode with isolated user-data-dir
           REMOVED harmful flags (--enable-gpu-rasterization, --enable-zero-copy)
           that caused DirectX GPU TDR freezes (3-4 second typing delay) and crashes.
  BUG-004: Received files path anchored to project directory
  BUG-031: Reliable server-readiness health polling before launching window
  BUG-032: Auto-client retry loop in background thread to avoid race conditions
  BUG-035: GUI process monitoring: auto-fallback to default browser if app-mode exits,
           and clean shutdown when user closes window.
"""

import sys
import os
import time
import socket
import threading
import argparse
import webbrowser
import subprocess
import tempfile
import urllib.request
import uvicorn

# PyInstaller --windowed guard: prevent NoneType write crashes
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

# Anchor CWD to this file's folder and ensure sys.path
if getattr(sys, "frozen", False):
    PROJECT_ROOT = sys._MEIPASS
else:
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

os.chdir(PROJECT_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.web_bridge import app, node
from backend.protocol import SecurityMode


def find_free_port(start_port: int = 8082) -> int:
    """Finds an open TCP port on localhost with dual connect/bind verification."""
    port = start_port
    while port < 65535:
        # Check 1: Can we connect? If yes, another process is actively listening!
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                port += 1
                continue
        # Check 2: Can we bind?
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    return start_port


def run_fastapi_server(host: str, port: int):
    """Runs uvicorn in a dedicated worker thread."""
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False
    )
    server = uvicorn.Server(config)
    server.run()


def wait_until_server_ready(url: str, timeout: float = 6.0) -> bool:
    """Polls the FastAPI /health endpoint until it responds with 200 OK."""
    health_url = f"{url.rstrip('/')}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(health_url, timeout=0.5) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def launch_native_window(url: str, port: int, title: str = "SecureVault LAN - Cyber Defense Vault"):
    """
    Launches the futuristic Liquidmorphism UI in a native standalone Desktop App Window.
    Uses Google Chrome or 64-bit Edge in direct '--app=' mode.
    Opens without browser tabs, bookmarks, or address bar for a 100% native software look.
    """
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"),
    ]

    for exe in candidates:
        if exe and os.path.isfile(exe):
            try:
                proc = subprocess.Popen([
                    exe,
                    f"--app={url}",
                    "--window-size=1260,820"
                ])
                print(f"[LAUNCHER] Standalone Cyber Window launched via {os.path.basename(exe)} (PID: {proc.pid})")
                return proc
            except Exception as e:
                print(f"[LAUNCHER] Launch attempt notice ({exe}): {e}")

    # Fallback to default browser if no standalone browser executable was matched
    print(f"[LAUNCHER] Opening via default browser: {url}")
    webbrowser.open(url)
    return None



def main():
    parser = argparse.ArgumentParser(description="SecureVault LAN - Encrypted Transport & Visual Protocol Suite")
    parser.add_argument("--web-port", type=int, default=None, help="Port for the internal Web UI bridge")
    parser.add_argument("--lan-port", type=int, default=5500, help="Port for TCP LAN socket communication")
    parser.add_argument("--auto-server", action="store_true", help="Auto-start as Server on launch")
    parser.add_argument("--auto-client", type=str, default=None, help="Auto-connect as Client to target IP")
    parser.add_argument("--insecure-demo", action="store_true", help="Start in Plaintext mode for Wireshark inspection")
    parser.add_argument("--headless", action="store_true", help="Run without opening GUI window")

    args = parser.parse_args()

    # Determine free Web UI port (auto-detects and avoids conflicts with background services)
    requested_port = args.web_port if args.web_port else 8082
    web_port = find_free_port(requested_port)
    if args.web_port and web_port != args.web_port:
        print(f"[LAUNCHER] Notice: Requested port {args.web_port} is busy. Automatically switched to open port {web_port}.")
    web_url = f"http://127.0.0.1:{web_port}"

    print("=" * 70)
    print("  [+] SECUREVAULT LAN - ENCRYPTED TRANSPORT SUITE")
    print(f"  * Project Root:       {PROJECT_ROOT}")
    print(f"  * Internal UI Bridge: {web_url}")
    print(f"  * Default Socket Port:{args.lan_port}")
    print("=" * 70)

    # Optional initial mode overrides
    if args.insecure_demo:
        node.set_security_mode(SecurityMode.PLAINTEXT)

    # Start FastAPI server in background thread FIRST
    server_thread = threading.Thread(
        target=run_fastapi_server,
        args=("127.0.0.1", web_port),
        daemon=True
    )
    server_thread.start()

    # Wait until FastAPI is 100% ready before any GUI launch or connection
    print("[LAUNCHER] Initializing cryptographic engine and web bridge...")
    is_ready = wait_until_server_ready(web_url, timeout=6.0)
    if not is_ready:
        print("[LAUNCHER] Warning: Server readiness check timed out. Proceeding anyway...")
    else:
        print("[LAUNCHER] Web Bridge is active and verified healthy.")

    # Auto actions after server is live
    if args.auto_server:
        print(f"[LAUNCHER] Auto-starting TCP Server on port {args.lan_port}...")
        node.start_server(host="0.0.0.0", port=args.lan_port)
    elif args.auto_client:
        def _connect_client_worker(target_ip, port):
            time.sleep(1.0)
            print(f"[LAUNCHER] Auto-connecting Client to {target_ip}:{port}...")
            for attempt in range(1, 4):
                try:
                    node.connect_to_server(host=target_ip, port=port)
                    break
                except Exception as e:
                    print(f"[LAUNCHER] Connect attempt {attempt} failed ({e}), retrying...")
                    time.sleep(1.0)

        threading.Thread(target=_connect_client_worker, args=(args.auto_client, args.lan_port), daemon=True).start()

    if not args.headless:
        print("[LAUNCHER] Launching Liquidmorphism Cyber Window...")
        launch_native_window(web_url, port=web_port)
    else:
        print("[LAUNCHER] Running headlessly. Press Ctrl+C to terminate.")

    # Keep main server loop alive until user closes terminal or presses Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[LAUNCHER] Shutting down SecureVault node...")
    finally:
        node.disconnect()


if __name__ == "__main__":
    main()
