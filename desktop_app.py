"""
SecureVault LAN - 100% Pure Native Desktop Application
Cyber-Green Obsidian Theme powered by CustomTkinter.
Zero browser, zero web server, zero Chromium dependencies.
Can be built into a standalone Windows .exe with PyInstaller.
"""

import sys
import os
import time
import socket
import threading
import argparse
from typing import Optional

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import customtkinter as ctk
from tkinter import filedialog, messagebox

from backend.lan_node import LanNode
from backend.crypto_engine import CryptoEngine
from backend.protocol import SecurityMode, FrameType


# ---------------------------------------------------------------------------
# Utility: LAN IP Detection
# ---------------------------------------------------------------------------
def get_local_ip() -> str:
    """Detects active local Wi-Fi/Ethernet IPv4 address."""
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
# Color Palette (Obsidian Cyber-Green)
# ---------------------------------------------------------------------------
C_BG_DEEP = "#070b08"
C_PANEL = "#0d1410"
C_PANEL_HEADER = "#111b15"
C_BORDER = "#1b3023"
C_BORDER_ACTIVE = "#00ff88"
C_NEON_GREEN = "#00ff88"
C_NEON_DARK = "#004d29"
C_EMERALD_BTN = "#00773d"
C_EMERALD_HOVER = "#00994e"
C_ALERT_RED = "#ff3366"
C_ALERT_DARK = "#661126"
C_TEXT_MAIN = "#f0f7f3"
C_TEXT_MUTED = "#8ca396"
C_TEXT_DIM = "#51695c"
C_CARD_BG = "#080e0a"
C_CYAN = "#38bdf8"


# ---------------------------------------------------------------------------
# Main Desktop Window
# ---------------------------------------------------------------------------
class SecureVaultApp(ctk.CTk):
    def __init__(self, lan_port: int = 5500, auto_server: bool = False, auto_client: Optional[str] = None):
        super().__init__()

        # Window Configuration
        self.title("SecureVault LAN — Hybrid Cryptographic Transport Suite")
        self.geometry("1240x820")
        self.minsize(1050, 700)
        self.configure(fg_color=C_BG_DEEP)

        # Core LAN Node
        downloads_path = os.path.join(PROJECT_ROOT, "received_files")
        self.node = LanNode(downloads_dir=downloads_path)
        self.default_port = lan_port
        self.current_role = "server"
        self.local_ip = get_local_ip()

        # Wire Node callbacks to UI thread via self.after
        self._wire_node_callbacks()

        # Build UI Components
        self._build_top_hud()
        self._build_main_workspace()

        # Handle window close cleanly
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Auto actions
        if auto_server:
            self.after(500, self._auto_start_server)
        elif auto_client:
            self.after(500, lambda: self._auto_start_client(auto_client))

    # -----------------------------------------------------------------------
    # Callback Thread Bridging (Thread-safe)
    # -----------------------------------------------------------------------
    def _wire_node_callbacks(self):
        self.node.on_log = lambda lvl, msg, det: self.after(0, self._ui_on_log, lvl, msg)
        self.node.on_status_change = lambda st, peer: self.after(0, self._ui_on_status_change, st, peer)
        self.node.on_message = lambda snd, txt, sec, hx: self.after(0, self._ui_on_message, snd, txt, sec)
        self.node.on_file_progress = lambda d, fn, c, t, pct: self.after(0, self._ui_on_file_prog, d, fn, c, t, pct)
        self.node.on_file_complete = lambda fn, p, intact, sha: self.after(0, self._ui_on_file_done, fn, p, intact, sha)
        self.node.on_packet_event = lambda d, ft, m, l, hx: self.after(0, self._ui_on_packet, d, ft, m, l, hx)

    # -----------------------------------------------------------------------
    # Top HUD Navigation
    # -----------------------------------------------------------------------
    def _build_top_hud(self):
        self.hud_frame = ctk.CTkFrame(self, fg_color=C_PANEL, corner_radius=10, border_width=1, border_color=C_BORDER)
        self.hud_frame.pack(fill="x", padx=14, pady=(12, 6))

        # Logo / Title
        logo_box = ctk.CTkFrame(self.hud_frame, fg_color="transparent")
        logo_box.pack(side="left", padx=14, pady=8)

        title_lbl = ctk.CTkLabel(
            logo_box,
            text="🛡️ SECUREVAULT LAN",
            font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            text_color=C_NEON_GREEN
        )
        title_lbl.pack(anchor="w")

        sub_lbl = ctk.CTkLabel(
            logo_box,
            text="HYBRID CRYPTO PROTOCOL • RSA-2048 + AES-256-GCM + SHA-256",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=C_TEXT_MUTED
        )
        sub_lbl.pack(anchor="w")

        # Security Mode Switch (Wireshark Hero Demo)
        self.mode_frame = ctk.CTkFrame(self.hud_frame, fg_color="#080e0a", corner_radius=20, border_width=1, border_color=C_BORDER)
        self.mode_frame.pack(side="right", padx=14, pady=8)

        self.mode_switch = ctk.CTkSwitch(
            self.mode_frame,
            text="🔐 AES-256-GCM SECURE",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=C_NEON_GREEN,
            progress_color=C_NEON_GREEN,
            button_color=C_TEXT_MAIN,
            button_hover_color=C_NEON_GREEN,
            command=self._on_security_toggle
        )
        self.mode_switch.select()
        self.mode_switch.pack(side="left", padx=12, pady=6)

        # Connection Status Badge
        self.status_badge = ctk.CTkFrame(self.hud_frame, fg_color="#080e0a", corner_radius=20, border_width=1, border_color=C_BORDER)
        self.status_badge.pack(side="right", padx=10, pady=8)

        self.status_dot = ctk.CTkLabel(
            self.status_badge,
            text="●",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=C_TEXT_MUTED
        )
        self.status_dot.pack(side="left", padx=(10, 4), pady=4)

        self.status_label = ctk.CTkLabel(
            self.status_badge,
            text="SYSTEM IDLE",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=C_TEXT_MAIN
        )
        self.status_label.pack(side="left", padx=(0, 12), pady=4)

    # -----------------------------------------------------------------------
    # Main 3-Column Workspace Grid
    # -----------------------------------------------------------------------
    def _build_main_workspace(self):
        self.main_grid = ctk.CTkFrame(self, fg_color="transparent")
        self.main_grid.pack(fill="both", expand=True, padx=14, pady=(4, 12))

        # Column Grid Weights
        self.main_grid.grid_columnconfigure(0, weight=280)  # Controller
        self.main_grid.grid_columnconfigure(1, weight=520)  # Messaging & Vault
        self.main_grid.grid_columnconfigure(2, weight=360)  # Audit & Hex
        self.main_grid.grid_rowconfigure(0, weight=1)

        self._build_col1_controller()
        self._build_col2_vault()
        self._build_col3_audit()

    # -----------------------------------------------------------------------
    # Column 1: Node Controller
    # -----------------------------------------------------------------------
    def _build_col1_controller(self):
        col1 = ctk.CTkFrame(self.main_grid, fg_color=C_PANEL, corner_radius=10, border_width=1, border_color=C_BORDER)
        col1.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=0)

        # Card Title
        lbl = ctk.CTkLabel(
            col1,
            text="⚡ NODE CONTROLLER",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=C_NEON_GREEN
        )
        lbl.pack(anchor="w", padx=12, pady=(12, 6))

        # Local IP Pill
        ip_pill = ctk.CTkLabel(
            col1,
            text=f"📡 Your LAN IP: {self.local_ip}",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=C_NEON_GREEN,
            fg_color="#08140c",
            corner_radius=6,
            padx=8,
            pady=4
        )
        ip_pill.pack(fill="x", padx=12, pady=(0, 10))

        # Role Selector (Host Server vs Connect Client)
        self.role_selector = ctk.CTkSegmentedButton(
            col1,
            values=["HOST SERVER", "CONNECT CLIENT"],
            selected_color=C_EMERALD_BTN,
            selected_hover_color=C_EMERALD_HOVER,
            unselected_color="#080e0a",
            unselected_hover_color="#101a13",
            text_color=C_TEXT_MAIN,
            command=self._on_role_change
        )
        self.role_selector.set("HOST SERVER")
        self.role_selector.pack(fill="x", padx=12, pady=(0, 12))

        # Server/Client Form Inputs
        self.form_frame = ctk.CTkFrame(col1, fg_color="transparent")
        self.form_frame.pack(fill="x", padx=12, pady=(0, 10))

        # Target IP (for Client Mode)
        self.lbl_target_ip = ctk.CTkLabel(self.form_frame, text="REMOTE SERVER IP:", font=ctk.CTkFont(size=11), text_color=C_TEXT_MUTED)
        self.entry_target_ip = ctk.CTkEntry(
            self.form_frame,
            placeholder_text="e.g. 192.168.1.15",
            fg_color="#080e0a",
            border_color=C_BORDER,
            text_color=C_TEXT_MAIN,
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.entry_target_ip.insert(0, "127.0.0.1")

        # LAN Port
        self.lbl_port = ctk.CTkLabel(self.form_frame, text="LAN PORT (TCP):", font=ctk.CTkFont(size=11), text_color=C_TEXT_MUTED)
        self.lbl_port.pack(anchor="w", pady=(0, 2))

        self.entry_port = ctk.CTkEntry(
            self.form_frame,
            fg_color="#080e0a",
            border_color=C_BORDER,
            text_color=C_TEXT_MAIN,
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.entry_port.insert(0, str(self.default_port))
        self.entry_port.pack(fill="x", pady=(0, 10))

        # Action Button (Initialize Server / Connect / Disconnect)
        self.btn_action = ctk.CTkButton(
            col1,
            text="INITIALIZE SECURE SERVER",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=C_EMERALD_BTN,
            hover_color=C_EMERALD_HOVER,
            height=38,
            command=self._on_action_click
        )
        self.btn_action.pack(fill="x", padx=12, pady=(0, 12))

        # Cryptographic Layer Telemetry Box
        crypto_card = ctk.CTkFrame(col1, fg_color=C_CARD_BG, corner_radius=8, border_width=1, border_color=C_BORDER)
        crypto_card.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        c_title = ctk.CTkLabel(
            crypto_card,
            text="🔒 CRYPTOGRAPHIC LAYER",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=C_NEON_GREEN
        )
        c_title.pack(anchor="w", padx=10, pady=(8, 4))

        self._add_crypto_row(crypto_card, "Key Exchange:", "RSA-2048 (OAEP-SHA256)")
        self.lbl_cipher_val = self._add_crypto_row(crypto_card, "Cipher Engine:", "AES-256-GCM (Authenticated)")
        self._add_crypto_row(crypto_card, "File Integrity:", "SHA-256 Checksums")
        self.lbl_fp_val = self._add_crypto_row(crypto_card, "Session Key:", "NOT NEGOTIATED", is_mono=True)

        # Wireshark Demo Tip Pill
        hint_card = ctk.CTkFrame(col1, fg_color="#0a140d", corner_radius=6, border_width=1, border_color="#183622")
        hint_card.pack(fill="x", padx=12, pady=(0, 10))

        hint_title = ctk.CTkLabel(hint_card, text="💡 WIRESHARK DEMO TIP", font=ctk.CTkFont(size=10, weight="bold"), text_color=C_NEON_GREEN)
        hint_title.pack(anchor="w", padx=8, pady=(4, 0))

        hint_msg = ctk.CTkLabel(
            hint_card,
            text="Capture on loopback or Wi-Fi with filter: 'tcp.port == 5500'. Toggle Secure to Plaintext to demo cleartext payload in Wireshark!",
            font=ctk.CTkFont(size=9),
            text_color=C_TEXT_MUTED,
            wraplength=230,
            justify="left"
        )
        hint_msg.pack(anchor="w", padx=8, pady=(0, 6))

    def _add_crypto_row(self, parent, label: str, val: str, is_mono: bool = False):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=2)
        lbl_k = ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=10), text_color=C_TEXT_MUTED)
        lbl_k.pack(side="left")
        lbl_v = ctk.CTkLabel(
            row,
            text=val,
            font=ctk.CTkFont(family="Consolas" if is_mono else "Segoe UI", size=10, weight="bold"),
            text_color=C_NEON_GREEN
        )
        lbl_v.pack(side="right")
        return lbl_v

    # -----------------------------------------------------------------------
    # Column 2: Messaging & File Vault
    # -----------------------------------------------------------------------
    def _build_col2_vault(self):
        col2 = ctk.CTkFrame(self.main_grid, fg_color=C_PANEL, corner_radius=10, border_width=1, border_color=C_BORDER)
        col2.grid(row=0, column=1, sticky="nsew", padx=4, pady=0)

        # Header
        head_box = ctk.CTkFrame(col2, fg_color="transparent")
        head_box.pack(fill="x", padx=12, pady=(12, 6))

        lbl = ctk.CTkLabel(
            head_box,
            text="💬 SECURE MESSAGING & FILE VAULT",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=C_TEXT_MAIN
        )
        lbl.pack(side="left")

        self.vault_badge = ctk.CTkLabel(
            head_box,
            text="STANDBY",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=C_TEXT_MUTED,
            fg_color="#080e0a",
            corner_radius=4,
            padx=6,
            pady=2
        )
        self.vault_badge.pack(side="right")

        # Chat Bubble Viewport (Scrollable)
        self.chat_scroll = ctk.CTkScrollableFrame(col2, fg_color=C_CARD_BG, corner_radius=8, border_width=1, border_color=C_BORDER)
        self.chat_scroll.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Initial placeholder
        self.placeholder_lbl = ctk.CTkLabel(
            self.chat_scroll,
            text="🛡️ Start server or connect to peer to begin encrypted LAN communication.",
            font=ctk.CTkFont(size=11),
            text_color=C_TEXT_DIM
        )
        self.placeholder_lbl.pack(pady=40)

        # Message Input Row
        input_row = ctk.CTkFrame(col2, fg_color="transparent")
        input_row.pack(fill="x", padx=12, pady=(0, 10))

        self.chat_input = ctk.CTkEntry(
            input_row,
            placeholder_text="Type confidential message to encrypt...",
            fg_color="#080e0a",
            border_color=C_BORDER,
            text_color=C_TEXT_MAIN,
            font=ctk.CTkFont(size=12),
            height=36
        )
        self.chat_input.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.chat_input.bind("<Return>", lambda e: self._on_send_message())

        self.btn_send = ctk.CTkButton(
            input_row,
            text="SEND",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color=C_EMERALD_BTN,
            hover_color=C_EMERALD_HOVER,
            width=70,
            height=36,
            command=self._on_send_message
        )
        self.btn_send.pack(side="right")

        # File Transfer Vessel
        file_box = ctk.CTkFrame(col2, fg_color=C_CARD_BG, corner_radius=8, border_width=1, border_color=C_BORDER)
        file_box.pack(fill="x", padx=12, pady=(0, 12))

        file_top = ctk.CTkFrame(file_box, fg_color="transparent")
        file_top.pack(fill="x", padx=10, pady=(8, 4))

        self.btn_pick_file = ctk.CTkButton(
            file_top,
            text="📁 BROWSE & SEND FILE SECURELY",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            fg_color="#0d2818",
            hover_color=C_EMERALD_BTN,
            border_width=1,
            border_color=C_NEON_GREEN,
            height=32,
            command=self._on_select_file
        )
        self.btn_pick_file.pack(side="left")

        self.lbl_file_meta = ctk.CTkLabel(
            file_top,
            text="Idle • Ready for 32KB AES chunk streaming",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=C_TEXT_MUTED
        )
        self.lbl_file_meta.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(file_box, progress_color=C_NEON_GREEN, fg_color="#000000", height=8)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=10, pady=(2, 8))

    # -----------------------------------------------------------------------
    # Column 3: Live Security Audit & Hex Telemetry
    # -----------------------------------------------------------------------
    def _build_col3_audit(self):
        col3 = ctk.CTkFrame(self.main_grid, fg_color=C_PANEL, corner_radius=10, border_width=1, border_color=C_BORDER)
        col3.grid(row=0, column=2, sticky="nsew", padx=(6, 0), pady=0)

        # Header
        head_box = ctk.CTkFrame(col3, fg_color="transparent")
        head_box.pack(fill="x", padx=12, pady=(12, 6))

        lbl = ctk.CTkLabel(
            head_box,
            text="🔬 LIVE SECURITY AUDIT & HEX",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=C_TEXT_MAIN
        )
        lbl.pack(side="left")

        btn_clear = ctk.CTkButton(
            head_box,
            text="CLEAR",
            font=ctk.CTkFont(size=9),
            fg_color="transparent",
            border_width=1,
            border_color=C_BORDER,
            text_color=C_TEXT_MUTED,
            width=50,
            height=22,
            command=self._clear_audit_log
        )
        btn_clear.pack(side="right")

        # Scrollable Audit Text Box
        self.audit_textbox = ctk.CTkTextbox(
            col3,
            fg_color="#040705",
            border_color=C_BORDER,
            border_width=1,
            text_color=C_TEXT_MUTED,
            font=ctk.CTkFont(family="Consolas", size=10),
            wrap="word"
        )
        self.audit_textbox.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.audit_textbox.insert("end", "[SYSTEM] Cryptographic node initialized and ready.\n")

        # Integrity Guard Card
        int_card = ctk.CTkFrame(col3, fg_color=C_CARD_BG, corner_radius=8, border_width=1, border_color=C_BORDER)
        int_card.pack(fill="x", padx=12, pady=(0, 12))

        self.lbl_int_header = ctk.CTkLabel(
            int_card,
            text="🛡️ INTEGRITY GUARD ACTIVE",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=C_NEON_GREEN
        )
        self.lbl_int_header.pack(anchor="w", padx=10, pady=(6, 2))

        self.lbl_int_body = ctk.CTkLabel(
            int_card,
            text="Guarded with 128-bit AES-GCM Auth Tags & SHA-256 Hashes.",
            font=ctk.CTkFont(size=10),
            text_color=C_TEXT_MUTED,
            wraplength=310,
            justify="left"
        )
        self.lbl_int_body.pack(anchor="w", padx=10, pady=(0, 8))

    # -----------------------------------------------------------------------
    # User Interactions & Handlers
    # -----------------------------------------------------------------------
    def _on_role_change(self, value):
        self.current_role = "server" if value == "HOST SERVER" else "client"
        if self.current_role == "server":
            self.lbl_target_ip.pack_forget()
            self.entry_target_ip.pack_forget()
            self.btn_action.configure(text="INITIALIZE SECURE SERVER", fg_color=C_EMERALD_BTN)
        else:
            self.lbl_target_ip.pack(anchor="w", pady=(0, 2))
            self.entry_target_ip.pack(fill="x", pady=(0, 8))
            self.btn_action.configure(text="CONNECT TO REMOTE PEER", fg_color=C_EMERALD_BTN)

    def _on_security_toggle(self):
        is_secure = self.mode_switch.get()
        if is_secure:
            self.node.set_security_mode(SecurityMode.ENCRYPTED)
            self.mode_switch.configure(text="🔐 AES-256-GCM SECURE", text_color=C_NEON_GREEN, progress_color=C_NEON_GREEN)
            self.lbl_cipher_val.configure(text="AES-256-GCM (Authenticated)", text_color=C_NEON_GREEN)
            self._log_audit("MODE", "[SECURE] AES-256-GCM authenticated cipher activated.")
        else:
            self.node.set_security_mode(SecurityMode.PLAINTEXT)
            self.mode_switch.configure(text="⚠️ PLAINTEXT (WIRESHARK DEMO)", text_color=C_ALERT_RED, progress_color=C_ALERT_RED)
            self.lbl_cipher_val.configure(text="UNENCRYPTED (Plaintext)", text_color=C_ALERT_RED)
            self._log_audit("ALERT", "[WIRESHARK DEMO] Switched to Plaintext cleartext mode!")

    def _on_action_click(self):
        if self.node.is_connected or self.node.is_running:
            self.node.disconnect()
            return

        port_str = self.entry_port.get().strip()
        port = int(port_str) if port_str.isdigit() else 5500

        if self.current_role == "server":
            self.node.start_server(host="0.0.0.0", port=port)
        else:
            target_ip = self.entry_target_ip.get().strip() or "127.0.0.1"
            self.node.connect_to_server(host=target_ip, port=port)

    def _on_send_message(self):
        msg = self.chat_input.get().strip()
        if not msg:
            return

        if not self.node.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to a LAN peer before sending messages.")
            return

        success = self.node.send_message(msg)
        if success:
            self.chat_input.delete(0, "end")

    def _on_select_file(self):
        if not self.node.is_connected:
            messagebox.showwarning("Not Connected", "Please connect to a LAN peer before transferring files.")
            return

        fpath = filedialog.askopenfilename(title="Select Confidential File for Encrypted LAN Transfer")
        if fpath:
            self.node.send_file(fpath)

    def _clear_audit_log(self):
        self.audit_textbox.delete("1.0", "end")
        self.audit_textbox.insert("end", "[SYSTEM] Audit buffer cleared.\n")

    # -----------------------------------------------------------------------
    # Node Event Handlers (Dispatched into UI)
    # -----------------------------------------------------------------------
    def _ui_on_log(self, level: str, msg: str):
        self._log_audit(level, f"[{level}] {msg}")

    def _log_audit(self, tag: str, text: str):
        self.audit_textbox.insert("end", f"{text}\n")
        self.audit_textbox.see("end")

    def _ui_on_status_change(self, status: str, peer_info: Optional[str]):
        if status == "CONNECTED":
            self.status_dot.configure(text_color=C_NEON_GREEN)
            self.status_label.configure(text=f"CONNECTED: {peer_info or 'PEER'}")
            self.btn_action.configure(text="DISCONNECT SESSION", fg_color=C_ALERT_DARK, hover_color=C_ALERT_RED)
            self.vault_badge.configure(text="ENCRYPTED STREAM ACTIVE", text_color=C_NEON_GREEN)

            if self.node.crypto.session_key:
                fp = self.node.crypto.compute_sha256(self.node.crypto.session_key)[:16]
                self.lbl_fp_val.configure(text=f"{fp}...")
        elif status == "LISTENING":
            self.status_dot.configure(text_color="#ffcc00")
            self.status_label.configure(text="LISTENING FOR PEER...")
            self.btn_action.configure(text="STOP LISTENING", fg_color=C_ALERT_DARK, hover_color=C_ALERT_RED)
            self.vault_badge.configure(text="WAITING FOR CONNECTION", text_color=C_TEXT_MUTED)
        else:
            self.status_dot.configure(text_color=C_TEXT_MUTED)
            self.status_label.configure(text="SYSTEM IDLE")
            btn_txt = "INITIALIZE SECURE SERVER" if self.current_role == "server" else "CONNECT TO REMOTE PEER"
            self.btn_action.configure(text=btn_txt, fg_color=C_EMERALD_BTN, hover_color=C_EMERALD_HOVER)
            self.vault_badge.configure(text="STANDBY", text_color=C_TEXT_MUTED)
            self.lbl_fp_val.configure(text="NOT NEGOTIATED")

    def _ui_on_message(self, sender: str, text: str, is_secure: bool):
        if hasattr(self, "placeholder_lbl") and self.placeholder_lbl.winfo_exists():
            self.placeholder_lbl.destroy()

        is_me = (sender == "Me")
        bg_col = "#003b1c" if is_me else "#0e1a12"
        border_col = C_NEON_GREEN if is_secure else C_ALERT_RED

        bubble = ctk.CTkFrame(self.chat_scroll, fg_color=bg_col, corner_radius=8, border_width=1, border_color=border_col)
        bubble.pack(fill="x", padx=6, pady=4, anchor="e" if is_me else "w")

        # Meta Header
        time_str = time.strftime("%H:%M:%S")
        sec_badge = "🔐 AES-256-GCM" if is_secure else "⚠️ PLAINTEXT"
        meta_lbl = ctk.CTkLabel(
            bubble,
            text=f"{sender} • {sec_badge} • {time_str}",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=C_TEXT_MUTED
        )
        meta_lbl.pack(anchor="w", padx=8, pady=(4, 0))

        # Body
        body_lbl = ctk.CTkLabel(
            bubble,
            text=text,
            font=ctk.CTkFont(size=12),
            text_color=C_TEXT_MAIN,
            wraplength=480,
            justify="left"
        )
        body_lbl.pack(anchor="w", padx=8, pady=(2, 6))

    def _ui_on_file_prog(self, direction: str, filename: str, cur: int, total: int, pct: float):
        self.progress_bar.set(pct / 100.0)
        cur_kb = round(cur / 1024, 1)
        tot_kb = round(total / 1024, 1)
        self.lbl_file_meta.configure(text=f"[{direction}] {filename}: {cur_kb}/{tot_kb} KB ({pct}%)")

    def _ui_on_file_done(self, filename: str, path: str, intact: bool, sha256: str):
        self.progress_bar.set(1.0)
        if intact:
            self.lbl_file_meta.configure(text=f"✓ '{filename}' Integrity 100% Verified")
            self.lbl_int_header.configure(text="SHA-256 CHECKSUM MATCH ✓", text_color=C_NEON_GREEN)
            self.lbl_int_body.configure(text=f"File: {filename}\nHash: {sha256[:24]}...")
        else:
            self.lbl_file_meta.configure(text=f"✗ '{filename}' INTEGRITY FAILED")
            self.lbl_int_header.configure(text="TAMPERING DETECTED ✗", text_color=C_ALERT_RED)
            self.lbl_int_body.configure(text=f"File: {filename} failed SHA-256 integrity checksum verification!")

    def _ui_on_packet(self, direction: str, ftype: str, mode: str, length: int, raw_hex: str):
        dir_sym = "▲ OUT" if direction == "TX" else "▼ IN"
        preview = f" Hex: {raw_hex[:24]}..." if raw_hex else ""
        self._log_audit(direction, f"[{dir_sym}] {ftype} ({length}B) [{mode}]{preview}")

    # -----------------------------------------------------------------------
    # Auto Launch Helpers
    # -----------------------------------------------------------------------
    def _auto_start_server(self):
        self.node.start_server(host="0.0.0.0", port=self.default_port)

    def _auto_start_client(self, target_ip: str):
        self.role_selector.set("CONNECT CLIENT")
        self._on_role_change("CONNECT CLIENT")
        self.entry_target_ip.delete(0, "end")
        self.entry_target_ip.insert(0, target_ip)
        self.node.connect_to_server(host=target_ip, port=self.default_port)

    def _on_close(self):
        try:
            self.node.disconnect()
        except Exception:
            pass
        self.destroy()


# ---------------------------------------------------------------------------
# CLI Master Entry
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SecureVault LAN — Native Cyber Desktop Application")
    parser.add_argument("--lan-port", type=int, default=5500, help="Port for TCP LAN socket")
    parser.add_argument("--auto-server", action="store_true", help="Auto start as server")
    parser.add_argument("--auto-client", type=str, default=None, help="Auto connect to target IP")
    args = parser.parse_args()

    app = SecureVaultApp(
        lan_port=args.lan_port,
        auto_server=args.auto_server,
        auto_client=args.auto_client
    )
    app.mainloop()


if __name__ == "__main__":
    main()
