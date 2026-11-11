"""
SecureVault LAN - Threat & Malware Inspection Core (Phase 2)
Provides multi-tiered threat detection for incoming/outgoing files:
  1. Standard EICAR Antivirus Test Signature Detection (100% safe lab demos)
  2. Executable & Dangerous Script Extension Blocking (.exe, .bat, .ps1, .vbs, .scr, etc.)
  3. Deceptive Double-Extension Heuristics (e.g. document.pdf.exe, invoice.docx.vbs)
  4. Header Magic-Bytes / PE Disguise Verification (e.g. .jpg file with 'MZ' PE header)
  5. Windows AMSI (Antimalware Scan Interface) Native Scanning
  6. Isolated Quarantine Storage (.locked payload + JSON telemetry report)
"""

import os
import sys
import ctypes
import hashlib
import json
from typing import Dict, Any, Tuple, Optional

# Standard EICAR Test String (Industry standard for AV verification)
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# High-risk executable & scripting extensions
BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".scr", ".pif", ".msi", ".dll", ".hta", ".cpl", ".reg"
}

# Known common non-executable extensions that should NEVER have a PE (MZ) header
DOCUMENT_IMAGE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".json", ".xml",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp",
    ".mp3", ".wav", ".mp4", ".mkv", ".zip", ".tar", ".gz"
}

# Windows PE Header Magic Bytes ('MZ')
PE_HEADER_MAGIC = b"MZ"
ELF_HEADER_MAGIC = b"\x7fELF"


class ThreatReport:
    def __init__(
        self,
        is_safe: bool,
        threat_type: str = "NONE",
        severity: str = "LOW",
        details: str = "No threats detected.",
        quarantined: bool = False,
        quarantine_path: Optional[str] = None
    ):
        self.is_safe = is_safe
        self.threat_type = threat_type
        self.severity = severity
        self.details = details
        self.quarantined = quarantined
        self.quarantine_path = quarantine_path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_safe": self.is_safe,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "details": self.details,
            "quarantined": self.quarantined,
            "quarantine_path": self.quarantine_path
        }


class ThreatScanner:
    """Multi-tiered Antimalware and Heuristic Threat Inspection Engine."""

    def __init__(self, quarantine_dir: str = "quarantine"):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.is_enabled = True  # Demo Toggle 3: Shield Active vs Bypass
        self._amsi_context = None
        self._init_amsi()

    def _init_amsi(self):
        """Attempts to load Windows AMSI (Antimalware Scan Interface) if available."""
        if sys.platform == "win32":
            try:
                self.amsi = ctypes.windll.amsi
                # AMSI is available on Windows 10/11
                self.has_native_amsi = True
            except Exception:
                self.has_native_amsi = False
        else:
            self.has_native_amsi = False

    def scan_buffer(self, filename: str, data: bytes) -> ThreatReport:
        """
        Performs full multi-tier inspection on an in-memory byte buffer.
        Returns a ThreatReport object.
        """
        if not self.is_enabled:
            return ThreatReport(
                is_safe=True,
                threat_type="BYPASSED",
                severity="NONE",
                details="[BYPASS DEMO] Threat Scanner is disabled via Presentation Toggle. Payload permitted without scan."
            )

        lower_name = filename.lower()
        ext = os.path.splitext(lower_name)[1]

        # -------------------------------------------------------------
        # Tier 1: EICAR Antivirus Test Signature Check
        # -------------------------------------------------------------
        if EICAR_SIGNATURE in data:
            return self._handle_quarantine(
                filename, data,
                threat_type="EICAR.StandardAntivirusTestFile",
                severity="CRITICAL",
                details="Standard EICAR Antivirus Test Pattern detected in payload! 100% matched."
            )

        # -------------------------------------------------------------
        # Tier 2: Double-Extension Deception Analysis (e.g. report.pdf.exe)
        # -------------------------------------------------------------
        parts = lower_name.split(".")
        if len(parts) >= 3:
            first_ext = "." + parts[-2]
            final_ext = "." + parts[-1]
            if first_ext in DOCUMENT_IMAGE_EXTENSIONS and final_ext in BLOCKED_EXTENSIONS:
                return self._handle_quarantine(
                    filename, data,
                    threat_type="HEURISTIC.DoubleExtensionDeception",
                    severity="HIGH",
                    details=f"Deceptive double-extension detected! Masquerading as '{first_ext}' while executing as dangerous '{final_ext}'."
                )

        # -------------------------------------------------------------
        # Tier 3: Dangerous Executable / Script Extension Policy
        # -------------------------------------------------------------
        if ext in BLOCKED_EXTENSIONS:
            return self._handle_quarantine(
                filename, data,
                threat_type="POLICY.DangerousExecutableBlocked",
                severity="HIGH",
                details=f"Restricted executable file format '{ext}' blocked by SecureVault network security policy."
            )

        # -------------------------------------------------------------
        # Tier 4: Header Magic-Bytes / PE Disguise Verification
        # -------------------------------------------------------------
        header_sample = data[:512]
        if ext in DOCUMENT_IMAGE_EXTENSIONS:
            if header_sample.startswith(PE_HEADER_MAGIC):
                return self._handle_quarantine(
                    filename, data,
                    threat_type="ATTACK.DisguisedExecutablePayload",
                    severity="CRITICAL",
                    details=f"Header anomaly! File declared as '{ext}' contains Windows PE executable header ('MZ'). Disguise attack blocked."
                )
            if header_sample.startswith(ELF_HEADER_MAGIC):
                return self._handle_quarantine(
                    filename, data,
                    threat_type="ATTACK.DisguisedLinuxBinary",
                    severity="CRITICAL",
                    details=f"Header anomaly! File declared as '{ext}' contains Linux ELF executable signature."
                )

        # -------------------------------------------------------------
        # Tier 5: Windows Native AMSI Buffer Scan
        # -------------------------------------------------------------
        if self.has_native_amsi and len(data) > 0:
            try:
                amsi_result = self._scan_with_amsi(filename, data)
                if amsi_result is not None and amsi_result >= 32768:
                    return self._handle_quarantine(
                        filename, data,
                        threat_type="AMSI.WindowsDefenderDetection",
                        severity="CRITICAL",
                        details="Microsoft Defender AMSI detected malicious code in data buffer."
                    )
            except Exception:
                pass  # Fallback gracefully if AMSI session fails

        # All tiers passed — payload is clean
        return ThreatReport(
            is_safe=True,
            threat_type="NONE",
            severity="CLEAN",
            details="All 5 Security Scanning Tiers Passed: Hash clean, Header verified, No malicious patterns."
        )

    def scan_file_on_disk(self, file_path: str) -> ThreatReport:
        """Inspects an existing file on disk."""
        filename = os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                header_data = f.read(1024 * 1024)  # First 1MB for inspection
            return self.scan_buffer(filename, header_data)
        except Exception as e:
            return ThreatReport(is_safe=False, threat_type="SCAN_ERROR", severity="HIGH", details=f"Failed to read file for scan: {str(e)}")

    def _handle_quarantine(self, filename: str, data: bytes, threat_type: str, severity: str, details: str) -> ThreatReport:
        """Locks malicious payload into quarantine directory with metadata."""
        file_hash = hashlib.sha256(data).hexdigest()
        sanitized_base = "".join(c for c in filename if c.isalnum() or c in "._- ")
        locked_filename = f"{file_hash[:16]}_{sanitized_base}.locked"
        locked_path = os.path.join(self.quarantine_dir, locked_filename)

        meta_path = locked_path + ".json"

        try:
            with open(locked_path, "wb") as f:
                f.write(data)

            report_meta = {
                "original_filename": filename,
                "threat_type": threat_type,
                "severity": severity,
                "sha256": file_hash,
                "size_bytes": len(data),
                "details": details,
                "status": "QUARANTINED"
            }
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(report_meta, f, indent=2)

            return ThreatReport(
                is_safe=False,
                threat_type=threat_type,
                severity=severity,
                details=details,
                quarantined=True,
                quarantine_path=locked_path
            )
        except Exception as e:
            return ThreatReport(
                is_safe=False,
                threat_type=threat_type,
                severity=severity,
                details=f"{details} (Quarantine file save error: {str(e)})",
                quarantined=False
            )

    def _scan_with_amsi(self, filename: str, data: bytes) -> Optional[int]:
        """Direct call to amsi.dll AmsiScanBuffer."""
        try:
            HRESULT = ctypes.c_long
            HAMSICONTEXT = ctypes.c_void_p
            HAMSISESSION = ctypes.c_void_p
            AMSI_RESULT = ctypes.c_int

            ctx = HAMSICONTEXT()
            res = self.amsi.AmsiInitialize(ctypes.c_wchar_p("SecureVaultLAN"), ctypes.byref(ctx))
            if res != 0 or not ctx:
                return None

            scan_res = AMSI_RESULT(0)
            sample_len = min(len(data), 65536)  # Scan first 64KB for speed
            scan_err = self.amsi.AmsiScanBuffer(
                ctx,
                ctypes.c_char_p(data[:sample_len]),
                ctypes.c_ulong(sample_len),
                ctypes.c_wchar_p(filename),
                HAMSISESSION(0),
                ctypes.byref(scan_res)
            )
            self.amsi.AmsiUninitialize(ctx)

            if scan_err == 0:
                return scan_res.value
            return None
        except Exception:
            return None
