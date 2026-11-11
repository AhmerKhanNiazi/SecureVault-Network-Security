"""
Automated Unit Tests for Phase 2: Threat Scanner & Malware Protection Core
"""

import unittest
import os
import tempfile
import shutil
from backend.threat_scanner import ThreatScanner, EICAR_SIGNATURE


class TestThreatScanner(unittest.TestCase):
    def setUp(self):
        self.temp_quarantine = tempfile.mkdtemp(prefix="sv_quarantine_test_")
        self.scanner = ThreatScanner(quarantine_dir=self.temp_quarantine)

    def tearDown(self):
        if os.path.exists(self.temp_quarantine):
            shutil.rmtree(self.temp_quarantine, ignore_errors=True)

    def test_eicar_signature_detection_and_quarantine(self):
        """Verify standard EICAR test file is detected, blocked, and quarantined."""
        test_payload = EICAR_SIGNATURE
        report = self.scanner.scan_buffer("eicar_test.com", test_payload)

        self.assertFalse(report.is_safe, "EICAR string must not be reported as safe.")
        self.assertEqual(report.threat_type, "EICAR.StandardAntivirusTestFile")
        self.assertTrue(report.quarantined, "Threat must be quarantined.")
        self.assertIsNotNone(report.quarantine_path)
        self.assertTrue(os.path.exists(report.quarantine_path), "Quarantine locked file must exist on disk.")

    def test_dangerous_extension_blocking(self):
        """Verify dangerous scripts like .bat and .ps1 are blocked."""
        report_bat = self.scanner.scan_buffer("cleanup.bat", b"@echo off\r\ndel /f /q C:\\*")
        self.assertFalse(report_bat.is_safe)
        self.assertEqual(report_bat.threat_type, "POLICY.DangerousExecutableBlocked")

        report_ps1 = self.scanner.scan_buffer("exploit.ps1", b"Invoke-Expression 'test'")
        self.assertFalse(report_ps1.is_safe)
        self.assertEqual(report_ps1.threat_type, "POLICY.DangerousExecutableBlocked")

    def test_double_extension_deception_trap(self):
        """Verify disguised double extensions like .pdf.exe are trapped."""
        report = self.scanner.scan_buffer("Invoice_2026.pdf.exe", b"Some random executable bytes")
        self.assertFalse(report.is_safe)
        self.assertEqual(report.threat_type, "HEURISTIC.DoubleExtensionDeception")

    def test_header_pe_disguise_detection(self):
        """Verify file named .png with Windows MZ executable header is trapped as attack."""
        fake_image = b"MZ\x90\x00\x03\x00\x00\x00This is a disguised PE binary!"
        report = self.scanner.scan_buffer("vacation_photo.png", fake_image)
        self.assertFalse(report.is_safe)
        self.assertEqual(report.threat_type, "ATTACK.DisguisedExecutablePayload")

    def test_clean_file_passes(self):
        """Verify legitimate text and images pass cleanly."""
        clean_text = b"This is a legitimate university assignment report."
        report = self.scanner.scan_buffer("Assignment.txt", clean_text)
        self.assertTrue(report.is_safe)
        self.assertEqual(report.severity, "CLEAN")

    def test_bypass_demo_toggle(self):
        """Verify Demo Toggle 3 bypass permits payload when shield is toggled OFF for presentation."""
        self.scanner.is_enabled = False
        report = self.scanner.scan_buffer("malware.exe", b"MZexecutable")
        self.assertTrue(report.is_safe, "Bypass mode should allow payload for presentation demo.")
        self.assertEqual(report.threat_type, "BYPASSED")
