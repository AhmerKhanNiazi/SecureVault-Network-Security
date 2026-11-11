"""
Automated Integration Tests for Phase 4: Multi-File Vault & Selective Download
"""

import unittest
import time
import os
import tempfile
import shutil
from backend.lan_node import LanNode
from backend.protocol import SecurityMode


class TestMultiFileVault(unittest.TestCase):
    def setUp(self):
        self.server_dl = tempfile.mkdtemp(prefix="sv_srv_mf_")
        self.client_dl = tempfile.mkdtemp(prefix="sv_cli_mf_")
        self.server = LanNode(downloads_dir=self.server_dl)
        self.client = LanNode(downloads_dir=self.client_dl)
        self.port = 5897

        self.server.start_server(host="127.0.0.1", port=self.port)
        time.sleep(0.2)
        self.client.connect_to_server(host="127.0.0.1", port=self.port)

        for _ in range(30):
            if self.server.is_connected and self.client.is_connected:
                break
            time.sleep(0.1)

    def tearDown(self):
        self.client.disconnect()
        self.server.disconnect()
        time.sleep(0.1)
        shutil.rmtree(self.server_dl, ignore_errors=True)
        shutil.rmtree(self.client_dl, ignore_errors=True)

    def test_multi_file_manifest_and_selective_pull(self):
        """Verify staging multiple files, publishing manifest, and selective download."""
        # 1. Create 3 test files on client side
        f1 = os.path.join(self.client_dl, "doc1.txt")
        f2 = os.path.join(self.client_dl, "doc2.txt")
        f3 = os.path.join(self.client_dl, "doc3.txt")

        with open(f1, "wb") as f:
            f.write(b"Document 1 Content")
        with open(f2, "wb") as f:
            f.write(b"Document 2 Content")
        with open(f3, "wb") as f:
            f.write(b"Document 3 Content")

        received_manifests = []
        received_files = []

        self.server.on_vault_manifest = lambda m: received_manifests.append(m)
        self.server.on_file_complete = lambda fname, fpath, intact, sha: received_files.append(fname)

        # 2. Client publishes multi-file vault
        ok = self.client.share_multi_files([f1, f2, f3])
        self.assertTrue(ok)

        # Wait for server to receive manifest
        for _ in range(30):
            if received_manifests:
                break
            time.sleep(0.1)

        self.assertEqual(len(received_manifests), 1)
        manifest = received_manifests[0]
        self.assertEqual(len(manifest["items"]), 3)
        self.assertEqual(manifest["items"][0]["filename"], "doc1.txt")
        self.assertEqual(manifest["items"][1]["filename"], "doc2.txt")
        self.assertEqual(manifest["items"][2]["filename"], "doc3.txt")

        # 3. Server requests selective download of ONLY doc1 (id 0) and doc3 (id 2)
        pull_ok = self.server.request_file_download(manifest["vault_id"], [0, 2])
        self.assertTrue(pull_ok)

        # Wait for both requested files to arrive
        for _ in range(50):
            if len(received_files) >= 2:
                break
            time.sleep(0.1)

        self.assertIn("doc1.txt", received_files)
        self.assertIn("doc3.txt", received_files)
        self.assertNotIn("doc2.txt", received_files, "Unselected file doc2 should NOT be downloaded!")
