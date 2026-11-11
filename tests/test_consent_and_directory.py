"""
Automated Integration Tests for Transfer Proposal, Dynamic Directory & Consent
"""

import unittest
import time
import os
import tempfile
import shutil
from backend.lan_node import LanNode


class TestConsentAndDirectory(unittest.TestCase):
    def setUp(self):
        self.server_dl = tempfile.mkdtemp(prefix="sv_srv_consent_")
        self.client_dl = tempfile.mkdtemp(prefix="sv_cli_consent_")
        self.server = LanNode(downloads_dir=self.server_dl)
        self.client = LanNode(downloads_dir=self.client_dl)
        self.port = 5898

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

    def test_dynamic_download_dir_and_incoming_callback(self):
        """Verify dynamic download directory change and on_file_incoming proposal event."""
        new_custom_dir = tempfile.mkdtemp(prefix="sv_custom_dir_")
        try:
            # 1. Update download directory dynamically
            self.server.set_downloads_dir(new_custom_dir)
            self.assertEqual(os.path.abspath(self.server.downloads_dir), os.path.abspath(new_custom_dir))

            incoming_proposals = []
            completed_transfers = []

            self.server.on_file_incoming = lambda meta: incoming_proposals.append(meta)
            self.server.on_file_complete = lambda fname, fpath, intact, sha: completed_transfers.append((fname, fpath, intact))

            # 2. Create sample file on client
            test_file = os.path.join(self.client_dl, "proposal_sample.bin")
            with open(test_file, "wb") as f:
                f.write(b"Test content for transfer proposal notification")

            # 3. Client sends file
            ok = self.client.send_file(test_file)
            self.assertTrue(ok)

            # Wait for transfer completion
            for _ in range(30):
                if len(completed_transfers) > 0:
                    break
                time.sleep(0.1)

            # 4. Assert proposal was triggered
            self.assertEqual(len(incoming_proposals), 1)
            self.assertEqual(incoming_proposals[0]["filename"], "proposal_sample.bin")

            # 5. Assert file landed in the custom directory, NOT the old one
            self.assertEqual(len(completed_transfers), 1)
            fname, fpath, intact = completed_transfers[0]
            self.assertTrue(intact)
            self.assertTrue(fpath.startswith(os.path.abspath(new_custom_dir)))
            self.assertTrue(os.path.exists(fpath))

        finally:
            shutil.rmtree(new_custom_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
