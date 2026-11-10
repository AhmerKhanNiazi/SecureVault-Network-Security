"""
End-to-End Automated Integration Test for SecureVault LAN
Spins up Server and Client on localhost, validates RSA handshake,
AES-256 message encryption, chunked file transfer, and SHA-256 integrity verification.
"""

import unittest
import time
import os
import tempfile
from backend.lan_node import LanNode
from backend.protocol import SecurityMode


class TestLanNetworkE2E(unittest.TestCase):
    def setUp(self):
        self.server_downloads = tempfile.mkdtemp(prefix="sv_server_dl_")
        self.client_downloads = tempfile.mkdtemp(prefix="sv_client_dl_")
        self.server = LanNode(downloads_dir=self.server_downloads)
        self.client = LanNode(downloads_dir=self.client_downloads)
        self.port = 5892

    def tearDown(self):
        self.client.disconnect()
        self.server.disconnect()
        time.sleep(0.1)

    def test_full_e2e_secure_handshake_and_transfer(self):
        server_received_messages = []
        client_received_messages = []
        server_files_received = []

        self.server.on_message = lambda sender, text, is_enc, hex_dump: server_received_messages.append((text, is_enc))
        self.client.on_message = lambda sender, text, is_enc, hex_dump: client_received_messages.append((text, is_enc))
        self.server.on_file_complete = lambda fname, fpath, intact, chash: server_files_received.append((fname, fpath, intact))

        # 1. Start Server
        self.server.start_server(host="127.0.0.1", port=self.port)
        time.sleep(0.3)

        # 2. Connect Client
        self.client.connect_to_server(host="127.0.0.1", port=self.port)
        
        # Wait for handshake to finish (max 3 seconds)
        for _ in range(30):
            if self.server.is_connected and self.client.is_connected:
                break
            time.sleep(0.1)

        self.assertTrue(self.server.is_connected, "Server failed to connect.")
        self.assertTrue(self.client.is_connected, "Client failed to connect.")
        self.assertIsNotNone(self.server.crypto.session_key, "Server session key is None")
        self.assertIsNotNone(self.client.crypto.session_key, "Client session key is None")
        self.assertEqual(len(self.server.crypto.session_key), 32, "Session key must be 32 bytes (AES-256)")
        self.assertEqual(self.server.crypto.session_key, self.client.crypto.session_key, "Session keys do not match!")

        # 3. Test Secure Encrypted Message Transfer
        test_msg = "Top-Secret-Assignment-Key: 99482-XYZ"
        sent_ok = self.client.send_message(test_msg)
        self.assertTrue(sent_ok)

        # Wait for message arrival
        time.sleep(0.3)
        self.assertEqual(len(server_received_messages), 1)
        self.assertEqual(server_received_messages[0][0], test_msg)
        self.assertTrue(server_received_messages[0][1], "Message should be marked as encrypted")

        # 4. Test Chunked File Transfer & SHA-256 Verification
        with tempfile.NamedTemporaryFile(delete=False, suffix=".dat") as tf:
            tf.write(os.urandom(100 * 1024))  # 100 KB random payload
            test_file_path = tf.name

        try:
            file_sent_ok = self.client.send_file(test_file_path)
            self.assertTrue(file_sent_ok)

            # Wait for file transfer and integrity verification
            for _ in range(40):
                if server_files_received:
                    break
                time.sleep(0.1)

            self.assertEqual(len(server_files_received), 1)
            fname, fpath, is_intact = server_files_received[0]
            self.assertTrue(is_intact, "File SHA-256 integrity verification failed!")
            self.assertTrue(os.path.exists(fpath))
            self.assertEqual(os.path.getsize(fpath), 100 * 1024)
        finally:
            if os.path.exists(test_file_path):
                os.remove(test_file_path)

        # 5. Test Wireshark Plaintext Demonstration Mode
        self.client.set_security_mode(SecurityMode.PLAINTEXT)
        plain_msg = "INSECURE_PLAINTEXT_PAYLOAD_FOR_WIRESHARK"
        self.client.send_message(plain_msg)
        time.sleep(0.3)

        self.assertEqual(len(server_received_messages), 2)
        self.assertEqual(server_received_messages[1][0], plain_msg)
        self.assertFalse(server_received_messages[1][1], "Message should be marked as unencrypted (plaintext)")


if __name__ == "__main__":
    unittest.main()
