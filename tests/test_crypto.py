"""
Unit & Security Tests for SecureVault LAN Crypto Engine & Protocol
"""

import unittest
import os
import tempfile
from cryptography.exceptions import InvalidTag
from backend.crypto_engine import CryptoEngine
from backend.protocol import ProtocolFrame, FrameType, SecurityMode


class TestCryptoEngine(unittest.TestCase):
    def setUp(self):
        self.server_crypto = CryptoEngine()
        self.client_crypto = CryptoEngine()

    def test_rsa_handshake_and_key_exchange(self):
        # 1. Server generates RSA-2048 keypair
        pub_pem, priv_pem = self.server_crypto.generate_rsa_keypair()
        self.assertIn(b"BEGIN PUBLIC KEY", pub_pem)
        self.assertIn(b"BEGIN PRIVATE KEY", priv_pem)

        # 2. Client loads server's public key
        server_pub = CryptoEngine.load_public_key_from_pem(pub_pem)

        # 3. Client generates 256-bit AES session key and encrypts with Server's RSA Pubkey
        client_aes_key = CryptoEngine.generate_aes_key()
        self.assertEqual(len(client_aes_key), 32)
        encrypted_session_key = CryptoEngine.rsa_encrypt_session_key(server_pub, client_aes_key)

        # 4. Server decrypts session key with its RSA Private key
        decrypted_session_key = self.server_crypto.rsa_decrypt_session_key(encrypted_session_key)

        # 5. Assert keys match
        self.assertEqual(client_aes_key, decrypted_session_key)
        self.assertEqual(self.server_crypto.session_key, client_aes_key)

    def test_aes_gcm_encrypt_decrypt(self):
        aes_key = CryptoEngine.generate_aes_key()
        self.server_crypto.set_session_key(aes_key)
        self.client_crypto.set_session_key(aes_key)

        secret_message = b"Confidential Network Security Lab Data: $1,000,000 Transfer Approved."
        nonce, ciphertext_and_tag = self.client_crypto.encrypt_aes_gcm(secret_message)

        # Ensure ciphertext is not plaintext
        self.assertNotEqual(secret_message, ciphertext_and_tag)
        self.assertEqual(len(nonce), 12)

        # Server decrypts
        decrypted = self.server_crypto.decrypt_aes_gcm(nonce, ciphertext_and_tag)
        self.assertEqual(secret_message, decrypted)

    def test_tamper_detection_integrity(self):
        """Simulate a Man-in-the-Middle (MITM) hacker flipping 1 bit in transit."""
        aes_key = CryptoEngine.generate_aes_key()
        self.server_crypto.set_session_key(aes_key)
        self.client_crypto.set_session_key(aes_key)

        secret_message = b"Transfer 100 USD to Alice"
        nonce, ciphertext_and_tag = self.client_crypto.encrypt_aes_gcm(secret_message)

        # MITM flipper
        tampered_bytes = bytearray(ciphertext_and_tag)
        tampered_bytes[5] ^= 0xFF  # Flip bits in ciphertext
        tampered_data = bytes(tampered_bytes)

        # Attempt to decrypt must raise InvalidTag
        with self.assertRaises(InvalidTag):
            self.server_crypto.decrypt_aes_gcm(nonce, tampered_data)

    def test_sha256_file_integrity(self):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Security test file content for integrity check verification.")
            temp_path = tf.name

        try:
            expected_hash = CryptoEngine.compute_sha256(b"Security test file content for integrity check verification.")
            file_hash = CryptoEngine.compute_file_sha256(temp_path)
            self.assertEqual(expected_hash, file_hash)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_protocol_frame_pack_unpack(self):
        frame = ProtocolFrame(
            frame_type=FrameType.MSG_TEXT,
            mode=SecurityMode.ENCRYPTED,
            nonce=b"123456789012",
            payload=b"EncryptedPayloadBytesHere"
        )
        packed = frame.pack()
        self.assertTrue(packed.startswith(b"SV"))

        # Test unpacking using mock socket-like stream
        import io
        stream = io.BytesIO(packed)
        unpacked_frame = ProtocolFrame.read_from_socket(stream)
        self.assertIsNotNone(unpacked_frame)
        self.assertEqual(unpacked_frame.frame_type, FrameType.MSG_TEXT)
        self.assertEqual(unpacked_frame.mode, SecurityMode.ENCRYPTED)
        self.assertEqual(unpacked_frame.nonce, b"123456789012")
        self.assertEqual(unpacked_frame.payload, b"EncryptedPayloadBytesHere")


if __name__ == "__main__":
    unittest.main()
