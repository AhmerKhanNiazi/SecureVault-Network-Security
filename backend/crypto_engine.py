"""
SecureVault LAN - Cryptographic Engine
Implements:
1. RSA-2048 Asymmetric Key Generation, Serialization, and OAEP Encryption/Decryption
2. AES-256-GCM Authenticated Symmetric Encryption & Decryption (with Integrity Tag)
3. SHA-256 Cryptographic Hashing for End-to-End File Integrity Verification
"""

import os
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoEngine:
    def __init__(self):
        self.rsa_private_key: Optional[rsa.RSAPrivateKey] = None
        self.rsa_public_key: Optional[rsa.RSAPublicKey] = None
        self.session_key: Optional[bytes] = None  # 32 bytes (256-bit AES)

    # -------------------------------------------------------------
    # RSA Asymmetric Cryptography (Handshake & Key Exchange)
    # -------------------------------------------------------------
    def generate_rsa_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generates RSA-2048 Key Pair.
        Returns (public_pem_bytes, private_pem_bytes).
        """
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        pub_pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        priv_pem = self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pub_pem, priv_pem

    def get_public_pem(self) -> bytes:
        if not self.rsa_public_key:
            self.generate_rsa_keypair()
        return self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_public_key_from_pem(pem_bytes: bytes) -> rsa.RSAPublicKey:
        """Parses RSA Public Key from PEM bytes."""
        return serialization.load_pem_public_key(pem_bytes)

    @staticmethod
    def rsa_encrypt_session_key(public_key: rsa.RSAPublicKey, session_key: bytes) -> bytes:
        """
        Encrypts the 256-bit AES session key using the receiver's RSA Public Key.
        Uses OAEP padding with SHA-256 for secure key transport.
        """
        return public_key.encrypt(
            session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def rsa_decrypt_session_key(self, encrypted_session_key: bytes) -> bytes:
        """
        Decrypts the incoming AES session key using the local RSA Private Key.
        """
        if not self.rsa_private_key:
            raise ValueError("RSA Private key not initialized on this node.")
        
        self.session_key = self.rsa_private_key.decrypt(
            encrypted_session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return self.session_key

    # -------------------------------------------------------------
    # AES-256-GCM Symmetric Authenticated Cryptography
    # -------------------------------------------------------------
    @staticmethod
    def generate_aes_key() -> bytes:
        """Generates a secure cryptographically random 256-bit (32 bytes) AES Key."""
        return AESGCM.generate_key(bit_length=256)

    def set_session_key(self, key: bytes):
        if len(key) != 32:
            raise ValueError(f"AES key must be exactly 32 bytes (256 bits). Got {len(key)}")
        self.session_key = key

    def encrypt_aes_gcm(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext using AES-256 in Galois/Counter Mode (GCM).
        Returns:
            nonce: 12-byte unique Initialization Vector
            ciphertext_and_tag: Ciphertext with 16-byte GCM authentication tag appended
        """
        if not self.session_key:
            raise ValueError("Session key not established. Handshake required.")
        
        aesgcm = AESGCM(self.session_key)
        nonce = os.urandom(12)  # 96-bit standard GCM nonce
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext_and_tag

    def decrypt_aes_gcm(self, nonce: bytes, ciphertext_and_tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypts and authenticates AES-256-GCM ciphertext.
        Raises cryptography.exceptions.InvalidTag if tampered!
        """
        if not self.session_key:
            raise ValueError("Session key not established. Handshake required.")
        
        aesgcm = AESGCM(self.session_key)
        return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)

    # -------------------------------------------------------------
    # SHA-256 Data Integrity Hashing
    # -------------------------------------------------------------
    @staticmethod
    def compute_sha256(data: bytes) -> str:
        """Computes SHA-256 hex digest of in-memory bytes."""
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def compute_file_sha256(file_path: str) -> str:
        """Computes SHA-256 hex digest of a file on disk via 64KB chunk streaming."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
