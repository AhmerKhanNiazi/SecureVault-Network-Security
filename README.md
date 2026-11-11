# 🛡️ SecureVault LAN v3.0 Enterprise — Hybrid Cryptographic Transport & AirShare Security Suite

> **Course:** Network Security (5th Semester Final Project / Open-Ended Lab)  
> **Platform:** Windows Native (Python 3.11) • 100% Real Sockets (Zero Simulation)  
> **Aesthetic:** Hyper-Fluid Obsidian Cyber-Liquidmorphism (6 Dedicated Tabs)  
> **Repository:** [AhmerKhanNiazi/SecureVault-Network-Security](https://github.com/AhmerKhanNiazi/SecureVault-Network-Security)

---

## 📌 1. Project Overview & Problem Statement

In standard Local Area Networks (LANs), everyday communication protocols (like HTTP, FTP, or raw TCP sockets) transmit traffic in plaintext. Any passive adversary running packet sniffers like **Wireshark** on the same Wi-Fi or Ethernet switch can intercept confidential files, read credentials, or execute Man-in-the-Middle (MITM) tampering.

**SecureVault LAN v3.0** is an enterprise-grade cryptographic workstation that solves this problem. It establishes a hardware-accelerated, authenticated, end-to-end encrypted transport channel directly between Windows machines. It combines:
* **Asymmetric Cryptography (RSA-2048)** with OAEP-SHA256 padding for initial key negotiation.
* **Symmetric Authenticated Cryptography (AES-256-GCM)** for streaming payload encryption.
* **Rolling Cryptographic Hash (SHA-256)** computed chunk-by-chunk on-the-fly for tamper-proof data verification.
* **Zero-Config LAN Peer Mesh (AirShare on UDP 5555)** for zero-setup automatic peer discovery.
* **Multi-Tier Malware Shield** integrating Windows AMSI, EICAR pattern detection, executable blocklists, and an isolated Quarantine Vault.

---

## 🔒 2. Cryptographic Architecture

SecureVault implements an industry-standard **Hybrid Cryptosystem** (analogous to modern TLS 1.3 and SSHv2):

```
+-----------------------------------------------------------------------------------------+
|                                HYBRID CRYPTOGRAPHIC HANDSHAKE                          |
|                                                                                         |
|      CLIENT NODE                                                      SERVER NODE       |
|           |                                                                |            |
|           |   1. TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK)              |            |
|           |<==============================================================>|            |
|           |                                                                |            |
|           |   2. Server RSA-2048 Ephemeral Public Key (PEM Frame)          |            |
|           |<---------------------------------------------------------------|            |
|           |                                                                |            |
|    [Generates fresh]                                                       |            |
|    [32-byte AES key]                                                       |            |
|    [Encrypts w/ RSA]                                                       |            |
|           |                                                                |            |
|           |   3. RSA-Encrypted AES-256 Session Key (OAEP-SHA256)          |            |
|           |--------------------------------------------------------------->|            |
|           |                                                      [Decrypts AES key w/]  |
|           |                                                      [RSA Private Key]      |
|           |                                                                |            |
|           |   4. Handshake ACK (Encrypted Confirmation Frame)              |            |
|           |<---------------------------------------------------------------|            |
|           |                                                                |            |
|  ========= SECURE CHANNEL ESTABLISHED (SESSION KEYS MATCH 100%) ======================  |
|           |                                                                |            |
|           |   5. AES-256-GCM Encrypted Messages & 32KB Stream Chunks       |            |
|           |<==============================================================>|            |
|           |   (Each packet guarded with 12-byte Nonce + 16-byte Auth Tag)  |            |
|           |                                                                |            |
|           |   6. Rolling SHA-256 Checksum Verified Post-Reconstruction     |            |
|           |<==============================================================>|            |
+-----------------------------------------------------------------------------------------+
```

### Cryptographic Standards:
1. **Asymmetric Key Exchange:** RSA-2048 using **OAEP (Optimal Asymmetric Encryption Padding)** with SHA-256 and MGF1 (immune to Bleichenbacher padding oracle attacks).
2. **Symmetric Stream Cipher:** **AES-256-GCM (Galois/Counter Mode)** — Authenticated Encryption with Associated Data (AEAD). Guarantees both Confidentiality and Authenticity.
3. **Data Integrity:** **Rolling SHA-256 Stream Hash** — updated dynamically chunk-by-chunk during transmission. Zero pre-hashing latency, even on 10GB+ video files.
4. **Replay Protection:** 12-byte unique cryptographic Nonce regenerated for every transmitted packet.
5. **Custom Binary Framing:** Compact 9-byte header (`SV` Magic, Security Mode, Frame Type, Nonce Length, Payload Length).

---

## 🗂️ 3. Enterprise 6-Tab Multi-Page Architecture

SecureVault LAN v3.0 features a modern liquidmorphic cyber interface structured across 6 dedicated tabs:

1. **📡 Radar & Devices (AirShare Mesh):**
   * Automatic UDP 5555 broadcast beacon discovering all online PCs on the subnet.
   * Responsive device mesh cards with hostname, IP, port, latency ring, and 1-click connect.
   * Server host controller with dynamic port collision avoidance.

2. **📦 Transfer Hub & Interactive Consent:**
   * **Drag & Drop Dropzone:** Native Windows file picker integration (100% bypasses browser `C:\fakepath` restrictions).
   * **Interactive Transfer Consent:** Prompts receiver with an illuminated banner: `[ Accept ]`, `[ Save As... ]`, or `[ Decline ]`.
   * **Active Wave Progress Vessel:** Displays real-time streaming speed (MB/s), ETA, and clamped % progress.
   * **Downloaded Files Manager:** Shows received files with direct `[ Open File ]`, `[ Show in Folder ]`, and `[ Save As ]` actions.

3. **💬 Secure Messenger:**
   * End-to-end encrypted chat timeline with timestamps and security badges.
   * Instant toggle between encrypted ciphertext and Wireshark cleartext mode.

4. **🛡️ Malware Shield & Security Center:**
   * Integrated Windows AMSI buffer inspection.
   * Signature detection intercepting EICAR antivirus test patterns.
   * Extension deception traps blocking double extensions (e.g. `invoice.pdf.exe`) and dangerous scripts (`.bat`, `.ps1`, `.vbs`).
   * MZ header inspection detecting Windows PE executables disguised as image/video extensions.
   * Isolated Quarantine Vault table with one-click folder exploration.

5. **📊 Protocol & Packet Inspector:**
   * Real-time Wireshark-grade frame dissector.
   * Categorical filtering (`ALL`, `HANDSHAKE`, `TEXT`, `FILES`, `ALERTS`) with live hex dump previews.

6. **⚙️ System Settings:**
   * Configurable download directories with native Windows folder browsing.
   * Transfer consent prompts toggle (Prompt Every Time vs Auto-Accept).

---

## 🚀 4. How to Run

### Option 1: Native Desktop Launcher (Recommended)
```powershell
# In project directory:
run_app.bat
```
* Automatically finds an open port (defaulting to 8082 to avoid background server conflicts), starts the backend, and opens the native standalone window.

### Option 2: Automated Dual Instance Test (Single PC)
```powershell
run_two_instances_test.bat
```
* Automatically spawns Server (Port 5500, UI: 8082) and Client (connecting to 127.0.0.1:5500, UI: 8083) in side-by-side native windows for instant local testing.

### Option 3: Pre-Compiled Standalone Windows Executable (.exe)
* Extract `SecureVault_LAN_v3.0_Windows_x64.zip` and run `SecureVault_LAN.exe`.
* To recompile from source, run:
```powershell
build_exe.bat
```

---

## 🧪 5. Automated Verification Suite

Run all 17 automated unit and integration tests:
```powershell
run_tests.bat
```

```text
test_dynamic_download_dir_and_incoming_callback ... ok
test_aes_gcm_encrypt_decrypt .................... ok
test_protocol_frame_pack_unpack ................ ok
test_rsa_handshake_and_key_exchange ............ ok
test_sha256_file_integrity ..................... ok
test_tamper_detection_integrity ................ ok
test_full_e2e_secure_handshake_and_transfer .... ok
test_lan_discovery_broadcast_and_receipt ....... ok
test_multi_file_manifest_and_selective_pull .... ok
test_tamper_injection_demo_toggle .............. ok
test_transfer_concurrency_lock ................. ok
test_bypass_demo_toggle ........................ ok
test_clean_file_passes ......................... ok
test_dangerous_extension_blocking .............. ok
test_double_extension_deception_trap ........... ok
test_eicar_signature_detection_and_quarantine .. ok
test_header_pe_disguise_detection .............. ok

Ran 17 tests in 3.822s — OK (100% Success Rate)
```

---

## 🎓 6. Academic Viva Defense Cheat Sheet

| Question | Core Defense Answer |
| :--- | :--- |
| **Why Hybrid Cryptography?** | RSA is mathematically heavy for bulk streaming; AES is fast but requires a shared secret. Hybrid cryptography uses RSA-2048 once during the handshake to exchange an ephemeral AES-256 key, then AES streams bulk data at wire speed. |
| **Why AES-GCM over AES-CBC?** | CBC only provides confidentiality and is susceptible to padding oracle attacks. GCM provides Authenticated Encryption (AEAD) with hardware Galois field acceleration and tamper resistance via 128-bit GMAC tags. |
| **Why OAEP padding for RSA?** | PKCS#1 v1.5 padding is vulnerable to Bleichenbacher chosen-ciphertext attacks. OAEP integrates dual random hashing (SHA-256 + MGF1), proving semantically secure against IND-CCA2 adversaries. |
| **How does Wireshark demo prove security?** | Toggling to Plaintext shows readable text in Wireshark TCP streams; toggling to Secure shows high-entropy ciphertext that cannot be decrypted without the ephemeral session key. |
| **How is MITM Tampering Detected?** | Flipping even 1 bit of ciphertext in transit causes AES-GCM tag authentication to fail, triggering an immediate drop and integrity alarm. |
