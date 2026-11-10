# 🛡️ SecureVault LAN — Hybrid Cryptographic Transport & Visual Protocol Suite

> **Subject:** Network Security (5th Semester OEL / Lab Project)  
> **Platform:** Windows Native (Python 3.11) • Zero Simulation • 100% Real TCP Sockets  
> **UI Aesthetic:** Cyber-Green Liquidmorphism (Hyper-Fluid v3.0) + Native Desktop GUI (.exe)

---

## 📌 1. Project Overview & Problem Statement

In local area networks (LANs), standard communication and file transfers (like unencrypted FTP, HTTP, or raw TCP sockets) transmit data in cleartext. Any adversary on the same Wi-Fi or subnet running packet sniffers like **Wireshark** can capture sensitive conversations and steal confidential files.

**SecureVault LAN** solves this problem by creating an authenticated, end-to-end encrypted transport channel directly between two Windows PCs over Wi-Fi or Ethernet. It combines **Asymmetric Cryptography (RSA-2048)** for secure key negotiation, **Symmetric Authenticated Cryptography (AES-256-GCM)** for ultra-fast payload encryption, and **Cryptographic Hash Functions (SHA-256)** for tamper-proof file integrity verification.

---

## 🔒 2. Cryptographic Architecture

SecureVault implements an industry-standard **Hybrid Cryptosystem** (similar to TLS/HTTPS and SSH):

```
+-----------------------------------------------------------------------------------------+
|                                HYBRID CRYPTOGRAPHIC HANDSHAKE                          |
|                                                                                         |
|      CLIENT NODE                                                      SERVER NODE       |
|           |                                                                |            |
|           |   1. TCP 3-Way Handshake Connection (SYN -> SYN-ACK -> ACK)   |            |
|           |<==============================================================>|            |
|           |                                                                |            |
|           |   2. Server RSA-2048 Public Key (Plaintext Frame)              |            |
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
|           |   5. AES-256-GCM Encrypted Messages & 32KB File Chunks         |            |
|           |<==============================================================>|            |
|           |   (Each packet guarded with 12-byte Nonce + 128-bit Auth Tag)  |            |
|           |                                                                |            |
|           |   6. SHA-256 File End-to-End Integrity Verification Checksum   |            |
|           |<==============================================================>|            |
+-----------------------------------------------------------------------------------------+
```

### Protocol Specifications:
1. **Key Exchange:** RSA-2048 using **OAEP (Optimal Asymmetric Encryption Padding)** with SHA-256 and MGF1.
2. **Data Cipher:** **AES-256-GCM (Galois/Counter Mode)** — provides both Confidentiality and Authenticity (AEAD). Each packet has a unique 12-byte cryptographically secure nonce and a 16-byte (128-bit) authentication tag.
3. **Tamper Detection:** If even a single bit in ciphertext or auth tag is modified in transit (MITM attack), AES-GCM immediately throws an `InvalidTag` exception and the packet is dropped.
4. **File Integrity:** Full **SHA-256 cryptographic digest** computed prior to transmission and re-verified post-reconstruction.
5. **Custom Binary Framing:** Compact 9-byte header (`SV` Magic, Security Mode, Frame Type, Nonce Length, Payload Length).

---

## 🎨 3. Visual & HCI Experience (Liquidmorphism v3.0)

1. **Interactive Liquid Glass Refraction:** As you move the mouse across the panels, a soft liquid neon refraction orb illuminates the frosted glass from behind.
2. **Living 60FPS Energy Pipeline Canvas:** Dual undulating electromagnetic sine waves (Neon Green & Electric Cyan) flow along the cable with pulsing radar node auras.
3. **Cyber Equalizer Spectrum:** Real-time animated frequency scanner bars in the telemetry HUD.
4. **Rotating Reactor Shield Logo:** Dynamic 360-degree rotating light beam behind the header shield badge.
5. **Cryptographic Glitch Decryption:** Negotiated session key fingerprints scramble random hex characters (`8F 2A E1 99...`) before locking in.
6. **Liquid Wave File Progress:** Dynamic animated fluid wave progress fill for confidential file streaming.
7. **Live Security Audit Terminal:** Color-coded badges for real-time packet telemetry (`[TX]`, `[RX]`, `[CRYPTO]`, `[ALERT]`).

---

## 🦈 4. Wireshark Live Viva Demonstration

The top right of the HUD includes a **Live Wireshark Hero Toggle Switch**:

* **SECURE MODE (Default):**
  - All chat and file frames are encrypted with AES-256-GCM.
  - In Wireshark (Filter: `tcp.port == 5500`), data payload appears as pure high-entropy pseudorandom ciphertext bytes (e.g. `9f a4 c1 3b...`).
* **PLAINTEXT DEMO MODE (For Teacher Viva):**
  - Switch the toggle to Plaintext.
  - Send a message (e.g. `"CONFIDENTIAL EXAM PAPER"`).
  - Inspect the TCP stream in Wireshark ➔ The cleartext ASCII characters are 100% visible in the packet stream, demonstrating what an attacker sees without cryptography!

---

## 🚀 5. How to Run

### Mode 1: Cyber-Liquid Master App (Recommended for Viva)
* Single Instance: Double-click [`run_app.bat`](run_app.bat)
* Dual Instance Test (Local Client + Server): Double-click [`run_two_instances_test.bat`](run_two_instances_test.bat)

### Mode 2: Compiled Standalone Windows Executable (.exe)
* Standalone Executable: `dist\SecureVault_LAN\SecureVault_LAN.exe`
* Dual Desktop Test: Double-click [`run_two_desktop_instances.bat`](run_two_desktop_instances.bat)

### Mode 3: Automated Test Suite (100% Pass)
* Double-click [`run_tests.bat`](run_tests.bat) to execute unit and E2E cryptographic verification.

---

## 🎓 6. Academic Viva Defense Cheat Sheet

| Question | Answer |
|:---|:---|
| **Why Hybrid Cryptography?** | RSA is computationally expensive for large data; AES is fast but requires pre-shared keys. Hybrid uses RSA once to securely share an ephemeral AES session key, then AES encrypts all high-speed traffic. |
| **Why AES-GCM over AES-CBC?** | CBC only provides confidentiality and is vulnerable to padding oracle attacks. GCM provides Authenticated Encryption (AEAD) with hardware acceleration and built-in tamper detection via GMAC auth tags. |
| **Why OAEP padding for RSA?** | PKCS#1 v1.5 padding is vulnerable to Bleichenbacher chosen-ciphertext attacks. OAEP adds randomness and hashing, making RSA semantically secure against adaptive chosen-ciphertext attacks (IND-CCA2). |
| **How does Wireshark demo prove security?** | Toggling to Plaintext shows readable text in Wireshark TCP stream; toggling to Secure shows high-entropy ciphertext that cannot be decrypted without the ephemeral session key. |
