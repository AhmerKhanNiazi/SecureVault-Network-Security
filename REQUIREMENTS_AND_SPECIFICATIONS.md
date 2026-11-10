# SecureVault LAN: Encrypted File & Message Transfer System
## Software Requirements Specification (SRS)

### 1. Project Overview
SecureVault LAN is a native Windows peer-to-peer/client-server secure communication and file transfer suite developed for Network Security Lab. It operates natively over standard Windows TCP/IP networking (Ethernet / Wi-Fi) with zero simulation and zero Linux/VM dependencies.

### 2. Functional Requirements (FR)
- **FR-1 [Hybrid Cryptographic Engine]**:
  - RSA-2048 Asymmetric Key Pair generation for initial handshake and secure AES Session Key distribution.
  - AES-256-GCM Symmetric Authenticated Encryption for all in-transit payload data (messages & chunked files).
  - SHA-256 Checksum generation and verification for End-to-End File Integrity checks.
- **FR-2 [Wireshark Demonstration Mode (Security Toggle)]**:
  - A real-time toggle between **🔐 SECURE MODE** (AES-256 ciphertext) and **⚠️ PLAINTEXT MODE** (cleartext).
  - Enables instant side-by-side verification under Wireshark packet capture ("Follow TCP Stream").
- **FR-3 [LAN Networking & Socket Layer]**:
  - Native Python TCP sockets binding to local IP (e.g. `192.168.x.x` or `0.0.0.0`).
  - Supports multiple clients or dedicated Peer-to-Peer / Client-Server models.
  - Chunked streaming for large files without memory exhaustion.
- **FR-4 [Live Security Audit & Crypto Telemetry]**:
  - Real-time logging of cryptographic handshake steps, IV/Nonce values, cipher hex streams, and integrity check results.
- **FR-5 [Automated Self-Test & Diagnostic Suite]**:
  - Built-in test script to simulate crypto operations, handshake, packet tampering detection, and file transfers headlessly.

### 3. Non-Functional & HCI Requirements (NFR)
- **NFR-1 [Cyberpunk Black & Neon Green Aesthetics]**: Obsidian black canvas (`#080b09`), cyber-green accents (`#00ff88`), and emerald borders (`#00aa55`).
- **NFR-2 [Liquidmorphism & Glassmorphism]**: Translucent blurred cards, glowing borders, smooth hover animations, and liquid fill gauges.
- **NFR-3 [Live Data Traveling Animation]**: Dynamic canvas showing animated neon packet pulses traveling across a fiber pipeline between nodes.
- **NFR-4 [HCI Compliance]**:
  - Visibility of system status (latency, live connection badge, transfer progress).
  - Error prevention (validation on IP/Port, tamper detection alert).
  - Minimalist, distraction-free aesthetic with high-contrast typography.
- **NFR-5 [Platform]**: 100% Windows 10/11 native (Python 3.11).
