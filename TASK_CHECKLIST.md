# SecureVault LAN Implementation Task Checklist

- [x] **Phase 1: Architecture & Requirements Formulation**
  - [x] Create project folder `SecureVault_LAN_Crypto`
  - [x] Formulate Software Requirements Specification (`REQUIREMENTS_AND_SPECIFICATIONS.md`)
  - [x] Formulate System Architecture & Framing Protocol (`SYSTEM_ARCHITECTURE.md`)
  - [x] Confirm specific UI framework & operational preferences with user

- [x] **Phase 2: Core Cryptographic & Protocol Engine**
  - [x] Implement `crypto_engine.py` (RSA-2048 keypair, RSA-OAEP encrypt/decrypt, AES-256-GCM cipher/decipher, SHA-256 integrity hash)
  - [x] Implement `framing_protocol.py` (Binary frame packing, unpacking, framing validation, tamper verification)
  - [x] Unit tests for crypto engine & framing (`test_crypto.py`)

- [x] **Phase 3: Network Socket Server & Client Implementation**
  - [x] Implement `lan_node.py` (Multi-threaded TCP Server & Client, non-blocking sockets, chunked file transfer handlers)
  - [x] Dual-mode support (Encrypted vs Plaintext for live Wireshark demonstration)
  - [x] Automated headless network integration test (`test_e2e_network.py`)

- [x] **Phase 4: Futuristic Liquidmorphism UI with Traveling Data Animations**
  - [x] Black & Cyber-Green palette (`#060907`, `#00ff88`, `#00aa55`)
  - [x] Liquidmorphism glass cards with neon glows & blur
  - [x] Real-time canvas animation showing glowing packets physically moving from sender node to receiver node
  - [x] Live security audit logger displaying raw hex cipher stream and SHA-256 integrity verification
  - [x] File dropzone with liquid wave progress bar

- [x] **Phase 5: Automated Testing & Verification**
  - [x] Automated end-to-end test script verifying file transfer, text chat, tamper detection, and key exchange
  - [x] Generate batch launch scripts (`run_app.bat`, `run_two_instances_test.bat`, `run_tests.bat`) for instant 1-click execution on Windows

- [x] **Phase 6: Lab Documentation, Viva Guide & Wireshark Demo Manual**
  - [x] Create `WIRESHARK_DEMO_GUIDE.md` (exact filter expressions and steps for teacher demonstration)
  - [x] Create `PROJECT_REPORT_AND_VIVA.md` (step-by-step viva questions, answers, and architecture explanations)
