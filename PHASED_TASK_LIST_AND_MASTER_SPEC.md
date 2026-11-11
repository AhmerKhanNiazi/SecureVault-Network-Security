# SecureVault LAN v2.0 — Phased Master Architecture & Granular Task Specification

---

## 1. Project Vision & Comprehensive System Overview

SecureVault LAN v2.0 evolves the project into a comprehensive **Zero-Config LAN Security & Hybrid Cryptographic Distribution Suite**. It combines:
1. **P2P Zero-Config Mesh (AirShare / LocalSend Architecture):** Auto-discovery across 50–300 PCs without manual IP entry.
2. **Robust Multi-File Selective Vault:** Pull-based file selection, folder chunking, and resume on disconnect.
3. **Advanced Threat Inspection Engine:** Multi-tiered file analysis (Magic bytes, EICAR, Heuristics, AMSI Windows Defender integration, and Quarantine).
4. **Interactive Lab Presentation Control Deck:** 5 Live switches enabling presenters to demonstrate both the **Compromised/Vulnerable State** and the **Defensive/Secured State** for teachers.

---

## 2. Comprehensive Phased Breakdown & Granular Task Lists

### Phase 1: Core Network Stabilization & Bug Eradication (P0 — Immediate)
*Goal: Fix large-file overruns (3GB -> 6GB), eliminate UI freezes, and establish bulletproof socket flow control.*

- [ ] **Task 1.1: Rolling On-The-Fly SHA-256 Hasher**
  - Remove synchronous pre-computation of full file hash before streaming.
  - Compute SHA-256 incrementally in `send_file()` via `hashlib.sha256().update(chunk)`.
  - Transmit the final verified checksum inside the `FILE_END` control frame.
- [ ] **Task 1.2: Atomic Transfer Concurrency Guard**
  - Implement `self._transfer_state` with thread-safe lock.
  - Reject duplicate send triggers (`TRANSFER_BUSY` error) while a transfer is underway.
  - Disable dropzone & send button in UI with glowing "Transfer in Progress" lock.
- [ ] **Task 1.3: Transfer Session UUID & Sequence Numbering**
  - Add `transfer_id` (UUID4 prefix) and `chunk_index` in `FILE_CHUNK` frames.
  - Discard any stray or duplicate chunks belonging to stale or mismatched transfers.
- [ ] **Task 1.4: Strict Receiver Boundary Clamping & Anomaly Trap**
  - Receiver checks: `if (bytes_received + len(chunk)) > expected_size`.
  - Abort transfer immediately and emit `ANOMALY_OVERFLOW_DETECTED` if unexpected bytes arrive.
- [ ] **Task 1.5: UI Progress Math Clamping & High-Precision Units**
  - Update `updateFileProgress` to clamp percentage strictly between `0%` and `100.0%`.
  - Add auto-scaling units: `B`, `KB`, `MB`, `GB` dynamically based on file size.
- [ ] **Task 1.6: Automated Regression Test for Large Chunk Simulation**
  - Write unit test in `tests/test_stream_guard.py` verifying duplicate send rejection and 100MB+ virtual chunk boundary enforcement.

---

### Phase 2: Threat Scanner & Malware Protection Core (Security P1)
*Goal: Address the teacher's requirement — detect malicious payloads, scripts, EICAR tests, and disguised executables before they touch the host OS.*

- [ ] **Task 2.1: Multi-Tier Threat Engine (`backend/threat_scanner.py`)**
  - Create standalone threat analysis module with 4 inspection layers.
- [ ] **Task 2.2: Signature & EICAR Pattern Detector**
  - Hardcode standard EICAR antivirus test signature:
    `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
  - Instant detection for live presentation demo without endangering system.
- [ ] **Task 2.3: Heuristic & Extension Deception Analyzer**
  - Block dangerous extensions: `.exe`, `.bat`, `.ps1`, `.vbs`, `.cmd`, `.scr`, `.msi`, `.dll`.
  - Detect double extension deception (e.g., `document.pdf.exe`, `notes.txt.vbs`).
- [ ] **Task 2.4: Magic Byte / Header MIME Disguise Verification**
  - Read first 512 bytes of payload.
  - Detect DOS/PE headers (`4D 5A` / `MZ`), ELF headers (`7F 45 4C 46`), or script headers masquerading as images/PDFs.
- [ ] **Task 2.5: Windows AMSI Direct Scan Integration (Optional Native Hook)**
  - Use `ctypes` to link `amsi.dll` (`AmsiInitialize`, `AmsiScanBuffer`).
  - Pass memory buffer to Windows Defender before writing to disk.
- [ ] **Task 2.6: Quarantine Vault Management**
  - Create isolated `quarantine/` folder.
  - Malicious files are sanitized, renamed to `<hash>.locked`, and logged with an audit JSON report.
  - UI emits high-priority audio-visual red alert: `[THREAT QUARANTINED]`.

---

### Phase 3: Zero-Config LAN Discovery Engine (AirShare Architecture)
*Goal: Eliminate manual IP entry across 50–300 PCs in a lab subnet.*

- [ ] **Task 3.1: UDP Broadcast / Multicast Beacon Service (`backend/lan_discovery.py`)**
  - Background daemon thread broadcasting UDP packets to `<broadcast>:5555` every 3 seconds.
  - Beacon schema: `{node_id, hostname, ip, tcp_port, status, fingerprint}`.
- [ ] **Task 3.2: Peer Table & Heartbeat TTL Manager**
  - Maintain thread-safe `active_peers` dictionary with 10-second expiration.
  - If a peer closes their app, remove them from the peer table automatically.
- [ ] **Task 3.3: WebSocket Integration & Discovery Events**
  - Bridge broadcasts `peer_discovered`, `peer_updated`, and `peer_lost` events to UI.
- [ ] **Task 3.4: Cyber Radar UI Grid**
  - Implement dynamic glowing radar grid in the frontend.
  - Discovered PCs appear as interactive cards with hostname, IP, and status.
  - Clicking any peer automatically triggers `connect_to_server(peer.ip, peer.port)`.

---

### Phase 4: Multi-File Vault & Selective Download Architecture
*Goal: Allow sharing bundles of files where receivers can browse and selectively download.*

- [ ] **Task 4.1: Vault Manifest Framing Protocol (`backend/protocol.py`)**
  - Define `FrameType.VAULT_MANIFEST` (0x23) and `FrameType.FILE_PULL_REQ` (0x24).
- [ ] **Task 4.2: Staged Multi-File Catalog**
  - Allow dropping multiple files into the Vault Dropzone.
  - Sender generates a catalog with File ID, Name, Size, and Expected SHA-256.
- [ ] **Task 4.3: Receiver Selective Download UI**
  - Receiver displays a sleek glassmorphic table listing all shared files with checkboxes.
  - "Download Selected" and "Download All" buttons.
- [ ] **Task 4.4: Pull-Based Chunk Streaming Queue**
  - Receiver requests specific file IDs; sender streams requested files sequentially with individual progress tracking.

---

### Phase 5: Interactive Lab Presentation Control Deck (5 Demo Toggles)
*Goal: Provide evaluators and teachers a live demonstration of vulnerabilities vs security defenses.*

- [ ] **Task 5.1: 5-Capsule Security Control Deck in UI**
  - Design illuminated switch deck in `frontend/index.html` and `frontend/style.css`.
- [ ] **Task 5.2: Toggle 1 — Encryption Guard (AES-256-GCM vs Cleartext)**
  - Toggle between encrypted cipher payload and plaintext Wireshark inspection.
- [ ] **Task 5.3: Toggle 2 — Integrity Guard & Tamper Injection**
  - **Secure Mode:** Verifies SHA-256 checksum; drops corrupted files.
  - **Demo Mode:** Deliberately flips 1 bit in transit to trigger and display `INTEGRITY VIOLATION DETECTED` live.
- [ ] **Task 5.4: Toggle 3 — Threat Scanner & Antivirus Shield**
  - **Secure Mode:** Threat scanner active; intercepts EICAR and dangerous scripts, saving to `quarantine/`.
  - **Bypass Mode:** Disables scanner to demonstrate risks of unfiltered socket transmission.
- [ ] **Task 5.5: Toggle 4 — Man-In-The-Middle (MITM) & Peer Fingerprint Pinning**
  - **Pinned Mode:** Verifies RSA public key fingerprint; warns if peer key changes unexpectedly.
  - **Promiscuous Mode:** Accepts any key without validation (demonstrates MITM susceptibility).
- [ ] **Task 5.6: Toggle 5 — Flow Control & Rate Limiting (DoS Defense)**
  - **Throttled Mode:** Regulated chunk flow with backpressure.
  - **Flood Mode:** Rapid unthrottled streaming to demonstrate buffer queuing.
- [ ] **Task 5.7: One-Click PCAP & Wireshark Filter Helper**
  - Button copying Wireshark display filter: `tcp.port == 5500 && frame contains "SV"`.

---

### Phase 6: System Verification, Documentation & Standalone Compilation
*Goal: 100% automated test coverage, complete project report, and standalone Windows `.exe` build.*

- [ ] **Task 6.1: Automated Test Suite Expansion**
  - Unit tests for Threat Scanner (EICAR detection, magic byte mismatch).
  - Integration tests for UDP Discovery beaconing.
  - End-to-end tests for Multi-file manifest and selective download.
- [ ] **Task 6.2: Standalone Windows `.exe` Build (`build_cyber_liquid_exe.bat`)**
  - Compile with PyInstaller 6.20+ with all modules, assets, and icons bundled.
  - Verify executable launch on clean system without Python.
- [ ] **Task 6.3: Distribution Package Creation**
  - Create release zip `SecureVault_LAN_v2.0_Windows_x64.zip`.
  - Update GitHub repository with tagged release `v2.0.0`.
- [ ] **Task 6.4: Lab Presentation & Viva Cheat Sheet**
  - Create step-by-step presentation script explaining each toggle to teachers.
