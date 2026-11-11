# SecureVault LAN v2.0 — Architecture & Feature Implementation Specification

---

## 1. Executive Summary & Problem Analysis

SecureVault LAN is being upgraded from a point-to-point single-file encrypted tunnel to a **Multi-Peer Zero-Config LAN Security Suite (AirShare / LocalSend style)** with **Integrated Malware Threat Inspection** and **Interactive Presentation Toggles** for live classroom/lab demonstrations.

---

## 2. Deep-Dive: Lab Bug Analysis (3GB -> 6GB File Overrun & Progress > 100%)

### 2.1 The Observed Anomaly
- **Test Scenario:** Sending a large file (~3GB) across LAN between two physical lab computers.
- **Symptom:** Progress exceeded 100% (105%, 120%, continuing upwards), and the received file on disk grew to ~6GB (double the source size).

### 2.2 Root Cause Diagnosis

1. **Pre-computation Freeze (Missing Streaming Hash):**
   - The sender executed `CryptoEngine.compute_file_sha256()` across the entire 3GB file synchronously **before** sending a single packet. On standard SATA/LAN disks, hashing 3GB takes 25–40 seconds.
   - During this silent time, the UI appeared inactive, prompting the user to drop/click again.
2. **Missing Transfer Concurrency Lock:**
   - `LanNode.send_file()` had no `is_transferring` state guard. Consecutive calls spawned multiple concurrent `_worker` threads that competed for `_send_lock`.
3. **No Transfer Session ID / Chunk Sequence Number:**
   - Protocol frames lacked a unique `transfer_id`. If two transfers fired, the receiver wrote chunks from both threads into the same file descriptor.
4. **Unbounded Receiver Write Loop:**
   - `lan_node.py` did not check `if self._incoming_bytes_received + len(chunk) > expected_filesize`. It blindly appended every received chunk to disk.
5. **Uncapped Progress Math:**
   - `pct = round((cur / total) * 100, 1)` lacked a clamp `min(100.0, pct)`.

### 2.3 Permanent Architectural Fixes
- **Rolling Incremental Hash:** Compute SHA-256 on the fly (`hasher.update(chunk)`) as chunks are read and transmitted. Zero pre-computation delay.
- **Atomic Concurrency Guard:** `self.is_sending_active` boolean flag blocks any secondary send attempts until the current transfer finishes or aborts.
- **Transfer Session UUID:** Include a 16-byte `transfer_id` and 32-bit chunk index in the protocol frame. Mismatched or duplicate transfer IDs are instantly dropped.
- **Strict Size Clamping & Overflow Guard:** If incoming bytes exceed `meta["filesize"]`, writing halts immediately, and an `ANOMALY_OVERFLOW_DETECTED` security alert is raised.
- **UI Progress Clamp:** UI clamps progress between 0% and 100%.

---

## 3. High-Priority Feature Specifications

### Feature A: Zero-Config LAN Peer Discovery (AirShare / LocalSend Architecture)
*Problem:* In a university lab with 50 to 300 PCs, manually finding and typing IP addresses (`192.168.1.X`) is tedious and prone to errors.

*Solution: UDP Broadcast & Multicast Beacon Service (`backend/lan_discovery.py`)*
- Runs an asynchronous UDP beacon listener on port `5555`.
- Broadcasts a lightweight JSON beacon every 3 seconds:
  ```json
  {
    "service": "SecureVault",
    "version": "2.0",
    "node_id": "SV-A48F",
    "hostname": "LAB-PC-42",
    "os": "Windows 11",
    "ip": "192.168.1.42",
    "tcp_port": 5500,
    "status": "READY"
  }
  ```
- Any machine on the subnet running SecureVault automatically displays a live **"Discovered Lab Peers" Radar Grid**.
- **1-Click Connect:** Clicking any discovered peer initiates the RSA-2048 handshake instantly.

---

### Feature B: Multi-File Vault & Selective Download
*Problem:* Currently, transfers are restricted to one file at a time, and the receiver has no choice in what they receive.

*Solution: Room Manifest & Selective Transfer Protocol*
1. **Multi-File Staging:** Sender drops 1 to 50 files into the Vault.
2. **Catalog Manifest Transmission:** Sender transmits a `VAULT_MANIFEST` frame containing:
   ```json
   {
     "vault_id": "vlt_9281a",
     "items": [
       {"id": 1, "filename": "Network_Security_Report.pdf", "size": 14201888, "sha256": "e3b0c4..."},
       {"id": 2, "filename": "Wireshark_Capture.pcapng", "size": 52428800, "sha256": "4b2277..."},
       {"id": 3, "filename": "SourceCode.zip", "size": 1048576, "sha256": "a1b2c3..."}
     ]
   }
   ```
3. **Selective Downloader UI:** The receiver views the manifest table with checkboxes:
   - Option to select specific files (e.g. only File 1 and File 3).
   - "Download Selected" or "Download All" buttons.
   - Pull-based transmission: Receiver sends `REQ_FILE_PULL` with requested item IDs; Sender streams only the selected items.

---

### Feature C: Antivirus & Malicious Payload Detection Engine
*Teacher's Inquiry:* *"Agar koi virus/malware daal ke bhej raha hai to kya detection hogi?"*

*Solution: Multi-Tiered Threat Inspection Core (`backend/threat_scanner.py`)*

1. **Tier 1 — Known Malware Signatures:**
   - **EICAR Test Signature:** Built-in detection for standard EICAR test string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) for live, 100% safe lab presentation testing.
   - **Known Hash Denylist:** MD5/SHA-256 blacklist matching known ransomware / trojan hashes.

2. **Tier 2 — Heuristic Extension & Double-Extension Analysis:**
   - Detects dangerous executable files: `.exe`, `.bat`, `.ps1`, `.vbs`, `.scr`, `.cmd`, `.msi`, `.dll`.
   - Flags deceptive double extensions (e.g., `Final_Exam_Dates.pdf.exe`, `Assignment.docx.vbs`).

3. **Tier 3 — Header Magic Bytes & Polyglot Disguise Inspection:**
   - Inspects the true file header bytes. If a file claims to be `photo.jpg` or `notes.txt` but starts with `4D 5A` (`MZ` header for DOS/Windows PE executable), the file is flagged as an **Impersonation/Disguise Attack**.

4. **Tier 4 — Native Windows AMSI (Antimalware Scan Interface):**
   - Direct memory scan using Windows Defender's native `amsi.dll` (`AmsiScanBuffer`). The payload is scanned in memory before ever being saved to disk!

5. **Tier 5 — Isolated Quarantine Storage:**
   - Flagged files are denied access to `received_files/`.
   - Automatically redirected to `quarantine/` with a `.locked` extension and a threat report JSON.

---

### Feature D: Interactive Security Demo Toggles (For Viva & Lab Presentations)
To demonstrate both **Secured State** and **Compromised/Vulnerable State** to lab evaluators, SecureVault will feature four real-time toggle switches in the Cyber-Green UI:

| Toggle Switch | Mode ON (Secure Defense) | Mode OFF (Lab Demo / Compromised) |
|---|---|---|
| **1. AES-256-GCM Engine** | Full cipher encryption (Hex ciphertext in Wireshark) | Cleartext Plaintext mode (Wireshark reads passwords/messages) |
| **2. Integrity Guard** | SHA-256 hash verified; corrupted packets instantly dropped | Tamper-Injection mode: Injects deliberate 1-bit flip to show checksum failure |
| **3. Anti-Malware Shield** | Threat engine blocks EICAR, malicious scripts, and quarantines files | Bypass mode: Malicious file is permitted without scanning to show the risk |
| **4. DoS / Flow Limiter** | Rate-limited chunk streaming with buffer backpressure | Uncapped flood mode: Demonstrates socket congestion and buffer overflow |

---

## 4. Phased Implementation Roadmap

- **Phase 1: Bug Eradication (Immediate Priority)**
  - Implement streaming on-the-fly SHA-256.
  - Add `is_transferring` atomic lock to `lan_node.py`.
  - Add ceiling clamp on `_incoming_bytes_received` and reject overflow chunks.
  - Add unit test simulating rapid duplicate triggers and large transfers.

- **Phase 2: Threat Scanner & Antivirus Layer**
  - Create `backend/threat_scanner.py` with EICAR, file extension rules, magic byte verification, and optional AMSI.
  - Add quarantine directory management.

- **Phase 3: LAN Auto-Discovery Engine**
  - Create `backend/lan_discovery.py` using UDP broadcast.
  - Wire discovery events to WebSocket bridge and frontend radar list.

- **Phase 4: Multi-File Vault & Selective Pull**
  - Update `protocol.py` with `VAULT_MANIFEST` and `FILE_PULL_REQ` frames.
  - Implement multi-file staging and selective download logic.

- **Phase 5: UI Liquidmorphism Upgrades & Presentation Toggles**
  - Add Security Demo Toggles deck.
  - Add Peer Radar panel.
  - Add Multi-File Staging and Download manager.

- **Phase 6: Testing & Production Compilation**
  - Run full test suite with 100% pass rate.
  - Compile standalone Windows `.exe` bundle and create distribution package.
