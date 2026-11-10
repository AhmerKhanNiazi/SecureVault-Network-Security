# 🛡️ SecureVault LAN — Standalone Windows Desktop App (.exe) & LAN Guide

> **Build Status:** ✅ Standalone Windows Executable Successfully Built!  
> **Executable Location:** `dist\SecureVault_LAN\SecureVault_LAN.exe`  
> **Framework:** CustomTkinter 5.2.2 (Pure Python Native GUI — Zero Browser Dependencies)

---

## 🌟 Key Highlights

1. **100% Native Desktop Software:**
   - No Edge, Chrome, or browser required.
   - No WebSockets, localhost servers, or port 8080 conflicts.
   - Zero C++ CRT runtime errors (`R6030` eliminated permanently).
2. **True Windows Executable (.exe):**
   - Compiled with PyInstaller 6.20.0.
   - Can be copied to a USB flash drive or sent over LAN to any other Windows PC.
3. **Pure LAN TCP Sockets & Hybrid Cryptography:**
   - **RSA-2048 (OAEP-SHA256)** for ephemeral session key negotiation.
   - **AES-256-GCM** with 128-bit authentication tags for authenticated payload encryption.
   - **SHA-256** integrity verification on all chunked file transfers.
   - **Wireshark Live Toggle:** Switch between Secure AES-GCM and Plaintext mode with one click.

---

## 🚀 How to Run on Single PC (Testing)

### Option A: Using the Compiled `.exe`
Open the folder:
`dist\SecureVault_LAN\`
Double-click:
`SecureVault_LAN.exe`

### Option B: Using Batch Script (Quick Launch)
Double-click:
[`run_desktop_app.bat`](file:///d:/IQRA%20UNI/5th%20Semester/Network%20Security%20Lab/Network%20Sec%20OEL/SecureVault_LAN_Crypto/run_desktop_app.bat)

### Option C: Dual Instance Test (Local Client + Server Simulation)
Double-click:
[`run_two_desktop_instances.bat`](file:///d:/IQRA%20UNI/5th%20Semester/Network%20Security%20Lab/Network%20Sec%20OEL/SecureVault_LAN_Crypto/run_two_desktop_instances.bat)
- Server window opens on Port 5500.
- Client window connects to `127.0.0.1:5500` automatically.
- Both reach `CONNECTED` state with matching cryptographic fingerprints!

---

## 🌐 How to Connect Two Different PCs over LAN / Wi-Fi

Follow these exact steps for your university lab or home LAN demo:

```
+---------------------------+                      +---------------------------+
|       PC 1 (SERVER)       |                      |       PC 2 (CLIENT)       |
|    IP: 192.168.1.115      |<====== Wi-Fi / =====>|     IP: 192.168.1.120     |
| Port: 5500 (Listening)    |       Ethernet       |  Connects to:             |
|                           |                      |  192.168.1.115 : 5500     |
+---------------------------+                      +---------------------------+
```

### Step 1: Copy to PC 2
Copy the folder:
`dist\SecureVault_LAN\`
onto a USB drive or share it over the network to **PC 2**.

### Step 2: Start Server on PC 1
1. On **PC 1**, double-click `SecureVault_LAN.exe`.
2. Notice your LAN IP displayed in the green box (e.g. `192.168.1.115`).
3. Leave role on **"HOST SERVER"**.
4. Port: `5500`.
5. Click **"INITIALIZE SECURE SERVER"**.
6. The status changes to yellow: **`LISTENING FOR PEER...`**.

### Step 3: Connect Client on PC 2
1. On **PC 2**, double-click `SecureVault_LAN.exe`.
2. Click the segmented tab: **"CONNECT CLIENT"**.
3. In **"REMOTE SERVER IP"**, type PC 1's IP address (e.g. `192.168.1.115`).
4. Port: `5500`.
5. Click **"CONNECT TO REMOTE PEER"**.

### Step 4: Verification & Live Demonstration
1. Within 1 second:
   - Both windows turn **NEON GREEN**: `CONNECTED: 192.168.1.x:5500`.
   - **Session Key Fingerprint** displays an identical 16-character SHA-256 hash on both screens.
2. **Encrypted Messaging:**
   - Type a secret message on PC 1 and click **SEND**.
   - It appears on PC 2 with `[🔐 AES-256-GCM]` badge and timestamp.
3. **Encrypted File Transfer:**
   - Click **"📁 BROWSE & SEND FILE SECURELY"** on either PC.
   - Watch the progress bar stream 32KB AES chunks.
   - When finished, the SHA-256 checksum is computed on both machines, confirming:
     `✓ SHA-256 CHECKSUM MATCH — INTEGRITY 100% VERIFIED`.
4. **Wireshark Live Viva Demonstration:**
   - Open Wireshark on PC 1 or PC 2, capture on the Wi-Fi/Ethernet adapter.
   - Filter: `tcp.port == 5500`.
   - Send a message in Secure mode ➔ Wireshark packet shows randomized ciphertext (`4a 8f 12 c9...`).
   - Toggle the switch at the top right to **"⚠️ PLAINTEXT (WIRESHARK DEMO)"**.
   - Send a message ➔ Wireshark packet shows readable ASCII plaintext!

---

## 🛠️ How to Rebuild the `.exe` at Any Time
If you ever modify any Python code, simply double-click:
[`build_exe.bat`](file:///d:/IQRA%20UNI/5th%20Semester/Network%20Security%20Lab/Network%20Sec%20OEL/SecureVault_LAN_Crypto/build_exe.bat)
It automatically re-compiles the entire project into `dist\SecureVault_LAN\SecureVault_LAN.exe`.
