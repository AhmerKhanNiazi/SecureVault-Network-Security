# SecureVault LAN: Wireshark Demonstration & Lab Guide

This guide gives you the exact step-by-step instructions to demonstrate **Encrypted vs. Unencrypted (Plaintext)** traffic in **Wireshark** to your professor during the lab evaluation.

---

## 1. Setup in Wireshark

1. **Launch Wireshark** on Windows.
2. **Select the Network Interface**:
   - If testing on **Localhost (Single PC)**: Select the **Adapter for loopback traffic capture** (or `Npcap Loopback Adapter`).
   - If testing over **LAN / Wi-Fi (Two Laptops)**: Select your active **Wi-Fi** or **Ethernet** network adapter.
3. In the Wireshark display filter bar at the top, type the filter and press Enter:
   ```wireshark
   tcp.port == 5500
   ```
4. Click the blue shark fin icon (**Start capturing packets**).

---

## 2. Test 1: Plaintext Mode (Demonstrating Vulnerability)

1. In the SecureVault LAN application, switch the top-right toggle to:
   **`⚠️ PLAINTEXT DEMO MODE`** (the status turns warning red).
2. In the Chat Input bar, type:
   ```text
   CONFIDENTIAL_PASSWORD=superSecret991; ACCOUNT_NO=0044918237
   ```
   and click **SEND**.
3. Go to **Wireshark**:
   - You will see TCP packets arriving.
   - Right-click any packet in the list with `[PSH, ACK]`.
   - Select **Follow** -> **TCP Stream**.
4. **What appears on screen (Cleartext Exposure)**:
   ```text
   SV...................CONFIDENTIAL_PASSWORD=superSecret991; ACCOUNT_NO=0044918237
   ```
5. **What to tell your Professor (Viva Defense Point)**:
   > *"Sir dekhein, jab insecure mode ON hota hai, LAN par baitha koi bhi attacker Wireshark ya ARP-poisoning ke zariye hamara password aur account details cleartext mein parh sakta hai. Isme na Confidentiality hai aur na Integrity."*

---

## 3. Test 2: Encrypted Mode (AES-256-GCM + RSA-2048)

1. In the SecureVault LAN application, switch the top-right toggle to:
   **`🔐 AES-256-GCM SECURE`** (the status turns vibrant neon green).
2. In the Chat Input bar, type the exact same sensitive data:
   ```text
   CONFIDENTIAL_PASSWORD=superSecret991; ACCOUNT_NO=0044918237
   ```
   and click **SEND**.
3. Or transfer a file by clicking the **Dropzone** (e.g. `secret_document.pdf`).
4. Go back to **Wireshark**:
   - Click the red stop button and start capture again, or filter the newest packets.
   - Right-click the newest packet and select **Follow** -> **TCP Stream**.
5. **What appears on screen (Pure Ciphertext & Authenticated Tag)**:
   ```text
   SV...................·$..Õ.¾.¿...eù.8¢...9..·.Úf.¢.Ì..¥.ü.£.
   [HEX STREAM: 4a f3 9b 12 d8 7e a1 09 c4 bb 10 32 f1 ...]
   ```
6. **What to tell your Professor (Viva Defense Point)**:
   > *"Sir ab dekhein, jab AES-256-GCM Secure Mode active hai, Wireshark packets toh capture kar raha hai lekin payload complete binary ciphertext ban chuka hai. Hacker ko data ka 1 byte bhi samajh nahi aa sakta kyunki Session Key RSA-2048 se encrypted share hui thi aur private key sirf server ki memory mein hai. Aur agar hacker 1 bit bhi badal de, toh AES-GCM ka authentication tag detect karke packet reject kar deta hai."*

---

## 4. Test 3: RSA-2048 Handshake Inspection

1. Start Wireshark before connecting.
2. When the Client connects to the Server, filter:
   ```wireshark
   tcp.port == 5500
   ```
3. Look at the very first packet after TCP 3-Way Handshake (`SYN`, `SYN-ACK`, `ACK`):
   - You will see the Server's **`-----BEGIN PUBLIC KEY-----`** transmitted to the Client.
   - The next packet from Client contains the **256-byte RSA-OAEP encrypted session payload**.
4. **Explanation for Professor**:
   > *"Sir yeh Asymmetric Hybrid Cryptography hai. Har session ke liye ek temporary random AES-256 key generate hoti hai jo server ki RSA Public Key se encrypt ho kar bhejte hain. Is tarah shared secret securely establish ho jata hai."*
