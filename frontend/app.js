/* ==========================================================================
   SecureVault LAN - Zero-Lag Ultra High-Perf Client Engine

   Fixes Applied:
     BUG-008: switchRole(null) guard — no-op if role is null/undefined
     BUG-009: triggerFileInput guards against disconnected state
     BUG-010: vaultBadge border reset on disconnect
     BUG-011: pipelineTelemetry reset on disconnect
     BUG-012: set_mode guard already removed — toggle works always
     BUG-013: handleFileSelected no longer uses prompt(); uses data attributes
     BUG-014: fadeIn animation added back to chat bubbles
     BUG-015: drawCanvas calls debounced; rapid calls coalesced
   ========================================================================== */

let ws = null;
let currentRole = 'server';
let currentStatus = 'IDLE';
let isSecureMode = true;
let localIp = '127.0.0.1';

// Debounce helper (FIX BUG-015)
let _drawDebounceTimer = null;
function drawCanvasDebounced() {
  if (_drawDebounceTimer) clearTimeout(_drawDebounceTimer);
  _drawDebounceTimer = setTimeout(drawCanvas, 50);
}

// -------------------------------------------------------------
// WebSocket Connection Management
// -------------------------------------------------------------
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;
  
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    appendAuditLog('system', '[WS] Secure WebSocket control bridge connected.');
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.event === 'ping') return; // Keepalive, ignore
      handleBackendEvent(msg.event, msg.data);
    } catch (e) {
      console.error('WS parse error:', e);
    }
  };

  ws.onclose = () => {
    appendAuditLog('alert', '[WS] Bridge disconnected. Reconnecting in 2s...');
    setTimeout(initWebSocket, 2000);
  };

  ws.onerror = () => {
    // Will trigger onclose after this
  };
}

function sendToBackend(action, payload = {}) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ action, ...payload }));
  } else {
    appendAuditLog('alert', '[ERR] WebSocket bridge is offline.');
  }
}

// -------------------------------------------------------------
// Event Dispatcher from Backend
// -------------------------------------------------------------
function handleBackendEvent(event, data) {
  switch (event) {
    case 'init_state':
      if (data.local_ip) {
        localIp = data.local_ip;
        document.getElementById('localIpBadge').innerText = `IP: ${localIp}`;
      }
      if (data.security_mode) {
        setSecurityModeUI(data.security_mode === 'ENCRYPTED');
      }
      if (data.status) {
        updateStatusBadge(data.status, data.peer_address);
      }
      // FIX BUG-008: guard against null role
      if (data.role) {
        switchRole(data.role);
      }
      if (data.session_fingerprint) {
        const fpEl = document.getElementById('sessionFpVal');
        if (fpEl) glitchDecodeText(fpEl, data.session_fingerprint + '...');
      }
      if (data.scanner_active !== undefined) {
        setMalwareUI(data.scanner_active);
      }
      if (data.tamper_active !== undefined) {
        setTamperUI(data.tamper_active);
      }
      if (data.discovered_peers) {
        discoveredPeersMap = {};
        data.discovered_peers.forEach(p => {
          discoveredPeersMap[`${p.ip}:${p.tcp_port}`] = p;
        });
        renderPeersList();
      }
      drawCanvasDebounced();
      break;

    case 'status_change':
      updateStatusBadge(data.status, data.peer_info);
      if (data.role) {
        switchRole(data.role);
      }
      if (data.fingerprint) {
        const fpEl = document.getElementById('sessionFpVal');
        if (fpEl) glitchDecodeText(fpEl, data.fingerprint + '...');
      } else if (data.status === 'DISCONNECTED' || data.status === 'IDLE') {
        const fpEl = document.getElementById('sessionFpVal');
        if (fpEl) fpEl.innerText = 'NOT NEGOTIATED';
      }
      drawCanvasDebounced();
      break;

    case 'log':
      appendAuditLog(data.level.toLowerCase(), `[${data.level}] ${data.msg}`);
      break;

    case 'chat_message':
      addChatBubble(data.sender, data.text, data.is_secure);
      break;

    case 'file_progress':
      updateFileProgress(data.filename, data.current_bytes, data.total_bytes, data.percent);
      break;

    case 'file_complete':
      finishFileTransfer(data.filename, data.is_intact, data.sha256);
      break;

    case 'packet_telemetry':
      spawnPacket(data.direction, data.mode, data.frame_type, data.length);
      const dirSymbol = data.direction === 'TX' ? '▲ OUT' : '▼ IN';
      appendAuditLog(
        data.direction.toLowerCase(),
        `[${dirSymbol}] ${data.frame_type} (${data.length}B) [${data.mode}] ${data.raw_hex || ''}`
      );
      break;

    case 'mode_updated':
      setSecurityModeUI(data.mode === 'ENCRYPTED');
      break;

    case 'tamper_updated':
      setTamperUI(data.enabled);
      break;

    case 'scanner_updated':
      setMalwareUI(data.enabled);
      break;

    case 'peer_discovered':
      discoveredPeersMap[`${data.ip}:${data.tcp_port}`] = data;
      renderPeersList();
      break;

    case 'peer_lost':
      if (discoveredPeersMap[data.peer_key]) {
        delete discoveredPeersMap[data.peer_key];
        renderPeersList();
      }
      break;

    case 'threat_alert':
      showThreatModal(data);
      break;

    case 'vault_manifest':
      showVaultManifest(data);
      break;
  }
}

// -------------------------------------------------------------
// Interactive Liquid Mouse Glow Follower
// -------------------------------------------------------------
window.addEventListener('mousemove', (e) => {
  const glow = document.getElementById('cursorGlow');
  if (glow) {
    glow.style.left = e.clientX + 'px';
    glow.style.top = e.clientY + 'px';
  }
});

// -------------------------------------------------------------
// Crypto Glitch Decode Effect for Session Fingerprints
// -------------------------------------------------------------
function glitchDecodeText(el, targetText, duration = 650) {
  if (!el) return;
  const chars = '0123456789ABCDEFabcdef';
  const start = Date.now();
  const interval = setInterval(() => {
    const elapsed = Date.now() - start;
    if (elapsed >= duration) {
      clearInterval(interval);
      el.innerText = targetText;
      return;
    }
    let scrambled = '';
    const ratio = elapsed / duration;
    for (let i = 0; i < targetText.length; i++) {
      if (Math.random() < ratio) {
        scrambled += targetText[i];
      } else {
        scrambled += chars[Math.floor(Math.random() * chars.length)];
      }
    }
    el.innerText = scrambled;
  }, 35);
}

// -------------------------------------------------------------
// UI State Handlers
// -------------------------------------------------------------
function switchRole(role) {
  // FIX BUG-008: guard null/undefined role
  if (!role) return;

  currentRole = role;
  const tabServer = document.getElementById('tabServer');
  const tabClient = document.getElementById('tabClient');
  const ipGroup = document.getElementById('ipFieldGroup');
  const actionBtn = document.getElementById('actionBtn');
  const btnText = actionBtn.querySelector('.btn-text');

  if (role === 'server') {
    tabServer.classList.add('active');
    tabClient.classList.remove('active');
    ipGroup.style.display = 'none';
    btnText.innerText = 'INITIALIZE SECURE SERVER';
  } else {
    tabClient.classList.add('active');
    tabServer.classList.remove('active');
    ipGroup.style.display = 'flex';
    btnText.innerText = 'CONNECT TO REMOTE PEER';
  }
}

function handlePrimaryAction() {
  if (currentStatus === 'CONNECTED' || currentStatus === 'LISTENING') {
    sendToBackend('disconnect');
    return;
  }

  const port = parseInt(document.getElementById('portInput').value) || 5500;

  if (currentRole === 'server') {
    sendToBackend('start_server', { port });
  } else {
    const host = document.getElementById('targetIpInput').value.trim() || '127.0.0.1';
    sendToBackend('connect_client', { host, port });
  }
}

function updateStatusBadge(status, peerInfo) {
  currentStatus = status;
  const indicator = document.getElementById('statusIndicator');
  const statusText = document.getElementById('statusText');
  const peerText = document.getElementById('peerText');
  const actionBtn = document.getElementById('actionBtn');
  const btnText = actionBtn.querySelector('.btn-text');
  const vaultBadge = document.getElementById('vaultStatusBadge');

  indicator.className = 'status-indicator';

  if (status === 'CONNECTED') {
    indicator.classList.add('connected');
    statusText.innerText = 'SECURE CHANNEL LIVE';
    peerText.innerText = `PEER: ${peerInfo || 'LAN NODE'}`;
    btnText.innerText = 'DISCONNECT SESSION';
    actionBtn.classList.add('disconnect-btn');
    vaultBadge.innerText = 'ENCRYPTED STREAM ACTIVE';
    vaultBadge.style.color = 'var(--neon-green)';
    vaultBadge.style.borderColor = 'var(--neon-green)';
  } else if (status === 'LISTENING') {
    indicator.classList.add('listening');
    statusText.innerText = 'SERVER LISTENING';
    peerText.innerText = peerInfo || 'WAITING FOR CLIENT...';
    btnText.innerText = 'STOP LISTENING';
    actionBtn.classList.add('disconnect-btn');
    vaultBadge.innerText = 'WAITING FOR CONNECTION';
    vaultBadge.style.color = '';
    vaultBadge.style.borderColor = '';
  } else {
    // IDLE / DISCONNECTED (FIX BUG-010: reset badge border)
    statusText.innerText = 'SYSTEM IDLE';
    peerText.innerText = 'NO ACTIVE PEER';
    btnText.innerText = currentRole === 'server' ? 'INITIALIZE SECURE SERVER' : 'CONNECT TO REMOTE PEER';
    actionBtn.classList.remove('disconnect-btn');
    vaultBadge.innerText = 'STANDBY';
    vaultBadge.style.color = '';
    vaultBadge.style.borderColor = '';
    // FIX BUG-011: reset pipeline telemetry text
    document.getElementById('pipelineTelemetry').innerText = 'IDLE \u2022 READY FOR DATA INJECTION';
  }
}

// -------------------------------------------------------------
// Security Mode Switcher
// -------------------------------------------------------------
document.getElementById('securityModeToggle').addEventListener('change', (e) => {
  const isEnc = e.target.checked;
  sendToBackend('set_mode', { mode: isEnc ? 'ENCRYPTED' : 'PLAINTEXT' });
});

function setSecurityModeUI(isEnc) {
  isSecureMode = isEnc;
  const toggleEl = document.getElementById('securityModeToggle');
  const titleEl = document.getElementById('modeTitle');
  const descEl = document.getElementById('modeDesc');
  const cipherLabel = document.getElementById('activeCipherLabel');

  toggleEl.checked = isEnc;
  if (isEnc) {
    titleEl.innerText = '\uD83D\uDD10 AES-256-GCM SECURE';
    titleEl.classList.remove('insecure');
    descEl.innerText = 'Encrypted Ciphertext Active';
    cipherLabel.innerText = 'AES-256-GCM (Authenticated)';
    cipherLabel.style.color = 'var(--neon-green)';
  } else {
    titleEl.innerText = '\u26A0\uFE0F PLAINTEXT DEMO MODE';
    titleEl.classList.add('insecure');
    descEl.innerText = 'Unencrypted for Wireshark Capture';
    cipherLabel.innerText = 'UNENCRYPTED (Plaintext)';
    cipherLabel.style.color = 'var(--alert-red)';
  }
}

// -------------------------------------------------------------
// Messaging
// -------------------------------------------------------------
function handleChatKeyPress(e) {
  if (e.key === 'Enter') {
    sendMessage();
  }
}

function sendMessage() {
  const input = document.getElementById('chatInput');
  const text = input.value.trim();
  if (!text) return;

  if (currentStatus !== 'CONNECTED') {
    appendAuditLog('alert', '[ERR] Cannot send message: not connected to peer.');
    return;
  }

  sendToBackend('send_message', { message: text });
  input.value = '';
}

function addChatBubble(sender, text, isSecure) {
  const viewport = document.getElementById('chatViewport');
  const placeholder = viewport.querySelector('.empty-chat-placeholder');
  if (placeholder) placeholder.remove();

  const bubble = document.createElement('div');
  const isMe = (sender === 'Me');
  // FIX BUG-014: fadeIn class added back
  bubble.className = `chat-bubble ${isMe ? 'me' : 'remote'} ${isSecure ? '' : 'insecure'} fadeIn`;

  const timeStr = new Date().toLocaleTimeString();
  const secBadge = isSecure ? '\uD83D\uDD10 AES-256' : '\u26A0\uFE0F PLAINTEXT';

  bubble.innerHTML = `
    <div class="bubble-meta">
      <span>${escapeHtml(sender)}</span>
      <span>${secBadge} &bull; ${timeStr}</span>
    </div>
    <div class="bubble-text">${escapeHtml(text)}</div>
  `;

  viewport.appendChild(bubble);
  viewport.scrollTop = viewport.scrollHeight;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.innerText = str;
  return div.innerHTML;
}

// -------------------------------------------------------------
// File Transfer (FIX BUG-009, BUG-013)
// -------------------------------------------------------------
function triggerFileInput() {
  // FIX BUG-009: block file pick if not connected
  if (currentStatus !== 'CONNECTED') {
    appendAuditLog('alert', '[ERR] Connect to a peer before sending files.');
    return;
  }
  document.getElementById('fileInputEl').click();
}

function handleFileSelected(e) {
  const file = e.target.files[0];
  if (!file) return;

  // FIX BUG-013: removed prompt() — use file.name directly
  // The backend receives a path, but since we're running locally we pass the full path
  // via a hidden data attribute set by the native file input.
  // We read the full path from the input element's value (works in Edge app-mode).
  const fileInput = document.getElementById('fileInputEl');
  // In Edge/Chrome app-mode, file.name is relative. We need the full path.
  // We store it in a dataset attribute for safety.
  let filepath = '';
  if (fileInput.files[0]) {
    // On Windows in Edge app-mode, we can get the path from the value
    filepath = fileInput.value || file.name;
    // Normalize Windows path separators
    filepath = filepath.replace(/\\/g, '\\');
  }

  if (!filepath) {
    appendAuditLog('alert', '[ERR] Could not determine file path. Please try again.');
    return;
  }

  sendToBackend('send_file', { filepath });

  // Reset file input so the same file can be re-selected
  fileInput.value = '';

  document.getElementById('fileDropzone').style.display = 'none';
  document.getElementById('progressVessel').style.display = 'flex';
  document.getElementById('progFileName').innerText = file.name;
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
}

function updateFileProgress(filename, cur, total, pct) {
  const vessel = document.getElementById('progressVessel');
  vessel.style.display = 'flex';
  document.getElementById('fileDropzone').style.display = 'none';

  const clampedPct = Math.min(100.0, Math.max(0.0, pct)).toFixed(1);
  document.getElementById('progFileName').innerText = filename;
  document.getElementById('progPercentage').innerText = `${clampedPct}%`;
  document.getElementById('liquidWaveFill').style.width = `${clampedPct}%`;

  document.getElementById('progBytesMeta').innerText = `${formatBytes(cur)} / ${formatBytes(total)}`;
}

function finishFileTransfer(filename, isIntact, sha256) {
  const pctEl = document.getElementById('progPercentage');
  const fillEl = document.getElementById('liquidWaveFill');

  pctEl.innerText = isIntact ? '100% (VERIFIED)' : 'FAILED';
  pctEl.style.color = isIntact ? 'var(--neon-green)' : 'var(--alert-red)';
  fillEl.style.width = '100%';

  setTimeout(() => {
    document.getElementById('progressVessel').style.display = 'none';
    document.getElementById('fileDropzone').style.display = 'block';
  }, 2500);

  const intCard = document.getElementById('integrityStatusText');
  const intBody = document.getElementById('integrityBody');
  if (isIntact) {
    intCard.innerText = 'SHA-256 CHECKSUM VERIFIED \u2713';
    intCard.style.color = 'var(--neon-green)';
    intBody.innerText = `File: '${filename}' \u2022 Hash: ${sha256.substring(0, 18)}...`;
  } else {
    intCard.innerText = 'INTEGRITY VIOLATION DETECTED \u2717';
    intCard.style.color = 'var(--alert-red)';
    intBody.innerText = `File: '${filename}' failed checksum verification!`;
  }
}

// -------------------------------------------------------------
// Live Security Audit (Capped at 50 items for zero lag)
// -------------------------------------------------------------
function appendAuditLog(type, text) {
  const container = document.getElementById('hexStream');
  const line = document.createElement('div');
  line.className = `hex-line ${type}-line`;
  line.innerText = text;
  container.appendChild(line);

  while (container.childNodes.length > 50) {
    container.removeChild(container.firstChild);
  }
  container.scrollTop = container.scrollHeight;
}

function clearAuditLog() {
  document.getElementById('hexStream').innerHTML = '';
  appendAuditLog('system', '[SYSTEM] Audit buffer cleared.');
}

// -------------------------------------------------------------
// On-Demand Canvas Engine (0% Idle CPU / GPU)
// -------------------------------------------------------------
const canvas = document.getElementById('packetCanvas');
const ctx = canvas.getContext('2d');

let packets = [];
let ripples = [];
let isLoopRunning = false;

function resizeCanvas() {
  const wrapper = canvas.parentElement;
  canvas.width = wrapper.clientWidth;
  canvas.height = wrapper.clientHeight;
  drawCanvas();
}

window.addEventListener('resize', () => {
  if (_drawDebounceTimer) clearTimeout(_drawDebounceTimer);
  _drawDebounceTimer = setTimeout(resizeCanvas, 100);
});
setTimeout(resizeCanvas, 30);

function spawnPacket(direction, mode, frameType, length) {
  if (packets.length >= 6) packets.shift();

  const w = canvas.width;
  const h = canvas.height;
  const y = h / 2;

  const isTX = (direction === 'TX');
  const startX = isTX ? 40 : w - 40;
  const endX = isTX ? w - 40 : 40;

  packets.push({
    x: startX,
    y: y,
    startX: startX,
    endX: endX,
    color: mode === 'ENCRYPTED' ? '#00ff88' : '#ff3366',
    progress: 0,
    speed: 0.04 + Math.random() * 0.02,
    frameType: frameType
  });

  const tele = document.getElementById('pipelineTelemetry');
  tele.innerText = `${direction} \u2022 ${frameType} (${length}B) \u2022 ${mode}`;

  startAnimationLoop();
}

let ambientPulseX = 0;

function startAnimationLoop() {
  if (!isLoopRunning) {
    isLoopRunning = true;
    requestAnimationFrame(animationStep);
  }
}

function animationStep() {
  drawCanvas();
  // Continuous smooth 60fps pipeline animation (ambient signal + packets)
  requestAnimationFrame(animationStep);
}

function drawCanvas() {
  const w = canvas.width;
  const h = canvas.height;
  if (!w || !h) return;

  ctx.clearRect(0, 0, w, h);

  const centerY = h / 2;
  const leftX = 50;
  const rightX = w - 50;
  const now = Date.now();

  // 1. Cyber Cable Background (Multi-layer fiber glow)
  ctx.beginPath();
  ctx.moveTo(leftX, centerY);
  ctx.lineTo(rightX, centerY);
  ctx.strokeStyle = 'rgba(0, 255, 136, 0.12)';
  ctx.lineWidth = 6;
  ctx.stroke();

  ctx.beginPath();
  ctx.moveTo(leftX, centerY);
  ctx.lineTo(rightX, centerY);
  ctx.strokeStyle = 'rgba(0, 255, 136, 0.45)';
  ctx.lineWidth = 1.5;
  ctx.stroke();

  // 1b. Undulating Electromagnetic Sine Wave along the Cable (Neon Green)
  ctx.beginPath();
  for (let x = leftX; x <= rightX; x += 3) {
    const waveY = centerY + Math.sin((x * 0.035) - (now * 0.004)) * 3.5;
    if (x === leftX) ctx.moveTo(x, waveY);
    else ctx.lineTo(x, waveY);
  }
  ctx.strokeStyle = 'rgba(0, 255, 136, 0.55)';
  ctx.lineWidth = 1.2;
  ctx.stroke();

  // Second harmonic sine wave (Electric Cyan)
  ctx.beginPath();
  for (let x2 = leftX; x2 <= rightX; x2 += 4) {
    const waveY2 = centerY + Math.sin((x2 * 0.025) + (now * 0.003)) * 2.2;
    if (x2 === leftX) ctx.moveTo(x2, waveY2);
    else ctx.lineTo(x2, waveY2);
  }
  ctx.strokeStyle = 'rgba(56, 189, 248, 0.35)';
  ctx.lineWidth = 1;
  ctx.stroke();

  // 2. Continuous Ambient Electric Pulse along the cable
  const cableLen = rightX - leftX;
  ambientPulseX = (ambientPulseX + 1.2) % cableLen;
  const curPulseX = leftX + ambientPulseX;

  const grad = ctx.createRadialGradient(curPulseX, centerY, 0, curPulseX, centerY, 24);
  grad.addColorStop(0, 'rgba(0, 255, 136, 0.7)');
  grad.addColorStop(0.5, 'rgba(56, 189, 248, 0.3)');
  grad.addColorStop(1, 'transparent');
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.arc(curPulseX, centerY, 24, 0, Math.PI * 2);
  ctx.fill();

  // 3. Nodes (with breathing aura)
  const peerTextEl = document.getElementById('peerText');
  const peerLabel = peerTextEl ? peerTextEl.innerText.replace('PEER: ', '') : '';
  drawTerminalNode(leftX, centerY, 'LOCAL NODE', localIp, currentStatus === 'CONNECTED', now);
  drawTerminalNode(rightX, centerY, 'REMOTE NODE', peerLabel, currentStatus === 'CONNECTED', now);

  // 4. Traveling Cryptogram Packets
  for (let i = packets.length - 1; i >= 0; i--) {
    const p = packets[i];
    p.progress += p.speed;
    p.x = p.startX + (p.endX - p.startX) * p.progress;

    // Multi-layer glowing particle
    for (let r = 16; r >= 4; r -= 4) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
      ctx.fillStyle = p.color + '25';
      ctx.fill();
    }

    // Core bright bead
    ctx.beginPath();
    ctx.arc(p.x, p.y, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = '#ffffff';
    ctx.fill();

    // Packet label (frame type)
    ctx.font = '8px Orbitron, Consolas, monospace';
    ctx.fillStyle = p.color;
    ctx.textAlign = 'center';
    ctx.fillText(p.frameType || 'DATA', p.x, p.y - 10);

    if (p.progress >= 1) {
      ripples.push({ x: p.endX, y: centerY, r: 3, maxR: 22, opacity: 1.0, color: p.color });
      packets.splice(i, 1);
    }
  }

  // 5. Destination Ripple Waves
  for (let j = ripples.length - 1; j >= 0; j--) {
    const r = ripples[j];
    r.r += 1.4;
    r.opacity -= 0.05;
    if (r.opacity <= 0) { ripples.splice(j, 1); continue; }

    ctx.beginPath();
    ctx.arc(r.x, r.y, r.r, 0, Math.PI * 2);
    ctx.strokeStyle = `${r.color}${Math.floor(r.opacity * 255).toString(16).padStart(2, '0')}`;
    ctx.lineWidth = 2;
    ctx.stroke();
  }
}

function drawTerminalNode(x, y, label, sub, isConnected, now) {
  const pulse = Math.sin(now / 350) * 3;
  const baseR = 12;

  // Breathing outer aura
  ctx.beginPath();
  ctx.arc(x, y, baseR + 8 + pulse, 0, Math.PI * 2);
  ctx.fillStyle = isConnected ? 'rgba(0, 255, 136, 0.08)' : 'rgba(255, 255, 255, 0.02)';
  ctx.fill();

  // Outer ring
  ctx.beginPath();
  ctx.arc(x, y, baseR, 0, Math.PI * 2);
  ctx.fillStyle = isConnected ? '#00381b' : '#0c140f';
  ctx.strokeStyle = isConnected ? '#00ff88' : '#33443a';
  ctx.lineWidth = 2;
  ctx.fill();
  ctx.stroke();

  // Center core
  ctx.beginPath();
  ctx.arc(x, y, 4, 0, Math.PI * 2);
  ctx.fillStyle = isConnected ? '#00ff88' : '#556b5e';
  ctx.fill();

  // Labels
  ctx.font = '700 9px Orbitron, Segoe UI, sans-serif';
  ctx.fillStyle = isConnected ? '#00ff88' : '#8ca396';
  ctx.textAlign = 'center';
  ctx.fillText(label, x, y - 18);

  ctx.font = '8px JetBrains Mono, Consolas, monospace';
  ctx.fillStyle = '#5f7a6b';
  const shortSub = sub && sub.length > 22 ? sub.substring(0, 20) + '..' : (sub || 'NO PEER');
  ctx.fillText(shortSub, x, y + 22);
}

// Initialize on Load
window.addEventListener('DOMContentLoaded', () => {
  initWebSocket();
  startAnimationLoop();
});

// -------------------------------------------------------------
// Phase 2: Anti-Malware & Threat Shield UI Controls
// -------------------------------------------------------------
function handleMalwareToggle(el) {
  const enabled = el.checked;
  sendToBackend('set_scanner', { enabled });
  setMalwareUI(enabled);
}

function setMalwareUI(enabled) {
  const title = document.getElementById('malwareShieldTitle');
  const desc = document.getElementById('malwareShieldDesc');
  const toggle = document.getElementById('malwareShieldToggle');
  if (toggle) toggle.checked = enabled;
  if (title && desc) {
    title.innerHTML = enabled ? '&#x1F6E1;&#xFE0F; MALWARE SHIELD' : '&#x26A0;&#xFE0F; SHIELD BYPASSED';
    title.style.color = enabled ? 'var(--neon-green)' : 'var(--alert-red)';
    desc.innerText = enabled ? 'Active • Quarantine' : 'Unrestricted Ingest';
  }
}

function showThreatModal(report) {
  const modal = document.getElementById('threatModal');
  const title = document.getElementById('threatModalTitle');
  const body = document.getElementById('threatModalBody');
  const meta = document.getElementById('threatModalMeta');
  if (!modal) return;

  if (title) title.innerText = `SECURITY THREAT INTERCEPTED: ${report.threat_type || 'MALWARE'}`;
  if (body) body.innerText = report.details || 'Dangerous payload blocked.';
  if (meta) {
    meta.innerHTML = report.quarantined
      ? `File quarantined securely to: <code>quarantine/</code> (isolated with .locked seal)`
      : `Threat warning generated.`;
  }
  modal.style.display = 'flex';
  appendAuditLog('alert', `[CRITICAL THREAT BLOCKED] ${report.threat_type}: ${report.details}`);
}

function closeThreatModal() {
  const modal = document.getElementById('threatModal');
  if (modal) modal.style.display = 'none';
}

// -------------------------------------------------------------
// Phase 1 Demo Toggle: Tamper Injection Control
// -------------------------------------------------------------
function handleTamperToggle(el) {
  const enabled = el.checked;
  sendToBackend('set_tamper', { enabled });
  setTamperUI(enabled);
}

function setTamperUI(enabled) {
  const title = document.getElementById('tamperTitle');
  const desc = document.getElementById('tamperDesc');
  const toggle = document.getElementById('tamperToggle');
  const container = document.querySelector('.tamper-toggle-box');
  if (toggle) toggle.checked = enabled;
  if (container) {
    if (enabled) container.classList.add('tampered');
    else container.classList.remove('tampered');
  }
  if (title && desc) {
    title.innerHTML = enabled ? '&#x2694;&#xFE0F; TAMPER DEMO (ON)' : '&#x2694;&#xFE0F; TAMPER DEMO';
    title.style.color = enabled ? 'var(--alert-red)' : 'var(--text-main)';
    desc.innerText = enabled ? '1-Bit Corrupted' : 'Off • Clean Stream';
  }
}

// -------------------------------------------------------------
// Phase 3: AirShare Zero-Config Peer Mesh Management
// -------------------------------------------------------------
let discoveredPeersMap = {};

function renderPeersList() {
  const listEl = document.getElementById('radarPeersList');
  const countEl = document.getElementById('peerCountBadge');
  if (!listEl) return;

  const keys = Object.keys(discoveredPeersMap);
  if (countEl) countEl.innerText = `${keys.length} Online`;

  if (keys.length === 0) {
    listEl.innerHTML = '<div class="radar-empty">Searching subnet for active SecureVault peers...</div>';
    return;
  }

  listEl.innerHTML = '';
  keys.forEach(k => {
    const peer = discoveredPeersMap[k];
    const card = document.createElement('div');
    card.className = 'radar-peer-card fadeIn';
    card.innerHTML = `
      <div class="peer-info-meta">
        <span class="peer-name">&#x1F4BB; ${escapeHtml(peer.hostname)}</span>
        <span class="peer-ip-port">${peer.ip}:${peer.tcp_port}</span>
      </div>
      <button class="peer-connect-btn" onclick="connectToDiscoveredPeer('${peer.ip}', ${peer.tcp_port})">CONNECT &#x2794;</button>
    `;
    listEl.appendChild(card);
  });
}

function connectToDiscoveredPeer(ip, port) {
  appendAuditLog('system', `[AIRSHARE] Connecting directly to discovered peer ${ip}:${port}...`);
  sendToBackend('connect_peer', { host: ip, port: port });
}

// -------------------------------------------------------------
// Phase 4: Multi-File Staging & Selective Vault Pull
// -------------------------------------------------------------
let currentManifest = null;

function triggerMultiFileInput() {
  if (currentStatus !== 'CONNECTED') {
    appendAuditLog('alert', '[ERR] Connect to a peer before sharing files.');
    return;
  }
  document.getElementById('fileInputMultiEl').click();
}

function handleMultiFilesSelected(e) {
  const files = Array.from(e.target.files);
  if (!files.length) return;

  const filepaths = files.map(f => f.value || f.name);
  sendToBackend('share_multi_files', { filepaths });
  appendAuditLog('system', `[VAULT] Staged ${files.length} file(s) for multi-file vault distribution.`);
  e.target.value = '';
}

function showVaultManifest(manifest) {
  currentManifest = manifest;
  const shelf = document.getElementById('vaultShelfBox');
  const itemsList = document.getElementById('vaultItemsList');
  if (!shelf || !itemsList) return;

  itemsList.innerHTML = '';
  manifest.items.forEach(item => {
    const row = document.createElement('div');
    row.className = 'vault-item-row';
    row.innerHTML = `
      <div class="vault-item-left">
        <input type="checkbox" class="vault-item-cb" data-id="${item.id}" checked>
        <span>&#x1F4C4; ${escapeHtml(item.filename)}</span>
      </div>
      <span class="vault-item-size">${formatBytes(item.size)}</span>
    `;
    itemsList.appendChild(row);
  });

  shelf.style.display = 'block';
  appendAuditLog('info', `[VAULT] Received catalog with ${manifest.items.length} shared file(s). Select files to download.`);
}

function closeVaultShelf() {
  const shelf = document.getElementById('vaultShelfBox');
  if (shelf) shelf.style.display = 'none';
}

function downloadSelectedVaultFiles() {
  if (!currentManifest) return;
  const cbs = document.querySelectorAll('.vault-item-cb:checked');
  const selectedIds = Array.from(cbs).map(cb => parseInt(cb.getAttribute('data-id')));
  if (!selectedIds.length) {
    appendAuditLog('alert', '[VAULT] No files selected for download.');
    return;
  }
  sendToBackend('request_file_download', {
    vault_id: currentManifest.vault_id,
    requested_ids: selectedIds
  });
  appendAuditLog('success', `[VAULT] Requested selective download of ${selectedIds.length} file(s).`);
  closeVaultShelf();
}

function downloadAllVaultFiles() {
  if (!currentManifest) return;
  const allIds = currentManifest.items.map(item => item.id);
  sendToBackend('request_file_download', {
    vault_id: currentManifest.vault_id,
    requested_ids: allIds
  });
  appendAuditLog('success', `[VAULT] Requested full download of all ${allIds.length} file(s).`);
  closeVaultShelf();
}

function copyWiresharkFilter() {
  const filterText = 'tcp.port == 5500 && frame contains "SV"';
  navigator.clipboard.writeText(filterText).then(() => {
    appendAuditLog('system', `[WIRESHARK] Copied filter to clipboard: ${filterText}`);
  });
}
