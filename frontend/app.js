/* ==========================================================================
   SecureVault LAN - Enterprise v3.0 Master Application Script
   Multi-Tab Navigation • Transfer Consent • Zero-Fakepath Native Bridge
   ========================================================================== */

let ws = null;
let localIp = '127.0.0.1';
let currentStatus = 'IDLE';
let currentRole = null;
let currentPeer = null;
let currentMode = 'ENCRYPTED';
let downloadsDir = '';
let quarantineDir = '';

// Discovered AirShare Peers Map
let discoveredPeersMap = {};

// Active Incoming Transfer Context
let activeIncomingProposal = null;
let stagedFilePath = null;

function sendStagedFile() {
  if (stagedFilePath) {
    sendToBackend('send_file', { filepath: stagedFilePath });
    const card = document.getElementById('stagedFileCard');
    if (card) card.style.display = 'none';
    stagedFilePath = null;
  }
}

// Downloaded Files History
let downloadedFilesHistory = [];

// Packet Telemetry Filter
let activeTelemetryFilter = 'all';
let packetCount = 0;

// Transfer Speed Calculation
let transferStartTime = 0;
let lastBytes = 0;

// -------------------------------------------------------------
// Initialization & Liquid Glow Follower
// -------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initCursorGlow();
  initWebSocket();
  initDragAndDrop();
  
  // Set default settings
  const webPort = window.location.port || '8082';
  const webPortEl = document.getElementById('settingsWebPortDisplay');
  if (webPortEl) webPortEl.value = `http://127.0.0.1:${webPort}`;
});

function initCursorGlow() {
  const glow = document.getElementById('cursorGlow');
  if (!glow) return;
  window.addEventListener('mousemove', (e) => {
    glow.style.left = `${e.clientX}px`;
    glow.style.top = `${e.clientY}px`;
  });
}

// -------------------------------------------------------------
// Multi-Tab Paging Navigation
// -------------------------------------------------------------
const TAB_TITLES = {
  devices: {
    title: 'Radar & Device Mesh',
    desc: 'Zero-Config AirShare Peer Discovery on UDP 5555'
  },
  transfers: {
    title: 'Transfer Hub & File Vault',
    desc: 'High-speed encrypted streaming with consent & verification'
  },
  chat: {
    title: 'Secure LAN Messenger',
    desc: 'End-to-end encrypted messaging with RSA-2048 & AES-256-GCM'
  },
  security: {
    title: 'Malware Shield & Security',
    desc: 'AMSI, EICAR inspection, and cryptographic validation'
  },
  inspector: {
    title: 'Packet & Protocol Inspector',
    desc: 'Wireshark-grade frame telemetry & hex dissection'
  },
  settings: {
    title: 'System Settings & Storage',
    desc: 'Configure download directories, consent, and ports'
  }
};

function switchTab(tabId) {
  // Update sidebar active buttons
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });

  // Switch visible page container
  document.querySelectorAll('.tab-page').forEach(page => {
    page.classList.remove('active');
  });

  const targetPage = document.getElementById(`tab${tabId.charAt(0).toUpperCase() + tabId.slice(1)}`);
  if (targetPage) {
    targetPage.classList.add('active');
  }

  // Update Top HUD Header Titles
  const titleInfo = TAB_TITLES[tabId];
  if (titleInfo) {
    const titleEl = document.getElementById('pageTitle');
    const descEl = document.getElementById('pageDesc');
    if (titleEl) titleEl.innerText = titleInfo.title;
    if (descEl) descEl.innerText = titleInfo.desc;
  }

  // Reset unread message badge when visiting chat
  if (tabId === 'chat') {
    const chatBadge = document.getElementById('chatUnreadBadge');
    if (chatBadge) {
      chatBadge.innerText = '0';
      chatBadge.style.display = 'none';
    }
  }
}

// -------------------------------------------------------------
// WebSocket Engine & Event Dispatcher
// -------------------------------------------------------------
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    updateSidebarStatus('CONNECTED TO BRIDGE');
    appendTelemetryLog('SYS', 'BRIDGE', 'WS_READY', 0, 'Internal WebSocket Control Bridge Online');
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.event === 'ping') return;
      handleBackendEvent(msg.event, msg.data);
    } catch (e) {
      console.error('WebSocket parse error:', e);
    }
  };

  ws.onclose = () => {
    updateSidebarStatus('BRIDGE OFFLINE');
    setTimeout(initWebSocket, 1500); // Auto-reconnect in 1.5s
  };

  ws.onerror = (err) => {
    console.warn('WebSocket error notice:', err);
  };
}

function sendToBackend(action, payload = {}) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ action, ...payload }));
  } else {
    alert('Backend connection is initializing. Please retry in a second.');
  }
}

// -------------------------------------------------------------
// Backend Event Dispatcher
// -------------------------------------------------------------
function handleBackendEvent(event, data) {
  switch (event) {
    case 'init_state':
      if (data.local_ip) {
        localIp = data.local_ip;
        const ipEl = document.getElementById('sidebarLocalIp');
        if (ipEl) ipEl.innerText = localIp;
      }
      if (data.downloads_dir) {
        downloadsDir = data.downloads_dir;
        updateDownloadDirDisplay(downloadsDir);
      }
      if (data.quarantine_dir) {
        quarantineDir = data.quarantine_dir;
        const qEl = document.getElementById('settingsQuarantineDirInput');
        if (qEl) qEl.value = quarantineDir;
      }
      if (data.security_mode) {
        setSecurityModeUI(data.security_mode === 'ENCRYPTED');
      }
      if (data.status) {
        updateNodeState(data.status, data.peer_address, data.role);
      }
      if (data.session_fingerprint) {
        updateSessionFingerprint(data.session_fingerprint);
      }
      if (data.scanner_active !== undefined) {
        setMalwareShieldUI(data.scanner_active);
      }
      if (data.tamper_active !== undefined) {
        setTamperUI(data.tamper_active);
      }
      if (data.discovered_peers) {
        data.discovered_peers.forEach(peer => handlePeerDiscovered(peer));
      }
      break;

    case 'status_change':
      updateNodeState(data.status, data.peer_info, data.role);
      if (data.fingerprint) updateSessionFingerprint(data.fingerprint);
      break;

    case 'mode_updated':
      setSecurityModeUI(data.mode === 'ENCRYPTED');
      break;

    case 'scanner_updated':
      setMalwareShieldUI(data.enabled);
      break;

    case 'tamper_updated':
      setTamperUI(data.enabled);
      break;

    case 'peer_discovered':
      handlePeerDiscovered(data);
      break;

    case 'peer_lost':
      handlePeerLost(data.peer_key);
      break;

    case 'incoming_transfer':
      handleIncomingTransferProposal(data);
      break;

    case 'file_progress':
      handleFileProgress(data);
      break;

    case 'file_complete':
      handleFileComplete(data);
      break;

    case 'chat_message':
      handleIncomingChatMessage(data);
      break;

    case 'threat_alert':
      handleThreatAlert(data);
      break;

    case 'vault_manifest':
      handleVaultManifest(data);
      break;

    case 'downloads_dir_updated':
      downloadsDir = data.downloads_dir;
      updateDownloadDirDisplay(downloadsDir);
      break;

    case 'packet_telemetry':
      appendTelemetryLog(data.direction, data.frame_type, data.mode, data.length, data.raw_hex);
      break;

    case 'log':
      appendTelemetryLog('LOG', data.level, 'SYSTEM', 0, data.msg);
      break;
  }
}

// -------------------------------------------------------------
// Node & State Updates
// -------------------------------------------------------------
function updateNodeState(status, peerInfo, role) {
  currentStatus = status;
  currentRole = role;
  currentPeer = peerInfo;

  const statusDot = document.getElementById('nodeStatusDot');
  const statusTitle = document.getElementById('sidebarNodeStatus');
  const peerVal = document.getElementById('sidebarPeerIp');
  const disconnectBtn = document.getElementById('sidebarDisconnectBtn');
  const chatPeerTitle = document.getElementById('chatPeerTitle');

  if (status === 'CONNECTED') {
    if (statusDot) statusDot.className = 'node-pulse-indicator online';
    if (statusTitle) statusTitle.innerText = `ONLINE (${role ? role.toUpperCase() : 'PEER'})`;
    if (peerVal) peerVal.innerText = peerInfo || 'Connected';
    if (disconnectBtn) disconnectBtn.style.display = 'block';
    if (chatPeerTitle) chatPeerTitle.innerText = `Connected to ${peerInfo || 'LAN Peer'}`;
  } else if (status === 'LISTENING') {
    if (statusDot) statusDot.className = 'node-pulse-indicator';
    if (statusTitle) statusTitle.innerText = 'LISTENING (SERVER)';
    if (peerVal) peerVal.innerText = 'Awaiting Client...';
    if (disconnectBtn) disconnectBtn.style.display = 'block';
    if (chatPeerTitle) chatPeerTitle.innerText = 'Listening for incoming peer...';
  } else {
    if (statusDot) statusDot.className = 'node-pulse-indicator';
    if (statusTitle) statusTitle.innerText = 'STANDBY';
    if (peerVal) peerVal.innerText = 'None';
    if (disconnectBtn) disconnectBtn.style.display = 'none';
    if (chatPeerTitle) chatPeerTitle.innerText = 'Chat with LAN Peer (Offline)';
  }
}

function updateSidebarStatus(text) {
  const el = document.getElementById('sidebarNodeStatus');
  if (el && currentStatus === 'IDLE') el.innerText = text;
}

function updateSessionFingerprint(fp) {
  const el = document.getElementById('cryptoSessionFingerprint');
  if (el) el.innerText = fp ? `${fp.substring(0, 16)}...` : 'Unnegotiated';
}

function updateDownloadDirDisplay(path) {
  const el = document.getElementById('settingsDownloadDirInput');
  const consentTarget = document.getElementById('incomingTargetFolder');
  if (el) el.value = path;
  if (consentTarget) consentTarget.innerText = path;
}

// -------------------------------------------------------------
// AirShare Peer Mesh Grid (Tab 1)
// -------------------------------------------------------------
function handlePeerDiscovered(peer) {
  const key = `${peer.ip}:${peer.port}`;
  discoveredPeersMap[key] = peer;
  renderDiscoveredPeersGrid();
}

function handlePeerLost(peerKey) {
  delete discoveredPeersMap[peerKey];
  renderDiscoveredPeersGrid();
}

function renderDiscoveredPeersGrid() {
  const grid = document.getElementById('discoveredPeersGrid');
  const countBadge = document.getElementById('peerCountBadge');
  const countText = document.getElementById('discoveredCountText');
  if (!grid) return;

  const peers = Object.values(discoveredPeersMap);
  const count = peers.length;

  if (countBadge) countBadge.innerText = count;
  if (countText) countText.innerText = `${count} Online Device${count === 1 ? '' : 's'}`;

  if (count === 0) {
    grid.innerHTML = `
      <div class="empty-peers-notice" id="emptyPeersNotice">
        <span class="radar-scan-icon">&#x1F4E1;</span>
        <span class="empty-title">Scanning Local Subnet...</span>
        <span class="empty-desc">Open SecureVault on another PC or launch a second client instance to discover.</span>
      </div>`;
    return;
  }

  grid.innerHTML = peers.map(peer => `
    <div class="peer-device-card glass-panel">
      <div class="peer-card-top">
        <div class="peer-avatar">&#x1F4BB;</div>
        <div class="peer-card-info">
          <span class="peer-name" title="${escapeHtml(peer.hostname || peer.node_id)}">${escapeHtml(peer.hostname || peer.node_id)}</span>
          <span class="peer-ip-badge">${peer.ip}:${peer.port}</span>
        </div>
      </div>
      <div class="peer-card-actions">
        <button class="glow-button primary-btn mini-btn w-100" onclick="connectToDiscoveredPeer('${peer.ip}', ${peer.port})">
          &#x27A4; CONNECT
        </button>
      </div>
    </div>
  `).join('');
}

function connectToDiscoveredPeer(ip, port) {
  sendToBackend('connect_peer', { host: ip, port: port });
  switchTab('transfers');
}

function connectDirectClient() {
  const host = document.getElementById('clientHostInput').value.trim() || '127.0.0.1';
  const port = parseInt(document.getElementById('clientPortInput').value.trim()) || 5500;
  sendToBackend('connect_client', { host, port });
  switchTab('transfers');
}

function startHostServer() {
  const port = parseInt(document.getElementById('serverPortInput').value.trim()) || 5500;
  sendToBackend('start_server', { port });
}

function disconnectNode() {
  sendToBackend('disconnect');
}

// -------------------------------------------------------------
// Native File Pickers & Drag-and-Drop (Eliminates C:\fakepath!)
// -------------------------------------------------------------
function triggerNativeFilePick() {
  // Directly asks backend Python to invoke Windows native file dialog
  sendToBackend('pick_and_send_file');
}

function triggerNativeMultiFilePick() {
  // Directly asks backend Python to invoke Windows native multi-file dialog
  sendToBackend('pick_and_share_multi');
}

function initDragAndDrop() {
  const dropZone = document.getElementById('dropZone');
  if (!dropZone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;

    if (files.length === 1) {
      uploadFileBinary(files[0]);
    } else {
      uploadMultiFilesBinary(files);
    }
  });
}

function handleBrowserFileSelected(input) {
  if (input.files && input.files.length > 0) {
    uploadFileBinary(input.files[0]);
    input.value = '';
  }
}

async function uploadFileBinary(file) {
  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch('/api/upload_and_send', {
      method: 'POST',
      body: formData
    });
    const result = await res.json();
    if (result.status === 'ok') {
      appendTelemetryLog('TX', 'FILE_UPLOAD', 'DIRECT', file.size, `File staged and streaming: ${file.name}`);
    } else {
      alert(`Transfer notice: ${result.message || 'Error occurred'}`);
    }
  } catch (err) {
    console.error('Binary upload error:', err);
  }
}

async function uploadMultiFilesBinary(files) {
  const formData = new FormData();
  for (let i = 0; i < files.length; i++) {
    formData.append('files', files[i]);
  }

  try {
    const res = await fetch('/api/upload_and_share_multi', {
      method: 'POST',
      body: formData
    });
    const result = await res.json();
    if (result.status === 'ok') {
      appendTelemetryLog('TX', 'VAULT_UPLOAD', 'DIRECT', 0, `Vault catalog staged with ${result.count} files.`);
    }
  } catch (err) {
    console.error('Multi-upload error:', err);
  }
}

// -------------------------------------------------------------
// Interactive Incoming File Consent Flow (Tab 2)
// -------------------------------------------------------------
function handleIncomingTransferProposal(meta) {
  activeIncomingProposal = meta;

  const card = document.getElementById('incomingConsentCard');
  const nameEl = document.getElementById('incomingFileName');
  const sizeEl = document.getElementById('incomingFileSize');
  const senderEl = document.getElementById('incomingSender');
  const targetFolderEl = document.getElementById('incomingTargetFolder');

  if (nameEl) nameEl.innerText = meta.filename || 'unknown.bin';
  if (sizeEl) sizeEl.innerText = formatBytes(meta.filesize || 0);
  if (senderEl) senderEl.innerText = `From: ${meta.sender || 'Peer'}`;
  if (targetFolderEl) targetFolderEl.innerText = downloadsDir || 'Default Directory';

  // Check user preference in settings
  const consentSetting = document.getElementById('settingConsentPrompt');
  const requiresConsent = consentSetting ? consentSetting.checked : true;

  if (card && requiresConsent) {
    card.style.display = 'flex';
  }

  // Switch to Transfers tab so user sees incoming file
  switchTab('transfers');
}

function acceptIncomingTransfer() {
  const card = document.getElementById('incomingConsentCard');
  if (card) card.style.display = 'none';
  // Let file continue into default directory
}

function saveAsIncomingTransfer() {
  if (activeIncomingProposal) {
    sendToBackend('save_file_as', { filename: activeIncomingProposal.filename });
  }
  const card = document.getElementById('incomingConsentCard');
  if (card) card.style.display = 'none';
}

function declineIncomingTransfer() {
  const card = document.getElementById('incomingConsentCard');
  if (card) card.style.display = 'none';
  appendTelemetryLog('RX', 'FILE_DECLINED', 'ABORT', 0, 'Incoming file transfer was declined by user.');
}

// -------------------------------------------------------------
// Streaming Progress & Wave Animation
// -------------------------------------------------------------
function handleFileProgress(data) {
  const vessel = document.getElementById('progressVessel');
  const dirEl = document.getElementById('progDirection');
  const nameEl = document.getElementById('progFileName');
  const pctEl = document.getElementById('progPercentage');
  const fillEl = document.getElementById('liquidWaveFill');
  const bytesMetaEl = document.getElementById('progBytesMeta');
  const speedMetaEl = document.getElementById('progSpeedMeta');
  const activeDot = document.getElementById('transferActiveDot');

  if (vessel) vessel.style.display = 'block';
  if (activeDot) activeDot.style.display = 'inline-block';

  const pct = Math.min(100.0, Math.max(0.0, data.percent || 0));

  if (dirEl) dirEl.innerText = data.direction === 'TX' ? 'SENDING:' : 'RECEIVING:';
  if (nameEl) nameEl.innerText = data.filename || 'streaming file';
  if (pctEl) pctEl.innerText = `${pct.toFixed(1)}%`;
  if (fillEl) fillEl.style.width = `${pct}%`;

  if (bytesMetaEl) {
    bytesMetaEl.innerText = `${formatBytes(data.current_bytes)} / ${formatBytes(data.total_bytes)}`;
  }

  // Calculate speed
  const now = Date.now();
  if (!transferStartTime || data.current_bytes === 0) {
    transferStartTime = now;
    lastBytes = data.current_bytes;
  } else {
    const elapsedSec = (now - transferStartTime) / 1000;
    if (elapsedSec > 0.5) {
      const speedBps = (data.current_bytes - lastBytes) / elapsedSec;
      if (speedMetaEl) speedMetaEl.innerText = `${(speedBps / (1024 * 1024)).toFixed(1)} MB/s`;
      transferStartTime = now;
      lastBytes = data.current_bytes;
    }
  }
}

function handleFileComplete(data) {
  const vessel = document.getElementById('progressVessel');
  const activeDot = document.getElementById('transferActiveDot');
  if (vessel) {
    const pctEl = document.getElementById('progPercentage');
    const fillEl = document.getElementById('liquidWaveFill');
    if (pctEl) pctEl.innerText = '100%';
    if (fillEl) fillEl.style.width = '100%';
    setTimeout(() => { vessel.style.display = 'none'; }, 2000);
  }
  if (activeDot) activeDot.style.display = 'none';

  // Add to Downloaded Files History
  addDownloadedFileRecord(data);
}

function addDownloadedFileRecord(data) {
  downloadedFilesHistory.unshift(data);
  const tbody = document.getElementById('transfersHistoryBody');
  const emptyRow = document.getElementById('emptyTransfersRow');
  if (emptyRow) emptyRow.style.display = 'none';

  if (!tbody) return;

  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td>
      <div style="font-weight: 600; font-family: var(--font-mono);">${escapeHtml(data.filename)}</div>
      <div style="font-size: 10px; color: var(--text-dim);">${escapeHtml(data.path)}</div>
    </td>
    <td><span style="font-family: var(--font-mono); color: var(--electric-cyan);">${formatBytes(data.filesize || 0)}</span></td>
    <td>
      <span class="status-badge-verified">
        ${data.is_intact ? '&#x2705; SHA-256 MATCH' : '&#x26A0;&#xFE0F; INTEGRITY BREACH'}
      </span>
    </td>
    <td>
      <div class="table-actions-cell">
        <button class="glow-button mini-btn" onclick="openSystemFile('${escapeJsString(data.path)}')">&#x1F4C2; OPEN</button>
        <button class="ghost-btn mini-ghost" onclick="openSystemFolder('${escapeJsString(data.path)}')">&#x1F4C1; FOLDER</button>
        <button class="ghost-btn mini-ghost" onclick="saveFileAsPrompt('${escapeJsString(data.filename)}', '${escapeJsString(data.path)}')">&#x1F4BE; SAVE AS</button>
      </div>
    </td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
}

// -------------------------------------------------------------
// System File / Folder Launcher Actions
// -------------------------------------------------------------
function openSystemFile(path) {
  fetch('/api/open_file', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path })
  });
}

function openSystemFolder(filePath) {
  sendToBackend('open_folder', { path: downloadsDir, highlight: filePath });
}

function openDownloadsFolder() {
  fetch('/api/open_folder', { method: 'POST' });
}

function openQuarantineFolder() {
  sendToBackend('open_folder', { path: quarantineDir });
}

function saveFileAsPrompt(filename, path) {
  sendToBackend('save_file_as', { filename, path });
}

async function browseDownloadDirectory() {
  try {
    const res = await fetch('/api/pick_folder');
    const data = await res.json();
    if (data.downloads_dir) {
      downloadsDir = data.downloads_dir;
      updateDownloadDirDisplay(downloadsDir);
    }
  } catch (e) {
    console.error('Folder picker error:', e);
  }
}

// -------------------------------------------------------------
// Multi-File Vault Shelf (Tab 2)
// -------------------------------------------------------------
function handleVaultManifest(manifest) {
  const shelf = document.getElementById('vaultShelf');
  const list = document.getElementById('vaultItemsList');
  const title = document.getElementById('vaultTitle');
  if (!shelf || !list) return;

  shelf.style.display = 'block';
  if (title) title.innerText = `Remote Catalog: ${manifest.vault_name || 'Shared Vault'} (${manifest.items.length} items)`;

  list.innerHTML = manifest.items.map(item => `
    <label style="display:flex; align-items:center; gap:8px; font-size:12px; font-family:var(--font-mono); color:var(--text-main); cursor:pointer;">
      <input type="checkbox" class="vault-checkbox" data-file-id="${item.file_id}" checked>
      <span>${escapeHtml(item.filename)}</span>
      <span style="color:var(--text-dim);">(${formatBytes(item.filesize)})</span>
    </label>
  `).join('');
}

function closeVaultShelf() {
  const shelf = document.getElementById('vaultShelf');
  if (shelf) shelf.style.display = 'none';
}

function downloadSelectedVaultFiles() {
  const selected = [];
  document.querySelectorAll('.vault-checkbox:checked').forEach(cb => {
    selected.push(parseInt(cb.dataset.fileId));
  });
  if (selected.length > 0) {
    sendToBackend('request_file_download', { requested_ids: selected });
    closeVaultShelf();
  }
}

function downloadAllVaultFiles() {
  const all = [];
  document.querySelectorAll('.vault-checkbox').forEach(cb => {
    all.push(parseInt(cb.dataset.fileId));
  });
  if (all.length > 0) {
    sendToBackend('request_file_download', { requested_ids: all });
    closeVaultShelf();
  }
}

// -------------------------------------------------------------
// Secure Messenger (Tab 3)
// -------------------------------------------------------------
function handleSendChatMessage(e) {
  e.preventDefault();
  const input = document.getElementById('chatInput');
  if (!input) return;
  const msg = input.value.trim();
  if (msg) {
    sendToBackend('send_message', { message: msg });
    input.value = '';
  }
}

function handleIncomingChatMessage(data) {
  const timeline = document.getElementById('chatTimeline');
  if (!timeline) return;

  const isMe = data.sender === 'Me';
  const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const bubbleRow = document.createElement('div');
  bubbleRow.className = `chat-bubble-row ${isMe ? 'me' : 'peer'}`;
  bubbleRow.innerHTML = `
    <div class="chat-bubble-meta">${escapeHtml(data.sender)} &bull; ${data.is_secure ? '&#x1F510; AES-256' : 'PLAINTEXT'} &bull; ${timeStr}</div>
    <div class="chat-bubble">${escapeHtml(data.text)}</div>
  `;
  timeline.appendChild(bubbleRow);
  timeline.scrollTop = timeline.scrollHeight;

  // Unread badge indicator if not on chat tab
  const activeTabBtn = document.querySelector('.nav-item.active');
  if (activeTabBtn && activeTabBtn.dataset.tab !== 'chat' && !isMe) {
    const badge = document.getElementById('chatUnreadBadge');
    if (badge) {
      badge.style.display = 'inline-block';
      badge.innerText = parseInt(badge.innerText || '0') + 1;
    }
  }
}

function clearChatTimeline() {
  const timeline = document.getElementById('chatTimeline');
  if (timeline) {
    timeline.innerHTML = `
      <div class="chat-welcome-notice">
        <span class="shield-mini-icon">&#x1F6E1;&#xFE0F;</span>
        <span>Timeline cleared. Future messages will be encrypted with AES-256-GCM.</span>
      </div>`;
  }
}

// -------------------------------------------------------------
// Threat Scanner & Quarantine (Tab 4)
// -------------------------------------------------------------
function handleThreatAlert(report) {
  const modal = document.getElementById('threatModal');
  const title = document.getElementById('threatModalTitle');
  const body = document.getElementById('threatModalBody');
  const meta = document.getElementById('threatModalMeta');

  if (title) title.innerText = `THREAT INTERCEPTED: ${report.threat_type || 'Malware Pattern'}`;
  if (body) body.innerText = `${report.details || 'Malicious pattern detected.'} (File: ${report.filename || 'unknown'})`;
  if (meta) meta.innerHTML = `Quarantined to: <code>${escapeHtml(report.quarantine_path || 'quarantine/')}</code>`;

  if (modal) modal.style.display = 'flex';

  // Add record to quarantine list in Security tab
  const list = document.getElementById('quarantineList');
  if (list) {
    const emptyNotice = list.querySelector('.empty-quarantine');
    if (emptyNotice) emptyNotice.remove();

    const item = document.createElement('div');
    item.className = 'threat-feature-item';
    item.style.borderColor = 'var(--alert-red)';
    item.innerHTML = `
      <span class="feat-icon" style="color:var(--alert-red);">&#x26A0;&#xFE0F;</span>
      <div class="feat-meta">
        <span class="feat-title" style="color:var(--alert-red);">${escapeHtml(report.threat_type)} (${escapeHtml(report.filename)})</span>
        <span class="feat-desc">${escapeHtml(report.details)} &bull; ${escapeHtml(report.quarantine_path)}</span>
      </div>
    `;
    list.prepend(item);
  }
}

function closeThreatModal() {
  const modal = document.getElementById('threatModal');
  if (modal) modal.style.display = 'none';
}

// -------------------------------------------------------------
// Presentation Demo Toggles
// -------------------------------------------------------------
function handleSecurityModeToggle(checkbox) {
  const mode = checkbox.checked ? 'ENCRYPTED' : 'PLAINTEXT';
  sendToBackend('set_mode', { mode });
}

function setSecurityModeUI(isEncrypted) {
  const toggle = document.getElementById('securityModeToggle');
  const title = document.getElementById('modeTitle');
  const desc = document.getElementById('modeDesc');
  const sidebarCipher = document.getElementById('sidebarCipherMode');

  if (toggle) toggle.checked = isEncrypted;
  if (title) title.innerHTML = isEncrypted ? '&#x1F510; AES-256' : '&#x1F513; PLAINTEXT';
  if (desc) desc.innerText = isEncrypted ? 'Ciphertext Active' : 'Wireshark Cleartext';
  if (sidebarCipher) sidebarCipher.innerText = isEncrypted ? 'AES-256-GCM' : 'PLAINTEXT';
}

function handleMalwareToggle(checkbox) {
  sendToBackend('set_scanner', { enabled: checkbox.checked });
}

function setMalwareShieldUI(enabled) {
  const toggle = document.getElementById('malwareShieldToggle');
  const title = document.getElementById('malwareShieldTitle');
  const desc = document.getElementById('malwareShieldDesc');
  const badge = document.getElementById('shieldActiveBadge');

  if (toggle) toggle.checked = enabled;
  if (title) title.innerHTML = enabled ? '&#x1F6E1;&#xFE0F; SHIELD' : '&#x26A0;&#xFE0F; BYPASS';
  if (desc) desc.innerText = enabled ? 'Quarantine Active' : 'Shield Disabled';
  if (badge) {
    badge.innerText = enabled ? 'ACTIVE & ENFORCED' : 'BYPASSED (DEMO)';
    badge.style.color = enabled ? 'var(--neon-green)' : 'var(--alert-red)';
    badge.style.borderColor = enabled ? 'rgba(0, 255, 136, 0.3)' : 'rgba(255, 51, 102, 0.4)';
  }
}

function handleTamperToggle(checkbox) {
  sendToBackend('set_tamper', { enabled: checkbox.checked });
}

function setTamperUI(enabled) {
  const toggle = document.getElementById('tamperToggle');
  const title = document.getElementById('tamperTitle');
  const desc = document.getElementById('tamperDesc');
  const pill = document.getElementById('tamperPill');

  if (toggle) toggle.checked = enabled;
  if (title) title.innerHTML = enabled ? '&#x26A0;&#xFE0F; SIMULATING MITM' : '&#x1F9EA; INTEGRITY TEST';
  if (desc) desc.innerText = enabled ? '1-Bit Error Injected' : 'Clean Stream';

  if (pill) {
    if (enabled) {
      pill.classList.add('alert-active');
    } else {
      pill.classList.remove('alert-active');
    }
  }
}

// -------------------------------------------------------------
// Packet Inspector & Telemetry Feed (Tab 5)
// -------------------------------------------------------------
function appendTelemetryLog(direction, frameType, mode, length, hexPreview) {
  packetCount++;
  const badge = document.getElementById('packetCountBadge');
  if (badge) badge.innerText = `${packetCount} Packets`;

  const feed = document.getElementById('telemetryFeed');
  const emptyNotice = document.getElementById('emptyTelemetryNotice');
  if (emptyNotice) emptyNotice.remove();

  if (!feed) return;

  const row = document.createElement('div');
  row.className = `telemetry-row ${direction.toLowerCase()}`;
  row.dataset.category = frameType;

  // Check filter
  if (activeTelemetryFilter !== 'all' && !frameType.includes(activeTelemetryFilter)) {
    row.style.display = 'none';
  }

  const tagClass = direction === 'TX' ? 'tx-tag' : 'rx-tag';

  row.innerHTML = `
    <span class="telemetry-tag ${tagClass}">[${direction}]</span>
    <span class="telemetry-frame-type">${escapeHtml(frameType)}</span>
    <span class="telemetry-mode">${escapeHtml(mode)}</span>
    <span class="telemetry-len">${length}B</span>
    <span class="telemetry-hex" title="${escapeHtml(hexPreview)}">${escapeHtml(hexPreview || '')}</span>
  `;

  feed.appendChild(row);
  feed.scrollTop = feed.scrollHeight;

  // Cap feed at 200 elements to prevent DOM bloat
  if (feed.children.length > 200) {
    feed.removeChild(feed.firstChild);
  }
}

function filterPackets(filter) {
  activeTelemetryFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.filter === filter);
  });

  document.querySelectorAll('.telemetry-row').forEach(row => {
    const cat = row.dataset.category || '';
    if (filter === 'all' || cat.includes(filter)) {
      row.style.display = 'flex';
    } else {
      row.style.display = 'none';
    }
  });
}

function clearPacketTelemetry() {
  const feed = document.getElementById('telemetryFeed');
  if (feed) {
    feed.innerHTML = '<div class="telemetry-empty-notice" id="emptyTelemetryNotice">Listening for LAN protocol frames...</div>';
  }
  packetCount = 0;
  const badge = document.getElementById('packetCountBadge');
  if (badge) badge.innerText = '0 Packets';
}

// -------------------------------------------------------------
// Utilities
// -------------------------------------------------------------
function formatBytes(bytes, decimals = 1) {
  if (!+bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeJsString(str) {
  if (!str) return '';
  return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
