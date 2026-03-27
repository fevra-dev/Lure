/**
 * extension/popup/popup.js
 *
 * LURE popup dashboard — canvas-based traffic visualization wired to
 * real detection events from chrome.storage.local.
 *
 * Packets flow along bezier "thread" paths from left to a SENTINEL
 * convergence point on the right. Color encodes severity:
 *   olive (#8b9e73)  = normal / low / medium
 *   bronze (#b59a6d) = high
 *   red (#c25e5e)    = critical
 */

'use strict';

/* ── Constants ──────────────────────────────────────────────── */

const STORAGE_KEY = 'phishops_events';
const MONO_FONT = '"SF Mono", "Cascadia Code", Consolas, "Liberation Mono", monospace';

const COLORS = {
  bg: '#1e2226',
  thread: 'rgba(181, 154, 109, 0.1)',
  packetNormal: '#8b9e73',
  packetHigh: '#b59a6d',
  packetCritical: '#c25e5e',
  packetSentinel: '#7ec4cf',
  text: 'rgba(209, 199, 177, 0.7)',
};

const EVENT_TYPE_LABELS = {
  'OAUTH_DEVICE_CODE_FLOW': 'Device Code Flow',
  'OAUTH_STATE_EMAIL_ENCODED': 'State Param Email',
  'BLOB_URL_CREDENTIAL_PAGE': 'Blob Credential Page',
  'EXTENSION_DNR_AUDIT': 'DNR Audit',
  'EXTENSION_OWNERSHIP_DRIFT': 'Ownership Drift',
  'EXTENSION_C2_POLLING': 'C2 Polling',
  'SUSPICION_RAISED': 'Suspicion Raised',
  'PHISHVISION_SUPPLEMENTARY_SIGNAL': 'GAN Page Signal',
  'AGENTIC_BLABBERING_GUARDRAIL_BYPASS': 'Guardrail Bypass',
  'AUTOFILL_HIDDEN_FIELD_HARVEST': 'Hidden Field Harvest',
  'AUTOFILL_EXTENSION_CLICKJACK': 'Extension Clickjacking',
  'CLICKFIX_CLIPBOARD_INJECTION': 'Clipboard Injection',
  'FULLSCREEN_BITM_OVERLAY': 'Fullscreen Overlay',
  'PASSKEY_CREDENTIAL_INTERCEPTION': 'Passkey Interception',
  'QRLJACKING_SESSION_HIJACK': 'QR Session Hijack',
  'WEBRTC_VIRTUAL_CAMERA_DETECTED': 'Virtual Camera',
  'SCREENSHARE_TOAD_DETECTED': 'TOAD Screen Share',
  'PHISHVISION_BRAND_IMPERSONATION': 'Brand Impersonation',
  'PROXY_AITM_DETECTED': 'AiTM Proxy',
  'SYNC_HIJACK_DETECTED': 'Sync Hijack',
  'FAKESENDER_BRAND_IMPERSONATION': 'Helpdesk Impersonation',
  'FIDO_DOWNGRADE_DETECTED': 'FIDO Downgrade',
  'IPFS_PHISHING_DETECTED': 'IPFS Phishing',
  'LLM_GENERATED_PHISHING_DETECTED': 'AI-Generated Phishing',
  'VNC_AITM_DETECTED': 'VNC AiTM',
  'PWA_PHISHING_DETECTED': 'PWA Phishing',
  'TPA_CONSENT_PHISHING_DETECTED': 'Consent Phishing',
  'CRYPTO_DRAINER_DETECTED': 'Wallet Drainer',
  'CSS_CREDENTIAL_EXFIL_DETECTED': 'CSS Exfiltration',
  'WEBSOCKET_CREDENTIAL_EXFIL_DETECTED': 'WS Credential Exfil',
  'SERVICE_WORKER_PERSISTENCE_DETECTED': 'SW Persistence',
  'ETHERHIDING_PAYLOAD_DETECTED': 'EtherHiding Payload',
  'NOTIFICATION_PHISHING_DETECTED': 'Notification Phishing',
  'WEBTRANSPORT_CREDENTIAL_EXFIL_DETECTED': 'WT Credential Relay',
  'CANVAS_CREDENTIAL_PHISHING_DETECTED': 'Canvas Credential Phish',
  'CANVAS_KEYSTROKE_CAPTURE_DETECTED': 'Canvas Keystroke Capture',
  'CANVAS_CREDENTIAL_EXFIL_DETECTED': 'Canvas Credential Exfil',
  'SPECULATION_RULES_PHISHING_DETECTED': 'Speculation Rules Phish',
  'EXTENSION_PROBE_DETECTED': 'Extension Probing',
  'PAYMENT_REQUEST_PHISHING_DETECTED': 'Payment Request Phish',
  'FILE_SYSTEM_PICKER_ABUSE_DETECTED': 'FS API Credential Exfil',
};

/* ── DOM refs ───────────────────────────────────────────────── */

let canvas, ctx;
let totalEl, highEl, criticalEl;
let telemetryDot, telemetryText, toggle;

/* ── State ──────────────────────────────────────────────────── */

let width = 0, height = 0;
let paths = [];
let packets = [];
let isRunning = true;
let totalCount = 0, highCount = 0, criticalCount = 0;
let lastEventCount = 0;
let heartbeatTimer = null;

/* ── Lifecycle ──────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  canvas = document.getElementById('lureCanvas');
  ctx = canvas.getContext('2d', { alpha: false });
  totalEl = document.getElementById('totalCount');
  highEl = document.getElementById('highCount');
  criticalEl = document.getElementById('criticalCount');
  telemetryDot = document.getElementById('telemetryDot');
  telemetryText = document.getElementById('telemetryText');
  toggle = document.getElementById('activeToggle');

  // Footer: version + detector count
  try {
    const manifest = chrome.runtime.getManifest();
    document.getElementById('footerInfo').textContent =
      `v${manifest.version} | 46 DETECTORS ACTIVE`;
  } catch (_) { /* non-extension context */ }

  // Toggle state
  try {
    const stored = await chrome.storage.local.get('phishops_enabled');
    const enabled = stored.phishops_enabled !== false; // default true
    toggle.checked = enabled;
    isRunning = enabled;
    updateTelemetryIndicator(enabled);
  } catch (_) { /* non-extension context */ }

  toggle.addEventListener('change', async (e) => {
    isRunning = e.target.checked;
    updateTelemetryIndicator(isRunning);
    try {
      await chrome.storage.local.set({ phishops_enabled: isRunning });
    } catch (_) { /* ignore */ }
    if (isRunning) startHeartbeat();
  });

  // Canvas setup
  resize();
  window.addEventListener('resize', resize);
  draw();

  // Load real data
  await loadAndReplayEvents();

  // Live updates while popup is open
  try {
    chrome.storage.onChanged.addListener((changes) => {
      if (!changes[STORAGE_KEY]) return;
      const newEvents = changes[STORAGE_KEY].newValue || [];
      const added = newEvents.length - lastEventCount;
      lastEventCount = newEvents.length;

      // Update stats
      updateStats(newEvents);

      // Spawn packets for new events
      if (added > 0 && isRunning) {
        const fresh = newEvents.slice(0, Math.min(added, 5));
        fresh.forEach((evt, i) => {
          setTimeout(() => spawnEventPacket(evt), i * 120);
        });
      }
    });
  } catch (_) { /* non-extension context */ }
});

/* ── Data loading ───────────────────────────────────────────── */

async function loadAndReplayEvents() {
  let events = [];
  try {
    const data = await chrome.storage.local.get(STORAGE_KEY);
    events = data[STORAGE_KEY] || [];
  } catch (_) { /* non-extension context — show idle */ }

  lastEventCount = events.length;
  updateStats(events);

  if (events.length > 0 && isRunning) {
    // Replay recent events as an initial burst
    const recent = events.slice(0, 20);
    recent.reverse().forEach((evt, i) => {
      setTimeout(() => spawnEventPacket(evt), i * 120);
    });
  } else {
    startHeartbeat();
  }
}

function updateStats(events) {
  totalCount = events.length;
  highCount = events.filter(e => e.severity === 'High').length;
  criticalCount = events.filter(e => e.severity === 'Critical').length;

  setStatValue(totalEl, totalCount.toLocaleString());
  setStatValue(highEl, highCount.toLocaleString());
  setStatValue(criticalEl, criticalCount.toLocaleString());
}

function setStatValue(el, value) {
  if (el.textContent !== value) {
    el.textContent = value;
    triggerFlash(el);
  }
}

function triggerFlash(el) {
  el.classList.remove('stat-updated');
  void el.offsetWidth;
  el.classList.add('stat-updated');
}

function updateTelemetryIndicator(enabled) {
  if (enabled) {
    telemetryDot.style.backgroundColor = '#8b9e73';
    telemetryText.textContent = 'TELEMETRY: ROUTING';
  } else {
    telemetryDot.style.backgroundColor = '#646a70';
    telemetryText.textContent = 'TELEMETRY: PAUSED';
  }
}

/* ── Heartbeat (idle state) ─────────────────────────────────── */

function startHeartbeat() {
  if (heartbeatTimer) return;
  heartbeatTimer = setInterval(() => {
    if (!isRunning) return;
    packets.push({
      t: 0,
      speed: 0.002 + Math.random() * 0.002,
      pathIndex: Math.floor(Math.random() * paths.length),
      color: COLORS.packetNormal,
      size: 0.8,
      isThreat: false,
      label: null,
      labelAlpha: 0,
      labelColor: '',
    });
  }, 2500);
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

/* ── Packet spawning ────────────────────────────────────────── */

function spawnEventPacket(event) {
  if (!isRunning) return;

  stopHeartbeat();

  const severity = event.severity || 'Low';
  let color = COLORS.packetNormal;
  let size = 1.2;
  let isThreat = false;
  let label = null;
  let labelColor = '';

  if (severity === 'Critical') {
    color = COLORS.packetCritical;
    size = 2.5;
    isThreat = true;
    label = briefLabel(event);
    labelColor = 'rgba(194, 94, 94, ';
  } else if (severity === 'High') {
    color = COLORS.packetHigh;
    size = 2.0;
    isThreat = true;
    label = briefLabel(event);
    labelColor = 'rgba(181, 154, 109, ';
  }

  packets.push({
    t: 0,
    speed: 0.003 + Math.random() * 0.005,
    pathIndex: Math.floor(Math.random() * paths.length),
    color,
    size,
    isThreat,
    label,
    labelAlpha: 0,
    labelColor,
  });

  // Restart heartbeat after burst settles
  setTimeout(() => {
    if (packets.length < 3) startHeartbeat();
  }, 4000);
}

function briefLabel(event) {
  const typeLabel = EVENT_TYPE_LABELS[event.eventType] || event.eventType || '';
  const detail = briefDetail(event);
  const full = detail ? `${typeLabel}: ${detail}` : typeLabel;
  return full.length > 45 ? full.substring(0, 42) + '...' : full;
}

function briefDetail(event) {
  switch (event.eventType) {
    case 'OAUTH_DEVICE_CODE_FLOW':
      return event.endpoint || '';
    case 'OAUTH_STATE_EMAIL_ENCODED':
      return event.decodedEmail || '';
    case 'BLOB_URL_CREDENTIAL_PAGE':
      return (event.matchedBrands || []).join(', ') || '';
    case 'EXTENSION_OWNERSHIP_DRIFT':
      return `${event.previousHomepage || '?'} \u2192 ${event.currentHomepage || '?'}`;
    case 'PHISHVISION_BRAND_IMPERSONATION':
    case 'FAKESENDER_BRAND_IMPERSONATION':
    case 'IPFS_PHISHING_DETECTED':
    case 'PWA_PHISHING_DETECTED':
      return event.matchedBrand || '';
    case 'PROXY_AITM_DETECTED':
      return event.targetProvider || '';
    case 'PASSKEY_CREDENTIAL_INTERCEPTION':
      return event.rpId || '';
    case 'CLICKFIX_CLIPBOARD_INJECTION':
      return (event.payloadSnippet || '').substring(0, 30);
    case 'FILE_SYSTEM_PICKER_ABUSE_DETECTED':
      return (event.credentialFilesDetected || []).slice(0, 2).join(', ') ||
             `${event.fileCount || 0} files`;
    default:
      return (event.signals || []).slice(0, 2).join(', ');
  }
}

/* ── Canvas engine ──────────────────────────────────────────── */

function resize() {
  const rect = canvas.parentElement.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  width = rect.width;
  height = rect.height;
  initPaths();
}

function initPaths() {
  paths = [];
  for (let i = 0; i < 18; i++) {
    const spread = (Math.random() - 0.5) * height * 0.8;
    paths.push({
      p0: { x: -10, y: height / 2 },
      p1: { x: width * 0.3, y: height / 2 + spread },
      p2: { x: width * 0.7, y: height / 2 + spread },
      p3: { x: width - 20, y: height / 2 },
    });
  }
}

function getBezierPoint(t, p0, p1, p2, p3) {
  const u = 1 - t;
  return {
    x: u*u*u * p0.x + 3*u*u*t * p1.x + 3*u*t*t * p2.x + t*t*t * p3.x,
    y: u*u*u * p0.y + 3*u*u*t * p1.y + 3*u*t*t * p2.y + t*t*t * p3.y,
  };
}

function draw() {
  ctx.fillStyle = COLORS.bg;
  ctx.fillRect(0, 0, width, height);

  // Thread paths
  ctx.lineWidth = 0.5;
  ctx.strokeStyle = COLORS.thread;
  for (const p of paths) {
    ctx.beginPath();
    ctx.moveTo(p.p0.x, p.p0.y);
    ctx.bezierCurveTo(p.p1.x, p.p1.y, p.p2.x, p.p2.y, p.p3.x, p.p3.y);
    ctx.stroke();
  }

  // Packets
  for (let i = packets.length - 1; i >= 0; i--) {
    const p = packets[i];
    p.t += p.speed;
    if (p.t > 1) {
      packets.splice(i, 1);
      continue;
    }

    const path = paths[p.pathIndex];
    const pos = getBezierPoint(p.t, path.p0, path.p1, path.p2, path.p3);

    // Glow for threat packets
    if (p.isThreat) {
      ctx.shadowBlur = p.size === 2.5 ? 12 : 8;
      ctx.shadowColor = p.color;
    }

    ctx.fillStyle = p.color;
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, p.size, 0, Math.PI * 2);
    ctx.fill();
    ctx.shadowBlur = 0;

    // Threat label
    if (p.label && p.t > 0.15 && p.t < 0.85) {
      p.labelAlpha = Math.sin((p.t - 0.15) / 0.7 * Math.PI);
      ctx.fillStyle = p.labelColor + p.labelAlpha.toFixed(2) + ')';
      ctx.font = `8px ${MONO_FONT}`;
      ctx.fillText(p.label, pos.x + 8, pos.y - 8);
    }
  }

  requestAnimationFrame(draw);
}
