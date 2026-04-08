/**
 * extension/content/qrljacking_guard.js
 *
 * QRLjackingGuard — Detects real-time QR code session hijacking attacks.
 * Injected at document_idle.
 *
 * Attack chain this closes:
 *   Attacker creates a phishing page that continuously proxies a legitimate
 *   service's QR code (WhatsApp Web, Teams, Entra ID). The QR refreshes
 *   every 2–3 seconds to stay synchronized with the real session. When the
 *   victim scans the cloned QR, they authenticate the attacker's session.
 *
 * Detection model: Additive signal scoring across two categories:
 *   1. Image refresh analysis — rapid src/data changes on QR-like elements
 *   2. Page context           — auth text, device code references, origin checks
 *
 * References:
 *   - OWASP QRLjacking definition
 *   - Seraphic Security 2025: reverse-proxy QR architectures
 *   - Microsoft MSTIC: Storm-2372 Device Code Flow + QR delivery
 *   - Cofense: 587% quishing increase Q1 2024 vs Q1 2023
 *   - MITRE ATT&CK T1539 (Steal Web Session Cookie)
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;
const REFRESH_COUNT_THRESHOLD = 3;
const REFRESH_WINDOW_MS = 15000;
const QR_MIN_SIZE = 100;
const QR_MAX_SIZE = 500;
const ASPECT_RATIO_TOLERANCE = 0.20;

const KNOWN_QR_AUTH_PLATFORMS = [
  'web.whatsapp.com',
  'whatsapp.com',
  'teams.microsoft.com',
  'login.microsoftonline.com',
  'web.telegram.org',
  'discord.com',
  'accounts.google.com',
];

const DEVICE_CODE_PATTERNS = [
  /devicelogin/i,
  /devicecode/i,
  /device_authorization/i,
  /\/oauth2\/deviceauth/i,
];

const AUTH_CONTEXT_PATTERNS = [
  /\b(sign\s*in|log\s*in|authenticate|verify\s+your|scan\s+(this|the)\s+qr)\b/i,
  /\b(scan\s+with\s+your\s+phone|open\s+your\s+app|use\s+your\s+mobile)\b/i,
];

// ---------------------------------------------------------------------------
// Image refresh tracking (WeakMap to avoid memory leaks)
// ---------------------------------------------------------------------------

const refreshTracking = new WeakMap();

// ---------------------------------------------------------------------------
// Signal checks (exported for unit testing)
// ---------------------------------------------------------------------------

function isQRLikeElement(element) {
  if (!element) return false;
  const tag = element.tagName;
  if (tag !== 'IMG' && tag !== 'CANVAS') return false;

  let width, height;
  if (typeof element.getBoundingClientRect === 'function') {
    const rect = element.getBoundingClientRect();
    width = rect.width;
    height = rect.height;
  } else {
    width = element.width || 0;
    height = element.height || 0;
  }

  // Check size range
  if (width < QR_MIN_SIZE || width > QR_MAX_SIZE) return false;
  if (height < QR_MIN_SIZE || height > QR_MAX_SIZE) return false;

  // Check roughly square aspect ratio
  if (width === 0 || height === 0) return false;
  const ratio = width / height;
  if (ratio < (1 - ASPECT_RATIO_TOLERANCE) || ratio > (1 + ASPECT_RATIO_TOLERANCE)) return false;

  return true;
}

function trackImageRefresh(element) {
  const now = Date.now();
  let data = refreshTracking.get(element);

  if (!data) {
    data = { timestamps: [], count: 0 };
    refreshTracking.set(element, data);
  }

  data.timestamps.push(now);
  data.count++;

  // Prune old timestamps outside the window
  while (data.timestamps.length > 0 && now - data.timestamps[0] > REFRESH_WINDOW_MS) {
    data.timestamps.shift();
  }

  return {
    count: data.timestamps.length,
    interval: data.timestamps.length >= 2
      ? (data.timestamps[data.timestamps.length - 1] - data.timestamps[0]) / (data.timestamps.length - 1)
      : 0,
  };
}

function checkRefreshSignals(element, refreshData) {
  const signals = [];

  // Signal 1: Rapid image refresh
  if (refreshData.count >= REFRESH_COUNT_THRESHOLD) {
    signals.push({ id: 'qrljack:rapid_image_refresh', weight: 0.45 });
  }

  // Signal 2: Cross-origin image source
  if (element.tagName === 'IMG') {
    const src = element.getAttribute('src') || '';
    if (/^https?:\/\//i.test(src)) {
      try {
        const imgOrigin = new URL(src).origin;
        if (imgOrigin !== window.location.origin) {
          signals.push({ id: 'qrljack:cross_origin_image', weight: 0.25 });
        }
      } catch {
        // Invalid URL — treat as suspicious
        signals.push({ id: 'qrljack:cross_origin_image', weight: 0.25 });
      }
    }
  }

  // Signal 6: iframe QR proxy
  try {
    if (window.self !== window.top) {
      signals.push({ id: 'qrljack:iframe_qr_proxy', weight: 0.30 });
    }
  } catch {
    signals.push({ id: 'qrljack:iframe_qr_proxy', weight: 0.30 });
  }

  return signals;
}

function checkQRPageContext() {
  const signals = [];
  const bodyText = (document.body?.innerText || document.body?.textContent || '').toLowerCase();
  const pageHtml = document.documentElement?.innerHTML || '';

  // Signal 3: Auth page context
  for (const pattern of AUTH_CONTEXT_PATTERNS) {
    if (pattern.test(bodyText)) {
      signals.push({ id: 'qrljack:auth_page_context', weight: 0.20 });
      break;
    }
  }

  // Signal 4: Device code reference
  for (const pattern of DEVICE_CODE_PATTERNS) {
    if (pattern.test(bodyText) || pattern.test(pageHtml)) {
      signals.push({ id: 'qrljack:device_code_reference', weight: 0.30 });
      break;
    }
  }

  // Signal 5: Non-platform origin
  try {
    const hostname = window.location.hostname;
    const isKnownPlatform = KNOWN_QR_AUTH_PLATFORMS.some(
      platform => hostname === platform || hostname.endsWith('.' + platform),
    );
    if (!isKnownPlatform) {
      signals.push({ id: 'qrljack:non_platform_origin', weight: 0.25 });
    }
  } catch {
    signals.push({ id: 'qrljack:non_platform_origin', weight: 0.25 });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Risk score calculation (exported for unit testing)
// ---------------------------------------------------------------------------

function calculateQRLjackingRiskScore(signals) {
  let score = 0.0;
  const signalList = [];

  for (const signal of signals) {
    score += signal.weight;
    signalList.push(signal.id);
  }

  return {
    riskScore: Math.round(Math.min(score, 1.0) * 100) / 100,
    signalList,
  };
}

// ---------------------------------------------------------------------------
// Warning banner (exported for unit testing)
// ---------------------------------------------------------------------------

function injectQRLjackingWarningBanner(riskScore, element, signals) {
  if (document.getElementById('phishops-qrljacking-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-qrljacking-warning';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #0A0907; border-bottom: 2px solid #BF1B1B;
    padding: 14px 20px; font-family: 'Work Sans', system-ui, -apple-system, sans-serif;
    display: flex; align-items: center; gap: 14px;
  `;

  banner.innerHTML = `
    <span style="font-size: 24px; flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B; font-size:15px; display:block; margin-bottom:3px; font-family:'Work Sans',system-ui,sans-serif;">
        qr session hijacking detected \u2014 phishops qrljackingguard
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        This page contains a rapidly refreshing QR code \u2014 a technique used to
        hijack login sessions in real time. Do not scan this QR code.
        Risk score: ${riskScore.toFixed(2)}.
      </span>
    </div>
    <button id="phishops-qrljacking-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-qrljacking-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });

  // If block threshold, overlay the QR element itself
  if (riskScore >= BLOCK_THRESHOLD && element) {
    try {
      const rect = element.getBoundingClientRect();
      const overlay = document.createElement('div');
      overlay.className = 'phishops-qr-overlay';
      overlay.style.cssText = `
        position: fixed; z-index: 2147483646;
        top: ${rect.top}px; left: ${rect.left}px;
        width: ${rect.width}px; height: ${rect.height}px;
        background: #0A0907; border: 2px solid #BF1B1B;
        display: flex; align-items: center; justify-content: center;
        font-family: 'Work Sans', system-ui, sans-serif;
        font-size: 12px; color: #BF1B1B; text-align: center;
        padding: 8px;
      `;
      overlay.textContent = '\u26A0 QR blocked by PhishOps';
      document.body.appendChild(overlay);
    } catch {
      // Best effort overlay
    }
  }
}

// ---------------------------------------------------------------------------
// Telemetry emitter
// ---------------------------------------------------------------------------

function sendToBackground(payload) {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'QRLJACKING_EVENT',
        payload,
      });
    }
  } catch (err) {
    console.error('[QRLJACKING_GUARD] sendToBackground failed:', err);
  }
}

// ---------------------------------------------------------------------------
// False positive checks
// ---------------------------------------------------------------------------

function isKnownQRAuthPlatform() {
  try {
    const hostname = window.location.hostname;
    return KNOWN_QR_AUTH_PLATFORMS.some(
      platform => hostname === platform || hostname.endsWith('.' + platform),
    );
  } catch {
    return false;
  }
}

function isDevEnvironment() {
  try {
    const hostname = window.location.hostname;
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0';
  } catch {
    return false;
  }
}

function isVideoContext(element) {
  let parent = element?.parentElement;
  while (parent) {
    if (parent.tagName === 'VIDEO') return true;
    if (parent.classList?.contains('video-player')) return true;
    parent = parent.parentElement;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Detection handler
// ---------------------------------------------------------------------------

function handleSuspiciousRefresh(element, refreshData) {
  // False positive checks
  if (isKnownQRAuthPlatform() || isDevEnvironment() || isVideoContext(element)) return;

  const refreshSignals = checkRefreshSignals(element, refreshData);
  const pageSignals = checkQRPageContext();
  const allSignals = [...refreshSignals, ...pageSignals];
  const { riskScore, signalList } = calculateQRLjackingRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const telemetry = {
    eventType: 'QRLJACKING_SESSION_HIJACK',
    riskScore,
    severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium',
    refreshCount: refreshData.count,
    imageSource: (element.getAttribute('src') || '').substring(0, 200),
    signals: signalList,
    url: window.location.href.substring(0, 200),
    timestamp: new Date().toISOString(),
  };

  sendToBackground(telemetry);
  injectQRLjackingWarningBanner(riskScore, element, signalList);
}

// ---------------------------------------------------------------------------
// Main runner (exported for unit testing)
// ---------------------------------------------------------------------------

function runQRLjackingGuard() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      // Watch for src attribute changes on existing img/canvas elements
      if (mutation.type === 'attributes' && mutation.attributeName === 'src') {
        const element = mutation.target;
        if (!isQRLikeElement(element)) continue;

        const refreshData = trackImageRefresh(element);
        if (refreshData.count >= REFRESH_COUNT_THRESHOLD) {
          handleSuspiciousRefresh(element, refreshData);
        }
      }

      // Watch for new img/canvas elements being added
      if (mutation.type === 'childList') {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== 1) continue;

          // Check the node itself
          if (isQRLikeElement(node)) {
            trackImageRefresh(node);
          }

          // Check descendants
          if (node.querySelectorAll) {
            const images = node.querySelectorAll('img, canvas');
            for (const img of images) {
              if (isQRLikeElement(img)) {
                trackImageRefresh(img);
              }
            }
          }
        }
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['src', 'data'],
  });
}

// ---------------------------------------------------------------------------
// Auto-run when injected as a content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runQRLjackingGuard, { once: true });
  } else {
    runQRLjackingGuard();
  }
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['qrljacking_guard'] = {
    isQRLikeElement,
    trackImageRefresh,
    checkRefreshSignals,
    checkQRPageContext,
    calculateQRLjackingRiskScore,
    injectQRLjackingWarningBanner,
    runQRLjackingGuard,
  };
}

})();
