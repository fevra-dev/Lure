/**
 * extension/content/vnc_guard.js
 *
 * VNCGuard — EvilnoVNC WebSocket AiTM Detection
 *
 * Detects EvilnoVNC phishing attacks that proxy a real browser session via
 * WebSocket/noVNC to the victim's browser. The victim sees a genuine login
 * page rendered as a VNC canvas stream — not a cloned page. Since the victim
 * interacts with a real IdP rendered remotely, traditional URL/DOM analysis
 * fails. However, EvilnoVNC pages exhibit unique browser-observable tells:
 * noVNC library signatures, canvas-as-primary-interaction, WebSocket to
 * non-standard ports, and RFB protocol strings. Exploited by Storm-1811
 * and TA577 since mid-2025 (Mandiant M-Trends 2026).
 *
 * Signal architecture:
 *   vnc:novnc_library_detected          +0.40
 *   vnc:canvas_primary_interaction      +0.30
 *   vnc:websocket_to_nonstandard_port   +0.25
 *   vnc:rfb_protocol_indicators         +0.20
 *   vnc:login_context_without_forms     +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module VNCGuard
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const NOVNC_SCRIPT_PATTERNS = [
  /noVNC/i,
  /rfb\.js/i,
  /websock\.js/i,
  /display\.js/i,
  /vnc_lite\.html/i,
];

const NOVNC_GLOBAL_SIGNATURES = ['RFB', 'Websock', 'Display', 'Keyboard', 'Mouse'];

const RFB_PROTOCOL_STRINGS = [
  'RFB 003', 'rfb', 'tight', 'copyrect', 'zrle', 'hextile', 'raw encoding',
];

const VNC_PORTS = new Set([
  5900, 5901, 5902, 5903, 5904, 5905,
  6080, 6081, 6082, 6083, 6090,
  8080, 8443,
]);

const CANVAS_VIEWPORT_RATIO_THRESHOLD = 0.80;

const LOGIN_TEXT_PATTERNS = [
  /sign\s*in/i,
  /log\s*in/i,
  /password/i,
  /username/i,
  /enter\s+your\s+(email|credentials)/i,
];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if page loads noVNC library files or contains noVNC-specific globals.
 */
function checkNoVncLibraryDetected(doc) {
  if (!doc) return [];

  // Check script src attributes
  const scripts = doc.querySelectorAll('script[src]');
  for (const script of scripts) {
    const src = script.getAttribute('src') || '';
    if (NOVNC_SCRIPT_PATTERNS.some(p => p.test(src))) {
      return [{
        id: 'vnc:novnc_library_detected',
        weight: 0.40,
        source: 'script_src',
        matched: src.substring(0, 200),
      }];
    }
  }

  // Check inline script content for noVNC references
  const inlineScripts = doc.querySelectorAll('script:not([src])');
  for (const script of inlineScripts) {
    const content = script.textContent || '';
    if (NOVNC_SCRIPT_PATTERNS.some(p => p.test(content))) {
      return [{
        id: 'vnc:novnc_library_detected',
        weight: 0.40,
        source: 'inline_script',
      }];
    }

    // Check for noVNC global constructor references
    if (NOVNC_GLOBAL_SIGNATURES.some(sig =>
      content.includes(`new ${sig}(`) || content.includes(`${sig}.prototype`)
    )) {
      return [{
        id: 'vnc:novnc_library_detected',
        weight: 0.40,
        source: 'global_signature',
      }];
    }
  }

  return [];
}

/**
 * Check if a single large canvas element is the primary interactive surface.
 * EvilnoVNC renders the remote session on a canvas with keyboard/mouse listeners,
 * with zero standard input elements.
 */
function checkCanvasPrimaryInteraction(doc) {
  if (!doc || !doc.body) return [];

  const canvases = doc.querySelectorAll('canvas');
  if (canvases.length === 0) return [];

  const inputs = doc.querySelectorAll('input, textarea, select');
  if (inputs.length > 0) return []; // Real forms present — not a VNC page

  // Check for a large canvas
  for (const canvas of canvases) {
    const width = canvas.width || parseInt(canvas.getAttribute('width') || '0');
    const height = canvas.height || parseInt(canvas.getAttribute('height') || '0');

    // Estimate viewport coverage (use reasonable defaults if window unavailable)
    const vpWidth = globalThis.innerWidth || 1280;
    const vpHeight = globalThis.innerHeight || 720;

    const coverage = (width * height) / (vpWidth * vpHeight);
    if (coverage >= CANVAS_VIEWPORT_RATIO_THRESHOLD) {
      return [{
        id: 'vnc:canvas_primary_interaction',
        weight: 0.30,
        canvasSize: `${width}x${height}`,
        coverage: coverage,
      }];
    }
  }

  return [];
}

/**
 * Check for WebSocket connections to non-standard ports in page scripts.
 * VNC typically uses ports 5900-5905 or 6080-6090 for WebSocket relay.
 */
function checkWebSocketToNonStandardPort(doc) {
  if (!doc) return [];

  const scripts = doc.querySelectorAll('script');
  const wsPattern = /new\s+WebSocket\s*\(\s*['"`]wss?:\/\/[^'"`]*:(\d+)/gi;

  for (const script of scripts) {
    const content = script.textContent || '';
    let match;

    while ((match = wsPattern.exec(content)) !== null) {
      const port = parseInt(match[1], 10);
      if (VNC_PORTS.has(port)) {
        return [{
          id: 'vnc:websocket_to_nonstandard_port',
          weight: 0.25,
          port,
        }];
      }
    }
  }

  return [];
}

/**
 * Check for RFB protocol indicators in page DOM or script content.
 */
function checkRfbProtocolIndicators(doc) {
  if (!doc) return [];

  // Check inline scripts
  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const content = script.textContent || '';
    for (const rfbStr of RFB_PROTOCOL_STRINGS) {
      if (content.includes(rfbStr)) {
        return [{
          id: 'vnc:rfb_protocol_indicators',
          weight: 0.20,
          matched: rfbStr,
          source: 'script',
        }];
      }
    }
  }

  // Check page text (less common but possible)
  const bodyText = doc.body?.innerText || doc.body?.textContent || '';
  for (const rfbStr of RFB_PROTOCOL_STRINGS) {
    if (bodyText.includes(rfbStr)) {
      return [{
        id: 'vnc:rfb_protocol_indicators',
        weight: 0.20,
        matched: rfbStr,
        source: 'body_text',
      }];
    }
  }

  return [];
}

/**
 * Check if page has login context (text about signing in) but zero form elements.
 * VNC pages display a real login page visually but have no local form elements.
 */
function checkLoginContextWithoutForms(doc) {
  if (!doc || !doc.body) return [];

  const forms = doc.querySelectorAll('form');
  const inputs = doc.querySelectorAll('input');
  if (forms.length > 0 || inputs.length > 0) return [];

  const bodyText = doc.body?.innerText || doc.body?.textContent || '';
  const title = doc.title || '';
  const combinedText = title + ' ' + bodyText;

  const hasLoginContext = LOGIN_TEXT_PATTERNS.some(p => p.test(combinedText));

  if (hasLoginContext) {
    return [{
      id: 'vnc:login_context_without_forms',
      weight: 0.15,
    }];
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

/**
 * Calculate composite risk score from signal array.
 * @param {Array<{id: string, weight: number}>} signals
 * @returns {{ riskScore: number, signalList: string[] }}
 */
function calculateVncRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

/**
 * Inject a warning banner into the page.
 */
function injectVncWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-vnc-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-vnc-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected VNC-Based Phishing (EvilnoVNC)</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('vnc:', '')).join(', ')}
    </div>
    <button id="phishops-vnc-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-vnc-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Run full VNCGuard analysis on the current page.
 */
function runVncGuardAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname) return;

  const doc = document;

  const librarySignals = checkNoVncLibraryDetected(doc);
  const canvasSignals = checkCanvasPrimaryInteraction(doc);
  const wsSignals = checkWebSocketToNonStandardPort(doc);
  const rfbSignals = checkRfbProtocolIndicators(doc);
  const loginSignals = checkLoginContextWithoutForms(doc);

  const allSignals = [
    ...librarySignals,
    ...canvasSignals,
    ...wsSignals,
    ...rfbSignals,
    ...loginSignals,
  ];

  const { riskScore, signalList } = calculateVncRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectVncWarningBanner(riskScore, allSignals);

  // Emit telemetry
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'VNCGUARD_EVENT',
      payload: {
        eventType: 'VNC_AITM_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: globalThis.location?.href || '',
        timestamp: new Date().toISOString(),
        action,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof document !== 'undefined' && typeof process === 'undefined') {
  runVncGuardAnalysis();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['vnc_guard'] = {
    checkNoVncLibraryDetected,
    checkCanvasPrimaryInteraction,
    checkWebSocketToNonStandardPort,
    checkRfbProtocolIndicators,
    checkLoginContextWithoutForms,
    calculateVncRiskScore,
    injectVncWarningBanner,
    runVncGuardAnalysis,
  };
}
