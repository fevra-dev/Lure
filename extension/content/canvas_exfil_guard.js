/**
 * extension/content/canvas_exfil_guard.js
 *
 * CanvasExfilGuard — Canvas Credential Exfiltration Detection
 *
 * Detects credential-shaped POST payloads exfiltrated via fetch, XHR,
 * sendBeacon, or Image pixel tracking from pages that use canvas-rendered
 * UI with no DOM input fields. This is the final step of the canvas
 * phishing kill chain: render form on canvas → capture keystrokes →
 * exfiltrate credentials.
 *
 * Distinct from existing guards:
 *   - etherhiding_guard.js wraps fetch/XHR but only inspects blockchain RPC
 *   - ws_exfil_guard.js wraps WebSocket only
 *   - webtransport_guard.js wraps WebTransport only
 *
 * Injected at document_start in the isolated world to wrap APIs before
 * page scripts cache references.
 *
 * Signal architecture:
 *   cxg:post_with_credential_fields        +0.40
 *   cxg:cross_origin_post_from_canvas_page +0.30
 *   cxg:beacon_from_canvas_page            +0.25
 *   cxg:small_json_post_pattern            +0.20
 *   cxg:image_pixel_exfil_pattern          +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module CanvasExfilGuard
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const CREDENTIAL_SELECTORS =
  'input[type="password"], input[type="email"], ' +
  'input[autocomplete="current-password"], input[autocomplete="new-password"], ' +
  'input[autocomplete="username"]';

const CREDENTIAL_FIELD_KEYS = new Set([
  'password', 'passwd', 'pass', 'pwd', 'passwort',
  'email', 'e-mail', 'mail',
  'user', 'username', 'user_name', 'userid', 'user_id',
  'login', 'logon', 'credential', 'secret',
]);

const LOGIN_CONTEXT_PATTERNS = [
  /sign[\s-]?in/i, /log[\s-]?in/i, /log[\s-]?on/i, /password/i,
  /credential/i, /authenticate/i, /verification/i,
  /account[\s-]?access/i, /secure[\s-]?login/i,
];

const MAX_SMALL_JSON_BYTES = 500;
const MIN_SMALL_JSON_KEYS = 2;
const MAX_SMALL_JSON_KEYS = 5;

const BODY_TEXT_LIMIT = 5000;

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

/**
 * Logged network requests from pages with canvas + no DOM inputs.
 * @type {{ method: string, url: string, bodySnippet: string, bodyLength: number, channel: string, timestamp: number }[]}
 */
const exfilRecords = [];

let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Helper Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if the current page has canvas element(s) and no DOM credential fields.
 */
export function isCanvasPageWithoutDomInputs(doc) {
  if (!doc) return false;

  const canvases = doc.querySelectorAll('canvas');
  if (canvases.length === 0) return false;

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  return credFields.length === 0;
}

/**
 * Check if the page has login/auth context via URL, title, or body text.
 */
export function hasLoginContext(doc) {
  if (!doc) return false;

  const url = (doc.location?.href || '').toLowerCase();
  const title = (doc.title || '').toLowerCase();

  for (const pattern of LOGIN_CONTEXT_PATTERNS) {
    if (pattern.test(url) || pattern.test(title)) return true;
  }

  const bodyText = (doc.body?.textContent || '').substring(0, BODY_TEXT_LIMIT);
  for (const pattern of LOGIN_CONTEXT_PATTERNS) {
    if (pattern.test(bodyText)) return true;
  }

  return false;
}

/**
 * Try to extract keys from a body string (JSON or form-encoded).
 */
export function extractBodyKeys(body) {
  if (!body || typeof body !== 'string') return [];

  // Try JSON
  try {
    const parsed = JSON.parse(body);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return Object.keys(parsed).map(k => k.toLowerCase());
    }
  } catch { /* not JSON */ }

  // Try form-encoded
  if (body.includes('=')) {
    return body.split('&')
      .map(pair => pair.split('=')[0]?.toLowerCase())
      .filter(Boolean);
  }

  return [];
}

/**
 * Parse hostname from URL, return empty on failure.
 */
export function parseHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Signal 1: POST body contains credential-like field keys on canvas page.
 * Weight: 0.40
 */
export function checkPostWithCredentialFields(records) {
  if (!records || records.length === 0) return [];

  for (const rec of records) {
    if (rec.method !== 'POST') continue;
    const keys = extractBodyKeys(rec.bodySnippet);
    for (const key of keys) {
      if (CREDENTIAL_FIELD_KEYS.has(key)) {
        return [{
          id: 'cxg:post_with_credential_fields',
          weight: 0.40,
          matchedKey: key,
          url: rec.url,
        }];
      }
    }
  }

  return [];
}

/**
 * Signal 2: POST request to a different hostname from a canvas page.
 * Weight: 0.30
 */
export function checkCrossOriginPostFromCanvasPage(records, pageHostname) {
  if (!records || records.length === 0 || !pageHostname) return [];

  for (const rec of records) {
    if (rec.method !== 'POST') continue;
    const targetHost = parseHostname(rec.url);
    if (targetHost && targetHost !== pageHostname) {
      return [{
        id: 'cxg:cross_origin_post_from_canvas_page',
        weight: 0.30,
        targetHost,
        pageHostname,
      }];
    }
  }

  return [];
}

/**
 * Signal 3: sendBeacon called on a canvas page with login context.
 * Weight: 0.25
 */
export function checkBeaconFromCanvasPage(records, doc) {
  if (!records || records.length === 0 || !doc) return [];

  if (!hasLoginContext(doc)) return [];

  for (const rec of records) {
    if (rec.channel === 'beacon') {
      return [{
        id: 'cxg:beacon_from_canvas_page',
        weight: 0.25,
        url: rec.url,
      }];
    }
  }

  return [];
}

/**
 * Signal 4: POST body is small JSON (<500 bytes) with 2-5 key-value pairs.
 * Weight: 0.20
 */
export function checkSmallJsonPostPattern(records) {
  if (!records || records.length === 0) return [];

  for (const rec of records) {
    if (rec.method !== 'POST') continue;
    if (rec.bodyLength > MAX_SMALL_JSON_BYTES) continue;

    try {
      const parsed = JSON.parse(rec.bodySnippet);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const keyCount = Object.keys(parsed).length;
        if (keyCount >= MIN_SMALL_JSON_KEYS && keyCount <= MAX_SMALL_JSON_KEYS) {
          return [{
            id: 'cxg:small_json_post_pattern',
            weight: 0.20,
            keyCount,
            bodyLength: rec.bodyLength,
          }];
        }
      }
    } catch { /* not JSON */ }
  }

  return [];
}

/**
 * Signal 5: Image.src set to URL with credential-like query param keys.
 * Weight: 0.15
 */
export function checkImagePixelExfilPattern(records) {
  if (!records || records.length === 0) return [];

  for (const rec of records) {
    if (rec.channel !== 'image') continue;

    try {
      const url = new URL(rec.url);
      for (const [key] of url.searchParams) {
        if (CREDENTIAL_FIELD_KEYS.has(key.toLowerCase())) {
          return [{
            id: 'cxg:image_pixel_exfil_pattern',
            weight: 0.15,
            matchedKey: key,
            url: rec.url,
          }];
        }
      }
    } catch { /* invalid URL */ }
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

export function calculateCxgRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

export function injectCxgWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-cxg-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-cxg-banner';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#0A0907', 'border-bottom:2px solid #BF1B1B',
    'padding:14px 20px',
    "font-family:'Work Sans',system-ui,-apple-system,sans-serif",
    'display:flex', 'align-items:center', 'gap:14px',
  ].join(';');

  banner.innerHTML = `
    <span style="font-size:24px;flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B;font-size:15px;display:block;margin-bottom:3px;font-family:'Work Sans',system-ui,sans-serif;">
        canvas credential exfiltration detected \u2014 phishops canvasexfilguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('cxg:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-cxg-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-cxg-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run analysis on accumulated exfiltration records.
 */
export function runCxgAnalysis(doc, records, pageHostname) {
  if (!doc || !records || records.length === 0) return;

  const credFieldSignals = checkPostWithCredentialFields(records);
  const crossOriginSignals = checkCrossOriginPostFromCanvasPage(records, pageHostname);
  const beaconSignals = checkBeaconFromCanvasPage(records, doc);
  const smallJsonSignals = checkSmallJsonPostPattern(records);
  const imagePixelSignals = checkImagePixelExfilPattern(records);

  const allSignals = [
    ...credFieldSignals,
    ...crossOriginSignals,
    ...beaconSignals,
    ...smallJsonSignals,
    ...imagePixelSignals,
  ];

  const { riskScore, signalList } = calculateCxgRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectCxgWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'CANVASEXFILGUARD_EVENT',
      payload: {
        eventType: 'CANVAS_CREDENTIAL_EXFIL_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
        exfilCount: records.length,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Network Proxy Installer                                            */
/* ------------------------------------------------------------------ */

/**
 * Stringify a body value for analysis (first 500 chars).
 */
function bodyToSnippet(body) {
  if (!body) return '';
  if (typeof body === 'string') return body.substring(0, MAX_SMALL_JSON_BYTES);
  if (body instanceof URLSearchParams) return body.toString().substring(0, MAX_SMALL_JSON_BYTES);
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    const parts = [];
    body.forEach((val, key) => parts.push(`${key}=${val}`));
    return parts.join('&').substring(0, MAX_SMALL_JSON_BYTES);
  }
  try { return String(body).substring(0, MAX_SMALL_JSON_BYTES); } catch { return ''; }
}

function bodyLength(body) {
  if (!body) return 0;
  if (typeof body === 'string') return body.length;
  if (body instanceof URLSearchParams) return body.toString().length;
  try { return String(body).length; } catch { return 0; }
}

/**
 * Record a network request if we're on a canvas page with no DOM inputs.
 */
function maybeRecordExfil(method, url, body, channel) {
  if (typeof document === 'undefined') return;
  if (!isCanvasPageWithoutDomInputs(document)) return;

  const snippet = bodyToSnippet(body);
  exfilRecords.push({
    method: (method || 'GET').toUpperCase(),
    url: String(url || ''),
    bodySnippet: snippet,
    bodyLength: bodyLength(body),
    channel: channel || 'fetch',
    timestamp: Date.now(),
  });

  // Trigger analysis if DOM ready and not yet run
  if (!analysisRun && document.readyState !== 'loading') {
    try {
      runCxgAnalysis(
        document,
        exfilRecords,
        (typeof globalThis !== 'undefined' && globalThis.location?.hostname) || '',
      );
      analysisRun = true;
    } catch { /* non-critical */ }
  }
}

/**
 * Install network proxy wrappers for fetch, XHR, sendBeacon, and Image.
 */
export function installExfilProxies() {
  // Wrap fetch
  if (typeof window !== 'undefined' && window.fetch) {
    const origFetch = window.fetch;
    window.fetch = function(input, init) {
      const url = typeof input === 'string' ? input : input?.url || '';
      const method = init?.method || (typeof input === 'object' ? input?.method : '') || 'GET';
      const body = init?.body || null;
      maybeRecordExfil(method, url, body, 'fetch');
      return origFetch.apply(this, arguments);
    };
  }

  // Wrap XMLHttpRequest
  if (typeof XMLHttpRequest !== 'undefined') {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url) {
      this._cxgMethod = method;
      this._cxgUrl = url;
      return origOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function(body) {
      if (this._cxgMethod && this._cxgUrl) {
        maybeRecordExfil(this._cxgMethod, this._cxgUrl, body, 'xhr');
      }
      return origSend.apply(this, arguments);
    };
  }

  // Wrap navigator.sendBeacon
  if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {
      maybeRecordExfil('POST', url, data, 'beacon');
      return origBeacon(url, data);
    };
  }

  // Wrap Image constructor for pixel exfil
  if (typeof window !== 'undefined' && window.Image) {
    const OriginalImage = window.Image;
    window.Image = function(width, height) {
      const img = new OriginalImage(width, height);
      const origSrcDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
      if (origSrcDescriptor?.set) {
        Object.defineProperty(img, 'src', {
          set(val) {
            maybeRecordExfil('GET', val, null, 'image');
            origSrcDescriptor.set.call(this, val);
          },
          get() {
            return origSrcDescriptor.get?.call(this) || '';
          },
          configurable: true,
        });
      }
      return img;
    };
    window.Image.prototype = OriginalImage.prototype;
  }

  // Run analysis on DOMContentLoaded + 2s
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        if (!analysisRun && exfilRecords.length > 0) {
          runCxgAnalysis(
            document,
            exfilRecords,
            (typeof globalThis !== 'undefined' && globalThis.location?.hostname) || '',
          );
          analysisRun = true;
        }
      }, 2000);
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

export function _getExfilRecords() {
  return exfilRecords;
}

export function _resetState() {
  exfilRecords.length = 0;
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installExfilProxies();
}
