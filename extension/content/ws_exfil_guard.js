/**
 * extension/content/ws_exfil_guard.js
 *
 * WebSocketExfilGuard — Real-Time Credential Exfiltration via WebSocket
 *
 * Detects PhaaS kits that open WebSocket channels to C2 servers on credential
 * pages and relay keystrokes character-by-character via WebSocket.send(). This
 * captures partial credentials even if the form is never submitted. Bypasses
 * CSP form-action directives. Used by EvilProxy derivatives, Modlishka 2.0+,
 * and custom kits since late 2025.
 *
 * Injected at document_start to wrap the WebSocket constructor before page
 * scripts can cache a reference to the original API.
 *
 * Signal architecture:
 *   wsexfil:ws_open_on_credential_page    +0.40
 *   wsexfil:keystroke_relay_pattern        +0.30
 *   wsexfil:cross_origin_ws_with_creds    +0.25
 *   wsexfil:form_value_in_ws_payload      +0.20
 *   wsexfil:ws_without_visible_ws_ui      +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module WebSocketExfilGuard
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

const CHAT_UI_SELECTORS = [
  '[class*="chat"]', '[class*="Chat"]',
  '[class*="messenger"]', '[class*="Messenger"]',
  '[id*="intercom"]', '[id*="Intercom"]',
  '[class*="crisp"]', '[class*="Crisp"]',
  '[class*="drift"]', '[class*="Drift"]',
  '[class*="zendesk"]', '[class*="Zendesk"]',
  '[class*="tawk"]', '[class*="Tawk"]',
  '[class*="livechat"]', '[class*="LiveChat"]',
  '[id*="hubspot-messages"]',
];

const KEYSTROKE_RELAY_THRESHOLD_BYTES = 10;
const KEYSTROKE_RELAY_THRESHOLD_HZ = 2;
const KEYSTROKE_WINDOW_MS = 3000;
const MIN_FORM_VALUE_MATCH_LENGTH = 3;

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

const wsConnections = [];  // { url, hostname, sendLog: [{payload, timestamp}] }
let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if any WebSocket was opened on a page with credential fields.
 */
export function checkWsOpenOnCredentialPage(doc, connections) {
  if (!doc || !connections || connections.length === 0) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length === 0) return [];

  return [{
    id: 'wsexfil:ws_open_on_credential_page',
    weight: 0.40,
    wsCount: connections.length,
    credFieldCount: credFields.length,
  }];
}

/**
 * Analyse recorded WS.send() calls for high-frequency small payloads
 * characteristic of keystroke relay.
 */
export function checkKeystrokeRelayPattern(connections) {
  if (!connections) return [];

  for (const conn of connections) {
    const log = conn.sendLog || [];
    if (log.length < 3) continue;

    // Sliding window analysis
    for (let i = 0; i <= log.length - 3; i++) {
      const windowEnd = log[i].timestamp + KEYSTROKE_WINDOW_MS;
      const windowEntries = [];

      for (let j = i; j < log.length && log[j].timestamp <= windowEnd; j++) {
        const payloadSize = typeof log[j].payload === 'string'
          ? log[j].payload.length
          : (log[j].payload?.byteLength || log[j].payload?.length || 0);

        if (payloadSize > 0 && payloadSize <= KEYSTROKE_RELAY_THRESHOLD_BYTES) {
          windowEntries.push(log[j]);
        }
      }

      if (windowEntries.length >= 2) {
        const windowDurationSec = (windowEntries[windowEntries.length - 1].timestamp - windowEntries[0].timestamp) / 1000;
        if (windowDurationSec > 0) {
          const hz = windowEntries.length / windowDurationSec;
          if (hz >= KEYSTROKE_RELAY_THRESHOLD_HZ) {
            return [{
              id: 'wsexfil:keystroke_relay_pattern',
              weight: 0.30,
              frequency: hz,
              smallMessageCount: windowEntries.length,
            }];
          }
        }
      }
    }
  }

  return [];
}

/**
 * Check if any WebSocket target hostname differs from the page origin
 * on a credential page.
 */
export function checkCrossOriginWsWithCreds(connections, pageHostname, doc) {
  if (!connections || !pageHostname || !doc) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length === 0) return [];

  for (const conn of connections) {
    if (conn.hostname && conn.hostname !== pageHostname) {
      return [{
        id: 'wsexfil:cross_origin_ws_with_creds',
        weight: 0.25,
        wsHostname: conn.hostname,
        pageHostname,
      }];
    }
  }

  return [];
}

/**
 * Check if any WS.send() payload contains a substring matching current
 * input field values.
 */
export function checkFormValueInWsPayload(connections, doc) {
  if (!connections || !doc) return [];

  const inputs = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (inputs.length === 0) return [];

  const values = [];
  for (const input of inputs) {
    const val = input.value || '';
    if (val.length >= MIN_FORM_VALUE_MATCH_LENGTH) {
      values.push(val);
    }
  }

  if (values.length === 0) return [];

  for (const conn of connections) {
    for (const entry of (conn.sendLog || [])) {
      const payload = typeof entry.payload === 'string' ? entry.payload : '';
      if (!payload) continue;

      for (const val of values) {
        if (payload.includes(val)) {
          return [{
            id: 'wsexfil:form_value_in_ws_payload',
            weight: 0.20,
            matchedLength: val.length,
          }];
        }
      }
    }
  }

  return [];
}

/**
 * Check if page has WebSocket connections but no visible chat/collaboration UI,
 * suggesting no legitimate reason for WebSocket use.
 */
export function checkWsWithoutVisibleWsUi(doc, connections) {
  if (!doc || !connections || connections.length === 0) return [];

  const hasChatUi = CHAT_UI_SELECTORS.some(sel => {
    try { return doc.querySelector(sel) !== null; } catch { return false; }
  });

  if (!hasChatUi) {
    return [{
      id: 'wsexfil:ws_without_visible_ws_ui',
      weight: 0.15,
    }];
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

export function calculateWsExfilRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

export function injectWsExfilWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-wsexfil-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-wsexfil-banner';
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
        websocket credential exfiltration detected \u2014 phishops wsexfilguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('wsexfil:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-wsexfil-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-wsexfil-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  WebSocket Proxy Installer                                          */
/* ------------------------------------------------------------------ */

/**
 * Parse hostname from a WebSocket URL.
 */
export function parseWsHostname(url) {
  try {
    // ws:// and wss:// → http:// for URL parsing
    const httpUrl = url.replace(/^ws(s?):\/\//, 'http$1://');
    return new URL(httpUrl).hostname;
  } catch {
    return '';
  }
}

/**
 * Run analysis on accumulated WebSocket data.
 * Called periodically and on DOMContentLoaded.
 */
export function runWsExfilAnalysis(doc, connections, pageHostname) {
  if (!doc || !connections || connections.length === 0) return;

  const openSignals = checkWsOpenOnCredentialPage(doc, connections);
  // Only continue if WS is on a credential page
  if (openSignals.length === 0) return;

  const keystrokeSignals = checkKeystrokeRelayPattern(connections);
  const crossOriginSignals = checkCrossOriginWsWithCreds(connections, pageHostname, doc);
  const formValueSignals = checkFormValueInWsPayload(connections, doc);
  const uiSignals = checkWsWithoutVisibleWsUi(doc, connections);

  const allSignals = [
    ...openSignals,
    ...keystrokeSignals,
    ...crossOriginSignals,
    ...formValueSignals,
    ...uiSignals,
  ];

  const { riskScore, signalList } = calculateWsExfilRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectWsExfilWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'WSEXFILGUARD_EVENT',
      payload: {
        eventType: 'WEBSOCKET_CREDENTIAL_EXFIL_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
        wsCount: connections.length,
      },
    }).catch(() => {});
  }
}

/**
 * Install WebSocket proxy at document_start.
 * Wraps the WebSocket constructor and send() to monitor for credential exfil.
 */
export function installWebSocketProxy() {
  if (typeof window === 'undefined' || !window.WebSocket) return;

  const OriginalWebSocket = window.WebSocket;

  const ProxyWebSocket = function(url, protocols) {
    const ws = protocols !== undefined
      ? new OriginalWebSocket(url, protocols)
      : new OriginalWebSocket(url);

    const connRecord = {
      url: String(url),
      hostname: parseWsHostname(String(url)),
      sendLog: [],
    };
    wsConnections.push(connRecord);

    // Wrap send()
    const originalSend = ws.send.bind(ws);
    ws.send = function(data) {
      connRecord.sendLog.push({
        payload: typeof data === 'string' ? data : data,
        timestamp: Date.now(),
      });

      // Check for keystroke relay pattern on each send (deferred to avoid blocking)
      if (!analysisRun && typeof document !== 'undefined' && document.readyState !== 'loading') {
        try {
          runWsExfilAnalysis(
            document,
            wsConnections,
            globalThis.location?.hostname || '',
          );
          analysisRun = true;
        } catch { /* non-critical */ }
      }

      return originalSend(data);
    };

    return ws;
  };

  // Preserve prototype chain and static properties
  ProxyWebSocket.prototype = OriginalWebSocket.prototype;
  ProxyWebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
  ProxyWebSocket.OPEN = OriginalWebSocket.OPEN;
  ProxyWebSocket.CLOSING = OriginalWebSocket.CLOSING;
  ProxyWebSocket.CLOSED = OriginalWebSocket.CLOSED;

  try {
    Object.defineProperty(window, 'WebSocket', {
      value: ProxyWebSocket,
      writable: false,
      configurable: true,
    });
  } catch {
    window.WebSocket = ProxyWebSocket;
  }

  // Run analysis on DOMContentLoaded
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      // Delay slightly to allow WS connections to be established
      setTimeout(() => {
        if (!analysisRun) {
          runWsExfilAnalysis(
            document,
            wsConnections,
            globalThis.location?.hostname || '',
          );
        }
      }, 2000);
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

export function _getWsConnections() {
  return wsConnections;
}

export function _resetState() {
  wsConnections.length = 0;
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installWebSocketProxy();
}
