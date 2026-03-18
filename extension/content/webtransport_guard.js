/**
 * extension/content/webtransport_guard.js
 *
 * WebTransportGuard — WebTransport AiTM Credential Relay Detection
 *
 * Detects phishing kits that use WebTransport (HTTP/3 QUIC) to relay credentials
 * from victim browsers to attacker C2. WebTransport offers 0-RTT setup, multiplexed
 * streams, unreliable datagrams, and self-signed certificate support — meaningful
 * advantages over WebSocket for AiTM credential relay. The serverCertificateHashes
 * option allows connections to ephemeral attacker infrastructure with no CA chain.
 *
 * Injected at document_start to wrap the WebTransport constructor before page
 * scripts can cache a reference to the original API.
 *
 * Signal architecture:
 *   wt:transport_on_credential_page       +0.40
 *   wt:self_signed_cert_hashes            +0.30
 *   wt:cross_origin_transport_with_creds  +0.25
 *   wt:credential_data_in_stream          +0.20
 *   wt:transport_without_media_context    +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module WebTransportGuard
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

const MEDIA_CONTEXT_SELECTORS = [
  'video', 'canvas',
  '[class*="player"]', '[class*="Player"]',
  '[class*="stream"]', '[class*="Stream"]',
  '[class*="game"]', '[class*="Game"]',
  '[class*="conference"]', '[class*="Conference"]',
  '[class*="twitch"]', '[class*="Twitch"]',
  '[id*="twitch"]', '[id*="Twitch"]',
  '[class*="webrtc"]', '[class*="WebRTC"]',
];

const MIN_FORM_VALUE_MATCH_LENGTH = 3;

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

const wtConnections = [];  // { url, hostname, usesHashCerts, writeLog: [{payload, timestamp}] }
let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if any WebTransport connection exists on a page with credential fields.
 */
export function checkTransportOnCredentialPage(doc, connections) {
  if (!doc || !connections || connections.length === 0) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length === 0) return [];

  return [{
    id: 'wt:transport_on_credential_page',
    weight: 0.40,
    wtCount: connections.length,
    credFieldCount: credFields.length,
  }];
}

/**
 * Check if any connection used serverCertificateHashes (self-signed certs).
 * Legitimate services use standard PKI; hash-pinned connections to unknown
 * servers indicate attacker-controlled ephemeral infrastructure.
 */
export function checkSelfSignedCertHashes(connections) {
  if (!connections || connections.length === 0) return [];

  for (const conn of connections) {
    if (conn.usesHashCerts) {
      return [{
        id: 'wt:self_signed_cert_hashes',
        weight: 0.30,
      }];
    }
  }

  return [];
}

/**
 * Check if any WebTransport target hostname differs from the page origin
 * on a credential page.
 */
export function checkCrossOriginTransportWithCreds(connections, pageHostname, doc) {
  if (!connections || !pageHostname || !doc) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length === 0) return [];

  for (const conn of connections) {
    if (conn.hostname && conn.hostname !== pageHostname) {
      return [{
        id: 'wt:cross_origin_transport_with_creds',
        weight: 0.25,
        wtHostname: conn.hostname,
        pageHostname,
      }];
    }
  }

  return [];
}

/**
 * Check if any stream/datagram write payload contains a substring matching
 * current credential field values.
 */
export function checkCredentialDataInStream(connections, doc) {
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
    for (const entry of (conn.writeLog || [])) {
      const payload = typeof entry.payload === 'string' ? entry.payload : '';
      if (!payload) continue;

      for (const val of values) {
        if (payload.includes(val)) {
          return [{
            id: 'wt:credential_data_in_stream',
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
 * Check if page has WebTransport connections but no visible media/streaming
 * context, suggesting no legitimate reason for WebTransport use.
 */
export function checkTransportWithoutMediaContext(doc, connections) {
  if (!doc || !connections || connections.length === 0) return [];

  const hasMediaContext = MEDIA_CONTEXT_SELECTORS.some(sel => {
    try { return doc.querySelector(sel) !== null; } catch { return false; }
  });

  if (!hasMediaContext) {
    return [{
      id: 'wt:transport_without_media_context',
      weight: 0.15,
    }];
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

export function calculateWtRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

export function injectWtWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-wt-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-wt-banner';
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
        webtransport credential relay detected \u2014 phishops webtransportguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('wt:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-wt-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-wt-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  URL Parsing                                                        */
/* ------------------------------------------------------------------ */

/**
 * Parse hostname from a WebTransport URL (https:// scheme).
 */
export function parseWtHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run analysis on accumulated WebTransport data.
 * Called periodically and on DOMContentLoaded.
 */
export function runWtAnalysis(doc, connections, pageHostname) {
  if (!doc || !connections || connections.length === 0) return;

  const transportSignals = checkTransportOnCredentialPage(doc, connections);
  // Only continue if WT is on a credential page
  if (transportSignals.length === 0) return;

  const certSignals = checkSelfSignedCertHashes(connections);
  const crossOriginSignals = checkCrossOriginTransportWithCreds(connections, pageHostname, doc);
  const dataSignals = checkCredentialDataInStream(connections, doc);
  const contextSignals = checkTransportWithoutMediaContext(doc, connections);

  const allSignals = [
    ...transportSignals,
    ...certSignals,
    ...crossOriginSignals,
    ...dataSignals,
    ...contextSignals,
  ];

  const { riskScore, signalList } = calculateWtRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectWtWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'WEBTRANSPORTGUARD_EVENT',
      payload: {
        eventType: 'WEBTRANSPORT_CREDENTIAL_EXFIL_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
        wtCount: connections.length,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  WebTransport Proxy Installer                                       */
/* ------------------------------------------------------------------ */

/**
 * Wrap a WritableStream's getWriter().write() to log data.
 */
function wrapWritableStream(writable, connRecord) {
  if (!writable || !writable.getWriter) return;

  const origGetWriter = writable.getWriter.bind(writable);
  writable.getWriter = function() {
    const writer = origGetWriter();
    const origWrite = writer.write.bind(writer);
    writer.write = function(chunk) {
      let payload;
      if (typeof chunk === 'string') {
        payload = chunk;
      } else if (chunk instanceof Uint8Array) {
        try { payload = new TextDecoder().decode(chunk); } catch { payload = ''; }
      } else {
        payload = String(chunk);
      }

      connRecord.writeLog.push({
        payload,
        timestamp: Date.now(),
      });

      // Trigger analysis if DOM ready
      if (!analysisRun && typeof document !== 'undefined' && document.readyState !== 'loading') {
        try {
          runWtAnalysis(
            document,
            wtConnections,
            globalThis.location?.hostname || '',
          );
          analysisRun = true;
        } catch { /* non-critical */ }
      }

      return origWrite(chunk);
    };
    return writer;
  };
}

/**
 * Install WebTransport proxy at document_start.
 * Wraps the WebTransport constructor, stream creation, and datagram writes
 * to monitor for credential exfiltration.
 */
export function installWebTransportProxy() {
  if (typeof window === 'undefined' || !window.WebTransport) return;

  const OriginalWebTransport = window.WebTransport;

  const ProxyWebTransport = function(url, options) {
    const transport = options !== undefined
      ? new OriginalWebTransport(url, options)
      : new OriginalWebTransport(url);

    const connRecord = {
      url: String(url),
      hostname: parseWtHostname(String(url)),
      usesHashCerts: !!(options?.serverCertificateHashes?.length),
      writeLog: [],
    };
    wtConnections.push(connRecord);

    // Wrap createBidirectionalStream()
    const origBidi = transport.createBidirectionalStream.bind(transport);
    transport.createBidirectionalStream = async function() {
      const stream = await origBidi();
      wrapWritableStream(stream.writable, connRecord);
      return stream;
    };

    // Wrap createUnidirectionalStream()
    const origUni = transport.createUnidirectionalStream.bind(transport);
    transport.createUnidirectionalStream = async function() {
      const writable = await origUni();
      wrapWritableStream(writable, connRecord);
      return writable;
    };

    // Wrap datagram writable
    if (transport.datagrams?.writable) {
      wrapWritableStream(transport.datagrams.writable, connRecord);
    }

    return transport;
  };

  // Preserve prototype chain
  ProxyWebTransport.prototype = OriginalWebTransport.prototype;

  try {
    Object.defineProperty(window, 'WebTransport', {
      value: ProxyWebTransport,
      writable: false,
      configurable: true,
    });
  } catch {
    window.WebTransport = ProxyWebTransport;
  }

  // Run analysis on DOMContentLoaded
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        if (!analysisRun) {
          runWtAnalysis(
            document,
            wtConnections,
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

export function _getWtConnections() {
  return wtConnections;
}

export function _resetState() {
  wtConnections.length = 0;
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installWebTransportProxy();
}
