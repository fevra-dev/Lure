/**
 * extension/content/probe_guard_bridge.js
 *
 * ProbeGuard — Isolated World Bridge & Signal Analyzer
 *
 * Receives probe detection signals from the MAIN world interceptor
 * (probe_guard_main.js) via window.postMessage, accumulates state,
 * and runs heuristic analysis to detect pages probing for security
 * browser extensions.
 *
 * Injected at document_start in the isolated world. Analysis runs on
 * DOMContentLoaded + 2 s delay so all probing attempts are captured.
 *
 * Signal architecture:
 *   probe:tostring_on_security_api      +0.40
 *   probe:iframe_function_verification  +0.30
 *   probe:timing_loop_on_api            +0.25
 *   probe:war_extension_probing         +0.20
 *   probe:prototype_lie_detection       +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module ProbeGuardBridge
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const SOURCE_ID = 'PHISHOPS_PG';

const SIGNAL_WEIGHTS = {
  'probe:tostring_on_security_api':     0.40,
  'probe:iframe_function_verification': 0.30,
  'probe:timing_loop_on_api':           0.25,
  'probe:war_extension_probing':        0.20,
  'probe:prototype_lie_detection':      0.15,
};

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

/**
 * Collected signals from the MAIN world probe detector.
 * Key: signal ID, value: array of detail objects.
 * @type {Record<string, Array<{detail: object, timestamp: number}>>}
 */
const signalRecords = {};

let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Message Listener (MAIN world → isolated world bridge)              */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined') {
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.source !== SOURCE_ID) return;

    const { type, data } = event.data;

    if (type === 'PROBE_SIGNAL' && data && data.signalId) {
      const id = data.signalId;
      if (!signalRecords[id]) signalRecords[id] = [];
      signalRecords[id].push({
        detail: data.detail || {},
        timestamp: data.timestamp || Date.now(),
      });
    }
  });
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Signal 1: toString probing on security-sensitive APIs.
 * Weight: 0.40 — strongest signal; deliberate extension fingerprinting.
 */
export function checkToStringProbing(records) {
  const entries = records['probe:tostring_on_security_api'];
  if (!entries || entries.length === 0) return null;
  return {
    id: 'probe:tostring_on_security_api',
    weight: SIGNAL_WEIGHTS['probe:tostring_on_security_api'],
    count: entries.length,
    lastDetail: entries[entries.length - 1].detail,
  };
}

/**
 * Signal 2: iframe cross-frame function verification.
 * Weight: 0.30 — iframe-based native function comparison.
 */
export function checkIframeVerification(records) {
  const entries = records['probe:iframe_function_verification'];
  if (!entries || entries.length === 0) return null;
  return {
    id: 'probe:iframe_function_verification',
    weight: SIGNAL_WEIGHTS['probe:iframe_function_verification'],
    count: entries.length,
    lastDetail: entries[entries.length - 1].detail,
  };
}

/**
 * Signal 3: timing loop microbenchmarking on APIs.
 * Weight: 0.25 — performance.now() high-frequency calls.
 */
export function checkTimingLoop(records) {
  const entries = records['probe:timing_loop_on_api'];
  if (!entries || entries.length === 0) return null;
  return {
    id: 'probe:timing_loop_on_api',
    weight: SIGNAL_WEIGHTS['probe:timing_loop_on_api'],
    count: entries.length,
    lastDetail: entries[entries.length - 1].detail,
  };
}

/**
 * Signal 4: WAR-based extension probing.
 * Weight: 0.20 — chrome-extension:// or moz-extension:// URL access.
 */
export function checkWarProbing(records) {
  const entries = records['probe:war_extension_probing'];
  if (!entries || entries.length === 0) return null;
  return {
    id: 'probe:war_extension_probing',
    weight: SIGNAL_WEIGHTS['probe:war_extension_probing'],
    count: entries.length,
    lastDetail: entries[entries.length - 1].detail,
  };
}

/**
 * Signal 5: prototype lie detection — CreepJS-style patterns.
 * Weight: 0.15 — getOwnPropertyDescriptor/Names on Function.prototype.
 */
export function checkPrototypeLieDetection(records) {
  const entries = records['probe:prototype_lie_detection'];
  if (!entries || entries.length === 0) return null;
  return {
    id: 'probe:prototype_lie_detection',
    weight: SIGNAL_WEIGHTS['probe:prototype_lie_detection'],
    count: entries.length,
    lastDetail: entries[entries.length - 1].detail,
  };
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                        */
/* ------------------------------------------------------------------ */

/**
 * Calculate the additive risk score from detected signals.
 * @param {object[]} signals - Array of signal objects from check functions.
 * @returns {number} Score capped at 1.0.
 */
export function calculateProbeRiskScore(signals) {
  if (!signals || signals.length === 0) return 0;
  const raw = signals.reduce((sum, s) => sum + (s.weight || 0), 0);
  return Math.min(raw, 1.0);
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                      */
/* ------------------------------------------------------------------ */

/**
 * Inject a warning banner into the page.
 * @param {number} riskScore - The calculated risk score.
 * @param {object[]} signals - Active signals.
 */
export function injectProbeWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-probe-warning')) return;

  const severity = riskScore >= BLOCK_THRESHOLD ? 'Critical' : 'High';
  const signalNames = signals.map(s => s.id.replace('probe:', '')).join(', ');

  const banner = document.createElement('div');
  banner.id = 'phishops-probe-warning';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#1a0000', 'color:#ff6b6b', 'padding:12px 16px',
    'font:bold 14px/1.4 system-ui,sans-serif', 'text-align:center',
    'border-bottom:3px solid #ff0000', 'cursor:pointer',
  ].join(';');
  banner.textContent =
    `[PhishOps] ${severity}: This page is probing for security tools ` +
    `(score: ${riskScore.toFixed(2)}, signals: ${signalNames})`;
  banner.addEventListener('click', () => banner.remove());

  (document.body || document.documentElement).prepend(banner);
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                     */
/* ------------------------------------------------------------------ */

/**
 * Run probe detection analysis against collected signals.
 * @param {object} records - The signalRecords state.
 * @returns {{ riskScore: number, signals: object[] }}
 */
export function runProbeAnalysis(records) {
  const checks = [
    checkToStringProbing,
    checkIframeVerification,
    checkTimingLoop,
    checkWarProbing,
    checkPrototypeLieDetection,
  ];

  const activeSignals = checks
    .map(fn => fn(records))
    .filter(Boolean);

  const riskScore = calculateProbeRiskScore(activeSignals);

  return { riskScore, signals: activeSignals };
}

/* ------------------------------------------------------------------ */
/*  Bootstrap                                                           */
/* ------------------------------------------------------------------ */

function triggerAnalysis() {
  if (analysisRun) return;
  analysisRun = true;

  const { riskScore, signals } = runProbeAnalysis(signalRecords);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= BLOCK_THRESHOLD ? 'Critical' : 'High';
  const signalIds = signals.map(s => s.id);

  injectProbeWarningBanner(riskScore, signals);

  // Emit telemetry via service worker
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'PROBEGUARD_EVENT',
      payload: {
        eventType: 'EXTENSION_PROBE_DETECTED',
        severity,
        riskScore,
        signals: signalIds,
        signalDetails: signals,
        url: location.href,
        timestamp: Date.now(),
      },
    }).catch(() => { /* extension context may be invalidated */ });
  }
}

// Run analysis after DOMContentLoaded + 2s delay
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(triggerAnalysis, 2000);
    });
  } else {
    setTimeout(triggerAnalysis, 2000);
  }
}

/* ------------------------------------------------------------------ */
/*  Test-only accessors                                                 */
/* ------------------------------------------------------------------ */

export function _getSignalRecords() { return signalRecords; }
export function _resetState() {
  for (const key of Object.keys(signalRecords)) {
    delete signalRecords[key];
  }
  analysisRun = false;
}
