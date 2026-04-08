/**
 * extension/content/canvas_keystroke_guard_bridge.js
 *
 * CanvasKeystrokeGuard — Isolated World Bridge & Signal Analyzer
 *
 * Receives observations from the MAIN world interceptor
 * (canvas_keystroke_guard_main.js) via window.postMessage, accumulates
 * state, and runs heuristic analysis to detect canvas-based credential
 * capture. Keyboard event listeners on canvas elements — the strongest
 * signal that a canvas is being used for credential input capture.
 *
 * Injected at document_start in the isolated world. Analysis runs on
 * DOMContentLoaded + 2 s delay so the DOM is ready for heuristic checks.
 *
 * Signal architecture:
 *   ckg:keyboard_listener_on_canvas       +0.40
 *   ckg:canvas_2d_context_on_login_page   +0.30
 *   ckg:multiple_keyboard_event_types     +0.25
 *   ckg:canvas_keyboard_no_dom_inputs     +0.20
 *   ckg:no_game_engine_with_canvas_keys   +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module CanvasKeystrokeGuardBridge
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const SOURCE_ID = 'PHISHOPS_CKG';

const CREDENTIAL_SELECTORS =
  'input[type="password"], input[type="email"], ' +
  'input[autocomplete="current-password"], input[autocomplete="new-password"], ' +
  'input[autocomplete="username"]';

const LOGIN_CONTEXT_PATTERNS = [
  /sign[\s-]?in/i, /log[\s-]?in/i, /log[\s-]?on/i, /password/i,
  /credential/i, /authenticate/i, /verification/i,
  /account[\s-]?access/i, /secure[\s-]?login/i,
  /enter\s+your\s+(email|password|username)/i,
];

const GAME_ENGINE_PATTERNS = [
  /UnityLoader/i, /UnityProgress/i, /unityInstance/i, /buildUrl.*\.wasm/i,
  /godot/i, /Engine\.start/i, /Phaser\./i, /PIXI\./i, /THREE\./i,
  /playcanvas/i, /pc\.app/i, /createScene/i, /babylon/i,
];

const BODY_TEXT_LIMIT = 5000;

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

/**
 * Records of keyboard event listeners on canvas elements.
 * @type {{ eventType: string, canvasIndex: number, canvasWidth: number, canvasHeight: number, timestamp: number }[]}
 */
const keyboardRecords = [];

/**
 * Records of canvas context creations.
 * @type {{ contextType: string, canvasIndex: number, canvasWidth: number, canvasHeight: number, timestamp: number }[]}
 */
const contextRecords = [];

let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Message Listener (MAIN world → isolated world bridge)              */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined') {
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.source !== SOURCE_ID) return;

    const { type, data } = event.data;

    if (type === 'CANVAS_KEYBOARD_LISTENER' && data) {
      keyboardRecords.push({
        eventType: data.eventType || '',
        canvasIndex: data.canvasIndex ?? -1,
        canvasWidth: data.canvasWidth || 0,
        canvasHeight: data.canvasHeight || 0,
        timestamp: data.timestamp || Date.now(),
      });
    }

    if (type === 'CANVAS_CONTEXT_CREATED' && data) {
      contextRecords.push({
        contextType: data.contextType || '',
        canvasIndex: data.canvasIndex ?? -1,
        canvasWidth: data.canvasWidth || 0,
        canvasHeight: data.canvasHeight || 0,
        timestamp: data.timestamp || Date.now(),
      });
    }
  });
}

/* ------------------------------------------------------------------ */
/*  Helper Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if the page has login/auth context via URL, title, or body text.
 */
function hasLoginContext(doc) {
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
 * Check if any game engine markers exist in the page scripts.
 */
function hasGameEngineMarkers(doc) {
  if (!doc) return false;

  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const src = script.src || '';
    const content = script.textContent || '';
    for (const pattern of GAME_ENGINE_PATTERNS) {
      if (pattern.test(src) || pattern.test(content)) return true;
    }
  }

  return false;
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Signal 1: Keyboard event listener attached to a canvas element.
 * Weight: 0.40 — strongest single signal of canvas credential capture.
 */
function checkKeyboardListenerOnCanvas(records) {
  if (!records || records.length === 0) return [];

  const hasKeyboardListener = records.some(r =>
    r.eventType === 'keydown' || r.eventType === 'keypress' ||
    r.eventType === 'keyup' || r.eventType === 'input'
  );

  if (!hasKeyboardListener) return [];

  return [{
    id: 'ckg:keyboard_listener_on_canvas',
    weight: 0.40,
    listenerCount: records.length,
  }];
}

/**
 * Signal 2: Canvas uses 2D context on a page with login context keywords.
 * Weight: 0.30 — Canvas 2D is the most realistic phishing rendering path.
 */
function checkCanvas2dContextOnLoginPage(contexts, doc) {
  if (!contexts || contexts.length === 0 || !doc) return [];

  const has2d = contexts.some(c => c.contextType === '2d');
  if (!has2d) return [];

  if (!hasLoginContext(doc)) return [];

  return [{
    id: 'ckg:canvas_2d_context_on_login_page',
    weight: 0.30,
  }];
}

/**
 * Signal 3: Multiple keyboard event types on the same canvas.
 * Weight: 0.25 — credential accumulation typically requires both keydown+keyup.
 */
function checkMultipleKeyboardEventTypes(records) {
  if (!records || records.length === 0) return [];

  // Group event types per canvas
  const canvasEventTypes = new Map();
  for (const r of records) {
    const key = r.canvasIndex;
    if (!canvasEventTypes.has(key)) canvasEventTypes.set(key, new Set());
    canvasEventTypes.get(key).add(r.eventType);
  }

  for (const [, types] of canvasEventTypes) {
    if (types.size >= 2) {
      return [{
        id: 'ckg:multiple_keyboard_event_types',
        weight: 0.25,
        eventTypes: Array.from(types),
      }];
    }
  }

  return [];
}

/**
 * Signal 4: Canvas has keyboard listeners AND zero DOM credential fields.
 * Weight: 0.20 — no legitimate reason for canvas keyboard input without DOM inputs
 *                 unless the form is rendered entirely on canvas.
 */
function checkCanvasKeyboardNoDomInputs(records, doc) {
  if (!records || records.length === 0 || !doc) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length > 0) return [];

  return [{
    id: 'ckg:canvas_keyboard_no_dom_inputs',
    weight: 0.20,
  }];
}

/**
 * Signal 5: Canvas has keyboard listeners with no game engine markers.
 * Weight: 0.15 — game engines legitimately use canvas + keyboard input.
 */
function checkNoGameEngineWithCanvasKeys(records, doc) {
  if (!records || records.length === 0 || !doc) return [];

  if (hasGameEngineMarkers(doc)) return [];

  return [{
    id: 'ckg:no_game_engine_with_canvas_keys',
    weight: 0.15,
  }];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateCkgRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectCkgWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-ckg-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-ckg-banner';
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
        canvas keystroke capture detected \u2014 phishops canvaskeystrokeguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('ckg:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-ckg-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-ckg-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run analysis on accumulated keyboard and context observations.
 */
function runCkgAnalysis(doc, kbRecords, ctxRecords) {
  if (!doc || !kbRecords || kbRecords.length === 0) return;

  const keyboardSignals = checkKeyboardListenerOnCanvas(kbRecords);
  if (keyboardSignals.length === 0) return;

  const contextSignals = checkCanvas2dContextOnLoginPage(ctxRecords, doc);
  const multipleTypeSignals = checkMultipleKeyboardEventTypes(kbRecords);
  const noDomInputSignals = checkCanvasKeyboardNoDomInputs(kbRecords, doc);
  const noGameSignals = checkNoGameEngineWithCanvasKeys(kbRecords, doc);

  const allSignals = [
    ...keyboardSignals,
    ...contextSignals,
    ...multipleTypeSignals,
    ...noDomInputSignals,
    ...noGameSignals,
  ];

  const { riskScore, signalList } = calculateCkgRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectCkgWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'CANVASKEYSTROKEGUARD_EVENT',
      payload: {
        eventType: 'CANVAS_KEYSTROKE_CAPTURE_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
        listenerCount: kbRecords.length,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

function _getKeyboardRecords() {
  return keyboardRecords;
}

function _getContextRecords() {
  return contextRecords;
}

function _resetState() {
  keyboardRecords.length = 0;
  contextRecords.length = 0;
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        if (!analysisRun) {
          runCkgAnalysis(document, keyboardRecords, contextRecords);
          analysisRun = true;
        }
      }, 2000);
    });
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
  globalThis.__phishopsExports['canvas_keystroke_guard_bridge'] = {
    hasLoginContext,
    hasGameEngineMarkers,
    checkKeyboardListenerOnCanvas,
    checkCanvas2dContextOnLoginPage,
    checkMultipleKeyboardEventTypes,
    checkCanvasKeyboardNoDomInputs,
    checkNoGameEngineWithCanvasKeys,
    calculateCkgRiskScore,
    injectCkgWarningBanner,
    runCkgAnalysis,
    _getKeyboardRecords,
    _getContextRecords,
    _resetState,
  };
}
