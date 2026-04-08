/**
 * extension/content/canvas_phish_guard.js
 *
 * CanvasPhishGuard — Canvas-Rendered Credential Phishing Detection
 *
 * Detects phishing pages that render login forms entirely on <canvas> elements
 * with zero DOM input fields, bypassing all DOM-based phishing detection.
 * Canvas 2D (~155 LOC) and Flutter Web CanvasKit (~50 LOC Dart) are realistic
 * threats. No published exploitation exists yet — proactive defense.
 *
 * Injected at document_idle for DOM heuristic analysis in isolated world.
 *
 * Signal architecture:
 *   canvas:isolated_canvas_login_context    +0.40
 *   canvas:framework_renderer_detected      +0.30
 *   canvas:low_dom_with_canvas              +0.25
 *   canvas:suspicious_canvas_dimensions     +0.20
 *   canvas:canvas_without_game_context      +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module CanvasPhishGuard
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

const FLUTTER_PATTERNS = [
  /canvaskit\.wasm/i, /flutter\.js/i, /flutter_service_worker\.js/i,
  /flutter_bootstrap\.js/i, /main\.dart\.js/i, /_flutter\./i,
];

const CANVAS_UI_FRAMEWORK_PATTERNS = [
  /canvasui/i, /zebkit/i, /fabric\.js/i, /fabric\.min\.js/i,
];

const NAVIGATION_SELECTORS = [
  'nav', '[role="navigation"]', '[role="toolbar"]', '[role="menubar"]',
  'header > *', '.sidebar', '.toolbar',
];

const DOM_COMPLEXITY_THRESHOLD = 50;
const MIN_CANVAS_WIDTH = 300;
const MIN_CANVAS_HEIGHT = 200;
const MAX_FORM_LIKE_ELEMENTS = 3;
const BODY_TEXT_LIMIT = 5000;

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

let analysisRun = false;

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
 * Return all <canvas> elements in the document.
 */
function getCanvasElements(doc) {
  if (!doc) return [];
  return Array.from(doc.querySelectorAll('canvas'));
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if canvas is present on a login-context page with no DOM credential fields.
 */
function checkIsolatedCanvasLoginContext(doc) {
  if (!doc) return [];

  const canvases = getCanvasElements(doc);
  if (canvases.length === 0) return [];

  if (!hasLoginContext(doc)) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length > 0) return [];

  return [{
    id: 'canvas:isolated_canvas_login_context',
    weight: 0.40,
    canvasCount: canvases.length,
  }];
}

/**
 * Check if a pure-canvas rendering framework (Flutter CanvasKit, CanvasUI,
 * Zebkit, Fabric.js) is loaded on a login-context page.
 */
function checkFrameworkRendererDetected(doc) {
  if (!doc) return [];

  const canvases = getCanvasElements(doc);
  if (canvases.length === 0) return [];

  if (!hasLoginContext(doc)) return [];

  const scripts = doc.querySelectorAll('script');

  for (const script of scripts) {
    const src = script.src || '';
    const content = script.textContent || '';

    for (const pattern of FLUTTER_PATTERNS) {
      if (pattern.test(src) || pattern.test(content)) {
        return [{
          id: 'canvas:framework_renderer_detected',
          weight: 0.30,
          framework: 'flutter',
        }];
      }
    }

    for (const pattern of CANVAS_UI_FRAMEWORK_PATTERNS) {
      if (pattern.test(src) || pattern.test(content)) {
        return [{
          id: 'canvas:framework_renderer_detected',
          weight: 0.30,
          framework: src.match(pattern)?.[0] || 'canvas-ui',
        }];
      }
    }
  }

  return [];
}

/**
 * Check if page has very low DOM element count alongside a canvas element,
 * with no navigation/toolbar structure.
 */
function checkLowDomWithCanvas(doc) {
  if (!doc) return [];

  const canvases = getCanvasElements(doc);
  if (canvases.length === 0) return [];

  const totalElements = doc.querySelectorAll('*').length;
  if (totalElements >= DOM_COMPLEXITY_THRESHOLD) return [];

  const hasNavigation = NAVIGATION_SELECTORS.some(sel => {
    try { return doc.querySelector(sel) !== null; } catch { return false; }
  });

  if (hasNavigation) return [];

  return [{
    id: 'canvas:low_dom_with_canvas',
    weight: 0.25,
    totalElements,
  }];
}

/**
 * Check if a canvas is large (≥300x200 or >40% viewport) on a page
 * with very few form-like elements.
 */
function checkSuspiciousCanvasDimensions(doc) {
  if (!doc) return [];

  const canvases = getCanvasElements(doc);
  if (canvases.length === 0) return [];

  const viewportWidth = doc.documentElement?.clientWidth || 1920;
  const viewportHeight = doc.documentElement?.clientHeight || 1080;
  const viewportArea = viewportWidth * viewportHeight;

  for (const canvas of canvases) {
    const w = canvas.width || 0;
    const h = canvas.height || 0;

    const meetsAbsoluteSize = w >= MIN_CANVAS_WIDTH && h >= MIN_CANVAS_HEIGHT;
    const areaRatio = viewportArea > 0 ? (w * h) / viewportArea : 0;
    const meetsRatio = areaRatio >= 0.40;

    if (meetsAbsoluteSize || meetsRatio) {
      const formElements = doc.querySelectorAll('form, input, select, textarea').length;
      if (formElements < MAX_FORM_LIKE_ELEMENTS) {
        return [{
          id: 'canvas:suspicious_canvas_dimensions',
          weight: 0.20,
          canvasWidth: w,
          canvasHeight: h,
          areaRatio: Math.round(areaRatio * 100) / 100,
        }];
      }
    }
  }

  return [];
}

/**
 * Check if canvas is present without any game engine markers in scripts.
 */
function checkCanvasWithoutGameContext(doc) {
  if (!doc) return [];

  const canvases = getCanvasElements(doc);
  if (canvases.length === 0) return [];

  const scripts = doc.querySelectorAll('script');

  for (const script of scripts) {
    const src = script.src || '';
    const content = script.textContent || '';

    for (const pattern of GAME_ENGINE_PATTERNS) {
      if (pattern.test(src) || pattern.test(content)) {
        return [];
      }
    }
  }

  return [{
    id: 'canvas:canvas_without_game_context',
    weight: 0.15,
  }];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateCanvasPhishRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectCanvasPhishWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-canvasphish-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-canvasphish-banner';
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
        canvas credential phishing detected \u2014 phishops canvasphishguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('canvas:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-canvasphish-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-canvasphish-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run canvas phishing analysis on the current page.
 * Called once at document_idle.
 */
function runCanvasPhishAnalysis(doc) {
  if (!doc) return;

  const canvases = getCanvasElements(doc);
  if (canvases.length === 0) return;

  const loginContextSignals = checkIsolatedCanvasLoginContext(doc);
  const frameworkSignals = checkFrameworkRendererDetected(doc);
  const lowDomSignals = checkLowDomWithCanvas(doc);
  const dimensionSignals = checkSuspiciousCanvasDimensions(doc);
  const gameContextSignals = checkCanvasWithoutGameContext(doc);

  const allSignals = [
    ...loginContextSignals,
    ...frameworkSignals,
    ...lowDomSignals,
    ...dimensionSignals,
    ...gameContextSignals,
  ];

  const { riskScore, signalList } = calculateCanvasPhishRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectCanvasPhishWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'CANVASPHISHGUARD_EVENT',
      payload: {
        eventType: 'CANVAS_CREDENTIAL_PHISHING_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
        canvasCount: canvases.length,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

function _resetState() {
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  if (!analysisRun) {
    runCanvasPhishAnalysis(document);
    analysisRun = true;
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
  globalThis.__phishopsExports['canvas_phish_guard'] = {
    hasLoginContext,
    getCanvasElements,
    checkIsolatedCanvasLoginContext,
    checkFrameworkRendererDetected,
    checkLowDomWithCanvas,
    checkSuspiciousCanvasDimensions,
    checkCanvasWithoutGameContext,
    calculateCanvasPhishRiskScore,
    injectCanvasPhishWarningBanner,
    runCanvasPhishAnalysis,
    _resetState,
  };
}
