/**
 * extension/__tests__/canvas_keystroke_guard.test.js
 *
 * Tests for CanvasKeystrokeGuard — Canvas Keystroke Capture Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkKeyboardListenerOnCanvas,
  checkCanvas2dContextOnLoginPage,
  checkMultipleKeyboardEventTypes,
  checkCanvasKeyboardNoDomInputs,
  checkNoGameEngineWithCanvasKeys,
  calculateCkgRiskScore,
  injectCkgWarningBanner,
  hasLoginContext,
  hasGameEngineMarkers,
  runCkgAnalysis,
} from '../content/canvas_keystroke_guard_bridge.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

function makeKbRecord(opts = {}) {
  return {
    eventType: opts.eventType || 'keydown',
    canvasIndex: opts.canvasIndex ?? 0,
    canvasWidth: opts.canvasWidth || 800,
    canvasHeight: opts.canvasHeight || 600,
    timestamp: opts.timestamp || Date.now(),
  };
}

function makeCtxRecord(opts = {}) {
  return {
    contextType: opts.contextType || '2d',
    canvasIndex: opts.canvasIndex ?? 0,
    canvasWidth: opts.canvasWidth || 800,
    canvasHeight: opts.canvasHeight || 600,
    timestamp: opts.timestamp || Date.now(),
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkKeyboardListenerOnCanvas                                       */
/* ================================================================== */

describe('checkKeyboardListenerOnCanvas', () => {
  it('detects keydown listener on canvas', () => {
    const records = [makeKbRecord({ eventType: 'keydown' })];
    const signals = checkKeyboardListenerOnCanvas(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ckg:keyboard_listener_on_canvas');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].listenerCount).toBe(1);
  });

  it('detects keypress listener on canvas', () => {
    const records = [makeKbRecord({ eventType: 'keypress' })];
    expect(checkKeyboardListenerOnCanvas(records)).toHaveLength(1);
  });

  it('detects keyup listener on canvas', () => {
    const records = [makeKbRecord({ eventType: 'keyup' })];
    expect(checkKeyboardListenerOnCanvas(records)).toHaveLength(1);
  });

  it('detects input listener on canvas', () => {
    const records = [makeKbRecord({ eventType: 'input' })];
    expect(checkKeyboardListenerOnCanvas(records)).toHaveLength(1);
  });

  it('returns empty for null/empty records', () => {
    expect(checkKeyboardListenerOnCanvas(null)).toHaveLength(0);
    expect(checkKeyboardListenerOnCanvas([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCanvas2dContextOnLoginPage                                     */
/* ================================================================== */

describe('checkCanvas2dContextOnLoginPage', () => {
  it('detects 2d context on login page', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body></body></html>');
    const contexts = [makeCtxRecord({ contextType: '2d' })];
    const signals = checkCanvas2dContextOnLoginPage(contexts, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ckg:canvas_2d_context_on_login_page');
    expect(signals[0].weight).toBe(0.30);
  });

  it('does NOT flag webgl context on login page', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body></body></html>');
    const contexts = [makeCtxRecord({ contextType: 'webgl' })];
    expect(checkCanvas2dContextOnLoginPage(contexts, doc)).toHaveLength(0);
  });

  it('does NOT flag 2d context on non-login page', () => {
    const doc = makeDoc('<html><head><title>My Game</title></head><body>Fun game!</body></html>');
    const contexts = [makeCtxRecord({ contextType: '2d' })];
    expect(checkCanvas2dContextOnLoginPage(contexts, doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCanvas2dContextOnLoginPage(null, makeDoc())).toHaveLength(0);
    expect(checkCanvas2dContextOnLoginPage([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkMultipleKeyboardEventTypes                                     */
/* ================================================================== */

describe('checkMultipleKeyboardEventTypes', () => {
  it('detects multiple event types on same canvas', () => {
    const records = [
      makeKbRecord({ eventType: 'keydown', canvasIndex: 0 }),
      makeKbRecord({ eventType: 'keyup', canvasIndex: 0 }),
    ];
    const signals = checkMultipleKeyboardEventTypes(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ckg:multiple_keyboard_event_types');
    expect(signals[0].weight).toBe(0.25);
    expect(signals[0].eventTypes).toContain('keydown');
    expect(signals[0].eventTypes).toContain('keyup');
  });

  it('does NOT flag single event type', () => {
    const records = [
      makeKbRecord({ eventType: 'keydown', canvasIndex: 0 }),
      makeKbRecord({ eventType: 'keydown', canvasIndex: 0 }),
    ];
    expect(checkMultipleKeyboardEventTypes(records)).toHaveLength(0);
  });

  it('does NOT flag multiple types on DIFFERENT canvases', () => {
    const records = [
      makeKbRecord({ eventType: 'keydown', canvasIndex: 0 }),
      makeKbRecord({ eventType: 'keyup', canvasIndex: 1 }),
    ];
    expect(checkMultipleKeyboardEventTypes(records)).toHaveLength(0);
  });

  it('returns empty for null/empty records', () => {
    expect(checkMultipleKeyboardEventTypes(null)).toHaveLength(0);
    expect(checkMultipleKeyboardEventTypes([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCanvasKeyboardNoDomInputs                                      */
/* ================================================================== */

describe('checkCanvasKeyboardNoDomInputs', () => {
  it('detects canvas keyboard with no DOM credential inputs', () => {
    const doc = makeDoc('<html><body><canvas></canvas></body></html>');
    const records = [makeKbRecord()];
    const signals = checkCanvasKeyboardNoDomInputs(records, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ckg:canvas_keyboard_no_dom_inputs');
    expect(signals[0].weight).toBe(0.20);
  });

  it('does NOT flag when password field exists', () => {
    const doc = makeDoc('<html><body><canvas></canvas><input type="password" /></body></html>');
    const records = [makeKbRecord()];
    expect(checkCanvasKeyboardNoDomInputs(records, doc)).toHaveLength(0);
  });

  it('does NOT flag when email field exists', () => {
    const doc = makeDoc('<html><body><canvas></canvas><input type="email" /></body></html>');
    const records = [makeKbRecord()];
    expect(checkCanvasKeyboardNoDomInputs(records, doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCanvasKeyboardNoDomInputs(null, makeDoc())).toHaveLength(0);
    expect(checkCanvasKeyboardNoDomInputs([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkNoGameEngineWithCanvasKeys                                     */
/* ================================================================== */

describe('checkNoGameEngineWithCanvasKeys', () => {
  it('flags when no game engine markers present', () => {
    const doc = makeDoc('<html><body><canvas></canvas><script>doLogin();</script></body></html>');
    const records = [makeKbRecord()];
    const signals = checkNoGameEngineWithCanvasKeys(records, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ckg:no_game_engine_with_canvas_keys');
    expect(signals[0].weight).toBe(0.15);
  });

  it('does NOT flag when Unity markers present', () => {
    const doc = makeDoc('<html><body><canvas></canvas><script>var UnityLoader = {};</script></body></html>');
    const records = [makeKbRecord()];
    expect(checkNoGameEngineWithCanvasKeys(records, doc)).toHaveLength(0);
  });

  it('does NOT flag when Phaser markers present', () => {
    const doc = makeDoc('<html><body><canvas></canvas><script>Phaser.Game();</script></body></html>');
    const records = [makeKbRecord()];
    expect(checkNoGameEngineWithCanvasKeys(records, doc)).toHaveLength(0);
  });

  it('does NOT flag when THREE.js markers present', () => {
    const doc = makeDoc('<html><body><canvas></canvas><script>THREE.Scene();</script></body></html>');
    const records = [makeKbRecord()];
    expect(checkNoGameEngineWithCanvasKeys(records, doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkNoGameEngineWithCanvasKeys(null, makeDoc())).toHaveLength(0);
    expect(checkNoGameEngineWithCanvasKeys([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  hasLoginContext                                                      */
/* ================================================================== */

describe('hasLoginContext', () => {
  it('detects login keyword in title', () => {
    const doc = makeDoc('<html><head><title>Sign In to Your Account</title></head><body></body></html>');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('detects password keyword in body', () => {
    const doc = makeDoc('<html><body>Enter your password</body></html>');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('returns false for generic page', () => {
    const doc = makeDoc('<html><head><title>Welcome</title></head><body>Hello world</body></html>');
    expect(hasLoginContext(doc)).toBe(false);
  });

  it('returns false for null doc', () => {
    expect(hasLoginContext(null)).toBe(false);
  });
});

/* ================================================================== */
/*  hasGameEngineMarkers                                                */
/* ================================================================== */

describe('hasGameEngineMarkers', () => {
  it('detects Unity markers', () => {
    const doc = makeDoc('<html><body><script>var UnityLoader = {};</script></body></html>');
    expect(hasGameEngineMarkers(doc)).toBe(true);
  });

  it('returns false for no game engine', () => {
    const doc = makeDoc('<html><body><script>console.log("hi");</script></body></html>');
    expect(hasGameEngineMarkers(doc)).toBe(false);
  });

  it('returns false for null doc', () => {
    expect(hasGameEngineMarkers(null)).toBe(false);
  });
});

/* ================================================================== */
/*  calculateCkgRiskScore                                               */
/* ================================================================== */

describe('calculateCkgRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateCkgRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'ckg:keyboard_listener_on_canvas', weight: 0.40 },
      { id: 'ckg:canvas_2d_context_on_login_page', weight: 0.30 },
    ];
    const { riskScore } = calculateCkgRiskScore(signals);
    expect(riskScore).toBeCloseTo(0.70, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
      { id: 'e', weight: 0.15 },
    ];
    const { riskScore } = calculateCkgRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for null input', () => {
    const { riskScore, signalList } = calculateCkgRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectCkgWarningBanner                                              */
/* ================================================================== */

describe('injectCkgWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectCkgWarningBanner(0.75, [
      { id: 'ckg:keyboard_listener_on_canvas', weight: 0.40 },
      { id: 'ckg:canvas_2d_context_on_login_page', weight: 0.30 },
    ]);

    const banner = dom.window.document.getElementById('phishops-ckg-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('canvas keystroke capture');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'ckg:test', weight: 0.50 }];
    injectCkgWarningBanner(0.50, signals);
    injectCkgWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-ckg-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectCkgWarningBanner(0.95, [{ id: 'ckg:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-ckg-banner');
    expect(banner.textContent).toContain('Critical');
    expect(banner.textContent).toContain('0.95');
  });
});

/* ================================================================== */
/*  runCkgAnalysis (integration)                                        */
/* ================================================================== */

describe('runCkgAnalysis', () => {
  it('emits telemetry when risk exceeds alert threshold', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body><canvas></canvas></body></html>');
    const kbRecords = [
      makeKbRecord({ eventType: 'keydown', canvasIndex: 0 }),
      makeKbRecord({ eventType: 'keyup', canvasIndex: 0 }),
    ];
    const ctxRecords = [makeCtxRecord({ contextType: '2d' })];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCkgAnalysis(doc, kbRecords, ctxRecords);

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'CANVASKEYSTROKEGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'CANVAS_KEYSTROKE_CAPTURE_DETECTED',
        }),
      }),
    );
  });

  it('does NOT emit when no keyboard records', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body></body></html>');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCkgAnalysis(doc, [], []);

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when risk below alert threshold', () => {
    // Single keydown on a game page — only keyboard_listener (0.40) fires, below 0.50
    const doc = makeDoc('<html><head><title>My Game</title></head><body><canvas></canvas><script>var UnityLoader = {};</script><input type="password" /></body></html>');
    const kbRecords = [makeKbRecord({ eventType: 'keydown', canvasIndex: 0 })];
    const ctxRecords = [makeCtxRecord({ contextType: 'webgl' })];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCkgAnalysis(doc, kbRecords, ctxRecords);

    expect(sendMessage).not.toHaveBeenCalled();
  });
});
