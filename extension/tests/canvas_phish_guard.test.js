/**
 * extension/__tests__/canvas_phish_guard.test.js
 *
 * Tests for CanvasPhishGuard — Canvas-Rendered Credential Phishing Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/canvas_phish_guard.js';
const { hasLoginContext, getCanvasElements, checkIsolatedCanvasLoginContext, checkFrameworkRendererDetected, checkLowDomWithCanvas, checkSuspiciousCanvasDimensions, checkCanvasWithoutGameContext, calculateCanvasPhishRiskScore, injectCanvasPhishWarningBanner, runCanvasPhishAnalysis } = globalThis.__phishopsExports['canvas_phish_guard'];

function makeDoc(html = '<html><head></head><body></body></html>', url = 'https://example.com') {
  const dom = new JSDOM(html, { url });
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  hasLoginContext                                                      */
/* ================================================================== */

describe('hasLoginContext', () => {
  it('detects login keyword in URL', () => {
    const doc = makeDoc('<html><body></body></html>', 'https://evil.com/login');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('detects sign-in keyword in URL', () => {
    const doc = makeDoc('<html><body></body></html>', 'https://evil.com/sign-in');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('detects password keyword in title', () => {
    const doc = makeDoc('<html><head><title>Enter Password</title></head><body></body></html>');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('detects "enter your email" in body text', () => {
    const doc = makeDoc('<html><body>Please enter your email to continue</body></html>');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('returns false when no login keywords', () => {
    const doc = makeDoc('<html><head><title>My Game</title></head><body>Play now</body></html>', 'https://game.com/play');
    expect(hasLoginContext(doc)).toBe(false);
  });

  it('returns false for null doc', () => {
    expect(hasLoginContext(null)).toBe(false);
  });
});

/* ================================================================== */
/*  getCanvasElements                                                   */
/* ================================================================== */

describe('getCanvasElements', () => {
  it('returns canvas elements', () => {
    const doc = makeDoc('<html><body><canvas id="a"></canvas><canvas id="b"></canvas></body></html>');
    expect(getCanvasElements(doc)).toHaveLength(2);
  });

  it('returns empty for no canvas', () => {
    const doc = makeDoc('<html><body><div>No canvas</div></body></html>');
    expect(getCanvasElements(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(getCanvasElements(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkIsolatedCanvasLoginContext                                      */
/* ================================================================== */

describe('checkIsolatedCanvasLoginContext', () => {
  it('detects canvas on login page with no credential fields', () => {
    const doc = makeDoc('<html><body><canvas width="800" height="600"></canvas></body></html>', 'https://evil.com/login');
    const signals = checkIsolatedCanvasLoginContext(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('canvas:isolated_canvas_login_context');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].canvasCount).toBe(1);
  });

  it('does NOT flag canvas without login context', () => {
    const doc = makeDoc('<html><body><canvas width="800" height="600"></canvas></body></html>', 'https://game.com/play');
    expect(checkIsolatedCanvasLoginContext(doc)).toHaveLength(0);
  });

  it('does NOT flag login page with DOM credential fields', () => {
    const doc = makeDoc('<html><body><canvas></canvas><input type="password" /></body></html>', 'https://evil.com/login');
    expect(checkIsolatedCanvasLoginContext(doc)).toHaveLength(0);
  });

  it('does NOT flag login page without canvas', () => {
    const doc = makeDoc('<html><body><div>Login</div></body></html>', 'https://evil.com/login');
    expect(checkIsolatedCanvasLoginContext(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkIsolatedCanvasLoginContext(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkFrameworkRendererDetected                                       */
/* ================================================================== */

describe('checkFrameworkRendererDetected', () => {
  it('detects Flutter flutter.js script', () => {
    const doc = makeDoc(
      '<html><body><canvas></canvas><script src="flutter.js"></script></body></html>',
      'https://evil.com/login',
    );
    const signals = checkFrameworkRendererDetected(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('canvas:framework_renderer_detected');
    expect(signals[0].weight).toBe(0.30);
    expect(signals[0].framework).toBe('flutter');
  });

  it('detects canvaskit.wasm in script content', () => {
    const doc = makeDoc(
      '<html><body><canvas></canvas><script>loadCanvasKit("canvaskit.wasm")</script></body></html>',
      'https://evil.com/sign-in',
    );
    expect(checkFrameworkRendererDetected(doc)).toHaveLength(1);
  });

  it('detects fabric.js script', () => {
    const doc = makeDoc(
      '<html><body><canvas></canvas><script src="fabric.min.js"></script></body></html>',
      'https://evil.com/login',
    );
    const signals = checkFrameworkRendererDetected(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].framework).not.toBe('flutter');
  });

  it('does NOT flag when no framework scripts present', () => {
    const doc = makeDoc(
      '<html><body><canvas></canvas><script src="app.js"></script></body></html>',
      'https://evil.com/login',
    );
    expect(checkFrameworkRendererDetected(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkFrameworkRendererDetected(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkLowDomWithCanvas                                               */
/* ================================================================== */

describe('checkLowDomWithCanvas', () => {
  it('detects low DOM complexity with canvas', () => {
    const doc = makeDoc('<html><body><canvas></canvas><div>Phish</div></body></html>');
    const signals = checkLowDomWithCanvas(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('canvas:low_dom_with_canvas');
    expect(signals[0].weight).toBe(0.25);
    expect(signals[0].totalElements).toBeLessThan(50);
  });

  it('does NOT flag high DOM complexity', () => {
    const elements = Array.from({ length: 60 }, (_, i) => `<div id="el${i}"></div>`).join('');
    const doc = makeDoc(`<html><body><canvas></canvas>${elements}</body></html>`);
    expect(checkLowDomWithCanvas(doc)).toHaveLength(0);
  });

  it('does NOT flag when navigation elements present', () => {
    const doc = makeDoc('<html><body><canvas></canvas><nav>Menu</nav></body></html>');
    expect(checkLowDomWithCanvas(doc)).toHaveLength(0);
  });

  it('does NOT flag without canvas', () => {
    const doc = makeDoc('<html><body><div>Simple</div></body></html>');
    expect(checkLowDomWithCanvas(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkLowDomWithCanvas(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSuspiciousCanvasDimensions                                     */
/* ================================================================== */

describe('checkSuspiciousCanvasDimensions', () => {
  it('detects large canvas with few form elements', () => {
    const doc = makeDoc('<html><body><canvas width="800" height="600"></canvas></body></html>');
    const signals = checkSuspiciousCanvasDimensions(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('canvas:suspicious_canvas_dimensions');
    expect(signals[0].weight).toBe(0.20);
    expect(signals[0].canvasWidth).toBe(800);
  });

  it('does NOT flag small canvas', () => {
    const doc = makeDoc('<html><body><canvas width="100" height="100"></canvas></body></html>');
    expect(checkSuspiciousCanvasDimensions(doc)).toHaveLength(0);
  });

  it('does NOT flag when many form elements present', () => {
    const doc = makeDoc(
      '<html><body><canvas width="800" height="600"></canvas>' +
      '<input type="text" /><input type="text" /><input type="text" />' +
      '</body></html>',
    );
    expect(checkSuspiciousCanvasDimensions(doc)).toHaveLength(0);
  });

  it('does NOT flag without canvas', () => {
    const doc = makeDoc('<html><body><div>No canvas</div></body></html>');
    expect(checkSuspiciousCanvasDimensions(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkSuspiciousCanvasDimensions(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCanvasWithoutGameContext                                        */
/* ================================================================== */

describe('checkCanvasWithoutGameContext', () => {
  it('flags canvas without game engine markers', () => {
    const doc = makeDoc('<html><body><canvas></canvas><script src="app.js"></script></body></html>');
    const signals = checkCanvasWithoutGameContext(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('canvas:canvas_without_game_context');
    expect(signals[0].weight).toBe(0.15);
  });

  it('does NOT flag when Unity detected', () => {
    const doc = makeDoc(
      '<html><body><canvas></canvas><script src="UnityLoader.js"></script></body></html>',
    );
    expect(checkCanvasWithoutGameContext(doc)).toHaveLength(0);
  });

  it('does NOT flag when Phaser detected in inline script', () => {
    const doc = makeDoc(
      '<html><body><canvas></canvas><script>var game = new Phaser.Game(config);</script></body></html>',
    );
    expect(checkCanvasWithoutGameContext(doc)).toHaveLength(0);
  });

  it('does NOT flag without canvas', () => {
    const doc = makeDoc('<html><body><div>No canvas</div></body></html>');
    expect(checkCanvasWithoutGameContext(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkCanvasWithoutGameContext(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateCanvasPhishRiskScore                                       */
/* ================================================================== */

describe('calculateCanvasPhishRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateCanvasPhishRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'canvas:isolated_canvas_login_context', weight: 0.40 },
      { id: 'canvas:low_dom_with_canvas', weight: 0.25 },
    ];
    const { riskScore } = calculateCanvasPhishRiskScore(signals);
    expect(riskScore).toBeCloseTo(0.65, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
      { id: 'e', weight: 0.15 },
    ];
    const { riskScore } = calculateCanvasPhishRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for null input', () => {
    const { riskScore, signalList } = calculateCanvasPhishRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectCanvasPhishWarningBanner                                      */
/* ================================================================== */

describe('injectCanvasPhishWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectCanvasPhishWarningBanner(0.80, [
      { id: 'canvas:isolated_canvas_login_context', weight: 0.40 },
      { id: 'canvas:low_dom_with_canvas', weight: 0.25 },
    ]);

    const banner = dom.window.document.getElementById('phishops-canvasphish-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('canvas credential phishing');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'canvas:test', weight: 0.50 }];
    injectCanvasPhishWarningBanner(0.50, signals);
    injectCanvasPhishWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-canvasphish-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectCanvasPhishWarningBanner(0.95, [{ id: 'canvas:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-canvasphish-banner');
    expect(banner.textContent).toContain('Critical');
    expect(banner.textContent).toContain('0.95');
  });
});

/* ================================================================== */
/*  runCanvasPhishAnalysis (integration)                                 */
/* ================================================================== */

describe('runCanvasPhishAnalysis', () => {
  it('emits telemetry for canvas phishing page', () => {
    const doc = makeDoc(
      '<html><body><canvas width="800" height="600"></canvas></body></html>',
      'https://evil.com/login',
    );

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCanvasPhishAnalysis(doc);

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'CANVASPHISHGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'CANVAS_CREDENTIAL_PHISHING_DETECTED',
        }),
      }),
    );
  });

  it('does NOT emit when no canvas', () => {
    const doc = makeDoc('<html><body><div>No canvas</div></body></html>', 'https://evil.com/login');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCanvasPhishAnalysis(doc);

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when canvas page has high DOM and no login context', () => {
    const elements = Array.from({ length: 60 }, (_, i) => `<div id="el${i}"></div>`).join('');
    const doc = makeDoc(
      `<html><body><canvas width="800" height="600"></canvas>${elements}</body></html>`,
      'https://game.com/play',
    );

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCanvasPhishAnalysis(doc);

    expect(sendMessage).not.toHaveBeenCalled();
  });
});
