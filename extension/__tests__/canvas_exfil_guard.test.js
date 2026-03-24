/**
 * extension/__tests__/canvas_exfil_guard.test.js
 *
 * Tests for CanvasExfilGuard — Canvas Credential Exfiltration Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkPostWithCredentialFields,
  checkCrossOriginPostFromCanvasPage,
  checkBeaconFromCanvasPage,
  checkSmallJsonPostPattern,
  checkImagePixelExfilPattern,
  calculateCxgRiskScore,
  injectCxgWarningBanner,
  isCanvasPageWithoutDomInputs,
  hasLoginContext,
  extractBodyKeys,
  parseHostname,
  runCxgAnalysis,
} from '../content/canvas_exfil_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

function makeRecord(opts = {}) {
  return {
    method: opts.method || 'POST',
    url: opts.url || 'https://evil.com/collect',
    bodySnippet: opts.bodySnippet || '{"email":"test@test.com","password":"hunter2"}',
    bodyLength: opts.bodyLength || (opts.bodySnippet || '{"email":"test@test.com","password":"hunter2"}').length,
    channel: opts.channel || 'fetch',
    timestamp: opts.timestamp || Date.now(),
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  isCanvasPageWithoutDomInputs                                        */
/* ================================================================== */

describe('isCanvasPageWithoutDomInputs', () => {
  it('returns true for page with canvas and no credential inputs', () => {
    const doc = makeDoc('<html><body><canvas></canvas></body></html>');
    expect(isCanvasPageWithoutDomInputs(doc)).toBe(true);
  });

  it('returns false when password field exists', () => {
    const doc = makeDoc('<html><body><canvas></canvas><input type="password" /></body></html>');
    expect(isCanvasPageWithoutDomInputs(doc)).toBe(false);
  });

  it('returns false when no canvas exists', () => {
    const doc = makeDoc('<html><body><div>No canvas</div></body></html>');
    expect(isCanvasPageWithoutDomInputs(doc)).toBe(false);
  });

  it('returns false for null doc', () => {
    expect(isCanvasPageWithoutDomInputs(null)).toBe(false);
  });
});

/* ================================================================== */
/*  extractBodyKeys                                                     */
/* ================================================================== */

describe('extractBodyKeys', () => {
  it('extracts keys from JSON body', () => {
    const keys = extractBodyKeys('{"email":"a","password":"b"}');
    expect(keys).toContain('email');
    expect(keys).toContain('password');
  });

  it('extracts keys from form-encoded body', () => {
    const keys = extractBodyKeys('email=a&password=b');
    expect(keys).toContain('email');
    expect(keys).toContain('password');
  });

  it('returns empty for null/empty input', () => {
    expect(extractBodyKeys(null)).toHaveLength(0);
    expect(extractBodyKeys('')).toHaveLength(0);
  });

  it('returns empty for non-string input', () => {
    expect(extractBodyKeys(123)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  parseHostname                                                       */
/* ================================================================== */

describe('parseHostname', () => {
  it('parses hostname from URL', () => {
    expect(parseHostname('https://evil.com/path')).toBe('evil.com');
  });

  it('returns empty for invalid URL', () => {
    expect(parseHostname('not-a-url')).toBe('');
  });
});

/* ================================================================== */
/*  checkPostWithCredentialFields                                       */
/* ================================================================== */

describe('checkPostWithCredentialFields', () => {
  it('detects POST with password field', () => {
    const records = [makeRecord({ bodySnippet: '{"password":"hunter2"}' })];
    const signals = checkPostWithCredentialFields(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('cxg:post_with_credential_fields');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].matchedKey).toBe('password');
  });

  it('detects POST with email field', () => {
    const records = [makeRecord({ bodySnippet: '{"email":"user@test.com"}' })];
    expect(checkPostWithCredentialFields(records)).toHaveLength(1);
  });

  it('detects POST with username in form-encoded body', () => {
    const records = [makeRecord({ bodySnippet: 'username=admin&token=abc' })];
    expect(checkPostWithCredentialFields(records)).toHaveLength(1);
  });

  it('does NOT flag GET requests', () => {
    const records = [makeRecord({ method: 'GET', bodySnippet: '{"password":"x"}' })];
    expect(checkPostWithCredentialFields(records)).toHaveLength(0);
  });

  it('does NOT flag POST without credential keys', () => {
    const records = [makeRecord({ bodySnippet: '{"action":"click","page":"home"}' })];
    expect(checkPostWithCredentialFields(records)).toHaveLength(0);
  });

  it('returns empty for null/empty records', () => {
    expect(checkPostWithCredentialFields(null)).toHaveLength(0);
    expect(checkPostWithCredentialFields([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCrossOriginPostFromCanvasPage                                  */
/* ================================================================== */

describe('checkCrossOriginPostFromCanvasPage', () => {
  it('detects cross-origin POST', () => {
    const records = [makeRecord({ url: 'https://evil.com/collect' })];
    const signals = checkCrossOriginPostFromCanvasPage(records, 'legit-bank.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('cxg:cross_origin_post_from_canvas_page');
    expect(signals[0].weight).toBe(0.30);
    expect(signals[0].targetHost).toBe('evil.com');
  });

  it('does NOT flag same-origin POST', () => {
    const records = [makeRecord({ url: 'https://legit-bank.com/api' })];
    expect(checkCrossOriginPostFromCanvasPage(records, 'legit-bank.com')).toHaveLength(0);
  });

  it('does NOT flag GET requests', () => {
    const records = [makeRecord({ method: 'GET', url: 'https://evil.com/track' })];
    expect(checkCrossOriginPostFromCanvasPage(records, 'legit-bank.com')).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCrossOriginPostFromCanvasPage(null, 'x')).toHaveLength(0);
    expect(checkCrossOriginPostFromCanvasPage([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkBeaconFromCanvasPage                                           */
/* ================================================================== */

describe('checkBeaconFromCanvasPage', () => {
  it('detects beacon on login page', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body></body></html>');
    const records = [makeRecord({ channel: 'beacon' })];
    const signals = checkBeaconFromCanvasPage(records, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('cxg:beacon_from_canvas_page');
    expect(signals[0].weight).toBe(0.25);
  });

  it('does NOT flag beacon on non-login page', () => {
    const doc = makeDoc('<html><head><title>Fun Game</title></head><body>Play now!</body></html>');
    const records = [makeRecord({ channel: 'beacon' })];
    expect(checkBeaconFromCanvasPage(records, doc)).toHaveLength(0);
  });

  it('does NOT flag non-beacon channel', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body></body></html>');
    const records = [makeRecord({ channel: 'fetch' })];
    expect(checkBeaconFromCanvasPage(records, doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkBeaconFromCanvasPage(null, makeDoc())).toHaveLength(0);
    expect(checkBeaconFromCanvasPage([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSmallJsonPostPattern                                           */
/* ================================================================== */

describe('checkSmallJsonPostPattern', () => {
  it('detects small JSON POST with 2-5 keys', () => {
    const body = '{"email":"a@b.com","pass":"x"}';
    const records = [makeRecord({ bodySnippet: body, bodyLength: body.length })];
    const signals = checkSmallJsonPostPattern(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('cxg:small_json_post_pattern');
    expect(signals[0].weight).toBe(0.20);
    expect(signals[0].keyCount).toBe(2);
  });

  it('does NOT flag JSON with too many keys', () => {
    const body = '{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6}';
    const records = [makeRecord({ bodySnippet: body, bodyLength: body.length })];
    expect(checkSmallJsonPostPattern(records)).toHaveLength(0);
  });

  it('does NOT flag JSON with only 1 key', () => {
    const body = '{"token":"abc"}';
    const records = [makeRecord({ bodySnippet: body, bodyLength: body.length })];
    expect(checkSmallJsonPostPattern(records)).toHaveLength(0);
  });

  it('does NOT flag large body', () => {
    const body = '{"email":"a","pass":"' + 'x'.repeat(500) + '"}';
    const records = [makeRecord({ bodySnippet: body, bodyLength: body.length })];
    expect(checkSmallJsonPostPattern(records)).toHaveLength(0);
  });

  it('does NOT flag GET requests', () => {
    const body = '{"email":"a","pass":"b"}';
    const records = [makeRecord({ method: 'GET', bodySnippet: body, bodyLength: body.length })];
    expect(checkSmallJsonPostPattern(records)).toHaveLength(0);
  });

  it('returns empty for null/empty records', () => {
    expect(checkSmallJsonPostPattern(null)).toHaveLength(0);
    expect(checkSmallJsonPostPattern([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkImagePixelExfilPattern                                         */
/* ================================================================== */

describe('checkImagePixelExfilPattern', () => {
  it('detects image src with credential-like query params', () => {
    const records = [makeRecord({
      channel: 'image',
      url: 'https://evil.com/pixel.gif?email=test@test.com&password=hunter2',
    })];
    const signals = checkImagePixelExfilPattern(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('cxg:image_pixel_exfil_pattern');
    expect(signals[0].weight).toBe(0.15);
  });

  it('does NOT flag image without credential params', () => {
    const records = [makeRecord({
      channel: 'image',
      url: 'https://analytics.com/pixel.gif?page=home&ts=123',
    })];
    expect(checkImagePixelExfilPattern(records)).toHaveLength(0);
  });

  it('does NOT flag non-image channel', () => {
    const records = [makeRecord({
      channel: 'fetch',
      url: 'https://evil.com/pixel.gif?password=hunter2',
    })];
    expect(checkImagePixelExfilPattern(records)).toHaveLength(0);
  });

  it('returns empty for null/empty records', () => {
    expect(checkImagePixelExfilPattern(null)).toHaveLength(0);
    expect(checkImagePixelExfilPattern([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateCxgRiskScore                                               */
/* ================================================================== */

describe('calculateCxgRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateCxgRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'cxg:post_with_credential_fields', weight: 0.40 },
      { id: 'cxg:cross_origin_post_from_canvas_page', weight: 0.30 },
    ];
    const { riskScore } = calculateCxgRiskScore(signals);
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
    const { riskScore } = calculateCxgRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for null input', () => {
    const { riskScore, signalList } = calculateCxgRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectCxgWarningBanner                                              */
/* ================================================================== */

describe('injectCxgWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectCxgWarningBanner(0.75, [
      { id: 'cxg:post_with_credential_fields', weight: 0.40 },
      { id: 'cxg:cross_origin_post_from_canvas_page', weight: 0.30 },
    ]);

    const banner = dom.window.document.getElementById('phishops-cxg-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('canvas credential exfiltration');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'cxg:test', weight: 0.50 }];
    injectCxgWarningBanner(0.50, signals);
    injectCxgWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-cxg-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectCxgWarningBanner(0.95, [{ id: 'cxg:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-cxg-banner');
    expect(banner.textContent).toContain('Critical');
    expect(banner.textContent).toContain('0.95');
  });
});

/* ================================================================== */
/*  runCxgAnalysis (integration)                                        */
/* ================================================================== */

describe('runCxgAnalysis', () => {
  it('emits telemetry when risk exceeds alert threshold', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body><canvas></canvas></body></html>');
    const records = [makeRecord({
      method: 'POST',
      url: 'https://evil.com/collect',
      bodySnippet: '{"email":"a@b.com","password":"hunter2"}',
      bodyLength: 40,
    })];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCxgAnalysis(doc, records, 'legit-bank.com');

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'CANVASEXFILGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'CANVAS_CREDENTIAL_EXFIL_DETECTED',
        }),
      }),
    );
  });

  it('does NOT emit when no records', () => {
    const doc = makeDoc('<html><body></body></html>');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCxgAnalysis(doc, [], 'legit.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when risk below threshold', () => {
    const doc = makeDoc('<html><body></body></html>');
    // Only image pixel signal (0.15) — well below 0.50 threshold
    const records = [makeRecord({
      method: 'GET',
      channel: 'image',
      url: 'https://evil.com/pixel.gif?page=home',
      bodySnippet: '',
      bodyLength: 0,
    })];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runCxgAnalysis(doc, records, 'legit.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });
});
