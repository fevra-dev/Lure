/**
 * extension/__tests__/ws_exfil_guard.test.js
 *
 * Tests for WebSocketExfilGuard — Real-Time Credential Exfiltration via WebSocket
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/ws_exfil_guard.js';
const { checkWsOpenOnCredentialPage, checkKeystrokeRelayPattern, checkCrossOriginWsWithCreds, checkFormValueInWsPayload, checkWsWithoutVisibleWsUi, calculateWsExfilRiskScore, injectWsExfilWarningBanner, parseWsHostname, runWsExfilAnalysis } = globalThis.__phishopsExports['ws_exfil_guard'];

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

function makeConn(url = 'wss://evil.com/ws', sendLog = []) {
  return {
    url,
    hostname: parseWsHostname(url),
    sendLog,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkWsOpenOnCredentialPage                                        */
/* ================================================================== */

describe('checkWsOpenOnCredentialPage', () => {
  it('detects WS connection on page with password field', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const signals = checkWsOpenOnCredentialPage(doc, [makeConn()]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wsexfil:ws_open_on_credential_page');
    expect(signals[0].weight).toBe(0.40);
  });

  it('detects WS connection on page with email field', () => {
    const doc = makeDoc('<html><body><input type="email" /></body></html>');
    const signals = checkWsOpenOnCredentialPage(doc, [makeConn()]);
    expect(signals).toHaveLength(1);
  });

  it('detects WS connection on page with autocomplete=current-password', () => {
    const doc = makeDoc('<html><body><input autocomplete="current-password" /></body></html>');
    expect(checkWsOpenOnCredentialPage(doc, [makeConn()])).toHaveLength(1);
  });

  it('does NOT flag page without credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    expect(checkWsOpenOnCredentialPage(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag when no WS connections', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    expect(checkWsOpenOnCredentialPage(doc, [])).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkWsOpenOnCredentialPage(null, [makeConn()])).toHaveLength(0);
    expect(checkWsOpenOnCredentialPage(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkKeystrokeRelayPattern                                         */
/* ================================================================== */

describe('checkKeystrokeRelayPattern', () => {
  it('detects high-frequency small messages (keystroke relay)', () => {
    const now = Date.now();
    const sendLog = [
      { payload: 'a', timestamp: now },
      { payload: 'b', timestamp: now + 200 },
      { payload: 'c', timestamp: now + 400 },
      { payload: 'd', timestamp: now + 600 },
      { payload: 'e', timestamp: now + 800 },
    ];
    const signals = checkKeystrokeRelayPattern([makeConn('wss://evil.com', sendLog)]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wsexfil:keystroke_relay_pattern');
    expect(signals[0].weight).toBe(0.30);
    expect(signals[0].frequency).toBeGreaterThanOrEqual(2);
  });

  it('does NOT flag infrequent messages', () => {
    const now = Date.now();
    const sendLog = [
      { payload: 'a', timestamp: now },
      { payload: 'b', timestamp: now + 5000 },
      { payload: 'c', timestamp: now + 10000 },
    ];
    expect(checkKeystrokeRelayPattern([makeConn('wss://evil.com', sendLog)])).toHaveLength(0);
  });

  it('does NOT flag large messages (not keystrokes)', () => {
    const now = Date.now();
    const sendLog = [
      { payload: 'A'.repeat(100), timestamp: now },
      { payload: 'B'.repeat(100), timestamp: now + 200 },
      { payload: 'C'.repeat(100), timestamp: now + 400 },
    ];
    expect(checkKeystrokeRelayPattern([makeConn('wss://evil.com', sendLog)])).toHaveLength(0);
  });

  it('does NOT flag with fewer than 3 messages', () => {
    const now = Date.now();
    const sendLog = [
      { payload: 'a', timestamp: now },
      { payload: 'b', timestamp: now + 100 },
    ];
    expect(checkKeystrokeRelayPattern([makeConn('wss://evil.com', sendLog)])).toHaveLength(0);
  });

  it('returns empty for null/empty connections', () => {
    expect(checkKeystrokeRelayPattern(null)).toHaveLength(0);
    expect(checkKeystrokeRelayPattern([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCrossOriginWsWithCreds                                        */
/* ================================================================== */

describe('checkCrossOriginWsWithCreds', () => {
  it('detects cross-origin WS on credential page', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const conn = makeConn('wss://evil.com/ws');
    const signals = checkCrossOriginWsWithCreds([conn], 'legit-bank.com', doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wsexfil:cross_origin_ws_with_creds');
    expect(signals[0].weight).toBe(0.25);
    expect(signals[0].wsHostname).toBe('evil.com');
  });

  it('does NOT flag same-origin WS', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const conn = makeConn('wss://legit-bank.com/ws');
    expect(checkCrossOriginWsWithCreds([conn], 'legit-bank.com', doc)).toHaveLength(0);
  });

  it('does NOT flag cross-origin WS without credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    const conn = makeConn('wss://evil.com/ws');
    expect(checkCrossOriginWsWithCreds([conn], 'legit-bank.com', doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCrossOriginWsWithCreds(null, 'x', makeDoc())).toHaveLength(0);
    expect(checkCrossOriginWsWithCreds([], null, makeDoc())).toHaveLength(0);
    expect(checkCrossOriginWsWithCreds([], 'x', null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkFormValueInWsPayload                                          */
/* ================================================================== */

describe('checkFormValueInWsPayload', () => {
  it('detects input value appearing in WS payload', () => {
    const doc = makeDoc('<html><body><input type="password" value="hunter2" /></body></html>');
    const conn = makeConn('wss://evil.com', [
      { payload: '{"pass":"hunter2"}', timestamp: Date.now() },
    ]);
    const signals = checkFormValueInWsPayload([conn], doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wsexfil:form_value_in_ws_payload');
    expect(signals[0].weight).toBe(0.20);
  });

  it('does NOT flag when input value is too short (<3 chars)', () => {
    const doc = makeDoc('<html><body><input type="password" value="ab" /></body></html>');
    const conn = makeConn('wss://evil.com', [
      { payload: 'ab', timestamp: Date.now() },
    ]);
    expect(checkFormValueInWsPayload([conn], doc)).toHaveLength(0);
  });

  it('does NOT flag when payload does not contain input value', () => {
    const doc = makeDoc('<html><body><input type="password" value="secret123" /></body></html>');
    const conn = makeConn('wss://evil.com', [
      { payload: 'unrelated data', timestamp: Date.now() },
    ]);
    expect(checkFormValueInWsPayload([conn], doc)).toHaveLength(0);
  });

  it('does NOT flag when no credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" value="hello" /></body></html>');
    const conn = makeConn('wss://evil.com', [
      { payload: 'hello', timestamp: Date.now() },
    ]);
    expect(checkFormValueInWsPayload([conn], doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkFormValueInWsPayload(null, makeDoc())).toHaveLength(0);
    expect(checkFormValueInWsPayload([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkWsWithoutVisibleWsUi                                          */
/* ================================================================== */

describe('checkWsWithoutVisibleWsUi', () => {
  it('flags WS on page without chat UI', () => {
    const doc = makeDoc('<html><body><div>Login page</div></body></html>');
    const signals = checkWsWithoutVisibleWsUi(doc, [makeConn()]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wsexfil:ws_without_visible_ws_ui');
    expect(signals[0].weight).toBe(0.15);
  });

  it('does NOT flag page with chat widget class', () => {
    const doc = makeDoc('<html><body><div class="chat-widget">Chat</div></body></html>');
    expect(checkWsWithoutVisibleWsUi(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag page with Intercom', () => {
    const doc = makeDoc('<html><body><div id="intercom-container">Help</div></body></html>');
    expect(checkWsWithoutVisibleWsUi(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag page with Drift', () => {
    const doc = makeDoc('<html><body><div class="drift-widget">Support</div></body></html>');
    expect(checkWsWithoutVisibleWsUi(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag when no WS connections', () => {
    const doc = makeDoc('<html><body><div>Login</div></body></html>');
    expect(checkWsWithoutVisibleWsUi(doc, [])).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkWsWithoutVisibleWsUi(null, [makeConn()])).toHaveLength(0);
    expect(checkWsWithoutVisibleWsUi(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  parseWsHostname                                                    */
/* ================================================================== */

describe('parseWsHostname', () => {
  it('parses wss:// URL', () => {
    expect(parseWsHostname('wss://evil.com/path')).toBe('evil.com');
  });

  it('parses ws:// URL', () => {
    expect(parseWsHostname('ws://example.org:8080/ws')).toBe('example.org');
  });

  it('returns empty for invalid URL', () => {
    expect(parseWsHostname('not-a-url')).toBe('');
  });
});

/* ================================================================== */
/*  calculateWsExfilRiskScore                                          */
/* ================================================================== */

describe('calculateWsExfilRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateWsExfilRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'wsexfil:ws_open_on_credential_page', weight: 0.40 },
      { id: 'wsexfil:keystroke_relay_pattern', weight: 0.30 },
    ];
    const { riskScore } = calculateWsExfilRiskScore(signals);
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
    const { riskScore } = calculateWsExfilRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns null/empty for null input', () => {
    const { riskScore, signalList } = calculateWsExfilRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectWsExfilWarningBanner                                         */
/* ================================================================== */

describe('injectWsExfilWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectWsExfilWarningBanner(0.75, [
      { id: 'wsexfil:ws_open_on_credential_page', weight: 0.40 },
      { id: 'wsexfil:keystroke_relay_pattern', weight: 0.30 },
    ]);

    const banner = dom.window.document.getElementById('phishops-wsexfil-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('websocket credential exfiltration');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'wsexfil:test', weight: 0.50 }];
    injectWsExfilWarningBanner(0.50, signals);
    injectWsExfilWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-wsexfil-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectWsExfilWarningBanner(0.95, [{ id: 'wsexfil:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-wsexfil-banner');
    expect(banner.textContent).toContain('Critical');
    expect(banner.textContent).toContain('0.95');
  });
});

/* ================================================================== */
/*  runWsExfilAnalysis (integration)                                   */
/* ================================================================== */

describe('runWsExfilAnalysis', () => {
  it('emits telemetry when risk exceeds alert threshold', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const now = Date.now();
    const conn = makeConn('wss://evil.com/ws', [
      { payload: 'a', timestamp: now },
      { payload: 'b', timestamp: now + 100 },
      { payload: 'c', timestamp: now + 200 },
      { payload: 'd', timestamp: now + 300 },
    ]);

    // Mock chrome.runtime.sendMessage
    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runWsExfilAnalysis(doc, [conn], 'legit.com');

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'WSEXFILGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'WEBSOCKET_CREDENTIAL_EXFIL_DETECTED',
        }),
      }),
    );
  });

  it('does NOT emit when no credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    const conn = makeConn('wss://evil.com/ws');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runWsExfilAnalysis(doc, [conn], 'legit.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when no WS connections', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runWsExfilAnalysis(doc, [], 'legit.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });
});
