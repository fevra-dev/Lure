/**
 * extension/__tests__/webtransport_guard.test.js
 *
 * Tests for WebTransportGuard — WebTransport AiTM Credential Relay Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkTransportOnCredentialPage,
  checkSelfSignedCertHashes,
  checkCrossOriginTransportWithCreds,
  checkCredentialDataInStream,
  checkTransportWithoutMediaContext,
  calculateWtRiskScore,
  injectWtWarningBanner,
  parseWtHostname,
  runWtAnalysis,
} from '../content/webtransport_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

function makeConn(url = 'https://evil.com/wt', opts = {}) {
  return {
    url,
    hostname: parseWtHostname(url),
    usesHashCerts: opts.usesHashCerts || false,
    writeLog: opts.writeLog || [],
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkTransportOnCredentialPage                                      */
/* ================================================================== */

describe('checkTransportOnCredentialPage', () => {
  it('detects WT connection on page with password field', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const signals = checkTransportOnCredentialPage(doc, [makeConn()]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wt:transport_on_credential_page');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].wtCount).toBe(1);
    expect(signals[0].credFieldCount).toBe(1);
  });

  it('detects WT connection on page with email field', () => {
    const doc = makeDoc('<html><body><input type="email" /></body></html>');
    const signals = checkTransportOnCredentialPage(doc, [makeConn()]);
    expect(signals).toHaveLength(1);
  });

  it('detects WT connection on page with autocomplete=current-password', () => {
    const doc = makeDoc('<html><body><input autocomplete="current-password" /></body></html>');
    expect(checkTransportOnCredentialPage(doc, [makeConn()])).toHaveLength(1);
  });

  it('does NOT flag page without credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    expect(checkTransportOnCredentialPage(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag when no WT connections', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    expect(checkTransportOnCredentialPage(doc, [])).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkTransportOnCredentialPage(null, [makeConn()])).toHaveLength(0);
    expect(checkTransportOnCredentialPage(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSelfSignedCertHashes                                           */
/* ================================================================== */

describe('checkSelfSignedCertHashes', () => {
  it('detects connection with serverCertificateHashes', () => {
    const conn = makeConn('https://evil.com/wt', { usesHashCerts: true });
    const signals = checkSelfSignedCertHashes([conn]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wt:self_signed_cert_hashes');
    expect(signals[0].weight).toBe(0.30);
  });

  it('does NOT flag connection without hash certs', () => {
    const conn = makeConn('https://evil.com/wt', { usesHashCerts: false });
    expect(checkSelfSignedCertHashes([conn])).toHaveLength(0);
  });

  it('returns empty for null/empty connections', () => {
    expect(checkSelfSignedCertHashes(null)).toHaveLength(0);
    expect(checkSelfSignedCertHashes([])).toHaveLength(0);
  });

  it('detects across mixed connections', () => {
    const conns = [
      makeConn('https://clean.com/wt', { usesHashCerts: false }),
      makeConn('https://evil.com/wt', { usesHashCerts: true }),
    ];
    expect(checkSelfSignedCertHashes(conns)).toHaveLength(1);
  });
});

/* ================================================================== */
/*  checkCrossOriginTransportWithCreds                                  */
/* ================================================================== */

describe('checkCrossOriginTransportWithCreds', () => {
  it('detects cross-origin WT on credential page', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const conn = makeConn('https://evil.com/wt');
    const signals = checkCrossOriginTransportWithCreds([conn], 'legit-bank.com', doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wt:cross_origin_transport_with_creds');
    expect(signals[0].weight).toBe(0.25);
    expect(signals[0].wtHostname).toBe('evil.com');
  });

  it('does NOT flag same-origin WT', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const conn = makeConn('https://legit-bank.com/wt');
    expect(checkCrossOriginTransportWithCreds([conn], 'legit-bank.com', doc)).toHaveLength(0);
  });

  it('does NOT flag cross-origin WT without credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    const conn = makeConn('https://evil.com/wt');
    expect(checkCrossOriginTransportWithCreds([conn], 'legit-bank.com', doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCrossOriginTransportWithCreds(null, 'x', makeDoc())).toHaveLength(0);
    expect(checkCrossOriginTransportWithCreds([], null, makeDoc())).toHaveLength(0);
    expect(checkCrossOriginTransportWithCreds([], 'x', null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCredentialDataInStream                                         */
/* ================================================================== */

describe('checkCredentialDataInStream', () => {
  it('detects input value appearing in stream write payload', () => {
    const doc = makeDoc('<html><body><input type="password" value="hunter2" /></body></html>');
    const conn = makeConn('https://evil.com/wt', {
      writeLog: [{ payload: '{"pass":"hunter2"}', timestamp: Date.now() }],
    });
    const signals = checkCredentialDataInStream([conn], doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wt:credential_data_in_stream');
    expect(signals[0].weight).toBe(0.20);
    expect(signals[0].matchedLength).toBe(7);
  });

  it('does NOT flag when input value is too short (<3 chars)', () => {
    const doc = makeDoc('<html><body><input type="password" value="ab" /></body></html>');
    const conn = makeConn('https://evil.com/wt', {
      writeLog: [{ payload: 'ab', timestamp: Date.now() }],
    });
    expect(checkCredentialDataInStream([conn], doc)).toHaveLength(0);
  });

  it('does NOT flag when payload does not contain input value', () => {
    const doc = makeDoc('<html><body><input type="password" value="secret123" /></body></html>');
    const conn = makeConn('https://evil.com/wt', {
      writeLog: [{ payload: 'unrelated data', timestamp: Date.now() }],
    });
    expect(checkCredentialDataInStream([conn], doc)).toHaveLength(0);
  });

  it('does NOT flag when no credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" value="hello world" /></body></html>');
    const conn = makeConn('https://evil.com/wt', {
      writeLog: [{ payload: 'hello world', timestamp: Date.now() }],
    });
    expect(checkCredentialDataInStream([conn], doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCredentialDataInStream(null, makeDoc())).toHaveLength(0);
    expect(checkCredentialDataInStream([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkTransportWithoutMediaContext                                    */
/* ================================================================== */

describe('checkTransportWithoutMediaContext', () => {
  it('flags WT on page without media context', () => {
    const doc = makeDoc('<html><body><div>Login page</div></body></html>');
    const signals = checkTransportWithoutMediaContext(doc, [makeConn()]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('wt:transport_without_media_context');
    expect(signals[0].weight).toBe(0.15);
  });

  it('does NOT flag page with video element', () => {
    const doc = makeDoc('<html><body><video src="stream.mp4"></video></body></html>');
    expect(checkTransportWithoutMediaContext(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag page with canvas element', () => {
    const doc = makeDoc('<html><body><canvas id="render"></canvas></body></html>');
    expect(checkTransportWithoutMediaContext(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag page with player class', () => {
    const doc = makeDoc('<html><body><div class="video-player">Streaming</div></body></html>');
    expect(checkTransportWithoutMediaContext(doc, [makeConn()])).toHaveLength(0);
  });

  it('does NOT flag when no WT connections', () => {
    const doc = makeDoc('<html><body><div>Login</div></body></html>');
    expect(checkTransportWithoutMediaContext(doc, [])).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkTransportWithoutMediaContext(null, [makeConn()])).toHaveLength(0);
    expect(checkTransportWithoutMediaContext(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  parseWtHostname                                                     */
/* ================================================================== */

describe('parseWtHostname', () => {
  it('parses https:// URL', () => {
    expect(parseWtHostname('https://evil.com/path')).toBe('evil.com');
  });

  it('parses URL with port', () => {
    expect(parseWtHostname('https://example.org:4433/wt')).toBe('example.org');
  });

  it('returns empty for invalid URL', () => {
    expect(parseWtHostname('not-a-url')).toBe('');
  });
});

/* ================================================================== */
/*  calculateWtRiskScore                                                */
/* ================================================================== */

describe('calculateWtRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateWtRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'wt:transport_on_credential_page', weight: 0.40 },
      { id: 'wt:self_signed_cert_hashes', weight: 0.30 },
    ];
    const { riskScore } = calculateWtRiskScore(signals);
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
    const { riskScore } = calculateWtRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for null input', () => {
    const { riskScore, signalList } = calculateWtRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectWtWarningBanner                                               */
/* ================================================================== */

describe('injectWtWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectWtWarningBanner(0.75, [
      { id: 'wt:transport_on_credential_page', weight: 0.40 },
      { id: 'wt:self_signed_cert_hashes', weight: 0.30 },
    ]);

    const banner = dom.window.document.getElementById('phishops-wt-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('webtransport credential relay');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'wt:test', weight: 0.50 }];
    injectWtWarningBanner(0.50, signals);
    injectWtWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-wt-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectWtWarningBanner(0.95, [{ id: 'wt:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-wt-banner');
    expect(banner.textContent).toContain('Critical');
    expect(banner.textContent).toContain('0.95');
  });
});

/* ================================================================== */
/*  runWtAnalysis (integration)                                         */
/* ================================================================== */

describe('runWtAnalysis', () => {
  it('emits telemetry when risk exceeds alert threshold', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const conn = makeConn('https://evil.com/wt', { usesHashCerts: true });

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runWtAnalysis(doc, [conn], 'legit.com');

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'WEBTRANSPORTGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'WEBTRANSPORT_CREDENTIAL_EXFIL_DETECTED',
        }),
      }),
    );
  });

  it('does NOT emit when no credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    const conn = makeConn('https://evil.com/wt');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runWtAnalysis(doc, [conn], 'legit.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when no WT connections', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runWtAnalysis(doc, [], 'legit.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });
});
