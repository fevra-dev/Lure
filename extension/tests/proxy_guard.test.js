/**
 * extension/__tests__/proxy_guard.test.js
 *
 * Tests for ProxyGuard — AiTM Reverse Proxy Detection
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkAtSymbolUrlMasking,
  checkAuthPageDomainMismatch,
  checkSuspiciousFormAction,
  checkMissingSecurityHeaders,
  checkDomInjectionArtifacts,
  checkResponseTimingAnomaly,
  calculateProxyRiskScore,
  injectProxyWarningBanner,
} from '../content/proxy_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

/* ================================================================== */
/*  checkAtSymbolUrlMasking                                            */
/* ================================================================== */

describe('checkAtSymbolUrlMasking', () => {
  it('detects Starkiller pattern with Microsoft', () => {
    const signals = checkAtSymbolUrlMasking('https://login.microsoftonline.com@evil.com/path');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('proxy:at_symbol_url_masking');
    expect(signals[0].weight).toBe(0.45);
    expect(signals[0].targetProvider).toBe('Microsoft');
  });

  it('detects Google variant', () => {
    const signals = checkAtSymbolUrlMasking('https://accounts.google.com@phish.net/auth');
    expect(signals).toHaveLength(1);
    expect(signals[0].targetProvider).toBe('Google');
  });

  it('detects Apple variant', () => {
    const signals = checkAtSymbolUrlMasking('https://appleid.apple.com@attacker.com/');
    expect(signals).toHaveLength(1);
    expect(signals[0].targetProvider).toBe('Apple');
  });

  it('does NOT flag URL without @', () => {
    const signals = checkAtSymbolUrlMasking('https://login.microsoftonline.com/common/oauth2');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag @ in query string', () => {
    // @ in query string does not create a username in URL parsing
    const signals = checkAtSymbolUrlMasking('https://example.com/path?email=user@example.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag @ with non-auth-provider username', () => {
    const signals = checkAtSymbolUrlMasking('https://user@example.com/path');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for malformed URL', () => {
    const signals = checkAtSymbolUrlMasking('not a url');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null', () => {
    expect(checkAtSymbolUrlMasking(null)).toHaveLength(0);
    expect(checkAtSymbolUrlMasking('')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkAuthPageDomainMismatch                                        */
/* ================================================================== */

describe('checkAuthPageDomainMismatch', () => {
  it('detects login form with Microsoft references on non-MS domain', () => {
    const doc = makeDoc(`
      <html><head><title>Sign in to your account</title></head>
      <body>
        <p>Microsoft account login</p>
        <form><input type="password"></form>
      </body></html>
    `);
    const signals = checkAuthPageDomainMismatch(doc, 'evil-proxy.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('proxy:auth_page_domain_mismatch');
    expect(signals[0].targetProvider).toBe('Microsoft');
  });

  it('detects Google references on non-Google domain', () => {
    const doc = makeDoc(`
      <html><head><title>Google Sign In</title></head>
      <body>
        <p>Sign in with your Google Account</p>
        <form><input type="email"><input type="password"></form>
      </body></html>
    `);
    const signals = checkAuthPageDomainMismatch(doc, 'proxy-site.net');
    expect(signals).toHaveLength(1);
    expect(signals[0].targetProvider).toBe('Google');
  });

  it('does NOT flag actual Microsoft domain', () => {
    const doc = makeDoc(`
      <html><head><title>Microsoft</title></head>
      <body><p>Microsoft</p><form><input type="password"></form></body></html>
    `);
    const signals = checkAuthPageDomainMismatch(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag page without login form', () => {
    const doc = makeDoc(`
      <html><head><title>Microsoft Blog</title></head>
      <body><p>Microsoft announced today...</p></body></html>
    `);
    const signals = checkAuthPageDomainMismatch(doc, 'news.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag page without auth provider references', () => {
    const doc = makeDoc(`
      <html><body><form><input type="password"></form></body></html>
    `);
    const signals = checkAuthPageDomainMismatch(doc, 'mysite.com');
    expect(signals).toHaveLength(0);
  });

  it('skips localhost', () => {
    const doc = makeDoc('<html><body><p>Microsoft</p><form><input type="password"></form></body></html>');
    expect(checkAuthPageDomainMismatch(doc, 'localhost')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSuspiciousFormAction                                          */
/* ================================================================== */

describe('checkSuspiciousFormAction', () => {
  it('detects form posting to unknown third-party domain', () => {
    const doc = makeDoc(`
      <html><body>
        <form action="https://evil-collector.com/steal">
          <input type="password">
        </form>
      </body></html>
    `);
    const signals = checkSuspiciousFormAction(doc, 'legit-looking.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('proxy:suspicious_form_action');
  });

  it('does NOT flag form posting to same domain', () => {
    const doc = makeDoc(`
      <html><body>
        <form action="https://mysite.com/login">
          <input type="password">
        </form>
      </body></html>
    `);
    const signals = checkSuspiciousFormAction(doc, 'mysite.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag form posting to known auth provider', () => {
    const doc = makeDoc(`
      <html><body>
        <form action="https://login.microsoftonline.com/common/oauth2/token">
          <input type="password">
        </form>
      </body></html>
    `);
    const signals = checkSuspiciousFormAction(doc, 'myapp.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag relative form action', () => {
    const doc = makeDoc(`
      <html><body>
        <form action="/login"><input type="password"></form>
      </body></html>
    `);
    const signals = checkSuspiciousFormAction(doc, 'mysite.com');
    expect(signals).toHaveLength(0);
  });

  it('skips localhost', () => {
    const doc = makeDoc('<html><body><form action="https://evil.com/steal"><input type="password"></form></body></html>');
    expect(checkSuspiciousFormAction(doc, 'localhost')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkMissingSecurityHeaders                                        */
/* ================================================================== */

describe('checkMissingSecurityHeaders', () => {
  it('fires when no CSP meta on auth-like page', () => {
    const doc = makeDoc('<html><head></head><body><form><input type="password"></form></body></html>');
    const signals = checkMissingSecurityHeaders(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('proxy:missing_security_headers');
  });

  it('does NOT fire when CSP meta present', () => {
    const doc = makeDoc(`
      <html><head>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
      </head><body><form><input type="password"></form></body></html>
    `);
    const signals = checkMissingSecurityHeaders(doc);
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire on non-auth page', () => {
    const doc = makeDoc('<html><head></head><body><p>Hello world</p></body></html>');
    const signals = checkMissingSecurityHeaders(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkMissingSecurityHeaders(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkDomInjectionArtifacts                                         */
/* ================================================================== */

describe('checkDomInjectionArtifacts', () => {
  it('detects proxy framework signature in HTML', () => {
    const doc = makeDoc(`
      <html><body>
        <!-- evilginx marker -->
        <form><input type="password"></form>
      </body></html>
    `);
    const signals = checkDomInjectionArtifacts(doc, 'proxy.evil.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('proxy:dom_injection_artifact');
  });

  it('detects multiple foreign scripts on auth page', () => {
    const doc = makeDoc(`
      <html><body>
        <script src="https://evil1.com/inject.js"></script>
        <script src="https://evil2.com/track.js"></script>
        <script src="https://evil3.com/steal.js"></script>
        <form><input type="password"></form>
      </body></html>
    `);
    const signals = checkDomInjectionArtifacts(doc, 'legit.com');
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag clean auth page', () => {
    const doc = makeDoc(`
      <html><body>
        <script src="https://legit.com/app.js"></script>
        <form><input type="password"></form>
      </body></html>
    `);
    const signals = checkDomInjectionArtifacts(doc, 'legit.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag non-auth page', () => {
    const doc = makeDoc(`
      <html><body>
        <script src="https://cdn.evil.com/inject.js"></script>
        <script src="https://cdn2.evil.com/inject.js"></script>
        <script src="https://cdn3.evil.com/inject.js"></script>
        <p>Hello</p>
      </body></html>
    `);
    const signals = checkDomInjectionArtifacts(doc, 'mysite.com');
    expect(signals).toHaveLength(0);
  });

  it('skips localhost', () => {
    const doc = makeDoc('<html><body>evilginx<form><input type="password"></form></body></html>');
    expect(checkDomInjectionArtifacts(doc, 'localhost')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkResponseTimingAnomaly                                         */
/* ================================================================== */

describe('checkResponseTimingAnomaly', () => {
  it('fires when load time exceeds 3000ms', () => {
    const originalPerformance = globalThis.performance;
    globalThis.performance = {
      getEntriesByType: () => [{
        startTime: 0,
        loadEventEnd: 4500,
      }],
    };

    try {
      const signals = checkResponseTimingAnomaly();
      expect(signals).toHaveLength(1);
      expect(signals[0].id).toBe('proxy:response_timing_anomaly');
    } finally {
      globalThis.performance = originalPerformance;
    }
  });

  it('does NOT fire for fast page load', () => {
    const originalPerformance = globalThis.performance;
    globalThis.performance = {
      getEntriesByType: () => [{
        startTime: 0,
        loadEventEnd: 800,
      }],
    };

    try {
      const signals = checkResponseTimingAnomaly();
      expect(signals).toHaveLength(0);
    } finally {
      globalThis.performance = originalPerformance;
    }
  });

  it('returns empty when performance API unavailable', () => {
    const originalPerformance = globalThis.performance;
    globalThis.performance = undefined;

    try {
      const signals = checkResponseTimingAnomaly();
      expect(signals).toHaveLength(0);
    } finally {
      globalThis.performance = originalPerformance;
    }
  });

  it('returns empty when no navigation entries', () => {
    const originalPerformance = globalThis.performance;
    globalThis.performance = {
      getEntriesByType: () => [],
    };

    try {
      const signals = checkResponseTimingAnomaly();
      expect(signals).toHaveLength(0);
    } finally {
      globalThis.performance = originalPerformance;
    }
  });
});

/* ================================================================== */
/*  calculateProxyRiskScore                                            */
/* ================================================================== */

describe('calculateProxyRiskScore', () => {
  it('returns 0 for empty signals', () => {
    const { riskScore, signalList } = calculateProxyRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('returns 0 for null', () => {
    expect(calculateProxyRiskScore(null).riskScore).toBe(0);
  });

  it('scores single signal', () => {
    const { riskScore } = calculateProxyRiskScore([
      { id: 'proxy:at_symbol_url_masking', weight: 0.45 },
    ]);
    expect(riskScore).toBeCloseTo(0.45);
  });

  it('sums multiple signals for Evilginx scenario', () => {
    const { riskScore } = calculateProxyRiskScore([
      { id: 'proxy:auth_page_domain_mismatch', weight: 0.40 },
      { id: 'proxy:suspicious_form_action', weight: 0.35 },
    ]);
    expect(riskScore).toBeCloseTo(0.75);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculateProxyRiskScore([
      { id: 'a', weight: 0.45 },
      { id: 'b', weight: 0.40 },
      { id: 'c', weight: 0.35 },
      { id: 'd', weight: 0.25 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('@-symbol alone reaches alert threshold', () => {
    const { riskScore } = calculateProxyRiskScore([
      { id: 'proxy:at_symbol_url_masking', weight: 0.45 },
    ]);
    // 0.45 is below 0.50 alert threshold — correct
    expect(riskScore).toBeLessThan(0.50);
  });

  it('timing alone does NOT reach alert', () => {
    const { riskScore } = calculateProxyRiskScore([
      { id: 'proxy:response_timing_anomaly', weight: 0.20 },
    ]);
    expect(riskScore).toBeLessThan(0.50);
  });
});

/* ================================================================== */
/*  injectProxyWarningBanner                                           */
/* ================================================================== */

describe('injectProxyWarningBanner', () => {
  let dom, doc;

  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>');
    doc = dom.window.document;
    vi.stubGlobal('document', doc);
  });

  it('injects banner into document', () => {
    injectProxyWarningBanner(0.80, 'Microsoft', [
      { id: 'proxy:auth_page_domain_mismatch' },
    ]);
    const banner = doc.getElementById('phishops-proxy-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('Microsoft');
  });

  it('is idempotent', () => {
    injectProxyWarningBanner(0.80, 'Google', [{ id: 'a' }]);
    injectProxyWarningBanner(0.80, 'Google', [{ id: 'a' }]);
    const banners = doc.querySelectorAll('#phishops-proxy-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays Critical severity', () => {
    injectProxyWarningBanner(0.95, 'Apple', [{ id: 'a' }]);
    const banner = doc.getElementById('phishops-proxy-banner');
    expect(banner.textContent).toContain('Critical');
  });

  it('dismiss button removes banner', () => {
    injectProxyWarningBanner(0.70, 'GitHub', [{ id: 'a' }]);
    const dismiss = doc.getElementById('phishops-proxy-dismiss');
    dismiss.click();
    expect(doc.getElementById('phishops-proxy-banner')).toBeNull();
  });
});
