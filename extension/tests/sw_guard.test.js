/**
 * extension/__tests__/sw_guard.test.js
 *
 * Tests for ServiceWorkerGuard — Phishing Persistence via Service Worker Registration
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkRegisterOnCredentialPage,
  checkFetchHandlerInSwScript,
  checkPushSubscribeWithCredContext,
  checkCacheApiStoresCredentialPage,
  checkBackgroundSyncRegistration,
  calculateSwRiskScore,
  injectSwWarningBanner,
  isKnownFramework,
  runSwGuardAnalysis,
} from '../content/sw_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

function makeReg(scriptUrl = '/sw.js', scriptSource = '', isFramework = false) {
  return { scriptUrl, scriptSource, isFramework };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkRegisterOnCredentialPage                                      */
/* ================================================================== */

describe('checkRegisterOnCredentialPage', () => {
  it('detects SW registration on page with password field', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const signals = checkRegisterOnCredentialPage(doc, [makeReg()]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sw:register_on_credential_page');
    expect(signals[0].weight).toBe(0.40);
  });

  it('detects SW registration on page with email field', () => {
    const doc = makeDoc('<html><body><input type="email" /></body></html>');
    expect(checkRegisterOnCredentialPage(doc, [makeReg()])).toHaveLength(1);
  });

  it('does NOT flag when all registrations are known frameworks', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const reg = makeReg('/workbox-sw.js', '', true);
    expect(checkRegisterOnCredentialPage(doc, [reg])).toHaveLength(0);
  });

  it('does NOT flag page without credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    expect(checkRegisterOnCredentialPage(doc, [makeReg()])).toHaveLength(0);
  });

  it('does NOT flag when no registrations', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    expect(checkRegisterOnCredentialPage(doc, [])).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkRegisterOnCredentialPage(null, [makeReg()])).toHaveLength(0);
    expect(checkRegisterOnCredentialPage(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkFetchHandlerInSwScript                                        */
/* ================================================================== */

describe('checkFetchHandlerInSwScript', () => {
  it('detects addEventListener("fetch") in SW source', () => {
    const reg = makeReg('/sw.js', 'self.addEventListener("fetch", (e) => { e.respondWith(fetch(e.request)); });');
    const signals = checkFetchHandlerInSwScript([reg]);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sw:fetch_handler_in_sw_script');
    expect(signals[0].weight).toBe(0.30);
  });

  it('detects onfetch = handler pattern', () => {
    const reg = makeReg('/sw.js', 'self.onfetch = function(e) {}');
    expect(checkFetchHandlerInSwScript([reg])).toHaveLength(1);
  });

  it('counts suspicious patterns', () => {
    const source = `
      self.addEventListener('fetch', (e) => {
        const all = clients.matchAll();
        const cloned = e.request.clone();
        importScripts('/payload.js');
      });
    `;
    const reg = makeReg('/sw.js', source);
    const signals = checkFetchHandlerInSwScript([reg]);
    expect(signals).toHaveLength(1);
    expect(signals[0].suspiciousPatternCount).toBeGreaterThanOrEqual(2);
  });

  it('does NOT flag SW without fetch handler', () => {
    const reg = makeReg('/sw.js', 'self.addEventListener("push", (e) => {});');
    expect(checkFetchHandlerInSwScript([reg])).toHaveLength(0);
  });

  it('skips framework registrations', () => {
    const reg = makeReg('/sw.js', 'self.addEventListener("fetch", () => {})', true);
    expect(checkFetchHandlerInSwScript([reg])).toHaveLength(0);
  });

  it('returns empty when no source available', () => {
    const reg = makeReg('/sw.js', '');
    expect(checkFetchHandlerInSwScript([reg])).toHaveLength(0);
  });

  it('returns empty for null input', () => {
    expect(checkFetchHandlerInSwScript(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkPushSubscribeWithCredContext                                   */
/* ================================================================== */

describe('checkPushSubscribeWithCredContext', () => {
  it('detects push subscribe on credential page', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const signals = checkPushSubscribeWithCredContext(doc, true);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sw:push_subscribe_with_cred_context');
    expect(signals[0].weight).toBe(0.25);
  });

  it('does NOT flag when push not subscribed', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    expect(checkPushSubscribeWithCredContext(doc, false)).toHaveLength(0);
  });

  it('does NOT flag when no credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    expect(checkPushSubscribeWithCredContext(doc, true)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkPushSubscribeWithCredContext(null, true)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCacheApiStoresCredentialPage                                  */
/* ================================================================== */

describe('checkCacheApiStoresCredentialPage', () => {
  it('detects cached URL matching current credential page', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const signals = checkCacheApiStoresCredentialPage(
      ['https://phish.com/login'], 'https://phish.com/login', doc,
    );
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sw:cache_api_stores_credential_page');
    expect(signals[0].weight).toBe(0.20);
  });

  it('matches URL ignoring query params', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    expect(checkCacheApiStoresCredentialPage(
      ['https://phish.com/login'], 'https://phish.com/login?token=abc', doc,
    )).toHaveLength(1);
  });

  it('does NOT flag when cached URL does not match', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    expect(checkCacheApiStoresCredentialPage(
      ['https://other.com/page'], 'https://phish.com/login', doc,
    )).toHaveLength(0);
  });

  it('does NOT flag when no credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    expect(checkCacheApiStoresCredentialPage(
      ['https://phish.com/login'], 'https://phish.com/login', doc,
    )).toHaveLength(0);
  });

  it('returns empty for empty/null inputs', () => {
    expect(checkCacheApiStoresCredentialPage([], 'url', makeDoc())).toHaveLength(0);
    expect(checkCacheApiStoresCredentialPage(null, 'url', makeDoc())).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkBackgroundSyncRegistration                                    */
/* ================================================================== */

describe('checkBackgroundSyncRegistration', () => {
  it('detects background sync registration', () => {
    const signals = checkBackgroundSyncRegistration(true);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sw:background_sync_registration');
    expect(signals[0].weight).toBe(0.15);
  });

  it('returns empty when not registered', () => {
    expect(checkBackgroundSyncRegistration(false)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  isKnownFramework                                                   */
/* ================================================================== */

describe('isKnownFramework', () => {
  it('detects Workbox', () => {
    expect(isKnownFramework('/workbox-sw.js', '')).toBe(true);
  });

  it('detects Firebase Messaging', () => {
    expect(isKnownFramework('/firebase-messaging-sw.js', '')).toBe(true);
  });

  it('detects OneSignal in source', () => {
    expect(isKnownFramework('/sw.js', 'importScripts("https://cdn.onesignal.com/sdks/OneSignalSDK.js");')).toBe(true);
  });

  it('does NOT flag unknown scripts', () => {
    expect(isKnownFramework('/evil-sw.js', 'self.addEventListener("fetch", () => {})')).toBe(false);
  });
});

/* ================================================================== */
/*  calculateSwRiskScore                                               */
/* ================================================================== */

describe('calculateSwRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateSwRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'sw:register_on_credential_page', weight: 0.40 },
      { id: 'sw:fetch_handler_in_sw_script', weight: 0.30 },
    ];
    const { riskScore } = calculateSwRiskScore(signals);
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
    const { riskScore } = calculateSwRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns null/empty for null input', () => {
    const { riskScore, signalList } = calculateSwRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectSwWarningBanner                                              */
/* ================================================================== */

describe('injectSwWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectSwWarningBanner(0.70, [
      { id: 'sw:register_on_credential_page', weight: 0.40 },
      { id: 'sw:fetch_handler_in_sw_script', weight: 0.30 },
    ]);

    const banner = dom.window.document.getElementById('phishops-sw-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('suspicious service worker');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'sw:test', weight: 0.50 }];
    injectSwWarningBanner(0.50, signals);
    injectSwWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-sw-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays correct severity', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectSwWarningBanner(0.95, [{ id: 'sw:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-sw-banner');
    expect(banner.textContent).toContain('Critical');
  });
});

/* ================================================================== */
/*  runSwGuardAnalysis (integration)                                   */
/* ================================================================== */

describe('runSwGuardAnalysis', () => {
  it('emits telemetry when risk exceeds alert threshold', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const reg = makeReg('/sw.js', 'self.addEventListener("fetch", (e) => { e.respondWith(fetch(e.request)); });');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSwGuardAnalysis(doc, [reg], false, false, [], 'https://phish.com/login');

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'SWGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'SERVICE_WORKER_PERSISTENCE_DETECTED',
          riskScore: expect.any(Number),
        }),
      }),
    );
  });

  it('does NOT emit when no credential fields', () => {
    const doc = makeDoc('<html><body><input type="text" /></body></html>');
    const reg = makeReg('/sw.js', 'self.addEventListener("fetch", () => {});');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSwGuardAnalysis(doc, [reg], false, false, [], 'https://example.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when only framework SWs registered', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const reg = makeReg('/workbox-sw.js', 'workbox precaching', true);

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSwGuardAnalysis(doc, [reg], false, false, [], 'https://example.com');

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('includes all fired signals in telemetry', () => {
    const doc = makeDoc('<html><body><input type="password" /></body></html>');
    const reg = makeReg('/sw.js', 'self.addEventListener("fetch", (e) => { clients.matchAll(); });');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSwGuardAnalysis(doc, [reg], true, true, ['https://phish.com/login'], 'https://phish.com/login');

    const payload = sendMessage.mock.calls[0][0].payload;
    expect(payload.signals).toContain('sw:register_on_credential_page');
    expect(payload.signals).toContain('sw:fetch_handler_in_sw_script');
    expect(payload.signals).toContain('sw:push_subscribe_with_cred_context');
    expect(payload.signals).toContain('sw:cache_api_stores_credential_page');
    expect(payload.signals).toContain('sw:background_sync_registration');
  });
});
