/**
 * extension/__tests__/speculation_rules_guard.test.js
 *
 * Tests for SpeculationRulesGuard — Speculation Rules API Phishing Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/speculation_rules_guard.js';
const { checkCrossOriginPrerenderRule, checkCrossOriginEagerPrefetch, checkDynamicRuleInjection, checkSuspiciousUrlPattern, checkPrerenderWithoutNavigation, calculateSrgRiskScore, injectSrgWarningBanner, removeMaliciousRules, parseSpeculationRules, isUrlCrossOrigin, runSrgAnalysis } = globalThis.__phishopsExports['speculation_rules_guard'];

const PAGE_ORIGIN = 'https://legit-bank.com';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html, { url: PAGE_ORIGIN });
  return dom.window.document;
}

function makeRule(opts = {}) {
  return {
    action: opts.action || 'prerender',
    urls: opts.urls || ['https://evil.com/phish'],
    eagerness: opts.eagerness || 'immediate',
    isDynamic: opts.isDynamic ?? false,
    element: opts.element || null,
    timestamp: opts.timestamp || Date.now(),
  };
}

function makeScriptElement(doc, json) {
  const el = doc.createElement('script');
  el.type = 'speculationrules';
  el.textContent = JSON.stringify(json);
  doc.head.appendChild(el);
  return el;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  isUrlCrossOrigin                                                    */
/* ================================================================== */

describe('isUrlCrossOrigin', () => {
  it('detects cross-origin URL', () => {
    expect(isUrlCrossOrigin('https://evil.com/phish', PAGE_ORIGIN)).toBe(true);
  });

  it('returns false for same-origin URL', () => {
    expect(isUrlCrossOrigin('https://legit-bank.com/account', PAGE_ORIGIN)).toBe(false);
  });

  it('handles relative URLs as same-origin', () => {
    expect(isUrlCrossOrigin('/login', PAGE_ORIGIN)).toBe(false);
  });

  it('returns false for invalid URL', () => {
    expect(isUrlCrossOrigin('not://valid', '')).toBe(false);
  });

  it('returns false for null inputs', () => {
    expect(isUrlCrossOrigin(null, PAGE_ORIGIN)).toBe(false);
    expect(isUrlCrossOrigin('https://evil.com', null)).toBe(false);
  });
});

/* ================================================================== */
/*  parseSpeculationRules                                               */
/* ================================================================== */

describe('parseSpeculationRules', () => {
  it('parses prerender rules from script element', () => {
    const doc = makeDoc();
    const el = makeScriptElement(doc, {
      prerender: [{ urls: ['https://evil.com/phish'], eagerness: 'immediate' }],
    });

    const entries = parseSpeculationRules(el, false);
    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe('prerender');
    expect(entries[0].urls).toContain('https://evil.com/phish');
    expect(entries[0].eagerness).toBe('immediate');
    expect(entries[0].isDynamic).toBe(false);
  });

  it('parses prefetch rules', () => {
    const doc = makeDoc();
    const el = makeScriptElement(doc, {
      prefetch: [{ urls: ['/page1', '/page2'], eagerness: 'eager' }],
    });

    const entries = parseSpeculationRules(el, true);
    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe('prefetch');
    expect(entries[0].isDynamic).toBe(true);
    expect(entries[0].eagerness).toBe('eager');
  });

  it('parses both prerender and prefetch in same element', () => {
    const doc = makeDoc();
    const el = makeScriptElement(doc, {
      prerender: [{ urls: ['/a'] }],
      prefetch: [{ urls: ['/b'] }],
    });

    const entries = parseSpeculationRules(el, false);
    expect(entries).toHaveLength(2);
  });

  it('returns empty for malformed JSON', () => {
    const doc = makeDoc();
    const el = doc.createElement('script');
    el.type = 'speculationrules';
    el.textContent = 'not valid json{{{';
    const entries = parseSpeculationRules(el, false);
    expect(entries).toHaveLength(0);
  });

  it('returns empty for null element', () => {
    expect(parseSpeculationRules(null, false)).toHaveLength(0);
  });

  it('defaults eagerness to conservative', () => {
    const doc = makeDoc();
    const el = makeScriptElement(doc, {
      prerender: [{ urls: ['/page'] }],
    });

    const entries = parseSpeculationRules(el, false);
    expect(entries[0].eagerness).toBe('conservative');
  });
});

/* ================================================================== */
/*  checkCrossOriginPrerenderRule                                       */
/* ================================================================== */

describe('checkCrossOriginPrerenderRule', () => {
  it('detects cross-origin prerender rule', () => {
    const rules = [makeRule({ action: 'prerender', urls: ['https://evil.com/phish'] })];
    const signals = checkCrossOriginPrerenderRule(rules, PAGE_ORIGIN);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('srg:cross_origin_prerender_rule');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].crossOriginUrl).toBe('https://evil.com/phish');
  });

  it('does NOT flag same-origin prerender rule', () => {
    const rules = [makeRule({ action: 'prerender', urls: ['https://legit-bank.com/page'] })];
    expect(checkCrossOriginPrerenderRule(rules, PAGE_ORIGIN)).toHaveLength(0);
  });

  it('does NOT flag prefetch rules', () => {
    const rules = [makeRule({ action: 'prefetch', urls: ['https://evil.com/phish'] })];
    expect(checkCrossOriginPrerenderRule(rules, PAGE_ORIGIN)).toHaveLength(0);
  });

  it('handles relative URLs as same-origin', () => {
    const rules = [makeRule({ action: 'prerender', urls: ['/login'] })];
    expect(checkCrossOriginPrerenderRule(rules, PAGE_ORIGIN)).toHaveLength(0);
  });

  it('returns empty for null/empty inputs', () => {
    expect(checkCrossOriginPrerenderRule(null, PAGE_ORIGIN)).toHaveLength(0);
    expect(checkCrossOriginPrerenderRule([], PAGE_ORIGIN)).toHaveLength(0);
    expect(checkCrossOriginPrerenderRule([makeRule()], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCrossOriginEagerPrefetch                                       */
/* ================================================================== */

describe('checkCrossOriginEagerPrefetch', () => {
  it('detects cross-origin immediate prefetch', () => {
    const rules = [makeRule({ action: 'prefetch', urls: ['https://evil.com/page'], eagerness: 'immediate' })];
    const signals = checkCrossOriginEagerPrefetch(rules, PAGE_ORIGIN);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('srg:cross_origin_eager_prefetch');
    expect(signals[0].weight).toBe(0.30);
    expect(signals[0].eagerness).toBe('immediate');
  });

  it('detects cross-origin eager prefetch', () => {
    const rules = [makeRule({ action: 'prefetch', urls: ['https://evil.com/page'], eagerness: 'eager' })];
    expect(checkCrossOriginEagerPrefetch(rules, PAGE_ORIGIN)).toHaveLength(1);
  });

  it('does NOT flag conservative prefetch', () => {
    const rules = [makeRule({ action: 'prefetch', urls: ['https://evil.com/page'], eagerness: 'conservative' })];
    expect(checkCrossOriginEagerPrefetch(rules, PAGE_ORIGIN)).toHaveLength(0);
  });

  it('does NOT flag moderate prefetch', () => {
    const rules = [makeRule({ action: 'prefetch', urls: ['https://evil.com/page'], eagerness: 'moderate' })];
    expect(checkCrossOriginEagerPrefetch(rules, PAGE_ORIGIN)).toHaveLength(0);
  });

  it('does NOT flag same-origin eager prefetch', () => {
    const rules = [makeRule({ action: 'prefetch', urls: ['https://legit-bank.com/page'], eagerness: 'immediate' })];
    expect(checkCrossOriginEagerPrefetch(rules, PAGE_ORIGIN)).toHaveLength(0);
  });

  it('does NOT flag prerender rules', () => {
    const rules = [makeRule({ action: 'prerender', urls: ['https://evil.com/page'], eagerness: 'immediate' })];
    expect(checkCrossOriginEagerPrefetch(rules, PAGE_ORIGIN)).toHaveLength(0);
  });

  it('returns empty for null/empty inputs', () => {
    expect(checkCrossOriginEagerPrefetch(null, PAGE_ORIGIN)).toHaveLength(0);
    expect(checkCrossOriginEagerPrefetch([], PAGE_ORIGIN)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkDynamicRuleInjection                                           */
/* ================================================================== */

describe('checkDynamicRuleInjection', () => {
  it('detects dynamically injected rules', () => {
    const rules = [makeRule({ isDynamic: true })];
    const signals = checkDynamicRuleInjection(rules);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('srg:dynamic_rule_injection');
    expect(signals[0].weight).toBe(0.25);
    expect(signals[0].dynamicCount).toBe(1);
  });

  it('counts multiple dynamic rules', () => {
    const rules = [makeRule({ isDynamic: true }), makeRule({ isDynamic: true })];
    const signals = checkDynamicRuleInjection(rules);
    expect(signals[0].dynamicCount).toBe(2);
  });

  it('does NOT flag static rules', () => {
    const rules = [makeRule({ isDynamic: false })];
    expect(checkDynamicRuleInjection(rules)).toHaveLength(0);
  });

  it('does NOT flag mixed when no dynamic rules', () => {
    const rules = [makeRule({ isDynamic: false }), makeRule({ isDynamic: false })];
    expect(checkDynamicRuleInjection(rules)).toHaveLength(0);
  });

  it('returns empty for null/empty inputs', () => {
    expect(checkDynamicRuleInjection(null)).toHaveLength(0);
    expect(checkDynamicRuleInjection([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSuspiciousUrlPattern                                           */
/* ================================================================== */

describe('checkSuspiciousUrlPattern', () => {
  it('detects login keyword in URL', () => {
    const rules = [makeRule({ urls: ['https://evil.com/login'] })];
    const signals = checkSuspiciousUrlPattern(rules);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('srg:suspicious_url_pattern');
    expect(signals[0].weight).toBe(0.20);
    expect(signals[0].matchedKeyword).toBe('login');
  });

  it('detects password keyword', () => {
    const rules = [makeRule({ urls: ['https://evil.com/reset-password'] })];
    expect(checkSuspiciousUrlPattern(rules)).toHaveLength(1);
  });

  it('detects verify keyword', () => {
    const rules = [makeRule({ urls: ['https://evil.com/verify-account'] })];
    expect(checkSuspiciousUrlPattern(rules)).toHaveLength(1);
  });

  it('detects mfa keyword', () => {
    const rules = [makeRule({ urls: ['https://evil.com/mfa-prompt'] })];
    expect(checkSuspiciousUrlPattern(rules)).toHaveLength(1);
  });

  it('does NOT flag clean URLs', () => {
    const rules = [makeRule({ urls: ['https://example.com/products', 'https://example.com/about'] })];
    expect(checkSuspiciousUrlPattern(rules)).toHaveLength(0);
  });

  it('returns empty for null/empty inputs', () => {
    expect(checkSuspiciousUrlPattern(null)).toHaveLength(0);
    expect(checkSuspiciousUrlPattern([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkPrerenderWithoutNavigation                                     */
/* ================================================================== */

describe('checkPrerenderWithoutNavigation', () => {
  it('detects orphaned prerender rules with no matching anchor', () => {
    const doc = makeDoc('<html><body><p>No links here</p></body></html>');
    const rules = [makeRule({ action: 'prerender', urls: ['https://evil.com/phish'] })];
    const signals = checkPrerenderWithoutNavigation(rules, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('srg:prerender_without_navigation');
    expect(signals[0].weight).toBe(0.15);
    expect(signals[0].orphanedCount).toBe(1);
  });

  it('does NOT flag when matching anchor exists', () => {
    const doc = makeDoc('<html><body><a href="https://evil.com/phish">Link</a></body></html>');
    const rules = [makeRule({ action: 'prerender', urls: ['https://evil.com/phish'] })];
    expect(checkPrerenderWithoutNavigation(rules, doc)).toHaveLength(0);
  });

  it('does NOT flag prefetch rules', () => {
    const doc = makeDoc('<html><body></body></html>');
    const rules = [makeRule({ action: 'prefetch', urls: ['https://evil.com/page'] })];
    expect(checkPrerenderWithoutNavigation(rules, doc)).toHaveLength(0);
  });

  it('handles mix of orphaned and linked prerender URLs', () => {
    const doc = makeDoc('<html><body><a href="https://evil.com/page1">Link</a></body></html>');
    const rules = [makeRule({ action: 'prerender', urls: ['https://evil.com/page1', 'https://evil.com/page2'] })];
    const signals = checkPrerenderWithoutNavigation(rules, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].orphanedCount).toBe(1);
  });

  it('returns empty for null/empty inputs', () => {
    expect(checkPrerenderWithoutNavigation(null, makeDoc())).toHaveLength(0);
    expect(checkPrerenderWithoutNavigation([], makeDoc())).toHaveLength(0);
    expect(checkPrerenderWithoutNavigation([makeRule()], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateSrgRiskScore                                               */
/* ================================================================== */

describe('calculateSrgRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculateSrgRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'srg:cross_origin_prerender_rule', weight: 0.40 },
      { id: 'srg:cross_origin_eager_prefetch', weight: 0.30 },
    ];
    const { riskScore } = calculateSrgRiskScore(signals);
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
    const { riskScore } = calculateSrgRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for null input', () => {
    const { riskScore } = calculateSrgRiskScore(null);
    expect(riskScore).toBe(0);
  });
});

/* ================================================================== */
/*  removeMaliciousRules                                                */
/* ================================================================== */

describe('removeMaliciousRules', () => {
  it('removes elements at block threshold', () => {
    const doc = makeDoc();
    const el = makeScriptElement(doc, { prerender: [{ urls: ['/evil'] }] });
    const rules = [makeRule({ element: el })];

    expect(el.parentNode).not.toBeNull();
    const removed = removeMaliciousRules(rules, 0.75);
    expect(removed).toBe(1);
    expect(el.parentNode).toBeNull();
  });

  it('does NOT remove elements below block threshold', () => {
    const doc = makeDoc();
    const el = makeScriptElement(doc, { prerender: [{ urls: ['/evil'] }] });
    const rules = [makeRule({ element: el })];

    const removed = removeMaliciousRules(rules, 0.60);
    expect(removed).toBe(0);
    expect(el.parentNode).not.toBeNull();
  });

  it('deduplicates element removal', () => {
    const doc = makeDoc();
    const el = makeScriptElement(doc, { prerender: [{ urls: ['/a'] }] });
    // Two rule entries pointing to the same element
    const rules = [makeRule({ element: el }), makeRule({ element: el })];

    const removed = removeMaliciousRules(rules, 0.80);
    expect(removed).toBe(1);
  });
});

/* ================================================================== */
/*  injectSrgWarningBanner                                              */
/* ================================================================== */

describe('injectSrgWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectSrgWarningBanner(0.75, [
      { id: 'srg:cross_origin_prerender_rule', weight: 0.40 },
      { id: 'srg:cross_origin_eager_prefetch', weight: 0.30 },
    ]);

    const banner = dom.window.document.getElementById('phishops-srg-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('speculation rules phishing');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'srg:test', weight: 0.50 }];
    injectSrgWarningBanner(0.50, signals);
    injectSrgWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-srg-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays correct severity for Critical', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectSrgWarningBanner(0.95, [{ id: 'srg:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-srg-banner');
    expect(banner.textContent).toContain('Critical');
    expect(banner.textContent).toContain('0.95');
  });

  it('displays correct severity for High', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectSrgWarningBanner(0.75, [{ id: 'srg:test', weight: 0.75 }]);

    const banner = dom.window.document.getElementById('phishops-srg-banner');
    expect(banner.textContent).toContain('High');
  });
});

/* ================================================================== */
/*  runSrgAnalysis (integration)                                        */
/* ================================================================== */

describe('runSrgAnalysis', () => {
  it('emits telemetry when risk exceeds alert threshold', () => {
    const doc = makeDoc('<html><body></body></html>');
    const rules = [
      makeRule({ action: 'prerender', urls: ['https://evil.com/login'], isDynamic: true }),
    ];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSrgAnalysis(doc, rules, PAGE_ORIGIN);

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'SPECULATIONRULESGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'SPECULATION_RULES_PHISHING_DETECTED',
        }),
      }),
    );
  });

  it('includes rulesRemoved count in payload at block threshold', () => {
    const doc = makeDoc('<html><body></body></html>');
    const el = doc.createElement('script');
    el.type = 'speculationrules';
    doc.head.appendChild(el);

    const rules = [
      makeRule({ action: 'prerender', urls: ['https://evil.com/login'], isDynamic: true, element: el }),
    ];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSrgAnalysis(doc, rules, PAGE_ORIGIN);

    const payload = sendMessage.mock.calls[0][0].payload;
    expect(payload.rulesRemoved).toBeGreaterThanOrEqual(0);
  });

  it('does NOT emit when no rules present', () => {
    const doc = makeDoc('<html><body></body></html>');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSrgAnalysis(doc, [], PAGE_ORIGIN);

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when risk below threshold', () => {
    const doc = makeDoc('<html><body><a href="https://legit-bank.com/page">Link</a></body></html>');
    // Same-origin, non-dynamic, non-suspicious URL, with matching anchor — no signals fire
    const rules = [makeRule({
      action: 'prerender',
      urls: ['https://legit-bank.com/page'],
      isDynamic: false,
    })];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSrgAnalysis(doc, rules, PAGE_ORIGIN);

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('handles null doc gracefully', () => {
    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runSrgAnalysis(null, [makeRule()], PAGE_ORIGIN);

    expect(sendMessage).not.toHaveBeenCalled();
  });
});
