/**
 * extension/__tests__/phishvision.test.js
 *
 * Tests for PhishVision — Brand Impersonation Detection
 *
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkBrandKeywordSignals,
  checkLoginFormSignals,
  checkDomainSuspicion,
  checkTextToHtmlRatio,
  checkFaviconBrandMatch,
  checkColorPaletteMatch,
  checkLOTLTrustedDomain,
  calculatePhishVisionRiskScore,
  injectPhishVisionWarningBanner,
} from '../content/phishvision.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

/* ================================================================== */
/*  checkBrandKeywordSignals                                           */
/* ================================================================== */

describe('checkBrandKeywordSignals', () => {
  it('detects Microsoft keywords on non-Microsoft domain', () => {
    const doc = makeDoc('<html><head><title>Sign in to Microsoft</title></head><body>Enter your Microsoft account</body></html>');
    const signals = checkBrandKeywordSignals(doc, 'evil-login.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('phishvision:brand_keyword_mismatch');
    expect(signals[0].matchedBrand).toBe('microsoft');
    expect(signals[0].weight).toBe(0.35);
  });

  it('detects Google keywords on non-Google domain', () => {
    const doc = makeDoc('<html><head><title>Sign in - Google Accounts</title></head><body>Google</body></html>');
    const signals = checkBrandKeywordSignals(doc, 'phish-site.net');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('google');
  });

  it('does NOT flag on legitimate Microsoft domain', () => {
    const doc = makeDoc('<html><head><title>Sign in to Microsoft</title></head><body>Microsoft</body></html>');
    const signals = checkBrandKeywordSignals(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag on legitimate Google subdomain', () => {
    const doc = makeDoc('<html><head><title>Google</title></head><body>Google account</body></html>');
    const signals = checkBrandKeywordSignals(doc, 'accounts.google.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for empty document', () => {
    const doc = makeDoc('<html><head></head><body></body></html>');
    const signals = checkBrandKeywordSignals(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('is case-insensitive for keywords', () => {
    const doc = makeDoc('<html><head><title>MICROSOFT LOGIN</title></head><body>MICROSOFT</body></html>');
    const signals = checkBrandKeywordSignals(doc, 'evil.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('microsoft');
  });

  it('skips localhost', () => {
    const doc = makeDoc('<html><head><title>Microsoft</title></head><body>microsoft</body></html>');
    expect(checkBrandKeywordSignals(doc, 'localhost')).toHaveLength(0);
    expect(checkBrandKeywordSignals(doc, '127.0.0.1')).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkBrandKeywordSignals(null, 'evil.com')).toHaveLength(0);
    expect(checkBrandKeywordSignals(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkLoginFormSignals                                              */
/* ================================================================== */

describe('checkLoginFormSignals', () => {
  it('detects password field', () => {
    const doc = makeDoc('<html><body><form><input type="password"></form></body></html>');
    const signals = checkLoginFormSignals(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('phishvision:login_form_present');
  });

  it('detects email field', () => {
    const doc = makeDoc('<html><body><form><input type="email"></form></body></html>');
    const signals = checkLoginFormSignals(doc);
    expect(signals).toHaveLength(1);
  });

  it('detects autocomplete username field', () => {
    const doc = makeDoc('<html><body><form><input autocomplete="username"></form></body></html>');
    const signals = checkLoginFormSignals(doc);
    expect(signals).toHaveLength(1);
  });

  it('returns empty for page without credential fields', () => {
    const doc = makeDoc('<html><body><form><input type="text"><input type="search"></form></body></html>');
    const signals = checkLoginFormSignals(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkLoginFormSignals(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkDomainSuspicion                                               */
/* ================================================================== */

describe('checkDomainSuspicion', () => {
  it('flags .pages.dev suffix', () => {
    const signals = checkDomainSuspicion('microsoft-login.pages.dev');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('phishvision:suspicious_domain');
  });

  it('flags .netlify.app suffix', () => {
    const signals = checkDomainSuspicion('google-sign-in.netlify.app');
    expect(signals).toHaveLength(1);
  });

  it('flags .vercel.app suffix', () => {
    const signals = checkDomainSuspicion('login-page.vercel.app');
    expect(signals).toHaveLength(1);
  });

  it('flags IP address hostname', () => {
    const signals = checkDomainSuspicion('192.168.1.100');
    expect(signals).toHaveLength(1);
  });

  it('flags excessive subdomains (5+ parts)', () => {
    const signals = checkDomainSuspicion('login.microsoft.com.evil.phish.net');
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag legitimate domain', () => {
    const signals = checkDomainSuspicion('microsoft.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag normal subdomain', () => {
    const signals = checkDomainSuspicion('login.microsoft.com');
    expect(signals).toHaveLength(0);
  });

  it('skips localhost', () => {
    expect(checkDomainSuspicion('localhost')).toHaveLength(0);
    expect(checkDomainSuspicion('127.0.0.1')).toHaveLength(0);
  });

  it('returns empty for null/empty', () => {
    expect(checkDomainSuspicion(null)).toHaveLength(0);
    expect(checkDomainSuspicion('')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkTextToHtmlRatio                                               */
/* ================================================================== */

describe('checkTextToHtmlRatio', () => {
  it('fires when ratio is low and password field present', () => {
    // Create a doc with lots of HTML but little text
    const bigStyle = '<style>' + 'x'.repeat(2000) + '</style>';
    const doc = makeDoc(`<html><head>${bigStyle}</head><body><input type="password">ab</body></html>`);
    const signals = checkTextToHtmlRatio(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('phishvision:low_text_ratio');
  });

  it('does NOT fire when ratio is normal', () => {
    const text = 'a'.repeat(200);
    const doc = makeDoc(`<html><head></head><body>${text}<input type="password"></body></html>`);
    const signals = checkTextToHtmlRatio(doc);
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire without password field even if ratio is low', () => {
    const bigStyle = '<style>' + 'x'.repeat(2000) + '</style>';
    const doc = makeDoc(`<html><head>${bigStyle}</head><body>ab</body></html>`);
    const signals = checkTextToHtmlRatio(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkTextToHtmlRatio(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkFaviconBrandMatch                                             */
/* ================================================================== */

describe('checkFaviconBrandMatch', () => {
  it('detects brand favicon on non-brand domain', () => {
    const doc = makeDoc('<html><head><link rel="icon" href="https://cdn.example.com/microsoft-icon.ico"></head><body></body></html>');
    const signals = checkFaviconBrandMatch(doc, 'evil-login.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('phishvision:favicon_brand_match');
    expect(signals[0].matchedBrand).toBe('microsoft');
  });

  it('does NOT flag non-brand favicon', () => {
    const doc = makeDoc('<html><head><link rel="icon" href="/favicon.ico"></head><body></body></html>');
    const signals = checkFaviconBrandMatch(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag brand favicon on own domain', () => {
    const doc = makeDoc('<html><head><link rel="icon" href="/microsoft-icon.ico"></head><body></body></html>');
    const signals = checkFaviconBrandMatch(doc, 'microsoft.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty when no favicon links', () => {
    const doc = makeDoc('<html><head></head><body></body></html>');
    const signals = checkFaviconBrandMatch(doc, 'evil.com');
    expect(signals).toHaveLength(0);
  });

  it('skips localhost', () => {
    const doc = makeDoc('<html><head><link rel="icon" href="/microsoft.ico"></head><body></body></html>');
    expect(checkFaviconBrandMatch(doc, 'localhost')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkColorPaletteMatch                                             */
/* ================================================================== */

describe('checkColorPaletteMatch', () => {
  it('returns empty when getComputedStyle not available', () => {
    // jsdom doesn't have a real getComputedStyle that returns brand colors
    const doc = makeDoc('<html><body><button>Login</button></body></html>');
    const signals = checkColorPaletteMatch(doc, 'evil.com');
    expect(signals).toHaveLength(0);
  });

  it('detects brand colors when mocked', () => {
    const doc = makeDoc('<html><body><button>A</button><button>B</button><button>C</button></body></html>');
    const originalGetComputedStyle = globalThis.getComputedStyle;

    let callCount = 0;
    globalThis.getComputedStyle = () => {
      callCount++;
      // Return Microsoft colors
      return {
        backgroundColor: 'rgb(0, 120, 212)', // #0078D4
        color: 'rgb(255, 185, 0)', // #FFB900
      };
    };

    try {
      const signals = checkColorPaletteMatch(doc, 'evil.com');
      expect(signals).toHaveLength(1);
      expect(signals[0].id).toBe('phishvision:brand_color_match');
      expect(signals[0].matchedBrand).toBe('microsoft');
    } finally {
      globalThis.getComputedStyle = originalGetComputedStyle;
    }
  });

  it('does NOT flag brand colors on own domain', () => {
    const doc = makeDoc('<html><body><button>A</button><button>B</button></body></html>');
    const originalGetComputedStyle = globalThis.getComputedStyle;

    globalThis.getComputedStyle = () => ({
      backgroundColor: 'rgb(0, 120, 212)',
      color: 'rgb(255, 185, 0)',
    });

    try {
      const signals = checkColorPaletteMatch(doc, 'microsoft.com');
      expect(signals).toHaveLength(0);
    } finally {
      globalThis.getComputedStyle = originalGetComputedStyle;
    }
  });

  it('skips localhost', () => {
    expect(checkColorPaletteMatch(makeDoc(), 'localhost')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkLOTLTrustedDomain                                             */
/* ================================================================== */

describe('checkLOTLTrustedDomain', () => {
  it('detects Microsoft branding on Google Sites with credential fields', () => {
    const doc = makeDoc(`
      <html><head><title>Sign in to Microsoft</title></head>
      <body><p>Microsoft account verification</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'sites.google.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('phishvision:lotl_trusted_domain_credential');
    expect(signals[0].weight).toBe(0.30);
    expect(signals[0].matchedBrand).toBe('microsoft');
    expect(signals[0].hostingPlatform).toBe('sites.google.com');
  });

  it('detects PayPal branding on Notion with credential fields', () => {
    const doc = makeDoc(`
      <html><head><title>PayPal Login</title></head>
      <body><p>PayPal account</p><input type="email"><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'mypage.notion.site');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('paypal');
    expect(signals[0].hostingPlatform).toBe('notion.site');
  });

  it('does NOT fire for Microsoft branding on SharePoint (same brand)', () => {
    const doc = makeDoc(`
      <html><head><title>Microsoft SharePoint</title></head>
      <body><p>Microsoft Teams integration</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'mycompany.sharepoint.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire for Google branding on Google Sites (same brand)', () => {
    const doc = makeDoc(`
      <html><head><title>Google Workspace</title></head>
      <body><p>Google account</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'sites.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire without credential fields', () => {
    const doc = makeDoc(`
      <html><head><title>Sign in to Microsoft</title></head>
      <body><p>Microsoft brand mentions but no login form</p></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'sites.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire on non-LOTL domain', () => {
    const doc = makeDoc(`
      <html><head><title>Microsoft Login</title></head>
      <body><p>Microsoft</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'evil-phish.com');
    expect(signals).toHaveLength(0);
  });

  it('fires for any brand on platform without own brand (e.g. Canva)', () => {
    const doc = makeDoc(`
      <html><head><title>Amazon Account</title></head>
      <body><p>Amazon Prime verification</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'mypage.canva.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('amazon');
    expect(signals[0].hostingPlatform).toBe('canva.com');
  });

  it('detects brand via email field (not just password)', () => {
    const doc = makeDoc(`
      <html><head><title>Coinbase</title></head>
      <body><p>Coinbase account</p><input type="email"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'test.wordpress.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('coinbase');
  });

  it('fires for non-Google brand on Google Docs subdomain', () => {
    const doc = makeDoc(`
      <html><head><title>Dropbox Sign In</title></head>
      <body><p>Dropbox file sharing</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'docs.google.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('dropbox');
    expect(signals[0].hostingPlatform).toBe('docs.google.com');
  });

  it('fires for webflow.io hosted page', () => {
    const doc = makeDoc(`
      <html><head><title>Slack Login</title></head>
      <body><p>Sign in to Slack</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'fake-workspace.webflow.io');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('slack');
  });

  it('returns empty for null inputs', () => {
    expect(checkLOTLTrustedDomain(null, 'sites.google.com')).toHaveLength(0);
    expect(checkLOTLTrustedDomain(makeDoc(), null)).toHaveLength(0);
  });

  it('returns empty for page with credentials but no brand keywords', () => {
    const doc = makeDoc(`
      <html><head><title>My Page</title></head>
      <body><p>Welcome to our site</p><input type="password"></body></html>
    `);
    const signals = checkLOTLTrustedDomain(doc, 'mysite.notion.site');
    expect(signals).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculatePhishVisionRiskScore                                      */
/* ================================================================== */

describe('calculatePhishVisionRiskScore', () => {
  it('returns 0 for empty signals', () => {
    const { riskScore, signalList } = calculatePhishVisionRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('returns 0 for null', () => {
    expect(calculatePhishVisionRiskScore(null).riskScore).toBe(0);
  });

  it('scores single signal correctly', () => {
    const { riskScore } = calculatePhishVisionRiskScore([
      { id: 'phishvision:brand_keyword_mismatch', weight: 0.35 },
    ]);
    expect(riskScore).toBeCloseTo(0.35);
  });

  it('sums multiple signals', () => {
    const { riskScore } = calculatePhishVisionRiskScore([
      { id: 'phishvision:brand_keyword_mismatch', weight: 0.35 },
      { id: 'phishvision:login_form_present', weight: 0.20 },
      { id: 'phishvision:suspicious_domain', weight: 0.25 },
    ]);
    expect(riskScore).toBeCloseTo(0.80);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculatePhishVisionRiskScore([
      { id: 'a', weight: 0.35 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
      { id: 'e', weight: 0.20 },
      { id: 'f', weight: 0.15 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('returns signal list', () => {
    const { signalList } = calculatePhishVisionRiskScore([
      { id: 'phishvision:brand_keyword_mismatch', weight: 0.35 },
      { id: 'phishvision:login_form_present', weight: 0.20 },
    ]);
    expect(signalList).toEqual([
      'phishvision:brand_keyword_mismatch',
      'phishvision:login_form_present',
    ]);
  });

  it('alert threshold at 0.50', () => {
    // keyword(0.35) + login(0.20) = 0.55 → alert
    const { riskScore } = calculatePhishVisionRiskScore([
      { id: 'a', weight: 0.35 },
      { id: 'b', weight: 0.20 },
    ]);
    expect(riskScore).toBeGreaterThanOrEqual(0.50);
  });

  it('brand keyword alone below alert threshold', () => {
    const { riskScore } = calculatePhishVisionRiskScore([
      { id: 'phishvision:brand_keyword_mismatch', weight: 0.35 },
    ]);
    expect(riskScore).toBeLessThan(0.50);
  });
});

/* ================================================================== */
/*  injectPhishVisionWarningBanner                                     */
/* ================================================================== */

describe('injectPhishVisionWarningBanner', () => {
  let dom, doc;

  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>');
    doc = dom.window.document;
    // Temporarily replace global document so banner function can use it
    vi.stubGlobal('document', doc);
  });

  it('injects banner into document', () => {
    injectPhishVisionWarningBanner(0.80, 'microsoft', [
      { id: 'phishvision:brand_keyword_mismatch' },
    ]);
    const banner = doc.getElementById('phishops-phishvision-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('Microsoft');
  });

  it('is idempotent', () => {
    injectPhishVisionWarningBanner(0.80, 'google', [{ id: 'a' }]);
    injectPhishVisionWarningBanner(0.80, 'google', [{ id: 'a' }]);
    const banners = doc.querySelectorAll('#phishops-phishvision-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity correctly', () => {
    injectPhishVisionWarningBanner(0.95, 'paypal', [{ id: 'a' }]);
    const banner = doc.getElementById('phishops-phishvision-banner');
    expect(banner.textContent).toContain('Critical');
  });

  it('dismiss button removes banner', () => {
    injectPhishVisionWarningBanner(0.70, 'amazon', [{ id: 'a' }]);
    const dismiss = doc.getElementById('phishops-phishvision-dismiss');
    dismiss.click();
    expect(doc.getElementById('phishops-phishvision-banner')).toBeNull();
  });

  it('shows High severity for 0.70-0.89 range', () => {
    injectPhishVisionWarningBanner(0.75, 'stripe', [{ id: 'a' }]);
    const banner = doc.getElementById('phishops-phishvision-banner');
    expect(banner.textContent).toContain('High');
  });
});
