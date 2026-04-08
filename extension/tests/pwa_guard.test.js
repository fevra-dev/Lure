/**
 * extension/__tests__/pwa_guard.test.js
 *
 * Tests for PWAGuard — Progressive Web App Install Phishing Detection
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/pwa_guard.js';
const { checkInstallPromptOnCredentialPage, checkManifestBrandMismatch, checkStandaloneDisplayWithCreds, checkManifestSuspiciousScope, checkInstallBannerLureText, calculatePwaRiskScore, injectPwaWarningBanner } = globalThis.__phishopsExports['pwa_guard'];

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkInstallPromptOnCredentialPage                                  */
/* ================================================================== */

describe('checkInstallPromptOnCredentialPage', () => {
  it('detects manifest + credential fields', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
      </head><body>
        <input type="password" />
        <input type="email" />
      </body></html>
    `);
    const signals = checkInstallPromptOnCredentialPage(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('pwa:install_prompt_on_credential_page');
    expect(signals[0].weight).toBe(0.40);
  });

  it('does NOT flag manifest without credential fields', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
      </head><body>
        <input type="text" />
      </body></html>
    `);
    expect(checkInstallPromptOnCredentialPage(doc)).toHaveLength(0);
  });

  it('does NOT flag credential fields without manifest', () => {
    const doc = makeDoc(`
      <html><head></head><body>
        <input type="password" />
      </body></html>
    `);
    expect(checkInstallPromptOnCredentialPage(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkInstallPromptOnCredentialPage(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkManifestBrandMismatch                                          */
/* ================================================================== */

describe('checkManifestBrandMismatch', () => {
  it('detects brand name in app title on non-brand domain', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
        <meta name="apple-mobile-web-app-title" content="Microsoft Login">
      </head><body></body></html>
    `);
    const signals = checkManifestBrandMismatch(doc, 'evil-phish.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('pwa:manifest_brand_mismatch');
    expect(signals[0].matchedBrand).toBe('microsoft');
  });

  it('does NOT flag brand name on matching domain', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
        <meta name="application-name" content="Microsoft Teams">
      </head><body></body></html>
    `);
    expect(checkManifestBrandMismatch(doc, 'teams.microsoft.com')).toHaveLength(0);
  });

  it('detects brand in page title', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
        <title>Chase Bank Mobile</title>
      </head><body></body></html>
    `);
    const signals = checkManifestBrandMismatch(doc, 'fake-chase.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('chase');
  });

  it('does NOT flag when no manifest present', () => {
    const doc = makeDoc(`
      <html><head>
        <meta name="application-name" content="PayPal">
      </head><body></body></html>
    `);
    expect(checkManifestBrandMismatch(doc, 'evil.com')).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkManifestBrandMismatch(null, 'test.com')).toHaveLength(0);
    expect(checkManifestBrandMismatch(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkStandaloneDisplayWithCreds                                     */
/* ================================================================== */

describe('checkStandaloneDisplayWithCreds', () => {
  it('detects mobile-web-app-capable meta with credential fields', () => {
    const doc = makeDoc(`
      <html><head>
        <meta name="mobile-web-app-capable" content="yes">
      </head><body>
        <input type="password" />
      </body></html>
    `);
    const signals = checkStandaloneDisplayWithCreds(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('pwa:standalone_display_with_creds');
  });

  it('detects apple-mobile-web-app-capable meta with credential fields', () => {
    const doc = makeDoc(`
      <html><head>
        <meta name="apple-mobile-web-app-capable" content="yes">
      </head><body>
        <input type="email" />
      </body></html>
    `);
    expect(checkStandaloneDisplayWithCreds(doc)).toHaveLength(1);
  });

  it('does NOT flag standalone without credential fields', () => {
    const doc = makeDoc(`
      <html><head>
        <meta name="mobile-web-app-capable" content="yes">
      </head><body>
        <input type="text" />
      </body></html>
    `);
    expect(checkStandaloneDisplayWithCreds(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkStandaloneDisplayWithCreds(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkManifestSuspiciousScope                                        */
/* ================================================================== */

describe('checkManifestSuspiciousScope', () => {
  it('detects brand in app name on non-brand domain', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
        <meta name="application-name" content="PayPal Secure">
      </head><body></body></html>
    `);
    const signals = checkManifestSuspiciousScope(doc, 'phish.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('pwa:manifest_suspicious_scope');
    expect(signals[0].matchedBrand).toBe('paypal');
  });

  it('does NOT flag on legitimate domain', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
        <meta name="application-name" content="Google Workspace">
      </head><body></body></html>
    `);
    expect(checkManifestSuspiciousScope(doc, 'workspace.google.com')).toHaveLength(0);
  });

  it('returns empty when no app name found', () => {
    const doc = makeDoc(`
      <html><head>
        <link rel="manifest" href="/manifest.json">
      </head><body></body></html>
    `);
    expect(checkManifestSuspiciousScope(doc, 'evil.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkInstallBannerLureText                                          */
/* ================================================================== */

describe('checkInstallBannerLureText', () => {
  it('detects "install this app" with credential fields', () => {
    const doc = makeDoc(`
      <html><body>
        <p>Please install this app to continue</p>
        <input type="password" />
      </body></html>
    `);
    const signals = checkInstallBannerLureText(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('pwa:install_banner_lure_text');
  });

  it('detects "add to home screen" with email field', () => {
    const doc = makeDoc(`
      <html><body>
        <p>Add to home screen for the best experience</p>
        <input type="email" />
      </body></html>
    `);
    expect(checkInstallBannerLureText(doc)).toHaveLength(1);
  });

  it('does NOT flag lure text without credential fields', () => {
    const doc = makeDoc(`
      <html><body>
        <p>Install this app for updates</p>
        <input type="text" />
      </body></html>
    `);
    expect(checkInstallBannerLureText(doc)).toHaveLength(0);
  });

  it('does NOT flag credential fields without lure text', () => {
    const doc = makeDoc(`
      <html><body>
        <p>Welcome to our service</p>
        <input type="password" />
      </body></html>
    `);
    expect(checkInstallBannerLureText(doc)).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkInstallBannerLureText(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculatePwaRiskScore                                               */
/* ================================================================== */

describe('calculatePwaRiskScore', () => {
  it('returns 0 for no signals', () => {
    expect(calculatePwaRiskScore([]).riskScore).toBe(0);
  });

  it('sums correctly', () => {
    const { riskScore } = calculatePwaRiskScore([
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
    ]);
    expect(riskScore).toBeCloseTo(0.70, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
    ];
    expect(calculatePwaRiskScore(signals).riskScore).toBe(1.0);
  });
});

/* ================================================================== */
/*  injectPwaWarningBanner                                              */
/* ================================================================== */

describe('injectPwaWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectPwaWarningBanner(0.70, [
      { id: 'pwa:install_prompt_on_credential_page', weight: 0.40, matchedBrand: 'chase' },
    ]);

    const banner = dom.window.document.getElementById('phishops-pwa-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('Malicious PWA');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'pwa:test', weight: 0.50 }];
    injectPwaWarningBanner(0.50, signals);
    injectPwaWarningBanner(0.50, signals);

    expect(dom.window.document.querySelectorAll('#phishops-pwa-banner')).toHaveLength(1);
  });
});
