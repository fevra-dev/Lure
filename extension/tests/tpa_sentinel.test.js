/**
 * extension/__tests__/tpa_sentinel.test.js
 *
 * Tests for TPASentinel — Third-Party App Consent Phishing Detection
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/tpa_sentinel.js';
const { checkHighRiskPermissionCombo, checkUnverifiedPublisher, checkConsentOnRedirectedPage, checkAppNameBrandImpersonation, checkExcessiveScopeCount, calculateTpaRiskScore, injectTpaWarningBanner } = globalThis.__phishopsExports['tpa_sentinel'];

function makeConsentDoc(bodyContent = '', hostname = 'login.microsoftonline.com') {
  // All TPA checks require consent page indicators in body text
  const html = `
    <html><head></head><body>
      <div>This app is requesting permission to access your account.</div>
      <div>Review permissions before you accept.</div>
      ${bodyContent}
    </body></html>
  `;
  const dom = new JSDOM(html, { url: `https://${hostname}/common/oauth2/authorize` });
  return dom.window.document;
}

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkHighRiskPermissionCombo                                        */
/* ================================================================== */

describe('checkHighRiskPermissionCombo', () => {
  it('detects 3+ high-risk scopes on consent page', () => {
    const doc = makeConsentDoc(`
      <ul>
        <li>Mail.ReadWrite</li>
        <li>Files.ReadWrite.All</li>
        <li>offline_access</li>
        <li>Directory.Read.All</li>
      </ul>
    `);
    const signals = checkHighRiskPermissionCombo(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('tpa:high_risk_permission_combo');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].highRiskCount).toBeGreaterThanOrEqual(3);
  });

  it('does NOT flag with only 1-2 scopes', () => {
    const doc = makeConsentDoc(`
      <ul>
        <li>openid</li>
        <li>User.Read</li>
      </ul>
    `);
    expect(checkHighRiskPermissionCombo(doc, 'login.microsoftonline.com')).toHaveLength(0);
  });

  it('does NOT fire on non-consent-page domains', () => {
    const doc = makeDoc(`
      <html><body>
        <div>Mail.ReadWrite Files.ReadWrite.All offline_access Directory.Read.All permissions requested</div>
      </body></html>
    `);
    expect(checkHighRiskPermissionCombo(doc, 'evil.com')).toHaveLength(0);
  });

  it('detects permission descriptions (not just scope names)', () => {
    const doc = makeConsentDoc(`
      <div>Read and write your mail</div>
      <div>Access your files</div>
      <div>Maintain access to data you have given access to</div>
    `);
    const signals = checkHighRiskPermissionCombo(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
  });

  it('returns empty for null inputs', () => {
    expect(checkHighRiskPermissionCombo(null, 'login.microsoftonline.com')).toHaveLength(0);
    expect(checkHighRiskPermissionCombo(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkUnverifiedPublisher                                            */
/* ================================================================== */

describe('checkUnverifiedPublisher', () => {
  it('detects "unverified" on consent page', () => {
    const doc = makeConsentDoc('<span class="publisher">unverified</span>');
    const signals = checkUnverifiedPublisher(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('tpa:unverified_publisher');
    expect(signals[0].weight).toBe(0.30);
  });

  it('detects "publisher not verified"', () => {
    const doc = makeConsentDoc('<div>Publisher not verified</div>');
    expect(checkUnverifiedPublisher(doc, 'login.microsoftonline.com')).toHaveLength(1);
  });

  it('does NOT flag verified publishers', () => {
    const doc = makeConsentDoc('<div>Publisher: Microsoft Corporation (verified)</div>');
    expect(checkUnverifiedPublisher(doc, 'login.microsoftonline.com')).toHaveLength(0);
  });

  it('does NOT fire on non-consent domains', () => {
    const doc = makeDoc('<html><body><div>unverified permissions requested</div></body></html>');
    expect(checkUnverifiedPublisher(doc, 'evil.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkConsentOnRedirectedPage                                        */
/* ================================================================== */

describe('checkConsentOnRedirectedPage', () => {
  it('detects non-IdP referrer on consent page', () => {
    const html = '<html><head></head><body><div>Consent page</div></body></html>';
    const dom = new JSDOM(html, {
      url: 'https://login.microsoftonline.com/common/oauth2/authorize',
      referrer: 'https://phishing-page.com/redirect',
    });
    const doc = dom.window.document;
    const signals = checkConsentOnRedirectedPage(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('tpa:consent_on_redirected_page');
    expect(signals[0].referrer).toBe('phishing-page.com');
  });

  it('does NOT flag IdP referrer', () => {
    const html = '<html><head></head><body><div>Consent page</div></body></html>';
    const dom = new JSDOM(html, {
      url: 'https://login.microsoftonline.com/common/oauth2/authorize',
      referrer: 'https://login.microsoftonline.com/common/login',
    });
    expect(checkConsentOnRedirectedPage(dom.window.document, 'login.microsoftonline.com')).toHaveLength(0);
  });

  it('does NOT flag when no referrer', () => {
    const html = '<html><head></head><body></body></html>';
    const dom = new JSDOM(html, {
      url: 'https://login.microsoftonline.com/common/oauth2/authorize',
    });
    expect(checkConsentOnRedirectedPage(dom.window.document, 'login.microsoftonline.com')).toHaveLength(0);
  });

  it('does NOT fire on non-consent domains', () => {
    const html = '<html><head></head><body></body></html>';
    const dom = new JSDOM(html, {
      url: 'https://evil.com/page',
      referrer: 'https://phishing.com/link',
    });
    expect(checkConsentOnRedirectedPage(dom.window.document, 'evil.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkAppNameBrandImpersonation                                      */
/* ================================================================== */

describe('checkAppNameBrandImpersonation', () => {
  it('detects "Microsoft Security" app name on consent page', () => {
    const doc = makeConsentDoc('<h2>Microsoft Security Scanner</h2>');
    const signals = checkAppNameBrandImpersonation(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('tpa:app_name_brand_impersonation');
    expect(signals[0].weight).toBe(0.20);
  });

  it('detects "Google Drive Sync" app name', () => {
    const doc = makeConsentDoc('<h2>Google Drive Sync Tool</h2>');
    expect(checkAppNameBrandImpersonation(doc, 'accounts.google.com')).toHaveLength(1);
  });

  it('does NOT flag generic app names', () => {
    const doc = makeConsentDoc('<h2>My Custom App</h2>');
    expect(checkAppNameBrandImpersonation(doc, 'login.microsoftonline.com')).toHaveLength(0);
  });

  it('does NOT fire on non-consent domains', () => {
    const doc = makeDoc('<html><body><div>Microsoft Security permissions requested</div></body></html>');
    expect(checkAppNameBrandImpersonation(doc, 'evil.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkExcessiveScopeCount                                            */
/* ================================================================== */

describe('checkExcessiveScopeCount', () => {
  it('detects 5+ scopes', () => {
    const doc = makeConsentDoc(`
      <ul>
        <li>Mail.ReadWrite</li>
        <li>Mail.Send</li>
        <li>Files.ReadWrite.All</li>
        <li>Directory.Read.All</li>
        <li>offline_access</li>
        <li>openid</li>
      </ul>
    `);
    const signals = checkExcessiveScopeCount(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('tpa:excessive_scope_count');
    expect(signals[0].scopeCount).toBeGreaterThanOrEqual(5);
  });

  it('does NOT flag with fewer than 5 scopes', () => {
    const doc = makeConsentDoc(`
      <ul>
        <li>openid</li>
        <li>offline_access</li>
      </ul>
    `);
    expect(checkExcessiveScopeCount(doc, 'login.microsoftonline.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateTpaRiskScore                                               */
/* ================================================================== */

describe('calculateTpaRiskScore', () => {
  it('returns 0 for no signals', () => {
    expect(calculateTpaRiskScore([]).riskScore).toBe(0);
  });

  it('sums correctly', () => {
    const { riskScore } = calculateTpaRiskScore([
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
    expect(calculateTpaRiskScore(signals).riskScore).toBe(1.0);
  });
});

/* ================================================================== */
/*  injectTpaWarningBanner                                              */
/* ================================================================== */

describe('injectTpaWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectTpaWarningBanner(0.70, [
      { id: 'tpa:high_risk_permission_combo', weight: 0.40 },
    ]);

    const banner = dom.window.document.getElementById('phishops-tpa-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('Suspicious App Consent');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'tpa:test', weight: 0.50 }];
    injectTpaWarningBanner(0.50, signals);
    injectTpaWarningBanner(0.50, signals);

    expect(dom.window.document.querySelectorAll('#phishops-tpa-banner')).toHaveLength(1);
  });
});
