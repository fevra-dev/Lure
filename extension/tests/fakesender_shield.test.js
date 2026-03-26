/**
 * extension/__tests__/fakesender_shield.test.js
 *
 * Tests for FakeSender Shield — Helpdesk Platform Brand Impersonation Detection
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  isHelpdeskPlatform,
  checkHelpdeskBrandSubdomainMismatch,
  checkCredentialOnHelpdesk,
  checkExternalPhishingLinks,
  checkBrandImpersonationText,
  checkFreeTierIndicator,
  checkUrgentActionLanguage,
  calculateFakeSenderRiskScore,
  injectFakeSenderWarningBanner,
} from '../content/fakesender_shield.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

/* ================================================================== */
/*  isHelpdeskPlatform                                                 */
/* ================================================================== */

describe('isHelpdeskPlatform', () => {
  it('detects Zendesk hostname', () => {
    const result = isHelpdeskPlatform('coinbase-help.zendesk.com');
    expect(result).not.toBeNull();
    expect(result.platformKey).toBe('zendesk');
    expect(result.subdomain).toBe('coinbase-help');
    expect(result.platform.name).toBe('Zendesk');
  });

  it('detects Freshdesk hostname', () => {
    const result = isHelpdeskPlatform('support.freshdesk.com');
    expect(result).not.toBeNull();
    expect(result.platformKey).toBe('freshdesk');
  });

  it('detects Zoho Desk hostname', () => {
    const result = isHelpdeskPlatform('mycompany.zohodesk.com');
    expect(result).not.toBeNull();
    expect(result.platformKey).toBe('zoho');
  });

  it('detects Intercom hostname', () => {
    const result = isHelpdeskPlatform('app.intercom.io');
    expect(result).not.toBeNull();
    expect(result.platformKey).toBe('intercom');
  });

  it('detects Atlassian/Jira hostname', () => {
    const result = isHelpdeskPlatform('company.atlassian.net');
    expect(result).not.toBeNull();
    expect(result.platformKey).toBe('jira');
  });

  it('returns null for regular domain', () => {
    expect(isHelpdeskPlatform('example.com')).toBeNull();
  });

  it('returns null for empty hostname', () => {
    expect(isHelpdeskPlatform('')).toBeNull();
  });

  it('returns null for null', () => {
    expect(isHelpdeskPlatform(null)).toBeNull();
  });
});

/* ================================================================== */
/*  checkHelpdeskBrandSubdomainMismatch                                */
/* ================================================================== */

describe('checkHelpdeskBrandSubdomainMismatch', () => {
  it('detects brand in subdomain on Zendesk', () => {
    const doc = makeDoc('<html><head><title>Coinbase Support</title></head><body>Help center</body></html>');
    const signals = checkHelpdeskBrandSubdomainMismatch(doc, 'coinbase-help.zendesk.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('fakesender:helpdesk_brand_subdomain_mismatch');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].matchedBrand).toBe('coinbase');
    expect(signals[0].platform).toBe('Zendesk');
  });

  it('detects brand in title on Freshdesk', () => {
    const doc = makeDoc('<html><head><title>Microsoft Support Portal</title></head><body>Get help</body></html>');
    const signals = checkHelpdeskBrandSubdomainMismatch(doc, 'ms-support.freshdesk.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('microsoft');
  });

  it('detects Google brand in subdomain', () => {
    const doc = makeDoc('<html><head><title>Help</title></head><body></body></html>');
    const signals = checkHelpdeskBrandSubdomainMismatch(doc, 'google-support.zendesk.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedBrand).toBe('google');
  });

  it('does NOT flag generic helpdesk without brand', () => {
    const doc = makeDoc('<html><head><title>Help Center</title></head><body>General support</body></html>');
    const signals = checkHelpdeskBrandSubdomainMismatch(doc, 'mycompany.zendesk.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag non-helpdesk domain', () => {
    const doc = makeDoc('<html><head><title>Coinbase</title></head><body></body></html>');
    const signals = checkHelpdeskBrandSubdomainMismatch(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for localhost', () => {
    const doc = makeDoc('<html><body></body></html>');
    expect(checkHelpdeskBrandSubdomainMismatch(doc, 'localhost')).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkHelpdeskBrandSubdomainMismatch(null, 'test.zendesk.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCredentialOnHelpdesk                                          */
/* ================================================================== */

describe('checkCredentialOnHelpdesk', () => {
  it('detects password field on helpdesk', () => {
    const doc = makeDoc('<html><body><form><input type="password"></form></body></html>');
    const signals = checkCredentialOnHelpdesk(doc, 'fake-support.zendesk.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('fakesender:credential_on_helpdesk');
    expect(signals[0].weight).toBe(0.25);
  });

  it('detects autocomplete password field on helpdesk', () => {
    const doc = makeDoc('<html><body><form><input autocomplete="current-password"></form></body></html>');
    const signals = checkCredentialOnHelpdesk(doc, 'support.freshdesk.com');
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag helpdesk without credential fields', () => {
    const doc = makeDoc('<html><body><form><input type="text"><textarea></textarea></form></body></html>');
    const signals = checkCredentialOnHelpdesk(doc, 'support.zendesk.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag password field on non-helpdesk', () => {
    const doc = makeDoc('<html><body><form><input type="password"></form></body></html>');
    const signals = checkCredentialOnHelpdesk(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkCredentialOnHelpdesk(null, 'test.zendesk.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkExternalPhishingLinks                                         */
/* ================================================================== */

describe('checkExternalPhishingLinks', () => {
  it('detects links to non-brand external domain', () => {
    const doc = makeDoc(`
      <html><head><title>Coinbase Support</title></head>
      <body><a href="https://evil-collect.net/login">Click here</a></body></html>
    `);
    const signals = checkExternalPhishingLinks(doc, 'coinbase-help.zendesk.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('fakesender:external_phishing_link');
    expect(signals[0].weight).toBe(0.30);
  });

  it('does NOT flag links to brand legitimate domain', () => {
    const doc = makeDoc(`
      <html><head><title>Coinbase Support</title></head>
      <body><a href="https://coinbase.com/help">Visit Coinbase</a></body></html>
    `);
    const signals = checkExternalPhishingLinks(doc, 'coinbase-help.zendesk.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag relative links', () => {
    const doc = makeDoc(`
      <html><head><title>Coinbase Support</title></head>
      <body><a href="/articles/123">Read more</a></body></html>
    `);
    const signals = checkExternalPhishingLinks(doc, 'coinbase-help.zendesk.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag when no brand is impersonated', () => {
    const doc = makeDoc(`
      <html><head><title>General Help</title></head>
      <body><a href="https://evil.com">Link</a></body></html>
    `);
    const signals = checkExternalPhishingLinks(doc, 'mycompany.zendesk.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag non-helpdesk domain', () => {
    const doc = makeDoc(`
      <html><head><title>Coinbase</title></head>
      <body><a href="https://evil.com">Link</a></body></html>
    `);
    const signals = checkExternalPhishingLinks(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkExternalPhishingLinks(null, 'test.zendesk.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkBrandImpersonationText                                        */
/* ================================================================== */

describe('checkBrandImpersonationText', () => {
  it('detects heavy brand references on helpdesk', () => {
    const doc = makeDoc(`
      <html><head><title>PayPal Support</title></head>
      <body>PayPal account issue. Contact PayPal support. Your PayPal payment failed.</body></html>
    `);
    const signals = checkBrandImpersonationText(doc, 'paypal-help.zendesk.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('fakesender:brand_impersonation_text');
    expect(signals[0].matchedBrand).toBe('paypal');
  });

  it('does NOT flag minimal brand mention', () => {
    const doc = makeDoc(`
      <html><head><title>Help</title></head>
      <body>We use PayPal for payments.</body></html>
    `);
    const signals = checkBrandImpersonationText(doc, 'mycompany.zendesk.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag non-helpdesk domain', () => {
    const doc = makeDoc(`
      <html><head><title>PayPal PayPal PayPal</title></head>
      <body>PayPal PayPal PayPal</body></html>
    `);
    const signals = checkBrandImpersonationText(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkBrandImpersonationText(null, 'test.zendesk.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkFreeTierIndicator                                             */
/* ================================================================== */

describe('checkFreeTierIndicator', () => {
  it('detects "Powered by Zendesk" text', () => {
    const doc = makeDoc('<html><body>Help center content. Powered by Zendesk</body></html>');
    const signals = checkFreeTierIndicator(doc, 'fake-support.zendesk.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('fakesender:free_tier_indicator');
    expect(signals[0].weight).toBe(0.20);
  });

  it('detects "free plan" indicator', () => {
    const doc = makeDoc('<html><body>This is a free plan help center.</body></html>');
    const signals = checkFreeTierIndicator(doc, 'test.freshdesk.com');
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag without free tier indicators', () => {
    const doc = makeDoc('<html><body>Professional help center content.</body></html>');
    const signals = checkFreeTierIndicator(doc, 'company.zendesk.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag non-helpdesk domain', () => {
    const doc = makeDoc('<html><body>Powered by Zendesk</body></html>');
    const signals = checkFreeTierIndicator(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkFreeTierIndicator(null, 'test.zendesk.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkUrgentActionLanguage                                          */
/* ================================================================== */

describe('checkUrgentActionLanguage', () => {
  it('detects multiple urgency phrases', () => {
    const doc = makeDoc(`
      <html><body>Your account suspended. Please verify immediately to restore access.</body></html>
    `);
    const signals = checkUrgentActionLanguage(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('fakesender:urgent_action_language');
    expect(signals[0].weight).toBe(0.15);
    expect(signals[0].matchedPhrases.length).toBeGreaterThanOrEqual(2);
  });

  it('does NOT flag single urgency phrase', () => {
    const doc = makeDoc('<html><body>Action required for your ticket update.</body></html>');
    const signals = checkUrgentActionLanguage(doc);
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag normal support text', () => {
    const doc = makeDoc('<html><body>Welcome to our help center. Browse articles for assistance.</body></html>');
    const signals = checkUrgentActionLanguage(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkUrgentActionLanguage(null)).toHaveLength(0);
  });

  it('detects urgency in title + body', () => {
    const doc = makeDoc(`
      <html><head><title>Account Suspended</title></head>
      <body>Unauthorized access detected on your account. Verify immediately.</body></html>
    `);
    const signals = checkUrgentActionLanguage(doc);
    expect(signals).toHaveLength(1);
  });
});

/* ================================================================== */
/*  calculateFakeSenderRiskScore                                       */
/* ================================================================== */

describe('calculateFakeSenderRiskScore', () => {
  it('returns 0 for empty signals', () => {
    const result = calculateFakeSenderRiskScore([]);
    expect(result.riskScore).toBe(0);
    expect(result.signalList).toHaveLength(0);
  });

  it('returns 0 for null', () => {
    const result = calculateFakeSenderRiskScore(null);
    expect(result.riskScore).toBe(0);
  });

  it('calculates single signal correctly', () => {
    const result = calculateFakeSenderRiskScore([
      { id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 },
    ]);
    expect(result.riskScore).toBeCloseTo(0.40);
  });

  it('sums multiple signals', () => {
    const result = calculateFakeSenderRiskScore([
      { id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 },
      { id: 'fakesender:credential_on_helpdesk', weight: 0.25 },
    ]);
    expect(result.riskScore).toBeCloseTo(0.65);
  });

  it('caps at 1.0', () => {
    const result = calculateFakeSenderRiskScore([
      { id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 },
      { id: 'fakesender:external_phishing_link', weight: 0.30 },
      { id: 'fakesender:credential_on_helpdesk', weight: 0.25 },
      { id: 'fakesender:brand_impersonation_text', weight: 0.25 },
    ]);
    expect(result.riskScore).toBe(1.0);
  });

  it('returns all signal IDs', () => {
    const result = calculateFakeSenderRiskScore([
      { id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 },
      { id: 'fakesender:urgent_action_language', weight: 0.15 },
    ]);
    expect(result.signalList).toEqual([
      'fakesender:helpdesk_brand_subdomain_mismatch',
      'fakesender:urgent_action_language',
    ]);
  });
});

/* ================================================================== */
/*  injectFakeSenderWarningBanner                                      */
/* ================================================================== */

describe('injectFakeSenderWarningBanner', () => {
  beforeEach(() => {
    const dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);
  });

  it('injects banner into document', () => {
    const signals = [{ id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 }];
    injectFakeSenderWarningBanner(0.70, 'coinbase', 'Zendesk', signals);
    const banner = document.getElementById('phishops-fakesender-banner');
    expect(banner).not.toBeNull();
    expect(banner.innerHTML).toContain('Coinbase');
    expect(banner.innerHTML).toContain('Zendesk');
  });

  it('is idempotent — does not inject twice', () => {
    const signals = [{ id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 }];
    injectFakeSenderWarningBanner(0.70, 'coinbase', 'Zendesk', signals);
    injectFakeSenderWarningBanner(0.70, 'coinbase', 'Zendesk', signals);
    const banners = document.querySelectorAll('#phishops-fakesender-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const signals = [{ id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 }];
    injectFakeSenderWarningBanner(0.75, 'paypal', 'Freshdesk', signals);
    const banner = document.getElementById('phishops-fakesender-banner');
    expect(banner.innerHTML).toContain('High');
    expect(banner.innerHTML).toContain('0.75');
  });

  it('shows Critical severity for score >= 0.90', () => {
    const signals = [{ id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 }];
    injectFakeSenderWarningBanner(0.95, 'microsoft', 'Zendesk', signals);
    const banner = document.getElementById('phishops-fakesender-banner');
    expect(banner.innerHTML).toContain('Critical');
  });

  it('dismiss button removes banner', () => {
    const signals = [{ id: 'fakesender:helpdesk_brand_subdomain_mismatch', weight: 0.40 }];
    injectFakeSenderWarningBanner(0.70, 'coinbase', 'Zendesk', signals);
    const dismissBtn = document.getElementById('phishops-fakesender-dismiss');
    expect(dismissBtn).not.toBeNull();
    dismissBtn.click();
    expect(document.getElementById('phishops-fakesender-banner')).toBeNull();
  });
});
