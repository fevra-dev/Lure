/**
 * extension/__tests__/sync_guard.test.js
 *
 * Tests for SyncGuard — Browser Sync Hijacking Detection
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkSuspiciousReferrer,
  checkSyncSetupInstructions,
  checkRemoteSupportContext,
  checkProfileCreationSocialEngineering,
  checkNonStandardAccountFlow,
  calculateSyncGuardRiskScore,
  injectSyncGuardWarningBanner,
} from '../content/sync_guard.js';

function makeDoc(html = '<html><head></head><body></body></html>', options = {}) {
  const dom = new JSDOM(html, { url: options.url || 'https://example.com' });
  const doc = dom.window.document;
  // Mock referrer if provided
  if (options.referrer !== undefined) {
    Object.defineProperty(doc, 'referrer', { value: options.referrer, writable: false });
  }
  return doc;
}

/* ================================================================== */
/*  checkSuspiciousReferrer                                            */
/* ================================================================== */

describe('checkSuspiciousReferrer', () => {
  it('detects suspicious referrer on Google account flow', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://helpdesk.evil.com/setup',
    });
    const signals = checkSuspiciousReferrer(doc, 'accounts.google.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sync:add_account_suspicious_referrer');
    expect(signals[0].weight).toBe(0.40);
    expect(signals[0].referrerDomain).toBe('helpdesk.evil.com');
  });

  it('detects suspicious referrer on Microsoft login', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://remote-support.example.com/session',
    });
    const signals = checkSuspiciousReferrer(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sync:add_account_suspicious_referrer');
  });

  it('does NOT flag trusted Google referrer', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://myaccount.google.com/settings',
    });
    const signals = checkSuspiciousReferrer(doc, 'accounts.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag trusted Microsoft referrer', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://office.com/dashboard',
    });
    const signals = checkSuspiciousReferrer(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag when no referrer', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', { referrer: '' });
    const signals = checkSuspiciousReferrer(doc, 'accounts.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag on non-account-flow domain', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://evil.com/setup',
    });
    const signals = checkSuspiciousReferrer(doc, 'example.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkSuspiciousReferrer(null, 'accounts.google.com')).toHaveLength(0);
  });

  it('returns empty for localhost', () => {
    const doc = makeDoc('<html><body></body></html>', { referrer: 'https://evil.com' });
    expect(checkSuspiciousReferrer(doc, 'localhost')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkSyncSetupInstructions                                         */
/* ================================================================== */

describe('checkSyncSetupInstructions', () => {
  it('detects "add account" instruction', () => {
    const doc = makeDoc('<html><body>Please add account to your browser to continue setup.</body></html>');
    const signals = checkSyncSetupInstructions(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sync:sync_setup_instructions');
    expect(signals[0].weight).toBe(0.35);
  });

  it('detects "turn on sync" instruction', () => {
    const doc = makeDoc('<html><body>Now turn on sync in your browser settings.</body></html>');
    const signals = checkSyncSetupInstructions(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].matchedKeywords).toContain('turn on sync');
  });

  it('detects "sign in to chrome" instruction', () => {
    const doc = makeDoc('<html><body>Step 1: Sign in to Chrome with the account below.</body></html>');
    const signals = checkSyncSetupInstructions(doc);
    expect(signals).toHaveLength(1);
  });

  it('detects "enable sync" case-insensitively', () => {
    const doc = makeDoc('<html><body>Please Enable Sync to continue the setup process.</body></html>');
    const signals = checkSyncSetupInstructions(doc);
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag normal page without sync keywords', () => {
    const doc = makeDoc('<html><body>Welcome to our website. Please log in to continue.</body></html>');
    const signals = checkSyncSetupInstructions(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for empty body', () => {
    const doc = makeDoc('<html><body></body></html>');
    const signals = checkSyncSetupInstructions(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkSyncSetupInstructions(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkRemoteSupportContext                                           */
/* ================================================================== */

describe('checkRemoteSupportContext', () => {
  it('detects TeamViewer reference', () => {
    const doc = makeDoc('<html><body>Open TeamViewer and enter the session code.</body></html>');
    const signals = checkRemoteSupportContext(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sync:remote_support_context');
    expect(signals[0].weight).toBe(0.30);
    expect(signals[0].matchedTools).toContain('teamviewer');
  });

  it('detects AnyDesk reference', () => {
    const doc = makeDoc('<html><body>Download AnyDesk for remote assistance.</body></html>');
    const signals = checkRemoteSupportContext(doc);
    expect(signals).toHaveLength(1);
  });

  it('detects "remote desktop" reference', () => {
    const doc = makeDoc('<html><body>Connect via remote desktop to resolve the issue.</body></html>');
    const signals = checkRemoteSupportContext(doc);
    expect(signals).toHaveLength(1);
  });

  it('detects ConnectWise reference', () => {
    const doc = makeDoc('<html><head><title>ConnectWise Support Session</title></head><body>Join session</body></html>');
    const signals = checkRemoteSupportContext(doc);
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag normal page', () => {
    const doc = makeDoc('<html><body>Welcome to our company website.</body></html>');
    const signals = checkRemoteSupportContext(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkRemoteSupportContext(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkProfileCreationSocialEngineering                              */
/* ================================================================== */

describe('checkProfileCreationSocialEngineering', () => {
  it('detects "create a new profile" instruction', () => {
    const doc = makeDoc('<html><body>Please create a new profile in Chrome and sign in with the credentials below.</body></html>');
    const signals = checkProfileCreationSocialEngineering(doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sync:profile_creation_social_engineering');
    expect(signals[0].weight).toBe(0.25);
  });

  it('detects "use these credentials" instruction', () => {
    const doc = makeDoc('<html><body>Use these credentials to sign in: user@attacker.com / password123</body></html>');
    const signals = checkProfileCreationSocialEngineering(doc);
    expect(signals).toHaveLength(1);
  });

  it('detects "enter this email" instruction', () => {
    const doc = makeDoc('<html><body>Enter this email address in the sign-in field: support@fake.com</body></html>');
    const signals = checkProfileCreationSocialEngineering(doc);
    expect(signals).toHaveLength(1);
  });

  it('does NOT flag normal page', () => {
    const doc = makeDoc('<html><body>Create your account to get started.</body></html>');
    const signals = checkProfileCreationSocialEngineering(doc);
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkProfileCreationSocialEngineering(null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkNonStandardAccountFlow                                        */
/* ================================================================== */

describe('checkNonStandardAccountFlow', () => {
  it('detects non-standard referrer to account flow', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://suspicious-helpdesk.com/ticket/123',
    });
    const signals = checkNonStandardAccountFlow(doc, 'accounts.google.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('sync:non_standard_account_flow');
    expect(signals[0].weight).toBe(0.20);
  });

  it('does NOT flag trusted referrer', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://myaccount.google.com/security',
    });
    const signals = checkNonStandardAccountFlow(doc, 'accounts.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag no referrer (direct navigation)', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', { referrer: '' });
    const signals = checkNonStandardAccountFlow(doc, 'accounts.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag on non-account-flow domain', () => {
    const doc = makeDoc('<html><body>Sign in</body></html>', {
      referrer: 'https://evil.com/setup',
    });
    const signals = checkNonStandardAccountFlow(doc, 'regular-site.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for localhost', () => {
    const doc = makeDoc('<html><body></body></html>', { referrer: 'https://evil.com' });
    expect(checkNonStandardAccountFlow(doc, 'localhost')).toHaveLength(0);
  });

  it('returns empty for null doc', () => {
    expect(checkNonStandardAccountFlow(null, 'accounts.google.com')).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateSyncGuardRiskScore                                        */
/* ================================================================== */

describe('calculateSyncGuardRiskScore', () => {
  it('returns 0 for empty signals', () => {
    const result = calculateSyncGuardRiskScore([]);
    expect(result.riskScore).toBe(0);
    expect(result.signalList).toHaveLength(0);
  });

  it('returns 0 for null', () => {
    const result = calculateSyncGuardRiskScore(null);
    expect(result.riskScore).toBe(0);
  });

  it('calculates single signal correctly', () => {
    const result = calculateSyncGuardRiskScore([
      { id: 'sync:add_account_suspicious_referrer', weight: 0.40 },
    ]);
    expect(result.riskScore).toBeCloseTo(0.40);
    expect(result.signalList).toEqual(['sync:add_account_suspicious_referrer']);
  });

  it('sums multiple signals', () => {
    const result = calculateSyncGuardRiskScore([
      { id: 'sync:add_account_suspicious_referrer', weight: 0.40 },
      { id: 'sync:sync_setup_instructions', weight: 0.35 },
    ]);
    expect(result.riskScore).toBeCloseTo(0.75);
  });

  it('caps at 1.0', () => {
    const result = calculateSyncGuardRiskScore([
      { id: 'sync:add_account_suspicious_referrer', weight: 0.40 },
      { id: 'sync:sync_setup_instructions', weight: 0.35 },
      { id: 'sync:remote_support_context', weight: 0.30 },
      { id: 'sync:profile_creation_social_engineering', weight: 0.25 },
    ]);
    expect(result.riskScore).toBe(1.0);
  });

  it('returns all signal IDs', () => {
    const result = calculateSyncGuardRiskScore([
      { id: 'sync:add_account_suspicious_referrer', weight: 0.40 },
      { id: 'sync:remote_support_context', weight: 0.30 },
    ]);
    expect(result.signalList).toEqual([
      'sync:add_account_suspicious_referrer',
      'sync:remote_support_context',
    ]);
  });
});

/* ================================================================== */
/*  injectSyncGuardWarningBanner                                       */
/* ================================================================== */

describe('injectSyncGuardWarningBanner', () => {
  beforeEach(() => {
    const dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);
  });

  it('injects banner into document', () => {
    const signals = [{ id: 'sync:add_account_suspicious_referrer', weight: 0.40 }];
    injectSyncGuardWarningBanner(0.75, signals);
    const banner = document.getElementById('phishops-syncguard-banner');
    expect(banner).not.toBeNull();
    expect(banner.innerHTML).toContain('Browser Sync Hijacking');
  });

  it('is idempotent — does not inject twice', () => {
    const signals = [{ id: 'sync:add_account_suspicious_referrer', weight: 0.40 }];
    injectSyncGuardWarningBanner(0.75, signals);
    injectSyncGuardWarningBanner(0.75, signals);
    const banners = document.querySelectorAll('#phishops-syncguard-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const signals = [
      { id: 'sync:add_account_suspicious_referrer', weight: 0.40 },
      { id: 'sync:sync_setup_instructions', weight: 0.35 },
    ];
    injectSyncGuardWarningBanner(0.75, signals);
    const banner = document.getElementById('phishops-syncguard-banner');
    expect(banner.innerHTML).toContain('High');
    expect(banner.innerHTML).toContain('0.75');
  });

  it('shows Critical severity for score >= 0.90', () => {
    const signals = [{ id: 'sync:add_account_suspicious_referrer', weight: 0.40 }];
    injectSyncGuardWarningBanner(0.95, signals);
    const banner = document.getElementById('phishops-syncguard-banner');
    expect(banner.innerHTML).toContain('Critical');
  });

  it('dismiss button removes banner', () => {
    const signals = [{ id: 'sync:add_account_suspicious_referrer', weight: 0.40 }];
    injectSyncGuardWarningBanner(0.75, signals);
    const dismissBtn = document.getElementById('phishops-syncguard-dismiss');
    expect(dismissBtn).not.toBeNull();
    dismissBtn.click();
    expect(document.getElementById('phishops-syncguard-banner')).toBeNull();
  });
});
