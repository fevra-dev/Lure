/**
 * extension/__tests__/ctap_guard.test.js
 *
 * Tests for CTAPGuard — FIDO Downgrade Detection
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import '../content/ctap_guard.js';
const { checkSafariWindowsUaSpoof, checkFidoAvailableButNotOffered, checkCrossDeviceWebauthnNonProvider, checkUaPlatformMismatch, calculateCtapRiskScore, injectCtapWarningBanner } = globalThis.__phishopsExports['ctap_guard'];

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkSafariWindowsUaSpoof                                          */
/* ================================================================== */

describe('checkSafariWindowsUaSpoof', () => {
  it('detects Safari on Windows (Evilginx spoof)', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
      platform: 'Win32',
    });
    const signals = checkSafariWindowsUaSpoof();
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ctap:safari_windows_ua_spoof');
    expect(signals[0].weight).toBe(0.45);
  });

  it('does NOT flag Chrome on Windows (contains "Safari" in UA)', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      platform: 'Win32',
    });
    const signals = checkSafariWindowsUaSpoof();
    expect(signals).toHaveLength(0);
  });

  it('does NOT flag Edge on Windows', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
      platform: 'Win32',
    });
    expect(checkSafariWindowsUaSpoof()).toHaveLength(0);
  });

  it('does NOT flag Safari on macOS (legitimate)', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
      platform: 'MacIntel',
    });
    expect(checkSafariWindowsUaSpoof()).toHaveLength(0);
  });

  it('does NOT flag Firefox on Windows', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
      platform: 'Win32',
    });
    expect(checkSafariWindowsUaSpoof()).toHaveLength(0);
  });

  it('returns empty when navigator has no userAgent', () => {
    vi.stubGlobal('navigator', { userAgent: '', platform: '' });
    expect(checkSafariWindowsUaSpoof()).toHaveLength(0);
  });

  it('includes fidoAvailable flag in signal', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
      platform: 'Win32',
    });
    vi.stubGlobal('PublicKeyCredential', class {});
    const signals = checkSafariWindowsUaSpoof();
    expect(signals[0].fidoAvailable).toBe(true);
  });
});

/* ================================================================== */
/*  checkFidoAvailableButNotOffered                                    */
/* ================================================================== */

describe('checkFidoAvailableButNotOffered', () => {
  beforeEach(() => {
    vi.stubGlobal('PublicKeyCredential', class {});
  });

  it('fires on FIDO provider login with no passkey UI', () => {
    const doc = makeDoc(`
      <html><body>
        <h1>Sign in</h1>
        <input type="email" placeholder="Email">
        <input type="password" placeholder="Password">
        <button>Sign in</button>
      </body></html>
    `);
    const signals = checkFidoAvailableButNotOffered(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ctap:fido_available_but_not_offered');
    expect(signals[0].weight).toBe(0.35);
  });

  it('does NOT fire when passkey UI elements present', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="email"><input type="password">
        <button data-testid="passkey-button">Use passkey</button>
      </body></html>
    `);
    const signals = checkFidoAvailableButNotOffered(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire when passkey text is present', () => {
    const doc = makeDoc(`
      <html><body>
        <input type="password">
        <p>Sign in with a passkey</p>
      </body></html>
    `);
    const signals = checkFidoAvailableButNotOffered(doc, 'accounts.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire on non-FIDO-provider domain', () => {
    const doc = makeDoc('<html><body><input type="password"></body></html>');
    const signals = checkFidoAvailableButNotOffered(doc, 'evil-phish.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire when PublicKeyCredential is undefined', () => {
    vi.stubGlobal('PublicKeyCredential', undefined);
    const doc = makeDoc('<html><body><input type="password"></body></html>');
    const signals = checkFidoAvailableButNotOffered(doc, 'login.microsoftonline.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire when no login form present', () => {
    const doc = makeDoc('<html><body><p>Just some text</p></body></html>');
    const signals = checkFidoAvailableButNotOffered(doc, 'login.okta.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkFidoAvailableButNotOffered(null, 'login.okta.com')).toHaveLength(0);
    expect(checkFidoAvailableButNotOffered(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkCrossDeviceWebauthnNonProvider                                */
/* ================================================================== */

describe('checkCrossDeviceWebauthnNonProvider', () => {
  it('fires when QR + passkey text on non-provider domain', () => {
    const doc = makeDoc(`
      <html><body>
        <canvas width="200" height="200"></canvas>
        <p>Use a passkey to sign in</p>
      </body></html>
    `);
    const signals = checkCrossDeviceWebauthnNonProvider(doc, 'evil-phish.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ctap:cross_device_webauthn_non_provider');
    expect(signals[0].weight).toBe(0.30);
  });

  it('fires with QR image + security key text', () => {
    const doc = makeDoc(`
      <html><body>
        <img src="/qr-code.png">
        <p>Insert your security key</p>
      </body></html>
    `);
    const signals = checkCrossDeviceWebauthnNonProvider(doc, 'phish-site.net');
    expect(signals).toHaveLength(1);
  });

  it('does NOT fire on FIDO provider domain', () => {
    const doc = makeDoc(`
      <html><body>
        <canvas></canvas>
        <p>Use a passkey</p>
      </body></html>
    `);
    const signals = checkCrossDeviceWebauthnNonProvider(doc, 'accounts.google.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire without QR code indicator', () => {
    const doc = makeDoc(`
      <html><body>
        <p>Use a passkey to sign in</p>
      </body></html>
    `);
    const signals = checkCrossDeviceWebauthnNonProvider(doc, 'evil.com');
    expect(signals).toHaveLength(0);
  });

  it('does NOT fire without passkey text', () => {
    const doc = makeDoc(`
      <html><body>
        <canvas></canvas>
        <p>Regular page content</p>
      </body></html>
    `);
    const signals = checkCrossDeviceWebauthnNonProvider(doc, 'evil.com');
    expect(signals).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkCrossDeviceWebauthnNonProvider(null, 'evil.com')).toHaveLength(0);
    expect(checkCrossDeviceWebauthnNonProvider(makeDoc(), null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkUaPlatformMismatch                                            */
/* ================================================================== */

describe('checkUaPlatformMismatch', () => {
  it('detects Windows UA with Mac platform', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      platform: 'MacIntel',
    });
    const signals = checkUaPlatformMismatch();
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('ctap:ua_platform_mismatch');
    expect(signals[0].weight).toBe(0.25);
  });

  it('detects Mac UA with Windows platform', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/120.0.0.0',
      platform: 'Win32',
    });
    expect(checkUaPlatformMismatch()).toHaveLength(1);
  });

  it('detects Linux UA with Windows platform', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0',
      platform: 'Win32',
    });
    expect(checkUaPlatformMismatch()).toHaveLength(1);
  });

  it('does NOT flag matching Windows UA + platform', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
      platform: 'Win32',
    });
    expect(checkUaPlatformMismatch()).toHaveLength(0);
  });

  it('does NOT flag matching Mac UA + platform', () => {
    vi.stubGlobal('navigator', {
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/120.0.0.0',
      platform: 'MacIntel',
    });
    expect(checkUaPlatformMismatch()).toHaveLength(0);
  });

  it('returns empty when UA or platform is missing', () => {
    vi.stubGlobal('navigator', { userAgent: '', platform: '' });
    expect(checkUaPlatformMismatch()).toHaveLength(0);
  });
});

/* ================================================================== */
/*  calculateCtapRiskScore                                             */
/* ================================================================== */

describe('calculateCtapRiskScore', () => {
  it('returns 0 for empty signals', () => {
    const { riskScore, signalList } = calculateCtapRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('returns 0 for null', () => {
    expect(calculateCtapRiskScore(null).riskScore).toBe(0);
  });

  it('scores safari spoof + platform mismatch correctly', () => {
    const { riskScore } = calculateCtapRiskScore([
      { id: 'ctap:safari_windows_ua_spoof', weight: 0.45 },
      { id: 'ctap:ua_platform_mismatch', weight: 0.25 },
    ]);
    expect(riskScore).toBeCloseTo(0.70);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculateCtapRiskScore([
      { id: 'a', weight: 0.45 },
      { id: 'b', weight: 0.35 },
      { id: 'c', weight: 0.30 },
      { id: 'd', weight: 0.25 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('returns signal list', () => {
    const { signalList } = calculateCtapRiskScore([
      { id: 'ctap:safari_windows_ua_spoof', weight: 0.45 },
    ]);
    expect(signalList).toEqual(['ctap:safari_windows_ua_spoof']);
  });
});

/* ================================================================== */
/*  injectCtapWarningBanner                                            */
/* ================================================================== */

describe('injectCtapWarningBanner', () => {
  let dom, doc;

  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>');
    doc = dom.window.document;
    vi.stubGlobal('document', doc);
  });

  it('injects banner into document', () => {
    injectCtapWarningBanner(0.80, [
      { id: 'ctap:safari_windows_ua_spoof' },
    ]);
    const banner = doc.getElementById('phishops-ctap-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('FIDO Downgrade');
  });

  it('is idempotent', () => {
    injectCtapWarningBanner(0.80, [{ id: 'a' }]);
    injectCtapWarningBanner(0.80, [{ id: 'a' }]);
    const banners = doc.querySelectorAll('#phishops-ctap-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays correct severity', () => {
    injectCtapWarningBanner(0.95, [{ id: 'a' }]);
    const banner = doc.getElementById('phishops-ctap-banner');
    expect(banner.textContent).toContain('Critical');
  });

  it('dismiss button removes banner', () => {
    injectCtapWarningBanner(0.70, [{ id: 'a' }]);
    const dismiss = doc.getElementById('phishops-ctap-dismiss');
    dismiss.click();
    expect(doc.getElementById('phishops-ctap-banner')).toBeNull();
  });
});
