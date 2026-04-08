/**
 * extension/content/ctap_guard.js
 *
 * CTAPGuard — FIDO Downgrade Detection
 *
 * Detects Evilginx-style User-Agent spoofing that forces identity providers
 * to fall back from FIDO2/passkey to password+OTP. Evilginx rewrites UA via
 * sub_filter to claim "Safari on Windows" — an impossible combination. This
 * causes Microsoft Entra and other IdPs to skip FIDO challenges, allowing
 * AiTM credential capture. Proofpoint demonstrated working PoC Aug 2025.
 *
 * Signal architecture:
 *   ctap:safari_windows_ua_spoof           +0.45
 *   ctap:fido_available_but_not_offered     +0.35
 *   ctap:cross_device_webauthn_non_provider +0.30
 *   ctap:ua_platform_mismatch              +0.25
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module CTAPGuard
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/** Duplicated from proxy_guard.js — MV3 content scripts cannot share modules. */
const FIDO_PROVIDER_DOMAINS = [
  'login.microsoftonline.com',
  'accounts.google.com',
  'login.okta.com',
  'id.atlassian.com',
  'auth0.com',
  'login.salesforce.com',
];

const PASSKEY_UI_SELECTORS = [
  '[data-testid*="passkey"]',
  '[data-testid*="fido"]',
  '[data-testid*="webauthn"]',
  '[id*="passkey"]',
  '[id*="fido"]',
  '[class*="passkey"]',
  '[class*="fido"]',
  'button[name*="passkey"]',
  'a[href*="passkey"]',
  'a[href*="fido"]',
];

const PASSKEY_TEXT_PATTERNS = [
  /use\s*a?\s*passkey/i,
  /sign\s*in\s*with\s*(a\s*)?passkey/i,
  /security\s*key/i,
  /use\s*your\s*fingerprint/i,
  /use\s*face\s*id/i,
  /windows\s*hello/i,
];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check for Safari + Windows User-Agent — an impossible combination.
 * Safari never runs on Windows. Evilginx uses this to force FIDO downgrade.
 * Must NOT flag Chrome (which includes "Safari" in its UA string).
 */
function checkSafariWindowsUaSpoof() {
  const ua = globalThis.navigator?.userAgent || '';
  if (!ua) return [];

  const hasSafari = /Safari/i.test(ua);
  const hasWindows = /Windows/i.test(ua);
  const hasChrome = /Chrome/i.test(ua) || /Chromium/i.test(ua) || /CriOS/i.test(ua);
  const hasFirefox = /Firefox/i.test(ua);
  const hasEdge = /Edg/i.test(ua);

  // Safari on Windows, excluding Chrome/Firefox/Edge (which include "Safari" in UA)
  if (hasSafari && hasWindows && !hasChrome && !hasFirefox && !hasEdge) {
    // Extra confidence: real browser should have PublicKeyCredential
    const hasFido = typeof globalThis.PublicKeyCredential !== 'undefined';

    return [{
      id: 'ctap:safari_windows_ua_spoof',
      weight: 0.45,
      userAgent: ua.substring(0, 200),
      fidoAvailable: hasFido,
    }];
  }

  return [];
}

/**
 * Check if page is a known FIDO provider login but no passkey UI is offered,
 * despite the browser supporting FIDO.
 */
function checkFidoAvailableButNotOffered(doc, hostname) {
  if (!doc || !hostname) return [];

  // Must be a known FIDO provider
  const isFidoProvider = FIDO_PROVIDER_DOMAINS.some(
    d => hostname === d || hostname.endsWith('.' + d)
  );
  if (!isFidoProvider) return [];

  // Browser must support FIDO
  if (typeof globalThis.PublicKeyCredential === 'undefined') return [];

  // Check for passkey UI elements
  const hasPasskeyUI = PASSKEY_UI_SELECTORS.some(
    selector => doc.querySelectorAll(selector).length > 0
  );
  if (hasPasskeyUI) return [];

  // Check for passkey text
  const bodyText = doc.body?.innerText || doc.body?.textContent || '';
  const hasPasskeyText = PASSKEY_TEXT_PATTERNS.some(p => p.test(bodyText));
  if (hasPasskeyText) return [];

  // Must have a login form to be relevant
  const hasLoginForm =
    doc.querySelectorAll('input[type="password"]').length > 0 ||
    doc.querySelectorAll('input[type="email"]').length > 0 ||
    doc.querySelectorAll('input[autocomplete="username"]').length > 0;
  if (!hasLoginForm) return [];

  return [{
    id: 'ctap:fido_available_but_not_offered',
    weight: 0.35,
    provider: hostname,
  }];
}

/**
 * Check for QR code + passkey text on a non-auth-provider domain.
 * Cross-device WebAuthn phishing.
 */
function checkCrossDeviceWebauthnNonProvider(doc, hostname) {
  if (!doc || !hostname) return [];

  // Must NOT be a known auth provider
  const isFidoProvider = FIDO_PROVIDER_DOMAINS.some(
    d => hostname === d || hostname.endsWith('.' + d)
  );
  if (isFidoProvider) return [];

  // Check for QR code indicators
  const hasQRCode =
    doc.querySelectorAll('canvas').length > 0 ||
    doc.querySelectorAll('img[src*="qr"]').length > 0 ||
    doc.querySelectorAll('[class*="qr"]').length > 0 ||
    doc.querySelectorAll('svg').length > 0;
  if (!hasQRCode) return [];

  // Check for passkey/WebAuthn text
  const bodyText = doc.body?.innerText || doc.body?.textContent || '';
  const hasPasskeyText = PASSKEY_TEXT_PATTERNS.some(p => p.test(bodyText));
  if (!hasPasskeyText) return [];

  return [{
    id: 'ctap:cross_device_webauthn_non_provider',
    weight: 0.30,
    domain: hostname,
  }];
}

/**
 * Check if navigator.platform contradicts the User-Agent OS claim.
 */
function checkUaPlatformMismatch() {
  const ua = globalThis.navigator?.userAgent || '';
  const platform = globalThis.navigator?.platform || '';
  if (!ua || !platform) return [];

  // Determine OS from UA
  const uaClaims = {
    windows: /Windows/i.test(ua),
    mac: /Macintosh|Mac OS/i.test(ua),
    linux: /Linux/i.test(ua) && !/Android/i.test(ua),
    android: /Android/i.test(ua),
  };

  // Determine OS from platform
  const platformIs = {
    windows: /Win/i.test(platform),
    mac: /Mac/i.test(platform),
    linux: /Linux/i.test(platform),
  };

  // Check for contradictions
  const mismatch =
    (uaClaims.windows && platformIs.mac) ||
    (uaClaims.windows && platformIs.linux) ||
    (uaClaims.mac && platformIs.windows) ||
    (uaClaims.mac && platformIs.linux) ||
    (uaClaims.linux && platformIs.windows) ||
    (uaClaims.linux && platformIs.mac);

  if (mismatch) {
    return [{
      id: 'ctap:ua_platform_mismatch',
      weight: 0.25,
      userAgent: ua.substring(0, 200),
      platform,
    }];
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

/**
 * Calculate composite risk score from signal array.
 * @param {Array<{id: string, weight: number}>} signals
 * @returns {{ riskScore: number, signalList: string[] }}
 */
function calculateCtapRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

/**
 * Inject a warning banner into the page.
 */
function injectCtapWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-ctap-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-ctap-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected FIDO Downgrade Attack</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('ctap:', '')).join(', ')}
    </div>
    <button id="phishops-ctap-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-ctap-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Run full CTAPGuard analysis on the current page.
 */
function runCtapGuardAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname) return;

  const doc = document;

  const safariSpoofSignals = checkSafariWindowsUaSpoof();
  const fidoSignals = checkFidoAvailableButNotOffered(doc, hostname);
  const crossDeviceSignals = checkCrossDeviceWebauthnNonProvider(doc, hostname);
  const platformSignals = checkUaPlatformMismatch();

  const allSignals = [
    ...safariSpoofSignals,
    ...fidoSignals,
    ...crossDeviceSignals,
    ...platformSignals,
  ];

  const { riskScore, signalList } = calculateCtapRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectCtapWarningBanner(riskScore, allSignals);

  // Emit telemetry
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'CTAPGUARD_EVENT',
      payload: {
        eventType: 'FIDO_DOWNGRADE_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: globalThis.location?.href || '',
        timestamp: new Date().toISOString(),
        action,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof document !== 'undefined' && typeof process === 'undefined') {
  runCtapGuardAnalysis();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['ctap_guard'] = {
    checkSafariWindowsUaSpoof,
    checkFidoAvailableButNotOffered,
    checkCrossDeviceWebauthnNonProvider,
    checkUaPlatformMismatch,
    calculateCtapRiskScore,
    injectCtapWarningBanner,
    runCtapGuardAnalysis,
  };
}
