/**
 * extension/content/passkey_guard.js
 *
 * PasskeyGuard — Detects WebAuthn/Passkey credential substitution attacks.
 * Injected at document_start to wrap navigator.credentials before attacker
 * code can cache a reference to the original API.
 *
 * Attack chain this closes:
 *   Attacker-controlled page intercepts navigator.credentials.create() to
 *   redirect passkey registration to attacker's relying party, or intercepts
 *   navigator.credentials.get() to relay authentication challenges. The
 *   passkey sync fabric (Google Password Manager, iCloud Keychain) means
 *   compromising one passkey gives access to ALL synced credentials.
 *
 * Detection model: Additive signal scoring across credential request analysis:
 *   1. RP ID mismatch       — relying party doesn't match page origin
 *   2. Gesture analysis      — no recent user interaction
 *   3. Context analysis      — cross-origin iframe, attestation, rapid calls
 *   4. Typosquatting         — RP ID resembles a major brand
 *
 * References:
 *   - Chad Spensky DEF CON 33: passkey sync fabric phishing
 *   - IEEE S&P 2026 (Singh, Lin, Seetoh / SquareX): WebAuthn attack research
 *   - MITRE ATT&CK T1556.006 (Modify Authentication Process: MFA)
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;
const GESTURE_WINDOW_MS = 1000;
const RAPID_WINDOW_MS = 10000;

const KNOWN_BRAND_DOMAINS = [
  'microsoft.com', 'google.com', 'apple.com', 'amazon.com',
  'facebook.com', 'meta.com', 'github.com', 'twitter.com',
  'linkedin.com', 'paypal.com', 'dropbox.com', 'salesforce.com',
  'adobe.com', 'netflix.com', 'spotify.com', 'slack.com',
  'zoom.us', 'okta.com', 'coinbase.com', 'binance.com',
];

const ENTERPRISE_AUTH_PROVIDERS = [
  'okta.com', 'auth0.com', 'duo.com', 'onelogin.com',
  'ping.com', 'pingidentity.com', 'cyberark.com',
  'login.microsoftonline.com', 'accounts.google.com',
];

// ---------------------------------------------------------------------------
// Levenshtein distance for typosquatting detection
// ---------------------------------------------------------------------------

function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = b[i - 1] === a[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
    }
  }

  return matrix[b.length][a.length];
}

// ---------------------------------------------------------------------------
// User gesture tracking
// ---------------------------------------------------------------------------

let lastGestureTimestamp = 0;

function trackGesture() {
  lastGestureTimestamp = Date.now();
}

// ---------------------------------------------------------------------------
// Rapid registration tracking
// ---------------------------------------------------------------------------

const createCallTimestamps = [];

// ---------------------------------------------------------------------------
// Signal checks (exported for unit testing)
// ---------------------------------------------------------------------------

export function checkCredentialRequestSignals(options, callType) {
  const signals = [];

  // Extract RP ID based on call type
  let rpId = null;
  if (callType === 'create') {
    rpId = options?.publicKey?.rp?.id || null;
  } else if (callType === 'get') {
    rpId = options?.publicKey?.rpId || null;
  }

  // Signal 1: RP ID mismatch
  if (rpId) {
    const hostname = window.location.hostname;
    const rpMatches = hostname === rpId ||
      hostname.endsWith('.' + rpId) ||
      rpId.endsWith('.' + hostname);

    // Also check enterprise auth providers
    const isEnterprise = ENTERPRISE_AUTH_PROVIDERS.some(
      provider => rpId === provider || rpId.endsWith('.' + provider),
    );

    if (!rpMatches && !isEnterprise) {
      signals.push({ id: 'passkey:rp_id_mismatch', weight: 0.45 });
    }

    // Signal 6: Known phishing RP (typosquatting)
    for (const brand of KNOWN_BRAND_DOMAINS) {
      if (rpId === brand) break; // Exact match is legitimate
      const distance = levenshteinDistance(rpId.toLowerCase(), brand);
      if (distance > 0 && distance <= 2) {
        signals.push({ id: 'passkey:known_phishing_rp', weight: 0.40 });
        break;
      }
    }
  }

  // Signal 2: No user gesture
  const timeSinceGesture = Date.now() - lastGestureTimestamp;
  if (timeSinceGesture > GESTURE_WINDOW_MS) {
    signals.push({ id: 'passkey:no_user_gesture', weight: 0.35 });
  }

  // Signal 3: Cross-origin iframe
  try {
    if (window.self !== window.top) {
      signals.push({ id: 'passkey:cross_origin_iframe', weight: 0.30 });
    }
  } catch {
    // Cross-origin iframe — accessing window.top throws
    signals.push({ id: 'passkey:cross_origin_iframe', weight: 0.30 });
  }

  // Signal 4: Suspicious attestation (create only)
  if (callType === 'create') {
    const attestation = options?.publicKey?.attestation;
    if (attestation === 'direct') {
      const hostname = window.location.hostname;
      const isEnterprise = ENTERPRISE_AUTH_PROVIDERS.some(
        provider => hostname === provider || hostname.endsWith('.' + provider),
      );
      if (!isEnterprise) {
        signals.push({ id: 'passkey:suspicious_attestation', weight: 0.25 });
      }
    }
  }

  // Signal 5: Rapid registration (create only)
  if (callType === 'create') {
    const now = Date.now();
    createCallTimestamps.push(now);
    // Keep only recent timestamps
    while (createCallTimestamps.length > 0 && now - createCallTimestamps[0] > RAPID_WINDOW_MS) {
      createCallTimestamps.shift();
    }
    if (createCallTimestamps.length >= 3) {
      signals.push({ id: 'passkey:rapid_registration', weight: 0.20 });
    }
  }

  return signals;
}

export function checkPasskeyPageContext() {
  // Reserved for future page-level context signals
  return [];
}

// ---------------------------------------------------------------------------
// Risk score calculation (exported for unit testing)
// ---------------------------------------------------------------------------

export function calculatePasskeyRiskScore(signals) {
  let score = 0.0;
  const signalList = [];

  for (const signal of signals) {
    score += signal.weight;
    signalList.push(signal.id);
  }

  return {
    riskScore: Math.round(Math.min(score, 1.0) * 100) / 100,
    signalList,
  };
}

// ---------------------------------------------------------------------------
// Warning banner (exported for unit testing)
// ---------------------------------------------------------------------------

export function injectPasskeyWarningBanner(riskScore, rpId, signals) {
  if (document.getElementById('phishops-passkey-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-passkey-warning';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #0A0907; border-bottom: 2px solid #BF1B1B;
    padding: 14px 20px; font-family: 'Work Sans', system-ui, -apple-system, sans-serif;
    display: flex; align-items: center; gap: 14px;
  `;

  banner.innerHTML = `
    <span style="font-size: 24px; flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B; font-size:15px; display:block; margin-bottom:3px; font-family:'Work Sans',system-ui,sans-serif;">
        passkey credential attack blocked \u2014 phishops passkeyguard
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        A page attempted a suspicious WebAuthn credential operation.
        Relying party: <code style="color:#BF1B1B;">${rpId || 'unknown'}</code>.
        Risk score: ${riskScore.toFixed(2)}.
      </span>
    </div>
    <button id="phishops-passkey-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-passkey-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

// ---------------------------------------------------------------------------
// Telemetry emitter
// ---------------------------------------------------------------------------

function sendToBackground(payload) {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'PASSKEYGUARD_EVENT',
        payload,
      });
    }
  } catch (err) {
    console.error('[PASSKEY_GUARD] sendToBackground failed:', err);
  }
}

// ---------------------------------------------------------------------------
// Credential interceptor (exported for unit testing)
// ---------------------------------------------------------------------------

export function installCredentialInterceptor() {
  // Track user gestures
  document.addEventListener('click', trackGesture, true);
  document.addEventListener('keydown', trackGesture, true);

  if (!navigator.credentials) return;

  const originalCreate = navigator.credentials.create?.bind(navigator.credentials);
  const originalGet = navigator.credentials.get?.bind(navigator.credentials);

  function analyzeAndAct(options, callType, originalFn) {
    const signals = checkCredentialRequestSignals(options, callType);
    const pageSignals = checkPasskeyPageContext();
    const allSignals = [...signals, ...pageSignals];
    const { riskScore, signalList } = calculatePasskeyRiskScore(allSignals);

    let rpId = null;
    if (callType === 'create') {
      rpId = options?.publicKey?.rp?.id || null;
    } else {
      rpId = options?.publicKey?.rpId || null;
    }

    if (riskScore >= BLOCK_THRESHOLD) {
      const telemetry = {
        eventType: 'PASSKEY_CREDENTIAL_INTERCEPTION',
        riskScore,
        severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium',
        rpId: rpId || 'unknown',
        callType,
        signals: signalList,
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'blocked',
      };

      sendToBackground(telemetry);
      injectPasskeyWarningBanner(riskScore, rpId, signalList);

      return Promise.reject(new DOMException(
        'Credential operation blocked by PhishOps — suspicious relying party',
        'NotAllowedError',
      ));
    }

    if (riskScore >= ALERT_THRESHOLD) {
      const telemetry = {
        eventType: 'PASSKEY_CREDENTIAL_INTERCEPTION',
        riskScore,
        severity: 'Medium',
        rpId: rpId || 'unknown',
        callType,
        signals: signalList,
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'alerted',
      };

      sendToBackground(telemetry);
      injectPasskeyWarningBanner(riskScore, rpId, signalList);
    }

    return originalFn(options);
  }

  // Wrap create()
  if (originalCreate) {
    try {
      Object.defineProperty(navigator.credentials, 'create', {
        value: function(options) {
          return analyzeAndAct(options, 'create', originalCreate);
        },
        writable: false,
        configurable: true,
      });
    } catch {
      navigator.credentials.create = function(options) {
        return analyzeAndAct(options, 'create', originalCreate);
      };
    }
  }

  // Wrap get()
  if (originalGet) {
    try {
      Object.defineProperty(navigator.credentials, 'get', {
        value: function(options) {
          return analyzeAndAct(options, 'get', originalGet);
        },
        writable: false,
        configurable: true,
      });
    } catch {
      navigator.credentials.get = function(options) {
        return analyzeAndAct(options, 'get', originalGet);
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Auto-run when injected as a content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installCredentialInterceptor();
}
