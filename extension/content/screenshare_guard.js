/**
 * extension/content/screenshare_guard.js
 *
 * ScreenShareGuard — Detects TOAD (Telephone-Oriented Attack Delivery)
 * screen share attacks via getDisplayMedia() interception.
 * Injected at document_start to wrap navigator.mediaDevices.getDisplayMedia
 * before attacker code can cache a reference to the original API.
 *
 * Attack chain this closes:
 *   Attacker calls victim (impersonating IT support / help desk), directs them
 *   to a web page, and requests screen share via getDisplayMedia(). Once sharing
 *   is active, the attacker observes MFA codes, password entry, sensitive
 *   documents, and session tokens visible on screen.
 *
 * Detection model: Additive signal scoring across share context analysis:
 *   1. Non-platform origin    — page is not a known video/support platform
 *   2. No user gesture        — getDisplayMedia called without recent interaction
 *   3. Support page context   — page text suggests tech support / remote assistance
 *   4. Credential during share — password field focused while screen share active
 *   5. Rapid share request    — getDisplayMedia called within 5s of page load
 *   6. Cross-origin iframe    — called from a cross-origin iframe
 *
 * References:
 *   - MuddyWater/TA450, RansomHub, Luna Moth, BazarCall TOAD campaigns
 *   - MITRE ATT&CK T1113 (Screen Capture) + T1056.003 (Web Portal Capture)
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;
const GESTURE_WINDOW_MS = 1000;
const RAPID_SHARE_MS = 5000;

const KNOWN_SHARE_PLATFORMS = [
  'zoom.us', 'meet.google.com', 'teams.microsoft.com', 'webex.com',
  'discord.com', 'gotomeeting.com', 'whereby.com', 'gather.town',
  'anydesk.com', 'teamviewer.com',
  'connectwise.com', 'bomgar.com', 'splashtop.com', 'logmein.com',
];

const SUPPORT_TEXT_PATTERNS = [
  'tech support',
  'remote assistance',
  'it support',
  'help desk',
  'diagnostic',
  'troubleshoot',
  'remote access',
  'screen share to',
  'share your screen',
];

// ---------------------------------------------------------------------------
// User gesture tracking
// ---------------------------------------------------------------------------

let lastGestureTimestamp = 0;

function trackGesture() {
  lastGestureTimestamp = Date.now();
}

// Exported for testing
function _setLastGestureTimestamp(ts) {
  lastGestureTimestamp = ts;
}

// ---------------------------------------------------------------------------
// Active screen share state
// ---------------------------------------------------------------------------

let activeScreenShare = false;

// Exported for testing
function _isScreenShareActive() {
  return activeScreenShare;
}

function _setScreenShareActive(val) {
  activeScreenShare = val;
}

// ---------------------------------------------------------------------------
// Signal checks (exported for unit testing)
// ---------------------------------------------------------------------------

/**
 * Check screen share signals based on call context.
 *
 * @returns {{ id: string, weight: number }[]}
 */
function checkScreenShareSignals() {
  const signals = [];

  // Signal 1: Non-platform origin
  try {
    const hostname = window.location.hostname;
    const isKnownPlatform = KNOWN_SHARE_PLATFORMS.some(
      p => hostname === p || hostname.endsWith('.' + p),
    );
    const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

    if (!isKnownPlatform && !isLocalhost) {
      signals.push({ id: 'screenshare:non_platform_origin', weight: 0.35 });
    }
  } catch {
    // Non-critical
  }

  // Signal 2: No user gesture
  const timeSinceGesture = Date.now() - lastGestureTimestamp;
  if (timeSinceGesture > GESTURE_WINDOW_MS) {
    signals.push({ id: 'screenshare:no_user_gesture', weight: 0.30 });
  }

  // Signal 5: Rapid share request (within 5s of page load)
  try {
    if (typeof performance !== 'undefined' && performance.now() < RAPID_SHARE_MS) {
      signals.push({ id: 'screenshare:rapid_share_request', weight: 0.20 });
    }
  } catch {
    // Non-critical
  }

  // Signal 6: Cross-origin iframe
  try {
    if (window.self !== window.top) {
      signals.push({ id: 'screenshare:cross_origin_iframe', weight: 0.30 });
    }
  } catch {
    // Cross-origin iframe — accessing window.top throws
    signals.push({ id: 'screenshare:cross_origin_iframe', weight: 0.30 });
  }

  return signals;
}

/**
 * Check page context for tech support / remote assistance signals.
 * @returns {{ id: string, weight: number }[]}
 */
function checkScreenSharePageContext() {
  const signals = [];

  try {
    const hostname = window.location.hostname;

    // Skip known platforms
    const isKnownPlatform = KNOWN_SHARE_PLATFORMS.some(
      p => hostname === p || hostname.endsWith('.' + p),
    );
    if (isKnownPlatform) return signals;

    // Skip localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1') return signals;

    const pageText = (document.body?.innerText || document.body?.textContent || '').toLowerCase();

    const hasSupportText = SUPPORT_TEXT_PATTERNS.some(
      pattern => pageText.includes(pattern),
    );

    if (hasSupportText) {
      signals.push({ id: 'screenshare:support_page_context', weight: 0.25 });
    }
  } catch {
    // Page context check is non-critical
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Risk score calculation (exported for unit testing)
// ---------------------------------------------------------------------------

function calculateScreenShareRiskScore(signals) {
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

function injectScreenShareWarningBanner(riskScore, signals) {
  if (document.getElementById('phishops-screenshare-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-screenshare-warning';
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
        suspicious screen share detected \u2014 phishops screenshareguard
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        A screen share request was flagged as potentially suspicious.
        Risk score: ${riskScore.toFixed(2)}.
        Avoid entering credentials while sharing your screen.
      </span>
    </div>
    <button id="phishops-screenshare-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-screenshare-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

// ---------------------------------------------------------------------------
// Credential warning banner (separate from main warning)
// ---------------------------------------------------------------------------

function injectCredentialWarningBanner() {
  if (document.getElementById('phishops-screenshare-cred-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-screenshare-cred-warning';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #0A0907; border-bottom: 2px solid #BF1B1B;
    padding: 14px 20px; font-family: 'Work Sans', system-ui, -apple-system, sans-serif;
    display: flex; align-items: center; gap: 14px;
  `;

  banner.innerHTML = `
    <span style="font-size: 24px; flex-shrink:0;">\u26A0\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B; font-size:15px; display:block; margin-bottom:3px; font-family:'Work Sans',system-ui,sans-serif;">
        credential field visible during screen share \u2014 phishops screenshareguard
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        You focused a password field while screen sharing is active.
        Anyone viewing your screen can see your credentials.
      </span>
    </div>
    <button id="phishops-screenshare-cred-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-screenshare-cred-dismiss')?.addEventListener('click', () => {
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
        type: 'SCREENSHAREGUARD_EVENT',
        payload,
      });
    }
  } catch (err) {
    console.error('[SCREENSHARE_GUARD] sendToBackground failed:', err);
  }
}

// ---------------------------------------------------------------------------
// Credential-during-share monitoring (exported for unit testing)
// ---------------------------------------------------------------------------

let credentialListener = null;

function monitorCredentialFieldsDuringShare(stream) {
  activeScreenShare = true;

  // Listen for password field focus
  credentialListener = (event) => {
    if (!activeScreenShare) return;

    const target = event.target;
    if (!target || !target.tagName) return;

    const isCredentialField =
      (target.tagName === 'INPUT' && (target.type === 'password' || target.type === 'text')) &&
      (target.type === 'password' ||
       target.autocomplete === 'current-password' ||
       target.autocomplete === 'new-password' ||
       target.name?.toLowerCase().includes('pass'));

    if (isCredentialField) {
      injectCredentialWarningBanner();

      sendToBackground({
        eventType: 'SCREENSHARE_TOAD_DETECTED',
        riskScore: 0.90,
        severity: 'Critical',
        signals: ['screenshare:credential_during_share'],
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'credential_warning',
        credentialFieldFocused: true,
      });
    }
  };

  document.addEventListener('focusin', credentialListener, true);

  // Track when screen share stops
  if (stream?.getTracks) {
    for (const track of stream.getTracks()) {
      track.addEventListener('ended', () => {
        activeScreenShare = false;
        if (credentialListener) {
          document.removeEventListener('focusin', credentialListener, true);
          credentialListener = null;
        }
        // Remove credential warning if showing
        document.getElementById('phishops-screenshare-cred-warning')?.remove();
      });
    }
  }
}

// ---------------------------------------------------------------------------
// getDisplayMedia interceptor (exported for unit testing)
// ---------------------------------------------------------------------------

function installGetDisplayMediaInterceptor() {
  // Track user gestures
  document.addEventListener('click', trackGesture, true);
  document.addEventListener('keydown', trackGesture, true);

  if (!navigator.mediaDevices?.getDisplayMedia) return;

  const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);

  async function wrappedGetDisplayMedia(options) {
    // Analyze signals before the call
    const shareSignals = checkScreenShareSignals();
    const pageSignals = checkScreenSharePageContext();
    const allSignals = [...shareSignals, ...pageSignals];
    const { riskScore, signalList } = calculateScreenShareRiskScore(allSignals);

    // Get the stream — we do NOT block screen share
    const stream = await originalGetDisplayMedia(options);

    if (riskScore >= ALERT_THRESHOLD) {
      const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';

      sendToBackground({
        eventType: 'SCREENSHARE_TOAD_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'alerted',
        credentialFieldFocused: false,
      });

      injectScreenShareWarningBanner(riskScore, signalList);
    }

    // Always monitor credentials during active share
    monitorCredentialFieldsDuringShare(stream);

    return stream;
  }

  try {
    Object.defineProperty(navigator.mediaDevices, 'getDisplayMedia', {
      value: wrappedGetDisplayMedia,
      writable: false,
      configurable: true,
    });
  } catch {
    navigator.mediaDevices.getDisplayMedia = wrappedGetDisplayMedia;
  }
}

// ---------------------------------------------------------------------------
// Auto-run when injected as a content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installGetDisplayMediaInterceptor();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['screenshare_guard'] = {
    _setLastGestureTimestamp,
    _isScreenShareActive,
    _setScreenShareActive,
    checkScreenShareSignals,
    checkScreenSharePageContext,
    calculateScreenShareRiskScore,
    injectScreenShareWarningBanner,
    monitorCredentialFieldsDuringShare,
    installGetDisplayMediaInterceptor,
  };
}

})();
