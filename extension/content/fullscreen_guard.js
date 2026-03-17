/**
 * extension/content/fullscreen_guard.js
 *
 * FullscreenGuard — Detects Browser-in-the-Middle fullscreen overlay attacks.
 * Injected at document_idle.
 *
 * Attack chain this closes:
 *   Attacker triggers fullscreen mode (often without user gesture), then
 *   renders a fake browser chrome overlay with a spoofed URL bar. The
 *   victim believes they are on a legitimate site and enters credentials
 *   into the attacker-controlled page.
 *
 * Detection model: Additive signal scoring across four categories:
 *   1. Gesture analysis    — fullscreen entered without recent user interaction
 *   2. Target analysis     — fullscreen element is/contains an iframe
 *   3. Post-fullscreen DOM — overlay creation, opacity manipulation, fake chrome
 *   4. Credential presence — password fields visible near fullscreen element
 *
 * References:
 *   - Safari unpatched (Apple refuses to fix fullscreen spoofing)
 *   - 1Password ≤8.11.27.2 and LastPass ≤4.150.1 vulnerable
 *   - MITRE ATT&CK T1185 (Browser Session Hijacking)
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALERT_THRESHOLD = 0.50;
const EXIT_THRESHOLD = 0.70;
const GESTURE_WINDOW_MS = 1000;
const MUTATION_WATCH_MS = 3000;
const OVERLAY_VIEWPORT_RATIO = 0.60;
const HIGH_Z_INDEX = 10000;

const VIDEO_PLATFORMS = [
  'youtube.com', 'www.youtube.com',
  'vimeo.com', 'player.vimeo.com',
  'netflix.com', 'www.netflix.com',
  'twitch.tv', 'www.twitch.tv',
];

const PRESENTATION_CLASS_PATTERNS = [
  /\breveal\b/i,
  /\bimpress\b/i,
  /\bslides?\b/i,
  /\bpresentation\b/i,
  /\bslideshow\b/i,
];

// ---------------------------------------------------------------------------
// User gesture tracking
// ---------------------------------------------------------------------------

let lastGestureTimestamp = 0;

function trackGesture() {
  lastGestureTimestamp = Date.now();
}

// ---------------------------------------------------------------------------
// Signal checks (exported for unit testing)
// ---------------------------------------------------------------------------

export function checkFullscreenGestureSignal() {
  const signals = [];
  const fsEl = document.fullscreenElement;

  if (!fsEl) return signals;

  const timeSinceGesture = Date.now() - lastGestureTimestamp;
  if (timeSinceGesture > GESTURE_WINDOW_MS) {
    signals.push({ id: 'fullscreen:no_user_gesture', weight: 0.40 });
  }

  return signals;
}

export function checkFullscreenTargetSignals() {
  const signals = [];
  const fsEl = document.fullscreenElement;

  if (!fsEl) return signals;

  const isIframe = fsEl.tagName === 'IFRAME' || fsEl.querySelector('iframe');
  if (isIframe) {
    signals.push({ id: 'fullscreen:iframe_target', weight: 0.30 });

    // Check for cross-origin iframe
    const iframe = fsEl.tagName === 'IFRAME' ? fsEl : fsEl.querySelector('iframe');
    if (iframe) {
      try {
        const iframeSrc = iframe.getAttribute('src') || '';
        if (iframeSrc && /^https?:\/\//i.test(iframeSrc)) {
          const iframeOrigin = new URL(iframeSrc).origin;
          if (iframeOrigin !== window.location.origin) {
            signals.push({ id: 'fullscreen:cross_origin_iframe', weight: 0.20 });
          }
        }
      } catch {
        // Invalid URL — treat as cross-origin
        signals.push({ id: 'fullscreen:cross_origin_iframe', weight: 0.20 });
      }
    }
  }

  return signals;
}

export function checkPostFullscreenMutations(mutations) {
  const signals = [];

  for (const mutation of mutations) {
    if (mutation.type === 'attributes') {
      // Opacity manipulation
      if (mutation.attributeName === 'style') {
        const el = mutation.target;
        const computed = typeof getComputedStyle === 'function' ? getComputedStyle(el) : null;
        const opacity = computed ? parseFloat(computed.opacity) : 1;
        if (opacity < 0.1) {
          signals.push({ id: 'fullscreen:opacity_manipulation', weight: 0.30 });
        }
      }
    }

    if (mutation.type === 'childList') {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== 1) continue;

        // Check for high-z-index overlay
        const style = typeof getComputedStyle === 'function' ? getComputedStyle(node) : null;
        if (style) {
          const zIndex = parseInt(style.zIndex, 10);
          if (zIndex > HIGH_Z_INDEX) {
            const rect = typeof node.getBoundingClientRect === 'function'
              ? node.getBoundingClientRect()
              : { width: 0, height: 0 };
            const viewportArea = window.innerWidth * window.innerHeight;
            const elementArea = rect.width * rect.height;
            if (viewportArea > 0 && (elementArea / viewportArea) > OVERLAY_VIEWPORT_RATIO) {
              signals.push({ id: 'fullscreen:overlay_created', weight: 0.35 });
            }
          }
        }

        // Check for fake browser chrome (fake URL bar)
        const text = node.textContent || '';
        if (/https?:\/\//.test(text)) {
          const innerStyle = typeof getComputedStyle === 'function' ? getComputedStyle(node) : null;
          if (innerStyle) {
            const height = parseInt(innerStyle.height, 10);
            const width = parseInt(innerStyle.width, 10);
            // Narrow height + wide width = URL-bar-like element
            if (height > 0 && height < 60 && width > 300) {
              signals.push({ id: 'fullscreen:fake_browser_chrome', weight: 0.35 });
            }
          }
        }
      }
    }
  }

  // Deduplicate by signal id
  const seen = new Set();
  return signals.filter(s => {
    if (seen.has(s.id)) return false;
    seen.add(s.id);
    return true;
  });
}

export function checkCredentialFieldVisibility() {
  const signals = [];
  const fsEl = document.fullscreenElement;

  if (!fsEl) return signals;

  const passwordFields = fsEl.querySelectorAll('input[type="password"], input[type=password]');
  if (passwordFields.length > 0) {
    signals.push({ id: 'fullscreen:credential_field_visible', weight: 0.25 });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Risk score calculation (exported for unit testing)
// ---------------------------------------------------------------------------

export function calculateFullscreenRiskScore(signals) {
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

export function injectFullscreenWarningBanner(riskScore, signals) {
  if (document.getElementById('phishops-fullscreen-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-fullscreen-warning';
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
        fullscreen overlay attack detected \u2014 phishops fullscreenguard
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        This page entered fullscreen mode with suspicious overlay behavior.
        This technique is used to spoof browser UI and steal credentials.
        Risk score: ${riskScore.toFixed(2)}.
      </span>
    </div>
    <button id="phishops-fullscreen-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-fullscreen-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

// ---------------------------------------------------------------------------
// False positive suppression
// ---------------------------------------------------------------------------

function isVideoFullscreen() {
  const fsEl = document.fullscreenElement;
  if (!fsEl) return false;

  // Direct video element or sole child is video
  if (fsEl.tagName === 'VIDEO') return true;
  if (fsEl.children.length === 1 && fsEl.children[0].tagName === 'VIDEO') return true;

  return false;
}

function isVideoPlatform() {
  try {
    const hostname = window.location.hostname;
    return VIDEO_PLATFORMS.includes(hostname);
  } catch {
    return false;
  }
}

function isPresentationMode() {
  const fsEl = document.fullscreenElement;
  if (!fsEl) return false;

  const classList = [...(fsEl.classList || [])].join(' ');
  return PRESENTATION_CLASS_PATTERNS.some(pattern => pattern.test(classList));
}

// ---------------------------------------------------------------------------
// Telemetry emitter
// ---------------------------------------------------------------------------

function sendToBackground(payload) {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'FULLSCREENGUARD_EVENT',
        payload,
      });
    }
  } catch (err) {
    console.error('[FULLSCREEN_GUARD] sendToBackground failed:', err);
  }
}

// ---------------------------------------------------------------------------
// Main runner (exported for unit testing)
// ---------------------------------------------------------------------------

export function runFullscreenGuard() {
  // Track user gestures
  document.addEventListener('click', trackGesture, true);
  document.addEventListener('keydown', trackGesture, true);

  document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) return;

    // False positive suppression
    if (isVideoFullscreen() || isVideoPlatform() || isPresentationMode()) return;

    // Immediate signals
    const gestureSignals = checkFullscreenGestureSignal();
    const targetSignals = checkFullscreenTargetSignals();
    const credentialSignals = checkCredentialFieldVisibility();

    const immediateSignals = [...gestureSignals, ...targetSignals, ...credentialSignals];

    // If no immediate signals, set up mutation observer for post-fullscreen changes
    // If immediate signals already exceed threshold, act now
    const { riskScore: immediateScore } = calculateFullscreenRiskScore(immediateSignals);

    if (immediateScore >= EXIT_THRESHOLD) {
      handleDetection(immediateSignals);
      return;
    }

    // Watch for post-fullscreen mutations (overlay creation, opacity changes)
    const observer = new MutationObserver((mutations) => {
      const mutationSignals = checkPostFullscreenMutations(mutations);
      const allSignals = [...immediateSignals, ...mutationSignals];
      const { riskScore } = calculateFullscreenRiskScore(allSignals);

      if (riskScore >= ALERT_THRESHOLD) {
        observer.disconnect();
        handleDetection(allSignals);
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'class'],
    });

    // Stop observing after MUTATION_WATCH_MS
    setTimeout(() => {
      observer.disconnect();
    }, MUTATION_WATCH_MS);

    // If immediate signals already meet alert threshold
    if (immediateScore >= ALERT_THRESHOLD) {
      handleDetection(immediateSignals);
    }
  });
}

function handleDetection(signals) {
  const { riskScore, signalList } = calculateFullscreenRiskScore(signals);

  const telemetry = {
    eventType: 'FULLSCREEN_BITM_OVERLAY',
    riskScore,
    severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium',
    fullscreenTarget: document.fullscreenElement?.tagName || 'unknown',
    signals: signalList,
    url: window.location.href.substring(0, 200),
    timestamp: new Date().toISOString(),
  };

  if (riskScore >= EXIT_THRESHOLD) {
    telemetry.action = 'exited_fullscreen';
    try {
      document.exitFullscreen?.();
    } catch {
      // Best effort
    }
  }

  sendToBackground(telemetry);
  injectFullscreenWarningBanner(riskScore, signalList);
}

// ---------------------------------------------------------------------------
// Auto-run when injected as a content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  runFullscreenGuard();
}
