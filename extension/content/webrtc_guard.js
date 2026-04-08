/**
 * extension/content/webrtc_guard.js
 *
 * WebRTCGuard — Detects virtual camera injection into WebRTC streams.
 * Injected at document_start to wrap navigator.mediaDevices.getUserMedia
 * before attacker code can cache a reference to the original API.
 *
 * Attack chain this closes:
 *   Real-time deepfake video injected via virtual camera software (OBS Virtual
 *   Camera, VCAMSX, Camo, ManyCam). Attacker uses AI voice clone + virtual
 *   camera to impersonate executives on video calls, requesting wire transfers
 *   or credential disclosure. The browser has zero native defenses.
 *   PhishOps operates on the sender's browser, checking the camera source
 *   before video transmission begins.
 *
 * Detection model: Additive signal scoring across device and stream analysis:
 *   1. Virtual camera label  — device label matches known virtual camera patterns
 *   2. Fast constraint resp  — applyConstraints resolves too fast for real hardware
 *   3. Arbitrary resolution  — continuous resolution range vs discrete hardware steps
 *   4. Low frame jitter     — unnaturally consistent frame timing
 *   5. No user gesture      — getUserMedia called without recent interaction
 *   6. Suspicious context   — page text suggests identity verification on non-platform
 *
 * References:
 *   - Hong Kong CFO deepfake ($25M loss, Jan 2024)
 *   - arxiv 2512.10653: timing-heuristic VCD in WebRTC context
 *   - MITRE ATT&CK T1566.003 (Phishing: Spearphishing via Service)
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;
const GESTURE_WINDOW_MS = 1000;

const VIRTUAL_CAMERA_PATTERNS = [
  'obs virtual camera',
  'vcamsx',
  'camo',
  'manycam',
  'snap camera',
  'virtual camera',
  'xsplit vcam',
  'chromacam',
  'camtwist',
  'vmix video',
  'e2esoft vcam',
  'sparkocam',
  'splitcam',
];

const KNOWN_VIDEO_PLATFORMS = [
  'zoom.us', 'meet.google.com', 'teams.microsoft.com', 'webex.com',
  'discord.com', 'whereby.com', 'gather.town',
  'twitch.tv', 'youtube.com', 'streamyard.com', 'restream.io',
];

const IDENTITY_VERIFICATION_PATTERNS = [
  'identity verification',
  'verify your identity',
  'biometric check',
  'face verification',
  'liveness check',
  'selfie verification',
];

// ---------------------------------------------------------------------------
// User gesture tracking
// ---------------------------------------------------------------------------

let lastGestureTimestamp = 0;

function trackGesture() {
  lastGestureTimestamp = Date.now();
}

// Exported for testing — allows tests to set gesture time
function _setLastGestureTimestamp(ts) {
  lastGestureTimestamp = ts;
}

// ---------------------------------------------------------------------------
// Signal checks (exported for unit testing)
// ---------------------------------------------------------------------------

/**
 * Check virtual camera signals from device list and stream characteristics.
 *
 * @param {MediaDeviceInfo[]} devices - Result of enumerateDevices()
 * @param {object} [streamInfo] - Optional stream timing info
 * @param {number} [streamInfo.constraintResponseMs] - applyConstraints timing
 * @param {number} [streamInfo.frameJitterStddev] - Frame timing stddev in ms
 * @param {boolean} [streamInfo.arbitraryResolution] - Continuous vs discrete resolution
 * @returns {{ id: string, weight: number }[]}
 */
function checkVirtualCameraSignals(devices, streamInfo) {
  const signals = [];

  // Signal 1: Virtual camera device label
  if (Array.isArray(devices)) {
    for (const device of devices) {
      if (device.kind !== 'videoinput') continue;
      const label = (device.label || '').toLowerCase();
      if (!label) continue;

      const isVirtual = VIRTUAL_CAMERA_PATTERNS.some(pattern => label.includes(pattern));
      if (isVirtual) {
        signals.push({ id: 'webrtc:virtual_camera_label', weight: 0.45 });
        break;
      }
    }
  }

  // Signal 2: Fast constraint response (<15ms = likely virtual)
  if (streamInfo?.constraintResponseMs != null && streamInfo.constraintResponseMs < 15) {
    signals.push({ id: 'webrtc:fast_constraint_response', weight: 0.30 });
  }

  // Signal 3: Arbitrary resolution (continuous range)
  if (streamInfo?.arbitraryResolution === true) {
    signals.push({ id: 'webrtc:arbitrary_resolution', weight: 0.20 });
  }

  // Signal 4: Low frame jitter (<0.5ms stddev)
  if (streamInfo?.frameJitterStddev != null && streamInfo.frameJitterStddev < 0.5) {
    signals.push({ id: 'webrtc:low_frame_jitter', weight: 0.25 });
  }

  // Signal 5: No user gesture
  const timeSinceGesture = Date.now() - lastGestureTimestamp;
  if (timeSinceGesture > GESTURE_WINDOW_MS) {
    signals.push({ id: 'webrtc:no_user_gesture', weight: 0.25 });
  }

  return signals;
}

/**
 * Check page context for identity verification signals.
 * @returns {{ id: string, weight: number }[]}
 */
function checkWebRTCPageContext() {
  const signals = [];

  try {
    const hostname = window.location.hostname;

    // Skip known video platforms
    const isKnownPlatform = KNOWN_VIDEO_PLATFORMS.some(
      p => hostname === p || hostname.endsWith('.' + p),
    );
    if (isKnownPlatform) return signals;

    // Skip localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1') return signals;

    const pageText = (document.body?.innerText || document.body?.textContent || '').toLowerCase();

    const hasVerificationText = IDENTITY_VERIFICATION_PATTERNS.some(
      pattern => pageText.includes(pattern),
    );

    if (hasVerificationText) {
      signals.push({ id: 'webrtc:suspicious_page_context', weight: 0.20 });
    }
  } catch {
    // Page context check is non-critical
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Risk score calculation (exported for unit testing)
// ---------------------------------------------------------------------------

function calculateWebRTCRiskScore(signals) {
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

function injectWebRTCWarningBanner(riskScore, deviceLabel, signals) {
  if (document.getElementById('phishops-webrtc-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-webrtc-warning';
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
        virtual camera detected \u2014 phishops webrtcguard
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        A virtual camera device was detected on this page.
        Device: <code style="color:#BF1B1B;">${(deviceLabel || 'unknown').substring(0, 100)}</code>.
        Risk score: ${riskScore.toFixed(2)}.
      </span>
    </div>
    <button id="phishops-webrtc-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-webrtc-dismiss')?.addEventListener('click', () => {
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
        type: 'WEBRTCGUARD_EVENT',
        payload,
      });
    }
  } catch (err) {
    console.error('[WEBRTC_GUARD] sendToBackground failed:', err);
  }
}

// ---------------------------------------------------------------------------
// getUserMedia interceptor (exported for unit testing)
// ---------------------------------------------------------------------------

function installGetUserMediaInterceptor() {
  // Track user gestures
  document.addEventListener('click', trackGesture, true);
  document.addEventListener('keydown', trackGesture, true);

  if (!navigator.mediaDevices?.getUserMedia) return;

  const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  const originalEnumerateDevices = navigator.mediaDevices.enumerateDevices?.bind(navigator.mediaDevices);

  async function wrappedGetUserMedia(constraints) {
    // Only analyze if video is requested
    if (!constraints?.video) {
      return originalGetUserMedia(constraints);
    }

    // Get stream first — we do NOT block
    const stream = await originalGetUserMedia(constraints);

    // Async analysis — does not delay the stream
    try {
      const devices = originalEnumerateDevices ? await originalEnumerateDevices() : [];

      // Gather stream info for supplementary signals
      const streamInfo = {};

      // Check constraint response timing
      const videoTrack = stream.getVideoTracks()[0];
      if (videoTrack?.applyConstraints) {
        const start = performance.now();
        try {
          await videoTrack.applyConstraints(videoTrack.getConstraints());
          streamInfo.constraintResponseMs = performance.now() - start;
        } catch {
          // Constraint check is supplementary
        }
      }

      // Check capabilities for arbitrary resolution
      if (videoTrack?.getCapabilities) {
        try {
          const caps = videoTrack.getCapabilities();
          if (caps.width && caps.height) {
            // Discrete hardware cameras report step values; virtual cameras report continuous
            const hasSteps = (caps.width.step && caps.width.step > 1) ||
                             (caps.height.step && caps.height.step > 1);
            streamInfo.arbitraryResolution = !hasSteps;
          }
        } catch {
          // Capability check is supplementary
        }
      }

      const cameraSignals = checkVirtualCameraSignals(devices, streamInfo);
      const pageSignals = checkWebRTCPageContext();
      const allSignals = [...cameraSignals, ...pageSignals];
      const { riskScore, signalList } = calculateWebRTCRiskScore(allSignals);

      // Find the device label for the active track
      const activeLabel = videoTrack?.label || '';

      if (riskScore >= ALERT_THRESHOLD) {
        const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';

        sendToBackground({
          eventType: 'WEBRTC_VIRTUAL_CAMERA_DETECTED',
          riskScore,
          severity,
          deviceLabel: activeLabel.substring(0, 100),
          signals: signalList,
          url: window.location.href.substring(0, 200),
          timestamp: new Date().toISOString(),
          action: 'alerted',
        });

        injectWebRTCWarningBanner(riskScore, activeLabel, signalList);
      }
    } catch {
      // Analysis failure must not break the stream
    }

    return stream;
  }

  try {
    Object.defineProperty(navigator.mediaDevices, 'getUserMedia', {
      value: wrappedGetUserMedia,
      writable: false,
      configurable: true,
    });
  } catch {
    navigator.mediaDevices.getUserMedia = wrappedGetUserMedia;
  }
}

// ---------------------------------------------------------------------------
// Auto-run when injected as a content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installGetUserMediaInterceptor();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['webrtc_guard'] = {
    _setLastGestureTimestamp,
    checkVirtualCameraSignals,
    checkWebRTCPageContext,
    calculateWebRTCRiskScore,
    injectWebRTCWarningBanner,
    installGetUserMediaInterceptor,
  };
}
