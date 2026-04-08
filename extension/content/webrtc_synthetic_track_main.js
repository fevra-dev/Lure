/**
 * extension/content/webrtc_synthetic_track_main.js
 *
 * WebRTC Deepfake Sentinel — MAIN world constructor interception.
 *
 * Wave 25. Wraps MediaStreamTrackGenerator, MediaStreamTrackProcessor,
 * VideoTrackGenerator, and RTCPeerConnection.addTrack to detect synthetic
 * video tracks injected into WebRTC calls — the forensically stealthy
 * alternative to OBS Virtual Camera (no enumerateDevices() entry, no
 * system-level device registration, no process footprint).
 *
 * Attack chain: camera → MediaStreamTrackProcessor (frame decompose) →
 *   deepfake transform (server-relayed or future client-side WebGPU) →
 *   MediaStreamTrackGenerator (synthetic track) → addTrack → peer
 *
 * MITRE ATT&CK T1566.003 — Phishing: Spearphishing via Service
 *
 * References:
 *   - Arup $25.6M deepfake wire transfer (Jan 2024)
 *   - Scattered Spider AI-assisted impersonation (CISA/FBI July 2025)
 *   - FinCEN Alert FIN-2024-Alert004: webcam plugin SAR filing keyword
 */

'use strict';

// ---------------------------------------------------------------------------
// Signal weights
// ---------------------------------------------------------------------------

const SIGNAL_WEIGHTS = {
  'webrtc:track_generator_created': 0.30,
  'webrtc:track_processor_created': 0.20,
  'webrtc:synthetic_track_added_to_peerconnection': 0.40,
  'webrtc:getuseromedia_plus_synthetic_pipeline': 0.50,
  'webrtc:ml_model_fetch_detected': 0.20,
  'webrtc:video_track_generator_created': 0.30,
};

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const VIDEO_CONFERENCING_DOMAINS = [
  'zoom.us', 'meet.google.com', 'teams.microsoft.com', 'webex.com',
  'discord.com', 'whereby.com', 'gather.town', 'bluejeans.com',
  'gotomeeting.com', 'streamyard.com',
];

const ML_MODEL_PATTERNS = [
  /\.onnx$/i, /\.tflite$/i, /model\.json$/i,
  /shard\d+of\d+\.bin$/i, /ort-wasm.*\.wasm$/i,
];

// ---------------------------------------------------------------------------
// Exported pure functions (testable without DOM/chrome context)
// ---------------------------------------------------------------------------

/**
 * Compute additive risk score from signal IDs.
 * @param {string[]} signals
 * @returns {{ riskScore: number, signalList: string[] }}
 */
function computeSyntheticTrackRiskScore(signals) {
  const score = signals.reduce((sum, s) => sum + (SIGNAL_WEIGHTS[s] ?? 0), 0);
  return {
    riskScore: Math.round(Math.min(score, 1.0) * 100) / 100,
    signalList: signals,
  };
}

/**
 * Returns true if a MediaStreamTrack appears to be synthetically generated.
 * Synthetic tracks: no deviceId in settings, and no displaySurface (screen share).
 * @param {{ label: string, getSettings?: () => object } | null} track
 * @returns {boolean}
 */
function isSyntheticTrack(track) {
  if (!track) return false;
  try {
    const settings = track.getSettings?.() ?? {};
    if (settings.displaySurface) return false; // Screen share exclusion
    if (settings.deviceId) return false;       // Real camera with deviceId
  } catch { /* ignore */ }
  return true;
}

/**
 * Check if a hostname is a known first-party video conferencing platform.
 * @param {string} hostname
 * @returns {boolean}
 */
function isVideoConferencingDomain(hostname) {
  if (!hostname) return false;
  return VIDEO_CONFERENCING_DOMAINS.some(
    p => hostname === p || hostname.endsWith('.' + p),
  );
}

// ---------------------------------------------------------------------------
// MAIN world runtime — only active when injected as content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  (() => {
    const hostname = window.location.hostname.replace(/^www\./, '');
    if (isVideoConferencingDomain(hostname)) return;

    const state = {
      generatorCreated: false,
      processorCreated: false,
      getUserMediaCalled: false,
      signals: new Set(),
    };

    function dispatchSignal(signalId) {
      state.signals.add(signalId);
      const { riskScore } = computeSyntheticTrackRiskScore([...state.signals]);
      if (riskScore < ALERT_THRESHOLD) return;

      window.dispatchEvent(new CustomEvent('PHISHOPS_WEBRTC_SYNTHETIC', {
        detail: {
          signals: [...state.signals],
          riskScore,
          severity: riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium',
        },
      }));
    }

    // Wrap MediaStreamTrackGenerator
    if (window.MediaStreamTrackGenerator) {
      const Orig = window.MediaStreamTrackGenerator;
      window.MediaStreamTrackGenerator = new Proxy(Orig, {
        construct(target, args) {
          const instance = Reflect.construct(target, args);
          state.generatorCreated = true;
          dispatchSignal('webrtc:track_generator_created');
          if (state.processorCreated && state.getUserMediaCalled) {
            dispatchSignal('webrtc:getuseromedia_plus_synthetic_pipeline');
          }
          return instance;
        },
      });
    }

    // Wrap MediaStreamTrackProcessor
    if (window.MediaStreamTrackProcessor) {
      const Orig = window.MediaStreamTrackProcessor;
      window.MediaStreamTrackProcessor = new Proxy(Orig, {
        construct(target, args) {
          const instance = Reflect.construct(target, args);
          state.processorCreated = true;
          dispatchSignal('webrtc:track_processor_created');
          if (state.generatorCreated && state.getUserMediaCalled) {
            dispatchSignal('webrtc:getuseromedia_plus_synthetic_pipeline');
          }
          return instance;
        },
      });
    }

    // Wrap VideoTrackGenerator (W3C standard, Safari 18+)
    if (window.VideoTrackGenerator) {
      const Orig = window.VideoTrackGenerator;
      window.VideoTrackGenerator = new Proxy(Orig, {
        construct(target, args) {
          const instance = Reflect.construct(target, args);
          state.generatorCreated = true;
          dispatchSignal('webrtc:video_track_generator_created');
          return instance;
        },
      });
    }

    // Wrap RTCPeerConnection.addTrack
    if (window.RTCPeerConnection?.prototype?.addTrack) {
      const origAddTrack = window.RTCPeerConnection.prototype.addTrack;
      window.RTCPeerConnection.prototype.addTrack = function(track, ...streams) {
        if (track?.kind === 'video' && isSyntheticTrack(track) && state.generatorCreated) {
          dispatchSignal('webrtc:synthetic_track_added_to_peerconnection');
        }
        return origAddTrack.call(this, track, ...streams);
      };
    }

    // Track getUserMedia calls for compound signal
    if (navigator.mediaDevices?.getUserMedia) {
      const origGUM = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = function(constraints) {
        if (constraints?.video) {
          state.getUserMediaCalled = true;
          if (state.generatorCreated && state.processorCreated) {
            dispatchSignal('webrtc:getuseromedia_plus_synthetic_pipeline');
          }
        }
        return origGUM(constraints);
      };
    }

    // Monitor fetch for ML model patterns
    const origFetch = window.fetch;
    window.fetch = function(input, init) {
      try {
        const url = typeof input === 'string' ? input : input?.url ?? '';
        if (ML_MODEL_PATTERNS.some(re => re.test(url))) {
          dispatchSignal('webrtc:ml_model_fetch_detected');
        }
      } catch { /* non-critical */ }
      return origFetch.call(this, input, init);
    };
  })();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['webrtc_synthetic_track_main'] = {
    VIDEO_CONFERENCING_DOMAINS,
    computeSyntheticTrackRiskScore,
    isSyntheticTrack,
    isVideoConferencingDomain,
  };
}
