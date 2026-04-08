/**
 * extension/content/webrtc_synthetic_track_bridge.js
 *
 * WebRTC Deepfake Sentinel — ISOLATED world bridge.
 * Relays PHISHOPS_WEBRTC_SYNTHETIC CustomEvents from MAIN world to service worker.
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  window.addEventListener('PHISHOPS_WEBRTC_SYNTHETIC', (event) => {
    const { signals, riskScore, severity } = event.detail ?? {};
    if (!signals?.length) return;

    try {
      chrome.runtime.sendMessage({
        type: 'WEBRTC_SYNTHETIC_TRACK_EVENT',
        payload: {
          eventType: 'WEBRTC_SYNTHETIC_TRACK_DETECTED',
          riskScore,
          severity,
          signals,
          url: window.location.href.substring(0, 200),
          timestamp: new Date().toISOString(),
        },
      });
    } catch (err) {
      console.error('[WEBRTC_SYNTHETIC] bridge sendMessage failed:', err);
    }
  });
}

})();
