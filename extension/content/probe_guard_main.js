/**
 * extension/content/probe_guard_main.js
 *
 * ProbeGuard — MAIN World Security Tool Probing Detector
 *
 * Runs in the MAIN world at document_start to detect pages probing for the
 * presence of security browser extensions. Monitors toString reflection on
 * security-sensitive APIs, iframe cross-frame verification, timing-based
 * microbenchmarking, WAR extension fingerprinting, and CreepJS-style
 * prototype lie detection.
 *
 * Uses StealthKit (globalThis.__PHISHOPS_STEALTH) for all API wrapping.
 * Forwards signals via window.postMessage() to the isolated-world bridge
 * (probe_guard_bridge.js).
 *
 * Message source identifier: 'PHISHOPS_PG'
 *
 * @module ProbeGuardMain
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

(function() {
  const SOURCE = 'PHISHOPS_PG';
  const sk = globalThis.__PHISHOPS_STEALTH;

  if (!sk) {
    // StealthKit not loaded — cannot operate
    return;
  }

  /* ------------------------------------------------------------------ */
  /*  Signal state tracking                                              */
  /* ------------------------------------------------------------------ */

  /** toString probe counter: security API toString calls within window */
  const toStringProbes = { count: 0, firstTs: 0 };
  const TOSTRING_THRESHOLD = 3;
  const TOSTRING_WINDOW_MS = 5000;

  /** iframe verification tracking */
  const iframeProbes = new WeakMap(); // iframe → creation timestamp

  /** performance.now() timing loop detection */
  const perfNowState = { calls: [], windowMs: 200, threshold: 50 };

  /** WAR probing tracking */
  let warProbeCount = 0;

  /** Prototype lie detection tracking */
  let protoLieCount = 0;

  /* ------------------------------------------------------------------ */
  /*  Helper: send signal to bridge                                      */
  /* ------------------------------------------------------------------ */

  function emitSignal(signalId, detail) {
    try {
      window.postMessage({
        source: SOURCE,
        type: 'PROBE_SIGNAL',
        data: {
          signalId,
          detail,
          timestamp: Date.now(),
        },
      }, '*');
    } catch { /* non-critical */ }
  }

  /* ------------------------------------------------------------------ */
  /*  Signal 1: toString probing on security APIs (0.40)                 */
  /* ------------------------------------------------------------------ */

  // Register the probe callback with StealthKit's patchToString.
  // This fires whenever toString is called on a security-API function.
  sk.patchToString({
    onProbe: function(fn) {
      const now = Date.now();
      if (now - toStringProbes.firstTs > TOSTRING_WINDOW_MS) {
        toStringProbes.count = 0;
        toStringProbes.firstTs = now;
      }
      toStringProbes.count++;

      if (toStringProbes.count >= TOSTRING_THRESHOLD) {
        emitSignal('probe:tostring_on_security_api', {
          count: toStringProbes.count,
          windowMs: now - toStringProbes.firstTs,
        });
        // Reset to avoid repeated signals
        toStringProbes.count = 0;
        toStringProbes.firstTs = 0;
      }
    },
  });

  // Register well-known security APIs for probe monitoring.
  // These are the APIs that phishing kits most likely toString-check.
  const securityApiRefs = [];
  try { securityApiRefs.push(window.fetch); } catch { /* may not exist */ }
  try { securityApiRefs.push(window.WebSocket); } catch { /* may not exist */ }
  try { securityApiRefs.push(XMLHttpRequest.prototype.open); } catch { /* */ }
  try { securityApiRefs.push(navigator.credentials.create); } catch { /* */ }
  try { securityApiRefs.push(navigator.credentials.get); } catch { /* */ }
  try { securityApiRefs.push(window.eval); } catch { /* */ }
  try { securityApiRefs.push(window.Notification); } catch { /* */ }
  try { securityApiRefs.push(navigator.clipboard.writeText); } catch { /* */ }

  securityApiRefs.forEach(fn => {
    if (typeof fn === 'function') sk.registerSecurityApi(fn);
  });

  /* ------------------------------------------------------------------ */
  /*  Signal 2: iframe cross-frame function verification (0.30)          */
  /* ------------------------------------------------------------------ */

  sk.stealthWrap(document, 'createElement', (target, thisArg, args) => {
    const el = sk.apply(target, thisArg, args);

    if (typeof args[0] === 'string' && args[0].toLowerCase() === 'iframe') {
      const creationTs = Date.now();
      iframeProbes.set(el, creationTs);

      // Wrap contentWindow accessor to detect cross-frame verification
      try {
        const origDesc = Object.getOwnPropertyDescriptor(
          HTMLIFrameElement.prototype, 'contentWindow'
        );
        if (origDesc && origDesc.get) {
          const origGet = origDesc.get;
          Object.defineProperty(el, 'contentWindow', {
            get: function() {
              const cw = origGet.call(this);
              if (cw) {
                const elapsed = Date.now() - creationTs;
                if (elapsed < 2000) {
                  // Wrap the contentWindow's Function.prototype.toString access
                  try {
                    const origCwToString = cw.Function.prototype.toString;
                    Object.defineProperty(cw.Function.prototype, 'toString', {
                      get: function() {
                        emitSignal('probe:iframe_function_verification', {
                          elapsedMs: Date.now() - creationTs,
                        });
                        return origCwToString;
                      },
                      configurable: true,
                    });
                  } catch { /* cross-origin or sandboxed — expected */ }
                }
              }
              return cw;
            },
            configurable: true,
          });
        }
      } catch { /* non-critical */ }
    }

    return el;
  });

  /* ------------------------------------------------------------------ */
  /*  Signal 3: timing loop on APIs (0.25)                               */
  /* ------------------------------------------------------------------ */

  if (typeof performance !== 'undefined' && typeof performance.now === 'function') {
    sk.stealthWrap(performance, 'now', (target, thisArg, args) => {
      const result = sk.apply(target, thisArg, args);

      const now = Date.now();
      const state = perfNowState;
      // Trim calls outside the window
      while (state.calls.length > 0 && now - state.calls[0] > state.windowMs) {
        state.calls.shift();
      }
      state.calls.push(now);

      if (state.calls.length >= state.threshold) {
        emitSignal('probe:timing_loop_on_api', {
          callCount: state.calls.length,
          windowMs: state.windowMs,
        });
        state.calls.length = 0; // Reset to avoid flooding
      }

      return result;
    });
  }

  /* ------------------------------------------------------------------ */
  /*  Signal 4: WAR extension probing (0.20)                             */
  /* ------------------------------------------------------------------ */

  const EXTENSION_URL_RE = /^(?:chrome-extension|moz-extension):\/\//i;

  sk.stealthWrap(window, 'fetch', (target, thisArg, args) => {
    const url = args[0];
    if (typeof url === 'string' && EXTENSION_URL_RE.test(url)) {
      warProbeCount++;
      emitSignal('probe:war_extension_probing', {
        url: url.substring(0, 120),
        count: warProbeCount,
      });
    } else if (url && typeof url === 'object' && url.url && EXTENSION_URL_RE.test(url.url)) {
      warProbeCount++;
      emitSignal('probe:war_extension_probing', {
        url: url.url.substring(0, 120),
        count: warProbeCount,
      });
    }
    return sk.apply(target, thisArg, args);
  }, { securityApi: true });

  sk.stealthWrapProto(XMLHttpRequest.prototype, 'open', (target, thisArg, args) => {
    const url = args[1];
    if (typeof url === 'string' && EXTENSION_URL_RE.test(url)) {
      warProbeCount++;
      emitSignal('probe:war_extension_probing', {
        url: url.substring(0, 120),
        count: warProbeCount,
      });
    }
    return sk.apply(target, thisArg, args);
  }, { securityApi: true });

  /* ------------------------------------------------------------------ */
  /*  Signal 5: prototype lie detection — CreepJS patterns (0.15)        */
  /* ------------------------------------------------------------------ */

  const origGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const origGetOwnPropertyNames = Object.getOwnPropertyNames;

  sk.stealthWrap(Object, 'getOwnPropertyDescriptor', (target, thisArg, args) => {
    const [obj, prop] = args;
    // Detect inspection of Function.prototype.toString descriptor
    if (obj === Function.prototype && prop === 'toString') {
      protoLieCount++;
      emitSignal('probe:prototype_lie_detection', {
        pattern: 'getOwnPropertyDescriptor(Function.prototype, "toString")',
        count: protoLieCount,
      });
    }
    return sk.apply(target, thisArg, args);
  });

  sk.stealthWrap(Object, 'getOwnPropertyNames', (target, thisArg, args) => {
    const [obj] = args;
    // Detect enumeration of Function.prototype properties
    if (obj === Function.prototype) {
      protoLieCount++;
      emitSignal('probe:prototype_lie_detection', {
        pattern: 'getOwnPropertyNames(Function.prototype)',
        count: protoLieCount,
      });
    }
    return sk.apply(target, thisArg, args);
  });

  /* ------------------------------------------------------------------ */
  /*  Test-only accessors                                                */
  /* ------------------------------------------------------------------ */

  if (typeof globalThis.__PHISHOPS_PG_TEST === 'undefined') {
    globalThis.__PHISHOPS_PG_TEST = Object.freeze({
      _getToStringProbes() { return { ...toStringProbes }; },
      _getWarProbeCount() { return warProbeCount; },
      _getProtoLieCount() { return protoLieCount; },
      _getPerfNowState() { return { ...perfNowState, calls: [...perfNowState.calls] }; },
      _resetState() {
        toStringProbes.count = 0;
        toStringProbes.firstTs = 0;
        warProbeCount = 0;
        protoLieCount = 0;
        perfNowState.calls.length = 0;
      },
    });
  }
})();

})();
