/**
 * extension/content/canvas_keystroke_guard_main.js
 *
 * CanvasKeystrokeGuard — MAIN World API Interceptor
 *
 * Runs in the MAIN world at document_start to wrap browser prototypes before
 * page scripts cache references. Detects keyboard event listeners attached
 * to <canvas> elements and tracks canvas context type creation.
 *
 * MAIN world scripts cannot access chrome.* APIs. All observations are
 * forwarded via window.postMessage() to the isolated-world bridge script
 * (canvas_keystroke_guard_bridge.js) which relays to the service worker.
 *
 * Message source identifier: 'PHISHOPS_CKG'
 *
 * @module CanvasKeystrokeGuardMain
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

(function() {
  const SOURCE = 'PHISHOPS_CKG';
  const sk = globalThis.__PHISHOPS_STEALTH;

  const KEYBOARD_EVENTS = new Set(['keydown', 'keypress', 'keyup', 'input']);

  /* ------------------------------------------------------------------ */
  /*  Wrap EventTarget.prototype.addEventListener                        */
  /* ------------------------------------------------------------------ */

  if (sk) {
    sk.stealthWrapProto(EventTarget.prototype, 'addEventListener',
      (target, thisArg, args) => {
        const [eventType] = args;
        if (
          thisArg instanceof HTMLCanvasElement &&
          typeof eventType === 'string' &&
          KEYBOARD_EVENTS.has(eventType)
        ) {
          try {
            window.postMessage({
              source: SOURCE,
              type: 'CANVAS_KEYBOARD_LISTENER',
              data: {
                eventType,
                canvasIndex: getCanvasIndex(thisArg),
                canvasWidth: thisArg.width || 0,
                canvasHeight: thisArg.height || 0,
                timestamp: Date.now(),
              },
            }, '*');
          } catch { /* non-critical */ }
        }
        return sk.apply(target, thisArg, args);
      }
    );

    /* ------------------------------------------------------------------ */
    /*  Wrap HTMLCanvasElement.prototype.getContext                         */
    /* ------------------------------------------------------------------ */

    sk.stealthWrapProto(HTMLCanvasElement.prototype, 'getContext',
      (target, thisArg, args) => {
        const [contextType] = args;
        if (typeof contextType === 'string') {
          try {
            window.postMessage({
              source: SOURCE,
              type: 'CANVAS_CONTEXT_CREATED',
              data: {
                contextType,
                canvasIndex: getCanvasIndex(thisArg),
                canvasWidth: thisArg.width || 0,
                canvasHeight: thisArg.height || 0,
                timestamp: Date.now(),
              },
            }, '*');
          } catch { /* non-critical */ }
        }
        return sk.apply(target, thisArg, args);
      }
    );
  } else {
    // Fallback: naive wrapping if StealthKit not loaded
    const origAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(eventType, listener, options) {
      if (
        this instanceof HTMLCanvasElement &&
        typeof eventType === 'string' &&
        KEYBOARD_EVENTS.has(eventType)
      ) {
        try {
          window.postMessage({
            source: SOURCE,
            type: 'CANVAS_KEYBOARD_LISTENER',
            data: {
              eventType,
              canvasIndex: getCanvasIndex(this),
              canvasWidth: this.width || 0,
              canvasHeight: this.height || 0,
              timestamp: Date.now(),
            },
          }, '*');
        } catch { /* non-critical */ }
      }
      return origAddEventListener.call(this, eventType, listener, options);
    };

    const origGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(contextType) {
      if (typeof contextType === 'string') {
        try {
          window.postMessage({
            source: SOURCE,
            type: 'CANVAS_CONTEXT_CREATED',
            data: {
              contextType,
              canvasIndex: getCanvasIndex(this),
              canvasWidth: this.width || 0,
              canvasHeight: this.height || 0,
              timestamp: Date.now(),
            },
          }, '*');
        } catch { /* non-critical */ }
      }
      return origGetContext.apply(this, arguments);
    };
  }

  /* ------------------------------------------------------------------ */
  /*  Helpers                                                            */
  /* ------------------------------------------------------------------ */

  /**
   * Return the index of a canvas element among all canvases on the page.
   * Falls back to -1 if the DOM isn't ready yet.
   */
  function getCanvasIndex(canvas) {
    try {
      const all = document.querySelectorAll('canvas');
      for (let i = 0; i < all.length; i++) {
        if (all[i] === canvas) return i;
      }
    } catch { /* DOM may not be ready at document_start */ }
    return -1;
  }
})();

})();
