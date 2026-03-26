/**
 * extension/content/payment_request_guard_main.js
 *
 * PaymentRequestGuard — MAIN World Constructor Interceptor
 *
 * Runs in the MAIN world at document_start to wrap the PaymentRequest
 * constructor and .show() method before page scripts can cache references.
 * Detects Payment Request API usage as a low-confidence, high-specificity
 * supplementary phishing signal.
 *
 * MAIN world scripts cannot access chrome.* APIs. All observations are
 * forwarded via window.postMessage() to the isolated-world bridge script
 * (payment_request_guard_bridge.js) which relays to the service worker.
 *
 * Message source identifier: 'PHISHOPS_PRG'
 *
 * @module PaymentRequestGuardMain
 */

'use strict';

(function() {
  if (typeof window.PaymentRequest === 'undefined') return;

  const SOURCE = 'PHISHOPS_PRG';
  const sk = globalThis.__PHISHOPS_STEALTH;
  const OriginalPR = window.PaymentRequest;

  /* ------------------------------------------------------------------ */
  /*  Wrap PaymentRequest constructor                                    */
  /* ------------------------------------------------------------------ */

  function emitCreation(methods, options) {
    try {
      window.postMessage({
        source: SOURCE,
        type: 'PAYMENT_REQUEST_CREATED',
        data: {
          methods: JSON.stringify(methods),
          requestsName: !!options?.requestPayerName,
          requestsEmail: !!options?.requestPayerEmail,
          requestsPhone: !!options?.requestPayerPhone,
          requestsShipping: !!options?.requestShipping,
          timestamp: Date.now(),
        },
      }, '*');
    } catch { /* non-critical */ }
  }

  if (sk) {
    const wrappedPR = function PaymentRequest(methods, details, options) {
      emitCreation(methods, options);
      return sk.apply(OriginalPR, this, [methods, details, options]);
    };
    wrappedPR.prototype = OriginalPR.prototype;
    sk.patchToString(wrappedPR, OriginalPR);
    window.PaymentRequest = wrappedPR;
  } else {
    window.PaymentRequest = function PaymentRequest(methods, details, options) {
      emitCreation(methods, options);
      return new OriginalPR(methods, details, options);
    };
    window.PaymentRequest.prototype = OriginalPR.prototype;
  }

  /* ------------------------------------------------------------------ */
  /*  Wrap PaymentRequest.prototype.show                                 */
  /* ------------------------------------------------------------------ */

  function emitShow() {
    try {
      window.postMessage({
        source: SOURCE,
        type: 'PAYMENT_REQUEST_SHOW',
        data: { timestamp: Date.now() },
      }, '*');
    } catch { /* non-critical */ }
  }

  if (sk) {
    sk.stealthWrapProto(PaymentRequest.prototype, 'show',
      (target, thisArg, args) => {
        emitShow();
        return sk.apply(target, thisArg, args);
      }
    );
  } else {
    const origShow = OriginalPR.prototype.show;
    PaymentRequest.prototype.show = function(...args) {
      emitShow();
      return origShow.apply(this, args);
    };
  }
})();
