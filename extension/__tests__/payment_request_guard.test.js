/**
 * extension/__tests__/payment_request_guard.test.js
 *
 * Tests for PaymentRequestGuard — Payment Request API Phishing Detection
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import {
  checkPaymentRequestCreated,
  checkPiiFieldsRequested,
  checkShowInvoked,
  checkNoEstablishedMerchant,
  checkLoginContextWithPayment,
  calculatePrgRiskScore,
  injectPrgWarningBanner,
  hasLoginContext,
  hasMerchantMarkers,
  runPrgAnalysis,
} from '../content/payment_request_guard_bridge.js';

function makeDoc(html = '<html><head></head><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

function makeCreationRecord(opts = {}) {
  return {
    methods: opts.methods || '[{"supportedMethods":"https://google.com/pay"}]',
    requestsName: opts.requestsName ?? false,
    requestsEmail: opts.requestsEmail ?? false,
    requestsPhone: opts.requestsPhone ?? false,
    requestsShipping: opts.requestsShipping ?? false,
    timestamp: opts.timestamp || Date.now(),
  };
}

function makeShowRecord(opts = {}) {
  return {
    timestamp: opts.timestamp || Date.now(),
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

/* ================================================================== */
/*  checkPaymentRequestCreated                                         */
/* ================================================================== */

describe('checkPaymentRequestCreated', () => {
  it('detects PaymentRequest constructor call', () => {
    const records = [makeCreationRecord()];
    const signals = checkPaymentRequestCreated(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('prg:payment_request_created');
    expect(signals[0].weight).toBe(0.15);
    expect(signals[0].callCount).toBe(1);
  });

  it('reports correct count for multiple calls', () => {
    const records = [makeCreationRecord(), makeCreationRecord()];
    const signals = checkPaymentRequestCreated(records);
    expect(signals[0].callCount).toBe(2);
  });

  it('returns empty for null/empty records', () => {
    expect(checkPaymentRequestCreated(null)).toHaveLength(0);
    expect(checkPaymentRequestCreated([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkPiiFieldsRequested                                            */
/* ================================================================== */

describe('checkPiiFieldsRequested', () => {
  it('detects requestPayerEmail', () => {
    const records = [makeCreationRecord({ requestsEmail: true })];
    const signals = checkPiiFieldsRequested(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('prg:pii_fields_requested');
    expect(signals[0].weight).toBe(0.20);
  });

  it('detects requestPayerName', () => {
    const records = [makeCreationRecord({ requestsName: true })];
    expect(checkPiiFieldsRequested(records)).toHaveLength(1);
  });

  it('detects requestPayerPhone', () => {
    const records = [makeCreationRecord({ requestsPhone: true })];
    expect(checkPiiFieldsRequested(records)).toHaveLength(1);
  });

  it('does NOT flag when no PII requested', () => {
    const records = [makeCreationRecord()];
    expect(checkPiiFieldsRequested(records)).toHaveLength(0);
  });

  it('returns empty for null/empty records', () => {
    expect(checkPiiFieldsRequested(null)).toHaveLength(0);
    expect(checkPiiFieldsRequested([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkShowInvoked                                                    */
/* ================================================================== */

describe('checkShowInvoked', () => {
  it('detects .show() invocation', () => {
    const records = [makeShowRecord()];
    const signals = checkShowInvoked(records);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('prg:show_invoked');
    expect(signals[0].weight).toBe(0.15);
    expect(signals[0].showCount).toBe(1);
  });

  it('returns empty for null/empty records', () => {
    expect(checkShowInvoked(null)).toHaveLength(0);
    expect(checkShowInvoked([])).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkNoEstablishedMerchant                                         */
/* ================================================================== */

describe('checkNoEstablishedMerchant', () => {
  it('flags when no merchant markers present', () => {
    const doc = makeDoc('<html><body><p>Welcome</p></body></html>');
    const records = [makeCreationRecord()];
    const signals = checkNoEstablishedMerchant(records, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('prg:no_established_merchant');
    expect(signals[0].weight).toBe(0.20);
  });

  it('does NOT flag when Shopify markers present', () => {
    const doc = makeDoc('<html><body><script src="https://cdn.shopify.com/s/files/1/checkout.js"></script></body></html>');
    const records = [makeCreationRecord()];
    expect(checkNoEstablishedMerchant(records, doc)).toHaveLength(0);
  });

  it('does NOT flag when Stripe markers present', () => {
    const doc = makeDoc('<html><body><script src="https://js.stripe.com/v3/"></script></body></html>');
    const records = [makeCreationRecord()];
    expect(checkNoEstablishedMerchant(records, doc)).toHaveLength(0);
  });

  it('does NOT flag when checkout keyword in body', () => {
    const doc = makeDoc('<html><body>Complete your checkout</body></html>');
    const records = [makeCreationRecord()];
    expect(checkNoEstablishedMerchant(records, doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkNoEstablishedMerchant(null, makeDoc())).toHaveLength(0);
    expect(checkNoEstablishedMerchant([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  checkLoginContextWithPayment                                       */
/* ================================================================== */

describe('checkLoginContextWithPayment', () => {
  it('detects login context on payment page', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body></body></html>');
    const records = [makeCreationRecord()];
    const signals = checkLoginContextWithPayment(records, doc);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('prg:login_context_with_payment');
    expect(signals[0].weight).toBe(0.15);
  });

  it('does NOT flag non-login page', () => {
    const doc = makeDoc('<html><head><title>Shop Now</title></head><body>Buy stuff</body></html>');
    const records = [makeCreationRecord()];
    expect(checkLoginContextWithPayment(records, doc)).toHaveLength(0);
  });

  it('returns empty for null inputs', () => {
    expect(checkLoginContextWithPayment(null, makeDoc())).toHaveLength(0);
    expect(checkLoginContextWithPayment([], null)).toHaveLength(0);
  });
});

/* ================================================================== */
/*  hasLoginContext                                                      */
/* ================================================================== */

describe('hasLoginContext', () => {
  it('detects login keyword in title', () => {
    const doc = makeDoc('<html><head><title>Sign In to Your Account</title></head><body></body></html>');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('detects password keyword in body', () => {
    const doc = makeDoc('<html><body>Enter your password</body></html>');
    expect(hasLoginContext(doc)).toBe(true);
  });

  it('returns false for generic page', () => {
    const doc = makeDoc('<html><head><title>Welcome</title></head><body>Hello world</body></html>');
    expect(hasLoginContext(doc)).toBe(false);
  });

  it('returns false for null doc', () => {
    expect(hasLoginContext(null)).toBe(false);
  });
});

/* ================================================================== */
/*  hasMerchantMarkers                                                  */
/* ================================================================== */

describe('hasMerchantMarkers', () => {
  it('detects Shopify in script src', () => {
    const doc = makeDoc('<html><body><script src="https://cdn.shopify.com/checkout.js"></script></body></html>');
    expect(hasMerchantMarkers(doc)).toBe(true);
  });

  it('detects checkout keyword in body text', () => {
    const doc = makeDoc('<html><body>Proceed to checkout</body></html>');
    expect(hasMerchantMarkers(doc)).toBe(true);
  });

  it('returns false for non-merchant page', () => {
    const doc = makeDoc('<html><body>Hello world</body></html>');
    expect(hasMerchantMarkers(doc)).toBe(false);
  });

  it('returns false for null doc', () => {
    expect(hasMerchantMarkers(null)).toBe(false);
  });
});

/* ================================================================== */
/*  calculatePrgRiskScore                                               */
/* ================================================================== */

describe('calculatePrgRiskScore', () => {
  it('returns 0 for no signals', () => {
    const { riskScore, signalList } = calculatePrgRiskScore([]);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });

  it('sums signal weights correctly', () => {
    const signals = [
      { id: 'prg:payment_request_created', weight: 0.15 },
      { id: 'prg:pii_fields_requested', weight: 0.20 },
      { id: 'prg:show_invoked', weight: 0.15 },
    ];
    const { riskScore } = calculatePrgRiskScore(signals);
    expect(riskScore).toBeCloseTo(0.50, 2);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
    ];
    const { riskScore } = calculatePrgRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for null input', () => {
    const { riskScore, signalList } = calculatePrgRiskScore(null);
    expect(riskScore).toBe(0);
    expect(signalList).toHaveLength(0);
  });
});

/* ================================================================== */
/*  injectPrgWarningBanner                                              */
/* ================================================================== */

describe('injectPrgWarningBanner', () => {
  it('injects banner into document', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectPrgWarningBanner(0.65, [
      { id: 'prg:payment_request_created', weight: 0.15 },
      { id: 'prg:pii_fields_requested', weight: 0.20 },
      { id: 'prg:show_invoked', weight: 0.15 },
      { id: 'prg:no_established_merchant', weight: 0.20 },
    ]);

    const banner = dom.window.document.getElementById('phishops-prg-banner');
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('suspicious payment request');
  });

  it('does not inject duplicate banners', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'prg:test', weight: 0.50 }];
    injectPrgWarningBanner(0.50, signals);
    injectPrgWarningBanner(0.50, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-prg-banner');
    expect(banners).toHaveLength(1);
  });

  it('displays severity and risk score', () => {
    const dom = new JSDOM('<html><head></head><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    injectPrgWarningBanner(0.95, [{ id: 'prg:test', weight: 0.95 }]);

    const banner = dom.window.document.getElementById('phishops-prg-banner');
    expect(banner.textContent).toContain('Critical');
    expect(banner.textContent).toContain('0.95');
  });
});

/* ================================================================== */
/*  runPrgAnalysis (integration)                                        */
/* ================================================================== */

describe('runPrgAnalysis', () => {
  it('emits telemetry when risk exceeds alert threshold', () => {
    // Non-merchant, non-login page with PII + show = 0.15 + 0.20 + 0.15 + 0.20 = 0.70
    const doc = makeDoc('<html><head><title>Verify</title></head><body></body></html>');
    const crRecords = [makeCreationRecord({ requestsEmail: true, requestsPhone: true })];
    const shRecords = [makeShowRecord()];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runPrgAnalysis(doc, crRecords, shRecords);

    expect(sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'PAYMENTREQUESTGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'SUSPICIOUS_PAYMENT_REQUEST_DETECTED',
        }),
      }),
    );
  });

  it('does NOT emit when no creation records', () => {
    const doc = makeDoc('<html><head><title>Sign In</title></head><body></body></html>');

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runPrgAnalysis(doc, [], []);

    expect(sendMessage).not.toHaveBeenCalled();
  });

  it('does NOT emit when risk below alert threshold', () => {
    // Merchant checkout page, no PII, no show = 0.15 only (created signal)
    const doc = makeDoc('<html><head><title>Checkout</title></head><body>Complete your checkout<script src="https://js.stripe.com/v3/"></script></body></html>');
    const crRecords = [makeCreationRecord()];
    const shRecords = [];

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    runPrgAnalysis(doc, crRecords, shRecords);

    expect(sendMessage).not.toHaveBeenCalled();
  });
});
