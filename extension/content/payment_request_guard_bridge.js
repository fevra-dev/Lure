/**
 * extension/content/payment_request_guard_bridge.js
 *
 * PaymentRequestGuard — Isolated World Bridge & Signal Analyzer
 *
 * Receives observations from the MAIN world interceptor
 * (payment_request_guard_main.js) via window.postMessage, accumulates
 * state, and runs heuristic analysis to detect suspicious Payment Request
 * API usage on phishing pages.
 *
 * This is a low-confidence, high-specificity supplementary detector.
 * It is meaningful only when co-occurring with domain-reputation failures,
 * brand-mismatch detections, or other phishing indicators.
 *
 * Injected at document_start in the isolated world. Analysis runs on
 * DOMContentLoaded + 2 s delay so the DOM is ready for heuristic checks.
 *
 * Signal architecture:
 *   prg:payment_request_created        +0.15
 *   prg:pii_fields_requested           +0.20
 *   prg:show_invoked                   +0.15
 *   prg:no_established_merchant        +0.20
 *   prg:login_context_with_payment     +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module PaymentRequestGuardBridge
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const SOURCE_ID = 'PHISHOPS_PRG';

const LOGIN_CONTEXT_PATTERNS = [
  /sign[\s-]?in/i, /log[\s-]?in/i, /log[\s-]?on/i, /password/i,
  /credential/i, /authenticate/i, /verification/i,
  /account[\s-]?access/i, /secure[\s-]?login/i,
  /enter\s+your\s+(email|password|username)/i,
];

const MERCHANT_PATTERNS = [
  /shopify/i, /stripe/i, /woocommerce/i, /bigcommerce/i,
  /magento/i, /squarespace/i, /ecwid/i, /prestashop/i,
  /checkout/i, /add[\s-]?to[\s-]?cart/i, /shopping[\s-]?cart/i,
  /product[\s-]?page/i,
];

const BODY_TEXT_LIMIT = 5000;

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

/**
 * Records of PaymentRequest constructor calls.
 * @type {{ methods: string, requestsName: boolean, requestsEmail: boolean, requestsPhone: boolean, requestsShipping: boolean, timestamp: number }[]}
 */
const creationRecords = [];

/**
 * Records of PaymentRequest.show() calls.
 * @type {{ timestamp: number }[]}
 */
const showRecords = [];

let analysisRun = false;

/* ------------------------------------------------------------------ */
/*  Message Listener (MAIN world -> isolated world bridge)             */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined') {
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.source !== SOURCE_ID) return;

    const { type, data } = event.data;

    if (type === 'PAYMENT_REQUEST_CREATED' && data) {
      creationRecords.push({
        methods: data.methods || '',
        requestsName: !!data.requestsName,
        requestsEmail: !!data.requestsEmail,
        requestsPhone: !!data.requestsPhone,
        requestsShipping: !!data.requestsShipping,
        timestamp: data.timestamp || Date.now(),
      });
    }

    if (type === 'PAYMENT_REQUEST_SHOW' && data) {
      showRecords.push({
        timestamp: data.timestamp || Date.now(),
      });
    }
  });
}

/* ------------------------------------------------------------------ */
/*  Helper Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if the page has login/auth context via URL, title, or body text.
 */
export function hasLoginContext(doc) {
  if (!doc) return false;

  const url = (doc.location?.href || '').toLowerCase();
  const title = (doc.title || '').toLowerCase();

  for (const pattern of LOGIN_CONTEXT_PATTERNS) {
    if (pattern.test(url) || pattern.test(title)) return true;
  }

  const bodyText = (doc.body?.textContent || '').substring(0, BODY_TEXT_LIMIT);
  for (const pattern of LOGIN_CONTEXT_PATTERNS) {
    if (pattern.test(bodyText)) return true;
  }

  return false;
}

/**
 * Check if the page has established e-commerce/merchant markers.
 */
export function hasMerchantMarkers(doc) {
  if (!doc) return false;

  const url = (doc.location?.href || '').toLowerCase();
  const title = (doc.title || '').toLowerCase();

  for (const pattern of MERCHANT_PATTERNS) {
    if (pattern.test(url) || pattern.test(title)) return true;
  }

  const scripts = doc.querySelectorAll('script');
  for (const script of scripts) {
    const src = script.src || '';
    for (const pattern of MERCHANT_PATTERNS) {
      if (pattern.test(src)) return true;
    }
  }

  const bodyText = (doc.body?.textContent || '').substring(0, BODY_TEXT_LIMIT);
  for (const pattern of MERCHANT_PATTERNS) {
    if (pattern.test(bodyText)) return true;
  }

  return false;
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Signal 1: PaymentRequest constructor was called.
 * Weight: 0.15 — baseline detection of API usage (extremely rare on the web).
 */
export function checkPaymentRequestCreated(records) {
  if (!records || records.length === 0) return [];

  return [{
    id: 'prg:payment_request_created',
    weight: 0.15,
    callCount: records.length,
  }];
}

/**
 * Signal 2: PII fields (name, email, phone) explicitly requested.
 * Weight: 0.20 — requesting PII via the payment API on a phishing page
 * enables identity fraud without needing card data.
 */
export function checkPiiFieldsRequested(records) {
  if (!records || records.length === 0) return [];

  const anyPii = records.some(r =>
    r.requestsName || r.requestsEmail || r.requestsPhone
  );

  if (!anyPii) return [];

  return [{
    id: 'prg:pii_fields_requested',
    weight: 0.20,
  }];
}

/**
 * Signal 3: PaymentRequest.show() was invoked (payment sheet displayed).
 * Weight: 0.15 — confirms the payment UI was actually triggered, not just constructed.
 */
export function checkShowInvoked(records) {
  if (!records || records.length === 0) return [];

  return [{
    id: 'prg:show_invoked',
    weight: 0.15,
    showCount: records.length,
  }];
}

/**
 * Signal 4: Page lacks established e-commerce/merchant markers.
 * Weight: 0.20 — legitimate Payment Request API usage almost always
 * occurs on recognisable merchant checkout pages.
 */
export function checkNoEstablishedMerchant(records, doc) {
  if (!records || records.length === 0 || !doc) return [];

  if (hasMerchantMarkers(doc)) return [];

  return [{
    id: 'prg:no_established_merchant',
    weight: 0.20,
  }];
}

/**
 * Signal 5: Page has login/auth context combined with payment API usage.
 * Weight: 0.15 — payment requests on login pages are anomalous;
 * legitimate login flows don't request payment.
 */
export function checkLoginContextWithPayment(records, doc) {
  if (!records || records.length === 0 || !doc) return [];

  if (!hasLoginContext(doc)) return [];

  return [{
    id: 'prg:login_context_with_payment',
    weight: 0.15,
  }];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

export function calculatePrgRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

export function injectPrgWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-prg-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-prg-banner';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#0A0907', 'border-bottom:2px solid #BF1B1B',
    'padding:14px 20px',
    "font-family:'Work Sans',system-ui,-apple-system,sans-serif",
    'display:flex', 'align-items:center', 'gap:14px',
  ].join(';');

  banner.innerHTML = `
    <span style="font-size:24px;flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B;font-size:15px;display:block;margin-bottom:3px;font-family:'Work Sans',system-ui,sans-serif;">
        suspicious payment request detected \u2014 phishops paymentrequestguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('prg:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-prg-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-prg-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run analysis on accumulated PaymentRequest observations.
 */
export function runPrgAnalysis(doc, crRecords, shRecords) {
  if (!doc || !crRecords || crRecords.length === 0) return;

  const createdSignals = checkPaymentRequestCreated(crRecords);
  if (createdSignals.length === 0) return;

  const piiSignals = checkPiiFieldsRequested(crRecords);
  const showSignals = checkShowInvoked(shRecords);
  const merchantSignals = checkNoEstablishedMerchant(crRecords, doc);
  const loginSignals = checkLoginContextWithPayment(crRecords, doc);

  const allSignals = [
    ...createdSignals,
    ...piiSignals,
    ...showSignals,
    ...merchantSignals,
    ...loginSignals,
  ];

  const { riskScore, signalList } = calculatePrgRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectPrgWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'PAYMENTREQUESTGUARD_EVENT',
      payload: {
        eventType: 'SUSPICIOUS_PAYMENT_REQUEST_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
        callCount: crRecords.length,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

export function _getCreationRecords() {
  return creationRecords;
}

export function _getShowRecords() {
  return showRecords;
}

export function _resetState() {
  creationRecords.length = 0;
  showRecords.length = 0;
  analysisRun = false;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        if (!analysisRun) {
          runPrgAnalysis(document, creationRecords, showRecords);
          analysisRun = true;
        }
      }, 2000);
    });
  }
}
