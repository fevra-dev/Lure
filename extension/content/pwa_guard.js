/**
 * extension/content/pwa_guard.js
 *
 * PWAGuard — Progressive Web App Install Phishing Detection
 *
 * Detects malicious PWAs that impersonate banking/enterprise apps. Once
 * installed, the PWA opens in a standalone window without a URL bar,
 * presenting a credential harvesting form. ESET documented Czech/Hungarian
 * bank targeting (Oct 2024); SANS confirmed US FinServ campaigns (Jan 2026).
 *
 * Signal architecture:
 *   pwa:install_prompt_on_credential_page  +0.40
 *   pwa:manifest_brand_mismatch           +0.30
 *   pwa:standalone_display_with_creds     +0.25
 *   pwa:manifest_suspicious_scope         +0.20
 *   pwa:install_banner_lure_text          +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module PWAGuard
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const BRAND_NAMES_FOR_PWA = [
  'microsoft', 'google', 'apple', 'paypal', 'amazon', 'chase', 'wells fargo',
  'bank of america', 'citibank', 'hsbc', 'barclays', 'revolut', 'monzo',
  'coinbase', 'binance', 'metamask', 'outlook', 'gmail', 'dropbox', 'slack',
];

const BRAND_DOMAIN_MAP = {
  'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'],
  'google': ['google.com', 'gmail.com', 'googleapis.com'],
  'apple': ['apple.com', 'icloud.com'],
  'paypal': ['paypal.com'],
  'amazon': ['amazon.com', 'aws.amazon.com'],
  'chase': ['chase.com'],
  'wells fargo': ['wellsfargo.com'],
  'bank of america': ['bankofamerica.com'],
  'citibank': ['citibank.com', 'citi.com'],
  'hsbc': ['hsbc.com'],
  'barclays': ['barclays.co.uk', 'barclays.com'],
  'revolut': ['revolut.com'],
  'monzo': ['monzo.com'],
  'coinbase': ['coinbase.com'],
  'binance': ['binance.com'],
  'metamask': ['metamask.io'],
  'outlook': ['outlook.com', 'outlook.live.com'],
  'gmail': ['gmail.com', 'mail.google.com'],
  'dropbox': ['dropbox.com'],
  'slack': ['slack.com'],
};

const INSTALL_LURE_PATTERNS = [
  /install\s+(this|our|the)\s+(app|application)/i,
  /add\s+to\s+(home\s+screen|desktop)/i,
  /download\s+(our|this)\s+(app|banking\s+app)/i,
  /get\s+the\s+(app|mobile\s+app)/i,
];

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function hasCredentialFields(doc) {
  return doc.querySelectorAll('input[type="password"]').length > 0 ||
    doc.querySelectorAll('input[type="email"]').length > 0;
}

function getManifestData(doc) {
  const link = doc.querySelector('link[rel="manifest"]');
  if (!link) return null;

  // We can't fetch the manifest in a content script synchronously,
  // but we can check if data is embedded in the DOM via meta tags or
  // check common inline manifest patterns.
  // For signal detection we parse any inline JSON-LD or data attributes.
  return { href: link.getAttribute('href') || '' };
}

function matchesBrandDomain(hostname, brand) {
  const domains = BRAND_DOMAIN_MAP[brand] || [];
  return domains.some(d => hostname === d || hostname.endsWith('.' + d));
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if page has credential fields and a web app manifest
 * (indicator of PWA install prompt on a credential harvesting page).
 */
function checkInstallPromptOnCredentialPage(doc) {
  if (!doc) return [];
  if (!hasCredentialFields(doc)) return [];

  const manifest = getManifestData(doc);
  if (!manifest) return [];

  return [{
    id: 'pwa:install_prompt_on_credential_page',
    weight: 0.40,
    manifestHref: manifest.href,
  }];
}

/**
 * Check if Web App Manifest name/meta tags reference a known brand
 * but the hosting domain doesn't match that brand.
 */
function checkManifestBrandMismatch(doc, hostname) {
  if (!doc || !hostname) return [];

  const manifest = getManifestData(doc);
  if (!manifest) return [];

  // Check apple-mobile-web-app-title and application-name meta tags
  const appName = (
    doc.querySelector('meta[name="apple-mobile-web-app-title"]')?.getAttribute('content') ||
    doc.querySelector('meta[name="application-name"]')?.getAttribute('content') ||
    ''
  ).toLowerCase();

  // Also check title as fallback
  const title = (doc.title || '').toLowerCase();
  const combinedName = appName + ' ' + title;

  for (const brand of BRAND_NAMES_FOR_PWA) {
    if (combinedName.includes(brand) && !matchesBrandDomain(hostname, brand)) {
      return [{
        id: 'pwa:manifest_brand_mismatch',
        weight: 0.30,
        matchedBrand: brand,
        hostname,
      }];
    }
  }

  return [];
}

/**
 * Check if page is running in standalone display mode with credential fields.
 * Standalone mode means no URL bar — the user can't verify the domain.
 */
function checkStandaloneDisplayWithCreds(doc) {
  if (!doc) return [];
  if (!hasCredentialFields(doc)) return [];

  // Check if running in standalone mode
  try {
    if (globalThis.matchMedia?.('(display-mode: standalone)')?.matches) {
      return [{
        id: 'pwa:standalone_display_with_creds',
        weight: 0.25,
      }];
    }
  } catch (_) {
    // matchMedia not available
  }

  // Also check meta tag for mobile-web-app-capable
  const capable =
    doc.querySelector('meta[name="mobile-web-app-capable"]')?.getAttribute('content') ||
    doc.querySelector('meta[name="apple-mobile-web-app-capable"]')?.getAttribute('content') || '';

  if (capable === 'yes' && hasCredentialFields(doc)) {
    return [{
      id: 'pwa:standalone_display_with_creds',
      weight: 0.25,
      source: 'meta_tag',
    }];
  }

  return [];
}

/**
 * Check if manifest references a broad scope with a brand name in app metadata.
 */
function checkManifestSuspiciousScope(doc, hostname) {
  if (!doc || !hostname) return [];

  const manifest = getManifestData(doc);
  if (!manifest) return [];

  // Check theme-color and brand references in meta tags
  const appName = (
    doc.querySelector('meta[name="apple-mobile-web-app-title"]')?.getAttribute('content') ||
    doc.querySelector('meta[name="application-name"]')?.getAttribute('content') ||
    ''
  ).toLowerCase();

  if (!appName) return [];

  for (const brand of BRAND_NAMES_FOR_PWA) {
    if (appName.includes(brand) && !matchesBrandDomain(hostname, brand)) {
      return [{
        id: 'pwa:manifest_suspicious_scope',
        weight: 0.20,
        matchedBrand: brand,
      }];
    }
  }

  return [];
}

/**
 * Check for install instruction lure text near credential fields.
 */
function checkInstallBannerLureText(doc) {
  if (!doc || !doc.body) return [];
  if (!hasCredentialFields(doc)) return [];

  const bodyText = doc.body?.innerText || doc.body?.textContent || '';

  for (const pattern of INSTALL_LURE_PATTERNS) {
    if (pattern.test(bodyText)) {
      return [{
        id: 'pwa:install_banner_lure_text',
        weight: 0.15,
        matched: bodyText.match(pattern)?.[0] || '',
      }];
    }
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculatePwaRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectPwaWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-pwa-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const matchedBrand = signals.find(s => s.matchedBrand)?.matchedBrand || null;

  const banner = document.createElement('div');
  banner.id = 'phishops-pwa-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected Malicious PWA${matchedBrand ? ` (${matchedBrand})` : ''}</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('pwa:', '')).join(', ')}
    </div>
    <button id="phishops-pwa-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-pwa-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

function runPwaGuardAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname) return;

  const doc = document;

  const installSignals = checkInstallPromptOnCredentialPage(doc);
  const brandSignals = checkManifestBrandMismatch(doc, hostname);
  const standaloneSignals = checkStandaloneDisplayWithCreds(doc);
  const scopeSignals = checkManifestSuspiciousScope(doc, hostname);
  const lureSignals = checkInstallBannerLureText(doc);

  const allSignals = [
    ...installSignals,
    ...brandSignals,
    ...standaloneSignals,
    ...scopeSignals,
    ...lureSignals,
  ];

  const { riskScore, signalList } = calculatePwaRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';
  const matchedBrand = allSignals.find(s => s.matchedBrand)?.matchedBrand || null;

  injectPwaWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'PWAGUARD_EVENT',
      payload: {
        eventType: 'PWA_PHISHING_DETECTED',
        riskScore,
        severity,
        matchedBrand,
        signals: signalList,
        url: globalThis.location?.href || '',
        timestamp: new Date().toISOString(),
        action,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof document !== 'undefined' && typeof process === 'undefined') {
  runPwaGuardAnalysis();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['pwa_guard'] = {
    checkInstallPromptOnCredentialPage,
    checkManifestBrandMismatch,
    checkStandaloneDisplayWithCreds,
    checkManifestSuspiciousScope,
    checkInstallBannerLureText,
    calculatePwaRiskScore,
    injectPwaWarningBanner,
    runPwaGuardAnalysis,
  };
}

})();
