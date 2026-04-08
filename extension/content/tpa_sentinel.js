/**
 * extension/content/tpa_sentinel.js
 *
 * TPASentinel — Third-Party App Consent Phishing Detection
 *
 * Detects malicious OAuth applications that request dangerous permissions
 * and social-engineer users into granting consent. Microsoft rated consent
 * phishing as a top 3 cloud attack vector in 2025. Detectable on consent
 * page DOM: high-risk permission combos, unverified publisher badges,
 * brand impersonation in app names.
 *
 * Only runs on known consent page domains (login.microsoftonline.com,
 * accounts.google.com, login.okta.com, id.atlassian.com).
 *
 * Signal architecture:
 *   tpa:high_risk_permission_combo     +0.40
 *   tpa:unverified_publisher           +0.30
 *   tpa:consent_on_redirected_page     +0.25
 *   tpa:app_name_brand_impersonation   +0.20
 *   tpa:excessive_scope_count          +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module TPASentinel
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const CONSENT_PAGE_DOMAINS = [
  'login.microsoftonline.com',
  'accounts.google.com',
  'login.okta.com',
  'id.atlassian.com',
  'login.salesforce.com',
];

const CONSENT_PAGE_INDICATORS = [
  /consent/i,
  /permissions?\s+requested/i,
  /app\s+wants\s+to\s+access/i,
  /allow\s+this\s+app/i,
  /accept\s+permissions/i,
  /approve\s+access/i,
  /is\s+requesting\s+permission/i,
  /review\s+permissions/i,
];

const HIGH_RISK_SCOPES = [
  'mail.readwrite', 'mail.send', 'mail.readwrite.all',
  'files.readwrite.all', 'sites.readwrite.all',
  'directory.readwrite.all', 'directory.read.all',
  'user.readwrite.all', 'offline_access',
  'user_impersonation', 'openid',
];

const KNOWN_BRAND_APP_NAMES = [
  /microsoft\s+(security|teams|365|office|defender)/i,
  /google\s+(drive|workspace|security|sync)/i,
  /adobe\s+(sign|acrobat|creative)/i,
  /dropbox\s+(sync|backup)/i,
  /zoom\s+(meeting|conference)/i,
  /slack\s+(bot|connector|integration)/i,
];

const HIGH_RISK_COMBO_THRESHOLD = 3;
const EXCESSIVE_SCOPE_THRESHOLD = 5;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function isConsentPageDomain(hostname) {
  return CONSENT_PAGE_DOMAINS.some(
    d => hostname === d || hostname.endsWith('.' + d)
  );
}

function isConsentPage(doc, hostname) {
  if (!isConsentPageDomain(hostname)) return false;

  const bodyText = doc.body?.innerText || doc.body?.textContent || '';
  return CONSENT_PAGE_INDICATORS.some(p => p.test(bodyText));
}

function extractPermissionsFromPage(doc) {
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();
  const matched = [];

  for (const scope of HIGH_RISK_SCOPES) {
    // Check for scope name in various formats
    if (bodyText.includes(scope) ||
        bodyText.includes(scope.replace(/\./g, ' ')) ||
        bodyText.includes(scope.replace(/\./g, '_'))) {
      matched.push(scope);
    }
  }

  // Also check for common permission description patterns
  const permPatterns = [
    { pattern: /read\s+(and\s+write\s+)?your\s+mail/i, scope: 'mail.readwrite' },
    { pattern: /send\s+mail\s+(as\s+you|on\s+your\s+behalf)/i, scope: 'mail.send' },
    { pattern: /access\s+(your\s+)?files/i, scope: 'files.readwrite.all' },
    { pattern: /read\s+(your\s+)?directory/i, scope: 'directory.read.all' },
    { pattern: /sign\s+in\s+and\s+read\s+your\s+profile/i, scope: 'openid' },
    { pattern: /maintain\s+access/i, scope: 'offline_access' },
  ];

  for (const { pattern, scope } of permPatterns) {
    if (pattern.test(bodyText) && !matched.includes(scope)) {
      matched.push(scope);
    }
  }

  return [...new Set(matched)];
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if consent page shows 3+ high-risk scopes simultaneously.
 */
function checkHighRiskPermissionCombo(doc, hostname) {
  if (!doc || !hostname) return [];
  if (!isConsentPage(doc, hostname)) return [];

  const permissions = extractPermissionsFromPage(doc);
  const highRiskCount = permissions.filter(p => HIGH_RISK_SCOPES.includes(p)).length;

  if (highRiskCount >= HIGH_RISK_COMBO_THRESHOLD) {
    return [{
      id: 'tpa:high_risk_permission_combo',
      weight: 0.40,
      permissions,
      highRiskCount,
    }];
  }

  return [];
}

/**
 * Check for "unverified" publisher badge or publisher name mismatch.
 */
function checkUnverifiedPublisher(doc, hostname) {
  if (!doc || !hostname) return [];
  if (!isConsentPage(doc, hostname)) return [];

  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();

  if (bodyText.includes('unverified') ||
      bodyText.includes('not verified') ||
      bodyText.includes('publisher not verified')) {
    return [{
      id: 'tpa:unverified_publisher',
      weight: 0.30,
    }];
  }

  return [];
}

/**
 * Check if user arrived at consent page from a non-IdP referrer.
 */
function checkConsentOnRedirectedPage(doc, hostname) {
  if (!doc || !hostname) return [];
  if (!isConsentPageDomain(hostname)) return [];

  let referrer = '';
  try {
    referrer = doc.referrer || '';
  } catch (_) {
    return [];
  }

  if (!referrer) return [];

  try {
    const refHostname = new URL(referrer).hostname;
    // If referrer is from a non-IdP domain, this is suspicious
    if (!isConsentPageDomain(refHostname)) {
      return [{
        id: 'tpa:consent_on_redirected_page',
        weight: 0.25,
        referrer: refHostname,
      }];
    }
  } catch (_) {
    // Invalid referrer URL
  }

  return [];
}

/**
 * Check if app name on consent page impersonates a known brand.
 */
function checkAppNameBrandImpersonation(doc, hostname) {
  if (!doc || !hostname) return [];
  if (!isConsentPage(doc, hostname)) return [];

  const bodyText = doc.body?.innerText || doc.body?.textContent || '';

  for (const pattern of KNOWN_BRAND_APP_NAMES) {
    if (pattern.test(bodyText)) {
      const match = bodyText.match(pattern);
      return [{
        id: 'tpa:app_name_brand_impersonation',
        weight: 0.20,
        matchedName: (match?.[0] || '').substring(0, 100),
      }];
    }
  }

  return [];
}

/**
 * Check if app requests 5+ distinct permission scopes.
 */
function checkExcessiveScopeCount(doc, hostname) {
  if (!doc || !hostname) return [];
  if (!isConsentPage(doc, hostname)) return [];

  const permissions = extractPermissionsFromPage(doc);

  if (permissions.length >= EXCESSIVE_SCOPE_THRESHOLD) {
    return [{
      id: 'tpa:excessive_scope_count',
      weight: 0.15,
      scopeCount: permissions.length,
    }];
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateTpaRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectTpaWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-tpa-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-tpa-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspicious App Consent Request</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('tpa:', '')).join(', ')}
    </div>
    <button id="phishops-tpa-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-tpa-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

function runTpaSentinelAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname) return;

  // Only run on consent page domains
  if (!isConsentPageDomain(hostname)) return;

  const doc = document;

  const permSignals = checkHighRiskPermissionCombo(doc, hostname);
  const publisherSignals = checkUnverifiedPublisher(doc, hostname);
  const redirectSignals = checkConsentOnRedirectedPage(doc, hostname);
  const brandSignals = checkAppNameBrandImpersonation(doc, hostname);
  const scopeSignals = checkExcessiveScopeCount(doc, hostname);

  const allSignals = [
    ...permSignals,
    ...publisherSignals,
    ...redirectSignals,
    ...brandSignals,
    ...scopeSignals,
  ];

  const { riskScore, signalList } = calculateTpaRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectTpaWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'TPASENTINEL_EVENT',
      payload: {
        eventType: 'TPA_CONSENT_PHISHING_DETECTED',
        riskScore,
        severity,
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
  runTpaSentinelAnalysis();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['tpa_sentinel'] = {
    checkHighRiskPermissionCombo,
    checkUnverifiedPublisher,
    checkConsentOnRedirectedPage,
    checkAppNameBrandImpersonation,
    checkExcessiveScopeCount,
    calculateTpaRiskScore,
    injectTpaWarningBanner,
    runTpaSentinelAnalysis,
  };
}
