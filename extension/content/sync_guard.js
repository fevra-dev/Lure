/**
 * extension/content/sync_guard.js
 *
 * SyncGuard — Browser Sync Hijacking Detection
 *
 * Detects social engineering attacks that trick users into adding attacker-
 * controlled accounts to their browser sync (Scattered Spider / UNC3944 TTP).
 * Once sync activates, all saved passwords, cookies, and autofill data
 * replicate to the attacker's device.
 *
 * Signal architecture:
 *   sync:add_account_suspicious_referrer       +0.40
 *   sync:sync_setup_instructions               +0.35
 *   sync:remote_support_context                +0.30
 *   sync:profile_creation_social_engineering   +0.25
 *   sync:non_standard_account_flow             +0.20
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module SyncGuard
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

/* ------------------------------------------------------------------ */
/*  Known Account Flow Domains                                         */
/* ------------------------------------------------------------------ */

const ACCOUNT_FLOW_DOMAINS = [
  'accounts.google.com',
  'login.microsoftonline.com',
  'login.live.com',
  'login.windows.net',
];

const TRUSTED_REFERRER_DOMAINS = [
  'google.com',
  'accounts.google.com',
  'myaccount.google.com',
  'microsoft.com',
  'login.microsoftonline.com',
  'login.live.com',
  'login.windows.net',
  'microsoftonline.com',
  'office.com',
  'live.com',
];

/* ------------------------------------------------------------------ */
/*  Keyword Sets                                                       */
/* ------------------------------------------------------------------ */

const SYNC_INSTRUCTION_KEYWORDS = [
  'add account',
  'add an account',
  'sign in to chrome',
  'sign into chrome',
  'turn on sync',
  'enable sync',
  'enable browser sync',
  'add profile',
  'add a new profile',
  'add new profile',
  'add your account',
  'sync your browser',
  'sync your data',
  'link your account',
  'connect your account',
  'sign in to your browser',
];

const REMOTE_SUPPORT_KEYWORDS = [
  'teamviewer',
  'anydesk',
  'connectwise',
  'logmein',
  'gotomypc',
  'remote desktop',
  'remote session',
  'remote support',
  'screen share',
  'remote assistance',
  'remote access',
  'splashtop',
  'bomgar',
  'beyondtrust',
  'dameware',
];

const PROFILE_CREATION_KEYWORDS = [
  'create a new profile',
  'create new profile',
  'set up a new profile',
  'use these credentials',
  'use this account',
  'enter these credentials',
  'enter this email',
  'enter this password',
  'sign in with these',
  'log in with this account',
  'use the following account',
  'use the following credentials',
];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Detect navigation to account add/sign-in pages from suspicious referrers.
 * Social engineering attacks direct users from helpdesk or remote support
 * pages to account sign-in flows.
 */
function checkSuspiciousReferrer(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const signals = [];

  // Only relevant on account flow domains
  const isAccountFlow = ACCOUNT_FLOW_DOMAINS.some(d =>
    hostname === d || hostname.endsWith('.' + d)
  );
  if (!isAccountFlow) return [];

  const referrer = doc.referrer || '';
  if (!referrer) return [];

  try {
    const refUrl = new URL(referrer);
    const refHost = refUrl.hostname;

    // If referrer is from a trusted domain, it's a normal flow
    const isTrusted = TRUSTED_REFERRER_DOMAINS.some(d =>
      refHost === d || refHost.endsWith('.' + d)
    );

    if (!isTrusted) {
      signals.push({
        id: 'sync:add_account_suspicious_referrer',
        weight: 0.40,
        referrerDomain: refHost,
      });
    }
  } catch (_) {
    // Malformed referrer
  }

  return signals;
}

/**
 * Detect pages containing sync setup instructions — social engineering
 * text that guides users to add accounts or enable browser sync.
 */
function checkSyncSetupInstructions(doc) {
  if (!doc) return [];

  const signals = [];
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();

  if (!bodyText) return [];

  const matchedKeywords = SYNC_INSTRUCTION_KEYWORDS.filter(kw => bodyText.includes(kw));

  if (matchedKeywords.length > 0) {
    signals.push({
      id: 'sync:sync_setup_instructions',
      weight: 0.35,
      matchedKeywords,
    });
  }

  return signals;
}

/**
 * Detect remote support tool references on the current page.
 * Scattered Spider attacks often begin with a remote support session.
 */
function checkRemoteSupportContext(doc) {
  if (!doc) return [];

  const signals = [];
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();
  const title = (doc.title || '').toLowerCase();
  const combinedText = title + ' ' + bodyText;

  if (!combinedText.trim()) return [];

  const matchedTools = REMOTE_SUPPORT_KEYWORDS.filter(kw => combinedText.includes(kw));

  if (matchedTools.length > 0) {
    signals.push({
      id: 'sync:remote_support_context',
      weight: 0.30,
      matchedTools,
    });
  }

  return signals;
}

/**
 * Detect pages that instruct users to create browser profiles or
 * sign in with specific provided credentials.
 */
function checkProfileCreationSocialEngineering(doc) {
  if (!doc) return [];

  const signals = [];
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();

  if (!bodyText) return [];

  const matchedPhrases = PROFILE_CREATION_KEYWORDS.filter(kw => bodyText.includes(kw));

  if (matchedPhrases.length > 0) {
    signals.push({
      id: 'sync:profile_creation_social_engineering',
      weight: 0.25,
      matchedPhrases,
    });
  }

  return signals;
}

/**
 * Detect account add flows reached via non-standard paths.
 * Normal account adds come from browser settings (chrome://settings)
 * or the Google/Microsoft ecosystem. Unusual referrers suggest social
 * engineering.
 */
function checkNonStandardAccountFlow(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const signals = [];

  // Only relevant on account flow domains
  const isAccountFlow = ACCOUNT_FLOW_DOMAINS.some(d =>
    hostname === d || hostname.endsWith('.' + d)
  );
  if (!isAccountFlow) return [];

  const referrer = doc.referrer || '';

  // No referrer could be direct navigation (benign) or stripped referrer
  if (!referrer) return [];

  try {
    const refUrl = new URL(referrer);
    const refHost = refUrl.hostname;

    // chrome:// referrers are not sent in document.referrer (always empty for chrome:// origins)
    // So if we have a referrer and it's not from the account provider ecosystem,
    // it's a non-standard flow
    const isStandardFlow = TRUSTED_REFERRER_DOMAINS.some(d =>
      refHost === d || refHost.endsWith('.' + d)
    );

    if (!isStandardFlow) {
      signals.push({
        id: 'sync:non_standard_account_flow',
        weight: 0.20,
        referrerDomain: refHost,
      });
    }
  } catch (_) {
    // Malformed referrer
  }

  return signals;
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

/**
 * Calculate composite risk score from signal array.
 * @param {Array<{id: string, weight: number}>} signals
 * @returns {{ riskScore: number, signalList: string[] }}
 */
function calculateSyncGuardRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

/**
 * Inject a warning banner for sync hijacking detection.
 */
function injectSyncGuardWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-syncguard-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-syncguard-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected Browser Sync Hijacking</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('sync:', '')).join(', ')}
    </div>
    <button id="phishops-syncguard-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-syncguard-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Run full SyncGuard analysis on the current page.
 */
function runSyncGuardAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1') return;

  const doc = document;

  const referrerSignals = checkSuspiciousReferrer(doc, hostname);
  const instructionSignals = checkSyncSetupInstructions(doc);
  const remoteSupportSignals = checkRemoteSupportContext(doc);
  const profileSignals = checkProfileCreationSocialEngineering(doc);
  const flowSignals = checkNonStandardAccountFlow(doc, hostname);

  const allSignals = [
    ...referrerSignals,
    ...instructionSignals,
    ...remoteSupportSignals,
    ...profileSignals,
    ...flowSignals,
  ];

  const { riskScore, signalList } = calculateSyncGuardRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectSyncGuardWarningBanner(riskScore, allSignals);

  // Emit telemetry
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'SYNCGUARD_EVENT',
      payload: {
        eventType: 'SYNC_HIJACK_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: globalThis.location?.href || '',
        referrer: doc.referrer || '',
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
  runSyncGuardAnalysis();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['sync_guard'] = {
    checkSuspiciousReferrer,
    checkSyncSetupInstructions,
    checkRemoteSupportContext,
    checkProfileCreationSocialEngineering,
    checkNonStandardAccountFlow,
    calculateSyncGuardRiskScore,
    injectSyncGuardWarningBanner,
    runSyncGuardAnalysis,
  };
}

})();
