/**
 * extension/content/proxy_guard.js
 *
 * ProxyGuard — AiTM Reverse Proxy Detection
 *
 * Detects Adversary-in-the-Middle reverse proxy phishing (Evilginx, Modlishka,
 * Muraena, Starkiller). These proxies transparently relay legitimate login pages
 * to capture credentials AND session tokens, defeating MFA.
 *
 * Signal architecture:
 *   proxy:at_symbol_url_masking       +0.45
 *   proxy:auth_page_domain_mismatch   +0.40
 *   proxy:suspicious_form_action      +0.35
 *   proxy:missing_security_headers    +0.25
 *   proxy:dom_injection_artifact      +0.20
 *   proxy:response_timing_anomaly     +0.20
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module ProxyGuard
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

/* ------------------------------------------------------------------ */
/*  Known Auth Providers                                               */
/* ------------------------------------------------------------------ */

const KNOWN_AUTH_PROVIDERS = {
  'login.microsoftonline.com': 'Microsoft',
  'accounts.google.com': 'Google',
  'appleid.apple.com': 'Apple',
  'login.live.com': 'Microsoft',
  'login.windows.net': 'Microsoft',
  'github.com': 'GitHub',
  'login.salesforce.com': 'Salesforce',
  'login.okta.com': 'Okta',
  'id.atlassian.com': 'Atlassian',
  'auth0.com': 'Auth0',
  'login.yahoo.com': 'Yahoo',
  'signin.aws.amazon.com': 'AWS',
};

const AUTH_PROVIDER_DOMAINS = Object.keys(KNOWN_AUTH_PROVIDERS);

/* ------------------------------------------------------------------ */
/*  Proxy Framework Signatures                                         */
/* ------------------------------------------------------------------ */

const PROXY_SIGNATURES = [
  'evilginx',
  'modlishka',
  'muraena',
  'gophish',
  'king-phisher',
  'evilproxy',
  'caffeine', // PhaaS framework
];

/* ------------------------------------------------------------------ */
/*  Legitimate Major Domain Allowlist                                  */
/* ------------------------------------------------------------------ */
// Hard allowlist for popular legitimate sites that consistently trip
// proxy heuristics (lots of CDN scripts, no CSP meta tag, "Sign in with
// Google/Microsoft" buttons that reference auth providers in body text).
// Matches both bare domain and any subdomain.

const LEGIT_DOMAIN_ALLOWLIST = new Set([
  'linkedin.com',
  'github.com',
  'gitlab.com',
  'bitbucket.org',
  'stackoverflow.com',
  'stackexchange.com',
  'reddit.com',
  'twitter.com',
  'x.com',
  'facebook.com',
  'instagram.com',
  'youtube.com',
  'wikipedia.org',
  'medium.com',
  'substack.com',
  'notion.so',
  'figma.com',
  'slack.com',
  'discord.com',
  'zoom.us',
  'spotify.com',
  'netflix.com',
  'amazon.com',
  'ebay.com',
  'paypal.com',
  'cloudflare.com',
  'tryhackme.com',
  'hackthebox.com',
  'protonmail.com',
  'proton.me',
  'mail.proton.me',
  'anthropic.com',
  'openai.com',
  'huggingface.co',
  'kaggle.com',
]);

function isLegitAllowlistedHost(hostname) {
  if (!hostname) return false;
  if (LEGIT_DOMAIN_ALLOWLIST.has(hostname)) return true;
  for (const root of LEGIT_DOMAIN_ALLOWLIST) {
    if (hostname.endsWith('.' + root)) return true;
  }
  return false;
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Detect @-symbol URL masking (Starkiller pattern).
 * URL like https://login.microsoft.com@evil.com/path
 * The browser sends traffic to evil.com, but displays login.microsoft.com.
 */
function checkAtSymbolUrlMasking(urlString) {
  if (!urlString) return [];

  const signals = [];

  try {
    const url = new URL(urlString);

    // Check if URL has a username (text before @)
    if (url.username) {
      // Check if the username portion contains a known auth provider
      const usernameDecoded = decodeURIComponent(url.username);
      const hasAuthProvider = AUTH_PROVIDER_DOMAINS.some(domain =>
        usernameDecoded.includes(domain) || usernameDecoded.replace(/\./g, '').includes(domain.replace(/\./g, ''))
      );

      if (hasAuthProvider) {
        signals.push({
          id: 'proxy:at_symbol_url_masking',
          weight: 0.45,
          targetProvider: KNOWN_AUTH_PROVIDERS[
            AUTH_PROVIDER_DOMAINS.find(d => usernameDecoded.includes(d))
          ] || 'Unknown',
        });
      }
    }
  } catch (_) {
    // Malformed URL — not a signal
  }

  return signals;
}

/**
 * Detect auth page content served from a non-auth domain.
 * Checks for login forms + auth provider references in page text/title
 * while hostname doesn't match the provider.
 */
function checkAuthPageDomainMismatch(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const signals = [];

  // Must have a login form
  const hasPasswordField = doc.querySelectorAll('input[type="password"]').length > 0;
  const hasEmailField = doc.querySelectorAll('input[type="email"]').length > 0;
  if (!hasPasswordField && !hasEmailField) return [];

  const title = (doc.title || '').toLowerCase();
  const bodyText = (doc.body?.innerText || doc.body?.textContent || '').toLowerCase();
  const combinedText = title + ' ' + bodyText;

  // Check form action URLs for auth provider references
  const forms = doc.querySelectorAll('form');
  let formReferencesAuth = false;
  for (const form of forms) {
    const action = (form.getAttribute('action') || '').toLowerCase();
    if (AUTH_PROVIDER_DOMAINS.some(d => action.includes(d))) {
      formReferencesAuth = true;
      break;
    }
  }

  // Check if page text references an auth provider
  for (const [domain, provider] of Object.entries(KNOWN_AUTH_PROVIDERS)) {
    // Skip if hostname IS this auth provider
    if (hostname === domain || hostname.endsWith('.' + domain)) continue;

    // Also skip if hostname belongs to the same org (e.g. microsoft.com for login.microsoftonline.com)
    const providerLower = provider.toLowerCase();
    if (hostname.includes(providerLower)) continue;

    const domainShort = domain.split('.')[0]; // e.g. "login" from "login.microsoftonline.com"
    const textReferences = combinedText.includes(domain) ||
      combinedText.includes(provider.toLowerCase()) ||
      formReferencesAuth;

    if (textReferences) {
      signals.push({
        id: 'proxy:auth_page_domain_mismatch',
        weight: 0.40,
        targetProvider: provider,
      });
      break;
    }
  }

  return signals;
}

/**
 * Detect suspicious form actions that post to a different domain.
 */
function checkSuspiciousFormAction(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  const signals = [];
  const forms = doc.querySelectorAll('form');

  for (const form of forms) {
    const action = form.getAttribute('action') || '';
    if (!action || action.startsWith('/') || action.startsWith('#') || action.startsWith('?')) continue;

    try {
      const actionUrl = new URL(action, `https://${hostname}`);
      const actionHost = actionUrl.hostname;

      // Skip if same domain
      if (actionHost === hostname || actionHost.endsWith('.' + hostname) || hostname.endsWith('.' + actionHost)) continue;

      // Skip if action goes to a known auth provider
      if (AUTH_PROVIDER_DOMAINS.includes(actionHost) || AUTH_PROVIDER_DOMAINS.some(d => actionHost.endsWith('.' + d))) continue;

      // Form posts to an unknown third-party domain
      signals.push({
        id: 'proxy:suspicious_form_action',
        weight: 0.35,
      });
      break;
    } catch (_) {
      // Malformed URL
    }
  }

  return signals;
}

/**
 * Detect missing CSP meta tag on auth-like pages.
 * Reverse proxies strip HTTP security headers; we check for CSP meta tags
 * since content scripts can't read HTTP response headers.
 */
function checkMissingSecurityHeaders(doc) {
  if (!doc) return [];

  // Only fire on auth-like pages (pages with login forms)
  const hasPasswordField = doc.querySelectorAll('input[type="password"]').length > 0;
  if (!hasPasswordField) return [];

  const signals = [];
  const cspMeta = doc.querySelector('meta[http-equiv="Content-Security-Policy"]');

  if (!cspMeta) {
    signals.push({
      id: 'proxy:missing_security_headers',
      weight: 0.25,
    });
  }

  return signals;
}

/**
 * Detect DOM injection artifacts — foreign scripts, proxy framework signatures.
 */
function checkDomInjectionArtifacts(doc, hostname) {
  if (!doc || !hostname) return [];
  if (hostname === 'localhost' || hostname === '127.0.0.1') return [];

  // Only check auth-like pages
  const hasPasswordField = doc.querySelectorAll('input[type="password"]').length > 0;
  if (!hasPasswordField) return [];

  const signals = [];
  const scripts = doc.querySelectorAll('script[src]');
  const html = (doc.documentElement?.outerHTML || '').toLowerCase();

  // Check for proxy framework signatures in page HTML
  const hasProxySignature = PROXY_SIGNATURES.some(sig => html.includes(sig));

  // Check for foreign script injections on auth-like page
  let foreignScriptCount = 0;
  for (const script of scripts) {
    const src = script.getAttribute('src') || '';
    if (!src) continue;

    try {
      const scriptUrl = new URL(src, `https://${hostname}`);
      if (scriptUrl.hostname !== hostname && !scriptUrl.hostname.endsWith('.' + hostname)) {
        foreignScriptCount++;
      }
    } catch (_) {
      // Skip malformed
    }
  }

  if (hasProxySignature || foreignScriptCount >= 3) {
    signals.push({
      id: 'proxy:dom_injection_artifact',
      weight: 0.20,
    });
  }

  return signals;
}

/**
 * Detect response timing anomaly — proxy latency adds delay.
 * Uses PerformanceNavigationTiming API.
 */
function checkResponseTimingAnomaly() {
  const signals = [];

  try {
    const navEntries = globalThis.performance?.getEntriesByType?.('navigation');
    if (!navEntries || navEntries.length === 0) return [];

    const nav = navEntries[0];
    const loadTime = nav.loadEventEnd - nav.startTime;

    // Auth pages are typically fast (<1s for the login form).
    // Proxy relay adds 1-3s overhead.
    if (loadTime > 3000) {
      signals.push({
        id: 'proxy:response_timing_anomaly',
        weight: 0.20,
      });
    }
  } catch (_) {
    // performance API not available
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
function calculateProxyRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

/**
 * Inject a warning banner for proxy detection.
 */
function injectProxyWarningBanner(riskScore, targetProvider, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-proxy-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const providerDisplay = targetProvider || 'Unknown';

  const banner = document.createElement('div');
  banner.id = 'phishops-proxy-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — Suspected ${providerDisplay} Proxy Phishing</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('proxy:', '')).join(', ')}
    </div>
    <button id="phishops-proxy-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-proxy-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

/**
 * Run full ProxyGuard analysis on the current page.
 */
function runProxyGuardAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname || hostname === 'localhost' || hostname === '127.0.0.1') return;
  // Skip popular legitimate sites — these are not Evilginx/Modlishka/Muraena
  // hosts and the soft signals (CDN scripts, missing CSP meta, "Sign in with
  // Google" copy) consistently produce false positives.
  if (isLegitAllowlistedHost(hostname)) return;

  const doc = document;
  const url = globalThis.location?.href || '';

  const atSymbolSignals = checkAtSymbolUrlMasking(url);
  const mismatchSignals = checkAuthPageDomainMismatch(doc, hostname);
  const formSignals = checkSuspiciousFormAction(doc, hostname);
  const headerSignals = checkMissingSecurityHeaders(doc);
  const injectionSignals = checkDomInjectionArtifacts(doc, hostname);
  const timingSignals = checkResponseTimingAnomaly();

  const allSignals = [
    ...atSymbolSignals,
    ...mismatchSignals,
    ...formSignals,
    ...headerSignals,
    ...injectionSignals,
    ...timingSignals,
  ];

  const { riskScore, signalList } = calculateProxyRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const targetProvider = allSignals.find(s => s.targetProvider)?.targetProvider || null;
  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectProxyWarningBanner(riskScore, targetProvider, allSignals);

  // Emit telemetry
  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'PROXYGUARD_EVENT',
      payload: {
        eventType: 'PROXY_AITM_DETECTED',
        riskScore,
        severity,
        targetProvider,
        signals: signalList,
        url,
        timestamp: new Date().toISOString(),
        action,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError at parse time. Register this module's public API
// on a global namespace so vitest can side-effect-import the file and
// read functions from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports.proxy_guard = {
    checkAtSymbolUrlMasking,
    checkAuthPageDomainMismatch,
    checkSuspiciousFormAction,
    checkMissingSecurityHeaders,
    checkDomInjectionArtifacts,
    checkResponseTimingAnomaly,
    calculateProxyRiskScore,
    injectProxyWarningBanner,
    runProxyGuardAnalysis,
    isLegitAllowlistedHost,
  };
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof document !== 'undefined' && typeof process === 'undefined') {
  runProxyGuardAnalysis();
}

})();
