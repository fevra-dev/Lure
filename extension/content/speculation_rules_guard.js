/**
 * extension/content/speculation_rules_guard.js
 *
 * SpeculationRulesGuard — Speculation Rules API Phishing Detection
 *
 * Detects malicious use of the Speculation Rules API for phishing. Attackers
 * with XSS can inject <script type="speculationrules"> to prerender phishing
 * content on same-origin pages, making the URL bar show the legitimate domain
 * throughout. No prior security research documents this attack vector.
 *
 * Unique capabilities in the PhishOps suite:
 *   - MutationObserver-based collection (first detector to use this pattern)
 *   - Active defense: removes malicious <script type="speculationrules">
 *     elements at block threshold, cancelling the prerender in Chrome
 *   - Prerender lifecycle awareness: defers banner until prerenderingchange
 *
 * Injected at document_start in the isolated world. Static scan + MutationObserver
 * catch rules in initial HTML and dynamically injected rules. Analysis runs on
 * DOMContentLoaded + 2 s delay.
 *
 * Signal architecture:
 *   srg:cross_origin_prerender_rule       +0.40
 *   srg:cross_origin_eager_prefetch       +0.30
 *   srg:dynamic_rule_injection            +0.25
 *   srg:suspicious_url_pattern            +0.20
 *   srg:prerender_without_navigation      +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module SpeculationRulesGuard
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const SUSPICIOUS_URL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'logon',
  'auth', 'authenticate', 'credential', 'password',
  'verify', 'verification', 'account', 'secure',
  'mfa', '2fa', 'otp', 'token', 'confirm',
];

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

/**
 * Parsed speculation rule entries.
 * @type {{ action: string, urls: string[], eagerness: string, isDynamic: boolean, element: Element|null, timestamp: number }[]}
 */
const speculationRules = [];

let analysisRun = false;
let observer = null;

/* ------------------------------------------------------------------ */
/*  Helper Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if a URL is cross-origin relative to the page hostname.
 */
function isUrlCrossOrigin(url, pageOrigin) {
  if (!url || !pageOrigin) return false;

  try {
    const parsed = new URL(url, pageOrigin);
    const pageUrl = new URL(pageOrigin);
    return parsed.origin !== pageUrl.origin;
  } catch {
    return false;
  }
}

/**
 * Parse a <script type="speculationrules"> element into rule entries.
 * @param {Element} element - The script element
 * @param {boolean} isDynamic - Whether the element was dynamically injected
 * @returns {object[]} Parsed rule entries
 */
function parseSpeculationRules(element, isDynamic) {
  if (!element) return [];

  let json;
  try {
    json = JSON.parse(element.textContent || '');
  } catch {
    return [];
  }

  const entries = [];

  for (const action of ['prerender', 'prefetch']) {
    const ruleArray = json[action];
    if (!Array.isArray(ruleArray)) continue;

    for (const rule of ruleArray) {
      const urls = Array.isArray(rule.urls) ? rule.urls : [];
      const eagerness = rule.eagerness || 'conservative';

      entries.push({
        action,
        urls,
        eagerness,
        isDynamic: !!isDynamic,
        element,
        timestamp: Date.now(),
      });
    }
  }

  return entries;
}

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Signal 1: Cross-origin URL in prerender rules.
 * Weight: 0.40 — near-zero false positives. Chrome blocks cross-site prerender,
 * so cross-origin prerender rules are essentially nonexistent in legitimate traffic.
 */
function checkCrossOriginPrerenderRule(rules, pageOrigin) {
  if (!rules || rules.length === 0 || !pageOrigin) return [];

  for (const rule of rules) {
    if (rule.action !== 'prerender') continue;
    for (const url of rule.urls) {
      if (isUrlCrossOrigin(url, pageOrigin)) {
        return [{
          id: 'srg:cross_origin_prerender_rule',
          weight: 0.40,
          crossOriginUrl: url,
        }];
      }
    }
  }

  return [];
}

/**
 * Signal 2: Cross-origin prefetch with immediate or eager eagerness.
 * Weight: 0.30 — high eagerness cross-origin prefetch reduces user's window
 * to notice a domain change on navigation.
 */
function checkCrossOriginEagerPrefetch(rules, pageOrigin) {
  if (!rules || rules.length === 0 || !pageOrigin) return [];

  const highEagerness = new Set(['immediate', 'eager']);

  for (const rule of rules) {
    if (rule.action !== 'prefetch') continue;
    if (!highEagerness.has(rule.eagerness)) continue;
    for (const url of rule.urls) {
      if (isUrlCrossOrigin(url, pageOrigin)) {
        return [{
          id: 'srg:cross_origin_eager_prefetch',
          weight: 0.30,
          crossOriginUrl: url,
          eagerness: rule.eagerness,
        }];
      }
    }
  }

  return [];
}

/**
 * Signal 3: Speculation rules added dynamically via JavaScript.
 * Weight: 0.25 — dynamic injection is an XSS indicator. Legitimate speculation
 * rules are typically in the initial HTML or HTTP header.
 */
function checkDynamicRuleInjection(rules) {
  if (!rules || rules.length === 0) return [];

  const dynamicCount = rules.filter(r => r.isDynamic).length;
  if (dynamicCount === 0) return [];

  return [{
    id: 'srg:dynamic_rule_injection',
    weight: 0.25,
    dynamicCount,
  }];
}

/**
 * Signal 4: Rule targets URLs with login/auth/credential keywords.
 * Weight: 0.20 — suspicious URL patterns in speculation rule targets.
 */
function checkSuspiciousUrlPattern(rules) {
  if (!rules || rules.length === 0) return [];

  for (const rule of rules) {
    for (const url of rule.urls) {
      const urlLower = url.toLowerCase();
      for (const keyword of SUSPICIOUS_URL_KEYWORDS) {
        if (urlLower.includes(keyword)) {
          return [{
            id: 'srg:suspicious_url_pattern',
            weight: 0.20,
            matchedKeyword: keyword,
            url,
          }];
        }
      }
    }
  }

  return [];
}

/**
 * Signal 5: Prerender rules exist but no corresponding <a> links in the DOM.
 * Weight: 0.15 — orphaned prerender rules indicate the prerender exists purely
 * to pre-load content without user-visible navigation intent.
 */
function checkPrerenderWithoutNavigation(rules, doc) {
  if (!rules || rules.length === 0 || !doc) return [];

  const prerenderUrls = [];
  for (const rule of rules) {
    if (rule.action !== 'prerender') continue;
    prerenderUrls.push(...rule.urls);
  }

  if (prerenderUrls.length === 0) return [];

  const anchors = doc.querySelectorAll('a[href]');
  const anchorHrefs = new Set();
  for (const a of anchors) {
    try {
      anchorHrefs.add(new URL(a.href, doc.location?.href || '').href);
    } catch { /* invalid href */ }
  }

  let orphanedCount = 0;
  for (const url of prerenderUrls) {
    try {
      const resolved = new URL(url, doc.location?.href || '').href;
      if (!anchorHrefs.has(resolved)) orphanedCount++;
    } catch { /* invalid URL */ }
  }

  if (orphanedCount === 0) return [];

  return [{
    id: 'srg:prerender_without_navigation',
    weight: 0.15,
    orphanedCount,
  }];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateSrgRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Active Defense — Element Removal                                   */
/* ------------------------------------------------------------------ */

/**
 * Remove malicious <script type="speculationrules"> elements from the DOM.
 * Chrome cancels associated prerenders when the element is removed.
 * Only activates at BLOCK_THRESHOLD or above.
 */
function removeMaliciousRules(rules, riskScore) {
  if (riskScore < BLOCK_THRESHOLD) return 0;

  let removedCount = 0;
  const seen = new Set();

  for (const rule of rules) {
    if (!rule.element || seen.has(rule.element)) continue;
    seen.add(rule.element);

    try {
      if (rule.element.parentNode) {
        rule.element.remove();
        removedCount++;
      }
    } catch { /* non-critical */ }
  }

  return removedCount;
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectSrgWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-srg-banner')) return;

  // Defer banner if page is still in prerender state
  if (document.prerendering) {
    document.addEventListener('prerenderingchange', () => {
      injectSrgWarningBanner(riskScore, signals);
    }, { once: true });
    return;
  }

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-srg-banner';
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
        speculation rules phishing detected \u2014 phishops speculationrulesguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('srg:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-srg-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-srg-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run analysis on accumulated speculation rule entries.
 */
function runSrgAnalysis(doc, rules, pageOrigin) {
  if (!doc || !rules || rules.length === 0) return;

  const crossOriginPrerenderSignals = checkCrossOriginPrerenderRule(rules, pageOrigin);
  const crossOriginPrefetchSignals = checkCrossOriginEagerPrefetch(rules, pageOrigin);
  const dynamicInjectionSignals = checkDynamicRuleInjection(rules);
  const suspiciousUrlSignals = checkSuspiciousUrlPattern(rules);
  const orphanedPrerenderSignals = checkPrerenderWithoutNavigation(rules, doc);

  const allSignals = [
    ...crossOriginPrerenderSignals,
    ...crossOriginPrefetchSignals,
    ...dynamicInjectionSignals,
    ...suspiciousUrlSignals,
    ...orphanedPrerenderSignals,
  ];

  const { riskScore, signalList } = calculateSrgRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  // Active defense: remove malicious elements at block threshold
  const rulesRemoved = removeMaliciousRules(rules, riskScore);

  injectSrgWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'SPECULATIONRULESGUARD_EVENT',
      payload: {
        eventType: 'SPECULATION_RULES_PHISHING_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
        rulesRemoved,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  MutationObserver + Static Scan                                     */
/* ------------------------------------------------------------------ */

/**
 * Install the SpeculationRules monitor: static scan + MutationObserver.
 */
function installSpeculationRulesMonitor() {
  // Static scan: catch rules already in the HTML
  if (typeof document !== 'undefined') {
    const existing = document.querySelectorAll('script[type="speculationrules"]');
    for (const el of existing) {
      const entries = parseSpeculationRules(el, false);
      speculationRules.push(...entries);
    }
  }

  // Dynamic observation: catch rules injected by JS (XSS indicator)
  if (typeof MutationObserver !== 'undefined' && typeof document !== 'undefined') {
    observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (
            node.nodeType === 1 &&
            node.tagName === 'SCRIPT' &&
            node.type === 'speculationrules'
          ) {
            const entries = parseSpeculationRules(node, true);
            speculationRules.push(...entries);

            // Trigger immediate analysis if DOM is ready and we haven't run yet
            if (!analysisRun && document.readyState !== 'loading') {
              const pageOrigin = (typeof globalThis !== 'undefined' && globalThis.location?.href) || '';
              runSrgAnalysis(document, speculationRules, pageOrigin);
              analysisRun = true;
            }
          }
        }
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  // DOMContentLoaded + 2s delay for deferred analysis
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        if (!analysisRun && speculationRules.length > 0) {
          const pageOrigin = (typeof globalThis !== 'undefined' && globalThis.location?.href) || '';
          runSrgAnalysis(document, speculationRules, pageOrigin);
          analysisRun = true;
        }
      }, 2000);
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

function _getSpeculationRules() {
  return speculationRules;
}

function _resetState() {
  speculationRules.length = 0;
  analysisRun = false;
  if (observer) {
    observer.disconnect();
    observer = null;
  }
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installSpeculationRulesMonitor();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['speculation_rules_guard'] = {
    isUrlCrossOrigin,
    parseSpeculationRules,
    checkCrossOriginPrerenderRule,
    checkCrossOriginEagerPrefetch,
    checkDynamicRuleInjection,
    checkSuspiciousUrlPattern,
    checkPrerenderWithoutNavigation,
    calculateSrgRiskScore,
    removeMaliciousRules,
    injectSrgWarningBanner,
    runSrgAnalysis,
    installSpeculationRulesMonitor,
    _getSpeculationRules,
    _resetState,
  };
}
