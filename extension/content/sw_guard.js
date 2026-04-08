/**
 * extension/content/sw_guard.js
 *
 * ServiceWorkerGuard — Phishing Persistence via Service Worker Registration
 *
 * Detects phishing pages that register Service Workers to persist credential
 * harvesting beyond tab closure. The SW can: (1) cache the phishing page for
 * offline replay, (2) intercept fetch events to relay credentials to C2
 * post-close, (3) use Push API to re-engage victims with fake notifications,
 * (4) use BackgroundSync for periodic C2 callbacks. Documented by SquareX
 * "Year of Browser Bugs" (2025); Mandiant M-Trends 2026 notes SW persistence
 * in watering-hole attacks.
 *
 * Injected at document_start to wrap ServiceWorkerContainer.prototype.register
 * before page scripts can cache a reference to the original API.
 *
 * Signal architecture:
 *   sw:register_on_credential_page        +0.40
 *   sw:fetch_handler_in_sw_script         +0.30
 *   sw:push_subscribe_with_cred_context   +0.25
 *   sw:cache_api_stores_credential_page   +0.20
 *   sw:background_sync_registration       +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module ServiceWorkerGuard
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const CREDENTIAL_SELECTORS =
  'input[type="password"], input[type="email"], ' +
  'input[autocomplete="current-password"], input[autocomplete="new-password"], ' +
  'input[autocomplete="username"]';

const FETCH_HANDLER_PATTERNS = [
  /addEventListener\s*\(\s*['"]fetch['"]/,
  /onfetch\s*=/,
  /self\.addEventListener\s*\(\s*['"]fetch['"]/,
];

const SUSPICIOUS_SW_PATTERNS = [
  /importScripts/,
  /clients\.matchAll/,
  /client\.postMessage/,
  /\.clone\(\)/,
];

/**
 * Known legitimate SW frameworks — if the SW script URL or source
 * contains one of these, reduce suspicion.
 */
const KNOWN_SW_FRAMEWORKS = [
  'workbox', 'firebase-messaging', 'OneSignal',
  'sw-precache', 'sw-toolbox', 'next-pwa',
  'serwist', 'vite-plugin-pwa',
];

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

const swRegistrations = [];  // { scriptUrl, scriptSource, isFramework }
let pushSubscribeCalled = false;
let backgroundSyncCalled = false;
const cachedUrls = [];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if a Service Worker was registered on a page with credential fields.
 */
function checkRegisterOnCredentialPage(doc, registrations) {
  if (!doc || !registrations || registrations.length === 0) return [];

  // Skip if all registrations are known frameworks
  const nonFramework = registrations.filter(r => !r.isFramework);
  if (nonFramework.length === 0) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length === 0) return [];

  return [{
    id: 'sw:register_on_credential_page',
    weight: 0.40,
    scriptUrl: nonFramework[0].scriptUrl,
    credFieldCount: credFields.length,
  }];
}

/**
 * Check if any registered SW script contains a fetch event handler,
 * indicating it can intercept and relay credential form submissions.
 */
function checkFetchHandlerInSwScript(registrations) {
  if (!registrations) return [];

  for (const reg of registrations) {
    if (reg.isFramework) continue;
    const source = reg.scriptSource || '';
    if (!source) continue;

    const hasFetchHandler = FETCH_HANDLER_PATTERNS.some(p => p.test(source));
    if (hasFetchHandler) {
      const suspiciousCount = SUSPICIOUS_SW_PATTERNS.filter(p => p.test(source)).length;
      return [{
        id: 'sw:fetch_handler_in_sw_script',
        weight: 0.30,
        scriptUrl: reg.scriptUrl,
        suspiciousPatternCount: suspiciousCount,
      }];
    }
  }

  return [];
}

/**
 * Check if PushManager.subscribe() was called alongside credential form context.
 */
function checkPushSubscribeWithCredContext(doc, didPushSubscribe) {
  if (!doc || !didPushSubscribe) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length === 0) return [];

  return [{
    id: 'sw:push_subscribe_with_cred_context',
    weight: 0.25,
  }];
}

/**
 * Check if Cache API stored URLs matching the current credential page.
 */
function checkCacheApiStoresCredentialPage(cached, currentUrl, doc) {
  if (!cached || cached.length === 0 || !currentUrl || !doc) return [];

  const credFields = doc.querySelectorAll(CREDENTIAL_SELECTORS);
  if (credFields.length === 0) return [];

  // Check if any cached URL matches or contains the current page URL
  const currentPath = currentUrl.split('?')[0]; // Strip query params
  const match = cached.some(url => {
    const cachedPath = url.split('?')[0];
    return cachedPath === currentPath || currentPath.startsWith(cachedPath);
  });

  if (match) {
    return [{
      id: 'sw:cache_api_stores_credential_page',
      weight: 0.20,
      cachedUrl: currentPath,
    }];
  }

  return [];
}

/**
 * Check if BackgroundSync was registered (periodic C2 callback capability).
 */
function checkBackgroundSyncRegistration(didBackgroundSync) {
  if (!didBackgroundSync) return [];

  return [{
    id: 'sw:background_sync_registration',
    weight: 0.15,
  }];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateSwRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectSwWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-sw-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-sw-banner';
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
        suspicious service worker detected \u2014 phishops swguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('sw:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-sw-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-sw-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run full ServiceWorkerGuard analysis.
 */
function runSwGuardAnalysis(doc, registrations, didPushSubscribe, didBackgroundSync, cached, currentUrl) {
  if (!doc || !registrations || registrations.length === 0) return;

  const registerSignals = checkRegisterOnCredentialPage(doc, registrations);
  // Only continue if SW registered on a credential page
  if (registerSignals.length === 0) return;

  const fetchSignals = checkFetchHandlerInSwScript(registrations);
  const pushSignals = checkPushSubscribeWithCredContext(doc, didPushSubscribe);
  const cacheSignals = checkCacheApiStoresCredentialPage(cached, currentUrl, doc);
  const syncSignals = checkBackgroundSyncRegistration(didBackgroundSync);

  const allSignals = [
    ...registerSignals,
    ...fetchSignals,
    ...pushSignals,
    ...cacheSignals,
    ...syncSignals,
  ];

  const { riskScore, signalList } = calculateSwRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectSwWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'SWGUARD_EVENT',
      payload: {
        eventType: 'SERVICE_WORKER_PERSISTENCE_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: currentUrl || '',
        timestamp: new Date().toISOString(),
        action,
        swScriptUrl: registrations[0]?.scriptUrl || '',
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Framework Detection                                                */
/* ------------------------------------------------------------------ */

/**
 * Check if a SW script URL or source matches known legitimate frameworks.
 */
function isKnownFramework(scriptUrl, scriptSource) {
  const combined = (scriptUrl || '') + ' ' + (scriptSource || '');
  const lower = combined.toLowerCase();
  return KNOWN_SW_FRAMEWORKS.some(fw => lower.includes(fw.toLowerCase()));
}

/* ------------------------------------------------------------------ */
/*  Service Worker Proxy Installer                                     */
/* ------------------------------------------------------------------ */

/**
 * Install ServiceWorker proxy at document_start.
 */
function installServiceWorkerProxy() {
  if (typeof navigator === 'undefined') return;

  // Wrap ServiceWorkerContainer.prototype.register
  if (navigator.serviceWorker) {
    const originalRegister = navigator.serviceWorker.register?.bind(navigator.serviceWorker);
    if (originalRegister) {
      navigator.serviceWorker.register = async function(scriptUrl, options) {
        const urlStr = String(scriptUrl);

        // Attempt to fetch and scan the SW script
        let scriptSource = '';
        let framework = false;
        try {
          const resp = await fetch(urlStr, { mode: 'same-origin' });
          if (resp.ok) {
            scriptSource = await resp.text();
          }
        } catch { /* cross-origin or network error — non-critical */ }

        framework = isKnownFramework(urlStr, scriptSource);

        swRegistrations.push({
          scriptUrl: urlStr,
          scriptSource,
          isFramework: framework,
        });

        // Pass through to original
        const registration = await originalRegister(scriptUrl, options);

        // Run analysis after DOM is ready
        if (typeof document !== 'undefined' && document.readyState !== 'loading') {
          runSwGuardAnalysis(
            document, swRegistrations, pushSubscribeCalled,
            backgroundSyncCalled, cachedUrls,
            globalThis.location?.href || '',
          );
        }

        return registration;
      };
    }
  }

  // Wrap PushManager.prototype.subscribe
  if (typeof PushManager !== 'undefined' && PushManager.prototype?.subscribe) {
    const originalPushSubscribe = PushManager.prototype.subscribe;
    PushManager.prototype.subscribe = function(...args) {
      pushSubscribeCalled = true;
      return originalPushSubscribe.apply(this, args);
    };
  }

  // Wrap SyncManager.prototype.register
  if (typeof SyncManager !== 'undefined' && SyncManager.prototype?.register) {
    const originalSyncRegister = SyncManager.prototype.register;
    SyncManager.prototype.register = function(...args) {
      backgroundSyncCalled = true;
      return originalSyncRegister.apply(this, args);
    };
  }

  // Wrap Cache.prototype.put and Cache.prototype.add
  if (typeof Cache !== 'undefined') {
    if (Cache.prototype?.put) {
      const originalPut = Cache.prototype.put;
      Cache.prototype.put = function(request, ...args) {
        const url = typeof request === 'string' ? request : request?.url || '';
        if (url) cachedUrls.push(url);
        return originalPut.call(this, request, ...args);
      };
    }
    if (Cache.prototype?.add) {
      const originalAdd = Cache.prototype.add;
      Cache.prototype.add = function(request) {
        const url = typeof request === 'string' ? request : request?.url || '';
        if (url) cachedUrls.push(url);
        return originalAdd.call(this, request);
      };
    }
  }

  // Run analysis on DOMContentLoaded
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      // Also check pre-existing registrations
      if (navigator.serviceWorker?.getRegistrations) {
        navigator.serviceWorker.getRegistrations().then(async (regs) => {
          for (const reg of regs) {
            const sw = reg.active || reg.installing || reg.waiting;
            if (!sw) continue;
            const urlStr = sw.scriptURL || '';

            // Skip if already tracked
            if (swRegistrations.some(r => r.scriptUrl === urlStr)) continue;

            let scriptSource = '';
            let framework = false;
            try {
              const resp = await fetch(urlStr, { mode: 'same-origin' });
              if (resp.ok) scriptSource = await resp.text();
            } catch { /* non-critical */ }

            framework = isKnownFramework(urlStr, scriptSource);
            swRegistrations.push({ scriptUrl: urlStr, scriptSource, isFramework: framework });
          }

          runSwGuardAnalysis(
            document, swRegistrations, pushSubscribeCalled,
            backgroundSyncCalled, cachedUrls,
            globalThis.location?.href || '',
          );
        }).catch(() => {});
      } else {
        runSwGuardAnalysis(
          document, swRegistrations, pushSubscribeCalled,
          backgroundSyncCalled, cachedUrls,
          globalThis.location?.href || '',
        );
      }
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

function _getSwRegistrations() {
  return swRegistrations;
}

function _resetState() {
  swRegistrations.length = 0;
  pushSubscribeCalled = false;
  backgroundSyncCalled = false;
  cachedUrls.length = 0;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installServiceWorkerProxy();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['sw_guard'] = {
    checkRegisterOnCredentialPage,
    checkFetchHandlerInSwScript,
    checkPushSubscribeWithCredContext,
    checkCacheApiStoresCredentialPage,
    checkBackgroundSyncRegistration,
    calculateSwRiskScore,
    injectSwWarningBanner,
    runSwGuardAnalysis,
    isKnownFramework,
    installServiceWorkerProxy,
    _getSwRegistrations,
    _resetState,
  };
}

})();
