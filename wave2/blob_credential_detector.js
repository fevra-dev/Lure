/**
 * packages/extension/dataegress/blob_credential_detector.js
 *
 * DataEgressMonitor — HTML smuggling terminal page detector.
 * Injected programmatically into blob: scheme navigations at document_start.
 *
 * Attack chain this closes:
 *   ProxyGuard (Wave 1) detects the *loader* page that calls atob()+createObjectURL().
 *   THIS script detects the *terminal* page — the credential-harvesting HTML document
 *   that the loader navigated the victim to via a blob: URL. The two detectors cover
 *   opposite ends of the same kill chain:
 *
 *     [Delivery site]  →  atob()+Blob loader  →  blob:uuid/...  →  [Fake login page]
 *       ProxyGuard                                              THIS SCRIPT
 *       (response body)                                         (DOM inspection)
 *
 *   The blob: URL is ephemeral (cleared on tab close), never appears in network logs,
 *   and is never submitted to Safe Browsing URL checks. The only detection point is
 *   inside the running page — which is where a content script lives.
 *
 * Detection model:
 *   Additive signal scoring across four categories:
 *     1. Credential fields    — password inputs in a blob: page context
 *     2. Brand impersonation  — page text/title matches known high-value brands
 *     3. Nested smuggling     — script tags contain further atob()/Blob calls
 *     4. Exfiltration form    — form action or JS patterns pointing to external URL
 *
 *   Alert threshold:  >= 0.65 (emit BLOB_URL_CREDENTIAL_PAGE event)
 *   Disable threshold: >= 0.80 (disable password fields + show warning banner)
 *
 * Communication:
 *   Uses chrome.runtime.sendMessage() → background service worker → emitTelemetry()
 *   Falls back to console.warn if runtime is unavailable (test environment).
 *
 * References:
 *   - Mandiant 2025: HTML smuggling used by NOBELIUM, TA4557, GhostSpider
 *   - Microsoft MSTIC: ISO/HTML smuggling for RAT delivery (2024–2025)
 *   - SquareX YOBB 2025: blob: URL as phishing delivery mechanism
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** High-value brand names commonly impersonated in HTML smuggling phishing pages. */
const BRAND_KEYWORDS = [
  'microsoft', 'outlook', 'office 365', 'onedrive', 'sharepoint', 'azure',
  'google', 'gmail', 'google drive', 'google workspace',
  'apple', 'icloud', 'apple id',
  'amazon', 'aws', 'amazon web services',
  'paypal', 'docusign', 'dropbox', 'salesforce',
  'linkedin', 'facebook', 'instagram',
  'chase', 'wellsfargo', 'bank of america', 'citibank',
  // Generic credential-harvesting lures
  'verify your identity', 'confirm your account', 'security alert',
  'account suspended', 'unusual sign-in', 'action required',
];

/** Nested smuggling patterns — presence in blob: page scripts indicates a second-stage loader. */
const NESTED_SMUGGLING_PATTERNS = [
  /\batob\s*\(/i,
  /createObjectURL\s*\(/i,
  /new\s+Blob\s*\(/i,
];

/** External URL pattern — form action or fetch pointing outside the blob: origin. */
const EXTERNAL_URL_PATTERN = /^https?:\/\//i;

/** Scoring thresholds */
const ALERT_THRESHOLD = 0.65;
const DISABLE_THRESHOLD = 0.80;

// ---------------------------------------------------------------------------
// Core detection functions (exported for unit testing)
// ---------------------------------------------------------------------------

/**
 * Count password-type input fields in the current document.
 * Includes hidden password fields (display:none) — attackers use these to
 * collect credentials before showing them to the user.
 *
 * @returns {number}
 */
export function countPasswordFields() {
  return document.querySelectorAll('input[type="password"], input[type=password]').length;
}

/**
 * Check page text, title, and meta tags for brand impersonation keywords.
 *
 * @returns {{ matched: boolean, matchedBrands: string[] }}
 */
export function checkBrandKeywords() {
  // Collect all inspectable text sources
  const textSources = [
    document.title || '',
    document.body?.innerText?.substring(0, 5000) || '',  // cap at 5KB
    ...[...document.querySelectorAll('meta[name], meta[property]')]
      .map(m => m.getAttribute('content') || ''),
    ...[...document.querySelectorAll('h1, h2, h3, label, button')]
      .map(el => el.textContent || ''),
  ].join(' ').toLowerCase();

  const matchedBrands = BRAND_KEYWORDS.filter(brand => textSources.includes(brand));

  return {
    matched: matchedBrands.length > 0,
    matchedBrands: [...new Set(matchedBrands)].slice(0, 5),  // deduplicate, cap
  };
}

/**
 * Check inline script tags for nested HTML smuggling patterns.
 * Indicates a second-stage loader is embedded in the phishing page,
 * ready to deliver a further payload.
 *
 * @returns {{ detected: boolean, patternCount: number }}
 */
export function checkNestedSmuggling() {
  const scripts = [...document.querySelectorAll('script:not([src])')];
  let patternCount = 0;

  for (const script of scripts) {
    const content = script.textContent || '';
    for (const pattern of NESTED_SMUGGLING_PATTERNS) {
      if (pattern.test(content)) {
        patternCount++;
        break;  // Count each script at most once per loop
      }
    }
  }

  return {
    detected: patternCount > 0,
    patternCount,
  };
}

/**
 * Check form action attributes for external exfiltration endpoints.
 * A form action pointing to an https:// URL in a blob: page is a
 * near-certain credential exfiltration indicator.
 *
 * @returns {{ detected: boolean, externalActions: string[] }}
 */
export function checkFormExfiltration() {
  const forms = [...document.querySelectorAll('form')];
  const externalActions = forms
    .map(f => f.getAttribute('action') || '')
    .filter(action => EXTERNAL_URL_PATTERN.test(action))
    .slice(0, 3);  // cap at 3 for payload size

  return {
    detected: externalActions.length > 0,
    externalActions,
  };
}

/**
 * Calculate composite risk score from individual signal results.
 * Returns a score in [0.0, 1.0] and a populated signals array.
 *
 * Score composition:
 *   Password field present:      +0.50  (base — any credential field in blob: is suspicious)
 *   Second password field:       +0.10  (confirm/re-enter pattern)
 *   Brand keyword match:         +0.20  (impersonation)
 *   Nested smuggling pattern:    +0.20  (second-stage loader)
 *   External form action:        +0.15  (explicit exfil endpoint)
 *
 * @param {Object} signals
 * @param {number} signals.passwordFieldCount
 * @param {string[]} signals.matchedBrands
 * @param {boolean} signals.nestedSmugglingDetected
 * @param {number}  signals.nestedPatternCount
 * @param {boolean} signals.formExfiltrationDetected
 * @param {string[]} signals.externalActions
 * @returns {{ riskScore: number, signalList: string[] }}
 */
export function calculateRiskScore({
  passwordFieldCount,
  matchedBrands,
  nestedSmugglingDetected,
  nestedPatternCount,
  formExfiltrationDetected,
  externalActions,
}) {
  let score = 0.0;
  const signalList = [];

  if (passwordFieldCount >= 1) {
    score += 0.50;
    signalList.push(`credential_field_present:count=${passwordFieldCount}`);
  }
  if (passwordFieldCount >= 2) {
    score += 0.10;
    signalList.push('multiple_credential_fields');
  }
  if (matchedBrands.length > 0) {
    score += 0.20;
    signalList.push(`brand_impersonation:${matchedBrands.slice(0, 3).join(',')}`);
  }
  if (nestedSmugglingDetected) {
    score += 0.20;
    signalList.push(`nested_smuggling:${nestedPatternCount}_scripts`);
  }
  if (formExfiltrationDetected) {
    score += 0.15;
    signalList.push(`external_form_action:${externalActions[0]?.substring(0, 80) || 'unknown'}`);
  }

  return {
    riskScore: Math.round(Math.min(score, 1.0) * 100) / 100,
    signalList,
  };
}

// ---------------------------------------------------------------------------
// Field disabler
// ---------------------------------------------------------------------------

/**
 * Disable all password fields and inject a visible warning on each.
 * Called when riskScore >= DISABLE_THRESHOLD.
 * Prevents credentials from being entered and submitted even if the user
 * ignores the warning banner.
 *
 * @param {number} riskScore
 */
export function disableCredentialFields(riskScore) {
  const fields = document.querySelectorAll('input[type="password"], input[type=password]');

  fields.forEach(field => {
    field.disabled = true;
    field.placeholder = '⚠ Blocked by PhishOps — HTML smuggling detected';
    field.style.cssText = 'border: 2px solid #e63946 !important; background: #2a0a0a !important; color: #e63946 !important;';

    console.warn('[BLOB_DETECTOR] Credential field disabled risk=%.2f', riskScore);
  });

  injectWarningBanner(riskScore);
}

/**
 * Inject a persistent warning banner at the top of the blob: page.
 * Uses inline styles scoped to avoid conflicts with page CSS.
 *
 * @param {number} riskScore
 */
export function injectWarningBanner(riskScore) {
  // Idempotent — don't inject twice
  if (document.getElementById('phishops-blob-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-blob-warning';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #1a0a0a; border-bottom: 3px solid #e63946;
    padding: 14px 20px; font-family: system-ui, -apple-system, sans-serif;
    display: flex; align-items: center; gap: 14px; box-shadow: 0 4px 20px rgba(230,57,70,0.5);
  `;

  banner.innerHTML = `
    <span style="font-size: 24px; flex-shrink:0;">🛡️</span>
    <div style="flex:1;">
      <strong style="color:#e63946; font-size:15px; display:block; margin-bottom:3px;">
        HTML Smuggling Attack Blocked — PhishOps DataEgressMonitor
      </strong>
      <span style="color:#ccc; font-size:13px;">
        This page was delivered via a <code style="color:#e63946;">blob:</code> URL —
        a technique used to bypass gateway security filters.
        Credential fields have been disabled. Risk score: ${riskScore.toFixed(2)}.
      </span>
    </div>
    <button id="phishops-blob-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #555; border-radius:6px; color:#aaa;
      cursor:pointer; font-size:13px;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-blob-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

// ---------------------------------------------------------------------------
// Telemetry emitter
// ---------------------------------------------------------------------------

/**
 * Send detection result to the background service worker.
 * The background worker routes this to emitTelemetry() → BrowserPhishingTelemetry_CL.
 *
 * @param {Object} payload
 */
function sendToBackground(payload) {
  try {
    // chrome.runtime is available in content scripts — including injected ones
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'BLOB_CREDENTIAL_DETECTED',
        payload,
      });
    } else {
      // Fallback for test environments where chrome APIs are mocked
      console.warn('[BLOB_DETECTOR] chrome.runtime unavailable — payload:', JSON.stringify(payload));
    }
  } catch (err) {
    console.error('[BLOB_DETECTOR] sendToBackground failed: %s', err);
  }
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

/**
 * Main entry point — runs at document_start on blob: pages.
 * Waits for DOMContentLoaded to ensure the DOM is fully constructed,
 * then runs all detection checks.
 *
 * @returns {Promise<Object>} Detection result (for testing)
 */
export async function runBlobDetection() {
  return new Promise((resolve) => {
    // Use DOMContentLoaded if document not yet ready; otherwise run immediately
    function run() {
      console.debug('[BLOB_DETECTOR] Starting detection on blob: page url=%s',
        window.location.href.substring(0, 60));

      try {
        // ---------------------------------------------------------------- //
        // Collect all signals
        // ---------------------------------------------------------------- //
        const passwordFieldCount = countPasswordFields();
        const { matched: brandMatched, matchedBrands } = checkBrandKeywords();
        const { detected: nestedSmuggling, patternCount: nestedPatternCount } = checkNestedSmuggling();
        const { detected: formExfiltration, externalActions } = checkFormExfiltration();

        console.debug(
          '[BLOB_DETECTOR] signals passwordFields=%d brandMatch=%s nested=%s formExfil=%s',
          passwordFieldCount, brandMatched, nestedSmuggling, formExfiltration,
        );

        // ---------------------------------------------------------------- //
        // Score
        // ---------------------------------------------------------------- //
        const { riskScore, signalList } = calculateRiskScore({
          passwordFieldCount,
          matchedBrands,
          nestedSmugglingDetected: nestedSmuggling,
          nestedPatternCount,
          formExfiltrationDetected: formExfiltration,
          externalActions,
        });

        console.debug('[BLOB_DETECTOR] risk_score=%.2f signals=%s', riskScore, signalList.join(', '));

        if (riskScore < ALERT_THRESHOLD) {
          console.debug('[BLOB_DETECTOR] below threshold — no action');
          resolve({ detected: false, riskScore, signals: signalList });
          return;
        }

        // ---------------------------------------------------------------- //
        // Alert
        // ---------------------------------------------------------------- //
        const result = {
          detected: true,
          riskScore,
          severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.80 ? 'High' : 'Medium',
          credentialFieldCount: passwordFieldCount,
          matchedBrands,
          nestedSmugglingDetected: nestedSmuggling,
          formExfiltrationDetected: formExfiltration,
          externalActions,
          signals: signalList,
          blobUrl: window.location.href.substring(0, 100),
          pageTitle: document.title?.substring(0, 100) || '',
          timestamp: new Date().toISOString(),
        };

        console.warn(
          '[BLOB_DETECTOR] ALERT BLOB_URL_CREDENTIAL_PAGE riskScore=%.2f severity=%s signals=%s',
          riskScore, result.severity, signalList.join(', '),
        );

        // ---------------------------------------------------------------- //
        // Mitigate: disable fields above DISABLE_THRESHOLD
        // ---------------------------------------------------------------- //
        if (riskScore >= DISABLE_THRESHOLD && passwordFieldCount > 0) {
          disableCredentialFields(riskScore);
          console.warn('[BLOB_DETECTOR] Credential fields disabled riskScore=%.2f', riskScore);
        } else if (riskScore >= ALERT_THRESHOLD) {
          // Alert-only tier: inject banner but don't disable fields
          injectWarningBanner(riskScore);
        }

        // ---------------------------------------------------------------- //
        // Telemetry
        // ---------------------------------------------------------------- //
        sendToBackground(result);

        resolve(result);

      } catch (err) {
        console.error('[BLOB_DETECTOR] unexpected error: %s', err);
        resolve({ detected: false, riskScore: 0.0, signals: ['detector_error'], error: String(err) });
      }
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', run, { once: true });
    } else {
      run();
    }
  });
}

// Auto-run when injected as a content script (not in test environment)
if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  runBlobDetection();
}
