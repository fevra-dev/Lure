/**
 * extension/content/blob_credential_detector.js
 *
 * DataEgressMonitor — HTML smuggling terminal page detector.
 * Injected programmatically into blob: scheme navigations at document_start.
 *
 * Attack chain this closes:
 *   ProxyGuard (Wave 1) detects the *loader* page that calls atob()+createObjectURL().
 *   THIS script detects the *terminal* page — the credential-harvesting HTML document
 *   that the loader navigated the victim to via a blob: URL.
 *
 * Detection model: Additive signal scoring across four categories:
 *   1. Credential fields    — password inputs in a blob: page context
 *   2. Brand impersonation  — page text/title matches known high-value brands
 *   3. Nested smuggling     — script tags contain further atob()/Blob calls
 *   4. Exfiltration form    — form action pointing to external URL
 *
 * References:
 *   - Mandiant 2025: HTML smuggling used by NOBELIUM, TA4557, GhostSpider
 *   - SquareX YOBB 2025: blob: URL as phishing delivery mechanism
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BRAND_KEYWORDS = [
  'microsoft', 'outlook', 'office 365', 'onedrive', 'sharepoint', 'azure',
  'google', 'gmail', 'google drive', 'google workspace',
  'apple', 'icloud', 'apple id',
  'amazon', 'aws', 'amazon web services',
  'paypal', 'docusign', 'dropbox', 'salesforce',
  'linkedin', 'facebook', 'instagram',
  'chase', 'wellsfargo', 'bank of america', 'citibank',
  'verify your identity', 'confirm your account', 'security alert',
  'account suspended', 'unusual sign-in', 'action required',
];

const NESTED_SMUGGLING_PATTERNS = [
  /\batob\s*\(/i,
  /createObjectURL\s*\(/i,
  /new\s+Blob\s*\(/i,
];

const EXTERNAL_URL_PATTERN = /^https?:\/\//i;
const ALERT_THRESHOLD = 0.65;
const DISABLE_THRESHOLD = 0.80;

// ---------------------------------------------------------------------------
// Core detection functions (exported for unit testing)
// ---------------------------------------------------------------------------

function countPasswordFields() {
  return document.querySelectorAll('input[type="password"], input[type=password]').length;
}

function checkBrandKeywords() {
  const textSources = [
    document.title || '',
    document.body?.innerText?.substring(0, 5000) || '',
    ...[...document.querySelectorAll('meta[name], meta[property]')]
      .map(m => m.getAttribute('content') || ''),
    ...[...document.querySelectorAll('h1, h2, h3, label, button')]
      .map(el => el.textContent || ''),
  ].join(' ').toLowerCase();

  const matchedBrands = BRAND_KEYWORDS.filter(brand => textSources.includes(brand));

  return {
    matched: matchedBrands.length > 0,
    matchedBrands: [...new Set(matchedBrands)].slice(0, 5),
  };
}

function checkNestedSmuggling() {
  const scripts = [...document.querySelectorAll('script:not([src])')];
  let patternCount = 0;

  for (const script of scripts) {
    const content = script.textContent || '';
    for (const pattern of NESTED_SMUGGLING_PATTERNS) {
      if (pattern.test(content)) {
        patternCount++;
        break;
      }
    }
  }

  return {
    detected: patternCount > 0,
    patternCount,
  };
}

function checkFormExfiltration() {
  const forms = [...document.querySelectorAll('form')];
  const externalActions = forms
    .map(f => f.getAttribute('action') || '')
    .filter(action => EXTERNAL_URL_PATTERN.test(action))
    .slice(0, 3);

  return {
    detected: externalActions.length > 0,
    externalActions,
  };
}

function calculateRiskScore({
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

function disableCredentialFields(riskScore) {
  const fields = document.querySelectorAll('input[type="password"], input[type=password]');

  fields.forEach(field => {
    field.disabled = true;
    field.placeholder = '\u26A0 Blocked by PhishOps \u2014 HTML smuggling detected';
    field.style.cssText = 'border: 2px solid #BF1B1B !important; background: #1A0F0F !important; color: #BF1B1B !important;';
  });

  injectWarningBanner(riskScore);
}

function injectWarningBanner(riskScore) {
  if (document.getElementById('phishops-blob-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'phishops-blob-warning';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #0A0907; border-bottom: 2px solid #BF1B1B;
    padding: 14px 20px; font-family: 'Work Sans', system-ui, -apple-system, sans-serif;
    display: flex; align-items: center; gap: 14px;
  `;

  banner.innerHTML = `
    <span style="font-size: 24px; flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B; font-size:15px; display:block; margin-bottom:3px; font-family:'Work Sans',system-ui,sans-serif;">
        html smuggling attack blocked \u2014 phishops dataegressmonitor
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        This page was delivered via a <code style="color:#BF1B1B;">blob:</code> URL \u2014
        a technique used to bypass gateway security filters.
        Credential fields have been disabled. Risk score: ${riskScore.toFixed(2)}.
      </span>
    </div>
    <button id="phishops-blob-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
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

function sendToBackground(payload) {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'BLOB_CREDENTIAL_DETECTED',
        payload,
      });
    } else {
      console.warn('[BLOB_DETECTOR] chrome.runtime unavailable \u2014 payload:', JSON.stringify(payload));
    }
  } catch (err) {
    console.error('[BLOB_DETECTOR] sendToBackground failed: %s', err);
  }
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

async function runBlobDetection() {
  return new Promise((resolve) => {
    function run() {
      try {
        const passwordFieldCount = countPasswordFields();
        const { matched: brandMatched, matchedBrands } = checkBrandKeywords();
        const { detected: nestedSmuggling, patternCount: nestedPatternCount } = checkNestedSmuggling();
        const { detected: formExfiltration, externalActions } = checkFormExfiltration();

        const { riskScore, signalList } = calculateRiskScore({
          passwordFieldCount,
          matchedBrands,
          nestedSmugglingDetected: nestedSmuggling,
          nestedPatternCount,
          formExfiltrationDetected: formExfiltration,
          externalActions,
        });

        if (riskScore < ALERT_THRESHOLD) {
          resolve({ detected: false, riskScore, signals: signalList });
          return;
        }

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

        if (riskScore >= DISABLE_THRESHOLD && passwordFieldCount > 0) {
          disableCredentialFields(riskScore);
        } else if (riskScore >= ALERT_THRESHOLD) {
          injectWarningBanner(riskScore);
        }

        sendToBackground(result);
        resolve(result);

      } catch (err) {
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

// Auto-run when injected as a content script
if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  runBlobDetection();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== "undefined") {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports["blob_credential_detector"] = {
    countPasswordFields,
    checkBrandKeywords,
    checkNestedSmuggling,
    checkFormExfiltration,
    calculateRiskScore,
    disableCredentialFields,
    injectWarningBanner,    runBlobDetection,
  
  };
}

})();
