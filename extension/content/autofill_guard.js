/**
 * extension/content/autofill_guard.js
 *
 * AutofillGuard — Detects autofill credential harvesting attacks.
 *
 * Two attack vectors covered:
 *
 *   Vector 1: Hidden Field Harvest (Kuosmanen 2017 / Princeton 2018)
 *     Credential fields hidden via CSS (display:none, visibility:hidden, opacity:0,
 *     zero-size, off-screen, clip-path, transform:scale(0)) that harvest autofilled
 *     credentials on form submission.
 *
 *   Vector 2: DOM-based Extension Clickjacking (Toth 2025, DEF CON 33)
 *     Page-level opacity/overlay manipulation that makes the password manager's
 *     autofill UI invisible, tricking the user into clicking it unknowingly.
 *     Affects 18-20M unpatched 1Password/LastPass users (Jan 2026).
 *
 * Performance strategy:
 *   - Quick bail-out: if no credential fields exist, only a lightweight Tier 1
 *     MutationObserver watches for password input additions.
 *   - Tier 2 (full monitoring) activates only when credential fields are present.
 *   - Periodic clickjacking audit runs every 5s, paused when tab is hidden.
 *   - Form submit interception on capture phase prevents exfiltration.
 *
 * References:
 *   - marektoth.com/blog/dom-based-extension-clickjacking/ (primary source)
 *   - Princeton 2018: invisible login field ad-network email harvesting
 *   - Kuosmanen 2017: browser autofill phishing via hidden fields
 */

'use strict';

/* __IIFE_WRAPPED__ */
(function () {

// Provided by lib/shadow_dom_utils.js (loaded earlier in manifest as a
// classic content script — registers on globalThis.__phishopsLib).
const deepQuerySelectorAll = (typeof globalThis !== 'undefined' && globalThis.__phishopsLib?.deepQuerySelectorAll)
  || ((sel, root = document) => Array.from((root || document).querySelectorAll(sel)));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALERT_THRESHOLD = 0.50;
const DISABLE_THRESHOLD = 0.70;

/** CSS selector for credential fields. */
const CREDENTIAL_SELECTOR = [
  'input[type="password"]',
  'input[type=password]',
  'input[autocomplete="current-password"]',
  'input[autocomplete="new-password"]',
].join(', ');

/** Max ancestor levels to walk for inherited hiding styles. */
const MAX_ANCESTOR_DEPTH = 5;

/** Known OAuth endpoints — suppress hidden field signals on OAuth redirect forms. */
const OAUTH_ENDPOINTS = [
  'login.microsoftonline.com', 'accounts.google.com', 'login.live.com',
  'auth.apple.com', 'github.com', 'login.salesforce.com', 'login.okta.com',
];

// ---------------------------------------------------------------------------
// Vector 1: Hidden Field Detection (per-field)
// ---------------------------------------------------------------------------

/**
 * Get all credential fields on the page.
 * @returns {Element[]}
 */
function getCredentialFields() {
  return deepQuerySelectorAll(CREDENTIAL_SELECTOR, document);
}

/**
 * Check a single field for visibility-hiding CSS techniques.
 * Returns an array of signal objects { id, weight }.
 *
 * @param {Element} field
 * @returns {{ id: string, weight: number }[]}
 */
function getFieldVisibilitySignals(field) {
  const signals = [];

  // Check field and ancestors for hiding styles
  let el = field;
  let depth = 0;

  while (el && el !== document.documentElement && depth <= MAX_ANCESTOR_DEPTH) {
    const style = el.style;
    const computed = window.getComputedStyle ? window.getComputedStyle(el) : null;

    // display:none
    if ((computed?.display === 'none') || style.display === 'none') {
      signals.push({ id: 'hidden_field:display_none', weight: 0.40 });
      break; // No need to check further ancestors
    }

    // visibility:hidden
    if ((computed?.visibility === 'hidden') || style.visibility === 'hidden') {
      signals.push({ id: 'hidden_field:visibility_hidden', weight: 0.40 });
      break;
    }

    // opacity:0 (check field + up to MAX_ANCESTOR_DEPTH ancestors)
    const opacity = parseFloat(computed?.opacity ?? style.opacity);
    if (opacity === 0 || (computed?.opacity === '0') || style.opacity === '0') {
      signals.push({ id: 'hidden_field:opacity_zero', weight: 0.35 });
      break;
    }

    // transform:scale(0)
    const transform = computed?.transform || style.transform || '';
    if (/scale\s*\(\s*0\s*[\s,)]/i.test(transform) || transform === 'scale(0)') {
      signals.push({ id: 'hidden_field:transform_zero', weight: 0.30 });
      break;
    }

    // clip-path / clip (only on the field itself or immediate container)
    if (depth <= 1) {
      const clipPath = computed?.clipPath || style.clipPath || '';
      const clip = computed?.clip || style.clip || '';
      if (clipPath === 'inset(100%)' || clip === 'rect(0, 0, 0, 0)' ||
          clip === 'rect(0px, 0px, 0px, 0px)' || clipPath === 'inset(100% 100% 100% 100%)') {
        signals.push({ id: 'hidden_field:clip_hidden', weight: 0.30 });
        break;
      }
    }

    el = el.parentElement;
    depth++;
  }

  // Zero-size check (field only)
  const rect = field.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) {
    // Only flag if not already caught by display:none (which also causes zero rect)
    if (!signals.some(s => s.id === 'hidden_field:display_none')) {
      signals.push({ id: 'hidden_field:zero_size', weight: 0.35 });
    }
  }

  // Off-screen check
  if (rect.width > 0 && rect.height > 0) {
    const vw = window.innerWidth || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    if (rect.right < 0 || rect.bottom < 0 || rect.left > vw || rect.top > vh) {
      signals.push({ id: 'hidden_field:offscreen', weight: 0.35 });
    }
  } else if (rect.width === 0 && rect.height === 0) {
    // getBoundingClientRect returns all zeros in some environments (jsdom)
    // Fall back to inline style position check
    const pos = field.style?.position || '';
    const left = parseInt(field.style?.left, 10);
    const top = parseInt(field.style?.top, 10);
    if (pos && (left < -1000 || top < -1000 || left > 10000 || top > 10000)) {
      signals.push({ id: 'hidden_field:offscreen', weight: 0.35 });
    }
  }

  return signals;
}

// ---------------------------------------------------------------------------
// False Positive Suppression
// ---------------------------------------------------------------------------

/**
 * Check if a hidden credential field is likely a false positive.
 *
 * @param {Element} field
 * @param {Element|null} form - the field's parent form (if any)
 * @returns {boolean}
 */
function isLikelyFalsePositive(field, form) {
  // 1. Show/hide password toggle: adjacent button/label with reveal-like text
  const togglePattern = /\b(show|hide|eye|toggle|reveal|unmask)\b/i;
  const siblings = field.parentElement?.children || [];
  for (const sibling of siblings) {
    if (sibling === field) continue;
    const tag = sibling.tagName?.toLowerCase();
    if ((tag === 'button' || tag === 'label' || tag === 'span' || tag === 'a' ||
         sibling.getAttribute('role') === 'button') &&
        togglePattern.test(sibling.textContent || '')) {
      return true;
    }
  }

  // Also check aria-describedby pointing to a toggle element
  const describedBy = field.getAttribute('aria-describedby');
  if (describedBy) {
    const descEl = document.getElementById(describedBy);
    if (descEl && togglePattern.test(descEl.textContent || '')) {
      return true;
    }
  }

  // 2. Multi-step form: field is in a non-active tab/step
  const stepContainer = field.closest('[data-step], [role="tabpanel"], .step, .form-step');
  if (stepContainer) {
    const style = window.getComputedStyle ? window.getComputedStyle(stepContainer) : stepContainer.style;
    // If the step container itself is hidden, the field hiding is likely intentional multi-step
    if (style?.display === 'none' || style?.visibility === 'hidden' ||
        stepContainer.getAttribute('aria-hidden') === 'true' ||
        stepContainer.hidden) {
      return true;
    }
  }

  // 3. OAuth redirect form: form action matches known OAuth endpoint
  if (form) {
    const action = form.getAttribute('action') || '';
    try {
      const actionUrl = new URL(action, window.location.href);
      if (OAUTH_ENDPOINTS.some(ep => actionUrl.hostname === ep ||
          actionUrl.hostname.endsWith('.' + ep))) {
        return true;
      }
    } catch (_) { /* not a valid URL */ }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Vector 2: Extension Clickjacking Detection (page-level)
// ---------------------------------------------------------------------------

/**
 * Check for page-level clickjacking signals that make password manager
 * UI invisible.
 *
 * @returns {{ id: string, weight: number }[]}
 */
function checkClickjackingSignals() {
  const signals = [];
  const credentialFields = getCredentialFields();
  if (credentialFields.length === 0) return signals;

  // body or html opacity:0
  for (const root of [document.body, document.documentElement]) {
    if (!root) continue;
    const computed = window.getComputedStyle ? window.getComputedStyle(root) : null;
    const opacity = parseFloat(computed?.opacity ?? root.style?.opacity);
    if (opacity < 0.01 || root.style?.opacity === '0' || computed?.opacity === '0') {
      // Suppress if opacity is being animated (page load transition)
      let animated = false;
      try {
        const animations = root.getAnimations?.() || [];
        animated = animations.some(a =>
          a.effect?.getKeyframes?.().some(kf => 'opacity' in kf) &&
          (a.currentTime < 2000)
        );
      } catch (_) { /* getAnimations not supported */ }

      if (!animated) {
        signals.push({ id: 'clickjack:body_opacity_zero', weight: 0.50 });
        break; // Only report once
      }
    }

    // transform:scale(0) on body/html
    const transform = computed?.transform || root.style?.transform || '';
    if (/scale\s*\(\s*0\s*[\s,)]/i.test(transform) || transform === 'scale(0)') {
      signals.push({ id: 'clickjack:transform_scale_zero', weight: 0.35 });
      break;
    }
  }

  // Overlay occlusion: high z-index non-input element covering viewport
  const vw = window.innerWidth || document.documentElement.clientWidth || 1024;
  const vh = window.innerHeight || document.documentElement.clientHeight || 768;
  const vpArea = vw * vh;

  if (vpArea > 0) {
    // Check all elements with explicit high z-index
    const candidates = document.querySelectorAll('[style*="z-index"]');
    for (const el of candidates) {
      if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') continue;
      if (el.id === 'phishops-autofill-warning') continue; // Skip our own banner

      const computed = window.getComputedStyle ? window.getComputedStyle(el) : null;
      const zIndex = parseInt(computed?.zIndex || el.style?.zIndex, 10);
      if (zIndex > 10000) {
        const rect = el.getBoundingClientRect();
        const elArea = rect.width * rect.height;
        if (elArea / vpArea > 0.80) {
          signals.push({ id: 'clickjack:overlay_occluding', weight: 0.40 });
          break;
        }
      }
    }
  }

  // Popover API occlusion
  try {
    const openPopovers = document.querySelectorAll('[popover]:popover-open');
    for (const pop of openPopovers) {
      const rect = pop.getBoundingClientRect();
      const popArea = rect.width * rect.height;
      if (vpArea > 0 && popArea / vpArea > 0.50) {
        signals.push({ id: 'clickjack:popover_occluding', weight: 0.40 });
        break;
      }
    }
  } catch (_) { /* :popover-open not supported in this environment */ }

  return signals;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/**
 * Calculate risk score from field-level and page-level signals.
 * Score = max(vector1Score, vector2Score), capped at 1.0.
 *
 * @param {{ fieldSignals: { id: string, weight: number }[], exfilSignals: { id: string, weight: number }[], clickjackSignals: { id: string, weight: number }[] }} params
 * @returns {{ riskScore: number, signalList: string[], vector: string }}
 */
function calculateAutofillRiskScore({ fieldSignals = [], exfilSignals = [], clickjackSignals = [] }) {
  // Vector 1: hidden field harvest
  const v1Score = Math.min(
    fieldSignals.reduce((sum, s) => sum + s.weight, 0) +
    exfilSignals.reduce((sum, s) => sum + s.weight, 0),
    1.0,
  );

  // Vector 2: extension clickjacking
  const v2Score = Math.min(
    clickjackSignals.reduce((sum, s) => sum + s.weight, 0),
    1.0,
  );

  const riskScore = Math.round(Math.max(v1Score, v2Score) * 100) / 100;
  const vector = v2Score > v1Score ? 'extension_clickjacking' : 'hidden_field_harvest';
  const signalList = [...fieldSignals, ...exfilSignals, ...clickjackSignals].map(s => s.id);

  return { riskScore, signalList, vector };
}

// ---------------------------------------------------------------------------
// Exfiltration signals (form-level)
// ---------------------------------------------------------------------------

/**
 * Get exfiltration signals for a form containing hidden credential fields.
 *
 * @param {Element} form
 * @param {number} hiddenFieldCount
 * @returns {{ id: string, weight: number }[]}
 */
function getExfilSignals(form, hiddenFieldCount) {
  const signals = [];

  if (form) {
    const action = form.getAttribute('action') || '';
    try {
      if (action && /^https?:\/\//i.test(action)) {
        const actionOrigin = new URL(action).origin;
        if (actionOrigin !== window.location.origin) {
          signals.push({ id: 'exfil:cross_origin_action', weight: 0.25 });
        }
      }
    } catch (_) { /* invalid URL */ }
  }

  if (hiddenFieldCount >= 2) {
    signals.push({ id: 'exfil:hidden_field_count', weight: 0.15 });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// UI: Field disabling + Warning banner
// ---------------------------------------------------------------------------

/**
 * Disable hidden credential fields: clear value, set disabled, prevent re-fill.
 *
 * @param {Element[]} fields
 * @param {number} riskScore
 */
function disableHiddenCredentialFields(fields, riskScore) {
  for (const field of fields) {
    field.disabled = true;
    field.value = '';
    field.autocomplete = 'off';
    field.placeholder = '\u26A0 Blocked by PhishOps \u2014 hidden field harvest detected';
    field.style.cssText = 'border: 2px solid #BF1B1B !important; background: #1A0F0F !important; color: #BF1B1B !important;';
  }
  console.warn('[AUTOFILLGUARD] %d credential fields disabled riskScore=%.2f', fields.length, riskScore);
}

/**
 * Restore a clickjacked page by resetting opacity and hiding overlays.
 *
 * @param {number} riskScore
 */
function restoreClickjackedPage(riskScore) {
  if (document.body) document.body.style.opacity = '1';
  if (document.documentElement) document.documentElement.style.opacity = '1';

  // Remove high-z overlays covering viewport
  const vw = window.innerWidth || 1024;
  const vh = window.innerHeight || 768;
  const vpArea = vw * vh;

  const candidates = document.querySelectorAll('[style*="z-index"]');
  for (const el of candidates) {
    if (el.tagName === 'INPUT' || el.id === 'phishops-autofill-warning') continue;
    const zIndex = parseInt(window.getComputedStyle?.(el)?.zIndex || el.style?.zIndex, 10);
    if (zIndex > 10000) {
      const rect = el.getBoundingClientRect();
      if ((rect.width * rect.height) / vpArea > 0.80) {
        el.style.display = 'none';
      }
    }
  }

  console.warn('[AUTOFILLGUARD] Clickjacked page restored riskScore=%.2f', riskScore);
}

/**
 * Inject a warning banner at the top of the page.
 * Idempotent — will not inject twice.
 *
 * @param {number} riskScore
 * @param {string} vector
 * @param {string[]} signals
 */
function injectAutofillWarningBanner(riskScore, vector, signals) {
  if (document.getElementById('phishops-autofill-warning')) return;

  const isClickjack = vector === 'extension_clickjacking';
  const title = isClickjack
    ? 'Extension Clickjacking Detected \u2014 PhishOps AutofillGuard'
    : 'Hidden Credential Harvest Blocked \u2014 PhishOps AutofillGuard';
  const description = isClickjack
    ? 'This page attempted to make your password manager\'s autofill UI invisible using opacity/overlay manipulation. This is a DOM-based Extension Clickjacking attack (T\u00F3th 2025).'
    : 'This page contains hidden credential fields designed to silently harvest autofilled passwords. Credential fields have been disabled.';

  const banner = document.createElement('div');
  banner.id = 'phishops-autofill-warning';
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
        ${title.toLowerCase()}
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        ${description}
        Risk score: ${riskScore.toFixed(2)}. Signals: ${signals.slice(0, 5).join(', ')}.
      </span>
    </div>
    <button id="phishops-autofill-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-autofill-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

// ---------------------------------------------------------------------------
// Telemetry emitter
// ---------------------------------------------------------------------------

function sendToBackground(payload) {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({ type: 'AUTOFILLGUARD_EVENT', payload });
    } else {
      console.warn('[AUTOFILLGUARD] chrome.runtime unavailable \u2014 payload:', JSON.stringify(payload));
    }
  } catch (err) {
    console.error('[AUTOFILLGUARD] sendToBackground failed: %s', err);
  }
}

// ---------------------------------------------------------------------------
// Core audit runner
// ---------------------------------------------------------------------------

/**
 * Run the full AutofillGuard audit on the current page.
 * Called by MutationObserver, periodic interval, and form submit handler.
 *
 * @returns {{ detected: boolean, riskScore: number, vector: string, signals: string[] }}
 */
function runAudit() {
  const credentialFields = getCredentialFields();
  if (credentialFields.length === 0) {
    return { detected: false, riskScore: 0, vector: '', signals: [] };
  }

  // Collect per-field signals (use worst-offending field)
  let worstFieldSignals = [];
  let worstFieldScore = 0;
  const hiddenFields = [];

  for (const field of credentialFields) {
    const fieldSignals = getFieldVisibilitySignals(field);
    if (fieldSignals.length === 0) continue;

    const form = field.closest('form');
    if (isLikelyFalsePositive(field, form)) {
      continue; // Skip suppressed fields
    }

    const fieldScore = fieldSignals.reduce((s, sig) => s + sig.weight, 0);
    if (fieldScore > worstFieldScore) {
      worstFieldScore = fieldScore;
      worstFieldSignals = fieldSignals;
    }
    hiddenFields.push(field);
  }

  // Exfiltration signals (from the form containing hidden fields)
  let exfilSignals = [];
  if (hiddenFields.length > 0) {
    const form = hiddenFields[0].closest('form');
    exfilSignals = getExfilSignals(form, hiddenFields.length);
  }

  // Clickjacking signals (page-level)
  const clickjackSignals = checkClickjackingSignals();

  // Score
  const { riskScore, signalList, vector } = calculateAutofillRiskScore({
    fieldSignals: worstFieldSignals,
    exfilSignals,
    clickjackSignals,
  });

  if (riskScore < ALERT_THRESHOLD) {
    return { detected: false, riskScore, vector, signals: signalList };
  }

  // Determine severity
  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  // Mitigate
  if (riskScore >= DISABLE_THRESHOLD) {
    if (vector === 'extension_clickjacking') {
      restoreClickjackedPage(riskScore);
    } else if (hiddenFields.length > 0) {
      disableHiddenCredentialFields(hiddenFields, riskScore);
    }
  }

  // Banner
  injectAutofillWarningBanner(riskScore, vector, signalList);

  // Build event payload
  const eventType = vector === 'extension_clickjacking'
    ? 'AUTOFILL_EXTENSION_CLICKJACK'
    : 'AUTOFILL_HIDDEN_FIELD_HARVEST';

  const payload = {
    eventType,
    riskScore,
    severity,
    vector,
    hiddenFieldCount: hiddenFields.length,
    hidingTechniques: worstFieldSignals.map(s => s.id),
    credentialFieldCount: credentialFields.length,
    url: window.location.href.substring(0, 200),
    pageTitle: document.title?.substring(0, 100) || '',
    signals: signalList,
    timestamp: new Date().toISOString(),
  };

  if (vector === 'extension_clickjacking') {
    payload.technique = clickjackSignals[0]?.id || 'unknown';
    payload.bodyOpacity = document.body?.style?.opacity || '';
  }

  if (exfilSignals.some(s => s.id === 'exfil:cross_origin_action')) {
    const form = hiddenFields[0]?.closest('form');
    payload.formAction = form?.getAttribute('action')?.substring(0, 200) || '';
    payload.crossOriginAction = true;
  }

  sendToBackground(payload);

  console.warn(
    '[AUTOFILLGUARD] ALERT %s riskScore=%.2f severity=%s signals=%s',
    eventType, riskScore, severity, signalList.join(', '),
  );

  return { detected: true, riskScore, vector, signals: signalList };
}

// ---------------------------------------------------------------------------
// Main entry point — MutationObserver + periodic audit + form submit
// ---------------------------------------------------------------------------

/** Internal state for the observer lifecycle. */
let _tier2Active = false;
let _tier1Observer = null;
let _tier2Observer = null;
let _periodicInterval = null;
let _alerted = false; // Prevent duplicate alerts within the same page

/**
 * Main entry point. Sets up Tier 1 observer, upgrading to Tier 2 when
 * credential fields are found.
 */
function runAutofillGuard() {
  if (!document.body) return;

  // Quick check: do credential fields already exist?
  if (getCredentialFields().length > 0) {
    _upgradeTo_tier2();
  } else {
    _installTier1();
  }

  console.debug('[AUTOFILLGUARD] content script active url=%s', window.location.href.substring(0, 80));
}

function _installTier1() {
  if (_tier1Observer) return;

  _tier1Observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.matches?.(CREDENTIAL_SELECTOR) ||
            node.querySelector?.(CREDENTIAL_SELECTOR)) {
          _upgradeTo_tier2();
          return;
        }
      }
    }
  });

  _tier1Observer.observe(document.body, { childList: true, subtree: true });
}

function _upgradeTo_tier2() {
  if (_tier2Active) return;
  _tier2Active = true;

  // Disconnect Tier 1
  if (_tier1Observer) {
    _tier1Observer.disconnect();
    _tier1Observer = null;
  }

  // Run initial audit
  _debouncedAudit();

  // Tier 2 observer: watch attribute changes that could hide fields
  let debounceTimer = null;
  _tier2Observer = new MutationObserver(() => {
    if (debounceTimer) return;
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      _debouncedAudit();
    }, 300);
  });

  _tier2Observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['style', 'class', 'hidden', 'popover'],
  });

  // Periodic clickjacking audit (catches JS-timer-based opacity changes)
  _periodicInterval = setInterval(() => {
    if (document.hidden) return; // Skip when tab not visible
    _debouncedAudit();
  }, 5000);

  // Pause/resume on visibility change
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && _periodicInterval) {
      clearInterval(_periodicInterval);
      _periodicInterval = null;
    } else if (!document.hidden && !_periodicInterval) {
      _periodicInterval = setInterval(() => {
        if (document.hidden) return;
        _debouncedAudit();
      }, 5000);
    }
  });

  // Form submit interception (capture phase)
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!form || form.tagName !== 'FORM') return;

    const pwFields = form.querySelectorAll(CREDENTIAL_SELECTOR);
    if (pwFields.length === 0) return;

    // Quick hidden-field check on the submitting form
    let hasHiddenField = false;
    for (const field of pwFields) {
      const sigs = getFieldVisibilitySignals(field);
      if (sigs.length > 0 && !isLikelyFalsePositive(field, form)) {
        hasHiddenField = true;
        break;
      }
    }

    if (hasHiddenField) {
      const result = runAudit();
      if (result.riskScore >= DISABLE_THRESHOLD) {
        event.preventDefault();
        event.stopPropagation();
        console.warn('[AUTOFILLGUARD] Form submission blocked riskScore=%.2f', result.riskScore);
      }
    }
  }, true);
}

function _debouncedAudit() {
  if (_alerted) return; // Already fired an alert on this page
  const result = runAudit();
  if (result.detected) {
    _alerted = true; // One alert per page load
  }
}

// ---------------------------------------------------------------------------
// Auto-bootstrap guard
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => runAutofillGuard(), { once: true });
  } else {
    runAutofillGuard();
  }
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['autofill_guard'] = {
    getCredentialFields,
    getFieldVisibilitySignals,
    isLikelyFalsePositive,
    checkClickjackingSignals,
    calculateAutofillRiskScore,
    disableHiddenCredentialFields,
    restoreClickjackedPage,
    injectAutofillWarningBanner,
    runAudit,
    runAutofillGuard,
  };
}

})();
