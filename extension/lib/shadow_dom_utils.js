/**
 * extension/lib/shadow_dom_utils.js
 *
 * Shadow DOM deep traversal utility.
 * Provides deepQuerySelectorAll() which recursively walks open shadow roots
 * so existing detectors (AutofillGuard, PhishVision) can find credential
 * fields hidden inside web components.
 *
 * Design constraints:
 *   - ISOLATED world only — no chrome.dom.openOrClosedShadowRoot needed
 *     because no phishing kit uses closed shadow DOM intentionally
 *   - Depth limit: 5 levels (covers all real-world shadow DOM nesting)
 *   - Graceful on elements that throw when accessing .shadowRoot
 *   - Zero chrome.* deps — fully testable in jsdom
 */

'use strict';

const MAX_SHADOW_DEPTH = 5;

/**
 * Recursively query all elements matching `selector` across open shadow roots.
 * Traverses open shadow roots up to MAX_SHADOW_DEPTH levels deep.
 *
 * @param {string} selector - CSS selector to match
 * @param {Document|ShadowRoot|Element} root - Root to query from
 * @param {number} [depth=0] - Current recursion depth (internal use)
 * @returns {Element[]} All matching elements including those in shadow roots
 */
function deepQuerySelectorAll(selector, root = document, depth = 0) {
  const results = [];

  try {
    results.push(...root.querySelectorAll(selector));
  } catch {
    return results;
  }

  if (depth >= MAX_SHADOW_DEPTH) return results;

  try {
    for (const el of root.querySelectorAll('*')) {
      try {
        const sr = el.shadowRoot;
        if (sr) {
          results.push(...deepQuerySelectorAll(selector, sr, depth + 1));
        }
      } catch {
        // Skip elements that throw on shadowRoot access
      }
    }
  } catch { /* ignore */ }

  return results;
}

/* ------------------------------------------------------------------ */
/*  Test export bridge + global registration                           */
/* ------------------------------------------------------------------ */
// Loaded as a classic content script (must be listed in manifest before
// any detector that needs it). Registers on globalThis so detectors and
// vitest tests can both reach it.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsLib = globalThis.__phishopsLib || {};
  globalThis.__phishopsLib.deepQuerySelectorAll = deepQuerySelectorAll;
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports.shadow_dom_utils = { deepQuerySelectorAll };
}
