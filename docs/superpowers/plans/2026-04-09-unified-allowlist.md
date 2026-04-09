# Unified Domain Allowlist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate false-positive alerts on trusted sites (claude.ai, LinkedIn, TryHackMe, etc.) by adding a unified user-editable allowlist that suppresses both visual banners and telemetry events for allowlisted domains.

**Architecture:** Two suppression layers — (1) a content script CSS gate (`allowlist_gate.js`) that hides all PhishOps-injected banners on allowlisted domains via a single `[id^="phishops-"]` CSS rule, and (2) a service-worker pre-filter that drops telemetry for allowlisted domains before it reaches storage/badge. The allowlist lives in `chrome.storage.local['phishops_user_allowlist']` and is editable via a new panel in the popup. A builtin hardcoded list covers well-known safe sites; the user list extends it. Zero existing content scripts need modification.

**Tech Stack:** Vanilla JS (ES module for lib, classic script for content/popup), Chrome MV3 `chrome.storage.local`, Vitest for unit tests.

---

## File Structure

**Create:**
- `extension/lib/allowlist.js` — ES module. Contains a `BUILTIN_ALLOWLIST` set (mega-merge of all detector-specific trusted domains), plus CRUD functions for the user allowlist in `chrome.storage.local`. Exported: `isDomainAllowlisted(hostname)`, `getUserAllowlist()`, `addToUserAllowlist(domain)`, `removeFromUserAllowlist(domain)`, `BUILTIN_ALLOWLIST`. Used by the service worker (ES module context) and popup (via `window.LureAllowlist` assignment, same pattern as `event_export.js`).
- `extension/tests/allowlist.test.js` — Vitest suite.
- `extension/content/allowlist_gate.js` — Classic content script. Runs at `document_start` before all other content scripts. Reads the user allowlist from `chrome.storage.local`, merges with the builtin list (duplicated as a small inline Set — can't import from ES module), and if the current domain matches: (a) injects a `<style>` tag hiding all `[id^="phishops-"]` elements, and (b) sets `window.__phishopsAllowlisted = true` for any detector that wants to short-circuit expensive work.

**Modify:**
- `extension/manifest.json` — prepend `allowlist_gate.js` as the first content script entry (must run before all detectors).
- `extension/background/service-worker.js` — import `isDomainAllowlisted` from `lib/allowlist.js`, add an allowlist check in `emitTriagedTelemetry()` that extracts the hostname from the event's `url` field and skips emission if allowlisted.
- `extension/popup/popup.html` — add an allowlist editor panel (between the events list and footer): an input + "Add" button, and a scrollable list of allowlisted domains with "×" remove buttons. Add corresponding CSS.
- `extension/popup/popup.js` — wire the allowlist editor: load + render the list, add/remove handlers, reload on storage change.

**Not touched:**
- No existing content scripts are modified. The CSS gate handles all visual suppression.
- `lib/telemetry.js`, `lib/event_export.js` — unchanged.

---

## Important design notes

### Why CSS hiding instead of modifying 20+ content scripts

Every PhishOps detector that shows a visual alert creates a DOM element with an `id` starting with `phishops-` (e.g., `phishops-qrljacking-warning`, `phishops-proxy-banner`, `phishops-style-banner`). A single CSS rule `[id^="phishops-"] { display: none !important; }` hides all of them. This is injected once by `allowlist_gate.js` at `document_start`, before any detector runs.

Pros: zero changes to existing detectors, one file, future detectors automatically covered if they follow the naming convention.

Con: detectors still execute their detection logic (CPU cost on allowlisted sites). This is acceptable for v1 — the user's pain is seeing alerts, not CPU usage. Detectors can optionally check `window.__phishopsAllowlisted` to short-circuit, but that's a follow-up optimization, not part of this plan.

### Builtin list: duplicated in `allowlist_gate.js`

`allowlist_gate.js` is a classic content script and cannot import from `lib/allowlist.js`. The builtin domain list (~40 domains) is duplicated as an inline `Set` in the gate. This is deliberate: the gate must be self-contained and fast. The canonical list in `lib/allowlist.js` is the source of truth for tests and the service worker. If the builtin list changes, both files must be updated. A comment in each file cross-references the other.

### User allowlist storage key

`chrome.storage.local['phishops_user_allowlist']` stores an array of lowercase domain strings (e.g., `['claude.ai', 'internal.corp.com']`). Domains are stored bare (no protocol, no path, no wildcards). Subdomain matching is applied at check time: `claude.ai` matches `www.claude.ai` and `chat.claude.ai`.

---

### Task 1: Create `allowlist.js` with builtin list and `isDomainAllowlisted`

**Files:**
- Create: `extension/lib/allowlist.js`
- Create: `extension/tests/allowlist.test.js`

- [ ] **Step 1: Write failing tests**

Create `extension/tests/allowlist.test.js`:

```js
/**
 * extension/tests/allowlist.test.js
 *
 * Unit tests for the unified domain allowlist module.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

const mockStorage = {};
const mockGet = vi.fn(async (key) => ({ [key]: mockStorage[key] ?? null }));
const mockSet = vi.fn(async (obj) => { Object.assign(mockStorage, obj); });

vi.stubGlobal('chrome', {
  storage: { local: { get: mockGet, set: mockSet } },
});

const {
  BUILTIN_ALLOWLIST,
  isDomainAllowlisted,
} = await import('../lib/allowlist.js');

describe('BUILTIN_ALLOWLIST', () => {
  it('contains well-known safe domains', () => {
    expect(BUILTIN_ALLOWLIST.has('linkedin.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('github.com')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('claude.ai')).toBe(true);
    expect(BUILTIN_ALLOWLIST.has('tryhackme.com')).toBe(true);
  });

  it('does not contain random domains', () => {
    expect(BUILTIN_ALLOWLIST.has('evil-phish.example')).toBe(false);
  });
});

describe('isDomainAllowlisted', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_user_allowlist;
  });

  it('returns true for a builtin domain', async () => {
    expect(await isDomainAllowlisted('linkedin.com')).toBe(true);
  });

  it('matches subdomains of builtin entries', async () => {
    expect(await isDomainAllowlisted('www.linkedin.com')).toBe(true);
    expect(await isDomainAllowlisted('chat.claude.ai')).toBe(true);
  });

  it('returns true for a user-added domain', async () => {
    mockStorage.phishops_user_allowlist = ['internal.corp.com'];
    expect(await isDomainAllowlisted('internal.corp.com')).toBe(true);
  });

  it('matches subdomains of user-added entries', async () => {
    mockStorage.phishops_user_allowlist = ['corp.com'];
    expect(await isDomainAllowlisted('app.corp.com')).toBe(true);
  });

  it('returns false for unknown domains', async () => {
    expect(await isDomainAllowlisted('evil-phish.example')).toBe(false);
  });

  it('strips www. prefix before checking', async () => {
    expect(await isDomainAllowlisted('www.github.com')).toBe(true);
  });

  it('handles empty/null input', async () => {
    expect(await isDomainAllowlisted('')).toBe(false);
    expect(await isDomainAllowlisted(null)).toBe(false);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd extension && npx vitest run tests/allowlist.test.js`
Expected: FAIL — module `../lib/allowlist.js` does not exist.

- [ ] **Step 3: Create `allowlist.js`**

Create `extension/lib/allowlist.js`:

```js
/**
 * extension/lib/allowlist.js
 *
 * Unified domain allowlist for PhishOps. Combines a hardcoded builtin list
 * (mega-merge of all detector-specific trusted domains) with a user-editable
 * list stored in chrome.storage.local['phishops_user_allowlist'].
 *
 * Used by:
 *   - Service worker (ES module import) — suppress telemetry for allowlisted domains
 *   - Popup (via window.LureAllowlist) — allowlist editor UI
 *
 * NOTE: extension/content/allowlist_gate.js duplicates the builtin list
 * as an inline Set because content scripts can't import ES modules.
 * If you add/remove domains here, update allowlist_gate.js too.
 */

'use strict';

const STORAGE_KEY = 'phishops_user_allowlist';

/**
 * Builtin allowlist — well-known legitimate domains that consistently trigger
 * false positives across multiple detectors. Merged from:
 *   - proxy_guard.js LEGIT_DOMAIN_ALLOWLIST (34 domains)
 *   - qrljacking_guard.js KNOWN_QR_AUTH_PLATFORMS (7 domains)
 *   - clickfix_clipboard_defender.js ALLOWLISTED_ORIGINS (6 domains)
 *   - fullscreen_guard.js VIDEO_PLATFORMS (8 domains)
 *   - webrtc_guard.js KNOWN_VIDEO_PLATFORMS (10 domains)
 *   - sync_guard.js TRUSTED_REFERRER_DOMAINS (7 domains)
 *   - autofill_guard.js OAUTH_ENDPOINTS (7 domains)
 *   - service-worker.js SPA_TRUSTED_PLATFORMS (6 domains)
 *
 * Deduplicated and sorted. Per-detector lists remain in their respective
 * files for detector-specific logic (e.g., elevated thresholds). This global
 * list is the "never alert on these at all" set.
 */
const BUILTIN_ALLOWLIST = new Set([
  // Major platforms (from proxy_guard)
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
  'anthropic.com',
  'openai.com',
  'huggingface.co',
  'kaggle.com',
  // AI platforms
  'claude.ai',
  // Code platforms (from clickfix)
  'codepen.io',
  'codesandbox.io',
  'replit.com',
  // Video platforms (from fullscreen/webrtc)
  'vimeo.com',
  'twitch.tv',
  'webex.com',
  'whereby.com',
  'gather.town',
  'streamyard.com',
  'restream.io',
  // Auth providers (from sync/autofill/qrljacking)
  'accounts.google.com',
  'login.microsoftonline.com',
  'login.live.com',
  'login.windows.net',
  'auth.apple.com',
  'login.salesforce.com',
  'login.okta.com',
  'web.whatsapp.com',
  'web.telegram.org',
  'teams.microsoft.com',
  // SPA trusted (from service worker)
  'mail.google.com',
  'outlook.office.com',
  'outlook.live.com',
  'app.slack.com',
  // Documentation sites (from clickfix elevated threshold)
  'learn.microsoft.com',
  'developer.mozilla.org',
  'developer.apple.com',
  'docs.aws.amazon.com',
  'docs.google.com',
  // Google/Microsoft general
  'google.com',
  'microsoft.com',
  'office.com',
  'live.com',
  'meet.google.com',
]);

/**
 * Check whether a hostname is in the builtin OR user allowlist.
 *
 * @param {string} hostname — bare hostname (e.g. 'chat.claude.ai')
 * @returns {Promise<boolean>}
 */
async function isDomainAllowlisted(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase().replace(/^www\./, '');

  if (_matchesSet(h, BUILTIN_ALLOWLIST)) return true;

  const userList = await getUserAllowlist();
  return _matchesArray(h, userList);
}

/**
 * Read the user-editable allowlist from storage.
 * @returns {Promise<string[]>}
 */
async function getUserAllowlist() {
  try {
    if (typeof chrome === 'undefined' || !chrome.storage?.local) return [];
    const data = await chrome.storage.local.get(STORAGE_KEY);
    return Array.isArray(data[STORAGE_KEY]) ? data[STORAGE_KEY] : [];
  } catch {
    return [];
  }
}

/**
 * Add a domain to the user allowlist.
 * @param {string} domain — bare domain (e.g. 'internal.corp.com')
 */
async function addToUserAllowlist(domain) {
  const d = domain.toLowerCase().replace(/^www\./, '').trim();
  if (!d) return;
  const list = await getUserAllowlist();
  if (list.includes(d)) return;
  list.push(d);
  list.sort();
  await chrome.storage.local.set({ [STORAGE_KEY]: list });
}

/**
 * Remove a domain from the user allowlist.
 * @param {string} domain
 */
async function removeFromUserAllowlist(domain) {
  const d = domain.toLowerCase().replace(/^www\./, '').trim();
  const list = await getUserAllowlist();
  const updated = list.filter((entry) => entry !== d);
  await chrome.storage.local.set({ [STORAGE_KEY]: updated });
}

function _matchesSet(hostname, set) {
  if (set.has(hostname)) return true;
  for (const d of set) {
    if (hostname.endsWith('.' + d)) return true;
  }
  return false;
}

function _matchesArray(hostname, arr) {
  for (const d of arr) {
    if (hostname === d || hostname.endsWith('.' + d)) return true;
  }
  return false;
}

const LureAllowlist = {
  BUILTIN_ALLOWLIST,
  isDomainAllowlisted,
  getUserAllowlist,
  addToUserAllowlist,
  removeFromUserAllowlist,
};
if (typeof window !== 'undefined') window.LureAllowlist = LureAllowlist;
export {
  BUILTIN_ALLOWLIST,
  isDomainAllowlisted,
  getUserAllowlist,
  addToUserAllowlist,
  removeFromUserAllowlist,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd extension && npx vitest run tests/allowlist.test.js`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add extension/lib/allowlist.js extension/tests/allowlist.test.js
git commit -m "feat(allowlist): add unified domain allowlist module with builtin + user lists"
```

---

### Task 2: Add CRUD tests for `addToUserAllowlist` / `removeFromUserAllowlist`

**Files:**
- Modify: `extension/tests/allowlist.test.js`

- [ ] **Step 1: Write failing tests**

Append to `extension/tests/allowlist.test.js` (update the import to include `addToUserAllowlist` and `removeFromUserAllowlist`):

Update the import block:

```js
const {
  BUILTIN_ALLOWLIST,
  isDomainAllowlisted,
  getUserAllowlist,
  addToUserAllowlist,
  removeFromUserAllowlist,
} = await import('../lib/allowlist.js');
```

Append new describe blocks:

```js
describe('addToUserAllowlist', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_user_allowlist;
  });

  it('adds a domain to storage', async () => {
    await addToUserAllowlist('example.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['example.com']);
  });

  it('strips www. and lowercases', async () => {
    await addToUserAllowlist('www.Example.COM');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['example.com']);
  });

  it('does not add duplicates', async () => {
    mockStorage.phishops_user_allowlist = ['example.com'];
    await addToUserAllowlist('example.com');
    // set should still be called but list shouldn't grow
    const list = await getUserAllowlist();
    expect(list).toEqual(['example.com']);
  });

  it('sorts entries alphabetically', async () => {
    mockStorage.phishops_user_allowlist = ['zzz.com'];
    await addToUserAllowlist('aaa.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['aaa.com', 'zzz.com']);
  });

  it('ignores empty input', async () => {
    await addToUserAllowlist('');
    expect(mockSet).not.toHaveBeenCalled();
  });
});

describe('removeFromUserAllowlist', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_user_allowlist;
  });

  it('removes a domain from the list', async () => {
    mockStorage.phishops_user_allowlist = ['a.com', 'b.com', 'c.com'];
    await removeFromUserAllowlist('b.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['a.com', 'c.com']);
  });

  it('is a no-op for a domain not in the list', async () => {
    mockStorage.phishops_user_allowlist = ['a.com'];
    await removeFromUserAllowlist('b.com');
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_user_allowlist).toEqual(['a.com']);
  });
});
```

- [ ] **Step 2: Run tests to verify the new ones pass (they should — the functions already exist)**

Run: `cd extension && npx vitest run tests/allowlist.test.js`
Expected: PASS (15 tests — 8 from Task 1 + 7 new).

Note: these tests should pass immediately since the functions were already implemented in Task 1. If any fail, fix the implementation before committing.

- [ ] **Step 3: Commit**

```bash
git add extension/tests/allowlist.test.js
git commit -m "test(allowlist): add CRUD tests for user allowlist add/remove"
```

---

### Task 3: Create `allowlist_gate.js` content script

**Files:**
- Create: `extension/content/allowlist_gate.js`
- Modify: `extension/manifest.json`

- [ ] **Step 1: Create `allowlist_gate.js`**

Create `extension/content/allowlist_gate.js`:

```js
/**
 * extension/content/allowlist_gate.js
 *
 * Runs at document_start BEFORE all other PhishOps content scripts.
 * If the current page's domain is in the builtin or user allowlist,
 * this script:
 *
 *   1. Injects a <style> rule hiding all PhishOps-injected banners
 *      (every banner uses an id starting with "phishops-")
 *
 *   2. Sets window.__phishopsAllowlisted = true so detectors can
 *      optionally short-circuit expensive work (not required — the
 *      CSS rule handles visual suppression regardless)
 *
 * NOTE: The GATE_BUILTIN_ALLOWLIST below is a duplicate of BUILTIN_ALLOWLIST
 * from lib/allowlist.js. This file is a classic content script and cannot
 * import ES modules. If you add/remove domains in lib/allowlist.js,
 * update this list too.
 */

'use strict';

/* eslint-disable no-var */

var GATE_BUILTIN_ALLOWLIST = new Set([
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
  'anthropic.com',
  'openai.com',
  'huggingface.co',
  'kaggle.com',
  'claude.ai',
  'codepen.io',
  'codesandbox.io',
  'replit.com',
  'vimeo.com',
  'twitch.tv',
  'webex.com',
  'whereby.com',
  'gather.town',
  'streamyard.com',
  'restream.io',
  'accounts.google.com',
  'login.microsoftonline.com',
  'login.live.com',
  'login.windows.net',
  'auth.apple.com',
  'login.salesforce.com',
  'login.okta.com',
  'web.whatsapp.com',
  'web.telegram.org',
  'teams.microsoft.com',
  'mail.google.com',
  'outlook.office.com',
  'outlook.live.com',
  'app.slack.com',
  'learn.microsoft.com',
  'developer.mozilla.org',
  'developer.apple.com',
  'docs.aws.amazon.com',
  'docs.google.com',
  'google.com',
  'microsoft.com',
  'office.com',
  'live.com',
  'meet.google.com',
]);

(function allowlistGate() {
  var hostname = '';
  try {
    hostname = location.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return;
  }
  if (!hostname) return;

  // Check builtin list first (sync, fast)
  var isBuiltinAllowlisted = GATE_BUILTIN_ALLOWLIST.has(hostname);
  if (!isBuiltinAllowlisted) {
    for (var d of GATE_BUILTIN_ALLOWLIST) {
      if (hostname.endsWith('.' + d)) {
        isBuiltinAllowlisted = true;
        break;
      }
    }
  }

  if (isBuiltinAllowlisted) {
    _applySuppression();
    return;
  }

  // Check user allowlist (async — may race with document_start detectors,
  // but CSS rule still hides banners even if injected after detector fires)
  try {
    chrome.storage.local.get('phishops_user_allowlist', function (data) {
      var userList = Array.isArray(data.phishops_user_allowlist)
        ? data.phishops_user_allowlist
        : [];
      for (var i = 0; i < userList.length; i++) {
        var ud = userList[i];
        if (hostname === ud || hostname.endsWith('.' + ud)) {
          _applySuppression();
          return;
        }
      }
    });
  } catch {
    // Not in extension context
  }

  function _applySuppression() {
    // 1. CSS rule to hide all PhishOps banners
    var style = document.createElement('style');
    style.textContent = '[id^="phishops-"] { display: none !important; }';
    (document.head || document.documentElement).appendChild(style);

    // 2. Flag for detectors to optionally short-circuit
    window.__phishopsAllowlisted = true;
  }
})();
```

- [ ] **Step 2: Add `allowlist_gate.js` as the FIRST content script in manifest.json**

Edit `extension/manifest.json`. Find the `"content_scripts"` array (starts around line 27). **Prepend** this entry as the very first element of the array, before the existing `shadow_dom_utils.js` entry:

```json
    {
      "matches": ["<all_urls>"],
      "js": ["content/allowlist_gate.js"],
      "run_at": "document_start"
    },
```

- [ ] **Step 3: Verify manifest is valid JSON**

Run: `cd extension && node -e "JSON.parse(require('fs').readFileSync('manifest.json','utf8')); console.log('manifest.json valid')"`
Expected: `manifest.json valid`

- [ ] **Step 4: Commit**

```bash
git add extension/content/allowlist_gate.js extension/manifest.json
git commit -m "feat(allowlist): add allowlist_gate.js content script for banner suppression"
```

---

### Task 4: Add allowlist check in service worker `emitTriagedTelemetry`

**Files:**
- Modify: `extension/background/service-worker.js`

- [ ] **Step 1: Import `isDomainAllowlisted` in the service worker**

Edit `extension/background/service-worker.js`. Find the imports at the top (around line 32–34):

```js
import { emitTelemetry } from '../lib/telemetry.js';
import { triageEvent } from '../lib/triage.js';
import { syncThreatIntel, getStoredThreatIntel, isDomainKnownBad } from '../lib/threat_intel_sync.js';
```

Add after these:

```js
import { isDomainAllowlisted } from '../lib/allowlist.js';
```

- [ ] **Step 2: Replace `emitTriagedTelemetry` with an allowlist-aware version**

Find the existing function (around line 40–43):

```js
function emitTriagedTelemetry(event) {
  const triaged = triageEvent(event);
  emitTelemetry(triaged);
}
```

Replace it with:

```js
async function emitTriagedTelemetry(event) {
  // Extract hostname from event URL and suppress if allowlisted
  const hostname = _extractHostname(event.url || event.blobUrl || '');
  if (hostname) {
    const allowed = await isDomainAllowlisted(hostname);
    if (allowed) {
      console.debug('[PHISHOPS] Suppressed event for allowlisted domain: %s (%s)', hostname, event.eventType);
      return;
    }
  }

  const triaged = triageEvent(event);
  emitTelemetry(triaged);
}

function _extractHostname(url) {
  try {
    if (!url || typeof url !== 'string') return '';
    // Handle blob: URLs — strip the blob: prefix to get the real URL
    const clean = url.startsWith('blob:') ? url.slice(5) : url;
    return new URL(clean).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return '';
  }
}
```

- [ ] **Step 3: Manual verification**

The service worker changes can't be unit-tested easily (it's a monolithic registration script). Verify by:

Run: `cd extension && node -e "import('../background/service-worker.js').catch(e => console.log(e.message))" 2>&1 | head -5`

This will fail (no Chrome APIs in Node), but should NOT fail on a syntax error. If you see `chrome is not defined` or similar runtime error, the syntax is correct.

Better: just validate the file parses:

Run: `cd extension && node --check background/service-worker.js 2>&1 || node -e "try { new Function(require('fs').readFileSync('background/service-worker.js','utf8')); console.log('syntax ok'); } catch(e) { console.log('syntax error:', e.message); }"`

Note: `--check` may fail due to `import` statements in a non-module context. That's fine — the file is loaded by Chrome as a module. As long as it's valid ES syntax, Chrome will load it.

- [ ] **Step 4: Commit**

```bash
git add extension/background/service-worker.js
git commit -m "feat(allowlist): suppress telemetry for allowlisted domains in service worker"
```

---

### Task 5: Add allowlist editor styles and markup to popup.html

**Files:**
- Modify: `extension/popup/popup.html`

- [ ] **Step 1: Add CSS for the allowlist editor**

In `extension/popup/popup.html`, find the `/* ── Events List ─── */` CSS section. **After** the `.event-detail-key` rule (the last rule in the events list section, before `/* ── Footer ─── */`), add:

```css
    /* ── Allowlist Editor ───────────────────── */
    .allowlist-panel {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
      margin-bottom: 12px;
      font-family: var(--font-mono);
      font-size: 10px;
    }

    .allowlist-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }

    .allowlist-title {
      font-size: 8px;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.15em;
      color: var(--text-muted);
    }

    .allowlist-count {
      font-size: 8px;
      color: var(--text-dim);
    }

    .allowlist-add-row {
      display: flex;
      gap: 4px;
      margin-bottom: 6px;
    }

    .allowlist-input {
      flex: 1;
      background: var(--bg-shell);
      border: 1px solid var(--border);
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 10px;
      padding: 4px 6px;
      border-radius: 3px;
      outline: none;
    }

    .allowlist-input::placeholder {
      color: var(--text-dim);
    }

    .allowlist-input:focus {
      border-color: var(--accent-olive);
    }

    .allowlist-add-btn {
      background: var(--bg-stats);
      border: 1px solid var(--border);
      color: var(--accent-olive);
      font-family: var(--font-mono);
      font-size: 9px;
      padding: 4px 10px;
      border-radius: 3px;
      cursor: pointer;
    }

    .allowlist-add-btn:hover {
      border-color: var(--accent-olive);
    }

    .allowlist-domains {
      max-height: 64px;
      overflow-y: auto;
      display: flex;
      flex-wrap: wrap;
      gap: 4px;
    }

    .allowlist-domains::-webkit-scrollbar { width: 4px; }
    .allowlist-domains::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

    .allowlist-chip {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      background: rgba(139, 158, 115, 0.1);
      border: 1px solid rgba(139, 158, 115, 0.2);
      border-radius: 3px;
      padding: 2px 6px;
      font-size: 9px;
      color: var(--text-primary);
    }

    .allowlist-chip-remove {
      background: none;
      border: none;
      color: var(--text-dim);
      cursor: pointer;
      font-size: 11px;
      padding: 0;
      line-height: 1;
    }

    .allowlist-chip-remove:hover {
      color: var(--accent-red);
    }

    .allowlist-empty {
      color: var(--text-dim);
      font-size: 9px;
      padding: 4px 0;
    }
```

- [ ] **Step 2: Add the allowlist editor HTML**

In the `<body>` section of `extension/popup/popup.html`, find the closing `</div>` of the events panel (`id="eventsPanel"`). **After** it and **before** the `<!-- Footer -->` comment, add:

```html
    <!-- Allowlist Editor -->
    <div class="allowlist-panel">
      <div class="allowlist-header">
        <span class="allowlist-title">Trusted Domains</span>
        <span class="allowlist-count" id="allowlistCount">0 user entries</span>
      </div>
      <div class="allowlist-add-row">
        <input type="text" class="allowlist-input" id="allowlistInput"
               placeholder="e.g. claude.ai" spellcheck="false" autocomplete="off">
        <button class="allowlist-add-btn" id="allowlistAddBtn" type="button">Add</button>
      </div>
      <div class="allowlist-domains" id="allowlistDomains">
        <span class="allowlist-empty">No custom trusted domains.</span>
      </div>
    </div>
```

- [ ] **Step 3: Load `allowlist.js` as a module script**

Find the script tags near the bottom of popup.html:

```html
    <script type="module" src="../lib/event_export.js"></script>
    <script src="popup.js"></script>
```

Add the allowlist module BEFORE `event_export.js`:

```html
    <script type="module" src="../lib/allowlist.js"></script>
    <script type="module" src="../lib/event_export.js"></script>
    <script src="popup.js"></script>
```

- [ ] **Step 4: Grow popup height from 640px to 720px**

Find in the `<style>` block:

```css
      height: 640px;
```

Replace with:

```css
      height: 720px;
```

- [ ] **Step 5: Commit**

```bash
git add extension/popup/popup.html
git commit -m "feat(popup): add allowlist editor markup and styles"
```

---

### Task 6: Wire the allowlist editor in popup.js

**Files:**
- Modify: `extension/popup/popup.js`

- [ ] **Step 1: Add DOM refs for the allowlist editor**

Edit `extension/popup/popup.js`. Find the DOM refs section (near the top, around line 80–83):

```js
let canvas, ctx;
let totalEl, highEl, criticalEl;
let telemetryDot, telemetryText, toggle;
let eventsPanel;
```

Add:

```js
let allowlistInput, allowlistAddBtn, allowlistDomains, allowlistCount;
```

In the `DOMContentLoaded` handler, after `eventsPanel = document.getElementById('eventsPanel');`, add:

```js
  allowlistInput = document.getElementById('allowlistInput');
  allowlistAddBtn = document.getElementById('allowlistAddBtn');
  allowlistDomains = document.getElementById('allowlistDomains');
  allowlistCount = document.getElementById('allowlistCount');
```

- [ ] **Step 2: Add the allowlist rendering and wiring logic**

At the end of `extension/popup/popup.js`, after the `handleClearOld` function (and the `SEVEN_DAYS_MS` constant), add:

```js
/* ── Allowlist editor ───────────────────────────────────────── */

const ALLOWLIST_STORAGE_KEY = 'phishops_user_allowlist';

async function loadAllowlist() {
  let list = [];
  try {
    const data = await chrome.storage.local.get(ALLOWLIST_STORAGE_KEY);
    list = Array.isArray(data[ALLOWLIST_STORAGE_KEY]) ? data[ALLOWLIST_STORAGE_KEY] : [];
  } catch {
    // ignore
  }
  renderAllowlist(list);
}

function renderAllowlist(list) {
  if (!allowlistDomains || !allowlistCount) return;

  allowlistCount.textContent = `${list.length} user entr${list.length === 1 ? 'y' : 'ies'}`;

  if (list.length === 0) {
    allowlistDomains.innerHTML = '<span class="allowlist-empty">No custom trusted domains.</span>';
    return;
  }

  const frag = document.createDocumentFragment();
  list.forEach((domain) => {
    const chip = document.createElement('span');
    chip.className = 'allowlist-chip';
    chip.innerHTML = `${_escapeHtml(domain)}<button class="allowlist-chip-remove" data-domain="${_escapeHtml(domain)}" title="Remove ${_escapeHtml(domain)}">&times;</button>`;
    frag.appendChild(chip);
  });

  allowlistDomains.innerHTML = '';
  allowlistDomains.appendChild(frag);
}

async function handleAddDomain() {
  const raw = allowlistInput.value.trim().toLowerCase().replace(/^www\./, '');
  if (!raw) return;

  // Basic validation: must look like a domain
  if (!/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/.test(raw)) {
    allowlistInput.style.borderColor = '#c25e5e';
    setTimeout(() => { allowlistInput.style.borderColor = ''; }, 1500);
    return;
  }

  try {
    const data = await chrome.storage.local.get(ALLOWLIST_STORAGE_KEY);
    const list = Array.isArray(data[ALLOWLIST_STORAGE_KEY]) ? data[ALLOWLIST_STORAGE_KEY] : [];
    if (list.includes(raw)) {
      allowlistInput.value = '';
      return;
    }
    list.push(raw);
    list.sort();
    await chrome.storage.local.set({ [ALLOWLIST_STORAGE_KEY]: list });
    allowlistInput.value = '';
    renderAllowlist(list);
  } catch (err) {
    console.warn('[LURE popup] allowlist add failed:', err);
  }
}

async function handleRemoveDomain(domain) {
  try {
    const data = await chrome.storage.local.get(ALLOWLIST_STORAGE_KEY);
    const list = Array.isArray(data[ALLOWLIST_STORAGE_KEY]) ? data[ALLOWLIST_STORAGE_KEY] : [];
    const updated = list.filter((d) => d !== domain);
    await chrome.storage.local.set({ [ALLOWLIST_STORAGE_KEY]: updated });
    renderAllowlist(updated);
  } catch (err) {
    console.warn('[LURE popup] allowlist remove failed:', err);
  }
}
```

- [ ] **Step 3: Wire event listeners in `DOMContentLoaded`**

In the `DOMContentLoaded` handler, after the `clearOldBtn.addEventListener(...)` line, add:

```js
  // Allowlist editor
  allowlistAddBtn.addEventListener('click', handleAddDomain);
  allowlistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleAddDomain();
  });
  allowlistDomains.addEventListener('click', (e) => {
    const btn = e.target.closest('.allowlist-chip-remove');
    if (!btn) return;
    handleRemoveDomain(btn.dataset.domain);
  });

  // Load initial allowlist
  loadAllowlist();
```

- [ ] **Step 4: Listen for external allowlist changes**

In the existing `chrome.storage.onChanged.addListener` callback (around line 148), after the `renderEventsList(newEvents);` line, add:

```js
      if (changes[ALLOWLIST_STORAGE_KEY]) {
        const newList = changes[ALLOWLIST_STORAGE_KEY].newValue || [];
        renderAllowlist(newList);
      }
```

Also, declare `ALLOWLIST_STORAGE_KEY` near the top of the file is not needed since it's already defined in the allowlist section. But the `chrome.storage.onChanged` listener fires before the allowlist code at the bottom is parsed. So move the constant to the top. Actually — `const` in a function body at the bottom of the file is NOT hoisted. Since the `onChanged` listener closure captures `ALLOWLIST_STORAGE_KEY` by reference and only executes it later (when storage changes), the const will be defined by then. But to be safe, use the string literal directly in the listener:

```js
      if (changes['phishops_user_allowlist']) {
        const newList = changes['phishops_user_allowlist'].newValue || [];
        renderAllowlist(newList);
      }
```

- [ ] **Step 5: Commit**

```bash
git add extension/popup/popup.js
git commit -m "feat(popup): wire allowlist editor with add/remove/render"
```

---

### Task 7: Full regression run

**Files:** none modified.

- [ ] **Step 1: Run the full test suite**

Run: `cd extension && npx vitest run`
Expected: All tests pass — existing suites plus the new `allowlist.test.js` (15 tests).

- [ ] **Step 2: Verify manifest is valid**

Run: `cd extension && node -e "JSON.parse(require('fs').readFileSync('manifest.json','utf8')); console.log('manifest.json valid')"`
Expected: `manifest.json valid`

- [ ] **Step 3: Manual popup smoke test checklist**

Load the extension unpacked in Chrome, open the LURE popup:

- Popup opens at ~720px tall with no console errors.
- Allowlist editor panel visible between events list and footer.
- Input field accepts a domain, "Add" button works. Enter key also adds.
- Domain appears as a chip with "×" remove button.
- Removing a chip deletes the domain.
- Count label updates ("1 user entry", "2 user entries").
- Invalid input (e.g. `not a domain!`) flashes the border red.

Test allowlist suppression:
- Add `claude.ai` to the user allowlist via the popup.
- Navigate to claude.ai in a tab.
- Verify: no QRLjacking warning banner appears.
- Open popup → events list should not show any new events from claude.ai.

- [ ] **Step 4: Commit if any fixes were needed**

```bash
git status
# If modified:
git add <files>
git commit -m "fix(allowlist): <specific fix from regression>"
```

---

## Out of scope (follow-up)

- **Per-detector `window.__phishopsAllowlisted` short-circuit** — content scripts can check this flag to skip expensive work on allowlisted domains. Currently they still run their detection logic; only the visual output is suppressed via CSS. This is a performance optimization, not a correctness issue.
- **"Add to allowlist" button in event detail drawer** — clicking an event row could show a quick "Trust this domain" action. Builds on the Task 7 click-to-expand drawer from the SOC essentials plan.
- **Sync allowlist across devices** — `chrome.storage.sync` instead of `local`.
- **Import/export allowlist** — could hang off the existing export system.
- **Remove per-detector hardcoded allowlists** — once the global allowlist is proven stable, the scattered `LEGIT_DOMAIN_ALLOWLIST`, `KNOWN_QR_AUTH_PLATFORMS`, etc. could be migrated to reference the shared module. But each has detector-specific semantics (e.g., clickfix's "elevated threshold" tier), so this is not a simple search-and-replace.
