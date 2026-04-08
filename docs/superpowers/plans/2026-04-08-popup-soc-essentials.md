# Popup SOC Essentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the LURE popup from a portfolio demo into a minimally usable SOC triage tool by adding event export (JSON + CSV), event clearing (all + age-based), and a click-to-expand recent-events list under the canvas.

**Architecture:** All changes are popup-side plus one new pure-logic library module. Export logic lives in a new `extension/lib/event_export.js` (pure, easy to unit-test with Vitest). Storage housekeeping (`clearEventsOlderThan`) extends the existing `extension/lib/telemetry.js`. The popup grows a new action bar and a scrollable events list under the canvas, with a click-to-expand detail drawer. No background/service-worker changes. No manifest changes. Scope intentionally excludes the allowlist editor (#3), filter chips (#5), and other items — those land in follow-up plans.

**Tech Stack:** Vanilla JS (ES modules in lib/, classic script in popup), Chrome MV3 extension APIs (`chrome.storage.local`, `chrome.downloads` — already permitted via the action popup, no new perms), Vitest for unit tests, no build step, no framework.

---

## File Structure

**Create:**
- `extension/lib/event_export.js` — pure functions: `eventsToJSON(events)`, `eventsToCSV(events)`, `buildExportFilename(format, now)`, `triggerBlobDownload(filename, mimeType, content)`. Uses `URL.createObjectURL` + anchor click (no `chrome.downloads` permission needed).
- `extension/tests/event_export.test.js` — Vitest suite for the pure export helpers.

**Modify:**
- `extension/lib/telemetry.js` — add and export `clearEventsOlderThan(maxAgeMs)`. Keeps existing `clearStoredEvents` untouched.
- `extension/tests/telemetry.test.js` — add tests for `clearEventsOlderThan`.
- `extension/popup/popup.html` — add action bar row (Export JSON / Export CSV / Clear ≥7d / Clear All) and a recent-events list panel under the stats bar. Grow popup height from 400 → 640 to fit the list. Add styles for list rows, severity chips, and the expansion drawer.
- `extension/popup/popup.js` — load `lib/event_export.js` as a classic script, wire the four action buttons, render the recent-events list (last 50) and re-render on `chrome.storage.onChanged`, implement click-to-expand detail drawer.

**Not touched:**
- `extension/manifest.json` — no new permissions, no new scripts registered (popup.html just adds a `<script src="../lib/event_export.js">`).
- `extension/background/service-worker.js` — untouched.
- Any content scripts, detectors, or `proxy_guard.js` allowlist logic.

---

## A note on ES modules in the popup

`lib/telemetry.js` uses `export` (ES module) because it's imported by the background service worker, which is declared as `"type": "module"` in `manifest.json`. The popup currently loads `popup.js` as a **classic** script. Rather than retrofitting the popup to be a module (and rewriting `popup.js`), the new `event_export.js` will be written so it **attaches its API to `window.LureEventExport`** when loaded as a classic script, and also uses `export` statements wrapped in a feature check so Vitest can import it as an ES module. Concretely:

```js
// At the bottom of extension/lib/event_export.js
const LureEventExport = { eventsToJSON, eventsToCSV, buildExportFilename, triggerBlobDownload };
if (typeof window !== 'undefined') window.LureEventExport = LureEventExport;
export { eventsToJSON, eventsToCSV, buildExportFilename, triggerBlobDownload };
```

Vitest (jsdom) can `import` the named exports. The popup loads the file via `<script src="../lib/event_export.js">` and reads `window.LureEventExport`. Chrome is fine with `export` at the top level of a classic script *only* if the script is not parsed as a module — but to be safe, we'll instead have the popup load the file with `<script type="module" src="../lib/event_export.js"></script>` which IS permitted in MV3 extension pages (popup.html is an extension page, not a content script). A `type="module"` script still runs in the same window, so assigning `window.LureEventExport` works identically.

**Decision:** load `event_export.js` in popup.html as `<script type="module">`. `popup.js` stays a classic script and reads from `window.LureEventExport`. This avoids rewriting popup.js as a module. Module scripts are implicitly deferred, but so is any code inside popup.js's `DOMContentLoaded` handler, so by the time a user clicks Export, `window.LureEventExport` is guaranteed to be set. The `handleExport` function still defensively checks `if (!api)` as a seatbelt.

For the `clearEventsOlderThan` call from the popup, we do the same trick: the popup cannot directly import from `lib/telemetry.js`, so we duplicate the small amount of logic inline in `popup.js` using `chrome.storage.local` directly. `lib/telemetry.js` remains the canonical version for the service worker and for tests; the popup's inline copy is a deliberate ~6-line duplicate.

---

### Task 1: Create `event_export.js` with failing tests for `eventsToJSON`

**Files:**
- Create: `extension/lib/event_export.js`
- Create: `extension/tests/event_export.test.js`

- [ ] **Step 1: Write the failing test for `eventsToJSON`**

Create `extension/tests/event_export.test.js` with:

```js
/**
 * extension/tests/event_export.test.js
 *
 * Unit tests for the pure export helpers used by the popup.
 */

import { describe, it, expect } from 'vitest';
import {
  eventsToJSON,
  eventsToCSV,
  buildExportFilename,
} from '../lib/event_export.js';

const SAMPLE_EVENTS = [
  {
    eventType: 'PROXY_AITM_DETECTED',
    severity: 'Critical',
    timestamp: '2026-04-08T10:15:00.000Z',
    targetProvider: 'microsoft',
    url: 'https://evil.example/login',
    signals: ['cname-chain', 'cdn-wrap'],
    extensionVersion: '1.0.0',
    source: 'PhishOps',
  },
  {
    eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
    severity: 'High',
    timestamp: '2026-04-08T10:14:00.000Z',
    payloadSnippet: 'powershell -enc ...',
    url: 'https://foo.test/page',
    extensionVersion: '1.0.0',
    source: 'PhishOps',
  },
];

describe('eventsToJSON', () => {
  it('returns a pretty-printed JSON bundle with metadata and events', () => {
    const now = new Date('2026-04-08T12:00:00.000Z');
    const out = eventsToJSON(SAMPLE_EVENTS, { now, extensionVersion: '1.0.0' });
    const parsed = JSON.parse(out);
    expect(parsed.exportedAt).toBe('2026-04-08T12:00:00.000Z');
    expect(parsed.extensionVersion).toBe('1.0.0');
    expect(parsed.eventCount).toBe(2);
    expect(parsed.events).toHaveLength(2);
    expect(parsed.events[0].eventType).toBe('PROXY_AITM_DETECTED');
  });

  it('handles empty input', () => {
    const out = eventsToJSON([], { now: new Date('2026-04-08T12:00:00.000Z') });
    const parsed = JSON.parse(out);
    expect(parsed.eventCount).toBe(0);
    expect(parsed.events).toEqual([]);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd extension && npx vitest run tests/event_export.test.js`
Expected: FAIL — module `../lib/event_export.js` does not exist.

- [ ] **Step 3: Create minimal `event_export.js` implementing `eventsToJSON`**

Create `extension/lib/event_export.js` with:

```js
/**
 * extension/lib/event_export.js
 *
 * Pure export helpers for LURE telemetry events.
 *
 * Loaded by the popup as a classic module script (<script type="module">)
 * and exposed on `window.LureEventExport` for use by popup.js. Also importable
 * as an ES module by Vitest for unit testing.
 */

'use strict';

/**
 * Build a JSON export bundle.
 *
 * @param {Object[]} events
 * @param {Object} [opts]
 * @param {Date} [opts.now]
 * @param {string} [opts.extensionVersion]
 * @returns {string} pretty-printed JSON
 */
function eventsToJSON(events, opts = {}) {
  const now = opts.now || new Date();
  const bundle = {
    exportedAt: now.toISOString(),
    extensionVersion: opts.extensionVersion || 'unknown',
    source: 'PhishOps',
    eventCount: events.length,
    events,
  };
  return JSON.stringify(bundle, null, 2);
}

const LureEventExport = { eventsToJSON };
if (typeof window !== 'undefined') window.LureEventExport = LureEventExport;
export { eventsToJSON };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd extension && npx vitest run tests/event_export.test.js`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add extension/lib/event_export.js extension/tests/event_export.test.js
git commit -m "feat(popup): add eventsToJSON export helper"
```

---

### Task 2: Add `eventsToCSV` with failing tests

**Files:**
- Modify: `extension/lib/event_export.js`
- Modify: `extension/tests/event_export.test.js`

- [ ] **Step 1: Write the failing test for `eventsToCSV`**

Append to `extension/tests/event_export.test.js` (before the final `});` of the file — i.e. add a new `describe` block at the top level):

```js
describe('eventsToCSV', () => {
  it('produces a header row and one row per event with core columns', () => {
    const csv = eventsToCSV(SAMPLE_EVENTS);
    const lines = csv.split('\n');
    expect(lines[0]).toBe('timestamp,severity,eventType,url,extensionVersion,signals,detail');
    expect(lines).toHaveLength(3); // header + 2 events
    expect(lines[1]).toContain('2026-04-08T10:15:00.000Z');
    expect(lines[1]).toContain('Critical');
    expect(lines[1]).toContain('PROXY_AITM_DETECTED');
    expect(lines[1]).toContain('https://evil.example/login');
  });

  it('quotes fields containing commas, quotes, or newlines', () => {
    const csv = eventsToCSV([{
      eventType: 'TEST',
      severity: 'Low',
      timestamp: '2026-04-08T00:00:00.000Z',
      url: 'https://a,b.test/"quoted"',
      extensionVersion: '1.0.0',
      signals: ['one', 'two,three'],
    }]);
    const lines = csv.split('\n');
    // URL contains a comma AND double-quotes → must be wrapped in quotes with "" escapes
    expect(lines[1]).toContain('"https://a,b.test/""quoted"""');
    // signals joined with "; " and wrapped because it contains ","
    expect(lines[1]).toContain('"one; two,three"');
  });

  it('handles empty input by returning only the header', () => {
    const csv = eventsToCSV([]);
    expect(csv).toBe('timestamp,severity,eventType,url,extensionVersion,signals,detail');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd extension && npx vitest run tests/event_export.test.js`
Expected: FAIL — `eventsToCSV is not a function` (not exported).

- [ ] **Step 3: Implement `eventsToCSV`**

Edit `extension/lib/event_export.js` — after the `eventsToJSON` function, add:

```js
const CSV_COLUMNS = [
  'timestamp',
  'severity',
  'eventType',
  'url',
  'extensionVersion',
  'signals',
  'detail',
];

/**
 * Build a CSV export of events. Only a fixed set of core columns — the full
 * structure lives in the JSON export. This is the "spreadsheet triage" view.
 *
 * @param {Object[]} events
 * @returns {string} CSV text (no trailing newline)
 */
function eventsToCSV(events) {
  const rows = [CSV_COLUMNS.join(',')];
  for (const e of events) {
    rows.push(CSV_COLUMNS.map((col) => _csvCell(e, col)).join(','));
  }
  return rows.join('\n');
}

function _csvCell(event, column) {
  let value;
  switch (column) {
    case 'signals':
      value = Array.isArray(event.signals) ? event.signals.join('; ') : '';
      break;
    case 'detail':
      // Small human-readable detail blob: anything not in the fixed columns
      // stringified as k=v pairs, joined with "; ". Keeps the CSV scannable
      // without exploding to hundreds of columns.
      value = Object.keys(event)
        .filter((k) => !CSV_COLUMNS.includes(k) && k !== 'source' && k !== 'riskScore')
        .map((k) => `${k}=${_stringify(event[k])}`)
        .join('; ');
      break;
    default:
      value = event[column] ?? '';
  }
  return _csvQuote(String(value));
}

function _stringify(v) {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  try { return JSON.stringify(v); } catch { return String(v); }
}

function _csvQuote(s) {
  if (s === '') return '';
  if (/[",\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}
```

Then update the bottom of the file:

```js
const LureEventExport = { eventsToJSON, eventsToCSV };
if (typeof window !== 'undefined') window.LureEventExport = LureEventExport;
export { eventsToJSON, eventsToCSV };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd extension && npx vitest run tests/event_export.test.js`
Expected: PASS (5 tests total).

- [ ] **Step 5: Commit**

```bash
git add extension/lib/event_export.js extension/tests/event_export.test.js
git commit -m "feat(popup): add eventsToCSV export helper with RFC 4180 quoting"
```

---

### Task 3: Add `buildExportFilename` and `triggerBlobDownload`

**Files:**
- Modify: `extension/lib/event_export.js`
- Modify: `extension/tests/event_export.test.js`

- [ ] **Step 1: Write failing test for `buildExportFilename`**

Append a new describe block to `extension/tests/event_export.test.js`:

```js
describe('buildExportFilename', () => {
  it('builds a timestamped filename for JSON', () => {
    const name = buildExportFilename('json', new Date('2026-04-08T10:15:03.123Z'));
    expect(name).toBe('lure-events-2026-04-08T10-15-03.json');
  });

  it('builds a timestamped filename for CSV', () => {
    const name = buildExportFilename('csv', new Date('2026-04-08T10:15:03.123Z'));
    expect(name).toBe('lure-events-2026-04-08T10-15-03.csv');
  });

  it('throws on unknown format', () => {
    expect(() => buildExportFilename('xml', new Date())).toThrow(/format/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd extension && npx vitest run tests/event_export.test.js`
Expected: FAIL — `buildExportFilename is not a function`.

- [ ] **Step 3: Implement `buildExportFilename` and `triggerBlobDownload`**

In `extension/lib/event_export.js`, after `eventsToCSV`, add:

```js
/**
 * Build a timestamped filename for an export.
 *
 * @param {'json'|'csv'} format
 * @param {Date} now
 */
function buildExportFilename(format, now) {
  if (format !== 'json' && format !== 'csv') {
    throw new Error(`unsupported export format: ${format}`);
  }
  const iso = now.toISOString();            // 2026-04-08T10:15:03.123Z
  const stamp = iso.slice(0, 19).replace(/:/g, '-'); // 2026-04-08T10-15-03
  return `lure-events-${stamp}.${format}`;
}

/**
 * Trigger a file download from a string blob inside the popup page.
 * Uses an anchor + URL.createObjectURL — no `downloads` permission needed.
 *
 * @param {string} filename
 * @param {string} mimeType
 * @param {string} content
 */
function triggerBlobDownload(filename, mimeType, content) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Release the blob URL on the next tick — giving the browser time to start the download.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
```

Update the bottom of the file:

```js
const LureEventExport = {
  eventsToJSON,
  eventsToCSV,
  buildExportFilename,
  triggerBlobDownload,
};
if (typeof window !== 'undefined') window.LureEventExport = LureEventExport;
export { eventsToJSON, eventsToCSV, buildExportFilename, triggerBlobDownload };
```

Note: `triggerBlobDownload` touches `document` and `Blob`, which exist under Vitest's default jsdom env but we deliberately don't unit-test it — it's glue that's verified by manual popup testing in Task 8. Unit tests cover the pure string-building helpers only.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd extension && npx vitest run tests/event_export.test.js`
Expected: PASS (8 tests total).

- [ ] **Step 5: Commit**

```bash
git add extension/lib/event_export.js extension/tests/event_export.test.js
git commit -m "feat(popup): add buildExportFilename and triggerBlobDownload helpers"
```

---

### Task 4: Add `clearEventsOlderThan` to telemetry.js

**Files:**
- Modify: `extension/lib/telemetry.js`
- Modify: `extension/tests/telemetry.test.js`

- [ ] **Step 1: Write the failing test**

Append a new describe block at the bottom of `extension/tests/telemetry.test.js` (after the existing `describe('clearStoredEvents', ...)` block):

```js
describe('clearEventsOlderThan', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete mockStorage.phishops_events;
  });

  it('removes events older than the cutoff and keeps newer ones', async () => {
    const { clearEventsOlderThan } = await import('../lib/telemetry.js');
    const now = Date.now();
    mockStorage.phishops_events = [
      { eventType: 'FRESH',  timestamp: new Date(now - 1 * 60 * 60 * 1000).toISOString() },   // 1h ago
      { eventType: 'BORDER', timestamp: new Date(now - 6 * 60 * 60 * 1000).toISOString() },   // 6h ago
      { eventType: 'OLD',    timestamp: new Date(now - 48 * 60 * 60 * 1000).toISOString() },  // 48h ago
    ];

    const removed = await clearEventsOlderThan(24 * 60 * 60 * 1000); // 24h

    expect(removed).toBe(1);
    const lastSet = mockSet.mock.calls.at(-1)[0];
    const kept = lastSet.phishops_events.map((e) => e.eventType);
    expect(kept).toEqual(['FRESH', 'BORDER']);
  });

  it('is a no-op when there are no events', async () => {
    const { clearEventsOlderThan } = await import('../lib/telemetry.js');
    const removed = await clearEventsOlderThan(24 * 60 * 60 * 1000);
    expect(removed).toBe(0);
  });

  it('drops events with missing/invalid timestamps (treats them as old)', async () => {
    const { clearEventsOlderThan } = await import('../lib/telemetry.js');
    mockStorage.phishops_events = [
      { eventType: 'NO_TS' },
      { eventType: 'BAD_TS', timestamp: 'not-a-date' },
      { eventType: 'FRESH', timestamp: new Date().toISOString() },
    ];
    const removed = await clearEventsOlderThan(24 * 60 * 60 * 1000);
    expect(removed).toBe(2);
    const lastSet = mockSet.mock.calls.at(-1)[0];
    expect(lastSet.phishops_events.map((e) => e.eventType)).toEqual(['FRESH']);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd extension && npx vitest run tests/telemetry.test.js`
Expected: FAIL — `clearEventsOlderThan is not a function`.

- [ ] **Step 3: Implement `clearEventsOlderThan`**

In `extension/lib/telemetry.js`, add this export after the existing `clearStoredEvents` function (around line 123):

```js
/**
 * Remove events whose timestamp is older than `maxAgeMs` from now.
 * Events with missing or unparseable timestamps are treated as old and removed.
 *
 * @param {number} maxAgeMs
 * @returns {Promise<number>} number of events removed
 */
export async function clearEventsOlderThan(maxAgeMs) {
  try {
    if (typeof chrome === 'undefined' || !chrome.storage?.local) return 0;

    const data = await chrome.storage.local.get(STORAGE_KEY);
    const events = data[STORAGE_KEY] || [];
    if (events.length === 0) return 0;

    const cutoff = Date.now() - maxAgeMs;
    const kept = events.filter((e) => {
      const t = Date.parse(e.timestamp);
      return Number.isFinite(t) && t >= cutoff;
    });

    const removed = events.length - kept.length;
    if (removed > 0) {
      await chrome.storage.local.set({ [STORAGE_KEY]: kept });
    }
    return removed;
  } catch (err) {
    console.debug('[PHISHOPS_TELEMETRY] clearEventsOlderThan failed: %s', err.message);
    return 0;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd extension && npx vitest run tests/telemetry.test.js`
Expected: PASS (all prior tests + 3 new).

- [ ] **Step 5: Commit**

```bash
git add extension/lib/telemetry.js extension/tests/telemetry.test.js
git commit -m "feat(telemetry): add clearEventsOlderThan for age-based housekeeping"
```

---

### Task 5: Grow the popup, add action bar + events list markup & styles

**Files:**
- Modify: `extension/popup/popup.html`

No new tests in this task — this is pure markup/CSS. Behaviour tests come with the JS wiring in Tasks 6–8 via manual load-unpacked verification (Step 5 of each).

- [ ] **Step 1: Resize popup body and shell**

Edit `extension/popup/popup.html`. Find (around line 26–36):

```css
    body {
      width: 440px;
      height: 400px;
```

Replace the `height` value with `640px`:

```css
    body {
      width: 440px;
      height: 640px;
```

- [ ] **Step 2: Add styles for action bar, events list, and detail drawer**

In the same `<style>` block, immediately **before** the `/* ── Footer ─── */` comment (around line 245), add:

```css
    /* ── Action Bar ─────────────────────────── */
    .action-bar {
      display: flex;
      gap: 6px;
      margin-bottom: 10px;
    }

    .action-btn {
      flex: 1;
      background: var(--bg-stats);
      border: 1px solid var(--border);
      color: var(--text-primary);
      font-family: var(--font-mono);
      font-size: 9px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 6px 4px;
      border-radius: 4px;
      cursor: pointer;
      transition: background-color 0.15s, border-color 0.15s;
    }

    .action-btn:hover {
      background: #2d3439;
      border-color: var(--accent-bronze);
    }

    .action-btn-danger:hover {
      border-color: var(--accent-red);
      color: var(--accent-red);
    }

    /* ── Events List ────────────────────────── */
    .events-panel {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px;
      margin-bottom: 12px;
      height: 180px;
      overflow-y: auto;
      font-family: var(--font-mono);
      font-size: 10px;
    }

    .events-panel::-webkit-scrollbar { width: 6px; }
    .events-panel::-webkit-scrollbar-track { background: transparent; }
    .events-panel::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

    .events-empty {
      color: var(--text-dim);
      text-align: center;
      padding: 24px 8px;
      font-size: 10px;
    }

    .event-row {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 5px 6px;
      border-bottom: 1px solid rgba(59, 66, 72, 0.4);
      cursor: pointer;
      transition: background-color 0.12s;
    }

    .event-row:hover {
      background: rgba(139, 158, 115, 0.05);
    }

    .event-row:last-child { border-bottom: none; }

    .event-sev {
      display: inline-block;
      min-width: 56px;
      text-align: center;
      padding: 1px 4px;
      border-radius: 3px;
      font-size: 8px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-weight: 600;
    }

    .event-sev-critical { background: rgba(194, 94, 94, 0.2); color: var(--accent-red); }
    .event-sev-high     { background: rgba(181, 154, 109, 0.2); color: var(--accent-bronze); }
    .event-sev-medium   { background: rgba(126, 196, 207, 0.15); color: var(--accent-cyan); }
    .event-sev-low      { background: rgba(139, 158, 115, 0.15); color: var(--accent-olive); }

    .event-detector {
      flex: 1;
      color: var(--text-primary);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .event-domain {
      color: var(--text-muted);
      max-width: 110px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .event-time {
      color: var(--text-dim);
      font-size: 9px;
    }

    .event-detail {
      background: rgba(0, 0, 0, 0.25);
      border-left: 2px solid var(--accent-bronze);
      padding: 8px 10px;
      margin: 2px 4px 6px 4px;
      font-size: 9px;
      color: var(--text-primary);
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 200px;
      overflow-y: auto;
    }

    .event-detail-key {
      color: var(--text-muted);
      display: inline-block;
      min-width: 110px;
    }
```

- [ ] **Step 3: Add the action bar and events panel to the DOM**

In `extension/popup/popup.html`, find the end of the `<!-- Detection Statistics -->` `<div class="stats-bar">` block (closes around line 326). **After** the closing `</div>` of `stats-bar` and **before** the `<!-- Footer -->` comment, insert:

```html
    <!-- Action Bar -->
    <div class="action-bar">
      <button class="action-btn" id="exportJsonBtn" type="button">Export JSON</button>
      <button class="action-btn" id="exportCsvBtn" type="button">Export CSV</button>
      <button class="action-btn action-btn-danger" id="clearOldBtn" type="button" title="Clear events older than 7 days">Clear &gt;7d</button>
      <button class="action-btn action-btn-danger" id="clearAllBtn" type="button">Clear All</button>
    </div>

    <!-- Recent Events List -->
    <div class="events-panel" id="eventsPanel">
      <div class="events-empty">No events captured yet.</div>
    </div>
```

- [ ] **Step 4: Load `event_export.js` as a module script**

In `extension/popup/popup.html`, find (near the bottom, around line 341):

```html
    <script src="popup.js"></script>
```

Replace it with:

```html
    <script type="module" src="../lib/event_export.js"></script>
    <script src="popup.js"></script>
```

- [ ] **Step 5: Manual verification — popup loads and shows new UI (no interactivity yet)**

Run: load the extension unpacked in Chrome (chrome://extensions → Load unpacked → `extension/`), click the LURE icon.
Expected: popup is now ~640px tall, shows the canvas, stats bar, a row of 4 buttons (Export JSON, Export CSV, Clear >7d, Clear All), and an empty events panel reading "No events captured yet." No console errors. Buttons do nothing when clicked (wiring comes next).

- [ ] **Step 6: Commit**

```bash
git add extension/popup/popup.html
git commit -m "feat(popup): add action bar and recent-events list markup"
```

---

### Task 6: Render the recent events list in popup.js

**Files:**
- Modify: `extension/popup/popup.js`

- [ ] **Step 1: Add DOM ref and helper constants**

Edit `extension/popup/popup.js`. Find the `/* ── DOM refs ─── */` block (around line 78–82) and add `eventsPanel` to the declaration list:

```js
let canvas, ctx;
let totalEl, highEl, criticalEl;
let telemetryDot, telemetryText, toggle;
let eventsPanel;
```

Find the `DOMContentLoaded` handler (around line 96) where other DOM elements are looked up. After `toggle = document.getElementById('activeToggle');` add:

```js
  eventsPanel = document.getElementById('eventsPanel');
```

- [ ] **Step 2: Add the `renderEventsList` function**

At the end of `extension/popup/popup.js` (after the `draw()` function), add:

```js
/* ── Events List rendering ─────────────────────────────────── */

const MAX_LIST_EVENTS = 50;

function renderEventsList(events) {
  if (!eventsPanel) return;

  if (!events || events.length === 0) {
    eventsPanel.innerHTML = '<div class="events-empty">No events captured yet.</div>';
    return;
  }

  const slice = events.slice(0, MAX_LIST_EVENTS);
  const frag = document.createDocumentFragment();

  slice.forEach((evt, idx) => {
    const row = document.createElement('div');
    row.className = 'event-row';
    row.dataset.idx = String(idx);

    const sev = (evt.severity || 'Low');
    const sevClass = `event-sev-${sev.toLowerCase()}`;
    row.innerHTML = `
      <span class="event-sev ${sevClass}">${_escapeHtml(sev)}</span>
      <span class="event-detector">${_escapeHtml(_detectorLabel(evt))}</span>
      <span class="event-domain">${_escapeHtml(_hostOf(evt))}</span>
      <span class="event-time">${_escapeHtml(_shortTime(evt.timestamp))}</span>
    `;
    frag.appendChild(row);
  });

  eventsPanel.innerHTML = '';
  eventsPanel.appendChild(frag);
}

function _detectorLabel(evt) {
  return EVENT_TYPE_LABELS[evt.eventType] || evt.eventType || 'Unknown';
}

function _hostOf(evt) {
  if (evt.domain) return evt.domain;
  if (evt.url) {
    try { return new URL(evt.url).hostname; } catch { return evt.url; }
  }
  return '';
}

function _shortTime(iso) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '';
  const d = new Date(t);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return `${d.getMonth() + 1}/${d.getDate()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
}

function _escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
```

- [ ] **Step 3: Call `renderEventsList` from `loadAndReplayEvents` and the `onChanged` listener**

In `loadAndReplayEvents` (around line 163), after `updateStats(events);` add:

```js
  renderEventsList(events);
```

In the `chrome.storage.onChanged.addListener` callback (around line 141), after `updateStats(newEvents);` add:

```js
      renderEventsList(newEvents);
```

- [ ] **Step 4: Manual verification**

Run: reload the unpacked extension, visit a page that triggers a detector (or open `extension/demo/` pages if any), open the popup.
Expected: recent events appear in the list as `[SEVERITY] Detector Label — domain — time`. Verify with a brand-new profile: the list shows "No events captured yet." On fresh events from another tab, the list re-renders live.

Alternative verification if no demo triggers an event: in DevTools console of the popup (right-click popup → Inspect), run:

```js
chrome.storage.local.set({ phishops_events: [
  { eventType: 'PROXY_AITM_DETECTED', severity: 'Critical', timestamp: new Date().toISOString(), url: 'https://evil.test/login', signals: ['cname-chain'] },
  { eventType: 'CLICKFIX_CLIPBOARD_INJECTION', severity: 'High', timestamp: new Date().toISOString(), url: 'https://foo.test/x', payloadSnippet: 'powershell -enc ...' },
]});
```

The list should update to show both events. Remember to `chrome.storage.local.set({ phishops_events: [] })` when done testing to clear the injected data.

- [ ] **Step 5: Commit**

```bash
git add extension/popup/popup.js
git commit -m "feat(popup): render recent events list under canvas"
```

---

### Task 7: Wire click-to-expand detail drawer

**Files:**
- Modify: `extension/popup/popup.js`

- [ ] **Step 1: Track expanded state and add click handler**

Edit `extension/popup/popup.js`. Near the top of the State block (around line 86), add:

```js
let currentEvents = [];
let expandedIdx = -1;
```

- [ ] **Step 2: Update `renderEventsList` to cache events and render the drawer**

Replace the `renderEventsList` function you added in Task 6 with this version:

```js
function renderEventsList(events) {
  if (!eventsPanel) return;
  currentEvents = events || [];

  if (currentEvents.length === 0) {
    expandedIdx = -1;
    eventsPanel.innerHTML = '<div class="events-empty">No events captured yet.</div>';
    return;
  }

  const slice = currentEvents.slice(0, MAX_LIST_EVENTS);
  if (expandedIdx >= slice.length) expandedIdx = -1;

  const frag = document.createDocumentFragment();

  slice.forEach((evt, idx) => {
    const row = document.createElement('div');
    row.className = 'event-row';
    row.dataset.idx = String(idx);

    const sev = (evt.severity || 'Low');
    const sevClass = `event-sev-${sev.toLowerCase()}`;
    row.innerHTML = `
      <span class="event-sev ${sevClass}">${_escapeHtml(sev)}</span>
      <span class="event-detector">${_escapeHtml(_detectorLabel(evt))}</span>
      <span class="event-domain">${_escapeHtml(_hostOf(evt))}</span>
      <span class="event-time">${_escapeHtml(_shortTime(evt.timestamp))}</span>
    `;
    frag.appendChild(row);

    if (idx === expandedIdx) {
      const drawer = document.createElement('div');
      drawer.className = 'event-detail';
      drawer.innerHTML = _renderEventDetail(evt);
      frag.appendChild(drawer);
    }
  });

  eventsPanel.innerHTML = '';
  eventsPanel.appendChild(frag);
}

function _renderEventDetail(evt) {
  const lines = [];
  const orderedKeys = ['eventType', 'severity', 'timestamp', 'url', 'signals', 'extensionVersion'];
  const seen = new Set();

  for (const k of orderedKeys) {
    if (k in evt) {
      lines.push(`<span class="event-detail-key">${_escapeHtml(k)}</span>${_escapeHtml(_formatValue(evt[k]))}`);
      seen.add(k);
    }
  }

  for (const k of Object.keys(evt)) {
    if (seen.has(k) || k === 'source') continue;
    lines.push(`<span class="event-detail-key">${_escapeHtml(k)}</span>${_escapeHtml(_formatValue(evt[k]))}`);
  }

  return lines.join('\n');
}

function _formatValue(v) {
  if (v == null) return '';
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'object') {
    try { return JSON.stringify(v); } catch { return String(v); }
  }
  return String(v);
}
```

- [ ] **Step 3: Add a delegated click handler inside the `DOMContentLoaded` handler**

In `extension/popup/popup.js`, inside the `DOMContentLoaded` async handler, after `eventsPanel = document.getElementById('eventsPanel');` add:

```js
  eventsPanel.addEventListener('click', (e) => {
    const row = e.target.closest('.event-row');
    if (!row) return;
    const idx = Number(row.dataset.idx);
    expandedIdx = (expandedIdx === idx) ? -1 : idx;
    renderEventsList(currentEvents);
  });
```

- [ ] **Step 4: Manual verification**

Run: reload the unpacked extension. Inject test events via the console snippet from Task 6 Step 4. Click on an event row.
Expected: a drawer appears below the clicked row with all event fields (`eventType`, `severity`, `timestamp`, `url`, `signals`, `extensionVersion`, then any event-type-specific fields). Clicking the same row again closes the drawer. Clicking a different row collapses the first and opens the second.

- [ ] **Step 5: Commit**

```bash
git add extension/popup/popup.js
git commit -m "feat(popup): add click-to-expand detail drawer for event rows"
```

---

### Task 8: Wire the Export JSON and Export CSV buttons

**Files:**
- Modify: `extension/popup/popup.js`

- [ ] **Step 1: Add button refs and click handlers in `DOMContentLoaded`**

In `extension/popup/popup.js`, inside the `DOMContentLoaded` async handler, after the `eventsPanel.addEventListener('click', ...)` block from Task 7, add:

```js
  const exportJsonBtn = document.getElementById('exportJsonBtn');
  const exportCsvBtn = document.getElementById('exportCsvBtn');

  exportJsonBtn.addEventListener('click', () => handleExport('json'));
  exportCsvBtn.addEventListener('click', () => handleExport('csv'));
```

- [ ] **Step 2: Add the `handleExport` helper at the bottom of the file**

At the end of `extension/popup/popup.js`, after the `_escapeHtml` helper, add:

```js
/* ── Export handlers ────────────────────────────────────────── */

async function handleExport(format) {
  const api = window.LureEventExport;
  if (!api) {
    console.warn('[LURE popup] export library not loaded');
    return;
  }

  let events = [];
  try {
    const data = await chrome.storage.local.get(STORAGE_KEY);
    events = data[STORAGE_KEY] || [];
  } catch (err) {
    console.warn('[LURE popup] export read failed:', err);
    return;
  }

  const now = new Date();
  const filename = api.buildExportFilename(format, now);
  const version = (() => {
    try { return chrome.runtime.getManifest().version; } catch { return 'unknown'; }
  })();

  let content;
  let mime;
  if (format === 'json') {
    content = api.eventsToJSON(events, { now, extensionVersion: version });
    mime = 'application/json';
  } else {
    content = api.eventsToCSV(events);
    mime = 'text/csv';
  }

  api.triggerBlobDownload(filename, mime, content);
}
```

- [ ] **Step 3: Manual verification**

Run: reload the unpacked extension. Inject test events via the console snippet from Task 6 Step 4. Click "Export JSON".
Expected: a file `lure-events-<timestamp>.json` downloads, containing the bundle with `exportedAt`, `extensionVersion`, `eventCount: 2`, and the two test events.

Then click "Export CSV".
Expected: a file `lure-events-<timestamp>.csv` downloads with 3 lines (header + 2 events), correctly quoting any field with commas.

Verify empty case: `chrome.storage.local.set({ phishops_events: [] })`, click Export JSON — should download a bundle with `eventCount: 0` and `events: []`. Export CSV — downloads a file containing only the header row.

- [ ] **Step 4: Commit**

```bash
git add extension/popup/popup.js
git commit -m "feat(popup): wire Export JSON and Export CSV buttons"
```

---

### Task 9: Wire the Clear All and Clear >7d buttons

**Files:**
- Modify: `extension/popup/popup.js`

- [ ] **Step 1: Add button refs and handlers in `DOMContentLoaded`**

In `extension/popup/popup.js`, inside the `DOMContentLoaded` handler, immediately after the export button wiring from Task 8, add:

```js
  const clearAllBtn = document.getElementById('clearAllBtn');
  const clearOldBtn = document.getElementById('clearOldBtn');

  clearAllBtn.addEventListener('click', handleClearAll);
  clearOldBtn.addEventListener('click', handleClearOld);
```

- [ ] **Step 2: Add `handleClearAll` and `handleClearOld` at the bottom of the file**

Append to `extension/popup/popup.js` after `handleExport`:

```js
/* ── Clear handlers ─────────────────────────────────────────── */

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

async function handleClearAll() {
  if (!confirm('Clear ALL stored LURE events? This cannot be undone.')) return;
  try {
    await chrome.storage.local.set({ [STORAGE_KEY]: [] });
    if (chrome.action?.setBadgeText) {
      chrome.action.setBadgeText({ text: '' });
    }
    // The onChanged listener will re-render the list, but trigger immediately
    // for responsiveness in case the listener is flaky on first install.
    updateStats([]);
    renderEventsList([]);
  } catch (err) {
    console.warn('[LURE popup] clear all failed:', err);
  }
}

async function handleClearOld() {
  try {
    const data = await chrome.storage.local.get(STORAGE_KEY);
    const events = data[STORAGE_KEY] || [];
    if (events.length === 0) return;

    const cutoff = Date.now() - SEVEN_DAYS_MS;
    const kept = events.filter((e) => {
      const t = Date.parse(e.timestamp);
      return Number.isFinite(t) && t >= cutoff;
    });

    const removed = events.length - kept.length;
    if (removed === 0) {
      alert('No events older than 7 days to clear.');
      return;
    }

    if (!confirm(`Remove ${removed} event${removed === 1 ? '' : 's'} older than 7 days?`)) return;

    await chrome.storage.local.set({ [STORAGE_KEY]: kept });
    updateStats(kept);
    renderEventsList(kept);
  } catch (err) {
    console.warn('[LURE popup] clear old failed:', err);
  }
}
```

Note: this duplicates the filter logic from `lib/telemetry.js`'s `clearEventsOlderThan` deliberately — the popup is a classic script and can't `import` from the ES module. The canonical version stays in `telemetry.js` and is covered by tests in Task 4.

- [ ] **Step 3: Manual verification — Clear All**

Run: reload the unpacked extension. Inject test events. Open the popup — the list shows the events and the stats bar shows the counts. Click "Clear All" and confirm the dialog.
Expected: list becomes "No events captured yet.", stats bar zeros out, Chrome badge (if present) clears.

- [ ] **Step 4: Manual verification — Clear >7d**

Run: inject an event with an old timestamp and a fresh one via the popup's DevTools console:

```js
chrome.storage.local.set({ phishops_events: [
  { eventType: 'FRESH', severity: 'High', timestamp: new Date().toISOString(), url: 'https://x.test' },
  { eventType: 'OLD', severity: 'High', timestamp: new Date(Date.now() - 10*24*60*60*1000).toISOString(), url: 'https://y.test' },
]});
```

Click "Clear >7d" and confirm.
Expected: dialog says "Remove 1 event older than 7 days?", after confirm only `FRESH` remains in the list. Running "Clear >7d" again with no old events shows "No events older than 7 days to clear."

- [ ] **Step 5: Commit**

```bash
git add extension/popup/popup.js
git commit -m "feat(popup): wire Clear All and Clear >7d buttons"
```

---

### Task 10: Full regression run

**Files:** none modified.

- [ ] **Step 1: Run the full extension test suite**

Run: `cd extension && npx vitest run`
Expected: all tests pass — existing suites (proxy_guard, telemetry, scorer, parser, any agentintentguard tests) plus the new `event_export.test.js` additions and the `clearEventsOlderThan` cases.

- [ ] **Step 2: Manual popup smoke test**

Run: reload unpacked extension, click the LURE icon.
Expected checklist:
- Popup opens at ~640px tall with no console errors.
- Canvas viz still animates (heartbeat + threat packets).
- Stats bar updates live.
- Action bar shows 4 buttons.
- Events list shows real captured events (or "No events captured yet.").
- Clicking a row toggles the detail drawer.
- Export JSON downloads a valid JSON bundle.
- Export CSV downloads a valid CSV.
- Clear >7d only removes old events.
- Clear All wipes everything and resets the badge.
- Toggle off → telemetry status reads "PAUSED", canvas packets stop. Toggle back on restores behaviour.

- [ ] **Step 3: Commit if any lint/formatting touch-ups were needed**

If Step 2 surfaced any issues and you made fixes, commit them. Otherwise no commit.

```bash
git status
# If nothing is modified: skip. Otherwise:
git add <files>
git commit -m "fix(popup): <specific fix found during regression>"
```

---

## Out of scope (deferred to follow-up plans)

- Per-domain user allowlist editor (#3) — needs to merge with `proxy_guard.js`'s hardcoded `LEGIT_DOMAIN_ALLOWLIST` and plumb through every detector. Separate plan.
- Filter chips (#5) and top offending domains panel (#6) — separate plan, builds on the events list added here.
- Detector toggle panel (#7), threat intel freshness footer (#8), `chrome.notifications` on critical (#9), full settings page (#10) — separate plans.
- STIX 2.1 bundle export — can hang off `event_export.js` later, not needed for v1.
