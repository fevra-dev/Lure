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

const LureEventExport = {
  eventsToJSON,
  eventsToCSV,
  buildExportFilename,
  triggerBlobDownload,
};
if (typeof window !== 'undefined') window.LureEventExport = LureEventExport;
export { eventsToJSON, eventsToCSV, buildExportFilename, triggerBlobDownload };
