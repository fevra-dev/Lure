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
