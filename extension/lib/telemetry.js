/**
 * extension/lib/telemetry.js
 *
 * Shared telemetry emitter for all PhishOps detectors.
 *
 * All detection events route through emitTelemetry() which:
 *   1. Logs to console.info (always — visible in DevTools)
 *   2. Persists to chrome.storage.local for the popup dashboard
 *
 * Production SOC deployment:
 *   Replace the storage-only path with an HTTP POST to an Azure Monitor
 *   Data Collection Rule (DCR) endpoint. The payload schema maps 1:1 to
 *   the BrowserPhishingTelemetry_CL Sentinel table documented in each
 *   wave's BrowserPhishingTelemetry_CL.md.
 *
 *   Example DCR integration (not active — requires Azure subscription):
 *     const DCR_ENDPOINT = 'https://<DCE>.ingest.monitor.azure.com/dataCollectionRules/<DCR_ID>/streams/Custom-BrowserPhishingTelemetry_CL?api-version=2023-01-01';
 *     await fetch(DCR_ENDPOINT, {
 *       method: 'POST',
 *       headers: {
 *         'Authorization': `Bearer ${token}`,
 *         'Content-Type': 'application/json',
 *       },
 *       body: JSON.stringify([event]),
 *     });
 */

'use strict';

const STORAGE_KEY = 'phishops_events';
const MAX_STORED_EVENTS = 200;

/**
 * Emit a structured detection event.
 *
 * @param {Object} event - Detection event payload
 * @param {string} event.eventType - e.g. 'OAUTH_DEVICE_CODE_FLOW', 'BLOB_URL_CREDENTIAL_PAGE'
 * @param {string} [event.severity] - 'Critical' | 'High' | 'Medium' | 'Low'
 * @param {number} [event.riskScore] - Numeric risk score from the detector
 */
export async function emitTelemetry(event) {
  const enriched = {
    ...event,
    timestamp: event.timestamp || new Date().toISOString(),
    extensionVersion: '1.0.0',
    source: 'PhishOps',
  };

  // 1. Console logging (always)
  console.info('[PHISHOPS_TELEMETRY]', JSON.stringify(enriched));

  // 2. Persist to chrome.storage.local for popup dashboard
  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      const data = await chrome.storage.local.get(STORAGE_KEY);
      const events = data[STORAGE_KEY] || [];
      events.unshift(enriched);

      // Cap stored events to prevent unbounded growth
      if (events.length > MAX_STORED_EVENTS) {
        events.length = MAX_STORED_EVENTS;
      }

      await chrome.storage.local.set({ [STORAGE_KEY]: events });

      // Update detection count for badge
      await _updateBadge(events);
    }
  } catch (err) {
    console.debug('[PHISHOPS_TELEMETRY] storage write failed: %s', err.message);
  }
}

/**
 * Read all stored detection events.
 * @returns {Promise<Object[]>}
 */
export async function getStoredEvents() {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      const data = await chrome.storage.local.get(STORAGE_KEY);
      return data[STORAGE_KEY] || [];
    }
  } catch (_) {
    // Fallback for test environments
  }
  return [];
}

/**
 * Clear all stored events.
 */
export async function clearStoredEvents() {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      await chrome.storage.local.set({ [STORAGE_KEY]: [] });
      if (chrome.action?.setBadgeText) {
        chrome.action.setBadgeText({ text: '' });
      }
    }
  } catch (_) {
    // Ignore in test environments
  }
}

/**
 * Update the extension badge with the count of recent high-severity events.
 * @param {Object[]} events
 */
async function _updateBadge(events) {
  try {
    if (!chrome.action?.setBadgeText) return;

    const recentHighSeverity = events.filter(e => {
      const age = Date.now() - new Date(e.timestamp).getTime();
      return age < 24 * 60 * 60 * 1000 && (e.severity === 'Critical' || e.severity === 'High');
    });

    if (recentHighSeverity.length > 0) {
      chrome.action.setBadgeText({ text: String(recentHighSeverity.length) });
      chrome.action.setBadgeBackgroundColor({ color: '#e63946' });
    } else {
      chrome.action.setBadgeText({ text: '' });
    }
  } catch (_) {
    // Badge API may not be available
  }
}
