/**
 * packages/extension/extensionauditor/background.js
 *
 * ExtensionAuditor — Background service worker integration.
 * Wires Plans E and F auditors into chrome.management event hooks.
 *
 * Audit chain on install/update:
 *   1. Plan E — declarativeNetRequest security header stripping (dnr_header_audit.js)
 *   2. Plan F — Developer contact / ownership drift detection (ownership_drift.js)
 *
 * Continuous monitoring:
 *   3. Plan F — Extension C2 polling pattern (c2_polling_detector.js)
 *      Registered as a persistent webRequest listener at service worker startup.
 *
 * Message flow:
 *   chrome.management.onInstalled → runDnrAudit + runOwnershipDriftCheck
 *   chrome.webRequest.onBeforeRequest (extension origins) → C2 polling check
 *   Any alert → emitAlert() → BrowserPhishingTelemetry_CL
 *
 * Integration with other background modules:
 *   This module runs alongside background/service-worker.js (OAuthGuard) and
 *   dataegress/background.js (blob: navigator). All three modules share the same
 *   MV3 service worker process via import. Each registers its own event listeners
 *   independently without interference.
 */

'use strict';

import { runDnrAudit }           from './auditors/dnr_header_audit.js';
import { runOwnershipDriftCheck } from './auditors/ownership_drift.js';
import { registerC2PollingDetector } from './auditors/c2_polling_detector.js';

// ---------------------------------------------------------------------------
// Shared telemetry emitter
// All ExtensionAuditor events route through here → BrowserPhishingTelemetry_CL
// ---------------------------------------------------------------------------
function emitAlert(event) {
  console.info('[EXTENSIONAUDITOR_BG] TELEMETRY_EMIT type=%s extensionId=%s riskScore=%.2f',
    event.type, event.extensionId, event.riskScore ?? 0);
  // Production: POST to Azure Monitor DCR HTTP Data Collection API
  // fetch(DCR_ENDPOINT, { method: 'POST', body: JSON.stringify([event]), headers: {...} })
}

// ---------------------------------------------------------------------------
// Install / update audit pipeline
// Fires for both new installs and extension updates.
// ---------------------------------------------------------------------------
chrome.management.onInstalled.addListener(async (info) => {
  const { id: extensionId, name: extensionName } = info;

  // Skip our own extension to avoid circular self-auditing
  if (extensionId === chrome.runtime.id) return;

  console.debug(
    '[EXTENSIONAUDITOR_BG] onInstalled extensionId=%s name=%s',
    extensionId, extensionName,
  );

  // Plan E — declarativeNetRequest security header stripping
  // Runs first: highest severity, most novel attack primitive (QuickLens Feb 2026)
  await runDnrAudit(extensionId, extensionName, emitAlert);

  // Plan F — Developer contact / ownership drift
  // Baseline recorded silently on first-seen; alert on any subsequent URL change
  await runOwnershipDriftCheck(extensionId, emitAlert);
});

// Also audit on enable — a previously-disabled extension being re-enabled
// may have been updated while disabled without triggering onInstalled
chrome.management.onEnabled?.addListener(async (info) => {
  const { id: extensionId, name: extensionName } = info;
  if (extensionId === chrome.runtime.id) return;

  console.debug(
    '[EXTENSIONAUDITOR_BG] onEnabled extensionId=%s name=%s',
    extensionId, extensionName,
  );

  await runDnrAudit(extensionId, extensionName, emitAlert);
  // Note: ownership drift not re-run on enable — baseline comparison requires
  // an actual update event to be meaningful
});

// ---------------------------------------------------------------------------
// C2 polling — persistent webRequest listener
// Registered once at service worker startup; monitors all extension-origin requests
// ---------------------------------------------------------------------------
registerC2PollingDetector(emitAlert);

console.debug('[EXTENSIONAUDITOR_BG] ExtensionAuditor background module loaded');
