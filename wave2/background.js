/**
 * packages/extension/dataegress/background.js
 *
 * DataEgressMonitor — Background service worker additions for Wave 2 Plan C.
 *
 * Adds a chrome.webNavigation.onCommitted listener that detects blob: URL
 * navigations and programmatically injects blob_credential_detector.js into
 * the target tab/frame.
 *
 * Why programmatic injection (not manifest content_scripts):
 *   Chrome MV3 content_scripts[].matches does NOT support the blob: scheme.
 *   The only way to run a content script on a blob: page is to:
 *     1. Monitor chrome.webNavigation.onCommitted for blob: URLs
 *     2. Call chrome.scripting.executeScript() with the target tab/frame
 *   This is the documented Chrome extension approach for blob: scheme injection.
 *   Ref: https://developer.chrome.com/docs/extensions/reference/api/scripting
 *
 * Integration with Wave 1 service-worker.js:
 *   This file is a SEPARATE module from background/service-worker.js (which handles
 *   webRequest listeners for OAuthGuard). Both are registered in manifest.json as
 *   background service worker modules. The BLOB_CREDENTIAL_DETECTED message from
 *   blob_credential_detector.js is routed through the shared emitTelemetry() function.
 *
 * Message flow:
 *   blob_credential_detector.js (content script)
 *     → chrome.runtime.sendMessage({ type: 'BLOB_CREDENTIAL_DETECTED', payload })
 *       → this file: chrome.runtime.onMessage listener
 *         → emitTelemetry({ eventType: 'BLOB_URL_CREDENTIAL_PAGE', ... })
 *           → BrowserPhishingTelemetry_CL
 */

'use strict';

// ---------------------------------------------------------------------------
// Telemetry pipeline (shared with service-worker.js in production)
// Stub in this module — in production, import from a shared telemetry module.
// ---------------------------------------------------------------------------
function emitTelemetry(event) {
  console.info('[DATAEGRESS_BG] TELEMETRY_EMIT', JSON.stringify(event));
  // Production: POST to Azure Monitor DCR ingestion endpoint
}

// ---------------------------------------------------------------------------
// Blob: URL navigation listener
// ---------------------------------------------------------------------------

/**
 * Listen for committed navigations to blob: URLs.
 * blob: navigations are committed immediately and synchronously —
 * onCommitted is the correct hook (onBeforeNavigate fires too early
 * and the frame may not yet be injectable).
 *
 * Filtering:
 *   - Only matches URLs starting with "blob:"
 *   - Fires on both main frame and sub-frame navigations (all_frames)
 *   - Excludes chrome-extension:// origins (our own popup/options pages)
 */
chrome.webNavigation.onCommitted.addListener(
  async (details) => {
    const { tabId, frameId, url } = details;

    if (!url.startsWith('blob:')) return;

    console.debug(
      '[DATAEGRESS_BG] blob: navigation detected tabId=%d frameId=%d url=%s',
      tabId, frameId, url.substring(0, 80),
    );

    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: [frameId] },
        files: ['dataegress/blob_credential_detector.js'],
        injectImmediately: true,  // Inject at document_start equivalent
      });

      console.debug(
        '[DATAEGRESS_BG] blob_credential_detector.js injected tabId=%d frameId=%d',
        tabId, frameId,
      );
    } catch (err) {
      // Frame may already be closed or navigated away — safe to ignore
      console.debug(
        '[DATAEGRESS_BG] injection failed tabId=%d frameId=%d err=%s',
        tabId, frameId, err.message,
      );
    }
  },
  { url: [{ urlPrefix: 'blob:' }] },
);

// ---------------------------------------------------------------------------
// Message handler — receives detection results from injected script
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'BLOB_CREDENTIAL_DETECTED') return false;

  const { payload } = message;
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;

  console.warn(
    '[DATAEGRESS_BG] BLOB_CREDENTIAL_DETECTED tabId=%d riskScore=%.2f severity=%s signals=%s',
    tabId,
    payload.riskScore,
    payload.severity,
    (payload.signals || []).join(', '),
  );

  emitTelemetry({
    eventType:                 'BLOB_URL_CREDENTIAL_PAGE',
    tabId:                     tabId ?? -1,
    frameId:                   frameId ?? 0,
    blobUrl:                   (payload.blobUrl || '').substring(0, 100),
    pageTitle:                 (payload.pageTitle || '').substring(0, 100),
    riskScore:                 payload.riskScore,
    severity:                  payload.severity,
    credentialFieldCount:      payload.credentialFieldCount ?? 0,
    matchedBrands:             payload.matchedBrands ?? [],
    nestedSmugglingDetected:   payload.nestedSmugglingDetected ?? false,
    formExfiltrationDetected:  payload.formExfiltrationDetected ?? false,
    externalActions:           payload.externalActions ?? [],
    signals:                   payload.signals ?? [],
    timestamp:                 payload.timestamp ?? new Date().toISOString(),
  });

  sendResponse({ received: true });
  return true;  // Keep message channel open for async sendResponse
});
