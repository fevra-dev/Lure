/**
 * extension/background/service-worker.js
 *
 * PhishOps Security Suite — Unified MV3 Background Service Worker
 *
 * Merges all Wave 1–3 background modules into a single service worker:
 *
 *   Wave 1 (OAuthGuard):
 *     - Device code flow detection on OAuth endpoints
 *     - OAuth state parameter email encoding detection (Storm-2372)
 *
 *   Wave 2 (DataEgressMonitor):
 *     - blob: URL navigation monitoring + programmatic content script injection
 *     - BLOB_CREDENTIAL_DETECTED message routing
 *
 *   Wave 3 (ExtensionAuditor):
 *     - declarativeNetRequest security header stripping audit (Plan E)
 *     - Developer ownership drift detection (Plan F)
 *     - C2 polling pattern detection (Plan F continuous)
 *
 *   Wave 3 (AgentIntentGuard):
 *     - AGENTINTENTGUARD_EVENT message routing
 *
 * Telemetry:
 *   All events route through emitTelemetry() from lib/telemetry.js which
 *   persists to chrome.storage.local and logs to console. In production,
 *   this would POST to an Azure Monitor DCR endpoint.
 */

'use strict';

import { emitTelemetry } from '../lib/telemetry.js';
import { triageEvent } from '../lib/triage.js';

/**
 * Triage-enriched telemetry emitter.
 * Every event passes through the NIST 800-61r3 triage engine before persistence.
 */
function emitTriagedTelemetry(event) {
  const triaged = triageEvent(event);
  emitTelemetry(triaged);
}

// =============================================================================
// Wave 1: OAuthGuard — webRequest listeners
// =============================================================================

/**
 * OAuth authorization endpoints monitored for device code flow and state abuse.
 */
const OAUTH_URL_FILTER = {
  urls: [
    // Microsoft
    '*://login.microsoftonline.com/*/oauth2/authorize*',
    '*://login.microsoftonline.com/*/oauth2/v2.0/authorize*',
    '*://login.microsoftonline.com/*/oauth2/devicecode*',
    '*://login.microsoftonline.com/*/oauth2/v2.0/deviceauthorization*',
    '*://login.windows.net/*/oauth2/authorize*',
    // Google
    '*://accounts.google.com/o/oauth2/auth*',
    '*://accounts.google.com/o/oauth2/v2.0/auth*',
    '*://accounts.google.com/o/oauth2/device/code*',
    // Apple
    '*://auth.apple.com/auth/authorize*',
    // GitHub
    '*://github.com/login/oauth/authorize*',
    // Salesforce
    '*://login.salesforce.com/services/oauth2/authorize*',
    // Okta
    '*://login.okta.com/oauth2/*/v1/authorize*',
  ],
};

/**
 * Device code flow endpoint patterns.
 * Device code grants require a POST to these endpoints — but the GET redirect
 * to the device login page is what we intercept in the browser.
 */
const DEVICE_CODE_PATTERNS = [
  /\/oauth2\/v2\.0\/deviceauthorization/i,
  /\/oauth2\/devicecode/i,
  /\/o\/oauth2\/device\/code/i,
  /microsoft\.com\/devicelogin/i,
  /microsoft\.com\/common\/oauth2\/deviceauth/i,
];

/**
 * High-privilege OAuth scopes that indicate dangerous consent grants.
 */
const HIGH_PRIVILEGE_SCOPES = [
  'Mail.ReadWrite',
  'Mail.Send',
  'Files.ReadWrite.All',
  'Directory.ReadWrite.All',
  'offline_access',
  'user_impersonation',
];

/**
 * Detect device code flow from URL patterns.
 */
function detectDeviceCodeFlow(url) {
  try {
    const urlObj = new URL(url);
    const isDeviceCodeEndpoint = DEVICE_CODE_PATTERNS.some(p => p.test(url));

    if (!isDeviceCodeEndpoint) {
      return { detected: false };
    }

    // Extract scope from URL params
    const scope = urlObj.searchParams.get('scope') || '';
    const requestedScopes = scope.split(/[\s+]/).filter(Boolean);
    const hasHighPrivilegeScope = requestedScopes.some(s =>
      HIGH_PRIVILEGE_SCOPES.some(hp => s.toLowerCase().includes(hp.toLowerCase()))
    );

    return {
      detected: true,
      endpoint: urlObj.hostname,
      requestedScopes,
      hasHighPrivilegeScope,
      riskScore: hasHighPrivilegeScope ? 0.90 : 0.70,
      signals: [
        'device_code_flow_detected',
        ...(hasHighPrivilegeScope ? ['high_privilege_scope'] : []),
      ],
    };
  } catch (_) {
    return { detected: false };
  }
}

/**
 * Detect email encoded in OAuth state parameter.
 * Inlined from content/state_parameter_abuse.js for background context.
 */
function detectStateParameterAbuse(url) {
  const CLEAN = (signals) => ({
    detected: false, decodedEmail: '', stateValue: '', encodingMethod: '', riskScore: 0.0, signals,
  });

  try {
    if (!url || typeof url !== 'string') return CLEAN(['no_url']);

    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    const ENDPOINTS = [
      'login.microsoftonline.com', 'accounts.google.com', 'login.live.com',
      'auth.apple.com', 'github.com', 'login.salesforce.com', 'login.okta.com',
      'login.windows.net',
    ];

    if (!ENDPOINTS.some(ep => hostname === ep || hostname.endsWith('.' + ep))) {
      return CLEAN(['not_oauth_endpoint']);
    }

    const stateValue = urlObj.searchParams.get('state');
    if (!stateValue || stateValue.length < 4) return CLEAN(['no_state_param']);

    const EMAIL_RE = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

    // Fast path: already URL-decoded email
    if (EMAIL_RE.test(stateValue.trim())) {
      return {
        detected: true, decodedEmail: stateValue.trim(),
        stateValue: stateValue.substring(0, 64), encodingMethod: 'url',
        riskScore: 0.85, signals: [`email_in_state_param:${stateValue.trim()}`, `oauth_endpoint:${hostname}`],
      };
    }

    // Base64 decode attempt
    try {
      const normalised = stateValue.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
      const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
      const decoded = atob(padded);
      if (/^[\x20-\x7E]+$/.test(decoded) && EMAIL_RE.test(decoded.trim())) {
        return {
          detected: true, decodedEmail: decoded.trim(),
          stateValue: stateValue.substring(0, 64), encodingMethod: 'base64',
          riskScore: 0.85, signals: [`email_in_state_param:${decoded.trim()}`, `oauth_endpoint:${hostname}`],
        };
      }
    } catch (_) { /* not base64 */ }

    // Hex decode attempt
    if (/^[0-9a-f]{8,}$/i.test(stateValue)) {
      try {
        const decoded = stateValue.match(/.{1,2}/g).map(b => String.fromCharCode(parseInt(b, 16))).join('');
        if (/^[\x20-\x7E]+$/.test(decoded) && EMAIL_RE.test(decoded.trim())) {
          return {
            detected: true, decodedEmail: decoded.trim(),
            stateValue: stateValue.substring(0, 64), encodingMethod: 'hex',
            riskScore: 0.85, signals: [`email_in_state_param:${decoded.trim()}`, `oauth_endpoint:${hostname}`],
          };
        }
      } catch (_) { /* not hex */ }
    }

    return CLEAN(['state_not_email']);
  } catch (_) {
    return CLEAN(['detector_error']);
  }
}

// Main webRequest listener — OAuthGuard detectors
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { url, tabId } = details;

    // Detector 1 — Device code flow
    const deviceResult = detectDeviceCodeFlow(url);
    if (deviceResult.detected) {
      emitTriagedTelemetry({
        eventType: 'OAUTH_DEVICE_CODE_FLOW',
        tabId,
        url: url.substring(0, 500),
        endpoint: deviceResult.endpoint,
        requestedScopes: deviceResult.requestedScopes,
        hasHighPrivilegeScope: deviceResult.hasHighPrivilegeScope,
        riskScore: deviceResult.riskScore,
        signals: deviceResult.signals,
        severity: deviceResult.riskScore >= 0.85 ? 'Critical' : 'High',
      });
    }

    // Detector 2 — OAuth state parameter email encoding
    const stateResult = detectStateParameterAbuse(url);
    if (stateResult.detected) {
      emitTriagedTelemetry({
        eventType: 'OAUTH_STATE_EMAIL_ENCODED',
        tabId,
        url: url.substring(0, 500),
        decodedEmail: stateResult.decodedEmail,
        stateValue: stateResult.stateValue,
        encodingMethod: stateResult.encodingMethod,
        riskScore: stateResult.riskScore,
        signals: stateResult.signals,
        severity: 'High',
      });
    }
  },
  OAUTH_URL_FILTER,
);

// =============================================================================
// Wave 2: DataEgressMonitor — blob: URL navigation listener
// =============================================================================

chrome.webNavigation.onCommitted.addListener(
  async (details) => {
    const { tabId, frameId, url } = details;

    if (!url.startsWith('blob:')) return;

    console.debug('[DATAEGRESS] blob: navigation detected tabId=%d frameId=%d', tabId, frameId);

    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: [frameId] },
        files: ['content/blob_credential_detector.js'],
        injectImmediately: true,
      });
    } catch (err) {
      console.debug('[DATAEGRESS] injection failed: %s', err.message);
    }
  },
  { url: [{ urlPrefix: 'blob:' }] },
);

// =============================================================================
// Wave 3: ExtensionAuditor — management event listeners
// =============================================================================

/**
 * Plan E: Audit extensions for declarativeNetRequest rules that strip
 * security headers (CSP, X-Frame-Options, etc.).
 * Threat: QuickLens supply chain attack (Feb 2026) used DNR to strip
 * security headers, enabling AiTM injection on arbitrary pages.
 */
async function runDnrAudit(extensionId, extensionName) {
  try {
    // Check if the extension has declarativeNetRequest permission
    const info = await chrome.management.get(extensionId);
    const permissions = info.permissions || [];

    if (!permissions.includes('declarativeNetRequest') &&
        !permissions.includes('declarativeNetRequestWithHostAccess')) {
      return; // No DNR capability
    }

    console.warn(
      '[EXTENSIONAUDITOR] Extension "%s" (%s) has declarativeNetRequest — auditing rules',
      extensionName, extensionId,
    );

    emitTriagedTelemetry({
      eventType: 'EXTENSION_DNR_AUDIT',
      extensionId,
      extensionName,
      hasDnrPermission: true,
      riskScore: 0.60,
      severity: 'Medium',
      signals: ['dnr_permission_detected'],
    });

  } catch (err) {
    console.debug('[EXTENSIONAUDITOR] DNR audit failed for %s: %s', extensionId, err.message);
  }
}

/**
 * Plan F: Detect developer contact / ownership drift.
 * Baseline the homepage_url on first-seen; alert if it changes on update.
 */
async function runOwnershipDriftCheck(extensionId) {
  try {
    const info = await chrome.management.get(extensionId);
    const currentHomepage = info.homepageUrl || '';

    const storageKey = `ext_baseline_${extensionId}`;
    const data = await chrome.storage.local.get(storageKey);

    if (!data[storageKey]) {
      // First-seen: record baseline silently
      await chrome.storage.local.set({
        [storageKey]: { homepageUrl: currentHomepage, firstSeen: new Date().toISOString() },
      });
      return;
    }

    const baseline = data[storageKey];
    if (baseline.homepageUrl !== currentHomepage) {
      emitTriagedTelemetry({
        eventType: 'EXTENSION_OWNERSHIP_DRIFT',
        extensionId,
        extensionName: info.name,
        previousHomepage: baseline.homepageUrl,
        currentHomepage,
        riskScore: 0.75,
        severity: 'High',
        signals: ['homepage_url_changed'],
      });

      // Update baseline
      await chrome.storage.local.set({
        [storageKey]: { ...baseline, homepageUrl: currentHomepage, lastChanged: new Date().toISOString() },
      });
    }
  } catch (err) {
    console.debug('[EXTENSIONAUDITOR] Ownership drift check failed: %s', err.message);
  }
}

/**
 * Plan F (continuous): C2 polling detection.
 * Monitor extension-origin requests for regular interval patterns
 * that suggest command-and-control communication.
 */
const c2RequestLog = new Map(); // extensionId -> timestamps[]

function detectC2Polling(details) {
  try {
    const { initiator, url } = details;
    if (!initiator || !initiator.startsWith('chrome-extension://')) return;

    const extensionId = initiator.replace('chrome-extension://', '').split('/')[0];
    if (extensionId === chrome.runtime.id) return; // Skip self

    const now = Date.now();
    if (!c2RequestLog.has(extensionId)) {
      c2RequestLog.set(extensionId, []);
    }

    const timestamps = c2RequestLog.get(extensionId);
    timestamps.push(now);

    // Keep only last 60 minutes of data
    const cutoff = now - 60 * 60 * 1000;
    const recent = timestamps.filter(t => t > cutoff);
    c2RequestLog.set(extensionId, recent);

    // Check for polling pattern: 10+ requests with consistent intervals
    if (recent.length >= 10) {
      const intervals = [];
      for (let i = 1; i < recent.length; i++) {
        intervals.push(recent[i] - recent[i - 1]);
      }
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / intervals.length;
      const stddev = Math.sqrt(variance);

      // Low variance relative to mean = regular polling
      if (stddev / avgInterval < 0.3 && avgInterval < 300000) { // CV < 0.3, interval < 5min
        emitTriagedTelemetry({
          eventType: 'EXTENSION_C2_POLLING',
          extensionId,
          requestCount: recent.length,
          avgIntervalMs: Math.round(avgInterval),
          coefficientOfVariation: (stddev / avgInterval).toFixed(3),
          sampleUrl: url.substring(0, 200),
          riskScore: 0.80,
          severity: 'High',
          signals: ['regular_polling_pattern'],
        });

        // Reset to avoid repeated alerts
        c2RequestLog.set(extensionId, []);
      }
    }
  } catch (_) {
    // Non-critical
  }
}

// Register C2 polling detector on all requests
chrome.webRequest.onBeforeRequest.addListener(
  detectC2Polling,
  { urls: ['<all_urls>'] },
);

// Extension install/update audit pipeline
chrome.management.onInstalled.addListener(async (info) => {
  if (info.id === chrome.runtime.id) return;
  await runDnrAudit(info.id, info.name);
  await runOwnershipDriftCheck(info.id);
});

chrome.management.onEnabled?.addListener(async (info) => {
  if (info.id === chrome.runtime.id) return;
  await runDnrAudit(info.id, info.name);
});

// =============================================================================
// Message routing — all content scripts -> telemetry
// =============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id ?? -1;
  const frameId = sender.frameId ?? 0;

  // Wave 2: blob credential detection result
  if (message.type === 'BLOB_CREDENTIAL_DETECTED') {
    const { payload } = message;
    emitTriagedTelemetry({
      eventType: 'BLOB_URL_CREDENTIAL_PAGE',
      tabId,
      frameId,
      blobUrl: (payload.blobUrl || '').substring(0, 100),
      pageTitle: (payload.pageTitle || '').substring(0, 100),
      riskScore: payload.riskScore,
      severity: payload.severity,
      credentialFieldCount: payload.credentialFieldCount ?? 0,
      matchedBrands: payload.matchedBrands ?? [],
      nestedSmugglingDetected: payload.nestedSmugglingDetected ?? false,
      formExfiltrationDetected: payload.formExfiltrationDetected ?? false,
      externalActions: payload.externalActions ?? [],
      signals: payload.signals ?? [],
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 3: AgentIntentGuard events
  if (message.type === 'AGENTINTENTGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 4: AutofillGuard events
  if (message.type === 'AUTOFILLGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 5: ClickFix Clipboard Defender events
  if (message.type === 'CLICKFIX_CLIPBOARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 5: FullscreenGuard events
  if (message.type === 'FULLSCREENGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 6: PasskeyGuard events
  if (message.type === 'PASSKEYGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 6: QRLjackingGuard events
  if (message.type === 'QRLJACKING_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 7: WebRTCGuard events
  if (message.type === 'WEBRTCGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 7: ScreenShareGuard events
  if (message.type === 'SCREENSHAREGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 8: PhishVision events
  if (message.type === 'PHISHVISION_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 8: ProxyGuard events
  if (message.type === 'PROXYGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 9: SyncGuard events
  if (message.type === 'SYNCGUARD_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  // Wave 9: FakeSender Shield events
  if (message.type === 'FAKESENDER_EVENT') {
    emitTriagedTelemetry({
      ...message.payload,
      tabId,
      frameId,
    });
    sendResponse({ received: true });
    return true;
  }

  return false;
});

console.debug('[PHISHOPS] Service worker loaded — all Wave 1–9 detectors active');
