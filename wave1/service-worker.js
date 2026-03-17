/**
 * packages/extension/background/service-worker.js
 *
 * PhishOps Security Suite — MV3 Background Service Worker
 *
 * Registers webRequest listeners for all OAuthGuard detectors and routes
 * alerts through the telemetry pipeline to BrowserPhishingTelemetry_CL.
 *
 * Detector chain (webRequest.onBeforeRequest):
 *   1. Device code flow detection (EXISTING)
 *   2. [NEW Wave 1] OAuth state parameter email encoding
 */

'use strict';

import { detectDeviceCodeFlow } from '../oauthguard/detectors/device_code_detector.js';
import { detectStateParameterAbuse } from '../oauthguard/detectors/state_parameter_abuse.js';

// ---------------------------------------------------------------------------
// Telemetry pipeline
// Stub — replace with DCR HTTP Data Collection API POST in production.
// ---------------------------------------------------------------------------

/**
 * Emit a structured alert event to BrowserPhishingTelemetry_CL.
 * @param {Object} event
 */
function emitTelemetry(event) {
  console.info('[TELEMETRY_EMIT]', JSON.stringify(event));
  // Production: POST to Azure Monitor DCR ingestion endpoint
  // fetch(DCR_ENDPOINT, { method: 'POST', body: JSON.stringify([event]), headers: {...} })
}

// ---------------------------------------------------------------------------
// webRequest URL filter
// Covers all OAuth authorization and device code endpoints across the
// major identity providers OAuthGuard monitors.
// ---------------------------------------------------------------------------
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
    '*://accounts.google.com/o/oauth2/v2/auth*',
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

// ---------------------------------------------------------------------------
// Main webRequest listener
// ---------------------------------------------------------------------------
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const { url, tabId } = details;

    console.debug('[SERVICE_WORKER] onBeforeRequest url=%s', url.substring(0, 120));

    // ------------------------------------------------------------------ //
    // Detector 1 — Device code flow (EXISTING)
    // ------------------------------------------------------------------ //
    const deviceResult = detectDeviceCodeFlow(url, '');
    if (deviceResult.detected) {
      console.warn(
        '[SERVICE_WORKER] device_code_flow fired endpoint=%s risk=%.2f url=%s',
        deviceResult.endpoint,
        deviceResult.riskScore,
        url.substring(0, 120),
      );
      emitTelemetry({
        eventType:            'OAUTH_DEVICE_CODE_FLOW',
        tabId,
        url:                  url.substring(0, 500),
        endpoint:             deviceResult.endpoint,
        requestedScopes:      deviceResult.requestedScopes,
        hasHighPrivilegeScope: deviceResult.hasHighPrivilegeScope,
        riskScore:            deviceResult.riskScore,
        signals:              deviceResult.signals,
        timestamp:            new Date().toISOString(),
        severity:             deviceResult.riskScore >= 0.85 ? 'Critical' : 'High',
      });
    }

    // ------------------------------------------------------------------ //
    // Detector 2 — OAuth state parameter email encoding (NEW Wave 1)
    // Threat: Microsoft March 2, 2026 — attacker base64-encodes victim
    // email into the state= parameter as a C2 exfil channel.
    // ------------------------------------------------------------------ //
    const stateResult = detectStateParameterAbuse(url);
    if (stateResult.detected) {
      console.warn(
        '[SERVICE_WORKER] state_parameter_abuse fired email=%s url=%s',
        stateResult.decodedEmail,
        url.substring(0, 120),
      );
      emitTelemetry({
        eventType:      'OAUTH_STATE_EMAIL_ENCODED',
        tabId,
        url:            url.substring(0, 500),
        decodedEmail:   stateResult.decodedEmail,
        stateValue:     stateResult.stateValue,
        encodingMethod: stateResult.encodingMethod,
        riskScore:      stateResult.riskScore,
        signals:        stateResult.signals,
        timestamp:      new Date().toISOString(),
        severity:       'High',
      });
    }
  },
  OAUTH_URL_FILTER,
  // 'requestBody' would be needed to inspect POST bodies for device code grants —
  // left out here as state= abuse only occurs in GET authorization URLs.
);
