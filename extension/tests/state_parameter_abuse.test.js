/**
 * extension/__tests__/state_parameter_abuse.test.js
 *
 * Vitest unit tests for the OAuth state parameter email encoding detector.
 * Migrated from wave1/state_parameter_abuse.test.js with updated import paths.
 *
 * Run: npx vitest run
 */

import { describe, it, expect } from 'vitest';
import { detectStateParameterAbuse } from '../content/state_parameter_abuse.js';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const VICTIM_EMAIL_B64 = 'dmljdGltQGNvcnAuY29t'; // btoa('victim@corp.com')

const TEST_EMAIL_B64_URLSAFE = btoa('test@example.com')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '');

const ADMIN_EMAIL_HEX = Array.from('admin@target.org')
  .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
  .join('');

// ---------------------------------------------------------------------------
// Detection cases
// ---------------------------------------------------------------------------

describe('detectStateParameterAbuse — detection cases', () => {

  it('detects standard base64-encoded email on Microsoft OAuth URL', () => {
    const url =
      'https://login.microsoftonline.com/common/oauth2/authorize' +
      `?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46` +
      `&response_type=code` +
      `&redirect_uri=https://attacker.com/callback` +
      `&state=${VICTIM_EMAIL_B64}` +
      `&scope=openid profile email`;

    const result = detectStateParameterAbuse(url);

    expect(result.detected).toBe(true);
    expect(result.type).toBe('OAUTH_STATE_EMAIL_ENCODED');
    expect(result.decodedEmail).toBe('victim@corp.com');
    expect(result.encodingMethod).toBe('base64');
    expect(result.riskScore).toBeGreaterThanOrEqual(0.80);
    expect(result.signals.some(s => s.includes('email_in_state_param'))).toBe(true);
    expect(result.signals.some(s => s.includes('oauth_endpoint'))).toBe(true);
  });

  it('detects URL-safe base64 (- and _ instead of + and /)', () => {
    const url = `https://accounts.google.com/o/oauth2/auth?state=${TEST_EMAIL_B64_URLSAFE}&client_id=x`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(true);
    expect(result.decodedEmail).toBe('test@example.com');
    expect(result.encodingMethod).toBe('base64');
  });

  it('detects hex-encoded email address in state param', () => {
    const url =
      `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` +
      `?state=${ADMIN_EMAIL_HEX}&client_id=abc&response_type=code`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(true);
    expect(result.decodedEmail).toBe('admin@target.org');
    expect(result.encodingMethod).toBe('hex');
  });

  it('detects URL percent-encoded email in state param', () => {
    const urlEncodedEmail = encodeURIComponent('user@company.net');
    const url =
      `https://login.microsoftonline.com/common/oauth2/authorize` +
      `?state=${urlEncodedEmail}&client_id=abc&response_type=code`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(true);
    expect(result.decodedEmail).toBe('user@company.net');
    expect(result.encodingMethod).toBe('url');
  });

  it('detects on Google OAuth endpoint', () => {
    const url =
      `https://accounts.google.com/o/oauth2/v2/auth` +
      `?client_id=x&state=${btoa('ciso@bigcorp.com')}&response_type=code`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(true);
    expect(result.decodedEmail).toBe('ciso@bigcorp.com');
  });

  it('detects on login.live.com endpoint', () => {
    const url =
      `https://login.live.com/oauth20_authorize.srf` +
      `?state=${btoa('target@hotmail.com')}&client_id=abc`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(true);
    expect(result.decodedEmail).toBe('target@hotmail.com');
  });

  it('stateValue in result is truncated to 64 chars max', () => {
    const longEmail = 'averylongemailaddress123456789@someverylongcorporatedomain.example.com';
    const url =
      `https://login.microsoftonline.com/common/oauth2/authorize` +
      `?state=${btoa(longEmail)}&client_id=abc`;
    const result = detectStateParameterAbuse(url);
    if (result.detected) {
      expect(result.stateValue.length).toBeLessThanOrEqual(64);
    }
    expect(result).toBeDefined();
  });

  it('riskScore is exactly 0.85 on confirmed detection', () => {
    const url =
      `https://login.microsoftonline.com/common/oauth2/authorize` +
      `?state=${VICTIM_EMAIL_B64}&client_id=abc`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(true);
    expect(result.riskScore).toBe(0.85);
  });
});

// ---------------------------------------------------------------------------
// Clean cases
// ---------------------------------------------------------------------------

describe('detectStateParameterAbuse — clean cases', () => {

  it('does not fire on a non-OAuth endpoint', () => {
    const url = `https://example.com/page?state=${VICTIM_EMAIL_B64}`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
    expect(result.signals).toContain('not_oauth_endpoint');
  });

  it('does not fire when state param is a standard CSRF token', () => {
    const url =
      'https://login.microsoftonline.com/common/oauth2/authorize' +
      '?state=f4a3c2b1d9e8a7f6e5d4c3b2a1f0e9d8' +
      '&client_id=some-client-id&response_type=code';
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
  });

  it('does not fire when state param is a short random nonce', () => {
    const url =
      'https://login.microsoftonline.com/common/oauth2/authorize' +
      '?state=abc123&client_id=x';
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
  });

  it('does not fire when no state param is present', () => {
    const url =
      'https://login.microsoftonline.com/common/oauth2/authorize' +
      '?client_id=abc&response_type=code&scope=openid';
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
    expect(result.signals).toContain('no_state_param');
  });

  it('does not fire when state param decodes to a non-email string', () => {
    const url =
      'https://login.microsoftonline.com/common/oauth2/authorize' +
      `?state=${btoa('hello world')}&client_id=abc`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
    expect(result.signals).toContain('state_decoded_not_email');
  });

  it('does not fire on a clean MSAL state token (JSON)', () => {
    const msalState = btoa(JSON.stringify({ id: 'abc123', ts: 1741000000, method: 'silentInteraction' }));
    const url =
      'https://login.microsoftonline.com/common/oauth2/v2.0/authorize' +
      `?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46` +
      `&scope=openid profile email` +
      `&state=${msalState}` +
      `&response_type=code`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
  });

  it('does not fire when state is binary (non-printable base64)', () => {
    const binaryB64 = btoa('\x00\x01\x02\x03\xff\xfe\xfd');
    const url =
      `https://login.microsoftonline.com/common/oauth2/authorize?state=${binaryB64}&client_id=x`;
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Error resilience
// ---------------------------------------------------------------------------

describe('detectStateParameterAbuse — error resilience', () => {

  it('returns detected:false (no throw) on completely malformed URL', () => {
    expect(() => detectStateParameterAbuse('not a url at all %%%')).not.toThrow();
    const result = detectStateParameterAbuse('not a url at all %%%');
    expect(result.detected).toBe(false);
  });

  it('returns detected:false (no throw) on empty string', () => {
    expect(() => detectStateParameterAbuse('')).not.toThrow();
    const result = detectStateParameterAbuse('');
    expect(result.detected).toBe(false);
  });

  it('returns detected:false (no throw) on null input', () => {
    expect(() => detectStateParameterAbuse(null)).not.toThrow();
    const result = detectStateParameterAbuse(null);
    expect(result.detected).toBe(false);
  });

  it('returns detected:false (no throw) on undefined input', () => {
    expect(() => detectStateParameterAbuse(undefined)).not.toThrow();
    const result = detectStateParameterAbuse(undefined);
    expect(result.detected).toBe(false);
  });

  it('always returns a non-empty signals array', () => {
    const inputs = [
      null, '', 'not-a-url',
      'https://login.microsoftonline.com/auth?state=abc&client_id=x',
      `https://login.microsoftonline.com/auth?state=${VICTIM_EMAIL_B64}&client_id=x`,
    ];
    for (const input of inputs) {
      const result = detectStateParameterAbuse(input);
      expect(Array.isArray(result.signals)).toBe(true);
      expect(result.signals.length).toBeGreaterThan(0);
    }
  });

  it('always returns empty string fields when not detected', () => {
    const url = 'https://login.microsoftonline.com/auth?client_id=x';
    const result = detectStateParameterAbuse(url);
    expect(result.detected).toBe(false);
    expect(result.type).toBe('');
    expect(result.decodedEmail).toBe('');
    expect(result.stateValue).toBe('');
    expect(result.encodingMethod).toBe('');
    expect(result.riskScore).toBe(0.0);
  });
});
