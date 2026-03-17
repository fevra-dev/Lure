/**
 * extension/__tests__/screenshare_guard.test.js
 *
 * Tests for ScreenShareGuard — TOAD screen share detection.
 *
 * jsdom limitations:
 *   - navigator.mediaDevices not available. Mocked via Object.defineProperty.
 *   - getDisplayMedia() returns a fake MediaStream.
 *   - MediaStreamTrack mocked with ended event support.
 *   - focusin events work natively in jsdom.
 *   - hostname is localhost (skipped by platform/localhost checks).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock chrome APIs before importing the module
const mockSendMessage = vi.fn();
vi.stubGlobal('chrome', {
  runtime: {
    id: 'test-extension-id',
    sendMessage: mockSendMessage,
  },
});

import {
  checkScreenShareSignals,
  checkScreenSharePageContext,
  calculateScreenShareRiskScore,
  injectScreenShareWarningBanner,
  installGetDisplayMediaInterceptor,
  monitorCredentialFieldsDuringShare,
  _setLastGestureTimestamp,
  _isScreenShareActive,
  _setScreenShareActive,
} from '../content/screenshare_guard.js';

beforeEach(() => {
  document.body.innerHTML = '';
  document.getElementById('phishops-screenshare-warning')?.remove();
  document.getElementById('phishops-screenshare-cred-warning')?.remove();
  vi.clearAllMocks();
  _setLastGestureTimestamp(0);
  _setScreenShareActive(false);
});

// =========================================================================
// checkScreenShareSignals
// =========================================================================

describe('checkScreenShareSignals', () => {
  it('does NOT flag localhost as non-platform origin', () => {
    // jsdom hostname is localhost
    const signals = checkScreenShareSignals();
    expect(signals.some(s => s.id === 'screenshare:non_platform_origin')).toBe(false);
  });

  it('detects no user gesture', () => {
    _setLastGestureTimestamp(0); // Very old
    const signals = checkScreenShareSignals();
    expect(signals.some(s => s.id === 'screenshare:no_user_gesture')).toBe(true);
    expect(signals.find(s => s.id === 'screenshare:no_user_gesture').weight).toBe(0.30);
  });

  it('does NOT flag when gesture is recent', () => {
    _setLastGestureTimestamp(Date.now());
    const signals = checkScreenShareSignals();
    expect(signals.some(s => s.id === 'screenshare:no_user_gesture')).toBe(false);
  });

  it('detects cross-origin iframe when self !== top', () => {
    // In jsdom, window.self === window.top, so this won't fire
    // We just confirm the signal doesn't fire on top-level
    const signals = checkScreenShareSignals();
    expect(signals.some(s => s.id === 'screenshare:cross_origin_iframe')).toBe(false);
  });

  it('handles gracefully with multiple signals', () => {
    _setLastGestureTimestamp(0);
    const signals = checkScreenShareSignals();
    // At minimum, no_user_gesture fires
    expect(signals.some(s => s.id === 'screenshare:no_user_gesture')).toBe(true);
  });
});

// =========================================================================
// checkScreenSharePageContext
// =========================================================================

describe('checkScreenSharePageContext', () => {
  it('returns empty for localhost (jsdom default)', () => {
    document.body.textContent = 'tech support remote assistance help desk';
    const signals = checkScreenSharePageContext();
    // localhost is explicitly skipped
    expect(signals).toHaveLength(0);
  });

  it('returns empty for clean page on localhost', () => {
    document.body.textContent = 'Welcome to our platform.';
    const signals = checkScreenSharePageContext();
    expect(signals).toHaveLength(0);
  });
});

// =========================================================================
// calculateScreenShareRiskScore
// =========================================================================

describe('calculateScreenShareRiskScore', () => {
  it('returns 0.0 for empty signals', () => {
    const { riskScore, signalList } = calculateScreenShareRiskScore([]);
    expect(riskScore).toBe(0.0);
    expect(signalList).toHaveLength(0);
  });

  it('returns correct score for single signal', () => {
    const { riskScore } = calculateScreenShareRiskScore([
      { id: 'screenshare:non_platform_origin', weight: 0.35 },
    ]);
    expect(riskScore).toBe(0.35);
  });

  it('sums multiple signals', () => {
    const { riskScore, signalList } = calculateScreenShareRiskScore([
      { id: 'screenshare:non_platform_origin', weight: 0.35 },
      { id: 'screenshare:no_user_gesture', weight: 0.30 },
    ]);
    expect(riskScore).toBe(0.65);
    expect(signalList).toHaveLength(2);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculateScreenShareRiskScore([
      { id: 'screenshare:non_platform_origin', weight: 0.35 },
      { id: 'screenshare:no_user_gesture', weight: 0.30 },
      { id: 'screenshare:support_page_context', weight: 0.25 },
      { id: 'screenshare:credential_during_share', weight: 0.40 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('alert threshold is 0.50', () => {
    const { riskScore } = calculateScreenShareRiskScore([
      { id: 'screenshare:non_platform_origin', weight: 0.35 },
      { id: 'screenshare:rapid_share_request', weight: 0.20 },
    ]);
    expect(riskScore).toBe(0.55);
    expect(riskScore).toBeGreaterThanOrEqual(0.50);
  });

  it('block threshold is 0.70', () => {
    const { riskScore } = calculateScreenShareRiskScore([
      { id: 'screenshare:non_platform_origin', weight: 0.35 },
      { id: 'screenshare:no_user_gesture', weight: 0.30 },
      { id: 'screenshare:support_page_context', weight: 0.25 },
    ]);
    expect(riskScore).toBe(0.90);
    expect(riskScore).toBeGreaterThanOrEqual(0.70);
  });

  it('includes all signal IDs in signalList', () => {
    const { signalList } = calculateScreenShareRiskScore([
      { id: 'screenshare:non_platform_origin', weight: 0.35 },
      { id: 'screenshare:no_user_gesture', weight: 0.30 },
    ]);
    expect(signalList).toEqual(['screenshare:non_platform_origin', 'screenshare:no_user_gesture']);
  });
});

// =========================================================================
// injectScreenShareWarningBanner
// =========================================================================

describe('injectScreenShareWarningBanner', () => {
  it('injects a banner into the DOM', () => {
    injectScreenShareWarningBanner(0.75, ['screenshare:non_platform_origin']);
    const banner = document.getElementById('phishops-screenshare-warning');
    expect(banner).not.toBeNull();
    expect(banner.getAttribute('role')).toBe('alert');
  });

  it('is idempotent', () => {
    injectScreenShareWarningBanner(0.75, ['a']);
    injectScreenShareWarningBanner(0.80, ['b']);
    const banners = document.querySelectorAll('#phishops-screenshare-warning');
    expect(banners).toHaveLength(1);
  });

  it('displays the risk score', () => {
    injectScreenShareWarningBanner(0.85, ['screenshare:non_platform_origin']);
    const banner = document.getElementById('phishops-screenshare-warning');
    expect(banner.textContent).toContain('0.85');
  });

  it('contains screenshare-specific title text', () => {
    injectScreenShareWarningBanner(0.75, ['screenshare:non_platform_origin']);
    const banner = document.getElementById('phishops-screenshare-warning');
    expect(banner.textContent).toContain('suspicious screen share detected');
  });

  it('contains credential avoidance warning', () => {
    injectScreenShareWarningBanner(0.75, ['screenshare:non_platform_origin']);
    const banner = document.getElementById('phishops-screenshare-warning');
    expect(banner.textContent).toContain('Avoid entering credentials');
  });

  it('dismiss button removes the banner', () => {
    injectScreenShareWarningBanner(0.75, ['screenshare:non_platform_origin']);
    const dismissBtn = document.getElementById('phishops-screenshare-dismiss');
    expect(dismissBtn).not.toBeNull();
    dismissBtn.click();
    expect(document.getElementById('phishops-screenshare-warning')).toBeNull();
  });
});

// =========================================================================
// monitorCredentialFieldsDuringShare
// =========================================================================

describe('monitorCredentialFieldsDuringShare', () => {
  function createMockStream() {
    const endedListeners = [];
    const mockTrack = {
      addEventListener: vi.fn((event, handler) => {
        if (event === 'ended') endedListeners.push(handler);
      }),
    };
    return {
      stream: { getTracks: vi.fn().mockReturnValue([mockTrack]) },
      endShare: () => endedListeners.forEach(fn => fn()),
    };
  }

  it('sets activeScreenShare to true', () => {
    const { stream } = createMockStream();
    monitorCredentialFieldsDuringShare(stream);
    expect(_isScreenShareActive()).toBe(true);
  });

  it('fires credential warning when password field is focused during share', () => {
    const { stream } = createMockStream();
    monitorCredentialFieldsDuringShare(stream);

    const passwordInput = document.createElement('input');
    passwordInput.type = 'password';
    document.body.appendChild(passwordInput);

    passwordInput.dispatchEvent(new Event('focusin', { bubbles: true }));

    expect(mockSendMessage).toHaveBeenCalled();
    const call = mockSendMessage.mock.calls[0][0];
    expect(call.type).toBe('SCREENSHAREGUARD_EVENT');
    expect(call.payload.action).toBe('credential_warning');
    expect(call.payload.credentialFieldFocused).toBe(true);
    expect(call.payload.riskScore).toBe(0.90);
    expect(call.payload.severity).toBe('Critical');

    // Credential warning banner should appear
    const banner = document.getElementById('phishops-screenshare-cred-warning');
    expect(banner).not.toBeNull();
  });

  it('does NOT fire for regular text input during share', () => {
    const { stream } = createMockStream();
    monitorCredentialFieldsDuringShare(stream);

    const textInput = document.createElement('input');
    textInput.type = 'text';
    textInput.name = 'search-query';
    document.body.appendChild(textInput);

    textInput.dispatchEvent(new Event('focusin', { bubbles: true }));

    expect(mockSendMessage).not.toHaveBeenCalled();
  });

  it('fires for input with autocomplete=current-password', () => {
    const { stream } = createMockStream();
    monitorCredentialFieldsDuringShare(stream);

    const input = document.createElement('input');
    input.type = 'text';
    input.autocomplete = 'current-password';
    document.body.appendChild(input);

    input.dispatchEvent(new Event('focusin', { bubbles: true }));

    expect(mockSendMessage).toHaveBeenCalled();
  });

  it('fires for input with name containing "pass"', () => {
    const { stream } = createMockStream();
    monitorCredentialFieldsDuringShare(stream);

    const input = document.createElement('input');
    input.type = 'text';
    input.name = 'user_password';
    document.body.appendChild(input);

    input.dispatchEvent(new Event('focusin', { bubbles: true }));

    expect(mockSendMessage).toHaveBeenCalled();
  });

  it('stops monitoring when share ends', () => {
    const { stream, endShare } = createMockStream();
    monitorCredentialFieldsDuringShare(stream);

    expect(_isScreenShareActive()).toBe(true);

    endShare();

    expect(_isScreenShareActive()).toBe(false);

    // Focus a password field — should NOT fire
    const passwordInput = document.createElement('input');
    passwordInput.type = 'password';
    document.body.appendChild(passwordInput);

    passwordInput.dispatchEvent(new Event('focusin', { bubbles: true }));

    expect(mockSendMessage).not.toHaveBeenCalled();
  });

  it('removes credential warning banner when share ends', () => {
    const { stream, endShare } = createMockStream();
    monitorCredentialFieldsDuringShare(stream);

    // Trigger credential warning
    const passwordInput = document.createElement('input');
    passwordInput.type = 'password';
    document.body.appendChild(passwordInput);
    passwordInput.dispatchEvent(new Event('focusin', { bubbles: true }));

    expect(document.getElementById('phishops-screenshare-cred-warning')).not.toBeNull();

    endShare();

    expect(document.getElementById('phishops-screenshare-cred-warning')).toBeNull();
  });
});

// =========================================================================
// installGetDisplayMediaInterceptor
// =========================================================================

describe('installGetDisplayMediaInterceptor', () => {
  let mockGetDisplayMedia;

  beforeEach(() => {
    const mockTrack = {
      addEventListener: vi.fn(),
    };
    const mockStream = {
      getTracks: vi.fn().mockReturnValue([mockTrack]),
    };
    mockGetDisplayMedia = vi.fn().mockResolvedValue(mockStream);

    Object.defineProperty(navigator, 'mediaDevices', {
      value: {
        getDisplayMedia: mockGetDisplayMedia,
      },
      writable: true,
      configurable: true,
    });

    document.getElementById('phishops-screenshare-warning')?.remove();
  });

  it('installs without error', () => {
    expect(() => installGetDisplayMediaInterceptor()).not.toThrow();
  });

  it('passes through to original getDisplayMedia', async () => {
    _setLastGestureTimestamp(Date.now()); // Recent gesture
    installGetDisplayMediaInterceptor();
    const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
    expect(stream).toBeDefined();
    expect(stream.getTracks).toBeDefined();
    expect(mockGetDisplayMedia).toHaveBeenCalled();
  });

  it('sends telemetry when signals exceed alert threshold', async () => {
    // No gesture → no_user_gesture (0.30) + rapid_share_request (0.20) = 0.50
    // which hits the alert threshold
    _setLastGestureTimestamp(0);
    installGetDisplayMediaInterceptor();
    await navigator.mediaDevices.getDisplayMedia({ video: true });

    expect(mockSendMessage).toHaveBeenCalled();
    const call = mockSendMessage.mock.calls[0][0];
    expect(call.type).toBe('SCREENSHAREGUARD_EVENT');
    expect(call.payload.eventType).toBe('SCREENSHARE_TOAD_DETECTED');
    expect(call.payload.action).toBe('alerted');
    expect(call.payload.riskScore).toBeGreaterThanOrEqual(0.50);
  });

  it('starts credential monitoring after share begins', async () => {
    _setLastGestureTimestamp(Date.now());
    installGetDisplayMediaInterceptor();
    await navigator.mediaDevices.getDisplayMedia({ video: true });

    // After the interceptor runs, screen share should be active
    expect(_isScreenShareActive()).toBe(true);
  });
});
