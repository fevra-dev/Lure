/**
 * extension/__tests__/qrljacking_guard.test.js
 *
 * Tests for QRLjackingGuard — QR code session hijacking detector.
 *
 * jsdom limitations:
 *   - innerText returns empty — use innerText || textContent fallback (already in source).
 *   - getBoundingClientRect() must be mocked for element dimension checks.
 *   - window.location must be mocked for origin comparison tests.
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

import {
  isQRLikeElement,
  trackImageRefresh,
  checkRefreshSignals,
  checkQRPageContext,
  calculateQRLjackingRiskScore,
  injectQRLjackingWarningBanner,
} from '../content/qrljacking_guard.js';

beforeEach(() => {
  document.body.innerHTML = '';
  document.getElementById('phishops-qrljacking-warning')?.remove();
  document.querySelectorAll('.phishops-qr-overlay').forEach(el => el.remove());
  vi.clearAllMocks();
});

// Helper: create a mock element with getBoundingClientRect
function mockImgElement(width, height, tag = 'IMG') {
  const el = document.createElement(tag.toLowerCase());
  // jsdom doesn't set tagName correctly for non-standard usage, but
  // document.createElement('img') gives tagName 'IMG' as expected.
  el.getBoundingClientRect = () => ({
    width, height, top: 0, left: 0, right: width, bottom: height,
  });
  el.width = width;
  el.height = height;
  return el;
}

// =========================================================================
// isQRLikeElement
// =========================================================================

describe('isQRLikeElement', () => {
  it('returns true for square IMG in valid range', () => {
    const el = mockImgElement(200, 200);
    expect(isQRLikeElement(el)).toBe(true);
  });

  it('returns true for CANVAS in valid range', () => {
    const el = mockImgElement(150, 150, 'CANVAS');
    expect(isQRLikeElement(el)).toBe(true);
  });

  it('returns true at minimum size boundary (100px)', () => {
    const el = mockImgElement(100, 100);
    expect(isQRLikeElement(el)).toBe(true);
  });

  it('returns true at maximum size boundary (500px)', () => {
    const el = mockImgElement(500, 500);
    expect(isQRLikeElement(el)).toBe(true);
  });

  it('returns true for slightly rectangular (within 20% tolerance)', () => {
    // 200 x 230 → ratio 0.87 which is within 0.80–1.20
    const el = mockImgElement(200, 230);
    expect(isQRLikeElement(el)).toBe(true);
  });

  it('rejects elements too small', () => {
    const el = mockImgElement(50, 50);
    expect(isQRLikeElement(el)).toBe(false);
  });

  it('rejects elements too large', () => {
    const el = mockImgElement(600, 600);
    expect(isQRLikeElement(el)).toBe(false);
  });

  it('rejects non-square elements (outside tolerance)', () => {
    // 200 x 400 → ratio 0.5, outside 0.80–1.20
    const el = mockImgElement(200, 400);
    expect(isQRLikeElement(el)).toBe(false);
  });

  it('rejects non-IMG/CANVAS elements', () => {
    const el = document.createElement('div');
    el.getBoundingClientRect = () => ({ width: 200, height: 200, top: 0, left: 0, right: 200, bottom: 200 });
    expect(isQRLikeElement(el)).toBe(false);
  });

  it('returns false for null/undefined', () => {
    expect(isQRLikeElement(null)).toBe(false);
    expect(isQRLikeElement(undefined)).toBe(false);
  });

  it('rejects zero-dimension elements', () => {
    const el = mockImgElement(0, 0);
    expect(isQRLikeElement(el)).toBe(false);
  });
});

// =========================================================================
// trackImageRefresh
// =========================================================================

describe('trackImageRefresh', () => {
  it('counts first refresh as 1', () => {
    const el = mockImgElement(200, 200);
    const result = trackImageRefresh(el);
    expect(result.count).toBe(1);
  });

  it('increments count on subsequent refreshes', () => {
    const el = mockImgElement(200, 200);
    trackImageRefresh(el);
    trackImageRefresh(el);
    const result = trackImageRefresh(el);
    expect(result.count).toBe(3);
  });

  it('tracks separate elements independently', () => {
    const el1 = mockImgElement(200, 200);
    const el2 = mockImgElement(200, 200);
    trackImageRefresh(el1);
    trackImageRefresh(el1);
    trackImageRefresh(el2);
    expect(trackImageRefresh(el1).count).toBe(3);
    expect(trackImageRefresh(el2).count).toBe(2);
  });

  it('returns interval of 0 for single refresh', () => {
    const el = mockImgElement(200, 200);
    const result = trackImageRefresh(el);
    expect(result.interval).toBe(0);
  });
});

// =========================================================================
// checkRefreshSignals
// =========================================================================

describe('checkRefreshSignals', () => {
  it('detects rapid image refresh (count >= 3)', () => {
    const el = mockImgElement(200, 200);
    const refreshData = { count: 3, interval: 3000 };
    const signals = checkRefreshSignals(el, refreshData);
    expect(signals.some(s => s.id === 'qrljack:rapid_image_refresh')).toBe(true);
  });

  it('does NOT flag slow refresh (count < 3)', () => {
    const el = mockImgElement(200, 200);
    const refreshData = { count: 2, interval: 5000 };
    const signals = checkRefreshSignals(el, refreshData);
    expect(signals.some(s => s.id === 'qrljack:rapid_image_refresh')).toBe(false);
  });

  it('detects cross-origin image source', () => {
    const el = mockImgElement(200, 200);
    el.setAttribute('src', 'https://evil-site.com/qr.png');
    const refreshData = { count: 3, interval: 3000 };
    const signals = checkRefreshSignals(el, refreshData);
    expect(signals.some(s => s.id === 'qrljack:cross_origin_image')).toBe(true);
  });

  it('does NOT flag same-origin image source', () => {
    const el = mockImgElement(200, 200);
    // jsdom default origin is "null" (about:blank), so use a non-http src
    // to avoid triggering the cross-origin check (only http(s) URLs are checked)
    el.setAttribute('src', 'data:image/png;base64,iVBOR');
    const refreshData = { count: 3, interval: 3000 };
    const signals = checkRefreshSignals(el, refreshData);
    expect(signals.some(s => s.id === 'qrljack:cross_origin_image')).toBe(false);
  });

  it('does NOT flag relative image source (no cross-origin check)', () => {
    const el = mockImgElement(200, 200);
    el.setAttribute('src', '/images/qr.png');
    const refreshData = { count: 3, interval: 3000 };
    const signals = checkRefreshSignals(el, refreshData);
    expect(signals.some(s => s.id === 'qrljack:cross_origin_image')).toBe(false);
  });

  it('does NOT flag canvas elements for cross-origin (no src)', () => {
    const el = mockImgElement(200, 200, 'CANVAS');
    const refreshData = { count: 3, interval: 3000 };
    const signals = checkRefreshSignals(el, refreshData);
    expect(signals.some(s => s.id === 'qrljack:cross_origin_image')).toBe(false);
  });
});

// =========================================================================
// checkQRPageContext
// =========================================================================

describe('checkQRPageContext', () => {
  it('detects auth page context (sign in text)', () => {
    document.body.textContent = 'Please sign in to continue with your account verification.';
    const signals = checkQRPageContext();
    expect(signals.some(s => s.id === 'qrljack:auth_page_context')).toBe(true);
  });

  it('detects auth page context (scan QR text)', () => {
    document.body.textContent = 'Scan this QR code with your phone to authenticate.';
    const signals = checkQRPageContext();
    expect(signals.some(s => s.id === 'qrljack:auth_page_context')).toBe(true);
  });

  it('detects device code reference in body text', () => {
    document.body.textContent = 'Visit https://microsoft.com/devicelogin to enter your code.';
    const signals = checkQRPageContext();
    expect(signals.some(s => s.id === 'qrljack:device_code_reference')).toBe(true);
  });

  it('detects device code reference in HTML', () => {
    document.body.innerHTML = '<a href="https://login.microsoftonline.com/oauth2/deviceauth">Login</a>';
    const signals = checkQRPageContext();
    expect(signals.some(s => s.id === 'qrljack:device_code_reference')).toBe(true);
  });

  it('detects non-platform origin (localhost is not a known QR platform)', () => {
    const signals = checkQRPageContext();
    // localhost is not in KNOWN_QR_AUTH_PLATFORMS
    expect(signals.some(s => s.id === 'qrljack:non_platform_origin')).toBe(true);
  });

  it('returns no auth_page_context for clean page', () => {
    document.body.textContent = 'Welcome to our product catalog. Browse our selection.';
    const signals = checkQRPageContext();
    expect(signals.some(s => s.id === 'qrljack:auth_page_context')).toBe(false);
  });

  it('returns no device_code_reference for clean page', () => {
    document.body.textContent = 'Welcome to our product catalog.';
    const signals = checkQRPageContext();
    expect(signals.some(s => s.id === 'qrljack:device_code_reference')).toBe(false);
  });
});

// =========================================================================
// calculateQRLjackingRiskScore
// =========================================================================

describe('calculateQRLjackingRiskScore', () => {
  it('returns 0.0 for empty signals', () => {
    const { riskScore, signalList } = calculateQRLjackingRiskScore([]);
    expect(riskScore).toBe(0.0);
    expect(signalList).toHaveLength(0);
  });

  it('returns correct score for single signal', () => {
    const { riskScore } = calculateQRLjackingRiskScore([
      { id: 'qrljack:rapid_image_refresh', weight: 0.45 },
    ]);
    expect(riskScore).toBe(0.45);
  });

  it('sums multiple signals', () => {
    const { riskScore, signalList } = calculateQRLjackingRiskScore([
      { id: 'qrljack:rapid_image_refresh', weight: 0.45 },
      { id: 'qrljack:cross_origin_image', weight: 0.25 },
    ]);
    expect(riskScore).toBe(0.70);
    expect(signalList).toHaveLength(2);
  });

  it('caps at 1.0', () => {
    const { riskScore } = calculateQRLjackingRiskScore([
      { id: 'qrljack:rapid_image_refresh', weight: 0.45 },
      { id: 'qrljack:cross_origin_image', weight: 0.25 },
      { id: 'qrljack:device_code_reference', weight: 0.30 },
      { id: 'qrljack:non_platform_origin', weight: 0.25 },
    ]);
    expect(riskScore).toBe(1.0);
  });

  it('alert threshold is 0.50', () => {
    const { riskScore } = calculateQRLjackingRiskScore([
      { id: 'qrljack:rapid_image_refresh', weight: 0.45 },
      { id: 'qrljack:auth_page_context', weight: 0.20 },
    ]);
    expect(riskScore).toBe(0.65);
    expect(riskScore).toBeGreaterThanOrEqual(0.50);
  });

  it('block threshold is 0.70', () => {
    const { riskScore } = calculateQRLjackingRiskScore([
      { id: 'qrljack:rapid_image_refresh', weight: 0.45 },
      { id: 'qrljack:cross_origin_image', weight: 0.25 },
    ]);
    expect(riskScore).toBe(0.70);
    expect(riskScore).toBeGreaterThanOrEqual(0.70);
  });

  it('includes all signal IDs in signalList', () => {
    const { signalList } = calculateQRLjackingRiskScore([
      { id: 'qrljack:rapid_image_refresh', weight: 0.45 },
      { id: 'qrljack:iframe_qr_proxy', weight: 0.30 },
    ]);
    expect(signalList).toEqual(['qrljack:rapid_image_refresh', 'qrljack:iframe_qr_proxy']);
  });
});

// =========================================================================
// injectQRLjackingWarningBanner
// =========================================================================

describe('injectQRLjackingWarningBanner', () => {
  it('injects a banner into the DOM', () => {
    injectQRLjackingWarningBanner(0.65, null, ['qrljack:rapid_image_refresh']);
    const banner = document.getElementById('phishops-qrljacking-warning');
    expect(banner).not.toBeNull();
    expect(banner.getAttribute('role')).toBe('alert');
  });

  it('is idempotent', () => {
    injectQRLjackingWarningBanner(0.65, null, ['a']);
    injectQRLjackingWarningBanner(0.80, null, ['b']);
    const banners = document.querySelectorAll('#phishops-qrljacking-warning');
    expect(banners).toHaveLength(1);
  });

  it('displays the risk score', () => {
    injectQRLjackingWarningBanner(0.75, null, ['qrljack:rapid_image_refresh']);
    const banner = document.getElementById('phishops-qrljacking-warning');
    expect(banner.textContent).toContain('0.75');
  });

  it('contains QRLjacking-specific title text', () => {
    injectQRLjackingWarningBanner(0.65, null, ['qrljack:rapid_image_refresh']);
    const banner = document.getElementById('phishops-qrljacking-warning');
    expect(banner.textContent).toContain('qr session hijacking detected');
  });

  it('dismiss button removes the banner', () => {
    injectQRLjackingWarningBanner(0.65, null, ['qrljack:rapid_image_refresh']);
    const dismissBtn = document.getElementById('phishops-qrljacking-dismiss');
    expect(dismissBtn).not.toBeNull();
    dismissBtn.click();
    expect(document.getElementById('phishops-qrljacking-warning')).toBeNull();
  });

  it('adds QR overlay when risk score >= 0.70 and element provided', () => {
    const el = mockImgElement(200, 200);
    document.body.appendChild(el);
    injectQRLjackingWarningBanner(0.75, el, ['qrljack:rapid_image_refresh']);
    const overlays = document.querySelectorAll('.phishops-qr-overlay');
    expect(overlays).toHaveLength(1);
    expect(overlays[0].textContent).toContain('QR blocked by PhishOps');
  });

  it('does NOT add QR overlay when risk score < 0.70', () => {
    const el = mockImgElement(200, 200);
    document.body.appendChild(el);
    injectQRLjackingWarningBanner(0.55, el, ['qrljack:rapid_image_refresh']);
    const overlays = document.querySelectorAll('.phishops-qr-overlay');
    expect(overlays).toHaveLength(0);
  });
});
