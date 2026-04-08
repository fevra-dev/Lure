/**
 * extension/__tests__/notification_guard.test.js
 *
 * Tests for NotificationGuard — Browser Push Notification Phishing
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

import '../content/notification_guard.js';
const { checkPermissionRequestWithoutGesture, checkFakeVerificationLure, checkNotificationUrgencyContent, checkRapidPermissionOnLoad, checkCrossOriginNotificationLink, calculateNotifRiskScore, injectNotifWarningBanner, runNotificationGuardAnalysis, _resetState } = globalThis.__phishopsExports['notification_guard'];

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function makeDoc(html = '<html><body></body></html>') {
  const dom = new JSDOM(html);
  return dom.window.document;
}

const NOW = 1700000000000;

/* ------------------------------------------------------------------ */
/*  Setup                                                              */
/* ------------------------------------------------------------------ */

beforeEach(() => {
  _resetState();
});

/* ------------------------------------------------------------------ */
/*  checkPermissionRequestWithoutGesture                               */
/* ------------------------------------------------------------------ */

describe('checkPermissionRequestWithoutGesture', () => {
  it('detects permission request without recent gesture', () => {
    const permCalls = [{ timestamp: NOW }];
    const gestures = [{ timestamp: NOW - 5000 }]; // 5s ago — outside 1s window
    const signals = checkPermissionRequestWithoutGesture(permCalls, gestures);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('notif:permission_request_without_gesture');
    expect(signals[0].weight).toBe(0.40);
  });

  it('returns empty when gesture is within 1s window', () => {
    const permCalls = [{ timestamp: NOW }];
    const gestures = [{ timestamp: NOW - 500 }]; // 500ms ago — within window
    expect(checkPermissionRequestWithoutGesture(permCalls, gestures)).toEqual([]);
  });

  it('returns empty when no permission calls', () => {
    expect(checkPermissionRequestWithoutGesture([], [])).toEqual([]);
    expect(checkPermissionRequestWithoutGesture(null, [])).toEqual([]);
  });

  it('detects when gesture log is empty', () => {
    const permCalls = [{ timestamp: NOW }];
    const signals = checkPermissionRequestWithoutGesture(permCalls, []);
    expect(signals).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ */
/*  checkFakeVerificationLure                                          */
/* ------------------------------------------------------------------ */

describe('checkFakeVerificationLure', () => {
  it('detects "Click Allow to verify" lure', () => {
    const doc = makeDoc(`<html><body>
      <h1>Click Allow to verify you are not a robot</h1>
    </body></html>`);
    const permCalls = [{ timestamp: NOW }];
    const signals = checkFakeVerificationLure(doc, permCalls);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('notif:fake_verification_lure');
    expect(signals[0].weight).toBe(0.30);
  });

  it('detects "Press Allow to continue" lure', () => {
    const doc = makeDoc(`<html><body>
      <p>Press Allow to continue watching the video</p>
    </body></html>`);
    const permCalls = [{ timestamp: NOW }];
    expect(checkFakeVerificationLure(doc, permCalls)).toHaveLength(1);
  });

  it('detects "not a robot" lure', () => {
    const doc = makeDoc(`<html><body>
      <p>Prove you are not a robot</p>
    </body></html>`);
    const permCalls = [{ timestamp: NOW }];
    expect(checkFakeVerificationLure(doc, permCalls)).toHaveLength(1);
  });

  it('detects "enable notifications to watch" lure', () => {
    const doc = makeDoc(`<html><body>
      <p>Enable notifications to watch this content</p>
    </body></html>`);
    const permCalls = [{ timestamp: NOW }];
    expect(checkFakeVerificationLure(doc, permCalls)).toHaveLength(1);
  });

  it('detects "age verification" lure', () => {
    const doc = makeDoc(`<html><body>
      <p>Age verification required to proceed</p>
    </body></html>`);
    const permCalls = [{ timestamp: NOW }];
    expect(checkFakeVerificationLure(doc, permCalls)).toHaveLength(1);
  });

  it('returns empty for clean page', () => {
    const doc = makeDoc('<html><body><p>Welcome to our news site</p></body></html>');
    const permCalls = [{ timestamp: NOW }];
    expect(checkFakeVerificationLure(doc, permCalls)).toEqual([]);
  });

  it('returns empty without permission calls', () => {
    const doc = makeDoc(`<html><body><p>Click Allow to verify</p></body></html>`);
    expect(checkFakeVerificationLure(doc, [])).toEqual([]);
    expect(checkFakeVerificationLure(doc, null)).toEqual([]);
  });

  it('returns empty for null doc', () => {
    expect(checkFakeVerificationLure(null, [{ timestamp: NOW }])).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  checkNotificationUrgencyContent                                    */
/* ------------------------------------------------------------------ */

describe('checkNotificationUrgencyContent', () => {
  it('detects "verify now" urgency', () => {
    const notifs = [{ title: 'Security Alert', body: 'Verify now to protect your account' }];
    const signals = checkNotificationUrgencyContent(notifs);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('notif:notification_urgency_content');
    expect(signals[0].weight).toBe(0.25);
  });

  it('detects "account suspended" urgency', () => {
    const notifs = [{ title: 'Alert', body: 'Your account suspended due to suspicious activity' }];
    expect(checkNotificationUrgencyContent(notifs)).toHaveLength(1);
  });

  it('detects "security alert" in title', () => {
    const notifs = [{ title: 'Security Alert!', body: 'Check your account' }];
    expect(checkNotificationUrgencyContent(notifs)).toHaveLength(1);
  });

  it('detects "action required" urgency', () => {
    const notifs = [{ title: 'Important', body: 'Action required on your account' }];
    expect(checkNotificationUrgencyContent(notifs)).toHaveLength(1);
  });

  it('detects "unauthorized access" urgency', () => {
    const notifs = [{ title: 'Warning', body: 'Unauthorized access detected on your account' }];
    expect(checkNotificationUrgencyContent(notifs)).toHaveLength(1);
  });

  it('detects "MFA code" urgency', () => {
    const notifs = [{ title: 'MFA', body: 'MFA code required for login' }];
    expect(checkNotificationUrgencyContent(notifs)).toHaveLength(1);
  });

  it('returns empty for benign notification', () => {
    const notifs = [{ title: 'New message', body: 'You have a new chat message' }];
    expect(checkNotificationUrgencyContent(notifs)).toEqual([]);
  });

  it('returns empty for null/empty input', () => {
    expect(checkNotificationUrgencyContent(null)).toEqual([]);
    expect(checkNotificationUrgencyContent([])).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  checkRapidPermissionOnLoad                                         */
/* ------------------------------------------------------------------ */

describe('checkRapidPermissionOnLoad', () => {
  it('detects permission request within 3s of load', () => {
    const loadTs = NOW;
    const permCalls = [{ timestamp: NOW + 2000 }]; // 2s after load
    const signals = checkRapidPermissionOnLoad(permCalls, loadTs);
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('notif:rapid_permission_on_load');
    expect(signals[0].weight).toBe(0.20);
  });

  it('returns empty when permission is after 3s', () => {
    const loadTs = NOW;
    const permCalls = [{ timestamp: NOW + 5000 }]; // 5s after load
    expect(checkRapidPermissionOnLoad(permCalls, loadTs)).toEqual([]);
  });

  it('detects permission at exactly 3s boundary', () => {
    const loadTs = NOW;
    const permCalls = [{ timestamp: NOW + 3000 }]; // Exactly 3s
    const signals = checkRapidPermissionOnLoad(permCalls, loadTs);
    expect(signals).toHaveLength(1);
  });

  it('returns empty for null inputs', () => {
    expect(checkRapidPermissionOnLoad(null, NOW)).toEqual([]);
    expect(checkRapidPermissionOnLoad([], NOW)).toEqual([]);
    expect(checkRapidPermissionOnLoad([{ timestamp: NOW }], 0)).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  checkCrossOriginNotificationLink                                   */
/* ------------------------------------------------------------------ */

describe('checkCrossOriginNotificationLink', () => {
  it('detects cross-origin URL in notification body', () => {
    const notifs = [{
      title: 'Alert',
      body: 'Click here: https://evil.com/phish',
      data: null,
    }];
    const signals = checkCrossOriginNotificationLink(notifs, 'example.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe('notif:cross_origin_notification_link');
    expect(signals[0].weight).toBe(0.15);
    expect(signals[0].targetHostname).toBe('evil.com');
  });

  it('detects cross-origin URL in notification data', () => {
    const notifs = [{
      title: 'Alert',
      body: '',
      data: { url: 'https://phishing-site.com/login' },
    }];
    const signals = checkCrossOriginNotificationLink(notifs, 'example.com');
    expect(signals).toHaveLength(1);
    expect(signals[0].targetHostname).toBe('phishing-site.com');
  });

  it('returns empty when URL matches page hostname', () => {
    const notifs = [{
      title: 'Alert',
      body: 'Visit https://example.com/page',
      data: null,
    }];
    expect(checkCrossOriginNotificationLink(notifs, 'example.com')).toEqual([]);
  });

  it('returns empty when no URLs in notification', () => {
    const notifs = [{ title: 'Hello', body: 'No links here', data: null }];
    expect(checkCrossOriginNotificationLink(notifs, 'example.com')).toEqual([]);
  });

  it('returns empty for null inputs', () => {
    expect(checkCrossOriginNotificationLink(null, 'example.com')).toEqual([]);
    expect(checkCrossOriginNotificationLink([], '')).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  calculateNotifRiskScore                                            */
/* ------------------------------------------------------------------ */

describe('calculateNotifRiskScore', () => {
  it('sums signal weights', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
    ];
    const { riskScore, signalList } = calculateNotifRiskScore(signals);
    expect(riskScore).toBeCloseTo(0.70, 2);
    expect(signalList).toEqual(['a', 'b']);
  });

  it('caps at 1.0', () => {
    const signals = [
      { id: 'a', weight: 0.40 },
      { id: 'b', weight: 0.30 },
      { id: 'c', weight: 0.25 },
      { id: 'd', weight: 0.20 },
    ];
    const { riskScore } = calculateNotifRiskScore(signals);
    expect(riskScore).toBe(1.0);
  });

  it('returns 0 for empty signals', () => {
    expect(calculateNotifRiskScore([]).riskScore).toBe(0);
    expect(calculateNotifRiskScore(null).riskScore).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/*  runNotificationGuardAnalysis                                       */
/* ------------------------------------------------------------------ */

describe('runNotificationGuardAnalysis', () => {
  it('emits telemetry when threshold exceeded', () => {
    const sendMessage = vi.fn().mockReturnValue(Promise.resolve());
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    const doc = makeDoc(`<html><body>
      <h1>Click Allow to verify you are not a robot</h1>
    </body></html>`);

    const permCalls = [{ timestamp: NOW }];
    const gestures = []; // No gesture
    const notifs = [{ title: 'Security Alert', body: 'Verify now', data: null }];
    const loadTs = NOW - 1000; // Permission 1s after load

    runNotificationGuardAnalysis(doc, permCalls, gestures, notifs, loadTs, 'example.com');

    expect(sendMessage).toHaveBeenCalledTimes(1);
    const msg = sendMessage.mock.calls[0][0];
    expect(msg.type).toBe('NOTIFGUARD_EVENT');
    expect(msg.payload.eventType).toBe('NOTIFICATION_PHISHING_DETECTED');
    expect(msg.payload.riskScore).toBeGreaterThanOrEqual(0.50);

    vi.unstubAllGlobals();
  });

  it('does not emit when below threshold', () => {
    const sendMessage = vi.fn().mockReturnValue(Promise.resolve());
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    const doc = makeDoc('<html><body><p>Clean page</p></body></html>');

    runNotificationGuardAnalysis(doc, [], [], [], NOW, 'example.com');

    expect(sendMessage).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });

  it('does not crash on null doc', () => {
    expect(() => runNotificationGuardAnalysis(null, [], [], [], NOW, '')).not.toThrow();
  });

  it('assigns High severity at 0.70', () => {
    const sendMessage = vi.fn().mockReturnValue(Promise.resolve());
    vi.stubGlobal('chrome', { runtime: { sendMessage } });

    const doc = makeDoc(`<html><body>
      <h1>Click Allow to verify you are not a robot</h1>
    </body></html>`);

    // Without gesture (+0.40) + lure (+0.30) = 0.70 exactly
    const permCalls = [{ timestamp: NOW }];
    const gestures = [];
    const notifs = [];

    runNotificationGuardAnalysis(doc, permCalls, gestures, notifs, NOW - 10000, 'example.com');

    expect(sendMessage).toHaveBeenCalledTimes(1);
    const msg = sendMessage.mock.calls[0][0];
    expect(msg.payload.severity).toBe('High');
    expect(msg.payload.action).toBe('blocked');

    vi.unstubAllGlobals();
  });
});

/* ------------------------------------------------------------------ */
/*  injectNotifWarningBanner                                           */
/* ------------------------------------------------------------------ */

describe('injectNotifWarningBanner', () => {
  it('creates banner in DOM', () => {
    const dom = new JSDOM('<html><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'notif:permission_request_without_gesture', weight: 0.40 }];
    injectNotifWarningBanner(0.70, signals);

    const banner = dom.window.document.getElementById('phishops-notif-banner');
    expect(banner).not.toBeNull();
    expect(banner.innerHTML).toContain('notification phishing detected');

    vi.unstubAllGlobals();
  });

  it('does not create duplicate banners', () => {
    const dom = new JSDOM('<html><body></body></html>');
    vi.stubGlobal('document', dom.window.document);

    const signals = [{ id: 'test', weight: 0.5 }];
    injectNotifWarningBanner(0.70, signals);
    injectNotifWarningBanner(0.70, signals);

    const banners = dom.window.document.querySelectorAll('#phishops-notif-banner');
    expect(banners.length).toBe(1);

    vi.unstubAllGlobals();
  });
});
