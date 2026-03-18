/**
 * extension/content/notification_guard.js
 *
 * NotificationGuard — Browser Push Notification Phishing
 *
 * Detects sites that trick users into granting notification permission via
 * fake CAPTCHA/verification lures ("Click Allow to verify you are human"),
 * then push fake security alerts, MFA prompts, or credential harvesting
 * links. Once granted, notifications persist across sessions and reach users
 * even when the tab is closed. Google blocks billions of abusive notification
 * requests per year.
 *
 * Injected at document_start to wrap Notification.requestPermission() and
 * Notification constructor before page scripts can cache references.
 *
 * Signal architecture:
 *   notif:permission_request_without_gesture      +0.40
 *   notif:fake_verification_lure                  +0.30
 *   notif:notification_urgency_content            +0.25
 *   notif:rapid_permission_on_load                +0.20
 *   notif:cross_origin_notification_link          +0.15
 *
 * Alert threshold: 0.50 | Block threshold: 0.70
 *
 * @module NotificationGuard
 */

'use strict';

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.70;

const FAKE_VERIFICATION_PATTERNS = [
  /click\s*['"]?\s*allow['"]?\s*(to|and)\s*(verify|confirm|continue|access|prove|download)/i,
  /press\s*['"]?\s*allow['"]?\s*(to|and)/i,
  /not\s+a\s+robot/i,
  /age\s+verif/i,
  /enable\s+notifications?\s+to\s+(watch|download|play|continue)/i,
];

const URGENCY_PATTERNS = [
  /verify\s+(now|your|immediately)/i,
  /account\s+(suspended|locked|compromised)/i,
  /security\s+alert/i,
  /action\s+required/i,
  /unauthorized\s+(access|login|activity)/i,
  /MFA\s+(code|required|verify)/i,
];

const GESTURE_WINDOW_MS = 1000;
const RAPID_PERMISSION_THRESHOLD_MS = 3000;
const URL_PATTERN = /https?:\/\/[^\s"'<>]+/gi;

/* ------------------------------------------------------------------ */
/*  State tracking                                                     */
/* ------------------------------------------------------------------ */

const permissionCalls = [];     // { timestamp }
const gestureLog = [];          // { timestamp } — ring buffer, max 50
const notifications = [];       // { title, body, data, origin }
let pageLoadTimestamp = 0;

/* ------------------------------------------------------------------ */
/*  Signal Functions                                                    */
/* ------------------------------------------------------------------ */

/**
 * Check if Notification.requestPermission() was called without a recent user gesture.
 */
export function checkPermissionRequestWithoutGesture(permCalls, gestures) {
  if (!permCalls || permCalls.length === 0) return [];

  for (const call of permCalls) {
    const callTs = call.timestamp;
    const recentGesture = (gestures || []).some(g =>
      Math.abs(callTs - g.timestamp) <= GESTURE_WINDOW_MS
    );

    if (!recentGesture) {
      return [{
        id: 'notif:permission_request_without_gesture',
        weight: 0.40,
      }];
    }
  }

  return [];
}

/**
 * Check if page contains fake CAPTCHA/verification lure text.
 */
export function checkFakeVerificationLure(doc, permCalls) {
  if (!doc || !permCalls || permCalls.length === 0) return [];

  const bodyText = doc.body?.innerText || doc.body?.textContent || '';
  if (!bodyText) return [];

  const hasLure = FAKE_VERIFICATION_PATTERNS.some(p => p.test(bodyText));

  if (hasLure) {
    return [{
      id: 'notif:fake_verification_lure',
      weight: 0.30,
    }];
  }

  return [];
}

/**
 * Check if notification body/title contains urgency patterns.
 */
export function checkNotificationUrgencyContent(notifs) {
  if (!notifs || notifs.length === 0) return [];

  for (const notif of notifs) {
    const text = (notif.title || '') + ' ' + (notif.body || '');
    const hasUrgency = URGENCY_PATTERNS.some(p => p.test(text));

    if (hasUrgency) {
      return [{
        id: 'notif:notification_urgency_content',
        weight: 0.25,
      }];
    }
  }

  return [];
}

/**
 * Check if permission was requested within 3s of page load.
 */
export function checkRapidPermissionOnLoad(permCalls, loadTimestamp) {
  if (!permCalls || permCalls.length === 0 || !loadTimestamp) return [];

  for (const call of permCalls) {
    if (call.timestamp - loadTimestamp <= RAPID_PERMISSION_THRESHOLD_MS) {
      return [{
        id: 'notif:rapid_permission_on_load',
        weight: 0.20,
      }];
    }
  }

  return [];
}

/**
 * Check if notification data or body contains URL to a different origin.
 */
export function checkCrossOriginNotificationLink(notifs, pageHostname) {
  if (!notifs || notifs.length === 0 || !pageHostname) return [];

  for (const notif of notifs) {
    const text = (notif.body || '') + ' ' + JSON.stringify(notif.data || '');
    const urls = text.match(URL_PATTERN) || [];

    for (const url of urls) {
      try {
        const urlHostname = new URL(url).hostname;
        if (urlHostname && urlHostname !== pageHostname) {
          return [{
            id: 'notif:cross_origin_notification_link',
            weight: 0.15,
            targetHostname: urlHostname,
          }];
        }
      } catch { /* invalid URL */ }
    }
  }

  return [];
}

/* ------------------------------------------------------------------ */
/*  Risk Scoring                                                       */
/* ------------------------------------------------------------------ */

export function calculateNotifRiskScore(signals) {
  if (!signals || signals.length === 0) return { riskScore: 0, signalList: [] };

  const riskScore = Math.min(signals.reduce((sum, s) => sum + s.weight, 0), 1.0);
  const signalList = signals.map(s => s.id);

  return { riskScore, signalList };
}

/* ------------------------------------------------------------------ */
/*  Warning Banner                                                     */
/* ------------------------------------------------------------------ */

export function injectNotifWarningBanner(riskScore, signals) {
  if (typeof document === 'undefined') return;
  if (document.getElementById('phishops-notif-banner')) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= 0.70 ? 'High' : 'Medium';

  const banner = document.createElement('div');
  banner.id = 'phishops-notif-banner';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = [
    'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:2147483647',
    'background:#0A0907', 'border-bottom:2px solid #BF1B1B',
    'padding:14px 20px',
    "font-family:'Work Sans',system-ui,-apple-system,sans-serif",
    'display:flex', 'align-items:center', 'gap:14px',
  ].join(';');

  banner.innerHTML = `
    <span style="font-size:24px;flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B;font-size:15px;display:block;margin-bottom:3px;font-family:'Work Sans',system-ui,sans-serif;">
        notification phishing detected \u2014 phishops notificationguard
      </strong>
      <span style="color:#D4CCBC;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;">
        Severity: ${severity} | Risk: ${riskScore.toFixed(2)} |
        Signals: ${signals.map(s => s.id.replace('notif:', '')).join(', ')}
      </span>
    </div>
    <button id="phishops-notif-dismiss" style="
      flex-shrink:0;padding:8px 16px;background:transparent;
      border:1px solid #2A2520;color:#6B6560;
      cursor:pointer;font-size:13px;font-family:'Work Sans',system-ui,sans-serif;
    ">dismiss</button>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById('phishops-notif-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Analysis Runner                                                    */
/* ------------------------------------------------------------------ */

/**
 * Run full NotificationGuard analysis.
 */
export function runNotificationGuardAnalysis(doc, permCalls, gestures, notifs, loadTimestamp, pageHostname) {
  if (!doc) return;

  const gestureSignals = checkPermissionRequestWithoutGesture(permCalls, gestures);
  const lureSignals = checkFakeVerificationLure(doc, permCalls);
  const urgencySignals = checkNotificationUrgencyContent(notifs);
  const rapidSignals = checkRapidPermissionOnLoad(permCalls, loadTimestamp);
  const crossOriginSignals = checkCrossOriginNotificationLink(notifs, pageHostname);

  const allSignals = [
    ...gestureSignals,
    ...lureSignals,
    ...urgencySignals,
    ...rapidSignals,
    ...crossOriginSignals,
  ];

  if (allSignals.length === 0) return;

  const { riskScore, signalList } = calculateNotifRiskScore(allSignals);

  if (riskScore < ALERT_THRESHOLD) return;

  const severity = riskScore >= 0.90 ? 'Critical' : riskScore >= BLOCK_THRESHOLD ? 'High' : 'Medium';
  const action = riskScore >= BLOCK_THRESHOLD ? 'blocked' : 'alerted';

  injectNotifWarningBanner(riskScore, allSignals);

  if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'NOTIFGUARD_EVENT',
      payload: {
        eventType: 'NOTIFICATION_PHISHING_DETECTED',
        riskScore,
        severity,
        signals: signalList,
        url: (typeof globalThis !== 'undefined' && globalThis.location?.href) || '',
        timestamp: new Date().toISOString(),
        action,
      },
    }).catch(() => {});
  }
}

/* ------------------------------------------------------------------ */
/*  Notification Proxy Installer                                       */
/* ------------------------------------------------------------------ */

/**
 * Install Notification proxy at document_start.
 */
export function installNotificationProxy() {
  if (typeof window === 'undefined') return;

  pageLoadTimestamp = Date.now();

  // --- Gesture tracking ---
  if (typeof document !== 'undefined') {
    const recordGesture = () => {
      gestureLog.push({ timestamp: Date.now() });
      if (gestureLog.length > 50) gestureLog.shift();
    };

    document.addEventListener('click', recordGesture, { capture: true, passive: true });
    document.addEventListener('keydown', recordGesture, { capture: true, passive: true });
  }

  // --- Wrap Notification.requestPermission ---
  if (typeof Notification !== 'undefined' && Notification.requestPermission) {
    const originalRequestPermission = Notification.requestPermission.bind(Notification);

    Notification.requestPermission = function(callback) {
      permissionCalls.push({ timestamp: Date.now() });

      // Run analysis on permission request
      if (typeof document !== 'undefined' && document.readyState !== 'loading') {
        setTimeout(() => {
          runNotificationGuardAnalysis(
            document, permissionCalls, gestureLog, notifications,
            pageLoadTimestamp, globalThis.location?.hostname || '',
          );
        }, 100);
      }

      return originalRequestPermission(callback);
    };
  }

  // --- Wrap Notification constructor ---
  if (typeof Notification !== 'undefined') {
    const OriginalNotification = Notification;

    const ProxyNotification = function(title, options) {
      const notifRecord = {
        title: String(title || ''),
        body: String(options?.body || ''),
        data: options?.data || null,
        origin: globalThis.location?.hostname || '',
      };
      notifications.push(notifRecord);

      return new OriginalNotification(title, options);
    };

    // Preserve prototype and static properties
    ProxyNotification.prototype = OriginalNotification.prototype;
    ProxyNotification.permission = OriginalNotification.permission;
    ProxyNotification.requestPermission = Notification.requestPermission; // Use already-wrapped version

    try {
      Object.defineProperty(window, 'Notification', {
        value: ProxyNotification,
        writable: false,
        configurable: true,
      });
    } catch {
      window.Notification = ProxyNotification;
    }
  }

  // --- PushManager coordination with sw_guard.js ---
  if (typeof PushManager !== 'undefined' && PushManager.prototype?.subscribe) {
    // Check sentinel from sw_guard.js to avoid double-wrap
    if (!PushManager.prototype.subscribe.__phishops_wrapped) {
      const originalPushSubscribe = PushManager.prototype.subscribe;
      PushManager.prototype.subscribe = function(...args) {
        permissionCalls.push({ timestamp: Date.now() });
        return originalPushSubscribe.apply(this, args);
      };
      PushManager.prototype.subscribe.__phishops_wrapped = true;
    }
  }

  // --- Run analysis on DOMContentLoaded ---
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
      runNotificationGuardAnalysis(
        document, permissionCalls, gestureLog, notifications,
        pageLoadTimestamp, globalThis.location?.hostname || '',
      );

      // Also check at 5s for deferred notifications
      setTimeout(() => {
        runNotificationGuardAnalysis(
          document, permissionCalls, gestureLog, notifications,
          pageLoadTimestamp, globalThis.location?.hostname || '',
        );
      }, 5000);
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Exported state accessors (for testing)                             */
/* ------------------------------------------------------------------ */

export function _getPermissionCalls() {
  return permissionCalls;
}

export function _getGestureLog() {
  return gestureLog;
}

export function _getNotifications() {
  return notifications;
}

export function _getPageLoadTimestamp() {
  return pageLoadTimestamp;
}

export function _resetState() {
  permissionCalls.length = 0;
  gestureLog.length = 0;
  notifications.length = 0;
  pageLoadTimestamp = 0;
}

/* ------------------------------------------------------------------ */
/*  Auto-bootstrap                                                     */
/* ------------------------------------------------------------------ */

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installNotificationProxy();
}
