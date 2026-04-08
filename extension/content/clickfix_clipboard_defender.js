/**
 * extension/content/clickfix_clipboard_defender.js
 *
 * ClickFixClipboardDefender — Intercepts malicious clipboard writes.
 * Injected at document_start to wrap Clipboard.prototype.writeText before
 * attacker code can cache a reference to the original.
 *
 * Attack chain this closes:
 *   Attacker presents a fake CAPTCHA or "verify you are human" page.
 *   When the user clicks, JavaScript writes a malicious PowerShell/cmd
 *   command to the clipboard. The page instructs the user to press
 *   Win+R and Ctrl+V to execute it.
 *
 * Detection model: Additive signal scoring across two categories:
 *   1. Payload analysis — dangerous patterns in the clipboard text
 *   2. Page context     — DOM signals suggesting a ClickFix lure
 *
 * References:
 *   - ESET H1 2025: ClickFix = 8% of all phishing globally
 *   - Proofpoint 2025: FIN7 / Lazarus / Storm-1865 adoption
 *   - MITRE ATT&CK T1059.001 (Command and Scripting Interpreter: PowerShell)
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALERT_THRESHOLD = 0.50;
const BLOCK_THRESHOLD = 0.65;
const MIN_PAYLOAD_LENGTH = 20;

const ALLOWLISTED_ORIGINS = [
  'github.com',
  'stackoverflow.com',
  'codepen.io',
  'docs.google.com',
  'codesandbox.io',
  'replit.com',
];

const ELEVATED_THRESHOLD_ORIGINS = [
  'learn.microsoft.com',
  'developer.mozilla.org',
  'developer.apple.com',
  'docs.aws.amazon.com',
];

// ---------------------------------------------------------------------------
// Payload signal checks (exported for unit testing)
// ---------------------------------------------------------------------------

function checkPayloadSignals(text) {
  const signals = [];
  const lower = text.toLowerCase();

  // PowerShell patterns
  if (/\b(powershell|pwsh)\b/i.test(text) ||
      /-(enc|encodedcommand)\b/i.test(text) ||
      /\b(invoke-expression|iex|invoke-webrequest|start-process)\b/i.test(text)) {
    signals.push({ id: 'clickfix:powershell_pattern', weight: 0.45 });
  }

  // cmd execution patterns
  if (/\bcmd\s*(\/c|\.exe)\b/i.test(text) ||
      /\b(mshta|wscript|cscript|regsvr32)\b/i.test(text)) {
    signals.push({ id: 'clickfix:cmd_execution', weight: 0.40 });
  }

  // Download tool patterns
  if (/\b(curl|wget)\b/i.test(text) ||
      /\bcertutil\s+-urlcache\b/i.test(text) ||
      /\bbitsadmin\b/i.test(text)) {
    signals.push({ id: 'clickfix:curl_wget_download', weight: 0.35 });
  }

  // Pipe to shell
  if (/\|\s*(bash|sh|python|python3|iex)\b/i.test(text)) {
    signals.push({ id: 'clickfix:pipe_to_shell', weight: 0.40 });
  }

  // Base64 payload (40+ chars of contiguous base64)
  if (/[A-Za-z0-9+/=]{40,}/.test(text)) {
    signals.push({ id: 'clickfix:base64_payload', weight: 0.30 });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Page context signal checks (exported for unit testing)
// ---------------------------------------------------------------------------

function checkPageContextSignals() {
  const signals = [];
  const bodyText = (document.body?.innerText || document.body?.textContent || '').toLowerCase();

  // Run dialog instruction
  if (/win\s*\+\s*r/i.test(bodyText) ||
      /run\s+dialog/i.test(bodyText) ||
      /ctrl\s*\+\s*v/i.test(bodyText)) {
    signals.push({ id: 'clickfix:run_dialog_instruction', weight: 0.20 });
  }

  // Fake CAPTCHA context — but NOT real reCAPTCHA
  const hasRealRecaptcha = document.querySelector('iframe[src*="recaptcha"], .g-recaptcha');
  if (!hasRealRecaptcha) {
    if (/i[''\u2019]?m not a robot/i.test(bodyText) ||
        /verify you are human/i.test(bodyText) ||
        /prove you('re|\s+are)\s+(not\s+a\s+)?(human|robot|bot)/i.test(bodyText) ||
        /human verification/i.test(bodyText)) {
      signals.push({ id: 'clickfix:fake_captcha_context', weight: 0.15 });
    }
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Risk score calculation (exported for unit testing)
// ---------------------------------------------------------------------------

function calculateClickFixRiskScore(signals) {
  let score = 0.0;
  const signalList = [];

  for (const signal of signals) {
    score += signal.weight;
    signalList.push(signal.id);
  }

  return {
    riskScore: Math.round(Math.min(score, 1.0) * 100) / 100,
    signalList,
  };
}

// ---------------------------------------------------------------------------
// Warning banner (exported for unit testing)
// ---------------------------------------------------------------------------

function injectClickFixWarningBanner(riskScore, payload, signals) {
  if (document.getElementById('phishops-clickfix-warning')) return;

  const snippet = (payload || '').substring(0, 120);

  const banner = document.createElement('div');
  banner.id = 'phishops-clickfix-warning';
  banner.setAttribute('role', 'alert');
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
    background: #0A0907; border-bottom: 2px solid #BF1B1B;
    padding: 14px 20px; font-family: 'Work Sans', system-ui, -apple-system, sans-serif;
    display: flex; align-items: center; gap: 14px;
  `;

  banner.innerHTML = `
    <span style="font-size: 24px; flex-shrink:0;">\uD83D\uDEE1\uFE0F</span>
    <div style="flex:1;">
      <strong style="color:#BF1B1B; font-size:15px; display:block; margin-bottom:3px; font-family:'Work Sans',system-ui,sans-serif;">
        clickfix clipboard attack blocked \u2014 phishops clipboarddefender
      </strong>
      <span style="color:#D4CCBC; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;">
        A script attempted to write a malicious command to your clipboard.
        Risk score: ${riskScore.toFixed(2)}.
      </span>
      <div style="margin-top:6px; padding:6px 10px; background:#141210; border:1px solid #2A2520; font-family:monospace; font-size:11px; color:#BF1B1B; word-break:break-all;">
        ${snippet}${payload && payload.length > 120 ? '\u2026' : ''}
      </div>
    </div>
    <button id="phishops-clickfix-dismiss" style="
      flex-shrink:0; padding:8px 16px; background:transparent;
      border:1px solid #2A2520; color:#6B6560;
      cursor:pointer; font-size:13px; font-family:'Work Sans',system-ui,sans-serif;
    ">Dismiss</button>
  `;

  document.documentElement.insertBefore(banner, document.documentElement.firstChild);

  document.getElementById('phishops-clickfix-dismiss')?.addEventListener('click', () => {
    banner.remove();
  });
}

// ---------------------------------------------------------------------------
// Telemetry emitter
// ---------------------------------------------------------------------------

function sendToBackground(payload) {
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'CLICKFIX_CLIPBOARD_EVENT',
        payload,
      });
    }
  } catch (err) {
    console.error('[CLICKFIX_DEFENDER] sendToBackground failed:', err);
  }
}

// ---------------------------------------------------------------------------
// Origin checks
// ---------------------------------------------------------------------------

function isAllowlistedOrigin() {
  try {
    const hostname = window.location.hostname;
    return ALLOWLISTED_ORIGINS.some(origin => hostname === origin || hostname.endsWith('.' + origin));
  } catch {
    return false;
  }
}

function isElevatedThresholdOrigin() {
  try {
    const hostname = window.location.hostname;
    return ELEVATED_THRESHOLD_ORIGINS.some(origin => hostname === origin || hostname.endsWith('.' + origin));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// User gesture tracking
// ---------------------------------------------------------------------------

let lastUserGestureTimestamp = 0;

function trackUserGesture() {
  lastUserGestureTimestamp = Date.now();
}

// ---------------------------------------------------------------------------
// Clipboard interceptor (exported for unit testing)
// ---------------------------------------------------------------------------

function installClipboardInterceptor() {
  // Track user gestures
  document.addEventListener('click', trackUserGesture, true);
  document.addEventListener('keydown', trackUserGesture, true);

  const originalWriteText = navigator.clipboard?.writeText?.bind(navigator.clipboard);
  if (!originalWriteText) return;

  const defender = async function writeTextInterceptor(text) {
    // Skip short payloads
    if (!text || text.length < MIN_PAYLOAD_LENGTH) {
      return originalWriteText(text);
    }

    // Skip allowlisted origins
    if (isAllowlistedOrigin()) {
      return originalWriteText(text);
    }

    // Check payload signals
    const payloadSignals = checkPayloadSignals(text);
    const pageSignals = payloadSignals.length > 0 ? checkPageContextSignals() : [];
    const allSignals = [...payloadSignals, ...pageSignals];

    const { riskScore, signalList } = calculateClickFixRiskScore(allSignals);

    // User gesture within 500ms reduces confidence — but only for borderline cases
    const timeSinceGesture = Date.now() - lastUserGestureTimestamp;
    const userInitiated = timeSinceGesture < 500;

    // Determine effective threshold
    let effectiveBlockThreshold = BLOCK_THRESHOLD;
    if (isElevatedThresholdOrigin()) {
      effectiveBlockThreshold = 0.80;
    }

    if (riskScore >= effectiveBlockThreshold && !userInitiated) {
      // Block the write
      const telemetry = {
        eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
        riskScore,
        severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.65 ? 'High' : 'Medium',
        payloadSnippet: text.substring(0, 200),
        signals: signalList,
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'blocked',
      };

      sendToBackground(telemetry);
      injectClickFixWarningBanner(riskScore, text, signalList);

      return Promise.reject(new DOMException('Clipboard write blocked by PhishOps', 'NotAllowedError'));
    }

    if (riskScore >= ALERT_THRESHOLD) {
      const telemetry = {
        eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
        riskScore,
        severity: 'Medium',
        payloadSnippet: text.substring(0, 200),
        signals: signalList,
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'alerted',
      };

      sendToBackground(telemetry);
      injectClickFixWarningBanner(riskScore, text, signalList);
    }

    return originalWriteText(text);
  };

  // Replace clipboard.writeText
  try {
    Object.defineProperty(navigator.clipboard, 'writeText', {
      value: defender,
      writable: false,
      configurable: true,
    });
  } catch {
    // Fallback: direct assignment
    navigator.clipboard.writeText = defender;
  }

  // ── clipboard.write() interception ──────────────────────────────────
  const originalWrite = navigator.clipboard?.write?.bind(navigator.clipboard);
  if (originalWrite) {
    const writeDefender = async function writeInterceptor(data) {
      if (isAllowlistedOrigin()) return originalWrite(data);

      try {
        for (const item of data) {
          if (item.types.includes('text/plain')) {
            const blob = await item.getType('text/plain');
            const text = await blob.text();

            if (!text || text.length < MIN_PAYLOAD_LENGTH) continue;

            const payloadSignals = checkPayloadSignals(text);
            const pageSignals = payloadSignals.length > 0 ? checkPageContextSignals() : [];
            const allSignals = [...payloadSignals, ...pageSignals];
            const { riskScore, signalList } = calculateClickFixRiskScore(allSignals);

            const timeSinceGesture = Date.now() - lastUserGestureTimestamp;
            const userInitiated = timeSinceGesture < 500;
            let effectiveBlockThreshold = BLOCK_THRESHOLD;
            if (isElevatedThresholdOrigin()) effectiveBlockThreshold = 0.80;

            if (riskScore >= effectiveBlockThreshold && !userInitiated) {
              sendToBackground({
                eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
                riskScore,
                severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.65 ? 'High' : 'Medium',
                payloadSnippet: text.substring(0, 200),
                signals: signalList,
                url: window.location.href.substring(0, 200),
                timestamp: new Date().toISOString(),
                action: 'blocked',
                vector: 'clipboard.write',
              });
              injectClickFixWarningBanner(riskScore, text, signalList);
              return Promise.reject(new DOMException('Clipboard write blocked by PhishOps', 'NotAllowedError'));
            }

            if (riskScore >= ALERT_THRESHOLD) {
              sendToBackground({
                eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
                riskScore,
                severity: 'Medium',
                payloadSnippet: text.substring(0, 200),
                signals: signalList,
                url: window.location.href.substring(0, 200),
                timestamp: new Date().toISOString(),
                action: 'alerted',
                vector: 'clipboard.write',
              });
              injectClickFixWarningBanner(riskScore, text, signalList);
            }
          }
        }
      } catch (_) {
        // Don't break clipboard on inspection failure
      }
      return originalWrite(data);
    };

    try {
      Object.defineProperty(navigator.clipboard, 'write', {
        value: writeDefender,
        writable: false,
        configurable: true,
      });
    } catch {
      navigator.clipboard.write = writeDefender;
    }
  }

  // ── execCommand('copy') interception ────────────────────────────────
  if (typeof document.execCommand !== 'function') return;
  const originalExecCommand = document.execCommand.bind(document);
  document.execCommand = function execCommandInterceptor(command, ...args) {
    if (command !== 'copy' || isAllowlistedOrigin()) {
      return originalExecCommand(command, ...args);
    }

    const selection = window.getSelection?.()?.toString() || '';
    if (selection.length < MIN_PAYLOAD_LENGTH) {
      return originalExecCommand(command, ...args);
    }

    const payloadSignals = checkPayloadSignals(selection);
    if (payloadSignals.length === 0) {
      return originalExecCommand(command, ...args);
    }

    const pageSignals = checkPageContextSignals();
    const allSignals = [...payloadSignals, ...pageSignals];
    const { riskScore, signalList } = calculateClickFixRiskScore(allSignals);

    const timeSinceGesture = Date.now() - lastUserGestureTimestamp;
    const userInitiated = timeSinceGesture < 500;
    let effectiveBlockThreshold = BLOCK_THRESHOLD;
    if (isElevatedThresholdOrigin()) effectiveBlockThreshold = 0.80;

    if (riskScore >= effectiveBlockThreshold && !userInitiated) {
      sendToBackground({
        eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
        riskScore,
        severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.65 ? 'High' : 'Medium',
        payloadSnippet: selection.substring(0, 200),
        signals: signalList,
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'blocked',
        vector: 'execCommand',
      });
      injectClickFixWarningBanner(riskScore, selection, signalList);
      return false;
    }

    if (riskScore >= ALERT_THRESHOLD) {
      sendToBackground({
        eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
        riskScore,
        severity: 'Medium',
        payloadSnippet: selection.substring(0, 200),
        signals: signalList,
        url: window.location.href.substring(0, 200),
        timestamp: new Date().toISOString(),
        action: 'alerted',
        vector: 'execCommand',
      });
      injectClickFixWarningBanner(riskScore, selection, signalList);
    }

    return originalExecCommand(command, ...args);
  };

  // ── copy event manipulation detection (detect-only, cannot block) ───
  // Wrap clipboardData.setData at capturing phase. When an attacker's copy
  // handler calls setData('text/plain', ...) to substitute the clipboard
  // content, our wrapper sees the new value synchronously and can alert
  // if it differs from the user's actual selection and looks malicious.
  // We can't preventDefault() retroactively, so this vector is detect-only.
  document.addEventListener('copy', (e) => {
    if (isAllowlistedOrigin()) return;

    const originalSelection = window.getSelection?.()?.toString() || '';
    const origSetData = e.clipboardData?.setData?.bind(e.clipboardData);
    if (!origSetData) return;

    e.clipboardData.setData = function setDataInterceptor(type, value) {
      const result = origSetData(type, value);
      if (type !== 'text/plain' && type !== 'text') return result;

      try {
        const text = String(value ?? '');
        if (text === originalSelection) return result;
        if (text.length < MIN_PAYLOAD_LENGTH) return result;

        const payloadSignals = checkPayloadSignals(text);
        if (payloadSignals.length === 0) return result;

        const pageSignals = checkPageContextSignals();
        const allSignals = [...payloadSignals, ...pageSignals];
        const { riskScore, signalList } = calculateClickFixRiskScore(allSignals);

        if (riskScore >= ALERT_THRESHOLD) {
          sendToBackground({
            eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
            riskScore,
            severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.65 ? 'High' : 'Medium',
            payloadSnippet: text.substring(0, 200),
            signals: signalList,
            url: window.location.href.substring(0, 200),
            timestamp: new Date().toISOString(),
            action: 'alerted',
            vector: 'copy_event',
          });
          injectClickFixWarningBanner(riskScore, text, signalList);
        }
      } catch (_) {
        // Don't break copy on inspection failure
      }
      return result;
    };
  }, true); // Capturing phase — runs before attacker's copy handler
}

// ---------------------------------------------------------------------------
// Auto-run when injected as a content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  installClipboardInterceptor();
}

/* ------------------------------------------------------------------ */
/*  Test export bridge                                                 */
/* ------------------------------------------------------------------ */
// Chrome MV3 content scripts are classic scripts — top-level `export`
// throws SyntaxError. Register public API on a global namespace so
// vitest can side-effect-import and read from the global.

if (typeof globalThis !== 'undefined') {
  globalThis.__phishopsExports = globalThis.__phishopsExports || {};
  globalThis.__phishopsExports['clickfix_clipboard_defender'] = {
    checkPayloadSignals,
    checkPageContextSignals,
    calculateClickFixRiskScore,
    injectClickFixWarningBanner,
    installClipboardInterceptor,
  };
}
