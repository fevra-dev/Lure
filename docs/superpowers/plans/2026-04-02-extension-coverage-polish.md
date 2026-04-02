# Extension Coverage & Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 3 audit bugs (C2 memory leak, AgentIntentGuard test gap, campaign correlation window) and extend ClickFix Clipboard Defender to cover 3 additional clipboard APIs.

**Architecture:** Four atomic changes, each independently testable and committable. Tasks 1 and 3 are small surgical fixes. Task 2 adds a test suite to an untested content script. Task 4 extends an existing detector with new interception vectors. All changes are in the browser extension; CLI is out of scope.

**Tech Stack:** JavaScript (ES modules), Vitest, Chrome Extension APIs (MV3), jsdom

**Test runner:** `cd extension && npx vitest run` (all tests) or `cd extension && npx vitest run tests/<file>` (single file)

---

### Task 1: C2 Polling Memory Leak Fix

**Files:**
- Modify: `extension/background/service-worker.js:377-431`

- [ ] **Step 1: Add MAX_TRACKED_EXTENSIONS constant**

At line 377, before the `c2RequestLog` declaration, add the safety cap constant:

```javascript
const MAX_TRACKED_EXTENSIONS = 100;
const c2RequestLog = new Map(); // extensionId -> timestamps[]
```

- [ ] **Step 2: Add stale entry cleanup after timestamp pruning**

In `detectC2Polling()`, after the line `c2RequestLog.set(extensionId, recent);` (line 398), add an early return when the entry is empty:

Replace this block (lines 396-398):
```javascript
    const recent = timestamps.filter(t => t > cutoff);
    c2RequestLog.set(extensionId, recent);
```

With:
```javascript
    const recent = timestamps.filter(t => t > cutoff);
    if (recent.length === 0) {
      c2RequestLog.delete(extensionId);
      return;
    }
    c2RequestLog.set(extensionId, recent);
```

- [ ] **Step 3: Add safety cap eviction before adding new entries**

After the line `if (extensionId === chrome.runtime.id) return;` (line 385), add the cap check:

```javascript
    if (extensionId === chrome.runtime.id) return; // Skip self

    // Safety cap: evict least-recently-active extension if at limit
    if (!c2RequestLog.has(extensionId) && c2RequestLog.size >= MAX_TRACKED_EXTENSIONS) {
      let oldestKey = null;
      let oldestTime = Infinity;
      for (const [key, ts] of c2RequestLog) {
        const lastSeen = ts.length > 0 ? ts[ts.length - 1] : 0;
        if (lastSeen < oldestTime) {
          oldestTime = lastSeen;
          oldestKey = key;
        }
      }
      if (oldestKey) c2RequestLog.delete(oldestKey);
    }
```

- [ ] **Step 4: Run the full extension test suite to verify no regressions**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run`
Expected: All 1451 tests pass (no tests directly cover `detectC2Polling` since it's in the service worker, but this confirms no import/syntax breakage).

- [ ] **Step 5: Commit**

```bash
git add extension/background/service-worker.js
git commit -m "fix: evict stale entries from C2 polling request log

Clean up empty Map entries after timestamp pruning and add
MAX_TRACKED_EXTENSIONS=100 safety cap with LRU eviction."
```

---

### Task 2: AgentIntentGuard Test Coverage

**Files:**
- Modify: `extension/content/agentintentguard.js`
- Create: `extension/tests/agentintentguard.test.js`

- [ ] **Step 1: Refactor agentintentguard.js for testability**

Replace the entire file `extension/content/agentintentguard.js` with the following. Changes: (1) export the class, (2) wrap bootstrap in runtime guard matching ClickFix pattern:

```javascript
/**
 * extension/content/agentintentguard.js
 *
 * AgentIntentGuard — Content script entry point.
 * Bootstraps the AgentReasoningMonitor on every page at document_idle.
 *
 * What this does:
 *   1. Creates an AgentReasoningMonitor instance for this page/frame
 *   2. Installs the focusin listener to watch for credential field focus
 *   3. Installs the chrome.runtime.onMessage bridge to receive RAISE_SUSPICION
 *      signals from the background service worker
 *   4. Runs the text-to-HTML ratio check (GAN-optimised page heuristic)
 *      and auto-raises suspicion if the page is sparse + has credential fields
 *
 * Cross-module signal flow:
 *   PhishVision (future) -> background service worker
 *     -> chrome.tabs.sendMessage(tabId, { type: 'RAISE_SUSPICION', reason: '...' })
 *       -> this content script onMessage listener
 *         -> monitor.raiseSuspicion(reason)
 *           -> 30-second credential focus watch window
 *             -> AGENTIC_BLABBERING_GUARDRAIL_BYPASS alert
 */

'use strict';

// ---------------------------------------------------------------------------
// AgentReasoningMonitor — inline (no external module dependency)
// ---------------------------------------------------------------------------

export class AgentReasoningMonitor {
  constructor() {
    this._suspicious = false;
    this._watchTimeout = null;
    this._credentialFocused = false;
    this._init();
  }

  _init() {
    // Listen for credential field focus
    document.addEventListener('focusin', (e) => {
      const target = e.target;
      if (target?.tagName === 'INPUT' && target.type === 'password') {
        this._credentialFocused = true;
        if (this._suspicious) {
          this._fireAlert('credential_focus_during_suspicion');
        }
      }
    });

    // Cross-module message bridge
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
        chrome.runtime.onMessage.addListener((message) => {
          if (message.type === 'RAISE_SUSPICION') {
            this.raiseSuspicion(message.reason || 'external_signal');
          }
        });
      }
    } catch (_) {
      // Not in extension context
    }

    // GAN-optimised page check (Plan G4)
    this._checkGanOptimisedPage();
  }

  /**
   * Raise suspicion on this page — starts a 30-second watch window.
   * If a credential field receives focus during the window, fire alert.
   * @param {string} reason
   */
  raiseSuspicion(reason) {
    if (this._suspicious) return; // Already watching

    this._suspicious = true;
    console.debug('[AGENTINTENTGUARD] Suspicion raised: %s', reason);

    this._emitEvent({
      eventType: 'SUSPICION_RAISED',
      reason,
      url: window.location.href.substring(0, 200),
    });

    // 30-second watch window
    this._watchTimeout = setTimeout(() => {
      this._suspicious = false;
      console.debug('[AGENTINTENTGUARD] Watch window expired');
    }, 30000);

    // Check if credential is already focused
    if (this._credentialFocused) {
      this._fireAlert('credential_already_focused_when_suspicion_raised');
    }
  }

  /**
   * GAN-optimised page heuristic (Plan G4):
   *   bodyText.length / bodyHTML.length < 0.05 AND password field present
   *   -> auto-raises suspicion
   */
  _checkGanOptimisedPage() {
    try {
      const bodyHTML = document.body?.innerHTML || '';
      const bodyText = document.body?.innerText || '';

      if (bodyHTML.length === 0) return;

      const ratio = bodyText.length / bodyHTML.length;
      const hasPasswordField = document.querySelector('input[type="password"]') !== null;

      if (ratio < 0.05 && hasPasswordField) {
        console.warn(
          '[AGENTINTENTGUARD] GAN-optimised page detected: ratio=%.4f hasPassword=true',
          ratio,
        );

        this._emitEvent({
          eventType: 'PHISHVISION_SUPPLEMENTARY_SIGNAL',
          signalType: 'gan_optimised_page',
          textToHtmlRatio: ratio,
          url: window.location.href.substring(0, 200),
        });

        this.raiseSuspicion(`gan_optimised_page:ratio=${ratio.toFixed(4)}`);
      }
    } catch (_) {
      // DOM may not be fully ready
    }
  }

  _fireAlert(trigger) {
    console.warn('[AGENTINTENTGUARD] ALERT: AGENTIC_BLABBERING_GUARDRAIL_BYPASS trigger=%s', trigger);

    this._emitEvent({
      eventType: 'AGENTIC_BLABBERING_GUARDRAIL_BYPASS',
      trigger,
      url: window.location.href.substring(0, 200),
      severity: 'High',
    });
  }

  _emitEvent(event) {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'AGENTINTENTGUARD_EVENT',
          payload: {
            ...event,
            timestamp: new Date().toISOString(),
          },
        });
      }
    } catch (_) {
      // Not in extension context
    }
    console.info('[AGENTINTENTGUARD_TELEMETRY]', JSON.stringify(event));
  }
}

// ---------------------------------------------------------------------------
// Auto-run when injected as a content script
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof chrome !== 'undefined' && chrome.runtime?.id) {
  const monitor = new AgentReasoningMonitor();
  console.debug('[AGENTINTENTGUARD] content script active url=%s',
    window.location.href.substring(0, 80));
}
```

- [ ] **Step 2: Run existing test suite to verify refactor is non-breaking**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run`
Expected: All 1451 tests pass (the refactor only adds `export` and wraps bootstrap — no behavior change).

- [ ] **Step 3: Create the test file with all 11 test cases**

Create `extension/tests/agentintentguard.test.js`:

```javascript
/**
 * extension/tests/agentintentguard.test.js
 *
 * Tests for AgentIntentGuard — AgentReasoningMonitor content script.
 *
 * jsdom limitations:
 *   - chrome.runtime.onMessage not available; message bridge tested via direct method calls.
 *   - window.location.href is fixed at 'http://localhost:3000/' in jsdom.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock chrome APIs before importing the module
const mockSendMessage = vi.fn();
const mockAddListener = vi.fn();
vi.stubGlobal('chrome', {
  runtime: {
    id: 'test-extension-id',
    sendMessage: mockSendMessage,
    onMessage: {
      addListener: mockAddListener,
    },
  },
});

import { AgentReasoningMonitor } from '../content/agentintentguard.js';

describe('AgentReasoningMonitor', () => {
  let monitor;

  beforeEach(() => {
    vi.useFakeTimers();
    document.body.innerHTML = '';
    vi.clearAllMocks();
    monitor = new AgentReasoningMonitor();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ── Test 1: Construction installs focusin listener ──────────────────

  it('sets _credentialFocused when password field receives focus', () => {
    const input = document.createElement('input');
    input.type = 'password';
    document.body.appendChild(input);

    expect(monitor._credentialFocused).toBe(false);
    input.focus();
    expect(monitor._credentialFocused).toBe(true);
  });

  // ── Test 2: raiseSuspicion() sets state and emits event ─────────────

  it('raiseSuspicion sets _suspicious and emits SUSPICION_RAISED', () => {
    monitor.raiseSuspicion('test_reason');

    expect(monitor._suspicious).toBe(true);
    expect(mockSendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'AGENTINTENTGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'SUSPICION_RAISED',
          reason: 'test_reason',
        }),
      }),
    );
  });

  // ── Test 3: Credential focus during suspicion fires alert ───────────

  it('fires AGENTIC_BLABBERING_GUARDRAIL_BYPASS when password focused during suspicion', () => {
    monitor.raiseSuspicion('external_signal');
    vi.clearAllMocks();

    const input = document.createElement('input');
    input.type = 'password';
    document.body.appendChild(input);
    input.focus();

    expect(mockSendMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'AGENTINTENTGUARD_EVENT',
        payload: expect.objectContaining({
          eventType: 'AGENTIC_BLABBERING_GUARDRAIL_BYPASS',
          trigger: 'credential_focus_during_suspicion',
        }),
      }),
    );
  });

  // ── Test 4: Credential focus without suspicion — no alert ───────────

  it('does not fire alert when password focused without suspicion', () => {
    const input = document.createElement('input');
    input.type = 'password';
    document.body.appendChild(input);
    input.focus();

    const alertCalls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.eventType === 'AGENTIC_BLABBERING_GUARDRAIL_BYPASS',
    );
    expect(alertCalls).toHaveLength(0);
  });

  // ── Test 5: Credential already focused when suspicion raised ────────

  it('fires alert immediately if credential already focused when suspicion raised', () => {
    const input = document.createElement('input');
    input.type = 'password';
    document.body.appendChild(input);
    input.focus();
    vi.clearAllMocks();

    monitor.raiseSuspicion('late_signal');

    const alertCalls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.eventType === 'AGENTIC_BLABBERING_GUARDRAIL_BYPASS',
    );
    expect(alertCalls).toHaveLength(1);
    expect(alertCalls[0][0].payload.trigger).toBe('credential_already_focused_when_suspicion_raised');
  });

  // ── Test 6: Watch window expiry clears suspicious state ─────────────

  it('clears _suspicious after 30-second watch window', () => {
    monitor.raiseSuspicion('timeout_test');
    expect(monitor._suspicious).toBe(true);

    vi.advanceTimersByTime(30000);
    expect(monitor._suspicious).toBe(false);
  });

  // ── Test 7: Duplicate raiseSuspicion is no-op ───────────────────────

  it('ignores duplicate raiseSuspicion while already watching', () => {
    monitor.raiseSuspicion('first');
    vi.clearAllMocks();

    monitor.raiseSuspicion('second');

    const suspicionCalls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.eventType === 'SUSPICION_RAISED',
    );
    expect(suspicionCalls).toHaveLength(0);
  });

  // ── Test 8: GAN page — low ratio + password field → suspicion ───────

  it('auto-raises suspicion on GAN-optimised page (ratio < 0.05 + password)', () => {
    // Build a page with very low text-to-HTML ratio and a password field
    // Need innerHTML much longer than innerText
    const padding = '<div style="display:none">' + 'x'.repeat(2000) + '</div>';
    document.body.innerHTML = `${padding}<input type="password">`;

    vi.clearAllMocks();
    const ganMonitor = new AgentReasoningMonitor();

    const suspicionCalls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.eventType === 'SUSPICION_RAISED',
    );
    expect(suspicionCalls.length).toBeGreaterThanOrEqual(1);
    expect(suspicionCalls[0][0].payload.reason).toContain('gan_optimised_page');
  });

  // ── Test 9: GAN page — no password field → no suspicion ─────────────

  it('does not raise suspicion on low-ratio page without password field', () => {
    const padding = '<div style="display:none">' + 'x'.repeat(2000) + '</div>';
    document.body.innerHTML = padding;

    vi.clearAllMocks();
    const ganMonitor = new AgentReasoningMonitor();

    const suspicionCalls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.eventType === 'SUSPICION_RAISED',
    );
    expect(suspicionCalls).toHaveLength(0);
  });

  // ── Test 10: GAN page — high ratio → no suspicion ──────────────────

  it('does not raise suspicion on normal text-to-HTML ratio page', () => {
    document.body.innerHTML = '<p>This is a normal page with plenty of text content.</p><input type="password">';

    vi.clearAllMocks();
    const ganMonitor = new AgentReasoningMonitor();

    const suspicionCalls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.eventType === 'SUSPICION_RAISED',
    );
    expect(suspicionCalls).toHaveLength(0);
  });

  // ── Test 11: Telemetry format validation ────────────────────────────

  it('emits events with timestamp, eventType, and truncated url', () => {
    monitor.raiseSuspicion('format_test');

    const call = mockSendMessage.mock.calls[0][0];
    expect(call.type).toBe('AGENTINTENTGUARD_EVENT');
    expect(call.payload).toHaveProperty('timestamp');
    expect(call.payload).toHaveProperty('eventType');
    expect(call.payload).toHaveProperty('url');
    // URL should be truncated to 200 chars max
    expect(call.payload.url.length).toBeLessThanOrEqual(200);
    // Timestamp should be ISO format
    expect(new Date(call.payload.timestamp).toISOString()).toBe(call.payload.timestamp);
  });
});
```

- [ ] **Step 4: Run the new test file**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/agentintentguard.test.js`
Expected: 11 tests pass.

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run`
Expected: 1462 tests pass (1451 existing + 11 new).

- [ ] **Step 6: Commit**

```bash
git add extension/content/agentintentguard.js extension/tests/agentintentguard.test.js
git commit -m "test: add AgentIntentGuard test suite (11 cases)

Export AgentReasoningMonitor class for testability (matching ClickFix
pattern). Tests cover: suspicion lifecycle, credential focus alerts,
watch window expiry, GAN-optimised page detection, telemetry format."
```

---

### Task 3: Campaign Correlation Window Bump

**Files:**
- Modify: `extension/lib/intelligence_lifecycle.js:438`
- Modify: `extension/tests/intelligence_lifecycle.test.js:108`

- [ ] **Step 1: Update the correlation window constant**

In `extension/lib/intelligence_lifecycle.js`, replace line 438:

```javascript
  const WINDOW_MS = 15 * 60 * 1000;
```

With:

```javascript
  const WINDOW_MS = 2 * 60 * 60 * 1000; // 2 hours — multi-stage attacks span hours
```

- [ ] **Step 2: Update the existing test description**

In `extension/tests/intelligence_lifecycle.test.js`, replace line 108:

```javascript
  it('groups related OAuth events within 15-minute window', () => {
```

With:

```javascript
  it('groups related OAuth events within 2-hour window', () => {
```

- [ ] **Step 3: Add test for events 90 minutes apart (should correlate)**

After the existing `'groups related OAuth events within 2-hour window'` test block (after line 117), add:

```javascript
  it('correlates related events 90 minutes apart', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', timestamp: '2026-03-17T00:00:00Z', url: 'https://a.com', riskScore: 0.90 },
      { eventType: 'OAUTH_STATE_EMAIL_ENCODED', timestamp: '2026-03-17T01:30:00Z', url: 'https://b.com', riskScore: 0.85 },
    ];
    const { campaigns } = correlateEvents(events);
    expect(campaigns).toHaveLength(1);
    expect(campaigns[0].eventTypes).toContain('OAUTH_DEVICE_CODE_FLOW');
    expect(campaigns[0].eventTypes).toContain('OAUTH_STATE_EMAIL_ENCODED');
  });

  it('does not correlate related events more than 2 hours apart', () => {
    const events = [
      { eventType: 'OAUTH_DEVICE_CODE_FLOW', timestamp: '2026-03-17T00:00:00Z', url: 'https://a.com', riskScore: 0.90 },
      { eventType: 'OAUTH_STATE_EMAIL_ENCODED', timestamp: '2026-03-17T02:01:00Z', url: 'https://b.com', riskScore: 0.85 },
    ];
    const { campaigns, uncorrelated } = correlateEvents(events);
    expect(campaigns).toHaveLength(0);
    expect(uncorrelated).toHaveLength(2);
  });
```

- [ ] **Step 4: Run the intelligence lifecycle tests**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/intelligence_lifecycle.test.js`
Expected: All tests pass, including the 2 new ones.

- [ ] **Step 5: Run full test suite**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run`
Expected: 1464 tests pass (1462 from after Task 2 + 2 new).

- [ ] **Step 6: Commit**

```bash
git add extension/lib/intelligence_lifecycle.js extension/tests/intelligence_lifecycle.test.js
git commit -m "fix: bump campaign correlation window from 15min to 2hr

Multi-stage phishing attacks (e.g., device code phishing followed by
inbox rule creation) span hours, not minutes. 15-minute window was
missing real campaign correlations."
```

---

### Task 4: ClickFix Clipboard Defender — Extended API Coverage

**Files:**
- Modify: `extension/content/clickfix_clipboard_defender.js`
- Modify: `extension/tests/clickfix_clipboard_defender.test.js`

- [ ] **Step 1: Write failing tests for clipboard.write() interception**

Append to `extension/tests/clickfix_clipboard_defender.test.js`, after the last `describe` block:

```javascript
// =========================================================================
// Extended API coverage: clipboard.write()
// =========================================================================

describe('clipboard.write() interception', () => {
  let originalWrite;
  let originalWriteText;

  beforeEach(() => {
    originalWrite = vi.fn().mockResolvedValue(undefined);
    originalWriteText = vi.fn().mockResolvedValue(undefined);
    const clipboardObj = {
      writeText: originalWriteText,
      write: originalWrite,
    };
    Object.defineProperty(navigator, 'clipboard', {
      value: clipboardObj,
      writable: true,
      configurable: true,
    });
    document.getElementById('phishops-clickfix-warning')?.remove();
  });

  it('allows benign ClipboardItem through', async () => {
    installClipboardInterceptor();
    const blob = new Blob(['Hello world, this is perfectly normal clipboard content.'], { type: 'text/plain' });
    const item = new ClipboardItem({ 'text/plain': blob });
    await navigator.clipboard.write([item]);
    expect(originalWrite).toHaveBeenCalled();
  });

  it('blocks malicious text/plain ClipboardItem', async () => {
    installClipboardInterceptor();
    const payload = 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    const blob = new Blob([payload], { type: 'text/plain' });
    const item = new ClipboardItem({ 'text/plain': blob });
    await expect(navigator.clipboard.write([item])).rejects.toThrow('Clipboard write blocked');
    expect(mockSendMessage).toHaveBeenCalled();
    expect(mockSendMessage.mock.calls[0][0].payload.action).toBe('blocked');
  });

  it('passes through ClipboardItems without text/plain', async () => {
    installClipboardInterceptor();
    const blob = new Blob(['<b>bold</b>'], { type: 'text/html' });
    const item = new ClipboardItem({ 'text/html': blob });
    await navigator.clipboard.write([item]);
    expect(originalWrite).toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/clickfix_clipboard_defender.test.js`
Expected: The 3 new `clipboard.write()` tests fail (no interception exists yet).

- [ ] **Step 3: Implement clipboard.write() interception**

In `extension/content/clickfix_clipboard_defender.js`, inside the `installClipboardInterceptor()` function, after the `writeText` replacement block (after the try/catch at line 323), add the `clipboard.write()` interceptor:

```javascript
  // ── clipboard.write() interception ──────────────────────────────────
  const originalWrite = navigator.clipboard?.write?.bind(navigator.clipboard);
  if (originalWrite) {
    const writeDefender = async function writeInterceptor(data) {
      if (isAllowlistedOrigin()) return originalWrite(data);

      // Extract text/plain from ClipboardItems
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
```

- [ ] **Step 4: Run clipboard.write tests to verify they pass**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/clickfix_clipboard_defender.test.js`
Expected: All tests pass including the 3 new `clipboard.write()` tests.

- [ ] **Step 5: Write failing tests for execCommand('copy') interception**

Append to `extension/tests/clickfix_clipboard_defender.test.js`:

```javascript
// =========================================================================
// Extended API coverage: execCommand('copy')
// =========================================================================

describe('execCommand copy interception', () => {
  let originalExecCommand;

  beforeEach(() => {
    originalExecCommand = vi.fn().mockReturnValue(true);
    document.execCommand = originalExecCommand;
    // Set up clipboard mock
    const clipboardObj = {
      writeText: vi.fn().mockResolvedValue(undefined),
      write: vi.fn().mockResolvedValue(undefined),
    };
    Object.defineProperty(navigator, 'clipboard', {
      value: clipboardObj,
      writable: true,
      configurable: true,
    });
    document.getElementById('phishops-clickfix-warning')?.remove();
  });

  it('allows non-copy execCommand through unchanged', () => {
    installClipboardInterceptor();
    document.execCommand('bold');
    expect(originalExecCommand).toHaveBeenCalledWith('bold');
  });

  it('allows benign copy selection through', () => {
    installClipboardInterceptor();
    // Mock window.getSelection to return benign text
    const mockSelection = { toString: () => 'Just some normal text that a user selected on the page.' };
    vi.spyOn(window, 'getSelection').mockReturnValue(mockSelection);

    document.execCommand('copy');
    expect(originalExecCommand).toHaveBeenCalledWith('copy');
  });

  it('blocks copy of malicious selection', () => {
    installClipboardInterceptor();
    const malicious = 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
    const mockSelection = { toString: () => malicious };
    vi.spyOn(window, 'getSelection').mockReturnValue(mockSelection);

    const result = document.execCommand('copy');
    expect(result).toBe(false);
    expect(originalExecCommand).not.toHaveBeenCalledWith('copy');
    expect(mockSendMessage).toHaveBeenCalled();
    expect(mockSendMessage.mock.calls[0][0].payload.action).toBe('blocked');
  });
});
```

- [ ] **Step 6: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/clickfix_clipboard_defender.test.js`
Expected: The 3 new `execCommand` tests fail.

- [ ] **Step 7: Implement execCommand('copy') interception**

In `extension/content/clickfix_clipboard_defender.js`, inside `installClipboardInterceptor()`, after the `clipboard.write()` interceptor block, add:

```javascript
  // ── execCommand('copy') interception ────────────────────────────────
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
```

- [ ] **Step 8: Run execCommand tests to verify they pass**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/clickfix_clipboard_defender.test.js`
Expected: All tests pass including the 3 new `execCommand` tests.

- [ ] **Step 9: Write failing tests for copy event manipulation detection**

Append to `extension/tests/clickfix_clipboard_defender.test.js`:

```javascript
// =========================================================================
// Extended API coverage: copy event manipulation detection
// =========================================================================

describe('copy event manipulation detection', () => {
  beforeEach(() => {
    const clipboardObj = {
      writeText: vi.fn().mockResolvedValue(undefined),
      write: vi.fn().mockResolvedValue(undefined),
    };
    Object.defineProperty(navigator, 'clipboard', {
      value: clipboardObj,
      writable: true,
      configurable: true,
    });
    document.execCommand = vi.fn().mockReturnValue(true);
    document.getElementById('phishops-clickfix-warning')?.remove();
  });

  it('detects when copy event handler replaces selection with malicious content', () => {
    installClipboardInterceptor();

    // Simulate an attacker's copy event handler that replaces clipboard content.
    // This runs between our capturing listener and our bubble listener.
    document.addEventListener('copy', (e) => {
      e.clipboardData.setData('text/plain',
        'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA');
      e.preventDefault();
    });

    // Mock getSelection to return benign text (what user thought they copied)
    vi.spyOn(window, 'getSelection').mockReturnValue({ toString: () => 'benign selected text' });

    // Dispatch copy event — capturing listener stashes selection,
    // attacker handler modifies clipboardData, bubble listener detects it
    const clipboardData = new DataTransfer();
    const copyEvent = new ClipboardEvent('copy', { clipboardData, cancelable: true });
    document.dispatchEvent(copyEvent);

    expect(mockSendMessage).toHaveBeenCalled();
    const calls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.vector === 'copy_event',
    );
    expect(calls.length).toBeGreaterThanOrEqual(1);
    expect(calls[0][0].payload.action).toBe('alerted');
  });

  it('does not alert when copy event content matches selection', () => {
    installClipboardInterceptor();

    const benign = 'Just some normal text that a user selected on the page.';
    vi.spyOn(window, 'getSelection').mockReturnValue({ toString: () => benign });

    const clipboardData = new DataTransfer();
    clipboardData.setData('text/plain', benign);
    const copyEvent = new ClipboardEvent('copy', { clipboardData, cancelable: true });
    document.dispatchEvent(copyEvent);

    const calls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.vector === 'copy_event',
    );
    expect(calls).toHaveLength(0);
  });
});
```

- [ ] **Step 10: Run tests to verify they fail**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/clickfix_clipboard_defender.test.js`
Expected: The 2 new `copy event` tests fail.

- [ ] **Step 11: Implement copy event manipulation detection**

In `extension/content/clickfix_clipboard_defender.js`, inside `installClipboardInterceptor()`, after the `execCommand` interceptor block, add:

```javascript
  // ── copy event manipulation detection (detect-only, cannot block) ───
  // NOTE: clipboardData is only readable synchronously during the event.
  // We stash the original selection, then listen in bubble phase (after
  // attacker handlers) to read what was actually set on clipboardData.
  document.addEventListener('copy', (e) => {
    if (isAllowlistedOrigin()) return;

    // Stash what the user actually selected
    const originalSelection = window.getSelection?.()?.toString() || '';

    // Read clipboardData NOW (synchronously) — it's empty in capturing
    // phase before other handlers run, so we also install a bubble listener.
    // This capturing listener just stashes the selection for the bubble one.
    e.__phishops_original_selection = originalSelection;
  }, true); // Capturing phase

  document.addEventListener('copy', (e) => {
    if (isAllowlistedOrigin()) return;

    try {
      const originalSelection = e.__phishops_original_selection || '';
      const clipboardText = e.clipboardData?.getData('text/plain') || '';

      // Only alert if content was substituted AND is malicious
      if (clipboardText === originalSelection) return;
      if (clipboardText.length < MIN_PAYLOAD_LENGTH) return;

      const payloadSignals = checkPayloadSignals(clipboardText);
      if (payloadSignals.length === 0) return;

      const pageSignals = checkPageContextSignals();
      const allSignals = [...payloadSignals, ...pageSignals];
      const { riskScore, signalList } = calculateClickFixRiskScore(allSignals);

      if (riskScore >= ALERT_THRESHOLD) {
        sendToBackground({
          eventType: 'CLICKFIX_CLIPBOARD_INJECTION',
          riskScore,
          severity: riskScore >= 0.90 ? 'Critical' : riskScore >= 0.65 ? 'High' : 'Medium',
          payloadSnippet: clipboardText.substring(0, 200),
          signals: signalList,
          url: window.location.href.substring(0, 200),
          timestamp: new Date().toISOString(),
          action: 'alerted',
          vector: 'copy_event',
        });
        injectClickFixWarningBanner(riskScore, clipboardText, signalList);
      }
    } catch (_) {
      // Don't break copy on inspection failure
    }
  }, false); // Bubble phase — runs AFTER attacker handlers have modified clipboardData
```

- [ ] **Step 12: Run all clickfix tests to verify they pass**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run tests/clickfix_clipboard_defender.test.js`
Expected: All tests pass including the 8 new tests (3 clipboard.write + 3 execCommand + 2 copy event).

- [ ] **Step 13: Run full extension test suite**

Run: `cd /Users/fevra/Apps/lur3/extension && npx vitest run`
Expected: 1472 tests pass (1464 from after Task 3 + 8 new).

- [ ] **Step 14: Commit**

```bash
git add extension/content/clickfix_clipboard_defender.js extension/tests/clickfix_clipboard_defender.test.js
git commit -m "feat: extend ClickFix defender to cover clipboard.write, execCommand, and copy event manipulation

Three new interception vectors:
- clipboard.write(): extracts text/plain from ClipboardItem blobs
- execCommand('copy'): scores selected text before allowing copy
- copy event handler: detects when scripts replace clipboard content
  with malicious payloads (detect-and-alert only, cannot block)

All vectors reuse the existing signal scoring pipeline."
```
