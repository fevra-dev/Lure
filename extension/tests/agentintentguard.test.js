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
    monitor.destroy();
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
    ganMonitor.destroy();
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
    ganMonitor.destroy();
  });

  // ── Test 10: GAN page — high ratio → no suspicion ──────────────────

  it('does not raise suspicion on normal text-to-HTML ratio page', () => {
    // jsdom does not implement innerText (returns undefined), so we must
    // mock it to simulate a page with a normal text-to-HTML ratio.
    const longText = 'This is a normal page with plenty of visible text content. '.repeat(10);
    document.body.innerHTML = `<p>${longText}</p><input type="password">`;

    // Mock innerText to return the visible text so ratio > 0.05
    Object.defineProperty(document.body, 'innerText', {
      get: () => longText,
      configurable: true,
    });

    vi.clearAllMocks();
    const ganMonitor = new AgentReasoningMonitor();

    const suspicionCalls = mockSendMessage.mock.calls.filter(
      c => c[0]?.payload?.eventType === 'SUSPICION_RAISED',
    );
    expect(suspicionCalls).toHaveLength(0);
    ganMonitor.destroy();

    // Restore innerText
    delete document.body.innerText;
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
