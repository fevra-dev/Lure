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

class AgentReasoningMonitor {
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

// Bootstrap
const monitor = new AgentReasoningMonitor();

console.debug('[AGENTINTENTGUARD] content script active url=%s',
  window.location.href.substring(0, 80));
