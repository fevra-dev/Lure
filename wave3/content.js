/**
 * packages/extension/agentintentguard/content.js
 *
 * AgentIntentGuard — Content script entry point.
 * Bootstraps the AgentReasoningMonitor on every page at document_idle.
 *
 * What this does:
 *   1. Creates an AgentReasoningMonitor instance for this page/frame
 *   2. Installs the focusin listener to watch for credential field focus
 *   3. Installs the chrome.runtime.onMessage bridge to receive RAISE_SUSPICION
 *      signals from the background service worker (PhishVision cross-module events)
 *   4. Runs the text-to-HTML ratio check (GAN-optimised page heuristic)
 *      and auto-raises suspicion if the page is sparse + has credential fields
 *
 * Injection timing:
 *   document_idle — DOM is fully built, all scripts have run.
 *   This is correct: we need the DOM settled to run the ratio check and
 *   to attach focusin listeners that survive page script execution.
 *
 * Cross-module signal flow:
 *   PhishVision (future module) → background service worker
 *     → chrome.tabs.sendMessage(tabId, { type: 'RAISE_SUSPICION', reason: '...' })
 *       → this content script onMessage listener
 *         → monitor.raiseSuspicion(reason)
 *           → 30-second credential focus watch window
 *             → AGENTIC_BLABBERING_GUARDRAIL_BYPASS alert if triggered
 *
 * The GAN-optimised page check (Plan G4) fires immediately at injection:
 *   bodyText.length / bodyHTML.length < 0.05 AND password field present
 *   → auto-raises suspicion with reason 'gan_optimised_page:ratio={n}'
 *   → also emits PHISHVISION_SUPPLEMENTARY_SIGNAL for Sentinel correlation
 */

'use strict';

import { bootstrapAgentIntentGuard } from './reasoning_monitor.js';

// Bootstrap on this page — returns the monitor instance for this frame
const monitor = bootstrapAgentIntentGuard();

console.debug('[AGENTINTENTGUARD] content script active url=%s',
  window.location.href.substring(0, 80));
