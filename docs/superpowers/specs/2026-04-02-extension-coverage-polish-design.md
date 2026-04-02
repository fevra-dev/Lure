# Extension Coverage & Polish — Design Spec

**Date:** 2026-04-02
**Scope:** Browser extension only (CLI deferred)
**Approach:** Tight & Surgical — fix 3 audit bugs + extend ClickFix clipboard API coverage

## Summary

Four changes shipping as atomic commits:

1. C2 polling memory leak fix
2. AgentIntentGuard test coverage
3. Campaign correlation window bump (15min -> 2hr)
4. ClickFix Clipboard Defender extended API coverage

## 1. C2 Polling Memory Leak Fix

**File:** `extension/background/service-worker.js` (around line 377)

**Problem:** `c2RequestLog` Map accumulates stale empty entries. After timestamp pruning removes all entries older than 60 minutes, empty arrays persist in the Map indefinitely. After a C2 alert fires, the entry is reset to `[]` but never deleted.

**Note:** The audit rated this High, but the actual severity is low — the Map is naturally bounded by installed extensions (typically 5-30), and service worker hibernation resets it entirely. The real fix is just cleaning up empty entries.

**Fix:**
- After the timestamp pruning step (line 397-398), if `recent.length === 0`, call `c2RequestLog.delete(extensionId)` and return early.
- Add `MAX_TRACKED_EXTENSIONS = 100` safety cap. If the Map exceeds this, delete the entry with the oldest most-recent timestamp before adding a new one.

**Estimated change:** ~10 lines in `detectC2Polling()`.

## 2. AgentIntentGuard Test Coverage

**Files:**
- `extension/content/agentintentguard.js` — minor refactor for testability
- `extension/tests/agentintentguard.test.js` — new test file

**Problem:** `agentintentguard.js` has zero test coverage. The class auto-instantiates at module load, making it untestable without refactoring.

**Refactor (production code):**
- Export `AgentReasoningMonitor` class
- Move the auto-instantiation (`const monitor = new AgentReasoningMonitor()`) behind a runtime guard: `if (typeof window !== 'undefined' && chrome.runtime?.id)` — matches the pattern used by `clickfix_clipboard_defender.js`

**Test cases:**
| # | Test | Asserts |
|---|------|---------|
| 1 | Construction installs focusin listener | focusin on password input sets `_credentialFocused` |
| 2 | raiseSuspicion() sets state | `_suspicious` becomes true, `SUSPICION_RAISED` event emitted |
| 3 | Credential focus during suspicion | `AGENTIC_BLABBERING_GUARDRAIL_BYPASS` alert fires |
| 4 | Credential focus without suspicion | No alert |
| 5 | Credential already focused when suspicion raised | Alert fires immediately |
| 6 | Watch window expiry (30s) | `_suspicious` clears after timer (vi.advanceTimersByTime) |
| 7 | Duplicate raiseSuspicion | Second call is no-op while already watching |
| 8 | GAN page: ratio < 0.05 + password field | Auto-raises suspicion |
| 9 | GAN page: no password field | No suspicion |
| 10 | GAN page: high ratio | No suspicion |
| 11 | Telemetry format | Events include timestamp, eventType, url truncated to 200 chars |

## 3. Campaign Correlation Window Bump

**Files:**
- `extension/lib/intelligence_lifecycle.js` — line 438
- `extension/tests/intelligence_lifecycle.test.js` — line 108+

**Change:** `const WINDOW_MS = 15 * 60 * 1000` -> `const WINDOW_MS = 2 * 60 * 60 * 1000`

**Rationale:** 15 minutes is too short for multi-stage phishing attacks that span hours (e.g., device code phishing followed by inbox rule creation). 2 hours captures realistic attack timelines without over-correlating unrelated events.

**Test updates:**
- Update existing test description from "15-minute window" to "2-hour window"
- Add test: events ~90 minutes apart should correlate
- Add test: events >2 hours apart should not correlate

## 4. ClickFix Clipboard Defender — Extended API Coverage

**Files:**
- `extension/content/clickfix_clipboard_defender.js` — new interceptors
- `extension/tests/clickfix_clipboard_defender.test.js` — new describe blocks

**Current state:** Only intercepts `navigator.clipboard.writeText()`.

**New coverage:**

### 4a. `navigator.clipboard.write()` interception
- Wrap `navigator.clipboard.write()` the same way `writeText` is wrapped
- Extract `text/plain` content from `ClipboardItem` blobs
- Run through existing `checkPayloadSignals` + `checkPageContextSignals` pipeline
- Same threshold logic (alert vs block, elevated origins, user gesture)

### 4b. `document.execCommand('copy')` interception
- Wrap `document.execCommand`
- When called with `'copy'` argument, grab `window.getSelection().toString()`
- Score the selection text through the existing pipeline
- Block by returning `false` from execCommand if threshold exceeded

### 4c. `copy` event clipboard manipulation detection
- Install a capturing-phase `copy` event listener on `document` at `document_start`
- In the same capturing listener, use `setTimeout(0)` to defer inspection until after all other `copy` handlers have run. At that point, read the clipboard via `navigator.clipboard.readText()` (async) or compare against the original selection text stashed before propagation.
- If the final clipboard content differs from the user's original selection AND scores above threshold, emit telemetry and inject warning banner. Note: we cannot `preventDefault()` retroactively from a setTimeout, so this vector is detect-and-alert only (not block). The banner warns the user not to paste.

### Not building
- `clipboard.read()` interception (deferred to future deep ClickFix hardening pass)
- Proactive DOM scanning for ClickFix lure pages (deferred)

### Test additions
- New describe blocks for each interceptor
- Reuse existing payload/context signal test infrastructure
- Test that allowlisted origins bypass new interceptors
- Test that elevated threshold origins use higher thresholds

**Estimated new code:** ~80 lines production, ~120 lines test.

## Commit Plan

Four atomic commits:
1. `fix: evict stale entries from C2 polling request log`
2. `test: add AgentIntentGuard test suite (11 cases)`
3. `fix: bump campaign correlation window from 15min to 2hr`
4. `feat: extend ClickFix defender to cover clipboard.write, execCommand, and copy event manipulation`

## Out of Scope

- CLI hardening (DMARC alignment, verify=False, archive/VBA/PDF) — separate future pass
- New detectors from research backlog (AiTM, canvas rendering) — separate future pass
- Campaign correlation configurability via UI — just bumping the default
