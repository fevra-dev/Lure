# PhishOps — 2026 Update Implementation Plan
**Scope: March 2026 threat research findings · 6 modules · 3 implementation waves**

---

## Wave 1 — Atomic Rule Additions (1–2 days each, no structural changes)

These are single-function additions to existing modules. No new files, no architecture changes.

---

### Plan A: ProxyGuard — Two New URL/Body Rules

**Goal:** Add HTML smuggling loader detection and Starkiller `@`-symbol URL masking detection.

- [ ] **A1** Open `proxyguard/detectors/` — confirm existing structure for adding a new detector module → Verify: `ls proxyguard/detectors/` shows existing `gophish_fingerprint.py` and peers
- [ ] **A2** Create `proxyguard/detectors/html_smuggling.py` — port `HTML_SMUGGLING_PATTERNS` regex list and response body scanner from the research doc → Verify: `python -m pytest tests/test_html_smuggling.py` passes against a mock `atob()+createObjectURL` response body
- [ ] **A3** Create `proxyguard/detectors/url_masking.py` — port `AT_SYMBOL_MASKING` regex + `detect_userinfo_masking()` from research doc → Verify: `detect_userinfo_masking("https://microsoft.com@attacker.com/login")` returns `risk_score=0.90`
- [ ] **A4** Register both detectors in `proxy_guard.py` request hook — add calls alongside existing `gophish_fingerprint` and ConsentFix calls → Verify: mitmproxy integration test with smuggling loader URL emits `HTML_SMUGGLING_LOADER` event to stdout
- [ ] **A5** Add two new `EventType` values to `ProxyPhishingEvents_CL` schema doc (`HTML_SMUGGLING_LOADER`, `URL_USERINFO_MASKING`) → Verify: Sentinel custom table validator accepts the new field definitions

**Done When:** Both rules fire correctly in mitmproxy test harness; two new event types appear in Sentinel schema doc.

---

### Plan B: OAuthGuard — State Parameter Email Encoding

**Goal:** Detect OAuth `state` parameters that contain encoded email addresses (Microsoft, March 2, 2026).

- [ ] **B1** Open `oauthguard/detectors/` — locate existing `device_code_detector.js` or equivalent as the structural reference → Verify: file opens, confirm pattern used for registering a new `webRequest.onBeforeRequest` filter
- [ ] **B2** Create `oauthguard/detectors/state_parameter_abuse.js` — port `detectStateParameterAbuse()` + `tryDecode()` functions from research doc → Verify: unit test — `detectStateParameterAbuse("https://login.microsoftonline.com/common/oauth2/authorize?state=dmljdGltQGNvcnAuY29t")` returns `{ type: 'OAUTH_STATE_EMAIL_ENCODED', decodedEmail: 'victim@corp.com' }`
- [ ] **B3** Register the detector in `oauthguard/background.js` `webRequest.onBeforeRequest` listener — filter on OAuth authorization endpoint URLs → Verify: Playwright/Puppeteer test navigating to a crafted OAuth URL with base64 email in `state=` triggers the alert
- [ ] **B4** Add the companion KQL query (state abuse + SigninLogs join) from research doc to `sentinel/queries/oauthguard/` → Verify: KQL syntax validates in Sentinel query editor; `join` field names match `SigninLogs` schema
- [ ] **B5** Add `OAUTH_STATE_EMAIL_ENCODED` to the `BrowserPhishingTelemetry_CL` schema doc → Verify: schema doc updated, no field name collisions

**Done When:** Unit test passes; Playwright integration test emits `OAUTH_STATE_EMAIL_ENCODED` event; KQL validates in Sentinel.

---

## Wave 2 — New Content Script + Sentinel Query (2–3 days each)

These require new content script injection targets or new Sentinel workbook entries. Slightly more involved but still self-contained.

---

### Plan C: DataEgressMonitor — Blob URL Credential Page Detection

**Goal:** Detect HTML smuggling terminal pages by running a content script at `document_start` on `blob:` scheme navigations.

- [ ] **C1** Open `manifest.json` — check if `content_scripts` already declares `document_start` injection, and whether `blob:` scheme URLs are reachable. Confirm whether `matches` supports `blob:*` or requires `all_frames: true` + programmatic injection → Verify: Chrome extension docs confirm `blob:` scheme requires programmatic injection from `background.js`; note the approach
- [ ] **C2** In `dataegress/background.js`, add `chrome.webNavigation.onCommitted` listener filtering `url.startsWith('blob:')` — on match, inject `blob_credential_detector.js` via `chrome.scripting.executeScript` → Verify: manually navigate to `URL.createObjectURL(new Blob(['<input type=password>'], {type:'text/html'}))` in test Chrome profile and confirm script executes
- [ ] **C3** Create `dataegress/blob_credential_detector.js` — port full detection script from research doc (password field count, brand keyword check, nested smuggling check, risk scorer, field disabler) → Verify: script correctly identifies `<input type=password>` in blob page, emits `BLOB_URL_CREDENTIAL_PAGE` with `riskScore > 0.9`
- [ ] **C4** Wire `emitAlert()` to the existing DataEgressMonitor Sentinel telemetry pipeline → Verify: alert appears in `BrowserPhishingTelemetry_CL` schema test harness with correct field names
- [ ] **C5** Add `BLOB_URL_CREDENTIAL_PAGE` to the `BrowserPhishingTelemetry_CL` schema doc → Verify: no collision with existing event types; `credentialFieldCount` field typed as `int`

**Done When:** Manual test in unpacked extension loads a blob: page with a password field and emits a Critical alert to the telemetry pipeline.

---

### Plan D: Sentinel KQL — Starkiller Impossible Geography Session Reuse

**Goal:** Add post-compromise AiTM session hijack detection query targeting Starkiller-class real-time proxy kits.

- [ ] **D1** Open `sentinel/queries/` — confirm directory structure and naming convention for existing queries → Verify: directory listing shows peers like `oauthguard_device_code.kql`, `proxyguard_gophish.kql`
- [ ] **D2** Create `sentinel/queries/aitmpostcompromise_impossible_geography.kql` — port the `SigninLogs` impossible-travel query from the research doc → Verify: KQL syntax validates in Sentinel query editor with no parse errors
- [ ] **D3** Adjust `TimeDeltaMinutes < 30` threshold — review against your Entra tenant's baseline travel time distribution; set to a value that produces <5% false positives in a dry run against 7-day `SigninLogs` history → Verify: dry-run query returns zero results against known-good signin history
- [ ] **D4** Add the query as a Scheduled Analytics Rule in Sentinel with severity `High`, run every 30 minutes, lookback 2 hours → Verify: rule appears in Analytics → Active Rules; no validation errors on save
- [ ] **D5** Document the query in `sentinel/README.md` with the Starkiller context, Jinkusu attribution, and Abnormal AI source → Verify: README lists the new query with correct filename reference

**Done When:** KQL validates, Scheduled Rule saves without errors, dry-run against 7d lookback returns zero false positives.

---

## Wave 3 — ExtensionAuditor Structural Additions (3–5 days)

These add new audit sub-systems to ExtensionAuditor. More files, more test surface. Tackle after Wave 1 and 2 are stable.

---

### Plan E: ExtensionAuditor — declarativeNetRequest Security Header Stripping

**Goal:** Audit `rules.json` of installed/updated extensions for rules that remove or modify security response headers.

- [ ] **E1** Open `extensionauditor/auditors/` — confirm existing auditors (manifest key spoof, permission escalation, domain injection) as structural reference → Verify: find the hook point in `background.js` `chrome.management.onInstalled` listener where new auditor calls should be inserted
- [ ] **E2** Create `extensionauditor/auditors/dnr_header_audit.js` — port `SECURITY_RESPONSE_HEADERS` set, `auditDeclarativeNetRequestRules()`, fetch + parse `rules.json` from extension resources, violation loop → Verify: unit test with a mock `rules.json` containing `{action: {responseHeaders: [{header: 'content-security-policy', operation: 'remove'}]}}` returns one violation with `riskScore: 0.95`
- [ ] **E3** Handle edge case — extension does not expose `rules.json` as a web-accessible resource → `fetch()` will 404 or CORS-fail; wrap in try/catch and return `null` cleanly → Verify: test with an extension that has no DNR rules returns `null` without throwing
- [ ] **E4** Register `auditDeclarativeNetRequestRules()` in the `chrome.management.onInstalled` listener in `background.js` after existing auditors → Verify: in test Chrome profile, loading a mock extension with CSP-stripping DNR rule triggers `EXTENSION_SECURITY_HEADER_STRIP` alert in console
- [ ] **E5** Add `EXTENSION_SECURITY_HEADER_STRIP` to `BrowserPhishingTelemetry_CL` schema; add `violationCount` (`int`), `violations` (`dynamic`) fields → Verify: schema doc updated, field types consistent with other dynamic fields

**Done When:** Unit test passes for both violation-present and violation-absent cases; integration test in unpacked extension catches CSP-strip DNR rule.

---

### Plan F: ExtensionAuditor — Developer Contact Drift + C2 Polling

**Goal:** Detect extension ownership transfers (developer contact change) and background C2 polling patterns.

- [ ] **F1** Create `extensionauditor/auditors/ownership_drift.js` — port `extensionOwnershipBaseline` storage object, `checkOwnershipDrift()` function, `chrome.management.get()` call, homepage/updateUrl diff logic → Verify: unit test with mock `chrome.management.get()` returning changed `homepageUrl` emits `EXTENSION_DEVELOPER_CONTACT_CHANGED`
- [ ] **F2** Persist `extensionOwnershipBaseline` to `chrome.storage.local` (not in-memory) so baseline survives browser restart → Verify: set baseline, restart test browser, load extension — confirm baseline is re-read from storage and drift detection still works
- [ ] **F3** Create `extensionauditor/auditors/c2_polling_detector.js` — port `EXTENSION_C2_PATTERNS` regex array and `isExtensionC2Candidate()` from research doc; hook into background service worker `fetch()` monitoring via `chrome.webRequest.onBeforeRequest` filtered to extension origins → Verify: a mock extension that fetches `https://extensionanalyticspro.example.com/extensions/callback?uuid=abc123` triggers `EXTENSION_C2_POLLING` alert
- [ ] **F4** Register both auditors in `background.js` — ownership drift on `chrome.management.onInstalled`, C2 polling as a persistent `webRequest` listener → Verify: both auditors appear in the `chrome://extensions` background service worker console with no load errors
- [ ] **F5** Add `EXTENSION_DEVELOPER_CONTACT_CHANGED` and `EXTENSION_C2_POLLING` to schema doc → Verify: schema lists both with correct field definitions

**Done When:** Ownership drift unit test passes with persistent storage; C2 pattern test fires on mock extension fetch; both event types appear in schema.

---

### Plan G: AgentIntentGuard — Agentic Blabbering Signal

**Goal:** Add guardrail-bypass detection — credential field focus on a page that previously raised suspicion signals.

- [ ] **G1** Open `agentintentguard/` — confirm current module state (this is a newer module; review what signals already exist) → Verify: existing signal list in `background.js` or `content.js` is documented; identify where to add the new `AgentReasoningMonitor` class
- [ ] **G2** Create or extend `agentintentguard/reasoning_monitor.js` — port `AgentReasoningMonitor` class from research doc: `suspicionRaised` flag, `suspicionTimestamp`, `focusin` event listener, `isCredentialField()` check, 30-second window → Verify: unit test — call `raiseSuspicion()`, simulate `focusin` on `<input type=password>` within 5 seconds → alert emits; simulate focus after 31 seconds → no alert
- [ ] **G3** Connect `raiseSuspicion()` call to existing PhishVision page-flag events — when PhishVision emits a brand-impersonation signal, call `raiseSuspicion()` on the AgentIntentGuard instance for that tab → Verify: integration test — PhishVision flags a page, then a credential field is focused — `AGENTIC_BLABBERING_GUARDRAIL_BYPASS` emits with `elapsed` < 30000
- [ ] **G4** Add text-to-HTML ratio heuristic to PhishVision — calculate `bodyText.length / bodyHTML.length`; if ratio < 0.05 on a page with credential fields, add `gan_optimised_page` signal at `+0.15` risk contribution → Verify: test against a real Starkiller-style sparse page (minimal text, heavy CSS) — ratio check fires; test against a normal login page — does not fire
- [ ] **G5** Add `AGENTIC_BLABBERING_GUARDRAIL_BYPASS` to schema; add `elapsed` (`int`, ms), `fieldType` (`string`) → Verify: schema updated, no conflicts

**Done When:** Unit tests pass for both timing branches; integration test confirms cross-module signal chain from PhishVision → AgentIntentGuard fires correctly.

---

## KitRadar — Documentation Update (no code, 30 minutes)

- [ ] Add a `DETECTION_BOUNDARIES.md` to `kitradar/` documenting Starkiller-class kits as out-of-scope for template fingerprinting; explain the architectural reason (live headless Chrome proxy, no static DOM); note that detection shifts to ProxyGuard (`@` masking) + Sentinel (impossible geography) + CTAPGuard (passkey resistance)
- [ ] Add a note in the Tycoon 2FA fingerprint file that the operator group was dismantled by Europol (March 2026) but fingerprints remain valid for circulating forks

---

## Dependency Map

```
Wave 1 (Plans A, B) ──┐
                       ├──► Wave 2 (Plans C, D) ──► Wave 3 (Plans E, F, G)
                       │         ↑
Wave 1 schema updates ─┘   (schema must exist before C/D telemetry wiring)
```

Wave 2 Plan C depends on the `BrowserPhishingTelemetry_CL` schema additions from Wave 1 Plans A and B — complete those schema docs before writing C4.

Wave 3 Plans E and F can be run in parallel. Plan G can start independently but the PhishVision integration step (G3) requires PhishVision to be at a stable state.

---

## Done When (All Waves)

- [ ] 5 new detector files created and unit-tested
- [ ] 6 new `EventType` values in schema: `HTML_SMUGGLING_LOADER`, `URL_USERINFO_MASKING`, `OAUTH_STATE_EMAIL_ENCODED`, `BLOB_URL_CREDENTIAL_PAGE`, `EXTENSION_SECURITY_HEADER_STRIP`, `EXTENSION_DEVELOPER_CONTACT_CHANGED`
- [ ] 1 new Sentinel Scheduled Analytics Rule (impossible geography) active and dry-run clean
- [ ] KitRadar `DETECTION_BOUNDARIES.md` written
- [ ] All unit tests passing; integration smoke tests passing in test Chrome profile
