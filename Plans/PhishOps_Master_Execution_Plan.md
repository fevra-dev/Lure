# PhishOps — Master Execution Plan
## Wave 4 through v2 Completion
**Start date:** March 17, 2026 · **Baseline:** Waves 1–3 complete (136 tests) · **Status:** Lure in progress, telemetry pending, extension unification pending

---

## Current State Snapshot

| Area | Status | Debt |
|------|--------|------|
| Wave 1 — ProxyGuard + OAuthGuard | ✅ Complete | `emitTelemetry()` stubs not wired to DCR |
| Wave 2 — DataEgressMonitor | ✅ Complete | `emitTelemetry()` stubs not wired to DCR |
| Wave 3 — ExtensionAuditor + AgentIntentGuard | ✅ Complete | `emitTelemetry()` stubs not wired to DCR |
| Lure CLI | 🔧 In progress | Parser + extractor scaffolded only; Phases 1–5 remaining |
| Telemetry pipeline | ⏳ Blocked | All waves emit to `chrome.storage.local` — DCR not wired |
| Extension packaging | ⏳ Blocked | Wave 1–3 in separate directories; not unified into single CRX |
| Demo infrastructure | ⏳ Blocked | No demo pages built |
| Wave 4 — AiTM detection | 📋 Researched | Research complete (March 17); implementation not started |
| v2 modules | 📋 Researched | 8 modules with deep technical write-ups; not started |

**Total detectors built:** 13 extension + 6 KitRadar YARA families
**Total tests:** 136 (31 pytest, 105 Vitest)
**Target on completion:** ~21 detectors, ~280 tests, 5 Sentinel tables, unified extension

---

## Execution Philosophy

Each wave follows the same pattern established in Waves 1–3:

1. **Detector first** — write the detection logic with tests before wiring telemetry
2. **Test gate** — minimum test coverage before moving to next task (target ≥20 tests per new module)
3. **KQL alongside** — write Sentinel analytics rule in the same week as the detector it covers
4. **Schema update** — every new EventType gets a `BrowserPhishingTelemetry_CL.md` entry on the same day it's built
5. **Surgical edits** — once a module is baseline, targeted additions only; no rewrites

---

## PHASE 0 — Telemetry Wiring & Extension Unification
### Weeks 1–2 (March 17–28)

**Goal:** Take Waves 1–3 from working code to deployable product. Unblock everything downstream.

These are not new features — they are the connective tissue that makes the existing 13 detectors production-grade. Do this before building anything new.

---

### Week 1 — Azure Monitor DCR Wiring

**Why first:** Every wave's `emitTelemetry()` function is a stub writing to `chrome.storage.local`. Without real DCR ingestion, there is no Sentinel visibility. This is the most critical infrastructure gap.

#### Task 0.1 — DCR + DCE infrastructure setup

Create the two custom Log Analytics tables:

```
BrowserPhishingTelemetry_CL  — Chrome extension events
ProxyPhishingEvents_CL       — ProxyGuard mitmproxy events
```

Files to create:
```
sentinel/
├── tables/
│   ├── BrowserPhishingTelemetry_CL.json     # ARM template — table schema
│   └── ProxyPhishingEvents_CL.json          # ARM template — table schema
├── dcr/
│   ├── phishops-browser-dcr.json            # DCR for extension → Sentinel
│   └── phishops-proxy-dcr.json             # DCR for ProxyGuard → Sentinel
└── deploy.sh                                # az cli deployment script
```

DCR schema matches what's documented in `wave3/BrowserPhishingTelemetry_CL.md`. No schema changes in this task — wire, don't redesign.

**Acceptance:** `az monitor data-collection rule show` returns both DCRs without error. Tables visible in Sentinel workspace.

---

#### Task 0.2 — Replace `emitTelemetry()` stub in extension

All three waves write to `chrome.storage.local` via a shared `lib/telemetry.js`. Replace the stub with a real Logs Ingestion API call.

File to edit: `extension/lib/telemetry.js`

```javascript
// Current (stub):
export async function emitTelemetry(event) {
  await chrome.storage.local.set({ [event.type]: event });
}

// Replace with:
export async function emitTelemetry(event) {
  // 1. Always write to local storage for popup display (keep this)
  await chrome.storage.local.set({ lastEvent: event });

  // 2. Attempt DCR ingestion (fail silently if not configured)
  const config = await chrome.storage.sync.get(['dcrEndpoint', 'dcrToken']);
  if (!config.dcrEndpoint) return;

  try {
    await fetch(config.dcrEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.dcrToken}`
      },
      body: JSON.stringify([{
        TimeGenerated:      new Date().toISOString(),
        EventType_s:        event.type,
        RiskScore_d:        event.riskScore ?? 0,
        Severity_s:         event.severity ?? 'Medium',
        Signals_s:          JSON.stringify(event.signals ?? []),
        URL_s:              (event.url ?? '').slice(0, 500),
        TabId_d:            event.tabId ?? 0,
        ExtensionVersion_s: chrome.runtime.getManifest().version
      }])
    });
  } catch (_) {
    // Network failure — degrade gracefully, local storage still has event
  }
}
```

New Vitest tests to write (`extension/__tests__/telemetry.test.js`):
- Stub fires local storage write on every call
- DCR POST fires when `dcrEndpoint` is set in sync storage
- DCR POST does NOT fire when `dcrEndpoint` is absent (graceful degrade)
- Network failure does not throw (catch block works)
- Payload shape matches `BrowserPhishingTelemetry_CL` schema exactly

**Target: +8 tests → running total: 144**

---

#### Task 0.3 — ProxyGuard DCR wiring

File to edit: `wave1/proxy_guard.py` → `proxyguard/lib/sentinel.py` (extract)

```python
# proxyguard/lib/sentinel.py
import os, json, time
from datetime import datetime, timezone
import requests

class SentinelEmitter:
    def __init__(self):
        self.endpoint = os.getenv('PHISHOPS_DCR_ENDPOINT')
        self.token    = os.getenv('PHISHOPS_DCR_TOKEN')
        self.enabled  = bool(self.endpoint and self.token)

    def emit(self, event: dict) -> bool:
        if not self.enabled:
            return False
        payload = [{
            'TimeGenerated': datetime.now(timezone.utc).isoformat(),
            **event
        }]
        try:
            r = requests.post(
                self.endpoint,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {self.token}'
                },
                json=payload,
                timeout=5
            )
            return r.status_code == 204
        except Exception:
            return False
```

New pytest tests (`proxyguard/tests/test_sentinel.py`):
- Emitter disabled when env vars absent
- POST fires when env vars set
- Returns `False` on network timeout (no raise)
- Payload contains `TimeGenerated` key
- Payload EventType matches ProxyPhishingEvents_CL schema

**Target: +5 tests → running total: 149**

---

### Week 2 — Extension Unification + Demo Pages + Popup UI

#### Task 0.4 — Unify Waves 1–3 into single extension package

Current state: Wave 1–3 source in separate directories (`wave1/`, `wave2/`, `wave3/`). README documents this as three separate packages. Merge into `extension/` (which appears to already exist as the unified target).

Files to consolidate:
```
extension/
├── manifest.json          # Merge all permissions from wave1–3 manifests
├── background/
│   └── service_worker.js  # Merge wave1 service-worker + wave2 background + wave3 background
├── content/
│   ├── state_parameter_abuse.js   # from wave1
│   ├── blob_credential_detector.js # from wave2
│   └── agent_intent_guard.js       # from wave3
├── lib/
│   └── telemetry.js               # unified (from Task 0.2)
└── popup/
    ├── popup.html
    └── popup.js
```

**Manifest merge checklist:**
- Permissions: `webNavigation`, `storage`, `scripting`, `declarativeNetRequest`, `management`, `tabs`
- Host permissions: `<all_urls>` (required for content script injection on arbitrary phishing domains)
- Content scripts: register all three content scripts with appropriate `matches` patterns
- Background: single service worker entry point
- Version: bump to `1.0.0`

#### Task 0.5 — Popup UI (minimal viable)

This is a portfolio artifact — it needs to be demonstrable. Minimal requirements:

```
popup/popup.html — shows:
  [PhishOps v1.0.0]
  Status: Active / Paused toggle
  Last detection: [EventType] [riskScore] [timestamp]
  Detection count (session): N
  [Open Sentinel Dashboard] link
  [Settings] gear → dcrEndpoint, dcrToken config fields
```

Stack: Vanilla JS + minimal CSS (no React needed for popup). Keep it under 200 lines total.

No tests required for popup UI — visual only.

#### Task 0.6 — Demo pages (4 pages)

These are critical for portfolio review. A reviewer should be able to load the extension, visit a demo page, and see a detection fire in the popup.

```
extension/demo/
├── clickfix.html           # ClickFix clipboard injection demo
│                             Shows fake CAPTCHA, navigator.clipboard.writeText()
│                             fires with PowerShell payload → DataEgressMonitor fires
│
├── oauth-consent.html      # OAuth device code flow demo
│                             Simulates Storm-2372 device code lure
│                             → OAuthGuard fires
│
├── blob-credential.html    # HTML smuggling terminal page demo
│                             Loads blob: URL with password field + Microsoft brand
│                             → DataEgressMonitor BLOB_URL_CREDENTIAL_PAGE fires
│
└── aitm-proxy.html         # AiTM proxy artifact demo (Wave 4 forward look)
                              Simulates domain mismatch + high resource latency
                              → AiTMProxyDetector fires (once Wave 4 built)
```

Each demo page: self-contained single HTML file, clearly labeled "PhishOps Demo — Not a real phishing page", triggers exactly one detector, shows a visible confirmation that the extension detected it.

**Week 2 gate:** Load unpacked extension in Chrome → visit all 3 complete demo pages → popup shows detections for each. If this doesn't work, don't move to Wave 4.

---

## PHASE 1 — Wave 4: AiTM Detection Layer
### Weeks 3–6 (March 31 – April 25)

**Goal:** Add the five AiTM detection gaps documented in the research report. This is the highest-impact addition — it closes the session hijacking blind spot that exists in all three current waves.

---

### Week 3 — KitRadar YARA + ProxyGuard IOK Rules

**Workstream A: KitRadar (Python)**

Add three new YARA-X rules to `lure/rules/phishing_custom.yar` (or create `proxyguard/rules/aitm_proxy_kits.yar` as a separate file for proxy-layer use):

```
Rule 1: phishops_evilginx3_header
  → Detects X-Evilginx: header in HTTP traffic
  → Severity: Critical

Rule 2: phishops_evilginx3_cache_control
  → Detects Cache-Control: no-cache, no-store on HTML/JS content
  → Severity: Medium (combine with domain age)

Rule 3: phishops_muraena_session_path
  → Detects /[a-f0-9]{8,16}/ hex path prefix
  → Severity: High
```

New pytest tests (`proxyguard/tests/test_aitm_yara.py`):
- `X-Evilginx:` header in response body → rule fires
- `X-Evilginx ` (space variant) → rule fires
- Legitimate `Cache-Control: no-cache` on HTML → rule fires (Medium)
- Same rule on `text/css` → does NOT fire (content-type scoping)
- Muraena hex path `/a1b2c3d4/` → rule fires
- Legitimate path `/api/v1/` → does NOT fire
- Short hex path `/ab/` (< 8 chars) → does NOT fire

**Target: +12 tests → running total: 161**

---

**Workstream B: ProxyGuard IOK detector**

New file: `proxyguard/detectors/aitm_kit_fingerprint.py`

Detects Evilginx3 URL path structure as an IOK signal in the ProxyGuard request hook (runs on every HTTP request, not just response bodies):

```python
# Key detection logic to implement:
EVILGINX3_PATH = re.compile(r'^/[a-z]{8}$')
EVILGINX3_SESSION_PATH = re.compile(r'^/[a-f0-9]{8,16}(/|$)')

def detect_aitm_kit_url(url: str, domain_age_days: int) -> AiTMKitFingerprint:
    # Returns risk score + signals
    # Signal 1: 8-char alpha path → +0.40
    # Signal 2: Fresh domain (<14d) → +0.35
    # Signal 3: login. subdomain → +0.15
    # Signal 4: LetsEncrypt cert (passed in from TLS inspection) → +0.10
```

Wire into `proxy_guard.py` request hook alongside existing Gophish RID detector.

New pytest tests:
- `/abcdefgh` on fresh domain → detected
- `/abcdefgh` on 90-day domain → lower score (domain age suppresses)
- `/abcdefgh` on `login.` subdomain + fresh → Critical
- `/api/users` → not detected
- 7-char path → not detected
- 9-char path → not detected (strict 8-char only for Evilginx3 default)

**Target: +10 tests → running total: 171**

---

### Week 4 — Entra ID Session Bifurcation KQL

**Workstream: Sentinel analytics rules**

This is pure KQL — no new code files. Write and deploy two scheduled analytics rules.

New files:
```
sentinel/analytics-rules/
├── aitm_session_bifurcation_entra.json      # ARM template wrapping KQL
└── aitm_session_bifurcation_google.json     # ARM template (after connector setup)

sentinel/kql/
├── aitm_session_bifurcation_entra.kql       # Standalone KQL (from research report)
├── aitm_session_bifurcation_google.kql      # Google Workspace variant
└── aitm_session_bifurcation_master_hunt.kql # Cross-platform join query
```

**Scheduled rule configuration:**
- Frequency: every 30 minutes
- Lookback: 2 hours
- Severity: Dynamic (Critical/High/Medium per `TimeDeltaMin`)
- Entity mapping: `UPN` → Account, `AuthIP` + `AccessIP` → IP
- Tactics: `CredentialAccess`, `InitialAccess`
- MITRE: `T1557.001`, `T1539`

**Master hunt query** — joins `SigninLogs` bifurcation with `BrowserPhishingTelemetry_CL` to correlate a browser-side `AITM_PROXY_ARTIFACT` event (from Wave 4 extension module) with an identity-layer session bifurcation for the same user within the same hour:

```kql
// Cross-layer AiTM correlation:
// Browser artifact + Identity bifurcation = confirmed AiTM
let BrowserSignals = BrowserPhishingTelemetry_CL
| where EventType_s == 'AITM_PROXY_ARTIFACT'
| where TimeGenerated > ago(4h);

let IdentitySignals = <bifurcation query from research report>;

BrowserSignals
| join kind=inner IdentitySignals
    on $left.UPN_s == $right.UPN
| where abs(datetime_diff('minute', TimeGenerated, AuthTime)) < 30
| extend ConfidenceLevel = 'CONFIRMED_AITM'
| extend Alert = strcat('Multi-layer AiTM confirmed: ', UPN)
```

**Schema update required:** Add `UPN_s` field to `BrowserPhishingTelemetry_CL` schema (already present in extension manifest telemetry, just not documented). Update `extension/lib/telemetry.js` to include it if missing.

No new code tests this week (KQL only). **Running total: 171**

---

### Week 5 — Google Workspace Connector + AiTMProxyDetector Content Script

**Workstream A: Google Workspace Sentinel connector**

This is infrastructure work, not code.

Steps:
1. Create Google Service Account in Google Admin Console
2. Grant `reports.audit.readonly` OAuth scope
3. Download Service Account JSON key
4. Deploy Google Workspace connector from Sentinel Content Hub
5. Configure Azure Function with Service Account credentials
6. Verify `GWorkspace_ReportsAPI_login_CL` table populating in Log Analytics
7. Deploy `aitm_session_bifurcation_google.json` analytics rule

**Deliverable:** `docs/deployment/google-workspace-connector.md` — step-by-step setup guide with screenshots. This is a portfolio artifact — a reviewer needs to be able to follow it.

---

**Workstream B: AiTMProxyDetector content script**

New file: `extension/content/aitm_proxy_detector.js`

Full implementation from research report (4 signals: domain mismatch, resource latency, SRI violation, referrer anomaly). Wire into manifest as a content script matching `<all_urls>` (same as other content scripts).

Wire into background service worker: `AITM_PROXY_ARTIFACT` message handler → `emitTelemetry()`.

Update `BrowserPhishingTelemetry_CL.md`:
```
New EventType: AITM_PROXY_ARTIFACT
Fields: riskScore, signals[], hostname, url
Threshold: riskScore >= 0.55
```

New Vitest tests (`extension/__tests__/aitm_proxy_detector.test.js`):
- `document.location.hostname` = `evil-login.xyz`, body contains "Sign in to Microsoft" → DOMAIN_MISMATCH fires, riskScore += 0.60
- Legitimate `login.microsoftonline.com` hostname → no detection
- `performance.getEntriesByType` median > 800ms → HIGH_RESOURCE_LATENCY fires
- Median < 800ms → no latency signal
- `securitypolicyviolation` event with `script-src` violated → SRI_VIOLATION fires
- Referrer = `login.microsoftonline.com`, current host = `attacker.xyz` → REFERRER_BRAND_MISMATCH fires
- Combined domain mismatch + referrer → riskScore >= 0.55 → message sent to background
- Single latency signal alone (0.15) → below threshold → no message sent
- riskScore capped at 1.0 (two high-weight signals don't exceed ceiling)

**Target: +18 tests → running total: 189**

---

### Week 6 — JA4 Integration + Wave 4 Tests + Schema Freeze

**Workstream A: JA4 composite signal in ProxyGuard**

New file: `proxyguard/detectors/ja4_fingerprint.py`

Full implementation from research report. Wire into `proxy_guard.py` as a **composite amplifier only** — JA4 match alone does not emit an alert; it adds `+0.25` to the existing `aitm_kit_fingerprint` risk score if that detector already fired.

Integration pattern:
```python
# In proxy_guard.py response() hook:
kit_result = detect_aitm_kit_url(url, domain_age)
if kit_result.detected:
    ja4_result = await assess_ja4_risk(get_ja4_fingerprint(flow))
    composite_score = min(kit_result.risk_score + ja4_result.risk_score, 1.0)
    emit_to_sentinel({
        'eventType': 'AITM_KIT_FINGERPRINT',
        'riskScore': composite_score,
        'signals': kit_result.signals + ja4_result.signals,
        ...
    })
```

New pytest tests (`proxyguard/tests/test_ja4.py`):
- Go 1.21 fingerprint → `go_http_client_fingerprint` signal, risk += 0.40
- Unknown fingerprint not in hardcoded set + not in DB → `unknown_fingerprint` signal, risk += 0.20
- DB returns `{'application': 'golang/net'}` → `ja4db_go_match` signal
- JA4 alone (no kit URL match) → no alert emitted (composite-only rule)
- Kit URL match + Go JA4 → composite score = kit_score + 0.25 (capped at 1.0)
- Network timeout on ja4db.com → graceful fallback, kit detection still emits

**Target: +10 tests → running total: 199**

---

**Workstream B: Wave 4 schema freeze and documentation**

Files to finalize this week:
```
extension/
└── BrowserPhishingTelemetry_CL.md   # Add AITM_PROXY_ARTIFACT EventType (9th total)

proxyguard/
└── ProxyPhishingEvents_CL.md        # Add AITM_KIT_FINGERPRINT EventType

sentinel/kql/
└── wave4_aitm_detection_library.kql # All 4 Wave 4 KQL queries in one file

docs/threat-model/
└── wave4_coverage_matrix.md         # Updated kill chain coverage including Wave 4
```

**Wave 4 gate:** 199 tests passing. All four AiTM detection surfaces covered. Demo page `aitm-proxy.html` triggers `AiTMProxyDetector`. Sentinel analytics rules deployed and returning results on test data.

---

## PHASE 2 — Lure CLI Completion
### Weeks 7–13 (April 28 – June 13)

**Goal:** Take Lure from scaffolded to production-ready. This runs in parallel to v2 module research but sequentially to Wave 4 — Lure completion is a prerequisite for the full portfolio narrative.

---

### Week 7 — Lure Phase 1: Core Pipeline

Complete the core `.eml` analysis pipeline. This week's output should be a working `lure analyze email.eml` command end-to-end.

Files to complete:

**`lure/modules/parser.py`** (currently started):
- RFC 5322 header parsing with `mail-parser`
- SPF validation: query sender IP against SPF record via `pyspf` or `checkdmarc`
- DKIM validation: verify signature against public key via `dkimpy`
- DMARC policy evaluation: `checkdmarc` library
- Reply-To mismatch: compare `Reply-To` domain vs. `From` domain
- Received chain: walk hops, extract IPs, flag RFC1918 → public transitions
- Homograph detection: `tldextract` + Unicode script mixing check

**`lure/modules/extractor.py`** (currently started):
- URL extraction from HTML body: `BeautifulSoup` (not regex)
- URL defanging: handle `hxxps://`, `[.]`, `(dot)`, etc.
- IP extraction with context (exclude `127.0.0.1`, `0.0.0.0`)
- Email address extraction
- Attachment IOC extraction: filename, hash (MD5/SHA256), MIME type
- ZIP traversal depth 3
- Multi-hop redirect following: `httpx` async, depth 5, timeout 10s, store chain

New pytest tests:
- SPF fail on known failing test email → `SPF_FAIL` signal
- SPF pass → no signal
- DKIM fail → `DKIM_FAIL` signal
- Reply-To domain differs from From → `REPLY_TO_MISMATCH`
- Cyrillic 'а' in From domain → `HOMOGRAPH_DOMAIN`
- URL extraction finds URLs in HTML body (not just headers)
- Defanged URL `hxxps://evil[.]com` → normalized to `https://evil.com`
- ZIP attachment → extracts files up to depth 3
- Redirect chain A→B→C→D → stored as list of 4 hops

**Target: +20 tests → running total: 219**

---

### Week 8 — Lure Phase 2: YARA + Attachment Analysis

**`lure/modules/scanner.py`:**
- Load `lure/rules/phishing_custom.yar` (8 existing rules)
- Compile once, cache in memory
- Add `--rules-dir` flag to accept additional rule directories
- Bundle `Neo23x0/signature-base` rules as optional (`pip install lure[full-rules]`)

**`lure/modules/attachment.py`** (new):
- `oletools` integration: `olevba` for VBA macro extraction, `mraptor` for risk classification
- XLM macro detection: `xlmdeobfuscator`
- PDF JavaScript extraction: `pdfminer.six` + `pdfid.py` pattern
- PE file: `pefile` — imports, exports, section entropy, PDB path
- Embedded URL extraction from PDFs and Office docs

New pytest tests:
- YARA rule `phishops_clickfix_clipboard_lure` fires on ClickFix payload HTML
- YARA rule `phishops_tycoon2fa_kit` fires on Tycoon 2FA kit fragment
- YARA rule `phishops_device_code_lure` fires on device code lure text
- No false positive on clean HTML (no rule fires)
- `olevba` detects AutoOpen macro in `.doc` → `SUSPICIOUS_ATTACHMENT` signal
- PDF with `/JavaScript` in xref → JS extraction fires
- PE file with high section entropy → flagged

**Target: +18 tests → running total: 237**

---

### Week 9 — Lure Phase 3: Threat Intelligence Enrichment

**`lure/modules/enrichment.py`** (new):
- VirusTotal v3 API: URL/hash lookup, 48h SQLite cache
- AbuseIPDB v2: IP reputation, rate-limited (1000 req/day), 24h cache
- urlscan.io: submit URL for scan, retrieve result
- WHOIS: `python-whois` for domain age (used by ProxyGuard too — share this module)
- Homograph/IDN: full `tldextract` + Unicode category check implementation
- PhishTank: bulk URL check (public API)

Cache architecture: SQLite at `~/.lure/cache.db` — one table per API source, TTL enforced on read.

New pytest tests:
- VT cache miss → API called, result stored
- VT cache hit within TTL → API NOT called
- AbuseIPDB returns `abuseConfidenceScore > 80` → `HIGH_ABUSE_IP` signal
- WHOIS domain age < 7 days → `FRESH_DOMAIN` signal
- Network failure on any API → graceful fallback (enrichment skipped, base verdict still returned)
- IDN domain `xn--80ak6aa92e.com` → decoded + flagged

**Target: +16 tests → running total: 253**

---

### Week 10 — Lure Phase 3 cont.: Verdict Engine + Scorer

**`lure/modules/scorer.py`** (extend from current scaffold):

Implement the full weighted scoring model from README:

| Signal | Weight |
|--------|--------|
| SPF_FAIL | 2.0 |
| DKIM_FAIL | 1.5 |
| DMARC_FAIL | 2.0 |
| REPLY_TO_MISMATCH | 2.5 |
| HOMOGRAPH_DOMAIN | 4.0 |
| SUSPICIOUS_ATTACHMENT | 3.0 |
| URL_SHORTENER | 1.0 |
| SUSPICIOUS_TLD | 1.5 |
| MANY_ANOMALIES | 1.0 |
| NO_AUTH_HEADERS | 1.5 |
| YARA_MATCH | 4.0 |

Verdict thresholds:
```
< 3.0   → CLEAN
3.0–4.99 → SUSPICIOUS
5.0–7.99 → LIKELY_PHISHING
≥ 8.0   → CONFIRMED_MALICIOUS
```

New pytest tests:
- SPF_FAIL + DMARC_FAIL (4.0 total) → `SUSPICIOUS`
- SPF_FAIL + DMARC_FAIL + REPLY_TO_MISMATCH (6.5) → `LIKELY_PHISHING`
- HOMOGRAPH_DOMAIN + YARA_MATCH (8.0) → `CONFIRMED_MALICIOUS`
- Clean email (no signals) → `CLEAN`
- Single URL_SHORTENER (1.0) → `CLEAN` (below threshold)
- Score exactly 3.0 → `SUSPICIOUS` (boundary condition)
- Score exactly 5.0 → `LIKELY_PHISHING` (boundary condition)
- Score exactly 8.0 → `CONFIRMED_MALICIOUS` (boundary condition)

**Target: +15 tests → running total: 268**

---

### Week 11 — Lure Phase 4: Campaign Correlation

**`lure/modules/correlation.py`** (new):
- SQLite persistence: `~/.lure/campaigns.db`
- Schema: `emails(id, hash, from_domain, subject_hash, urls, verdict, timestamp)`
- MinHash for subject line similarity (threshold 0.8 = same campaign)
- `lure correlate` command: finds clusters of emails sharing sender infrastructure or subject similarity
- Campaign tagging: auto-assign `CAMPAIGN-[date]-[hash]` ID to clusters

This is a differentiating feature for the portfolio — most open-source email analyzers do single-email verdicts only.

New pytest tests:
- Two emails with identical `From` domain and similar subjects → clustered
- Two emails with different domains and different subjects → not clustered
- MinHash similarity 0.85 → same cluster
- MinHash similarity 0.65 → different clusters
- `lure correlate` on empty DB → returns empty list (no crash)

**Target: +10 tests → running total: 278**

---

### Week 12 — Lure Phase 5: Output Formats

**Output modules:**

JSON canonical output (`--format json`):
```json
{
  "verdict": "CONFIRMED_MALICIOUS",
  "score": 9.5,
  "signals": ["SPF_FAIL", "YARA_MATCH", "HOMOGRAPH_DOMAIN"],
  "iocs": { "urls": [], "ips": [], "hashes": [], "emails": [] },
  "enrichment": { "vt": {}, "abuseipdb": {}, "urlscan": {} },
  "campaign_id": "CAMPAIGN-20260312-a3f2",
  "timestamp": "2026-03-17T12:00:00Z"
}
```

HTML report (`--format html`): Jinja2 template with:
- Verdict banner (color-coded)
- IOC tables (URLs, IPs, hashes)
- YARA match panel (rule name + matched strings)
- Received chain hop diagram (ASCII art is fine)
- Enrichment panels (VT, AbuseIPDB, urlscan results)

STIX 2.1 export (`--format stix`):
- `Indicator` SDO for each YARA rule match
- `ObservedData` SDO for each IOC
- `Bundle` wrapping all objects
- Save to `.json` for MISP import

No new tests for output formats (rendering, not logic). Update integration test in `tests/integration/` to run full pipeline on sample `.eml` and check JSON output schema.

**Running total: 278** (no new unit tests this week)

---

### Week 13 — Lure CLI Polish + Batch Mode

**`lure batch ./email_dir/`:**
- Process all `.eml` and `.msg` files in directory
- Progress bar via `rich`
- Summary table: verdict counts, top IOCs, top YARA rules
- Export combined JSON or HTML report for the batch

**`lure config validate`:** Check all API keys set, test connectivity.

**LLM verdict layer (optional, local only):**
- `lure analyze email.eml --explain` → routes to local Ollama (`qwen2.5:7b`)
- Prompt: "Given this phishing analysis result, explain in plain English why this email is suspicious: {json_result}"
- Falls back gracefully if Ollama not running

QR code extraction (`lure` v2 prep):
- `pyzbar` + `Pillow`: scan image attachments for QR codes
- Decoded URL fed into URL extraction pipeline
- If QR URL triggers YARA rule → `YARA_MATCH` signal + `QR_DELIVERED` tag

**`lure` gate (end of Week 13):** `lure analyze tests/samples/confirmed_phish.eml` returns `CONFIRMED_MALICIOUS` with ≥5 signals in < 30 seconds (including enrichment API calls). All 278 tests passing.

---

## PHASE 3 — Integration Hardening
### Weeks 14–15 (June 16–27)

**Goal:** Connect the dots between all components. Single `docker-compose up` brings the full stack online.

---

### Week 14 — Cross-Module Integration + Docker Stack

**`docker-compose.yml` (full stack):**
```yaml
services:
  proxyguard:     # mitmproxy + all detectors
  lure-api:       # Lure CLI exposed as REST API (FastAPI wrapper)
  sentinel-mock:  # Azure Monitor DCR mock (local Sentinel substitute for demos)
  redis:          # Shared cache (replace SQLite for multi-instance deployments)
```

**Cross-module integration test** (`tests/integration/test_full_chain.py`):
1. Send HTTP request through ProxyGuard containing `X-Evilginx:` header
2. Verify `AITM_KIT_FINGERPRINT` event emitted to Sentinel mock
3. Load `blob-credential.html` demo page in headless Chrome with extension loaded
4. Verify `BLOB_URL_CREDENTIAL_PAGE` event emitted
5. Run `lure analyze` on sample phishing email
6. Verify `CONFIRMED_MALICIOUS` verdict returned with correct signals

New pytest tests (integration):
- Full chain test passes end-to-end
- ProxyGuard + KitRadar joint detection: Evilginx URL → both URL detector AND YARA fire

**Target: +5 tests → running total: 283**

---

### Week 15 — False Positive Tuning + Dry Run

**FP tuning protocol:**
- Run all ProxyGuard detectors against 500 legitimate HTTP requests (captured from normal browsing)
- Run AiTMProxyDetector content script against top 20 legitimate login pages
- Run Entra KQL against 30 days of real SigninLogs
- Document FP rate per detector in `docs/fp-rates.md`
- Adjust thresholds where FP rate > 2%

**7-day Sentinel dry run:**
- Deploy all KQL analytics rules in **dry run mode** (alert but don't create incidents)
- Monitor for FP volume
- Adjust lookback windows and suppression lists
- Document final thresholds in `docs/deployment/sentinel-tuning-guide.md`

**v1.0 release gate (end of Week 15):**
- All 283 tests passing
- FP rate < 2% per detector on baseline traffic
- Full `docker-compose up` demo working
- README `Quick Start` reproducible by a new reviewer in < 10 minutes
- All Sentinel analytics rules deployed with documented tuning

---

## PHASE 4 — v2 Modules
### Weeks 16–26 (June 30 – September 12)

Build v2 modules in priority order based on: (1) research completeness, (2) kill chain gap severity, (3) build time estimate.

---

### Week 16–17 — AutofillGuard

**Research source:** `Research/AutofillGuard_DeepResearch_Report.md`
**Threat:** DOM-based extension clickjacking; hidden field autofill attacks (1Password/LastPass unpatched Jan 2026)
**Build estimate:** 2 weeks

New file: `extension/content/autofill_guard.js`

Key detection logic:
- Audit all `<input>` fields on the page for `opacity: 0`, `z-index < 0`, `clip-path` hiding
- Check for iframe overlays that intercept click events on autofill triggers
- Monitor `window.onbeforefill` / `document.execCommand('insertText')` abuse
- On password field focus: check if field is in a legitimate origin context

New Vitest tests:
- Hidden input field with `opacity: 0` → `HIDDEN_AUTOFILL_FIELD` signal
- Stacked iframe with high z-index over password field → `CLICKJACKING_OVERLAY` signal
- Legitimate password field on `accounts.google.com` → no detection
- Cross-origin iframe containing password field → flagged

**Target: +20 tests → running total: 303**

New EventType in `BrowserPhishingTelemetry_CL.md`: `AUTOFILL_CLICKJACKING`
New KQL analytics rule: `autofill_guard_detection.kql`

---

### Week 18 — FakeSender Shield

**Research source:** `Research/FakeSender_Shield_Technical_Deep_Dive.md`
**Threat:** Helpdesk platform sender spoofing (Zendesk, Freshdesk, ServiceNow abuse for phishing)
**Build estimate:** 1.5 weeks (fold in half of Week 18)

New file: `lure/modules/fake_sender.py`

Key detection logic:
- Parse `From:` for helpdesk platform patterns: `noreply@[company].zendesk.com`, `support@[company].freshdesk.com`
- Check if `Reply-To` redirects to non-platform domain
- Cross-reference sending domain against known helpdesk platform domain patterns
- Flag: legitimate helpdesk domain but body contains credential harvest indicators

New pytest tests:
- `From: noreply@corp.zendesk.com`, `Reply-To: attacker@gmail.com` → `FAKE_SENDER_HELPDESK`
- Legitimate Zendesk email with matching Reply-To → no detection
- ServiceNow notification with external Reply-To → flagged

**Target: +12 tests → running total: 315**

---

### Week 18–19 — FullscreenGuard + PasskeyGuard

**FullscreenGuard (1 week):**
- Detect `document.documentElement.requestFullscreen()` called on page with login/credential UI
- Evilginx phishlets and vishing chains use fullscreen to hide browser URL bar
- Signal: fullscreen API called + password field present on page

New file: `extension/content/fullscreen_guard.js`

**PasskeyGuard (1.5 weeks):**
- Monitor `navigator.credentials.create()` calls
- Validate that WebAuthn credential creation is happening on the expected RP ID
- Flag: FIDO2 registration initiated on a domain that doesn't match the user's current logged-in service

New file: `extension/content/passkey_guard.js`

**Target: +22 tests → running total: 337**

---

### Week 20 — QRSweep Integration with Lure

**Research source:** `Research/phishing_tool_research.md`
**Threat:** Quishing — QR codes in PDF/image email attachments; Device Code Flow QR delivery
**Build estimate:** 2 weeks

New file: `lure/modules/qr_sweep.py`

Key logic:
- `pyzbar` + `Pillow` for image QR decode
- `pdf2image` + `pyzbar` for PDF page QR decode
- Decoded URL fed into existing URL extraction + YARA pipeline
- Signal: QR decoded URL triggers YARA rule → `QR_DELIVERED` tag on verdict
- Cross-module composite: QR URL + Gophish RID pattern → automatic `Critical`

New YARA rule: `phishops_qr_device_code_lure` — QR page with device code flow instructions

New pytest tests:
- PNG attachment with QR → decoded, URL extracted
- PDF attachment with QR on page 2 → decoded
- Decoded URL triggers `phishops_device_code_lure` → `CONFIRMED_MALICIOUS` verdict
- No QR in attachment → no QR signals (no false positive)
- Corrupted PNG → graceful failure (QR extraction skipped)

**Target: +18 tests → running total: 355**

---

### Week 21 — PhishVision

**Research source:** `Research/PhishVision_Technical_Deep_Dive.md`
**Threat:** Visual brand impersonation detection; adversarial ML logo masking
**Build estimate:** 2 weeks

New file: `extension/content/phish_vision.js` (ONNX Runtime Web in-browser inference)

Key logic:
- EfficientNet-B0 model (ONNX format, <5MB) loaded via ONNX Runtime Web
- Extract favicon + logo images from page DOM
- Compare against brand embedding database (top 50 phishing targets)
- Randomized smoothing as adversarial defense (add noise before inference)
- Similarity score > 0.85 on non-matching domain → `VISUAL_BRAND_IMPERSONATION`

New Vitest tests (mock ONNX inference):
- Mock inference returning 0.90 similarity to Microsoft on `evil.xyz` → signal fires
- Legitimate `microsoft.com` with Microsoft logo → no detection (domain matches)
- Mock inference returning 0.70 similarity → below threshold, no detection
- Randomized smoothing applied before inference call

**Target: +15 tests → running total: 370**

---

### Weeks 22–23 — CTAPGuard + SyncGuard

**CTAPGuard (1 week):**
- Monitor WebAuthn assertion requests (`navigator.credentials.get()`)
- Validate challenge integrity: check `rpId` matches current origin
- Flag: CTAP2 credential request from an origin that doesn't match the RP registration domain
- Provides hardware-bound session signal as described in master architecture doc

**SyncGuard (1 week):**
- Detect unauthorized browser sync API access: monitor `chrome.identity.getAuthToken()` calls from non-first-party contexts
- Flag attempts to sync browser data to an attacker-controlled Google account
- Useful signal for enterprise deployments where profile sync is managed

**Target: +20 tests → running total: 390**

---

### Weeks 24–26 — Lure v2 Enhancements

**AI-Generated Email Detection (2 weeks):**

New file: `lure/modules/ai_classifier.py`

Features:
- DetectGPT curvature analysis (local, no API required)
- Burstiness variance: measure sentence length variance (AI text is more uniform)
- Cialdini persuasion density: count urgency/authority/scarcity keywords
- XGBoost classifier trained on labeled phishing corpus + AI-generated samples
- LIME/SHAP for explanation of classifier decision

**LLM Analysis Layer (1 week):**

Wire `--explain` flag across full Lure pipeline:
- Routes to local Ollama (`qwen2.5:7b` preferred, `llama3.2:3b` fallback)
- Verdict explanation in plain English
- Suggested response actions for SOC analysts

**Target: +15 tests → running total: 405**

---

## Final Portfolio State (Week 26)

| Component | Status | Detectors | Tests |
|-----------|--------|-----------|-------|
| ProxyGuard | Complete | 4 detectors + 3 YARA rules | ~55 |
| OAuthGuard | Complete | 2 detectors | ~21 |
| DataEgressMonitor | Complete | 2 detectors | ~35 |
| ExtensionAuditor + AgentIntentGuard | Complete | 5 detectors | ~49 |
| AiTMProxyDetector (Wave 4) | Complete | 4 signals | ~28 |
| AutofillGuard | Complete | 2 detectors | ~20 |
| FullscreenGuard | Complete | 1 detector | ~10 |
| PasskeyGuard | Complete | 1 detector | ~12 |
| CTAPGuard | Complete | 1 detector | ~10 |
| SyncGuard | Complete | 1 detector | ~10 |
| PhishVision | Complete | 1 detector | ~15 |
| KitRadar YARA (11 rules) | Complete | 11 rules | ~30 |
| Lure CLI (v1 + v2) | Complete | 5-stage pipeline + AI | ~130 |
| **Total** | | **~35 detectors** | **~405** |

| Sentinel Layer | Tables | Analytics Rules | KQL Queries |
|---------------|--------|-----------------|-------------|
| Browser telemetry | `BrowserPhishingTelemetry_CL` | 8 | 20+ |
| Proxy events | `ProxyPhishingEvents_CL` | 4 | 12+ |
| Kit fingerprints | `PhishKitFingerprint_CL` | 2 | 6+ |
| Google Workspace | `GWorkspace_ReportsAPI_login_CL` | 1 | 3+ |
| Quishing | `QuishingDetection_CL` | 1 | 3+ |

---

## Dependency Graph

```
Phase 0 (Telemetry + Unification)
  └─► Wave 4 (AiTM Detection)
        └─► Phase 2 (Lure Completion) [parallel after Week 6]
              └─► Phase 3 (Integration Hardening)
                    └─► Phase 4 (v2 Modules)

KitRadar YARA (Week 3) ──────────────────────► Lure scanner.py (Week 8)
Google Workspace connector (Week 5) ─────────► GWorkspace KQL (Week 4)
emitTelemetry DCR (Week 1) ──────────────────► All subsequent Sentinel tables
docker-compose.yml (Week 14) ────────────────► FP tuning (Week 15)
```

---

## Week-by-Week Summary Table

| Week | Dates | Focus | New Tests | Running Total |
|------|-------|-------|-----------|---------------|
| 1 | Mar 17–21 | DCR wiring + telemetry.js | +13 | 149 |
| 2 | Mar 24–28 | Extension unification + popup + demo pages | +0 | 149 |
| 3 | Mar 31–Apr 4 | KitRadar YARA + ProxyGuard IOK | +22 | 171 |
| 4 | Apr 7–11 | Entra ID bifurcation KQL | +0 | 171 |
| 5 | Apr 14–18 | GWorkspace connector + AiTMProxyDetector | +18 | 189 |
| 6 | Apr 21–25 | JA4 integration + schema freeze | +10 | 199 |
| 7 | Apr 28–May 2 | Lure Phase 1: core pipeline | +20 | 219 |
| 8 | May 5–9 | Lure Phase 2: YARA + attachments | +18 | 237 |
| 9 | May 12–16 | Lure Phase 3: TI enrichment | +16 | 253 |
| 10 | May 19–23 | Lure Phase 3: verdict engine | +15 | 268 |
| 11 | May 26–30 | Lure Phase 4: campaign correlation | +10 | 278 |
| 12 | Jun 2–6 | Lure Phase 5: output formats | +0 | 278 |
| 13 | Jun 9–13 | Lure CLI polish + batch mode | +0 | 278 |
| 14 | Jun 16–20 | docker-compose + integration tests | +5 | 283 |
| 15 | Jun 23–27 | FP tuning + 7-day dry run | +0 | 283 |
| 16–17 | Jun 30–Jul 11 | AutofillGuard | +20 | 303 |
| 18 | Jul 14–18 | FakeSender Shield | +12 | 315 |
| 18–19 | Jul 14–25 | FullscreenGuard + PasskeyGuard | +22 | 337 |
| 20 | Jul 28–Aug 1 | QRSweep (Lure integration) | +18 | 355 |
| 21 | Aug 4–8 | PhishVision | +15 | 370 |
| 22–23 | Aug 11–22 | CTAPGuard + SyncGuard | +20 | 390 |
| 24–26 | Aug 25–Sep 12 | Lure v2: AI classifier + LLM layer | +15 | 405 |

---

*PhishOps Master Execution Plan · March 2026*
*Picks up from: Wave 3 complete (136 tests) · Lure scaffolded · Telemetry pending*
