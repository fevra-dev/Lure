# BrowserPhishingTelemetry_CL — Custom Sentinel Table Schema
**Module: PhishOps Chrome Extension (PhishAgent) · Last Updated: March 2026 (Wave 1 additions)**

Custom Log table populated by the PhishOps Chrome MV3 extension's service worker
via the Azure Monitor DCR HTTP Data Collection API. Captures browser-layer signals
invisible to EDR, SASE, email gateways, and Microsoft Defender for Endpoint.

---

## Base Fields (All EventTypes)

| Field | Type | Description |
|---|---|---|
| `TimeGenerated` | datetime | UTC timestamp of event |
| `EventType_s` | string | Detector module that fired — see EventType table below |
| `TabId_d` | int | Chrome tab ID where the event was observed |
| `Url_s` | string | Page or request URL, truncated to 500 chars |
| `RiskScore_d` | double | Detector risk score, 0.0–1.0 |
| `Signals_s` | dynamic | JSON array of human-readable signal strings |
| `Severity_s` | string | `Critical` \| `High` \| `Medium` \| `Low` |
| `Timestamp_s` | string | ISO 8601 client-side timestamp (complement to TimeGenerated) |

---

## EventType Values

| EventType | Type | Description |
|---|---|---|
| `OAUTH_DEVICE_CODE_FLOW` | string | Browser initiated an OAuth device authorization flow (`/oauth2/devicecode` or equivalent) — Storm-2372 / APT29 technique |
| `CLIPBOARD_WRITE_DETECTED` | string | Page called `navigator.clipboard.writeText()` — ClickFix clipboard malware delivery (DataEgressMonitor) |
| `OAUTH_CONSENT_REQUESTED` | string | OAuth authorization page requested consent for one or more application scopes — OAuthGuard scope parser |
| `OAUTH_STATE_EMAIL_ENCODED` | string | OAuth authorization request contained a `state=` parameter that decoded to a victim email address — Microsoft March 2, 2026 documented C2 exfil technique; base64/hex/URL encoding detected |
| `BLOB_URL_CREDENTIAL_PAGE` | string | A `blob:` URL navigation contained a credential-harvesting page — terminal stage of an HTML smuggling attack chain; password fields detected in an ephemeral blob: document that never appears in network logs |
| `EXTENSION_SECURITY_HEADER_STRIP` | string | An installed or updated extension's `declarativeNetRequest` rules.json contains rules that remove or overwrite security response headers (CSP, X-Frame-Options, HSTS, etc.) — QuickLens supply chain attack pattern (Feb 2026) |
| `EXTENSION_DEVELOPER_CONTACT_CHANGED` | string | An installed extension's developer homepage URL or update URL changed since baseline was recorded — ownership transfer signal (QuickLens/Cyberhaven/ExtensionHub attack pattern) |
| `EXTENSION_C2_POLLING` | string | An extension's background service worker made an outbound request matching C2 polling URL patterns — QuickLens dynamic payload delivery fingerprint |
| `AGENTIC_BLABBERING_GUARDRAIL_BYPASS` | string | A credential field received focus within the suspicion window after a page-level threat signal was raised — AI agent guardrail bypass pattern; agent continues credential submission despite raised suspicion |

---

## Additional Fields by EventType

### OAUTH_DEVICE_CODE_FLOW additional fields

| Field | Type | Description |
|---|---|---|
| `Endpoint_s` | string | Device code endpoint matched (e.g. `/oauth2/devicecode`) |
| `RequestedScopes_s` | dynamic | JSON array of OAuth scopes in the request |
| `HasHighPrivilegeScope_b` | bool | True if any scope is in the high-privilege set (`Mail.ReadWrite`, `Directory.ReadWrite.All`, etc.) |

---

### CLIPBOARD_WRITE_DETECTED additional fields

| Field | Type | Description |
|---|---|---|
| `ClipboardContent_s` | string | First 200 chars of clipboard payload (PowerShell commands, etc.) |
| `TriggerType_s` | string | `user_gesture` \| `programmatic` — whether write was user-initiated |

---

### OAUTH_CONSENT_REQUESTED additional fields

| Field | Type | Description |
|---|---|---|
| `RequestedScopes_s` | dynamic | JSON array of OAuth scopes being requested |
| `ClientId_s` | string | OAuth `client_id` parameter value |
| `RedirectUri_s` | string | OAuth `redirect_uri` parameter value |
| `HighRiskScopes_s` | dynamic | Subset of RequestedScopes that match high-privilege patterns |

---

### OAUTH_STATE_EMAIL_ENCODED additional fields

| Field | Type | Description |
|---|---|---|
| `DecodedEmail_s` | string | The email address decoded from the `state` parameter value |
| `StateValue_s` | string | First 64 chars of the raw `state` parameter value (PII-truncated) |
| `EncodingMethod_s` | string | Encoding strategy detected: `base64` \| `hex` \| `url` |

**Detection behaviour:**
- Fires on `chrome.webRequest.onBeforeRequest` for OAuth authorization endpoints
- `RiskScore_d` is always `0.85` on confirmed detection
- `EncodingMethod_s = 'url'` covers cases where `URLSearchParams` pre-decoded the
  percent-encoding (e.g. `%40` → `@`) before the detector received the value

---

### BLOB_URL_CREDENTIAL_PAGE additional fields

| Field | Type | Description |
|---|---|---|
| `CredentialFieldCount_d` | int | Number of `<input type="password">` fields found in the blob: page |
| `MatchedBrands_s` | dynamic | JSON array of brand keywords matched in page text/title (e.g. `["microsoft","outlook"]`) |
| `NestedSmugglingDetected_b` | bool | True if inline `<script>` tags inside the blob: page contain further `atob()`/`Blob` calls (second-stage loader) |
| `FormExfiltrationDetected_b` | bool | True if a `<form action="https://...">` pointing to an external URL was found |
| `ExternalActions_s` | dynamic | JSON array of external form action URLs (capped at 3) |
| `BlobUrl_s` | string | First 100 chars of the `blob:` URL (ephemeral — for session correlation only) |
| `PageTitle_s` | string | `document.title` of the blob: page (first 100 chars) |

**Score composition reference:**

| Signal | Contribution | Notes |
|---|---|---|
| Password field present | +0.50 | Base signal — any credential field in blob: is high-risk |
| Second password field | +0.10 | Confirm-password pattern |
| Brand keyword match | +0.20 | Impersonation of known high-value brand |
| Nested smuggling pattern | +0.20 | Second-stage loader embedded in terminal page |
| External form action | +0.15 | Explicit credential exfiltration endpoint |

Alert threshold: `>= 0.65` (emit event). Disable threshold: `>= 0.80` (disable fields + inject banner).
Confirmed high-risk page (password + brand + nested): score = `0.90` → Critical.

---

### EXTENSION_SECURITY_HEADER_STRIP additional fields

| Field | Type | Description |
|---|---|---|
| `ExtensionId_s` | string | Chrome extension ID of the audited extension |
| `ExtensionName_s` | string | Display name of the extension |
| `ViolationCount_d` | int | Number of rules violating security header policy |
| `Violations_s` | dynamic | JSON array of up to 5 violation objects, each containing `ruleId`, `header`, `operation`, `newValue`, `conditionUrlFilter`, `conditionDomains` |

**Risk scoring:**
- Global CSP removal (`conditionDomains: []`): `riskScore = 0.95` → Critical
- Any other security header removal/modification: `riskScore = 0.80` → High

**Security headers monitored:** `content-security-policy`, `content-security-policy-report-only`, `x-frame-options`, `x-xss-protection`, `x-content-type-options`, `strict-transport-security`, `permissions-policy`, `cross-origin-opener-policy`, `cross-origin-embedder-policy`, `cross-origin-resource-policy`

---

### EXTENSION_DEVELOPER_CONTACT_CHANGED additional fields

| Field | Type | Description |
|---|---|---|
| `ExtensionId_s` | string | Chrome extension ID |
| `ExtensionName_s` | string | Display name of the extension |
| `PreviousHomepage_s` | string | Homepage URL recorded in baseline |
| `NewHomepage_s` | string | Current homepage URL (post-change) |
| `PreviousUpdateUrl_s` | string | Update URL recorded in baseline |
| `NewUpdateUrl_s` | string | Current update URL (post-change) |
| `VersionChanged_s` | string | Version delta string (e.g. `"5.7 → 5.8"`) or null if version unchanged |

---

### EXTENSION_C2_POLLING additional fields

| Field | Type | Description |
|---|---|---|
| `ExtensionId_s` | string | Initiating extension's Chrome ID (extracted from `chrome-extension://` origin) |
| `DestinationUrl_s` | string | Full C2 URL, truncated to 500 chars |
| `DestinationHost_s` | string | Hostname of the C2 endpoint |
| `MatchedPattern_s` | string | The regex pattern that matched (for investigation context) |

---

### AGENTIC_BLABBERING_GUARDRAIL_BYPASS additional fields

| Field | Type | Description |
|---|---|---|
| `Elapsed_d` | int | Milliseconds between suspicion being raised and credential field focus |
| `FieldType_s` | string | The `type` attribute of the focused input field (e.g. `password`, `email`) |
| `SuspicionReason_s` | string | The reason string from the module that raised suspicion (e.g. `phishvision_brand_impersonation`, `gan_optimised_page:ratio=0.02`) |

---

## Sample KQL Queries

```kql
// State parameter abuse — all events with correlated sign-in check
BrowserPhishingTelemetry_CL
| where TimeGenerated > ago(24h)
| where EventType_s == "OAUTH_STATE_EMAIL_ENCODED"
| extend
    Email  = tostring(parse_json(EventData_s).decodedEmail),
    Method = tostring(parse_json(EventData_s).encodingMethod)
| project TimeGenerated, Email, Method, RiskScore_d, Url_s, Severity_s
| order by TimeGenerated desc
```

```kql
// Cross-module: ClickFix delivery followed by OAuth consent on same tab
BrowserPhishingTelemetry_CL
| where TimeGenerated > ago(1h)
| where EventType_s in ("CLIPBOARD_WRITE_DETECTED", "OAUTH_CONSENT_REQUESTED")
| summarize
    EventTypes = make_set(EventType_s),
    EventCount = count()
  by TabId_d, bin(TimeGenerated, 10m)
| where array_length(EventTypes) > 1
| extend Alert = "Multi-stage: ClickFix delivery + OAuth consent on same tab within 10 minutes"
```

---

## Privacy and Data Handling

- `DecodedEmail_s` contains PII (victim email address). Apply appropriate Sentinel
  data retention and access controls — minimum 90-day retention recommended for
  incident investigation purposes.
- `StateValue_s` is intentionally truncated to 64 chars to limit PII surface area.
- `ClipboardContent_s` for `CLIPBOARD_WRITE_DETECTED` events may contain sensitive
  information (passwords, API keys in PowerShell commands). Apply column-level access
  restrictions if required by your privacy policy.

---

*BrowserPhishingTelemetry_CL schema · PhishOps Chrome Extension · PhishOps Detection Portfolio · March 2026*
