# ProxyPhishingEvents_CL — Custom Sentinel Table Schema
**Module: ProxyGuard · Last Updated: March 2026 (Wave 1 additions)**

Custom Log table populated by ProxyGuard's mitmproxy addon via the
Azure Monitor DCR HTTP Data Collection API.

---

## Base Fields (All EventTypes)

| Field | Type | Description |
|---|---|---|
| `TimeGenerated` | datetime | UTC timestamp of event |
| `EventType_s` | string | Detector that fired — see EventType table below |
| `DestinationUrl_s` | string | Full request URL, truncated to 500 chars |
| `DestinationHost_s` | string | Hostname of the destination |
| `RiskScore_d` | double | Composite risk score, 0.0–1.0 |
| `Signals_s` | dynamic | JSON array of human-readable signal strings |
| `ClientIp_s` | string | Source IP of the proxied client |

---

## EventType Values

| EventType | Type | Description |
|---|---|---|
| `GOPHISH_CAMPAIGN_FINGERPRINT` | string | HTTP request URL contained a Gophish-style recipient tracking parameter (`rid=`, `secure_id=`, etc.) |
| `HTML_SMUGGLING_LOADER` | string | HTTP response body contained JavaScript atob()+Blob+createObjectURL smuggling loader pattern — payload encoded to bypass gateway inspection |
| `URL_USERINFO_MASKING` | string | HTTP request URL contained userinfo `@` masking (Starkiller PhaaS delivery technique — displays trusted brand, resolves to attacker domain) |

---

## Additional Fields by EventType

### GOPHISH_CAMPAIGN_FINGERPRINT additional fields

| Field | Type | Description |
|---|---|---|
| `TrackingParam_s` | string | Matched parameter name (`rid`, `secure_id`, `track_id`, etc.) |
| `TrackingValue_s` | string | First 16 chars of token value (truncated — avoid storing full token) |
| `DomainAgeDays_d` | int | Domain age in days from WHOIS lookup. -1 if unavailable. |

---

### HTML_SMUGGLING_LOADER additional fields

| Field | Type | Description |
|---|---|---|
| `PatternName_s` | string | Primary matched pattern name (e.g. `ATOB_CALL`, `BLOB_CREATEOBJECTURL`, `MSHTA_SCRIPTBLOCK`) |
| `MatchedSnippet_s` | string | First 120 chars of the first matched code region (safety-truncated, never the full payload) |

**Pattern scoring reference (compound additive, alert threshold ≥ 0.65):**

| Pattern | Score Contribution | Description |
|---|---|---|
| `ATOB_CALL` | +0.40 | `atob()` call with non-trivial base64 argument |
| `BLOB_CREATEOBJECTURL` | +0.30 | `createObjectURL()` call (variable or inline Blob form) |
| `NEW_BLOB_CONSTRUCT` | +0.15 | `new Blob()` constructor present |
| `BLOB_NAVIGATE` | +0.20 | Navigation after blob URL assembly (`location.href=`, `window.open()`) |
| `DYNAMIC_ANCHOR_CLICK` | +0.20 | Synthetic anchor `createElement('a')` + `.click()` |
| `LARGE_BASE64_STRING` | +0.15 | Base64 literal ≥ 200 chars (payload carrier) |
| `MSHTA_SCRIPTBLOCK` | +0.65 | Windows `mshta.exe:javascript:` scriptblock — standalone alert |

---

### URL_USERINFO_MASKING additional fields

| Field | Type | Description |
|---|---|---|
| `DisplayedAs_s` | string | The fake brand/domain shown to the user (the `username[:password]` userinfo component before `@`) |
| `ActualHost_s` | string | The real destination hostname resolved by the browser (after `@`) |
| `Technique_s` | string | Always `Starkiller_URL_Masker` for threat attribution |

**Blocking behaviour:** At `RiskScore_d >= 0.85` ProxyGuard returns HTTP 403 to the client and does not forward the request. At `0.70–0.84` the event is logged and emitted but the request is forwarded (alert-only tier).

---

## Sample KQL Queries

```kql
// All URL masking events in last 24h — sorted by risk
ProxyPhishingEvents_CL
| where TimeGenerated > ago(24h)
| where EventType_s == "URL_USERINFO_MASKING"
| extend
    DisplayedAs = tostring(parse_json(EventData_s).displayedAs),
    ActualHost  = tostring(parse_json(EventData_s).actualHost)
| project TimeGenerated, DisplayedAs, ActualHost, RiskScore_d, ClientIp_s
| order by RiskScore_d desc
```

```kql
// HTML smuggling hits by pattern name — last 7 days
ProxyPhishingEvents_CL
| where TimeGenerated > ago(7d)
| where EventType_s == "HTML_SMUGGLING_LOADER"
| extend PatternName = tostring(parse_json(EventData_s).patternName)
| summarize HitCount = count(), AvgRisk = avg(RiskScore_d) by PatternName
| order by HitCount desc
```

---

*ProxyPhishingEvents_CL schema · ProxyGuard module · PhishOps Detection Portfolio · March 2026*
