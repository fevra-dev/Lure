# PhishOps Research Series
## AiTM Reverse Proxy Detection — Closing Detection Gaps in PhishOps Coverage
**TLP:WHITE · March 2026 · Defensive Research Only**

---

> All detection logic is defensive-only. No payload generation, no credential capture, no operational offensive tooling.

| Gap | Detection Surface | Module Target | Priority |
|-----|------------------|---------------|----------|
| 1: Evilginx3 / Muraena / Modlishka Fingerprinting | HTTP headers, URL structure, TLS certs | KitRadar + ProxyGuard | High |
| 2: Session Bifurcation KQL (Entra ID + Google) | SigninLogs, Google login_activity | Sentinel KQL | Critical |
| 3: Browser-Side Proxy Artifact Detection | DOM, timing, response headers | PhishAgent (new module) | High |
| 4: Google Workspace Identity Logs for AiTM | Admin SDK Reports API schema | Sentinel integration | High |
| 5: JA4 Fingerprint Integration | TLS client hello patterns | ProxyGuard + AiTM Guardian | Medium |

---

## GAP 1: Evilginx3 / Muraena / Modlishka Infrastructure Fingerprinting

### 1A — Threat Validation

Evilginx3 is the dominant open-source AiTM framework, used across commodity campaigns and named threat actors including Star Blizzard (Microsoft MSTIC). A campaign documented by Infoblox (December 2025) targeted 18 US universities using Evilginx 3.0, generating phishing URLs with eight random alphabetic characters as the URI path component, with URLs expiring within 24 hours to evade crawlers.

### 1B — Evilginx3 Default IOCs (Before Hardening)

#### X-Evilginx Header — Primary IOC

Evilginx3 source code (`core/http_proxy.go`) contains an intentional "easter egg" that injects an `X-Evilginx` header containing the attacker's phishing domain name into proxied requests. This is present in all default deployments and represents the single highest-confidence detection signal for unmodified Evilginx installations.

> **Detection priority: Highest.** Operators who discover this IOC remove it via source modification, but commodity campaigns (the majority) run default builds.

#### URL Path Structure

| Tool | Default URI Pattern | Detection Signal |
|------|--------------------|--------------------|
| Evilginx3 | `/[a-z]{8}` (8 lowercase alpha chars) | Case-insensitive 8-char alpha URI on fresh domain |
| Evilginx3 lure subdomain | `login.[attackerdomain]` (Microsoft phishlets) | `login.` subdomain + LetsEncrypt cert + fresh domain |
| Muraena | `/[a-f0-9]{8,16}/` (hex session path) | Hex path prefix on all proxied resources |
| Modlishka | `/?key=[token]` or `/?session=[token]` | Query param tracking token + proxy referrer behavior |
| Generic AiTM | `Cache-Control: no-cache, no-store` on HTML/JS | Evilginx 3.2+ injects this on all proxied HTML responses |

#### TLS Certificate Patterns

- Evilginx uses LetsEncrypt (certmagic library in v3) to auto-issue certificates — issuer is always `Let's Encrypt R3` or `E5/E6` for fresh domains
- Evilginx Pro 4.x defaults to wildcard certificates (`*.attackerdomain.com`) — wildcard LetsEncrypt on a <14 day old domain is high-signal
- Default Evilginx cert Subject Organization was `Gophish` in older versions; operators are advised to change this to `Microsoft Corporation` in `util/util.go` — detection opportunity: `Organization=Microsoft Corporation` on a non-Microsoft cert

### 1C — YARA-X Detection Rules

```yara
rule phishops_evilginx3_header {
    meta:
        description = "Detects X-Evilginx header in proxied HTTP traffic"
        author      = "PhishOps KitRadar"
        severity    = "Critical"
        mitre       = "T1557.001"
    strings:
        $h1 = "X-Evilginx:" nocase
        $h2 = "X-Evilginx " nocase
    condition:
        any of them
}

rule phishops_evilginx3_cache_control_inject {
    meta:
        description = "Evilginx 3.2+ injects no-cache on all proxied HTML/JS responses"
        severity    = "Medium"
        note        = "Combine with domain age signal to reduce FP rate"
    strings:
        $cc      = "Cache-Control: no-cache, no-store" nocase
        $ct_html = "Content-Type: text/html" nocase
        $ct_js   = "Content-Type: application/javascript" nocase
    condition:
        $cc and ($ct_html or $ct_js)
}

rule phishops_muraena_session_path {
    meta:
        description = "Muraena AiTM hex session path prefix"
        severity    = "High"
    strings:
        // HTTP request paths matching /[a-f0-9]{8,16}/
        $path = /\/[a-f0-9]{8,16}\// ascii
    condition:
        $path
}
```

### 1D — IOK Rules (Indicators of Kit)

| IOK Signal | Tool | Field | Value Pattern |
|-----------|------|-------|---------------|
| X-Evilginx header present | Evilginx3 | `response.headers` | `X-Evilginx: *` |
| 8-char alpha URI path | Evilginx3 | `request.uri.path` | `/^[a-z]{8}$/` |
| `login.` subdomain + LetsEncrypt + <14d domain | Evilginx3 MS phishlet | `tls.issuer + domain_age` | Combined signal |
| Cache-Control: no-cache on HTML | Evilginx 3.2+ | `response.headers` | `no-cache, no-store` on `text/html` |
| Wildcard cert on <14d domain | Evilginx Pro 4.x | `tls.san` | `*.domain` where `domain_age < 14d` |
| `/[0-9a-f]{8,16}/` path prefix | Muraena | `request.uri.path` | Hex path pattern |
| `?key=` or `?session=` with no other params | Modlishka | `request.uri.query` | Single tracking param |

---

## GAP 2: Session Bifurcation KQL — Post-Capture Detection

### 2A — Threat Validation

In a successful AiTM attack, a single authenticated session is used from two different IP addresses: the victim's IP (used during the AiTM-proxied authentication) and the attacker's IP (used to replay the stolen cookie). Unlike impossible travel — which requires two separate login events — AiTM typically produces only **one** login event (from the proxy's IP), followed by post-authentication resource access from a different IP using the same session.

> **Key insight:** Standard impossible travel alerts do not fire because there is only one authentication event. AiTM tools clone the victim's user agent during the proxy session, so UA-based anomaly detection also fails at this layer.

### 2B — Entra ID Session Bifurcation KQL

```kql
// PhishOps — AiTM Session Bifurcation Detection (Entra ID)
// Detects: stolen session cookie replayed from attacker IP after AiTM capture
// MITRE: T1557.001, T1539
// Table: SigninLogs (Entra ID / Microsoft Sentinel)

let lookback = 2h;

// Step 1: Capture interactive sign-ins (the AiTM proxy auth event)
let AuthEvents = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0  // successful
| where AuthenticationRequirement == 'multiFactorAuthentication'
    or AuthenticationDetails has 'Previously satisfied'
| project AuthTime       = TimeGenerated,
          UPN             = UserPrincipalName,
          AuthIP          = IPAddress,
          AuthCountry     = tostring(LocationDetails.countryOrRegion),
          SessionId       = CorrelationId,
          TokenId         = UniqueTokenIdentifier,
          UserAgent       = UserAgent,
          AppName         = AppDisplayName,
          DeviceCompliant = tostring(DeviceDetail.isCompliant),
          DeviceManaged   = tostring(DeviceDetail.isManaged);

// Step 2: Capture non-interactive / resource access events
// (attacker replaying cookie — no new MFA, different IP)
let AccessEvents = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| where IsInteractive == false or SignInEventTypes has 'nonInteractiveUser'
| project AccessTime    = TimeGenerated,
          UPN           = UserPrincipalName,
          AccessIP      = IPAddress,
          AccessCountry = tostring(LocationDetails.countryOrRegion),
          SessionId     = CorrelationId,
          TokenId       = UniqueTokenIdentifier,
          AccessApp     = AppDisplayName;

// Step 3: Join on SessionId; flag geo delta
AuthEvents
| join kind=inner AccessEvents on $left.SessionId == $right.SessionId
| where AuthIP != AccessIP
| where AuthCountry != AccessCountry
| extend TimeDeltaMin = datetime_diff('minute', AccessTime, AuthTime)
| where TimeDeltaMin between (0 .. 60)
// FP suppression: exclude RFC1918 addresses
| where AuthIP !in~ ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
| extend Severity = case(
    TimeDeltaMin < 5,  'Critical',
    TimeDeltaMin < 15, 'High',
    TimeDeltaMin < 60, 'Medium',
                       'Low')
| extend Alert = strcat('AiTM Session Bifurcation: ', UPN,
    ' authed from ', AuthCountry, ' (', AuthIP, ')',
    ' then accessed from ', AccessCountry, ' (', AccessIP, ')',
    ' within ', TimeDeltaMin, ' min')
| project AuthTime, AccessTime, TimeDeltaMin, UPN,
          AuthIP, AuthCountry, AccessIP, AccessCountry,
          AppName, AccessApp, SessionId, DeviceCompliant, Severity, Alert
| order by TimeDeltaMin asc
```

#### False Positive Suppression

| FP Scenario | Risk | Suppression |
|------------|------|-------------|
| Corporate VPN with split tunnel — auth from office, access from VPN | Medium | Allowlist known corporate VPN egress IPs |
| Cloud CDN-fronted app changes IP between auth and access | Low | Scope to high-value apps (Exchange, SharePoint, Graph) |
| Legitimate travel — user on airplane wifi then hotel | Low | `TimeDeltaMin < 5` is near-impossible for legitimate travel; scope `Critical` tier tightly |
| Shared corporate NAT — multiple users same IP | Medium | Require `AccessCountry != AuthCountry` — country-level suppresses most NAT FPs |

### 2C — Google Workspace Login Event Schema for AiTM

Google Workspace exposes login events via the Admin SDK Reports API (`applicationName=login`). Google does **not** expose a session ID equivalent to Entra's `CorrelationId` that directly correlates victim auth to attacker replay — detection must rely on IP + timing correlation per user.

| Event Name | Field | AiTM Relevance |
|-----------|-------|----------------|
| `login_success` | `ipAddress`, `login_type`, `is_suspicious` | Victim auth via AiTM proxy IP |
| `login_failure` | `ipAddress`, `login_challenge_method` | Failed MFA replay attempts by attacker |
| `suspicious_login` | `ipAddress`, `is_suspicious=true` | Google's own AiTM heuristic — not always triggered |
| `logout` | `ipAddress` | Proxy session termination signal |
| `login_verification` | `login_challenge_method` | MFA method used — TOTP vs security_key vs push |

---

## GAP 3: Browser-Side Transparent Proxy Artifact Detection

### 3A — Detectable AiTM Artifacts Ranked by Reliability

| Signal | Mechanism | FP Risk | MV3 Feasible? |
|--------|-----------|---------|---------------|
| Cache-Control: no-cache on HTML/JS | Evilginx 3.2+ injects to prevent caching of rewritten content | Medium | Yes — `declarativeNetRequest` header observer |
| Missing/altered CSP vs. known-good baseline | Proxy strips CSP to prevent origin leakage | Medium (many sites have no CSP) | Yes — `declarativeNetRequest onHeadersReceived` |
| Referrer shows phishing domain on subresource loads | Victim loads some resources direct; referrer = phishing domain | Low | Yes — content script `performance.getEntries()` |
| Resource timing latency delta >2x | Every proxied resource makes extra network hop | Medium (slow networks) | Yes — `PerformanceResourceTiming` API |
| SRI hash mismatch on injected resources | Proxy injects JS; modified version fails existing hash check | Low | Yes — `SecurityPolicyViolationEvent` listener |
| Cookie flags altered (SameSite=None, missing HttpOnly) | Proxy must access cookies — may strip HttpOnly | Medium | Partial — JS can only read non-HttpOnly cookies |
| `document.location.hostname` != expected TLD for brand | Core AiTM signal — user is on attacker domain | Low | Yes — content script URL check against brand list |

### 3B — AiTMProxyDetector Module (PhishAgent Wave 4)

```javascript
// phishops/extension/content/aitm_proxy_detector.js
// Detects browser-observable AiTM reverse proxy artifacts
// Fires on high-value login domains: microsoft.com, google.com, okta.com, etc.

const MONITORED_BRANDS = [
  { hostname: /login\.microsoftonline\.com$/, name: 'Microsoft' },
  { hostname: /accounts\.google\.com$/,       name: 'Google' },
  { hostname: /.*\.okta\.com$/,               name: 'Okta' },
  { hostname: /login\.live\.com$/,            name: 'Microsoft Live' },
];

const signals = [];
let riskScore = 0;

// Signal 1: Document hostname mismatch vs. brand list (weight: 0.60)
// If the page LOOKS like a Microsoft login but hostname doesn't match,
// this is the foundational AiTM signal.
function checkDomainMismatch() {
  const currentHost = document.location.hostname;
  const pageTitle   = document.title.toLowerCase();
  const bodyText    = document.body?.innerText?.slice(0, 2000).toLowerCase() || '';

  for (const brand of MONITORED_BRANDS) {
    const isLegitHost   = brand.hostname.test(currentHost);
    const mentionsBrand = pageTitle.includes(brand.name.toLowerCase()) ||
                          bodyText.includes('sign in to ' + brand.name.toLowerCase());
    if (!isLegitHost && mentionsBrand) {
      signals.push({ type: 'DOMAIN_MISMATCH', brand: brand.name, host: currentHost });
      riskScore += 0.60;
    }
  }
}

// Signal 2: Resource timing — proxied resources take ~2x longer
// Baseline: 50–200ms direct. AiTM adds 100–400ms proxy hop.
function checkResourceLatency() {
  const entries   = performance.getEntriesByType('resource');
  if (entries.length < 3) return;
  const durations = entries.map(e => e.duration).filter(d => d > 0);
  const median    = durations.sort((a, b) => a - b)[Math.floor(durations.length / 2)];
  if (median > 800) {
    signals.push({ type: 'HIGH_RESOURCE_LATENCY', medianMs: Math.round(median) });
    riskScore += 0.15;
  }
}

// Signal 3: SRI violation listener (weight: 0.35)
// If a proxied resource fails an SRI check, the browser fires this event.
document.addEventListener('securitypolicyviolation', (e) => {
  if (e.violatedDirective.includes('script-src') ||
      e.violatedDirective.includes('require-sri')) {
    signals.push({ type: 'SRI_VIOLATION', blockedURI: e.blockedURI?.slice(0, 200) });
    riskScore += 0.35;
  }
});

// Signal 4: Referrer anomaly — referrer is a legit brand domain
// but current page is on a different (attacker) domain. (weight: 0.45)
function checkReferrerAnomaly() {
  if (!document.referrer) return;
  const refHost     = new URL(document.referrer).hostname;
  const currentHost = document.location.hostname;
  for (const brand of MONITORED_BRANDS) {
    if (brand.hostname.test(refHost) && !brand.hostname.test(currentHost)) {
      signals.push({ type: 'REFERRER_BRAND_MISMATCH', refHost, currentHost });
      riskScore += 0.45;
      break;
    }
  }
}

window.addEventListener('load', () => {
  checkDomainMismatch();
  checkResourceLatency();
  checkReferrerAnomaly();

  if (riskScore >= 0.55) {
    chrome.runtime.sendMessage({
      type:      'AITM_PROXY_ARTIFACT',
      riskScore: Math.min(riskScore, 1.0),
      signals,
      url:       document.location.href.slice(0, 300),
      hostname:  document.location.hostname
    });
  }
});
```

#### MV3 API Feasibility Notes

- **`declarativeNetRequest`**: Read-only header observation available in MV3 — can observe response headers but not modify. Sufficient for CSP/Cache-Control detection.
- **`webRequest` (MV3 limitation)**: Blocking mode restricted in MV3; header reading still possible via `chrome.declarativeNetRequest.getMatchedRules`.
- **`PerformanceResourceTiming`**: Available to content scripts without additional permissions.
- **`SecurityPolicyViolationEvent`**: Available to content scripts. No additional permissions required. Only fires if the page has SRI attributes on script tags — not universal, but high-signal when it does fire.

---

## GAP 4: Google Workspace Identity Log Schema for AiTM Detection

### 4A — Admin SDK Reports API Login Event Schema

| JSON Field | Type | AiTM Detection Use |
|-----------|------|-------------------|
| `actor.email` | string | User account targeted — correlation key |
| `ipAddress` | string | IP of entity performing the action — proxy IP during AiTM |
| `events[].name` | string | `login_success`, `login_failure`, `suspicious_login`, `logout` |
| `events[].parameters[].name=login_type` | string | `exchange`, `google_password`, `saml`, `totp` |
| `events[].parameters[].name=is_suspicious` | bool | Google's internal heuristic — not reliable alone |
| `events[].parameters[].name=login_challenge_method` | string | MFA method: `idv_preregistered_phone`, `security_key`, `totp`, `none_enrolled` |
| `id.time` | datetime | Event timestamp (RFC 3339) |
| `id.uniqueQualifier` | string | Unique event ID — **no session binding across events** |

### 4B — Google Workspace AiTM KQL (Sentinel)

```kql
// PhishOps — Google Workspace AiTM Session Detection
// Requires: Google Workspace Sentinel data connector (GWorkspace_ReportsAPI_login_CL)
// Detects: Two successful logins from geo-distinct IPs within 30 minutes

let lookback = 4h;

GWorkspace_ReportsAPI_login_CL
| where TimeGenerated > ago(lookback)
| where EventName_s == 'login_success'
| extend UserEmail    = ActorEmail_s,
         LoginIP      = IPAddress_s,
         LoginTime    = TimeGenerated,
         MFAMethod    = tostring(parse_json(Parameters_s)['login_challenge_method']),
         IsSuspicious = tobool(parse_json(Parameters_s)['is_suspicious'])
| extend LoginGeo = geo_info_from_ip_address(LoginIP)
| extend Country  = tostring(LoginGeo.country)
| join kind=inner (
    GWorkspace_ReportsAPI_login_CL
    | where TimeGenerated > ago(lookback)
    | where EventName_s == 'login_success'
    | extend UserEmail2  = ActorEmail_s,
             LoginIP2    = IPAddress_s,
             LoginTime2  = TimeGenerated,
             Country2    = tostring(geo_info_from_ip_address(IPAddress_s).country)
  ) on $left.UserEmail == $right.UserEmail2
| where LoginIP  != LoginIP2
| where Country  != Country2
| extend DeltaMin = datetime_diff('minute', LoginTime2, LoginTime)
| where DeltaMin between (0 .. 30)
| where LoginIP !startswith '10.' and LoginIP !startswith '192.168.'
| summarize
    EarliestEvent = min(LoginTime),
    DeltaMin      = min(DeltaMin),
    IP1           = take_any(LoginIP),      Country1 = take_any(Country),
    IP2           = take_any(LoginIP2),     Country2 = take_any(Country2),
    MFAUsed       = take_any(MFAMethod)
  by UserEmail
| extend Severity = iff(DeltaMin < 5, 'Critical', iff(DeltaMin < 15, 'High', 'Medium'))
| extend Alert = strcat('Google AiTM: ', UserEmail,
    ' logged in from ', Country1, ' then ', Country2,
    ' within ', DeltaMin, ' min')
| project EarliestEvent, DeltaMin, UserEmail, IP1, Country1,
          IP2, Country2, MFAUsed, Severity, Alert
| order by DeltaMin asc
```

### 4C — Sentinel Ingestion Architecture

| Component | Specification |
|-----------|--------------|
| Connector type | Microsoft Sentinel Content Hub: `Google Workspace (G Suite)` native connector |
| Authentication | Google Service Account with Admin SDK Reports API `readonly` scope |
| Polling frequency | 5-minute timer-triggered Azure Function |
| Target table | `GWorkspace_ReportsAPI_login_CL` in Log Analytics |
| Prerequisite permissions | `reports.audit.readonly` OAuth scope on Service Account |
| Cross-platform join | Join `GWorkspace_ReportsAPI_login_CL` with `BrowserPhishingTelemetry_CL` on `actor.email = UPN` |
| Latency | ~5–10 min from event to Sentinel ingestion |

> **Note:** Google Workspace login events and GCP audit logs are **distinct pipelines**. The Workspace connector is required specifically for `login_activity` events. The GCP Pub/Sub connector does not capture these.

---

## GAP 5: JA4 Fingerprint Integration — ProxyGuard + AiTM Traffic Guardian

### 5A — JA4 and Evilginx Pro

Evilginx Pro (commercial version) uses JA4 fingerprinting as a bot detection mechanism — it blocks requests whose JA4 fingerprints match known security scanners. This creates a **detection inversion opportunity**: defenders can identify Evilginx infrastructure by correlating the Go HTTP client fingerprint that Evilginx uses when making upstream proxy requests to Microsoft/Google.

> **Critical distinction:** JA4 detects the **client's** TLS fingerprint. In an AiTM scenario, the Evilginx server acts as a client when making upstream requests to the origin. The Go standard library has a distinct JA4 fingerprint observable at the origin server's TLS layer. For ProxyGuard (a proxy between victim and attacker), we observe the attacker's TLS client hello toward the origin.

| JA4 Component | Value for Go HTTP Client (Evilginx) | Notes |
|--------------|-------------------------------------|-------|
| Protocol | `t13` (TLS 1.3) | Go `net/http` defaults to TLS 1.3 |
| SNI | `d` (domain present) | Evilginx uses SNI for upstream proxying |
| JA4 database | `ja4db.com` (FoxIO) — open, free lookup | Query fingerprints against published DB |
| Evilginx evasion | `utls` library can spoof JA4 to mimic Chrome/Firefox | Commodity campaigns rarely implement this |

### 5B — ProxyGuard JA4 Integration

```python
# proxyguard/detectors/ja4_fingerprint.py
# Composite signal: Go HTTP client JA4 on a fresh domain serving a login page
# = potential Evilginx upstream proxy.
#
# pip install ja4 aiohttp

import asyncio
import aiohttp
from dataclasses import dataclass
from typing import Optional

# Known Go HTTP client JA4 fingerprints (Evilginx upstream behavior)
# Source: ja4db.com — query 'Go' application
# Note: Update as Go versions release
GO_HTTP_JA4_FINGERPRINTS = {
    't13d3112h2_e8f1e7e78f70_6bebaf5329ac',  # Go 1.21 net/http
    't13d3112h2_8daaf6152771_b0da82dd1658',  # Go 1.20 net/http
}

JA4DB_URL = 'https://ja4db.com/api/read/'

@dataclass
class JA4Detection:
    fingerprint:  str
    matched:      bool
    application:  Optional[str]
    risk_score:   float
    signals:      list

async def lookup_ja4(fingerprint: str) -> dict:
    """Query ja4db.com for fingerprint attribution."""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                f'{JA4DB_URL}{fingerprint}',
                timeout=aiohttp.ClientTimeout(total=3)
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
    return {}

def assess_ja4_risk(fingerprint: str, db_result: dict) -> JA4Detection:
    signals    = []
    risk_score = 0.0
    app        = db_result.get('application', '').lower()

    # Signal 1: Hardcoded Go fingerprint match
    if fingerprint in GO_HTTP_JA4_FINGERPRINTS:
        signals.append('go_http_client_fingerprint')
        risk_score += 0.40

    # Signal 2: DB identifies as Go (broader match)
    if 'go' in app or 'golang' in app:
        signals.append(f'ja4db_go_match:{app}')
        risk_score += 0.25

    # Signal 3: Unknown fingerprint not in DB
    if not db_result:
        signals.append('unknown_fingerprint_not_in_ja4db')
        risk_score += 0.20

    return JA4Detection(
        fingerprint=fingerprint,
        matched=risk_score > 0.30,
        application=app or 'unknown',
        risk_score=min(risk_score, 1.0),
        signals=signals
    )
```

### 5C — FP Risk Assessment

| FP Scenario | Risk | Mitigation |
|------------|------|------------|
| Legitimate Go applications (Terraform, k8s clients, internal tools) | High | Only flag Go JA4 on fresh domains (<30d) serving login-like content |
| Cloudflare-fronted Evilginx (Cloudflare terminates TLS, hides Go fingerprint) | N/A — detection fails | Fall back to URL structure and header IOCs |
| Commodity VPN clients with Go HTTP layer | Medium | Combine with domain age + Evilginx URL structure signal |
| JA4 database incomplete/stale | Medium | Maintain local supplement; re-query quarterly against lab-tested Evilginx versions |

> **Note:** JA4 alone has a high FP rate in enterprise. Use as a **composite signal** with domain age, URL structure, and `X-Evilginx` header IOCs — not as a primary trigger.

---

## Synthesis: Module Integration Map

| Gap Closed | Module | Detection Trigger | Sentinel Table | Priority |
|-----------|--------|------------------|----------------|----------|
| Evilginx3 X-Evilginx header | KitRadar (new YARA rule) | YARA match on HTTP response | `PhishKitFingerprint_CL` | High — add to existing YARA pipeline |
| 8-char alpha URI + fresh domain | ProxyGuard (new IOK rule) | URL structure + WHOIS age | `ProxyPhishingEvents_CL` | High |
| Cache-Control: no-cache on HTML | ProxyGuard (new detector) | HTTP response header scan | `ProxyPhishingEvents_CL` | Medium |
| Entra ID session bifurcation | Sentinel KQL (new analytics rule) | SigninLogs join on SessionId | `SigninLogs` (native) | **Critical** — add as scheduled rule |
| Google Workspace login geo-anomaly | Sentinel KQL (new analytics rule) | `GWorkspace_ReportsAPI_login_CL` | `GWorkspace_ReportsAPI_login_CL` | High — requires connector setup |
| Browser-side proxy artifacts | PhishAgent (new AiTMProxyDetector) | DOM + timing + referrer | `BrowserPhishingTelemetry_CL` | High — new Wave 4 module |
| JA4 Go client fingerprint | ProxyGuard (composite signal) | TLS fingerprint + ja4db.com | `ProxyPhishingEvents_CL` | Medium — composite only |

### Implementation Sequence

- **Week 1–2:** Add YARA rules (Gap 1) to KitRadar — lowest effort, highest signal for unmodified deployments
- **Week 1–2:** Add Entra ID session bifurcation KQL as Sentinel scheduled analytics rule (Gap 2) — no new infrastructure required
- **Week 3–4:** Set up Google Workspace Sentinel connector + deploy GWorkspace KQL analytics rule (Gaps 2+4)
- **Week 5–6:** Add IOK rules and Cache-Control detector to ProxyGuard (Gap 1 extension + partial Gap 5)
- **Week 7–10:** Build `AiTMProxyDetector` content script as Wave 4 module (Gap 3) — highest development effort, highest pre-interaction detection value
- **Week 11–12:** Integrate JA4 composite signal into ProxyGuard as secondary risk amplifier (Gap 5)

### Coverage Gaps That Remain

- **Cloudflare-fronted Evilginx:** TLS fingerprint hidden; URL structure often randomized. DNS-based detection (passive DNS monitoring for Evilginx phishlet subdomain patterns) is the most viable remaining approach.
- **Mamba 2FA and Tycoon 2FA:** These PhaaS kits use custom proxy infrastructure, not Evilginx. KitRadar's existing rules cover these partially; full coverage requires dedicated research per kit version.
- **Real-time session revocation:** Detection without automated token revocation is alerting, not prevention. Integrating Entra ID token revocation (`Revoke-AzureADUserAllRefreshToken`) into Sentinel playbooks (Logic App) closes the response gap.

---

*PhishOps Detection Portfolio · AiTM Gap Research Report · March 2026 · TLP:WHITE*
