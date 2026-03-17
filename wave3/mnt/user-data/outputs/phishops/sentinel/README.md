# PhishOps Detection Portfolio — Sentinel Query Library

**Microsoft Sentinel KQL · Custom Analytics Rules · Workbook Queries**
**Last Updated: March 2026 · Wave 2 complete**

All queries target custom Sentinel tables populated by PhishOps modules.
Queries are validated against their respective table schemas before publication.

---

## Custom Tables

| Table | Populated By | Description |
|---|---|---|
| `ProxyPhishingEvents_CL` | ProxyGuard (Python/mitmproxy) | HTTP request/response layer detections |
| `BrowserPhishingTelemetry_CL` | PhishOps Chrome Extension | Browser DOM + API layer detections |

---

## Query Index

### ProxyGuard Queries (`queries/proxyguard/`)

| File | EventType | Severity | Description |
|---|---|---|---|
| `proxyguard_gophish.kql` | `GOPHISH_CAMPAIGN_FINGERPRINT` | Medium–High | Cross-victim Gophish `rid=` campaign correlation; token reuse detection |

### OAuthGuard Queries (`queries/oauthguard/`)

| File | EventType | Severity | Description |
|---|---|---|---|
| `state_parameter_abuse.kql` | `OAUTH_STATE_EMAIL_ENCODED` | High–Critical | OAuth `state=` parameter email encoding; joins with `SigninLogs` for identity correlation |

### AiTM / Post-Compromise Queries (`queries/`)

| File | Source Table | Severity | Description |
|---|---|---|---|
| `aitmpostcompromise_impossible_geography.kql` | `SigninLogs` | High–Critical | Starkiller-class AiTM session hijack via impossible-travel detection; ProxyGuard and BrowserPhishingTelemetry cross-module companion queries included |

---

## Scheduled Analytics Rules

### `aitmpostcompromise_impossible_geography.kql`

**Rule name:** PhishOps — AiTM Impossible Geography (Starkiller)
**Severity:** High (Critical when `TimeDeltaMinutes < 5`)
**Run frequency:** Every 30 minutes
**Lookback:** 2 hours
**Alert threshold:** 1+ result
**Suppression:** 1 hour per `UserPrincipalName`

**Threat context:**
Starkiller is a Docker-containerised headless Chrome reverse proxy PhaaS operated by the
Jinkusu group (Abnormal AI, February 25, 2026). The platform proxies the real Microsoft/Google/
Apple login page live — eliminating all static DOM fingerprints that KitRadar targets.
Because the attacker's session cookie reuse occurs from a geographically different location
than the victim's authentication, impossible-travel detection in `SigninLogs` is the primary
reliable signal for Starkiller-class kits.

**Tuning guidance:**
- Default threshold: `TimeDeltaMinutes < 30`
- Tighten to `< 10` after validating against your tenant's baseline travel distribution
- Add your corporate VPN IP ranges to a suppression watchlist to reduce false positives
  from split-tunnel VPN reconnects showing two locations
- Run a 7-day dry run against historical `SigninLogs` before enabling as a live alert rule

**Attribution:**
Jinkusu operator group · Starkiller PhaaS v6.2.4 · Source: Abnormal AI (Callie Baron,
Piotr Wojtyla), February 25, 2026 · Covered by: Krebs on Security, Dark Reading,
Infosecurity Magazine, The Hacker News, SC Media

---

## False Positive Guidance

| Query | Known FP Source | Mitigation |
|---|---|---|
| `state_parameter_abuse.kql` | MSAL `state` tokens containing base64 JSON (not emails) | Detector's `looksLikeEmail()` check filters these — JSON strings don't match email regex |
| `aitmpostcompromise_impossible_geography.kql` | Corporate VPN reconnects, split tunneling | Add corporate IP CIDR ranges to a watchlist; filter on `not(IPAddress in (watchlist))` |
| `aitmpostcompromise_impossible_geography.kql` | Legitimate international travel | Raise `TimeDeltaMinutes` threshold; suppress on known traveller accounts |
| `proxyguard_gophish.kql` | Marketing platforms using `uid=` parameter | Marketing platform allowlist in `gophish_fingerprint.py` handles this at source |

---

## Wave Completion Status

| Wave | Plans | Status |
|---|---|---|
| Wave 1 | A (ProxyGuard: html_smuggling + url_masking), B (OAuthGuard: state parameter abuse) | ✅ Complete |
| Wave 2 | C (DataEgressMonitor: blob credential detector), D (Starkiller impossible geography KQL) | ✅ Complete |
| Wave 3 | E (ExtensionAuditor: DNR header stripping), F (Ownership drift + C2 polling), G (AgentIntentGuard blabbering) | ✅ Complete |
| KitRadar docs | DETECTION_BOUNDARIES.md (Starkiller out-of-scope), Tycoon 2FA takedown note | ✅ Complete |

---

*PhishOps Detection Portfolio · Sentinel Query Library · March 2026 · TLP:WHITE*
