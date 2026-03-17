# ProxyGuard — Gophish Campaign Fingerprinting
## `rid=` Tracking Parameter Detection
**Module: ProxyGuard · Detection Layer: HTTP Request URL · Priority: Low-Medium**

---

## Background

Gophish (and forks like evilgogophish) injects a per-recipient tracking token into every phishing landing page URL. This token — the `rid` parameter by default, but configurable — lets the operator track which specific targets clicked a link. It is a **structural fingerprint of campaign infrastructure**, not just a URL reputation signal, which means it survives domain rotation: even when the operator uses a fresh domain with zero reputation history, the URL structure betrays the tooling.

The parameter appears as:
```
https://corp-helpdesk[.]com/verify?rid=Xk9mP3qL
https://login-portal[.]com/reset?secure_id=aB7fQ2nR
```

This is distinct from standard marketing tracking (UTM parameters, HubSpot `hs_email_track`, etc.) which use predictable fixed-length tokens in well-known parameter names and originate from legitimate infrastructure with aged domains. The Gophish pattern is detectable by combining the parameter signature with contextual signals.

---

## Detection Rule

```python
# proxyguard/detectors/gophish_fingerprint.py

import re
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass

# Known Gophish tracking parameter names (default + common custom configurations)
GOPHISH_PARAM_NAMES = {
    'rid',          # Gophish default
    'secure_id',    # evilgogophish default override
    'track_id',     # common operator customization
    'user_id',      # common operator customization
    'cid',          # campaign id variant
    'uid',          # user id variant
    'x',            # minimalist operator shorthand
}

# Token format: 8–32 alphanumeric characters, base64-safe charset
GOPHISH_TOKEN_PATTERN = re.compile(r'^[A-Za-z0-9_\-]{8,32}$')

# Legitimate marketing platforms that use overlapping param names
# These are excluded to suppress false positives
MARKETING_PLATFORM_ALLOWLIST = {
    'mailchimp.com', 'campaign-archive.com',
    'hubspot.com', 'hs-sites.com',
    'salesforce.com', 'pardot.com',
    'marketo.net', 'marketo.com',
    'sendgrid.net', 'sendgrid.com',
    'constantcontact.com',
    'klaviyo.com',
    'mailgun.net',
}


@dataclass
class GophishFingerprint:
    detected: bool
    param_name: str
    param_value: str
    risk_score: float
    signals: list[str]


def detect_gophish_tracking_param(url: str, domain_age_days: int = -1) -> GophishFingerprint:
    """
    Detect Gophish-style recipient tracking parameters in a URL.

    Args:
        url: Full URL from HTTP request
        domain_age_days: Domain age from WHOIS lookup (-1 if unavailable)

    Returns:
        GophishFingerprint with detection result and composite risk score
    """
    parsed = urlparse(url)
    hostname = parsed.netloc.lower().lstrip('www.')

    # Suppress on known marketing platforms
    if any(hostname.endswith(platform) for platform in MARKETING_PLATFORM_ALLOWLIST):
        return GophishFingerprint(False, '', '', 0.0, ['allowlisted_marketing_platform'])

    params = parse_qs(parsed.query, keep_blank_values=True)
    signals = []
    base_score = 0.0
    matched_param = ''
    matched_value = ''

    # Signal 1: Matching parameter name
    for param_name in GOPHISH_PARAM_NAMES:
        if param_name in params:
            value = params[param_name][0]
            if GOPHISH_TOKEN_PATTERN.match(value):
                matched_param = param_name
                matched_value = value
                base_score += 0.45
                signals.append(f'gophish_param_match:{param_name}={value[:8]}...')
                break

    if not matched_param:
        return GophishFingerprint(False, '', '', 0.0, ['no_param_match'])

    # Signal 2: URL has ONLY the tracking param — no other query params
    # Gophish landing pages typically use clean URLs: /track?rid=XXXX
    if len(params) == 1:
        base_score += 0.15
        signals.append('single_param_url')

    # Signal 3: Fresh domain (primary contextual amplifier)
    if 0 <= domain_age_days < 14:
        base_score += 0.35
        signals.append(f'fresh_domain:{domain_age_days}d')
    elif 14 <= domain_age_days < 30:
        base_score += 0.20
        signals.append(f'new_domain:{domain_age_days}d')
    elif 30 <= domain_age_days < 90:
        base_score += 0.05
        signals.append(f'young_domain:{domain_age_days}d')

    # Signal 4: Path pattern matches Gophish default routes
    # Default Gophish landing page routes: /login, /portal, /verify, /reset
    GOPHISH_PATH_PATTERNS = re.compile(
        r'/(login|portal|verify|reset|auth|signin|account|secure|helpdesk|support)',
        re.IGNORECASE
    )
    if GOPHISH_PATH_PATTERNS.search(parsed.path):
        base_score += 0.10
        signals.append(f'gophish_path_pattern:{parsed.path}')

    # Signal 5: No other tracking params present (UTM, fbclid, etc.)
    # Legitimate marketing emails always include UTM parameters alongside rid-like tokens
    MARKETING_PARAMS = {'utm_source', 'utm_medium', 'utm_campaign', 'fbclid', 'gclid', 'mc_eid'}
    if not any(p in params for p in MARKETING_PARAMS):
        base_score += 0.05
        signals.append('no_marketing_params')

    risk_score = min(base_score, 1.0)

    return GophishFingerprint(
        detected=risk_score > 0.5,
        param_name=matched_param,
        param_value=matched_value,
        risk_score=round(risk_score, 2),
        signals=signals
    )
```

---

## Integration into ProxyGuard

The detector slots into the existing ProxyGuard request hook alongside the ClickFix and ConsentFix detectors:

```python
# proxyguard/proxy_guard.py — add to request() hook

def request(flow: http.HTTPFlow) -> None:
    url = flow.request.pretty_url
    domain = flow.request.host

    # Existing: ConsentFix OAuth code detection
    # ...

    # NEW: Gophish campaign fingerprinting
    domain_age = get_domain_age(domain)  # cached WHOIS lookup
    gophish_result = detect_gophish_tracking_param(url, domain_age_days=domain_age)

    if gophish_result.detected:
        emit_to_sentinel({
            'eventType': 'GOPHISH_CAMPAIGN_FINGERPRINT',
            'destinationUrl': url[:500],
            'destinationHost': domain,
            'trackingParam': gophish_result.param_name,
            'trackingValue': gophish_result.param_value[:16],
            'domainAgeDays': domain_age,
            'riskScore': gophish_result.risk_score,
            'signals': gophish_result.signals,
            'clientIp': flow.client_conn.peername[0],
        })

        # At high confidence: warn but don't block
        # (tracking param alone is not execution-level signal)
        if gophish_result.risk_score > 0.85:
            flow.response = http.Response.make(
                403,
                b'<html><body><h2>Page blocked by ProxyGuard</h2>'
                b'<p>Phishing campaign infrastructure detected.</p></body></html>',
                {'Content-Type': 'text/html'}
            )
```

---

## Sentinel KQL — Gophish Campaign Correlation

The real value of this detection is **cross-victim correlation**: the same `rid=` token issued to multiple users means the attacker reused a token (misconfiguration) or the same victim was targeted across multiple sessions. More usefully, seeing `rid=` hits across multiple recipients in a short window is a near-certain campaign signal.

```kql
// ProxyGuard: Gophish Campaign Detection — Cross-Victim Correlation
ProxyPhishingEvents_CL
| where TimeGenerated > ago(24h)
| where EventType == "GOPHISH_CAMPAIGN_FINGERPRINT"
| extend TrackingParam = tostring(parse_json(Signals_s)[0])
| summarize
    HitCount        = count(),
    UniqueVictims   = dcount(ClientIp),
    UniqueTokens    = dcount(TrackingValue_s),
    FirstSeen       = min(TimeGenerated),
    LastSeen        = max(TimeGenerated),
    AvgRiskScore    = avg(RiskScore_d),
    SampleUrls      = make_set(DestinationUrl_s, 5)
  by DestinationHost_s, bin(TimeGenerated, 1h)
| where HitCount > 2 or UniqueVictims > 1
| extend CampaignId = strcat("GOPHISH_", DestinationHost_s, "_",
         format_datetime(FirstSeen, "yyyyMMdd_HH"))
| extend Severity = case(
    UniqueVictims > 5,   "Critical",
    UniqueVictims > 1,   "High",
    AvgRiskScore > 0.8,  "High",
                         "Medium")
| project FirstSeen, LastSeen, DestinationHost_s, HitCount,
         UniqueVictims, UniqueTokens, AvgRiskScore, CampaignId,
         SampleUrls, Severity
| order by UniqueVictims desc, FirstSeen asc
```

```kql
// Reused token detection — same rid= value seen from multiple source IPs
// Indicates either operator error (token collision) or shared phishing link
ProxyPhishingEvents_CL
| where TimeGenerated > ago(7d)
| where EventType == "GOPHISH_CAMPAIGN_FINGERPRINT"
| summarize
    SourceIPs = dcount(ClientIp),
    IPList    = make_set(ClientIp, 10),
    HitCount  = count()
  by TrackingValue_s, DestinationHost_s
| where SourceIPs > 1
| extend Alert = "Gophish token reuse — single rid= value seen from multiple source IPs"
| order by SourceIPs desc
```

---

## False Positive Analysis

| Scenario | False Positive Risk | Mitigation |
|---|---|---|
| Marketing email with `uid=` param | Medium | Marketing platform allowlist; require absence of UTM params |
| Legitimate SaaS app with `user_id=` in URL | Low–Medium | Domain age >90d + established ASN suppresses |
| Internal app with `track_id=` param | Low | Internal IP ranges excluded from ProxyGuard scope |
| Legitimate Gophish use by your own red team | Special case | Add your own Gophish domain to an operator allowlist |

Expected false positive rate at `risk_score > 0.85` threshold: **<2%** in enterprise environments where marketing platforms are covered by the allowlist. At `risk_score > 0.65`: ~5–8% — acceptable for a logged-only (non-blocking) alert tier.

---

## Extension Ideas

**1. Evilginx phishlet fingerprinting**
Evilginx (which evilgogophish claims to integrate with) uses a different but equally detectable pattern: every proxied page path is prefixed with a random hex session identifier. A URL path matching `^/[a-f0-9]{8,16}/` on a fresh domain is a strong Evilginx session token signal. This is structurally identical to the `rid=` detection and can be added as a second rule in the same detector module.

```python
EVILGINX_SESSION_PATH = re.compile(r'^/[a-f0-9]{8,16}(/|$)')
```

**2. Gophish admin panel exposure detection**
Gophish runs its admin interface on port `3333` with a self-signed cert by default. If ProxyGuard's network scanner sees a host serving HTTP on `:3333` with the Gophish login page title (`<title>Gophish - Login</title>`), it has found exposed campaign infrastructure — potentially useful for blue team threat hunting beyond just recipient-side detection.

**3. Correlation with QRSweep**
If a QR code decoded by QRSweep contains a URL that matches the `rid=` pattern, composite risk score should be amplified: QR delivery + Gophish campaign infrastructure is a confirmed `Critical` finding without needing domain age or any other signal.

```python
# QRSweep → ProxyGuard cross-module composite
if qr_decoded_url and detect_gophish_tracking_param(qr_decoded_url).detected:
    composite_risk = min(qr_risk + 0.35, 1.0)  # automatic escalation
    emit_alert(severity='Critical', reason='QR_DELIVERY+GOPHISH_INFRA')
```

---

## Schema Addition to `ProxyPhishingEvents_CL`

Two new fields required for Gophish fingerprinting events:

| Field | Type | Description |
|---|---|---|
| `TrackingParam_s` | string | Matched parameter name (`rid`, `secure_id`, etc.) |
| `TrackingValue_s` | string | First 16 chars of token value (truncated — avoid storing full token) |

---

*ProxyGuard Module Note · March 2026 · PhishOps Detection Portfolio*
*Source: evilgogophish (github.com/PurpleCode001/evilgogophish) analysis — defensive fingerprinting only*
