# PhishOps — 2026 Threat Research Update (March 13, 2026)
## New Findings: Starkiller PhaaS & QuickLens CSP-Strip Supply Chain
**Sources: Abnormal AI (Feb 25, 2026), BleepingComputer / Annex Security (Feb–Mar 2026), The Hacker News, Krebs on Security, SC Media, Infosecurity Magazine**

---

## Summary

Two confirmed, in-the-wild findings from the last three weeks are net-new to the PhishOps scope in meaningful ways. Both have clear browser-layer detection hooks that existing modules either miss entirely or only partially cover.

| Finding | Date | Novelty | Affected Module |
|---|---|---|---|
| **Starkiller** — headless Chrome reverse proxy PhaaS; proxies real login pages live, no static templates | Feb 25, 2026 (Abnormal AI) | KitRadar's fingerprinting model assumes static page templates — Starkiller has none | KitRadar, ProxyGuard |
| **QuickLens CSP-strip supply chain** — compromised extension used `declarativeNetRequest` rules to strip CSP/X-Frame-Options from all pages sitewide | Feb 17–Mar 2026 (Annex/BleepingComputer) | New attack primitive — security header stripping via `rules.json` — not in ExtensionAuditor's detection model | ExtensionAuditor |

The previously documented HTML smuggling, OAuth state parameter abuse, and Agentic Blabbering findings from the March 12 update are not duplicated here. This document covers only what is new relative to that prior research.

---

## Finding 1 — Starkiller: Headless Chrome Reverse Proxy PhaaS

### Source & Timeline
- **Abnormal AI** (Callie Baron, Piotr Wojtyla): blog post February 25, 2026
- Covered by Krebs on Security, Dark Reading, Infosecurity Magazine, The Hacker News, SC Media — same week
- Operator group: **Jinkusu** — sold as a subscription SaaS with Telegram support, monthly updates, a user community forum, and **two-factor authentication on the attacker's own dashboard** (version 6.2.4 at time of disclosure)

### What It Is

Most PhaaS kits — including Tycoon 2FA and Mamba 2FA, which KitRadar already fingerprints — work by serving static HTML clones of login pages. Starkiller is architecturally different. When an attacker selects a target brand, the platform spins up a Docker container running a headless Chrome instance that loads the **real** brand website live. That container then acts as a reverse proxy, forwarding the victim's inputs to the legitimate site and returning the site's responses. The victim is authenticating against the real Microsoft/Google/Apple login portal — just through attacker-controlled infrastructure.

Because the victim is interacting with the actual website via proxy, MFA tokens submitted in real time are captured and forwarded simultaneously. The attacker harvests the resulting session cookies and gains authenticated access without needing to re-prompt for credentials. The entire authentication flow completes as designed — from the victim's perspective it was a successful login.

**Why KitRadar can't fingerprint it:** KitRadar's fingerprinting model operates by detecting structural patterns in phishing page HTML — Evilginx session path prefixes, Tycoon's iframe injection pattern, Mamba's React bundle signature, etc. Starkiller dynamically generates page content for each session by proxying the real site live. There are no template files, no static HTML, and no consistent DOM fingerprint to match. The kit explicitly renders a perfect clone by definition, because it *is* the original page.

### New PhaaS Pattern It Represents

Starkiller is not an isolated product — it is the first widely-documented example of a new PhaaS class: **session-aware adversary-in-the-middle (AiTM) delivered via Docker-containerised headless browser**. Unlike Evilginx (which also uses a reverse proxy but requires manual configuration), Starkiller eliminates all technical skill requirements. A low-skill operator pastes a brand URL into a dashboard and receives a working, real-time credential-harvesting session with:
- Live screen monitoring of victim sessions
- Keystroke capture
- Cookie and session token exfiltration
- Geo-tracking and Telegram alerts on new credentials
- Campaign analytics (visit counts, conversion rates)

The platform also includes a **URL masker** that exploits `user@domain` URL parsing — browsers display `microsoft.com@attacker.com` with `microsoft.com` prominently — plus URL shorteners. This is a documented gap in all current browsers including Chrome, Edge, Brave, Firefox, and Mullvad (confirmed on Windows 11 as of Feb 19, 2026).

### What PhishOps Can Detect

Starkiller eliminates the page-fingerprint attack surface. Detection must shift to **behavioural and infrastructure signals** observable outside the page content:

**Signal 1 — URL `@` symbol abuse (ProxyGuard)**
The `user@domain` masking trick is detectable in the URL itself before any page content is evaluated. The `@` symbol appearing before the TLD in a link that arrived from email/QR/Teams is a high-confidence Starkiller delivery indicator. This is not currently in ProxyGuard's URL parsing rules.

```python
# ProxyGuard: user@domain URL masking detection
# Starkiller's primary URL obfuscation technique
AT_SYMBOL_MASKING = re.compile(
    r'https?://[^@\s]+@[^/\s]+',  # anything@actualdomain.com
    re.IGNORECASE
)

def detect_userinfo_masking(url: str) -> dict | None:
    if AT_SYMBOL_MASKING.match(url):
        # Extract what's displayed (before @) vs actual destination (after @)
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            return {
                'type': 'URL_USERINFO_MASKING',
                'displayed_as': f"{parsed.username or ''}@...",
                'actual_host': parsed.hostname,
                'risk_score': 0.90,
                'technique': 'Starkiller_URL_Masker / userinfo_@_trick'
            }
    return None
```

**Signal 2 — Headless Chrome TLS fingerprint divergence (ProxyGuard)**
When Starkiller's Docker-containerised headless Chrome acts as the proxy, the TLS client hello from the attacker's reverse proxy to the legitimate site has a specific fingerprint. More practically: the victim's browser connects to the attacker's domain, but the TLS certificate they see is issued for the **attacker's domain**, not `microsoft.com` or `google.com`. This means the certificate hostname does not match the brand being impersonated. This is a ProxyGuard signal already in scope — flag when a page visually presents as a major brand (PhishVision) but the TLS certificate CN differs from that brand's known domains.

**Signal 3 — Session token reuse from impossible geography (Sentinel KQL)**
Post-compromise, Starkiller attackers immediately reuse the harvested session token. A session authenticated from Location A and then used from a geographically distant Location B within minutes is a known AiTM signal. This is a Sentinel-layer detection, not browser-layer, but it directly catches Starkiller post-compromise:

```kql
// Sentinel: Session token reuse from impossible geography (Starkiller AiTM post-compromise)
SigninLogs
| where TimeGenerated > ago(2h)
| where ResultType == "0"  // successful sign-in
| summarize
    Locations   = make_set(Location, 5),
    IPs         = make_set(IPAddress, 5),
    SessionIds  = make_set(SessionId, 5),
    EventCount  = count(),
    FirstSeen   = min(TimeGenerated),
    LastSeen    = max(TimeGenerated)
  by UserPrincipalName, AppDisplayName
| where array_length(Locations) > 1
| extend TimeDeltaMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where TimeDeltaMinutes < 30 and array_length(Locations) > 1
| extend Alert = strcat(
    "Impossible travel post-auth: ",
    UserPrincipalName,
    " authenticated from ",
    tostring(array_length(Locations)),
    " locations in ",
    tostring(TimeDeltaMinutes),
    " minutes. Likely Starkiller AiTM session hijack."
  )
| project FirstSeen, LastSeen, UserPrincipalName, AppDisplayName,
         Locations, IPs, TimeDeltaMinutes, Alert
| order by TimeDeltaMinutes asc
```

**Signal 4 — Docker container infrastructure fingerprint (TPA Sentinel / threat intel)**
Starkiller's Docker containers have network-observable characteristics during setup: they pull public Docker images, establish outbound headless Chrome connections to brand login endpoints, and expose a control panel port. Passive DNS and certificate transparency logs will show attacker infrastructure patterns over time. The PhishOps threat intel pipeline should ingest Abnormal AI's Jinkusu IOC feed when published.

### What PhishOps Cannot Detect
The core page-content attack surface is gone for Starkiller-class kits. KitRadar's DOM fingerprinting and template matching produce zero signal. This is the expected outcome — the architecture was specifically designed to eliminate this. The detection model for this class of kit is entirely infrastructure and post-compromise behavioural, not page-content based. This is worth stating explicitly in KitRadar documentation as a documented detection boundary.

### Module Assignment
- **ProxyGuard**: Add `@`-symbol URL masking rule (P1, single rule)
- **KitRadar**: Document Starkiller as out-of-scope for page fingerprinting; note detection boundary
- **Sentinel KQL**: Add impossible-geography session token reuse query (P2)

---

## Finding 2 — QuickLens: CSP/Security Header Stripping via `declarativeNetRequest`

### Source & Timeline
- **Annex Security** (John Tuckner): initial disclosure February 2026
- **BleepingComputer**: detailed technical write-up, March 2026
- **The Hacker News**, SC Media, Cybernews, TechRepublic: same week
- Event: QuickLens v5.8 pushed February 17, 2026 to ~7,000 users after ownership transfer to `support@doodlebuggle.top` (LLC Quick Lens); removed by Google following public disclosure

### What It Is

The QuickLens attack is a supply chain compromise following ownership transfer — the same class as Cyberhaven (Dec 2024). What makes it structurally new is the specific attack primitive introduced in v5.8:

**The extension used `declarativeNetRequest` with a `rules.json` file to strip security headers — CSP, X-Frame-Options, and X-XSS-Protection — from every HTTP response across all visited pages.**

Prior documented supply chain attacks (Cyberhaven, Lumma GitHub) injected scripts to harvest credentials from specific target domains. QuickLens did something categorically different: it neutralised the browser's built-in script execution defences globally, then delivered subsequent malicious payloads at runtime from a C2 (`api.extensionanalyticspro[.]top`), polling every five minutes. The actual malicious code never existed in the packaged extension source — it was fetched dynamically and stored in localStorage, executed via a hidden 1×1 `<img>` element's `onload` handler.

This is a two-layer attack:
1. **Layer 1 (Extension):** Strip CSP and X-Frame-Options from all pages → disable browser-enforced script injection protections sitewide
2. **Layer 2 (C2):** Deliver arbitrary JavaScript to execute in the now-unprotected browsing context

The full payload capability included: credential harvesting from form fields, cryptocurrency wallet seed phrase extraction (MetaMask, Phantom, Solflare, Coinbase Wallet, Trust Wallet, Backpack, Exodus, Brave Wallet, Binance Chain, WalletConnect, Argon), Gmail inbox scraping, Facebook Business Manager data exfiltration, YouTube channel enumeration, and a ClickFix lure (fake Google Update prompt → PowerShell execution).

### Why This Is New to ExtensionAuditor

ExtensionAuditor's existing detection model monitors:
- Manifest key spoofing (CometJacking)
- New domain injection targets on `chrome.management.onInstalled`
- Permission escalation on extension update

It does **not** monitor for `declarativeNetRequest` rules that modify or remove security response headers. This is a new primitive. The `declarativeNetRequest` API was introduced specifically to replace `webRequest` for blocking/modifying network requests in MV3 extensions — it is the *intended* mechanism for content filtering. The difference between a legitimate adblocker using `declarativeNetRequest` and QuickLens using it to strip CSP is entirely in the rule content, not the permission request.

**New detection required:** Inspect `declarativeNetRequest` `rules.json` changes at install/update time for rules that `removeHeaders` on security-relevant response headers.

### New Detection Rule for ExtensionAuditor

```javascript
// ExtensionAuditor — declarativeNetRequest security header stripping detector
// Fires on extension install or update

const SECURITY_RESPONSE_HEADERS = new Set([
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-xss-protection',
  'x-content-type-options',
  'strict-transport-security',
  'permissions-policy',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
]);

async function auditDeclarativeNetRequestRules(extensionId) {
  let rulesJson;
  try {
    // Fetch rules.json from the installed extension's resources
    const rulesUrl = chrome.runtime.getURL
      ? `chrome-extension://${extensionId}/rules.json`
      : null;
    if (!rulesUrl) return null;

    const response = await fetch(rulesUrl);
    rulesJson = await response.json();
  } catch {
    return null; // Extension has no declarativeNetRequest rules
  }

  const violations = [];

  for (const rule of rulesJson) {
    // Look for modifyHeaders action on response headers
    const responseHeaders = rule?.action?.responseHeaders || [];
    for (const headerMod of responseHeaders) {
      const headerName = (headerMod.header || '').toLowerCase();
      const operation = (headerMod.operation || '').toLowerCase();

      if (SECURITY_RESPONSE_HEADERS.has(headerName) &&
          (operation === 'remove' || operation === 'set')) {
        violations.push({
          ruleId: rule.id,
          header: headerName,
          operation: operation,
          newValue: headerMod.value || null,
          conditionUrlFilter: rule.condition?.urlFilter || '*',
          conditionDomains: rule.condition?.requestDomains || ['ALL'],
        });
      }
    }
  }

  if (violations.length > 0) {
    const riskScore = violations.some(v =>
      v.header === 'content-security-policy' && v.conditionDomains.length === 0
    ) ? 0.95 : 0.80;

    emitAlert({
      type: 'EXTENSION_SECURITY_HEADER_STRIP',
      extensionId,
      violationCount: violations.length,
      violations: violations.slice(0, 5), // cap payload size
      riskScore,
      severity: riskScore > 0.90 ? 'Critical' : 'High',
      description:
        `Extension uses declarativeNetRequest to remove security headers: ` +
        violations.map(v => v.header).join(', ')
    });
  }

  return violations;
}

// Hook into extension install/update events
chrome.management.onInstalled.addListener(async (info) => {
  // Existing ExtensionAuditor checks here...
  await auditDeclarativeNetRequestRules(info.id);
});
```

**Additional signal — C2 polling pattern detection:**
QuickLens's C2 communication had a specific pattern: `api.extensionanalyticspro[.]top/extensions/callback?uuid=[uuid]&extension=[extensionId]`. The naming convention (`extensionanalytics`, `extensionpro`, `extensiontracker`) is designed to look like telemetry. ExtensionAuditor should flag background `fetch()` calls from extensions to domains registered within the last 30 days where the URL path contains `extension` or `uuid` query parameters:

```javascript
// ExtensionAuditor — Extension C2 polling fingerprint
// Monitors background service worker outbound fetch() calls

const EXTENSION_C2_PATTERNS = [
  /\/extensions?\/(callback|collect|ping|check|report)\?/i,
  /[?&](uuid|ext_id|extension|install_id)=[a-f0-9\-]{8,}/i,
  /extensionanalytics|extensionpro|exttrack|exttelemetry/i,
];

function isExtensionC2Candidate(url) {
  return EXTENSION_C2_PATTERNS.some(p => p.test(url));
}
```

### ExtensionHub Marketplace as a Risk Signal

QuickLens was listed for sale on **ExtensionHub** just two days after its initial publication, and again with a `Featured` badge. This marketplace — where developers sell extensions complete with existing users and reviews — is now a documented acquisition channel for supply chain attackers. ExtensionAuditor should track when an installed extension's Chrome Web Store developer contact changes (observable via the `chrome.management.get()` API's `homepageUrl` and `updateUrl` fields), and flag extensions whose developer email domain changes to a newly-registered domain:

```javascript
// ExtensionAuditor — Developer contact change detector
// Tracks ownership transfer signals

const extensionOwnershipBaseline = {}; // persisted to storage

async function checkOwnershipDrift(extensionId) {
  const info = await chrome.management.get(extensionId);
  const baseline = extensionOwnershipBaseline[extensionId];

  if (!baseline) {
    extensionOwnershipBaseline[extensionId] = {
      homepageUrl: info.homepageUrl,
      updateUrl: info.updateUrl,
      version: info.version,
    };
    return;
  }

  const homepageChanged = info.homepageUrl !== baseline.homepageUrl;
  const updateUrlChanged = info.updateUrl !== baseline.updateUrl;

  if (homepageChanged || updateUrlChanged) {
    emitAlert({
      type: 'EXTENSION_DEVELOPER_CONTACT_CHANGED',
      extensionId,
      extensionName: info.name,
      previousHomepage: baseline.homepageUrl,
      newHomepage: info.homepageUrl,
      previousUpdateUrl: baseline.updateUrl,
      newUpdateUrl: info.updateUrl,
      severity: 'High',
      description: 'Extension developer contact or update URL changed since baseline — ' +
                   'possible ownership transfer (QuickLens attack pattern)'
    });
  }
}
```

### Module Assignment
- **ExtensionAuditor**: Add `declarativeNetRequest` header-strip audit rule (P1 — new detection primitive, highest value addition)
- **ExtensionAuditor**: Add developer contact/homepage drift monitor (P2)
- **ExtensionAuditor**: Add extension C2 polling pattern from background fetch (P2)
- **KitRadar**: Add `extensionanalyticspro`-pattern domain naming as IOC class for threat intel

---

## Summary of Changes to PhishOps Modules

| Module | Addition | Priority |
|---|---|---|
| **ProxyGuard** | `user@domain` `@`-symbol URL masking detection — Starkiller's primary delivery obfuscation | P1 |
| **ExtensionAuditor** | `declarativeNetRequest rules.json` security header stripping audit on install/update | P1 |
| **ExtensionAuditor** | Developer contact / homepage drift detection — ownership transfer signal | P2 |
| **ExtensionAuditor** | Extension background C2 polling pattern fingerprint | P2 |
| **KitRadar** | Document Starkiller as out-of-scope for template fingerprinting; note detection boundary | P2 |
| **Sentinel KQL** | Impossible-geography session token reuse query (Starkiller AiTM post-compromise) | P2 |

### What's Confirmed Covered (no changes needed)
- Starkiller post-compromise session hijacking → **CTAPGuard** (passkey) + **OAuthGuard** (token scope) provide the upstream resistance
- QuickLens ClickFix stage → **DataEgressMonitor** clipboard intercept already covers fake-update PowerShell lures
- QuickLens crypto wallet targeting → not a PhishOps browser-layer concern; out of scope

---

## Tycoon 2FA Europol Takedown — Impact Assessment

**Rescana** noted in their QuickLens analysis that **Europol dismantled Tycoon 2FA** in a recent operation — "Europol Dismantles Tycoon 2FA: Inside the Takedown of a 64,000-Attack Phishing-as-a-Service Platform." This is directly relevant to KitRadar, which uses Tycoon 2FA's Cloudflare turnstile injection and React bundle signature as primary detection fingerprints.

The takedown does not reduce the value of those fingerprints — it increases it. Tycoon 2FA kits will continue to circulate, be forked, and be repurposed by successor operators. KitRadar's Tycoon 2FA detection remains valid. The Starkiller finding, combined with the Tycoon takedown, illustrates the bifurcation of the PhaaS market: commodity kits (Tycoon class) are being eliminated by law enforcement while premium real-time proxy kits (Starkiller class) emerge as the high-end replacement. KitRadar should be positioned as covering the former; the latter requires the ProxyGuard + Sentinel behavioural approach described above.

---

*PhishOps Threat Research Update — March 13, 2026*
*Sources: Abnormal AI (Feb 25), Annex Security / BleepingComputer (Feb–Mar 2026), Rescana, The Hacker News, Krebs on Security, Infosecurity Magazine, SC Media, Dark Reading*
