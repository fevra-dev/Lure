# PhishOps Detection Portfolio

**Open-source browser-native phishing defence · Fevra Security · March 2026**

Five detection layers covering the complete modern phishing kill chain — from URL delivery through browser interaction through credential harvesting through identity persistence. The first open-source framework to cover all five layers with unified Microsoft Sentinel analytics.

---

## The Problem

Every enterprise security product is architecturally blind to the browser layer.

| Tool | What It Misses |
|---|---|
| **EDR** | Zero visibility into browser DOM, clipboard content, OAuth redirects, or extension behaviour |
| **SASE / SSE** | Bypassed by hosting phishing infrastructure on trusted CDNs (AWS, Vercel, Cloudflare) |
| **Email Gateway** | Cannot detect credential submission, AiTM session hijacking, or post-delivery browser actions |
| **Microsoft MDE** | Cannot inspect clipboard writes, form field interaction, blob: URL content, or extension rules.json |
| **Microsoft Defender Browser Protection** | Being retired; replaced by OS-layer Network Protection with the same DOM blindness |

PhishOps instruments the browser layer from inside — where attacks live, not where defenders have been watching.

---

## Modules

### ProxyGuard — HTTP Proxy Layer (`proxyguard/`)

**Language:** Python 3.11 · **Runtime:** mitmproxy

Intercepts HTTP requests and responses at the network proxy layer. Fires before any page content reaches the victim's browser.

| Detector | EventType | Threat Countered |
|---|---|---|
| `gophish_fingerprint.py` | `GOPHISH_CAMPAIGN_FINGERPRINT` | Gophish/evilgogophish `rid=` campaign tracking tokens |
| `html_smuggling.py` | `HTML_SMUGGLING_LOADER` | `atob()+Blob+createObjectURL` HTML smuggling delivery (40%+ of enterprise phishing kits, Mandiant 2025) |
| `url_masking.py` | `URL_USERINFO_MASKING` | Starkiller PhaaS `microsoft.com@attacker.ru` userinfo masking (Abnormal AI, Feb 2026) |

---

### PhishOps Chrome Extension (`packages/extension/`)

**Language:** JavaScript ES2022 · **Runtime:** Chrome MV3

Four detection modules running as content scripts and a background service worker.

#### OAuthGuard (`oauthguard/`)
Monitors OAuth authorization flows via `chrome.webRequest.onBeforeRequest`.

| Detector | EventType | Threat Countered |
|---|---|---|
| `device_code_detector.js` | `OAUTH_DEVICE_CODE_FLOW` | Storm-2372 / APT29 device code flow QR phishing |
| `state_parameter_abuse.js` | `OAUTH_STATE_EMAIL_ENCODED` | Victim email encoded in OAuth `state=` parameter (Microsoft, Mar 2026) |

#### DataEgressMonitor (`dataegress/`)
Detects data exfiltration and credential harvest attempts at the browser API layer.

| Detector | EventType | Threat Countered |
|---|---|---|
| `clipboard-defender.js` | `CLICKFIX_DETECTED` | ClickFix clipboard malware injection (#2 global attack vector, ESET H1 2025) |
| `blob_credential_detector.js` | `BLOB_URL_CREDENTIAL_PAGE` | HTML smuggling terminal pages served via `blob:` URL (invisible to all network tools) |

#### ExtensionAuditor (`extensionauditor/`)
Audits installed and updated extensions for supply chain compromise indicators.

| Detector | EventType | Threat Countered |
|---|---|---|
| `dnr_header_audit.js` | `EXTENSION_SECURITY_HEADER_STRIP` | `declarativeNetRequest` CSP/header stripping (QuickLens, Feb 2026) |
| `ownership_drift.js` | `EXTENSION_DEVELOPER_CONTACT_CHANGED` | Extension ownership transfer via ExtensionHub marketplace (QuickLens / Cyberhaven pattern) |
| `c2_polling_detector.js` | `EXTENSION_C2_POLLING` | Extension background service worker C2 polling (dynamic payload delivery) |

#### AgentIntentGuard (`agentintentguard/`)
Detects AI browser agent prompt injection guardrail bypass patterns.

| Detector | EventType | Threat Countered |
|---|---|---|
| `reasoning_monitor.js` | `AGENTIC_BLABBERING_GUARDRAIL_BYPASS` | Credential field focus after raised suspicion — agent proceeding despite safety signal |
| `reasoning_monitor.js` (GAN heuristic) | `PHISHVISION_SUPPLEMENTARY_SIGNAL` | Starkiller-class sparse pages with minimal text/HTML ratio |

---

### KitRadar — PhaaS Kit Fingerprinting (`kitradar/`)

**Language:** Python · **Runtime:** YARA-X + IOK rules pipeline

Classifies PhaaS kit families from phishing page HTML using YARA-X rules and Indicator of Kit (IOK) patterns.

| Kit Family | Detection Method |
|---|---|
| Tycoon 2FA | Cloudflare Turnstile injection + React bundle hash |
| Mamba 2FA | React bundle fingerprint + anti-bot page structure |
| GhostFrame | Cross-origin iframe injection + session token URL path |
| Evilginx | Hex session token path prefix `^/[a-f0-9]{8,16}/` |
| EvilProxy | Cookie stripping pattern + `X-` header session token |

**Detection boundary:** Starkiller-class live-proxy kits (Docker headless Chrome reverse proxy) are explicitly out-of-scope for template fingerprinting. See [`kitradar/DETECTION_BOUNDARIES.md`](kitradar/DETECTION_BOUNDARIES.md).

---

### Lure — Email IOC Extraction (`lure/`)

**Language:** Python 3.11 · **Runtime:** Standalone CLI

Compresses the 15–45 minute manual L1/L2 SOC email triage workflow into sub-90-second automated analysis. Parses `.eml` and `.msg` files, validates SPF/DKIM/DMARC, extracts IOCs, walks redirect chains, and runs static attachment analysis.

```bash
lure analyze suspicious.eml --format json
```

---

## Sentinel Integration

All PhishOps modules emit to two custom Microsoft Sentinel tables:

| Table | Populated By | Detections |
|---|---|---|
| `ProxyPhishingEvents_CL` | ProxyGuard (Python/mitmproxy) | `GOPHISH_CAMPAIGN_FINGERPRINT`, `HTML_SMUGGLING_LOADER`, `URL_USERINFO_MASKING` |
| `BrowserPhishingTelemetry_CL` | Chrome Extension | `OAUTH_DEVICE_CODE_FLOW`, `OAUTH_STATE_EMAIL_ENCODED`, `CLICKFIX_DETECTED`, `BLOB_URL_CREDENTIAL_PAGE`, `EXTENSION_SECURITY_HEADER_STRIP`, `EXTENSION_DEVELOPER_CONTACT_CHANGED`, `EXTENSION_C2_POLLING`, `AGENTIC_BLABBERING_GUARDRAIL_BYPASS` |

See [`sentinel/README.md`](sentinel/README.md) for the full KQL query library and Scheduled Analytics Rule configuration.

---

## Kill Chain Coverage

```
[QR / Email Delivery]
        │
        ▼
[URL Layer]           ← ProxyGuard: URL masking, Gophish RID, HTML smuggling loader
        │
        ▼
[Browser Loads Page]  ← OAuthGuard: device code, state abuse
        │             ← AgentIntentGuard: GAN-optimised page heuristic
        ▼
[Victim Interacts]    ← DataEgressMonitor: clipboard write (ClickFix)
        │             ← AgentIntentGuard: credential field focus post-suspicion
        ▼
[Credential Harvest]  ← DataEgressMonitor: blob: credential page
        │             ← PhishVision: brand impersonation visual match
        ▼
[Session Reuse]       ← Sentinel KQL: impossible geography (Starkiller AiTM)
        │
        ▼
[Persistence]         ← ExtensionAuditor: DNR strip, ownership drift, C2 polling
                      ← KitRadar: kit family attribution
```

---

## Repository Structure

```
phishops/
├── proxyguard/                         Python mitmproxy addon
│   ├── detectors/
│   │   ├── gophish_fingerprint.py      Gophish rid= campaign fingerprinting
│   │   ├── html_smuggling.py           atob()+Blob HTML smuggling loader (Wave 1)
│   │   └── url_masking.py              Starkiller @-symbol URL masking (Wave 1)
│   ├── proxy_guard.py                  Main mitmproxy addon entry point
│   └── tests/                          pytest suite (31 tests)
│
├── packages/extension/                 Chrome MV3 extension
│   ├── manifest.json
│   ├── background/
│   │   └── service-worker.js           OAuthGuard webRequest listeners
│   ├── content/
│   │   ├── clipboard-defender.js       ClickFix clipboard write interception
│   │   └── oauth-guard.js              OAuthGuard content script
│   ├── oauthguard/
│   │   └── detectors/
│   │       ├── device_code_detector.js Device code flow detection
│   │       └── state_parameter_abuse.js OAuth state= email encoding (Wave 1)
│   ├── dataegress/
│   │   ├── background.js               blob: navigation listener + message handler
│   │   └── blob_credential_detector.js blob: page credential detection (Wave 2)
│   ├── extensionauditor/
│   │   ├── background.js               chrome.management.onInstalled wiring
│   │   └── auditors/
│   │       ├── dnr_header_audit.js     rules.json security header stripping (Wave 3)
│   │       ├── ownership_drift.js      Developer contact change detection (Wave 3)
│   │       └── c2_polling_detector.js  Background C2 polling fingerprint (Wave 3)
│   └── agentintentguard/
│       ├── content.js                  Content script bootstrap
│       └── reasoning_monitor.js        Agentic blabbering + GAN heuristic (Wave 3)
│
├── kitradar/
│   └── DETECTION_BOUNDARIES.md        Starkiller out-of-scope documentation
│
├── sentinel/
│   ├── README.md                       KQL query library index
│   ├── schema/
│   │   ├── ProxyPhishingEvents_CL.md
│   │   └── BrowserPhishingTelemetry_CL.md
│   └── queries/
│       ├── aitmpostcompromise_impossible_geography.kql   (Wave 2)
│       └── oauthguard/
│           └── state_parameter_abuse.kql                 (Wave 1)
│
├── lure/                               Email IOC extraction platform
│   └── README.md
│
└── README.md                           This file
```

---

## Test Coverage

| Suite | Runner | Tests | Coverage |
|---|---|---|---|
| ProxyGuard (Python) | pytest | 31 | `html_smuggling.py`, `url_masking.py`, `gophish_fingerprint.py` |
| OAuthGuard (JS) | Vitest | 21 | `state_parameter_abuse.js` — 3 encode methods, 6 edge cases, 6 error resilience |
| DataEgressMonitor (JS) | Vitest | 35 | `blob_credential_detector.js` — 4 signal functions, DOM manipulation, full scenario |
| ExtensionAuditor + AgentIntentGuard (JS) | Vitest | 49 | `dnr_header_audit`, `ownership_drift`, `c2_polling_detector`, `reasoning_monitor` |
| **Total** | | **136** | |

Run all tests:
```bash
# Python
pytest proxyguard/tests/ -v

# JavaScript (all three test files)
cd packages/extension && npx vitest run
```

---

## Threat Intelligence Sources

All detections are grounded in named primary-source threat intelligence:

| Source | Coverage |
|---|---|
| Abnormal AI (Feb 25, 2026) | Starkiller PhaaS / Jinkusu operator group |
| Annex Security / BleepingComputer (Feb–Mar 2026) | QuickLens CSP-strip supply chain attack |
| Microsoft Security Blog (Mar 2, 2026) | OAuth `state=` parameter email encoding |
| Mandiant 2025 | HTML smuggling prevalence (40%+ of enterprise phishing kits) |
| ESET H1 2025 Threat Report | ClickFix as #2 global attack vector (8% of all attacks) |
| Microsoft MSTIC (Feb 2025) | Storm-2372 device code flow + QR delivery |
| Europol (Mar 2026) | Tycoon 2FA operator group takedown |
| SquareX YOBB 2025 | Browser architectural attack surface — 11 disclosures |
| arXiv 2511.20597 — BrowseSafe | AI agent prompt injection defence framework |
| Proofpoint State of the Phish 2025 | OAuth consent phishing — 55%+ org impact |

---

## Licensing

MIT License. See `LICENSE` for details.

**Dependency note:** If PyMuPDF is used in QRSweep, it is AGPL-3.0 licensed and requires an Artifex commercial license for proprietary use. All other dependencies are MIT or Apache 2.0.

---

*PhishOps Detection Portfolio · Fevra Security · March 2026 · TLP:WHITE*  
*All four primary capabilities are net-new to the open-source ecosystem.*  
*No single commercial vendor covers all five kill chain layers. No open-source tool did before this.*
