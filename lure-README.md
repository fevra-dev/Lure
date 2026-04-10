# LURE — Browser Phishing Defence Platform

A browser-native phishing defence platform built for SOC teams. 49 real-time detection modules in a Chrome MV3 extension covering the full phishing kill chain — from delivery through credential harvest to persistence — paired with a Python email analysis CLI that produces verdicts from raw `.eml` files.

The extension ships with a canvas-based live threat visualization dashboard, SOC-ready event export (JSON/CSV), event housekeeping, and a unified domain allowlist (~229 builtin domains) to suppress false positives on trusted sites.

## Architecture

```mermaid
graph TB
    subgraph "Chrome Extension — 49 Detectors"
        SW[Service Worker<br/>Message Router + Triage Engine]
        SW --> D1[Foundation<br/>OAuthGuard · DataEgress · ExtensionAuditor · AgentIntentGuard]
        SW --> D2[Interaction Layer<br/>AutofillGuard · ClipboardDefender · FullscreenGuard<br/>PasskeyGuard · QRLjackingGuard]
        SW --> D3[Social Engineering<br/>WebRTCGuard · ScreenShareGuard · PhishVision<br/>ProxyGuard · SyncGuard · FakeSender]
        SW --> D4[Evasion<br/>CTAPGuard · IPFSGuard · LLMScorer<br/>VNCGuard · PWAGuard · TPASentinel]
        SW --> D5[Exfil + Persistence<br/>DrainerGuard · StyleAuditor · WsExfilGuard<br/>SwGuard · EtherHidingGuard · NotificationGuard]
        SW --> D6[Next-Gen<br/>WebTransportGuard · CanvasPhishGuard<br/>CanvasKeystrokeGuard · CanvasExfilGuard<br/>SpeculationRulesGuard]
        SW --> D7[Anti-Fingerprinting + Payment<br/>StealthKit · ProbeGuard · PaymentRequestGuard]
        SW --> D8[File System + Threat Intel<br/>FileSystemGuard · ThreatIntelSync]
        SW --> D9[SPA + Deepfake Sentinel<br/>SPANavigationMonitor · WebRTCSyntheticTrack]
    end

    subgraph "Allowlist + SOC Tools"
        AL[Unified Allowlist<br/>229 builtin domains · user-editable]
        AL --> CSS[CSS Gate<br/>document_start suppression]
        AL --> TEL_GATE[Telemetry Gate<br/>skip events for trusted domains]
        SW --> EXP[Event Export<br/>JSON · CSV]
        SW --> CLR[Housekeeping<br/>Clear All · Clear >7d]
    end

    subgraph "Lure CLI — Email Analysis Pipeline"
        EML[.eml / .msg] --> PA[Stage A: Parser<br/>SPF · DKIM · DMARC · Routing]
        PA --> PB[Stage B: Extractor<br/>URLs · IPs · Domains · Hashes]
        PB --> PC[Stage C: YARA Scanner<br/>8 custom rules]
        PC --> PE[Stage E: Scorer<br/>11 weighted signals]
        PE --> V{Verdict}
    end

    subgraph "Intelligence Layer"
        SW --> TRI[Triage Engine<br/>NIST 800-61r3 · MITRE ATT&CK]
        SW --> INT[Intelligence Lifecycle<br/>35 PIRs · 31 Correlation Sets]
        SW --> TIS[ThreatIntelSync<br/>PhishStats API · phishnet.cc]
        SW --> TEL[Telemetry<br/>chrome.storage.local]
        TEL --> POP[LURE Dashboard<br/>Canvas Visualization + Events List]
        TEL -.->|Production| DCR[Azure Monitor DCR]
    end
```

## Detector Inventory

49 detectors, each with additive signal scoring (alert at 0.50, block at 0.70, cap 1.0).

| Detector | Threat | MITRE ATT&CK | Injection |
|----------|--------|--------------|-----------|
| OAuthGuard — Device Code Flow | Storm-2372 | T1528 | background |
| OAuthGuard — State Parameter Abuse | Storm-2372 | T1598.004 | background |
| DataEgressMonitor — Blob Credential | NOBELIUM / TA4557 | T1027.006 | programmatic |
| ExtensionAuditor — DNR Audit | QuickLens | T1195.002 | background |
| ExtensionAuditor — Ownership Drift | Cyberhaven-style | T1195.002 | background |
| ExtensionAuditor — C2 Polling | Multiple | T1071.001 | background |
| AgentIntentGuard — GAN Page + Guardrail Bypass | Agentic | T1056.003 | document_idle |
| AutofillGuard — Hidden Field Harvest | Kuosmanen-class | T1056.003 | document_idle |
| AutofillGuard — Extension Clickjack | Toth-class | T1056.003 | document_idle |
| ClipboardDefender — ClickFix Injection | FIN7 / Lazarus | T1059.001 | document_start |
| FullscreenGuard — BitM Overlay | BitM-class | T1185 | document_idle |
| PasskeyGuard — Credential Interception | Spensky DEF CON 33 | T1556.006 | document_start |
| QRLjackingGuard — Session Hijack | APT29 / TA2723 | T1539 | document_idle |
| WebRTCGuard — Virtual Camera | Scattered Spider | T1566.003 | document_start |
| ScreenShareGuard — TOAD Detection | MuddyWater / Luna Moth | T1113 | document_start |
| PhishVision — Brand Impersonation + Favicon Hash | Multiple | T1566.002 | document_idle |
| ProxyGuard — AiTM Proxy | Evilginx / Modlishka | T1557.003 | document_idle |
| SyncGuard — Browser Sync Hijack | Scattered Spider | T1078.004 | document_idle |
| FakeSender — Helpdesk Impersonation | Multiple | T1566.002 | document_idle |
| CTAPGuard — FIDO Downgrade | Tycoon 2FA | T1556.006 | document_idle |
| IPFSGuard — Gateway Phishing | Commodity | T1583.006 | document_idle |
| LLMScorer — AI-Generated Phishing | TA4557 / Scattered Spider | T1566.002 | document_idle |
| VNCGuard — EvilnoVNC AiTM | Storm-1811 / TA577 | T1557.003 | document_idle |
| PWAGuard — Progressive Web App Phishing | Czech/Hungarian campaigns | T1036.005 | document_idle |
| TPASentinel — Consent Phishing | Storm-0324 / APT29 | T1528 | document_idle |
| DrainerGuard — Crypto Wallet Drainer | Inferno / Angel / Pink | T1656 | document_idle |
| StyleAuditor — CSS Credential Exfil | Advanced kits | T1056.003 | document_idle |
| WsExfilGuard — WebSocket Credential Exfil | EvilProxy / Modlishka 2.0+ | T1056.003 | document_start |
| SwGuard — Service Worker Persistence | Watering-hole campaigns | T1176 | document_start |
| EtherHidingGuard — Blockchain Payload Delivery | ClearFake / ClickFix | T1059.007 | document_start |
| NotificationGuard — Push Notification Phishing | Multiple | T1204.001 | document_start |
| WebTransportGuard — WebTransport AiTM Relay | Advanced PhaaS kits | T1056.003 | document_start |
| CanvasPhishGuard — Canvas Credential Phishing | Advanced kits / Flutter Web | T1056.003 | document_idle |
| CanvasKeystrokeGuard — Canvas Keystroke Capture | Advanced kits / Flutter Web | T1056.003 | document_start (MAIN world) |
| CanvasExfilGuard — Canvas Credential Exfiltration | Advanced kits / Flutter Web | T1041 | document_start |
| SpeculationRulesGuard — Speculation Rules Phishing | XSS → Prerender abuse | T1598.003 | document_start |
| StealthKit — Anti-Fingerprinting Hardening | Detection evasion | — | document_start (MAIN world) |
| ProbeGuard — Security Tool Probing Detection | Tycoon 2FA / EvilProxy / CreepJS | T1518.001 | document_start (MAIN world) |
| PaymentRequestGuard — Payment API Phishing Signal | PII harvesting via browser-native UI | T1056.003 | document_start (MAIN world) |
| FileSystemGuard — File System Access API Abuse | RøB-style ransomware / PhaaS kits | T1552.001 | document_start (MAIN world) |
| ThreatIntelSync — Domain Reputation Check | Confirmed phishing infrastructure | T1566.002 | background (alarm-based) |
| SPANavigationMonitor — SPA Login Path Injection | XSS/Nav API pushState phishing | T1185 | background |
| WebRTCSyntheticTrackSentinel — Deepfake Track Injection | Scattered Spider / state actors | T1566.003 | document_start (MAIN world) |

## Signal Scoring Model

Every detector uses the same additive scoring framework:

- Each signal contributes a weight (0.10–0.40)
- Signals are summed, capped at 1.0
- **Severity**: >= 0.90 Critical, >= 0.70 High, >= 0.50 Medium
- **Action**: >= 0.70 blocked (fields disabled, banner injected), >= 0.50 alerted

Example from WebTransportGuard:

| Signal | Weight | Trigger |
|--------|--------|---------|
| `wt:transport_on_credential_page` | +0.40 | WebTransport connection on page with credential fields |
| `wt:self_signed_cert_hashes` | +0.30 | `serverCertificateHashes` option used (self-signed certs) |
| `wt:cross_origin_transport_with_creds` | +0.25 | WebTransport target hostname differs from page origin |
| `wt:credential_data_in_stream` | +0.20 | Input field value found in stream/datagram write |
| `wt:transport_without_media_context` | +0.15 | WebTransport without video/streaming UI |

## Intelligence Layer

Every detection event is enriched by three engines before persistence:

**Triage Engine** (`lib/triage.js`) — NIST SP 800-61r3 classification with MITRE ATT&CK mapping, SANS PICERL priority/SLA assignment, and recommended containment actions per event type.

**Intelligence Lifecycle** (`lib/intelligence_lifecycle.js`) — 35 Priority Intelligence Requirements (PIRs), confidence scoring, deduplication, 31 correlation sets for campaign grouping, and tactical intelligence summary generation.

**ThreatIntelSync** (`lib/threat_intel_sync.js`) — Periodic ingestion from PhishStats API and phishnet.cc feed.txt. Builds compact domain/IP/exfil-endpoint lookup sets stored in `chrome.storage.local['threatIntel']`, refreshed every 4 hours via `chrome.alarms`. All lookups are supplementary — core detection quality never degrades if feeds are unreachable.

## Quick Start

### Chrome Extension

```bash
git clone <repo-url>
cd lur3

# Load in Chrome or Brave:
# 1. Navigate to chrome://extensions (or brave://extensions)
# 2. Enable "Developer mode"
# 3. Click "Load unpacked" → select the extension/ directory
```

### Run Tests

```bash
# Extension tests (Vitest) — 1507 tests across 43 suites
cd extension && npm test

# Lure CLI tests (pytest)
cd lure && pip install -e ".[dev,yara]" && pytest -v
```

## LURE Dashboard

The popup renders a live canvas visualization of all detection events. Packets travel along bezier thread paths, color-coded by severity:

- **Olive** (`#8b9e73`) — normal / low / medium traffic
- **Bronze** (`#b59a6d`) — high severity detections
- **Red** (`#c25e5e`) — critical detections with glow

Each threat packet carries a label showing the detector name and key detail (e.g. `AiTM Proxy: evilginx.example.com`, `FS API Credential Exfil: .aws, .env`).

### SOC Essentials

- **Recent Events List** — clickable rows with severity chips; expand any event to see full detail
- **Event Export** — download all events as JSON (with metadata bundle) or CSV (RFC 4180)
- **Housekeeping** — Clear All or Clear events older than 7 days
- **Allowlist Editor** — add/remove custom domains from the user allowlist directly in the popup

## Unified Domain Allowlist

Two-layer false-positive suppression for trusted domains:

1. **CSS Gate** (`allowlist_gate.js`) — runs at `document_start` before all detectors. Injects a single CSS rule `[id^="phishops-"] { display: none !important }` to hide all PhishOps banners on allowlisted domains. Zero existing detectors need modification.

2. **Telemetry Gate** — `emitTriagedTelemetry()` in the service worker extracts the hostname from each event's URL and skips emission for allowlisted domains, keeping storage and badge counts clean.

**Builtin list:** ~229 domains merged from all detector-specific trusted domain lists, the top-500 most-trafficked websites, and false-positive events observed in field testing. Covers Google, Microsoft, Amazon, major news/social/shopping/education sites, auth providers, and security platforms.

**User list:** stored in `chrome.storage.local['phishops_user_allowlist']`, editable via the popup. Subdomain matching is automatic — adding `corp.com` covers `app.corp.com`.

## Lure CLI

Email analysis pipeline producing categorical verdicts from raw `.eml` files.

| Stage | Module | What It Does |
|-------|--------|-------------|
| A | `parser.py` | Parse RFC 5322 / OLE .msg, validate SPF/DKIM/DMARC, walk Received chain |
| B | `extractor.py` | Extract URLs, IPs, domains, hashes, emails, crypto wallets |
| C | `scanner.py` | YARA scanning with 8 custom rules |
| E | `scorer.py` | 11 weighted signals producing categorical verdicts |

## Project Structure

```
lur3/
├── extension/                  # Chrome MV3 extension
│   ├── manifest.json           # v1.0.0, 49 detectors, alarms permission
│   ├── background/             # Service worker (message routing + triage + allowlist gate)
│   ├── content/                # 41 content scripts (incl. allowlist_gate.js)
│   ├── lib/                    # triage.js · intelligence_lifecycle.js · telemetry.js
│   │                           # stealth_kit.js · threat_intel_sync.js
│   │                           # allowlist.js · event_export.js
│   ├── popup/                  # LURE dashboard (canvas viz + events list + allowlist editor)
│   └── tests/                  # 43 Vitest test files, 1507 tests
│
├── lure/                       # Email analysis CLI
│   ├── lure/modules/           # parser, extractor, scanner, scorer
│   ├── rules/                  # YARA rule files
│   └── tests/                  # pytest tests
│
├── Research/                   # Threat research and detector design docs
├── Plans/                      # Architecture and implementation planning docs
├── CUTTING_EDGE_DETECTORS.md   # Next-gen detection candidates
├── RESEARCH_PROMPTS.md         # Structured research prompts
└── THREAT_INTELLIGENCE.md      # Detector → threat intel source mapping
```

## Threat Intelligence Sources

See [THREAT_INTELLIGENCE.md](THREAT_INTELLIGENCE.md) for the complete mapping of every detector to its primary threat intelligence source.

See [CUTTING_EDGE_DETECTORS.md](CUTTING_EDGE_DETECTORS.md) for research on next-generation detection candidates.

## What's Not Included (by design)

- **Azure Monitor DCR integration** — requires infrastructure. Telemetry architecture is documented; local storage stub demonstrates the full pipeline.
- **Chrome Web Store publication** — sideload is sufficient for review.
- **Favicon hash map populated** — `FAVICON_HASH_TO_BRAND` in PhishVision ships empty. Infrastructure is complete; hashes are collected operationally using the DevTools script in the source comments.
- **urlscan.io reactive enrichment** — Tier 2 integration (requires API key). Architecture designed; deferred per design constraints.
