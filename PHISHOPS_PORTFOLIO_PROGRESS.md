# PhishOps Detection Portfolio — Progress & Roadmap

> **Last updated:** March 16, 2026
> **Author:** Fevra — Cybersecurity Portfolio
> **Status:** Waves 1–3 complete | Lure in early implementation | v2 modules researched

---

## Project Overview

PhishOps is a five-layer, browser-native phishing defense framework that detects attacks where EDR, SASE, email gateways, and MDE are blind — inside the browser session itself. The portfolio pairs a Chrome MV3 extension suite with a mitmproxy network layer and Microsoft Sentinel KQL analytics.

Alongside PhishOps sits **Lure**, a standalone phishing email analysis and IOC extraction CLI tool.

---

## Architecture at a Glance

```
Kill Chain Layer          Module               Detection Surface
─────────────────────────────────────────────────────────────────
1. URL Delivery           ProxyGuard           Gophish RID, HTML smuggling, URL masking
2. Browser Page Load      OAuthGuard           Device code flow, state parameter abuse
                          AgentIntentGuard     Agentic blabbering, GAN-optimised pages
3. Victim Interaction     DataEgressMonitor    Clipboard ClickFix, blob: credential pages
4. Credential Harvest     DataEgressMonitor    Password field detection + brand impersonation
5. Session Reuse          Sentinel KQL         Impossible-geography AiTM detection
   & Persistence          ExtensionAuditor     DNR header strip, ownership drift, C2 polling
                          KitRadar             6 PhaaS kit families (Tycoon 2FA, Mamba, etc.)
```

**Telemetry target:** `BrowserPhishingTelemetry_CL` + `ProxyPhishingEvents_CL` custom Sentinel tables via Azure Monitor DCR.

---

## Completed Work

### Wave 1 — ProxyGuard + OAuthGuard (January 2026) ✅

| Component | File | What It Does | Tests |
|-----------|------|-------------|-------|
| ProxyGuard entry point | `wave1/proxy_guard.py` | mitmproxy addon — runs 3-detector pipeline, blocks at HTTP 403 | Indirect |
| HTML Smuggling Detector | `wave1/html_smuggling.py` | 7-pattern co-occurrence scoring (atob, Blob, createObjectURL, mshta) | 23 tests |
| URL Masking Detector | `wave1/url_masking.py` | @-symbol userinfo masking, 14 brand targets, TLD amplifier | 13 tests |
| State Parameter Abuse | `wave1/state_parameter_abuse.js` | OAuth state email encoding across 8 providers (base64, hex, URL) | 29 tests |
| Service Worker | `wave1/service-worker.js` | MV3 background — chains device code flow + state abuse detectors | — |
| Sentinel KQL | `wave1/state_parameter_abuse.kql` | Campaign aggregation, burst detection, impossible-travel join | — |
| Telemetry Schemas | `wave1/*.md` | BrowserPhishingTelemetry_CL + ProxyPhishingEvents_CL schemas | — |

**Total Wave 1 tests: 65**

### Wave 2 — DataEgressMonitor + Starkiller Detection (February 2026) ✅

| Component | File | What It Does | Tests |
|-----------|------|-------------|-------|
| Blob Credential Detector | `wave2/blob_credential_detector.js` | Detects phishing pages on blob: URLs — password fields, brand impersonation, nested smuggling, form exfiltration | 30+ tests |
| Background Service Worker | `wave2/background.js` | Monitors `webNavigation.onCommitted` for blob: navigations, injects detector | — |
| Impossible Geography KQL | `wave2/aitmpostcompromise_impossible_geography.kql` | Starkiller AiTM session hijack via SigninLogs impossible-travel (Critical/High/Medium severity) | — |
| Extension Manifest | `wave2/manifest.json` | Chrome MV3 v0.2.0 — all permissions for Wave 1–2 modules | — |
| Telemetry Schema | `wave2/BrowserPhishingTelemetry_CL.md` | Added `BLOB_URL_CREDENTIAL_PAGE` EventType | — |

**Scoring model:** Password (+0.50) + 2nd password (+0.10) + brand (+0.20) + nested smuggling (+0.20) + form exfil (+0.15) → alert at ≥0.65, disable fields at ≥0.80

**Total Wave 2 tests: 30+**

### Wave 3 — ExtensionAuditor + AgentIntentGuard (March 2026) ✅

| Component | File | What It Does | Tests |
|-----------|------|-------------|-------|
| ExtensionAuditor Background | `wave3/background.js` | 3-module audit pipeline on extension install/update/enable — DNR header strip, ownership drift, C2 polling | 49 tests |
| AgentIntentGuard Content | `wave3/content.js` | Agentic blabbering detection, GAN-optimised page heuristic, credential focus monitoring | (included in 49) |
| Detection Boundaries | `wave3/DETECTION_BOUNDARIES.md` | Documents KitRadar scope — Starkiller-class live-proxy kits are out-of-scope | — |
| Sentinel Query Library | `wave3/mnt/.../sentinel/README.md` | 3 KQL queries with deployment guide, false positive guidance | — |
| Final Manifest | `wave3/manifest.json` | Chrome MV3 v0.2.0 — all Wave 1–3 modules wired | — |
| Complete Telemetry Schema | `wave3/BrowserPhishingTelemetry_CL.md` | 8 EventTypes across all detectors | — |

**Total Wave 3 tests: 49**

### Cumulative Test Coverage

| Module | Framework | Count |
|--------|-----------|-------|
| ProxyGuard (Python) | pytest | 31 |
| OAuthGuard (JS) | Vitest | 21 |
| DataEgressMonitor (JS) | Vitest | 35 |
| ExtensionAuditor + AgentIntentGuard (JS) | Vitest | 49 |
| **Total** | | **136** |

---

## In Progress: Lure — Phishing Email Analysis CLI

**Location:** `lure/`
**Stack:** Python, Click CLI, mail-parser, iocextract, YARA

### What Exists

| File | Status |
|------|--------|
| `lure/cli.py` | Scaffolded |
| `lure/pipeline.py` | Scaffolded |
| `lure/models.py` | Scaffolded |
| `lure/config.py` | Scaffolded |
| `lure/modules/parser.py` | Started |
| `lure/modules/extractor.py` | Started |
| `tests/test_parser.py` | Started |
| `tests/test_extractor.py` | Started |
| `pyproject.toml` | Configured |
| `.env.example` | Template |

### What's Left to Build

#### Phase 1 — Core Pipeline (highest priority)
- [ ] Complete `.eml` parser with SPF/DKIM/DMARC validation
- [ ] Add Outlook `.msg` support via `extract-msg`
- [ ] Received chain hop-by-hop analysis
- [ ] Reply-To mismatch detection
- [ ] IOC extraction with defang handling (20+ variants)
- [ ] URL extraction from HTML body (BeautifulSoup, not regex)
- [ ] Attachment IOC extraction (PDF, Word, ZIP, nested archives depth 3)
- [ ] Multi-hop redirect chain following (depth 5)

#### Phase 2 — YARA + Attachment Analysis
- [ ] YARA scanning module (compile once, cache in memory)
- [ ] Bundle Neo23x0/signature-base ruleset
- [ ] `--learn` mode via yarGen for custom rule generation
- [ ] oletools macro detection (VBA + XLM)
- [ ] PDF JavaScript extraction (pdfminer, pdfid)
- [ ] PE file analysis for `.exe` attachments
- [ ] Hash enrichment (MD5/SHA256 → VirusTotal)

#### Phase 3 — Threat Intelligence Enrichment
- [ ] VirusTotal v3 API (48h cache TTL)
- [ ] AbuseIPDB v2 (rate-limited, 1000 req/day)
- [ ] Shodan, urlscan.io, AlienVault OTX
- [ ] PhishTank + Google Safe Browsing
- [ ] WHOIS domain age extraction
- [ ] Verdict engine (weighted 0–100 risk score)
- [ ] Homograph/IDN detection via tldextract

#### Phase 4 — Campaign Correlation
- [ ] SQLite persistence layer
- [ ] MinHash/LSH similarity clustering
- [ ] `lure correlate` command
- [ ] Campaign tagging + shared infrastructure detection

#### Phase 5 — Output & Integration
- [ ] JSON canonical output schema
- [ ] HTML report (Jinja2 — verdict banner, IOC tables, YARA panel, hop diagram)
- [ ] PDF export via weasyprint
- [ ] STIX 2.1 export for MISP sharing
- [ ] TheHive case creation + Cortex analyzer triggering
- [ ] Slack/Jira integration

---

## Remaining PhishOps Integration Work

These items are needed to take Waves 1–3 from "working detectors" to "deployed product":

### Telemetry Pipeline (All Waves)
- [ ] Replace `emitTelemetry()` stubs with real Azure Monitor DCR (Logs Ingestion API) calls
- [ ] Implement WHOIS caching in ProxyGuard
- [ ] Wire BrowserPhishingTelemetry_CL table creation in Sentinel workspace
- [ ] Deploy KQL scheduled analytics rules (30-min frequency, 2-hour lookback)
- [ ] 7-day dry-run validation before live alert deployment

### Extension Packaging
- [ ] Unify Wave 1–3 into single Chrome extension package
- [ ] Build popup UI for status/configuration
- [ ] Intune/Google Workspace policy deployment packaging
- [ ] Chrome Web Store listing (or enterprise-only sideload)

### Demo Infrastructure
- [ ] ClickFix simulation page
- [ ] Malicious OAuth consent screen demo
- [ ] Device code flow lure (QR code simulator)
- [ ] Blob: credential harvest demo page

---

## Possible Enhancements (v2 Modules — Research Complete)

These modules are fully researched with deep technical write-ups. Ready to build when v1 is stable.

| Module | What It Detects | Research Source | Build Estimate |
|--------|----------------|-----------------|----------------|
| **AutofillGuard** | DOM-based extension clickjacking, hidden field autofill attacks (1Password/LastPass unpatched as of Jan 2026) | `Research/AutofillGuard_DeepResearch_Report.md` | 2 weeks |
| **FullscreenGuard** | Fullscreen redirect attacks hiding browser UI during OAuth/vishing chains | `Research/PhishOps_DeepResearch_Full_Report.md` | 1 week |
| **PasskeyGuard** | Malicious passkey enrollment prompts, FIDO2 token theft via authorization prompt spoofing | `Research/PhishOps_DeepResearch_Full_Report.md` | 1.5 weeks |
| **SyncGuard** | Unauthorized browser sync to attacker-controlled accounts, data exfiltration | `Research/PhishOps_DeepResearch_Full_Report.md` | 1 week |
| **CTAPGuard** | CTAP2 credential theft, challenge/response integrity validation | `Research/PhishOps_DeepResearch_Full_Report.md` | 1 week |
| **QRSweep** | QR code phishing in PDFs, images, invoices | `Research/phishing_tool_research.md` | 2 weeks |
| **FakeSender Shield** | Helpdesk platform sender spoofing (Zendesk, Freshdesk, ServiceNow) | `Research/FakeSender_Shield_Technical_Deep_Dive.md` | 1.5 weeks |
| **PhishVision** | Visual similarity detection for brand impersonation pages | `Research/PhishVision_Technical_Deep_Dive.md` | 2 weeks |

### Lure v2 Enhancements

| Feature | Description |
|---------|-------------|
| **LLM Analysis Layer** | Ollama integration — routing anomaly detection, verdict explanation, semantic phishing intent (qwen2.5:7b) |
| **AI-Generated Email Detection** | DetectGPT curvature analysis, burstiness variance, Cialdini persuasion density, XGBoost + LIME/SHAP |
| **QR Code Extraction** | pyzbar/qreader for quishing payloads embedded in email attachments |
| **Cryptocurrency Wallet Extraction** | Bitcoin, Ethereum, Monero address patterns in email bodies |

---

## Threat Intelligence Driving This Work

| Threat | Date | Impact on Portfolio |
|--------|------|---------------------|
| **Starkiller PhaaS v6.2.4** (Jinkusu/Abnormal AI) | Feb 25, 2026 | Headless Chrome reverse proxy — KitRadar blind, drove impossible-geography KQL + ProxyGuard URL masking |
| **QuickLens Supply Chain** (Annex Security) | Feb–Mar 2026 | DNR header stripping — drove ExtensionAuditor DNR audit + C2 polling + ownership drift |
| **Storm-2372 Device Code Phishing** (Microsoft) | Mar 2, 2026 | OAuth state parameter email encoding — drove OAuthGuard state abuse detector |
| **ClickFix Malware Delivery** (ESET H1 2025) | 2025 | 8% of all phishing attacks — drove DataEgressMonitor clipboard defender |
| **Cyberhaven Extension Compromise** | 2025 | 35 extensions, 2.6M users — drove ExtensionAuditor hash baseline concept |
| **DOM Extension Clickjacking** (Marek Tóth) | 2025 | 1Password/LastPass unpatched — drove AutofillGuard research |

---

## Key Files Reference

| Purpose | Path |
|---------|------|
| Master architecture | `Plans/PhishOps_Detection_Portfolio_Architecture.md` |
| Execution roadmap | `Plans/PhishOps_Portfolio_Execution_Plan.md` |
| 2026 update implementation | `Plans/phishops-2026-update-implementation-plan.md` |
| Lure full blueprint | `Research/lure-deep-research-final.md` |
| Latest threat intel | `Research/PhishOps_2026_ThreatResearch_Update_Mar13.md` |
| All 14 attack domains | `Research/PhishOps_DeepResearch_Full_Report.md` |
| AutofillGuard deep dive | `Research/AutofillGuard_DeepResearch_Report.md` |
| AI classifier guide | `Plans/AI_Phishing_Classifier_Technical_Guide.md` |
| Detection boundaries | `wave3/DETECTION_BOUNDARIES.md` |
| Portfolio UI hub | `phishing_defense_hub.jsx` |

---

## Summary

| Area | Status | Details |
|------|--------|---------|
| **Wave 1** (ProxyGuard + OAuthGuard) | ✅ Complete | 5 detectors, 65 tests, 2 Sentinel schemas, 1 KQL query |
| **Wave 2** (DataEgressMonitor + Starkiller) | ✅ Complete | 1 detector, 30+ tests, 1 KQL analytics rule |
| **Wave 3** (ExtensionAuditor + AgentIntentGuard) | ✅ Complete | 5 detectors, 49 tests, detection boundary docs |
| **Lure** | 🔧 In Progress | Parser + extractor scaffolded, 5 phases remaining |
| **Telemetry Integration** | ⏳ Pending | emitTelemetry stubs need Azure Monitor DCR wiring |
| **Extension Packaging** | ⏳ Pending | Unify waves into single deployable extension |
| **v2 Modules** | 📋 Researched | 8 additional modules with full technical write-ups |
| **Total Detectors** | **13 built** | + 6 KitRadar families + 8 researched v2 modules |
| **Total Tests** | **136** | 31 pytest + 105 Vitest |
