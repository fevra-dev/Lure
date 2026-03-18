# PhishOps Detection Portfolio — Progress

> **Last updated:** March 18, 2026
> **Status:** Waves 1–15 complete (38 detectors) | Lure CLI in progress

---

## Detector Summary

| Wave | Detectors | Module | Tests |
|------|-----------|--------|-------|
| 1 | Device Code Flow, State Parameter Abuse | OAuthGuard | 21 |
| 2 | Blob Credential Page | DataEgressMonitor | 35 |
| 3 | DNR Audit, Ownership Drift, C2 Polling, GAN Page, Guardrail Bypass | ExtensionAuditor + AgentIntentGuard | 49 |
| 4 | Hidden Field Harvest, Extension Clickjack | AutofillGuard | 46 |
| 5 | ClickFix Clipboard Injection, BitM Fullscreen Overlay | ClipboardDefender + FullscreenGuard | 57 |
| 6 | Passkey Credential Interception, QR Session Hijack | PasskeyGuard + QRLjackingGuard | 66 |
| 7 | Virtual Camera Detection, TOAD Screen Share | WebRTCGuard + ScreenShareGuard | 62 |
| 8 | Brand Impersonation, AiTM Proxy | PhishVision + ProxyGuard | 70 |
| 9 | Browser Sync Hijack, Helpdesk Impersonation | SyncGuard + FakeSender | — |
| 10 | FIDO Downgrade, IPFS Gateway Phishing | CTAPGuard + IPFSGuard | — |
| 11 | AI-Generated Phishing, EvilnoVNC AiTM | LLMScorer + VNCGuard | 82 |
| 12 | PWA Phishing, Consent Phishing | PWAGuard + TPASentinel | 60 |
| 13 | Crypto Wallet Drainer, CSS Credential Exfil | DrainerGuard + StyleAuditor | 62 |
| 14 | WebSocket Credential Exfil, SW Persistence | WsExfilGuard + SwGuard | 78 |
| 15 | Blockchain Payload Delivery, Notification Phishing | EtherHidingGuard + NotificationGuard | 78 |
| **Total** | **38 detectors** | **26 content scripts** | **676 passing** |

---

## Intelligence Infrastructure

| Component | Count | Details |
|-----------|-------|---------|
| PIRs | 29 | Priority Intelligence Requirements mapped to detectors |
| Correlation Sets | 23 | Multi-stage attack campaign grouping |
| MITRE ATT&CK Techniques | 19 | Unique technique IDs mapped |
| Triage Classifications | 31 | NIST 800-61r3 event types with SLA targets |
| Threat Actors Tracked | 25+ | Storm-2372, ClearFake, Scattered Spider, APT29, FIN7, etc. |

---

## Architecture

- **Scoring**: Additive signal weights (0.10–0.40), capped at 1.0. Alert >= 0.50, Block >= 0.70
- **Injection**: `document_start` for API wrapping (fetch, WebSocket, Notification, passkey, clipboard), `document_idle` for DOM analysis
- **Telemetry**: All events → triage engine → chrome.storage.local (production: Azure Monitor DCR)
- **Design**: Dieter Rams / Braun — #0A0907 surface, #BF1B1B red, Work Sans, 0px radii

---

## Lure CLI Status

| Stage | Status |
|-------|--------|
| Parser (SPF/DKIM/DMARC) | Complete |
| IOC Extractor | Complete |
| YARA Scanner (8 rules) | Complete |
| Verdict Scorer (11 signals) | Complete |
| Enrichment APIs | Wired, optional |
| Campaign Correlation | Pending |
