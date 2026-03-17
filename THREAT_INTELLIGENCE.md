# Threat Intelligence Sources

Every PhishOps detector maps to a specific threat actor, campaign, or vulnerability disclosure. This document tracks the primary intelligence source for each detection module.

## Chrome Extension Detectors

| Detector | Threat | Source | Date |
|----------|--------|--------|------|
| **Device Code Flow Detection** | Storm-2372 OAuth device code phishing | Microsoft Security Blog: "Storm-2372 conducts device code phishing campaign" | March 2026 |
| **State Parameter Email Encoding** | Storm-2372 state parameter C2 exfiltration | Microsoft MSTIC advisory on OAuth state abuse as data exfiltration channel | March 2, 2026 |
| **Blob Credential Page Detection** | HTML smuggling terminal page delivery | Mandiant 2025: HTML smuggling by NOBELIUM, TA4557, GhostSpider | 2024-2025 |
| **Blob Navigation Injection** | blob: URL phishing delivery | SquareX YOBB 2025: "Year of Browser Bugs" — blob: URL as phishing mechanism | 2025 |
| **DNR Header Stripping Audit** | QuickLens extension supply chain | Chrome Web Store supply chain attack: declarativeNetRequest used to strip CSP/X-Frame-Options | February 2026 |
| **Ownership Drift Detection** | Cyberhaven extension compromise | Cyberhaven Chrome extension compromised via developer account takeover | December 2024 |
| **C2 Polling Detection** | Extension-based C2 infrastructure | Multiple campaigns using Chrome extensions as persistent C2 beacons | 2024-2025 |
| **GAN-Optimised Page Heuristic** | AI-generated phishing pages | Research on adversarial ML-optimised pages with sparse HTML | 2025 |
| **Credential Focus Monitoring** | Agentic guardrail bypass | LLM agents navigating to credential pages and entering sensitive data | 2025-2026 |
| **ClickFix Clipboard Injection** | ClickFix social engineering | Proofpoint: "ClickFix technique tricks users into running malicious commands" | 2025 |
| **Reverse Proxy Detection** | Starkiller PhaaS v6.2.4 | Phishing-as-a-Service platform using headless Chrome reverse proxy for AiTM | 2025-2026 |
| **HTML Smuggling Pattern Detection** | ISO/HTML smuggling for RAT delivery | Microsoft MSTIC: ISO and HTML smuggling campaigns for malware delivery | 2024-2025 |
| **OAuth Scope Analysis** | Illicit consent grant attacks | Microsoft: "Detect and remediate illicit consent grants" | 2024-2025 |

## Lure YARA Rules

| Rule | Threat / Campaign | Reference |
|------|------------------|-----------|
| `phishops_clickfix_clipboard_lure` | ClickFix social engineering campaign | Proofpoint Security Brief: ClickFix technique (2025) |
| `phishops_tycoon2fa_kit` | Tycoon 2FA AiTM phishing kit | Sekoia.io: "Tycoon 2FA — An In-Depth Analysis" (2024-2025) |
| `phishops_device_code_lure` | Storm-2372 device code phishing | Microsoft Security Blog (March 2026) |
| `phishops_html_smuggling_loader` | HTML smuggling payload delivery | Mandiant: NOBELIUM, TA4557 HTML smuggling campaigns (2024-2025) |
| `phishops_credential_harvest_form` | Generic credential harvesting | OWASP Phishing taxonomy: credential harvest via fake login forms |
| `phishops_qr_code_phishing` | Quishing campaigns | Multiple threat reports on QR code phishing (2024-2025) |
| `phishops_vba_macro_downloader` | Office macro malware delivery | MITRE ATT&CK T1059.005: Command and Scripting Interpreter: Visual Basic |
| `phishops_base64_encoded_url` | URL obfuscation in phishing | Common obfuscation technique across multiple phishing kits |

## Lure Scoring Signals

| Signal | Threat Rationale | MITRE ATT&CK |
|--------|-----------------|---------------|
| `SPF_FAIL` | Sender IP not authorised by domain's SPF record — strong indicator of spoofing | T1566.001 |
| `DKIM_FAIL` | Email signature tampered or forged — body/header modified in transit | T1566.001 |
| `DMARC_FAIL` | Domain's DMARC policy violated — neither SPF nor DKIM aligned | T1566.001 |
| `REPLY_TO_MISMATCH` | Reply-To domain differs from From — responses go to attacker mailbox | T1566.001 |
| `HOMOGRAPH_DOMAIN` | Mixed Unicode scripts in domain (Cyrillic/Latin) — visual impersonation | T1583.001 |
| `SUSPICIOUS_ATTACHMENT` | Office macro or PDF with auto-exec capabilities — payload delivery | T1204.002 |
| `URL_SHORTENER` | URL shortener masks true destination — common in phishing lures | T1566.002 |
| `SUSPICIOUS_TLD` | High-risk TLD (.xyz, .tk, etc.) heavily used in phishing infrastructure | T1583.001 |
| `MANY_ANOMALIES` | Multiple header anomalies suggest crafted/spoofed email | T1566.001 |
| `NO_AUTH_HEADERS` | No SPF/DKIM/DMARC — email from unvalidated source | T1566.001 |
| `YARA_MATCH` | Content matches known phishing/malware pattern | T1566 |

## Sentinel Integration (Production Architecture)

In a production deployment, all detection events map to the `BrowserPhishingTelemetry_CL` custom log table in Microsoft Sentinel:

| Field | Type | Description |
|-------|------|-------------|
| `TimeGenerated` | datetime | Event timestamp |
| `EventType_s` | string | Detection event type (e.g., `OAUTH_DEVICE_CODE_FLOW`) |
| `RiskScore_d` | double | Numeric risk score from detector |
| `Severity_s` | string | Critical / High / Medium / Low |
| `Signals_s` | string | Comma-separated signal list |
| `TabId_d` | double | Browser tab ID |
| `URL_s` | string | Truncated URL (first 500 chars) |
| `ExtensionVersion_s` | string | PhishOps extension version |

KQL queries for each detection type are documented in the wave-specific `BrowserPhishingTelemetry_CL.md` files.
