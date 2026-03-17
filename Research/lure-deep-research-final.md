# Lure — Deep Research Compendium
## Phishing Analysis & IOC Extraction Platform
### February 2026 · Fevra Security Portfolio

---

> **Purpose of this document:** Ground-truth research across all six implementation dimensions of Lure, compiled from live source analysis of production tools, current academic papers, active GitHub repositories, and API documentation. Use this before writing a single line of code.

---

## Table of Contents

1. [What Lure Must Do — The L1/L2 Analyst Contract](#analyst-contract)
2. [Dimension A — Email Parsing & Header Forensics](#dimension-a)
3. [Dimension B — IOC Extraction](#dimension-b)
4. [Dimension C — YARA Scanning Architecture](#dimension-c)
5. [Dimension D — Threat Intelligence Enrichment APIs](#dimension-d)
6. [Dimension E — Risk Scoring & Verdict Engine](#dimension-e)
7. [Dimension F — Output Formats & SOC Integration](#dimension-f)
8. [Frontier Research: LLM-Powered Analysis Layer](#llm-layer)
9. [Gap Analysis: What Lure Tackles That Reference Tools Miss](#gap-analysis)
10. [Master Library Reference](#library-reference)
11. [Master Repository Reference](#repo-reference)
12. [API Keys Required Before Building](#api-keys)

---

## 1. What Lure Must Do — The L1/L2 Analyst Contract {#analyst-contract}

The design contract for Lure is precise: **every manual click a Tier-1 analyst makes on a suspicious email should be replaceable by a single Lure command.** The full L1 workflow is:

```
Receive report → Open .eml → Read headers → Check SPF/DKIM/DMARC →
Identify originating IP → Look up IP in AbuseIPDB → Extract URLs from body →
Submit URLs to VirusTotal → Open attachments → Run olevba / pdfid →
Check file hash in VT → Document findings → Assign risk verdict → Escalate or close
```

Lure automates this entire sequence. The time-to-verdict for an L1 analyst on a typical phishing email is currently 15–45 minutes of manual work. Lure's target is under 90 seconds with a complete structured report.

The pipeline in full:

```
.eml / .msg input
        │
        ▼
┌─────────────────────┐
│  A. HEADER PARSER   │  SPF · DKIM · DMARC · Received chain · Reply-To · X-Originating-IP
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  B. IOC EXTRACTOR   │  URLs · IPs · Domains · Hashes · Emails · Crypto wallets
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  C. YARA SCANNER    │  Attachment decompression · Layer scanning · Rule matching
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  D. ENRICHMENT      │  VT · AbuseIPDB · Shodan · urlscan.io · OTX · WHOIS · URLhaus
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  E. VERDICT ENGINE  │  Weighted signal scoring → CLEAN / SUSPICIOUS / PHISHING / MALICIOUS
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  F. OUTPUT          │  JSON · HTML · STIX 2.1 · MISP Event · TheHive Case
└─────────────────────┘
```

---

## 2. Dimension A — Email Parsing & Header Forensics {#dimension-a}

### The Core Problem

`.eml` files are RFC 5322 multi-part MIME documents. The `From:` display name is trivially spoofed. The `Received:` chain tells the real routing story — read it bottom-to-top to find the true originating IP. The `Authentication-Results` header, added by the receiving mail server, summarizes SPF/DKIM/DMARC outcomes and is the fastest first-pass triage signal.

### What to Parse and Why

**SPF (Sender Policy Framework):** Lists which IPs are authorized to send for a domain. An `spf=fail` means the sending IP is not in the domain's SPF record — high phishing signal. Implementation: query the sender domain's TXT records, evaluate the sending IP against the SPF macro syntax using `pyspf`.

**DKIM (DomainKeys Identified Mail):** A cryptographic signature in the `DKIM-Signature` header. Verify by fetching the public key from `selector._domainkey.domain` DNS TXT record and validating the signature over the message body hash. Implementation: `dkimpy`.

**DMARC Alignment:** The critical step most analysts miss. DMARC requires that either SPF or DKIM pass *and* the authenticated domain aligns with the visible `From:` domain. A phishing email can pass SPF if sent through a legitimate relay — DMARC alignment catches this because the relay's domain won't match the claimed `From:`. Implementation: `checkdmarc`.

**Received Chain Analysis:** Walk `Received:` headers from bottom (first added, closest to origin) to top (added by the receiving server). Extract IP addresses from `from` clauses. Flag: residential ISP ASNs, unexpected geographies, unusually long chains (>6 hops is suspicious), unauthenticated relays (`with SMTP` without `ESMTPA`).

**Reply-To Mismatch:** `From: support@paypal.com` with `Reply-To: attacker@proton.me` is nearly diagnostic of credential phishing. Always flag this.

**X-Originating-IP / X-Mailer:** Consumer email clients (Outlook, Thunderbird) add these. Enterprise gateways typically strip them. If present, they reveal the actual sending machine or mail client version.

### Outlook .msg Files — Critical Implementation Note

`.msg` files are **not** RFC 822. They use Microsoft's proprietary OLE Compound Binary Format. `msgconvert` (the common Unix tool) introduces header artifacts that break forensic analysis. Use `extract-msg` directly — it reads the OLE structure natively without conversion.

### Python Library Stack (Header Forensics)

| Library | PyPI | Purpose | Notes |
|---|---|---|---|
| `mail-parser` | `mail-parser` | Full .eml/.msg parsing, attachment extraction | Best high-level parser; handles MIME edge cases |
| `email` | stdlib | MIME base parser | Always the underlying layer |
| `extract-msg` | `extract-msg` | Outlook .msg parsing | Required for corporate email workflows |
| `pyspf` | `pyspf` | SPF DNS validation | Needs `dnspython` |
| `dkimpy` | `dkimpy` | DKIM signature verification | Handles relaxed/strict canonicalization |
| `checkdmarc` | `checkdmarc` | DMARC + SPF + MX audit | Returns structured dict, easy to parse |
| `dnspython` | `dnspython` | DNS resolution | Foundation for all auth checks |
| `eml-parser` | `eml-parser` | Alternative .eml parser with JSON output | Good for pipeline integration |

### Reference Implementations

**njodzela/phishing-analyzer** — The closest existing tool to Lure's design. Built February 2026 by a SOC analyst with 5+ years experience. Implements the exact parse → validate → extract → enrich → score → report pipeline with terminal + HTML output. Architecture study is essential before building Lure.

**oussamamellakh/Phishing-Email-Detection-Tool** — Focused on header forensics scoring: SPF/DKIM/DMARC, Return-Path mismatch, Received chain anomalies, URL shortener detection. Good scoring model to reference.

**usnistgov/dmarc-tester** — NIST's own SPF/DKIM/DMARC test harness. Shows production-grade implementation of the DMARC milter protocol with SQLite result storage. Useful for understanding the authentication result format.

### Pitfalls

- Never trust `Authentication-Results` headers added by relay servers — only trust the one added by the final receiving server (topmost in the chain).
- SPF with `~all` (softfail) is not the same as `-all` (hardfail). Many legitimate bulk senders use `~all`. Weight accordingly.
- DKIM failure doesn't always mean phishing — signatures can break in legitimate forwarding chains. Weight DMARC alignment more heavily than raw DKIM pass/fail.

### Frontier: LLM Routing Anomaly Detection

Feed the full `Received:` chain to a local Ollama model (qwen2.5:7b) and ask: "Does this email's routing path match the infrastructure you'd expect from the claimed sender domain?" Regex cannot catch "this email claims to be from Citibank but was relayed through a residential Comcast IP in rural Ohio." LLM geographical and infrastructure reasoning can.

---

## 3. Dimension B — IOC Extraction {#dimension-b}

### The Core Problem

Phishing emails embed IOCs everywhere: plain text body, HTML body (with real URLs hidden behind anchor text), inline images (tracking pixels), attachments (PDFs with embedded URLs, Office docs with macros, ZIPs with executables). IOC extraction must cover all surfaces.

**The Anchor Text Trap:** The most common extraction mistake. The *visible* URL in an HTML email (`https://paypal.com/verify`) and the *actual href* (`https://evil.ru/steal?redirect=paypal`) are different. Always extract from `href`/`src` attributes using BeautifulSoup, not from rendered text. Regex on raw HTML body will catch both — but you must track which is display vs. destination.

**The Defang Problem:** Analysts defang IOCs in reports to prevent accidental clicks (`hxxps://evil[.]com`, `198[.]51[.]100[.]1`). `iocextract` handles 20+ defang variants including: `[.]`, `(.)`, `[dot]`, `(dot)`, `hxxp`, `hXXp`, HTML entity encoding of dots, base64-encoded URLs in query parameters. Always use `refang=True` before enrichment.

### IOC Types Lure Must Extract

From the email itself:
- **IPv4/IPv6 addresses** — in headers (originating IP), body, attachments
- **Domains and FQDNs** — with TLD validation against IANA public suffix list
- **URLs** — including encoded variants (URL encoding, base64 in params, Unicode lookalikes)
- **File hashes** — MD5/SHA1/SHA256/SHA512 from any text content
- **Email addresses** — sender, Reply-To, embedded in body text
- **MITRE ATT&CK IDs** — T1566.001 etc. (for threat report analysis mode)
- **Cryptocurrency wallet addresses** — Bitcoin, Ethereum, Monero (common in extortion phishing)

From attachments specifically:
- **Embedded URLs in PDFs** — via `pdfplumber`
- **Embedded URLs in Word/Excel** — via `python-docx` + `oletools`
- **VBA macro code** — via `olevba` (extract for display, never execute)
- **XLM macros (Excel 4.0)** — via `XLMMacroDeobfuscator`
- **Embedded objects / OLE streams** — via `oleobj`

### IOC Extraction Library Stack

| Library | PyPI | Purpose | Notes |
|---|---|---|---|
| `iocextract` | `iocextract` | Defanged IOC extraction — the standard | Handles 20+ defang variants; supports base64 URLs |
| `iocsearcher` | `iocsearcher` | Academic-grade extractor with validation | Best precision; deduplicates across defang variants |
| `ioc-fanger` | `ioc-fanger` | Bidirectional fang/defang | Test page at ioc-fanger.hightower.space |
| `beautifulsoup4` | `beautifulsoup4` | HTML parsing for href/src extraction | Essential for HTML body IOC extraction |
| `pdfplumber` | `pdfplumber` | PDF text + URL extraction | Better than PyPDF2 for embedded URL preservation |
| `python-docx` | `python-docx` | Word document link extraction | |
| `oletools` | `oletools[full]` | VBA macros, OLE streams, RTF objects | Use `[full]` for XLMMacroDeobfuscator support |
| `urlextract` | `urlextract` | URL extraction with TLD validation | Complements iocextract |
| `tldextract` | `tldextract` | Domain parsing + punycode handling | Required for homograph detection |

### The `iocsearcher` Advantage

`iocsearcher` (MaliciaLab/IMDEA Software Institute) is the academically evaluated standard. Key differentiators over `iocextract`:
- Validates extracted IOCs (domain TLD check, IP range validation) — dramatically reduces false positives
- Deduplicates across defang variants (same domain, different defanging = one result)
- Configurable regex via INI file — extend without modifying library code
- Published evaluation against competing tools in the *Future Generation Computer Systems* journal (2023)

Use `iocextract` for speed and base64 URL support; use `iocsearcher` as the primary extractor with validation layer.

### Multi-Hop Redirect Chain Following (Frontier)

Phishing kits increasingly use legitimate services as the first URL hop: Google Redirect (`/url?q=`), LinkedIn open redirects, Salesforce tracking URLs, Firebase Dynamic Links. The first URL is clean by every threat intel feed. Lure must follow redirect chains to the terminal destination before enrichment. Implementation: `requests` with `allow_redirects=False`, follow manually, stop at depth 5 or at known CDN/tracking domains. Log every hop.

---

## 4. Dimension C — YARA Scanning Architecture {#dimension-c}

### The Core Problem

Attachments are the highest-severity phishing vector. YARA is the industry standard for binary pattern matching against known malware families, phishing kit structures, and suspicious document patterns. The key architectural decisions determine whether YARA is useful or noisy.

### Architecture Decisions (Do These Right)

**1. Scan every MIME part, not just named attachments.** Multi-part email bodies include inline images, text/html parts, and application/* parts that are not "attachments" by MIME definition but may contain malicious content.

**2. Decompress before scanning.** ZIP/RAR/7z archives are the most common evasion technique. A ZIP containing `invoice.exe` renamed to `invoice.pdf` will not match YARA rules for executables unless decompressed first. Use Python's `zipfile`, `rarfile`, `py7zr` to extract before scanning. Handle nested archives (ZIP inside ZIP) recursively up to depth 3.

**3. Detect file type by magic bytes, not extension.** `python-magic` reads the file header (magic bytes) to determine the true file type. An `.exe` renamed to `.pdf` is detected correctly. Never trust file extensions.

**4. Use yaramail's four-scan model.** The `yara-mail` library scans: (a) email headers, (b) email body, (c) each attachment separately, (d) normalized body content. This model is purpose-built for email triage and avoids cross-contamination between rule sets.

**5. Compile rules once, scan many.** YARA rule compilation is expensive (~100ms for a large ruleset). Use `yara.compile(filepath='rules/')` once at startup, cache the compiled rules object, and reuse it for every scan in the session.

**6. Manage rules as a versioned directory tree.** Never use a single monolithic `.yar` file. Structure:

```
lure/rules/
    phishing/           ← phishing kit patterns, credential harvesting
        generic_phishing.yar
        phishing_kits.yar
    malware/            ← malware family detection
        ransomware/
        infostealer/
        trojan/
    documents/          ← document-specific rules
        office_macros.yar
        pdf_suspicious.yar
    custom/             ← Lure-generated rules from --learn mode
```

### YARA Rule Sources (All Open Source, All Bundle-Worthy)

| Repository | Stars | Contents | Update Frequency |
|---|---|---|---|
| Neo23x0/signature-base | ~5k | Florian Roth's comprehensive ruleset — the gold standard | Active |
| InQuest/yara-rules | ~1k | InQuest's regularly updated rules | Active |
| ReversingLabs/reversinglabs-yara-rules | ~600 | Ransomware + malware families | Active |
| kevoreilly/CAPEv2 | ~2k | Sandbox-derived rules from real malware detonations | Very Active |
| t4d/PhishingKitHunter | ~500 | Phishing kit ZIP detection via raw ZIP format analysis — unique | Active |
| InQuest/awesome-yara | ~4k | Curated list of every major ruleset | Active |

**The YARA-CI integration** (GitHub App at `YARA-CI`) provides continuous testing for rule repos — validates rules catch intended samples and don't false-positive on clean files. Run Lure's custom rules through YARA-CI before shipping.

### YARA Python Library Stack

| Library | PyPI | Purpose |
|---|---|---|
| `yara-python` | `yara-python` | Official Python YARA bindings — compile + scan |
| `yara-mail` | `yara-mail` | Email-specific YARA scanner — four-part scan model |
| `python-magic` | `python-magic` | File type detection by magic bytes |
| `py7zr` | `py7zr` | Pure-Python 7z extraction |
| `rarfile` | `rarfile` | RAR extraction (requires `unrar` system binary) |
| `zipfile` | stdlib | ZIP extraction |

### Pitfall: Platform-Specific Compiled Rules

Compiled YARA rule objects (`.yarc` files) are platform-specific and cannot be shared between Linux/macOS/Windows. Always distribute source `.yar` files and compile at runtime. Cache the compiled object in memory during the session, not to disk.

### Frontier: Automated Rule Generation with `--learn` Mode

`yarGen` (Neo23x0) generates YARA rules from PE files automatically. Lure's `--learn` flag should: accept a confirmed phishing sample → run yarGen → present the generated rule to the analyst for review → on approval, add to `lure/rules/custom/`. This converts every confirmed detection into future detection capability.

---

## 5. Dimension D — Threat Intelligence Enrichment APIs {#dimension-d}

### Design Principle: The Enrichment Layer Must Be Resilient

All enrichment must be: (1) cached locally with TTL, (2) deduplicated before API calls, (3) parallelized with per-API rate limit semaphores, (4) gracefully degraded — missing keys skip that source, never crash.

The cache pattern:

```python
async def enrich_with_cache(ioc: str, api_fn, ttl_hours: int = 48) -> dict:
    cache_key = f"{api_fn.__name__}:{ioc}"
    cached = sqlite_cache.get(cache_key)
    if cached and not is_expired(cached, ttl_hours):
        return cached['result']
    result = await api_fn(ioc)
    sqlite_cache.set(cache_key, result)
    return result
```

### VirusTotal v3 API

The authoritative multi-AV and threat intelligence platform. VT API v3 is the current default — v2 will not be deprecated but v3 provides MITRE ATT&CK TTP mapping, richer context, and relationship data.

**Key endpoints:**
- `/files/{sha256}` — file reputation by hash
- `/urls` (POST) → poll `/analyses/{id}` — submit URL for fresh scan
- `/domains/{domain}` — domain reputation, categories, WHOIS, subdomains
- `/ip_addresses/{ip}` — IP reputation, ASN, associated files, URLs

**Key response fields:**
- `last_analysis_stats.malicious` — count of engines flagging malicious
- `last_analysis_stats.suspicious` — count flagging suspicious
- `reputation` — VT's aggregate score (-100 to +100)
- `tags` — malware family tags assigned by community
- `last_analysis_results` — per-engine breakdown

**Rate limits:** Free = 4 requests/min, 500/day. Implement with `asyncio.Semaphore(4)` on a 60-second rolling window.

**Critical practice:** For URLs, always do both: (1) check existing report via URL ID, (2) submit for fresh scan if no recent report. A new phishing URL will have zero VT hits but submitting creates the analysis record for the community.

**Python client:** `vt-py` (official VirusTotal library, async-native)

### AbuseIPDB API v2

The most useful single API for IP reputation in L1 triage contexts.

**Key endpoint:** `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90`

**Key response fields:**
- `abuseConfidenceScore` — 0 to 100, community consensus on maliciousness
- `totalReports` — volume of community reports
- `lastReportedAt` — recency of most recent report
- `usageType` — "Data Center/Web Hosting/Transit", "ISP", "Tor Network" etc.
- `isp` / `domain` — hosting organization
- `countryCode` — originating country

**Rate limits:** Free = 1000 req/day. No official Python client — wrap `requests`.

**Tip:** `maxAgeInDays=90` is the sweet spot. Shorter windows miss campaigns that paused; longer windows produce false positives from reassigned IPs.

### Shodan API

Use Shodan for IP *context* — what is this IP actually running? Is it a C2 server, a Tor exit node, an exposed Redis instance, or a home router?

**Key endpoint:** `GET /shodan/host/{ip}`

**Key response fields:**
- `org` — organization name
- `isp` — internet service provider
- `asn` — autonomous system number
- `country_name` — geolocation
- `ports` — open ports at last scan
- `data[].product` / `data[].version` — service banners
- `vulns` — CVEs associated with detected services

**Python client:** `shodan` (official)

**Strategic use:** Distinguish "this IP is a known Tor exit node" from "this IP is a compromised home router running a phishing kit." The Shodan infrastructure story is essential for attribution and severity scoring.

### urlscan.io API

The most underused API in typical phishing pipelines. urlscan renders the page in a headless browser and returns a full DOM analysis, screenshot, and all network requests made by the page — revealing phishing kit behavior regardless of VT reputation.

**Flow:**
1. `POST /api/v1/scan/` with `{url, visibility: "public"}` → returns `uuid`
2. Wait ~15–30 seconds
3. `GET /api/v1/result/{uuid}/` → full analysis JSON

**Key response fields:**
- `page.title` — page title (often reveals the impersonated brand)
- `lists.urls` — all URLs loaded by the page (reveals tracking, CDN, exfiltration)
- `lists.certificates` — TLS certificate details
- `stats.domainStats` — domains contacted during page load
- `verdicts.urlscan.score` — urlscan's own maliciousness score
- `verdicts.urlscan.categories` — `["phishing"]`, `["malware"]` etc.

**Phishing kit fingerprint:** A urlscan result with `page.title` containing "PayPal" or "Microsoft" for a non-PayPal/Microsoft domain, combined with `<input type="password">` in the page DOM = confirmed credential harvesting phishing kit, regardless of VT status.

**Rate limits:** Free = 1000 private scans/day, unlimited public scans.

### AlienVault OTX (Open Threat Exchange)

Free, community-maintained threat intelligence. Query by IP, domain, URL, file hash. Returns "pulses" — community threat reports with IOC sets, malware family tags, and attribution.

**Python client:** `OTXv2`

**Best use:** As a final validation layer. If VT shows 0 detections but OTX has a pulse for the domain from a recent threat report, that's a high-confidence signal.

### Supplementary APIs

| API | PyPI / Access | Purpose | Rate Limit |
|---|---|---|---|
| URLhaus (abuse.ch) | Direct HTTP | Malware distribution URLs — real-time feed | Unlimited |
| PhishTank | `requests` + API key | Community-verified phishing URLs | 1000/day |
| Google Safe Browsing v4 | `requests` + API key | URL reputation from browser blocklists | 10k/day |
| ipwhois | `ipwhois` | ASN + org for any IP — no key needed | Unlimited |
| python-whois | `python-whois` | Domain registration date + registrar | Unlimited (rate-limited) |
| MXToolbox | `requests` | SPF/DKIM/DMARC detailed validation | Limited free |

**Domain age from WHOIS** is one of the highest-signal features for zero-day phishing detection. A domain registered in the last 7 days with a VT-clean URL is still extremely high-risk. Always extract `creation_date` from WHOIS.

---

## 6. Dimension E — Risk Scoring & Verdict Engine {#dimension-e}

### Signal Normalization

Every signal is normalized to 0–1 scale and multiplied by its weight. The raw weighted sum maps to a verdict.

### Complete Signal Table (Weighted)

| Signal | Weight | Rationale |
|---|---|---|
| **DMARC fail** | 2.5 | Highest single header signal — requires From: domain mismatch |
| **YARA match on attachment** | 4.0 | Known malware pattern — near-certain malicious |
| **VT URL: any engine malicious** | 3.0 | Near-certain if any reputable engine flags |
| **urlscan credential harvesting form** | 2.5 | Password input on non-org domain = phishing kit |
| **AbuseIPDB score > 75** | 2.5 | High community consensus on IP maliciousness |
| **SPF fail** | 2.0 | Strong sender spoofing signal |
| **Reply-To mismatch** | 2.0 | Nearly diagnostic of credential phishing |
| **Homograph domain detected** | 2.0 | Unicode lookalike domain — sophisticated attack |
| **DKIM fail** | 1.5 | Weaker alone; significant in combination |
| **Domain age < 7 days** | 1.5 | Newly registered domains heavily used in phishing |
| **VT URL: suspicious** | 1.0 | Softer signal — needs corroboration |
| **OTX pulse match** | 1.0 | Community threat report exists |
| **AbuseIPDB score 25–75** | 0.8 | Moderate IP reputation concern |
| **Phishing keyword in subject** | 0.5 | "urgent", "verify", "suspend", "limited time" |
| **URL shortener in body** | 0.5 | Weak — common in legitimate bulk email |
| **Suspicious domain TLD** | 0.3 | .xyz, .top, .click, .loan — common phishing TLDs |
| **No DMARC record exists** | 0.3 | Absence of DMARC is not phishing, but is a risk factor |

### Verdict Thresholds and L1 Actions

| Score Range | Verdict | Color | L1 Action |
|---|---|---|---|
| 0.0 – 3.0 | **CLEAN** | Green | Close ticket, log for metrics |
| 3.0 – 5.0 | **SUSPICIOUS** | Yellow | Escalate to L2 for manual review |
| 5.0 – 8.0 | **LIKELY PHISHING** | Orange | Quarantine email, notify user's manager, block domain |
| 8.0+ | **CONFIRMED MALICIOUS** | Red | Immediate block, MISP IOC submission, CIRT notification |

### Homograph Detection Implementation

Internationalized domain names (IDNs) substitute visually identical Unicode characters: `а` (Cyrillic U+0430) for `a` (Latin U+0061), `о` (Cyrillic) for `o`, `е` (Cyrillic) for `e`. `pаypal.com` != `paypal.com`.

Implementation:
```python
import unicodedata

def detect_homograph(domain: str) -> bool:
    # Check for mixed script usage — legitimate domains don't mix Cyrillic and Latin
    scripts = set()
    for char in domain:
        if char.isalpha():
            name = unicodedata.name(char, '')
            if 'LATIN' in name: scripts.add('LATIN')
            elif 'CYRILLIC' in name: scripts.add('CYRILLIC')
            elif 'GREEK' in name: scripts.add('GREEK')
    return len(scripts) > 1  # Mixed scripts = homograph attack
```

`tldextract` correctly handles punycode (`xn--pypal-4ve.com` = `рaypal.com`), essential for IDN detection.

### The Zero-Day Window Problem

The most important pitfall: **never return CLEAN based on VT alone.** A freshly registered phishing domain will have zero VT detections for 24–72 hours — the window when a campaign is most active. During this window:

1. Domain age < 7 days from WHOIS → weight 1.5
2. urlscan DOM analysis → reveals credential harvesting form regardless of VT
3. Google Safe Browsing → often catches new phishing faster than VT (browser integration means user reports flow in faster)
4. PhishTank → community submissions often precede automated feeds

Combine these four signals to cover the zero-day window.

---

## 7. Dimension F — Output Formats & SOC Integration {#dimension-f}

### Canonical JSON Schema

All Lure output begins as structured JSON. This is the source of truth from which all other formats are derived.

```json
{
  "lure_version": "1.0.0",
  "schema_version": "1",
  "analysis_timestamp": "2026-02-24T10:00:00Z",
  "email_id": "sha256:abc123...",
  "email_file": "suspicious_invoice.eml",
  "verdict": "LIKELY_PHISHING",
  "risk_score": 7.2,
  "verdict_color": "orange",
  "header_analysis": {
    "from": "support@paypa1.com",
    "reply_to": "attacker@protonmail.com",
    "reply_to_mismatch": true,
    "originating_ip": "185.220.101.45",
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail",
    "received_hops": 4,
    "routing_anomalies": ["Tor exit node as relay"]
  },
  "iocs": {
    "ips": ["185.220.101.45"],
    "domains": ["paypa1.com", "evil-cdn.xyz"],
    "urls": ["https://paypa1.com/verify?token=abc"],
    "hashes": {"sha256": ["deadbeef..."]},
    "emails": ["attacker@protonmail.com"]
  },
  "enrichment": {
    "virustotal": {"185.220.101.45": {"malicious": 12, "reputation": -75}},
    "abuseipdb": {"185.220.101.45": {"score": 97, "reports": 1247}},
    "shodan": {"185.220.101.45": {"org": "Frantech Solutions", "tags": ["tor"]}},
    "urlscan": {"https://paypa1.com/verify": {"verdict": "malicious", "has_password_field": true}},
    "whois": {"paypa1.com": {"creation_date": "2026-02-22", "age_days": 2}}
  },
  "yara_matches": [
    {
      "rule": "Phishing_PayPal_Kit_Generic",
      "ruleset": "signature-base",
      "attachment": "invoice.zip/invoice.html",
      "strings_matched": ["PayPal.com security", "verify your account"]
    }
  ],
  "attachment_analysis": {
    "invoice.zip": {
      "type": "application/zip",
      "size_bytes": 4821,
      "contains": ["invoice.html"],
      "yara_matches": 1
    },
    "invoice.html": {
      "type": "text/html",
      "vba_macros": false,
      "embedded_urls": ["https://paypa1.com/verify"],
      "suspicious_elements": ["password_field", "credit_card_field"]
    }
  },
  "analyst_summary": "This email exhibits strong phishing indicators. The sending domain paypa1.com (homograph of paypal.com, registered 2 days ago) fails SPF and DMARC. The originating IP is a known Tor exit node with 1,247 AbuseIPDB reports. The attached HTML file is a PayPal credential harvesting kit matching known YARA signatures. Recommended action: quarantine and block domain.",
  "signals_fired": [
    {"signal": "dmarc_fail", "weight": 2.5},
    {"signal": "yara_attachment_match", "weight": 4.0},
    {"signal": "homograph_domain", "weight": 2.0},
    {"signal": "domain_age_lt_7_days", "weight": 1.5}
  ]
}
```

### STIX 2.1 Output

STIX 2.1 is the interchange format for sharing with MISP, TheHive, and commercial TIPs. The February 2025 MISP update added full STIX 2.1 Note and Opinion object support — analyst commentary and confidence scores now travel with the IOC data.

**Lure → STIX mapping:**
- Extracted URLs → `url` Indicator with `pattern: "[url:value = 'https://...']"`
- IPs → `ipv4-addr` Observed Data
- Domains → `domain-name` Indicator
- File hashes → `file` with `hashes.SHA-256`
- Verdict explanation → `note` (new in STIX 2.1)
- Campaign (if multi-email correlation) → `campaign` SDO

**Python:** `stix2` (OASIS official, actively maintained)

MISP conversion: `misp-stix` library (MISP project) — bidirectional MISP ↔ STIX 2.1 conversion, updated February 2025.

### TheHive Integration

TheHive is the leading open-source SOAR/case management platform for SOCs. The integration pattern (from ThePhish reference implementation):

1. `thehive4py` → Create Case with `title`, `description`, `severity`, `tags`
2. Add Observables (IOCs) to the case → `ip`, `url`, `domain`, `hash`, `mail` observable types
3. Trigger Cortex Analyzers on each observable:
   - `VirusTotal_GetReport_3_0` → VT reputation
   - `AbuseIPDB` → IP abuse score
   - `URLScan_io_Scan_0_1` → DOM analysis
   - `Shodan_DNSScan_1_0` → infrastructure context

**Python clients:** `thehive4py` (Case/Observable creation) + `cortex4py` (Analyzer triggering)

### MISP Integration

After Lure confirms a campaign, auto-submit the IOC set to the team's MISP instance as a MISP Event for sharing with trust partners.

```python
from pymisp import MISPEvent, MISPAttribute, PyMISP
misp = PyMISP(url, key, ssl=True)
event = MISPEvent()
event.info = f"Lure: Phishing Campaign [{verdict}] {datetime.now()}"
event.add_tag('phishing')
event.add_attribute('ip-dst', originating_ip)
event.add_attribute('domain', sender_domain)
for url in malicious_urls:
    event.add_attribute('url', url)
misp.add_event(event)
```

**Tool:** `mail_to_misp` — connects a mail client/inbox directly to MISP. Lure could expose an SMTP endpoint that accepts forwarded suspicious emails and automatically creates MISP events.

### HTML Report Requirements

The HTML report is what L1 analysts actually look at during a shift. Requirements:
- Color-coded verdict banner (green/yellow/orange/red) — visible from across the room
- Sender/Reply-To mismatch highlighted in red if present
- SPF/DKIM/DMARC result badges with traffic-light colors
- Clickable IOC table with enrichment score badges
- YARA match panel with rule name, ruleset, matched strings preview
- Received chain hop-by-hop routing diagram (text-art or simple SVG)
- Attachment analysis panel with macro/suspicious element flags
- One-click "Copy all IOCs to clipboard" button (JSON format for SIEM paste)
- Export to PDF button (for ticket attachment, `weasyprint` library)

---

## 8. Frontier Research: LLM-Powered Analysis Layer {#llm-layer}

### The State of the Art (February 2026)

LLM integration in phishing analysis is no longer experimental — it's production-proven. Three distinct LLM architectures have been evaluated in academic and production contexts:

**1. Single-Agent Verdict Explanation (Recommended for Lure v1)**

The simplest integration. After the rule-based scoring engine produces a numerical verdict, pass the structured findings to a local Ollama model and ask it to generate a one-paragraph analyst-readable summary explaining *why* this email is malicious and what the likely attack scenario is. Eliminates the "translate scores into words" step for L1 analysts.

Implemented with:
```python
# Via Ollama OpenAI-compatible endpoint + instructor library
client = instructor.from_openai(
    OpenAI(base_url="http://127.0.0.1:11434/v1", api_key="ollama"),
    mode=instructor.Mode.JSON
)
response = client.chat.completions.create(
    model="qwen2.5:7b",  # or llama3.2
    messages=[{"role": "user", "content": analysis_context}],
    response_model=AnalystSummary  # Pydantic model for structured output
)
```

**Security note:** Cisco Talos (September 2025) found 1,100+ Ollama servers publicly exposed. Always bind Ollama to localhost (default port 11434) and never expose it externally.

**2. Multi-Agent Debate Framework (PhishDebate architecture)**

A three-agent system where two agents argue for/against phishing classification and a judge agent renders the final verdict. Published June 2025 (arxiv 2506.15656). Achieves better detection of subtle social engineering cues than single-agent classification. More compute-intensive — appropriate for L2 escalation review, not L1 triage.

**3. MultiPhishGuard (Five-Agent Architecture)**

Text Agent + URL Agent + Metadata Agent + Adversarial Agent + Rationale Simplifier, coordinated via PPO reinforcement learning. Presented at ACM CCS 2025. The most sophisticated published architecture — appropriate as a research target for Lure v2.

**4. EXPLICATE Framework**

ML classifier (domain features) + dual explainability layer (LIME + SHAP) + LLM (DeepSeek v3) for natural language translation of technical findings. 98.4% accuracy on test set. Published March 2025 (arxiv 2503.20796). The LIME+SHAP layer is particularly valuable — it tells the analyst *which specific features* drove the verdict.

### Recommended Lure v1 LLM Integration

Use the **Instructor + Ollama** pattern with `qwen2.5:7b` for:
1. Header routing anomaly detection (feed Received chain → ask for geographical/infrastructure analysis)
2. Verdict explanation generation (feed full analysis JSON → ask for analyst summary paragraph)
3. Suspicious keyword semantic analysis (go beyond keyword lists to semantic phishing intent detection)

The Pydantic model for structured output:
```python
class AnalystSummary(BaseModel):
    verdict_explanation: str  # One paragraph, analyst-readable
    attack_scenario: str      # "Credential harvesting", "Malware delivery", "BEC" etc.
    recommended_actions: list[str]  # Specific L1 actions
    confidence: float         # 0.0–1.0 model confidence in explanation
```

---

## 9. Gap Analysis: What Lure Tackles That Reference Tools Miss {#gap-analysis}

The existing landscape (ThePhish, phishing-analyzer, oussamamellakh's tool) leaves four meaningful gaps:

**Gap 1: Static Attachment Detonation Without a Sandbox**

Full sandboxes (Cuckoo, Any.Run) are heavyweight infrastructure. Lure achieves 80% of sandbox signal through static analysis:
- `olevba` — extract and display VBA macro source code (never execute); flag suspicious keywords (`Shell`, `WScript`, `CreateObject`, `AutoOpen`, `Document_Open`)
- `pdfid` (Didier Stevens) — score PDFs for suspicious elements: `/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`
- `pdf-parser` (Didier Stevens) — extract embedded objects and streams from PDFs
- `XLMMacroDeobfuscator` (part of oletools[full]) — deobfuscate Excel 4.0 XLM macros, which evade standard VBA detection

**Gap 2: DOM-Level Phishing Kit Detection via urlscan**

Most tools check "is this URL in a blocklist?" Fewer check "what does this page actually do?" urlscan returns DOM structure, form inputs, and page title. A freshly registered domain with zero VT hits that renders a PayPal login form is a confirmed phishing kit. Lure's urlscan integration must extract and flag `<input type="password">` presence, form `action` URLs pointing to non-org domains, and brand-impersonation keywords in page title/body.

**Gap 3: Campaign Correlation Across Multiple Emails**

SOC shared mailboxes receive multiple forwarded reports of the same campaign. 10 separate Lure analyses of the same campaign should be grouped, not treated as 10 independent incidents. Implementation: SQLite storage of all analyzed IOC sets → Jaccard similarity score across IOC sets → group emails scoring >0.7 similarity into a single campaign record.

**Gap 4: MCP Server Exposure for Agent-Driven Analysis**

Consistent with the Fevra portfolio's cross-cutting MCP-first direction: expose Lure's analysis functions as MCP tools:
- `lure_analyze_email(path: str) -> AnalysisResult`
- `lure_lookup_ioc(indicator: str) -> EnrichmentResult`
- `lure_get_verdict(email_hash: str) -> VerdictResult`
- `lure_get_campaigns() -> list[Campaign]`

This positions Lure as an agentic building block that Claude Code or another orchestration layer can call as part of a larger security workflow.

---

## 10. Master Library Reference {#library-reference}

### Installation Block (All Lure Dependencies)

```bash
pip install \
    mail-parser \
    extract-msg \
    pyspf \
    dkimpy \
    checkdmarc \
    dnspython \
    eml-parser \
    iocextract \
    iocsearcher \
    ioc-fanger \
    beautifulsoup4 \
    pdfplumber \
    python-docx \
    oletools[full] \
    urlextract \
    tldextract \
    yara-python \
    yara-mail \
    python-magic \
    py7zr \
    rarfile \
    vt-py \
    shodan \
    OTXv2 \
    ipwhois \
    python-whois \
    stix2 \
    pymisp \
    thehive4py \
    cortex4py \
    requests \
    aiohttp \
    asyncio \
    instructor \
    ollama \
    weasyprint \
    jinja2
```

---

## 11. Master Repository Reference {#repo-reference}

| Repository | URL | Stars | Use in Lure |
|---|---|---|---|
| ThePhish | emalderson/ThePhish | ~900 | Full pipeline architecture reference |
| phishing-analyzer | njodzela/phishing-analyzer | Active | Closest design analog — study first |
| iocextract | InQuest/iocextract | ~1.5k | IOC extraction library |
| iocsearcher | malicialab/iocsearcher | Active | Academic-grade IOC extraction |
| ThreatIngestor | InQuest/ThreatIngestor | ~1k | IOC pipeline architecture |
| awesome-yara | InQuest/awesome-yara | ~4k | YARA ecosystem map |
| signature-base | Neo23x0/signature-base | ~5k | Primary YARA ruleset |
| reversinglabs-yara | ReversingLabs/reversinglabs-yara-rules | ~600 | Ransomware/malware YARA rules |
| PhishingKitHunter | t4d/PhishingKitHunter | ~500 | Phishing kit ZIP YARA rules |
| CAPEv2 | kevoreilly/CAPEv2 | ~2k | Sandbox-derived YARA rules |
| oletools | decalage2/oletools | ~2.5k | Office document static analysis |
| vt-py | VirusTotal/vt-py | Official | VT API v3 Python client |
| misp-stix | MISP/misp-stix | Active | MISP ↔ STIX 2.1 conversion |
| awesome-iocs | sroberts/awesome-iocs | ~1k | IOC feed ecosystem map |
| mail_to_misp | MISP/mail_to_misp | Active | Mail → MISP event automation |

---

## 12. API Keys Required Before Building {#api-keys}

Obtain all keys before writing the enrichment module:

| Service | URL | Free Tier | Key Type |
|---|---|---|---|
| VirusTotal | virustotal.com/gui/sign-in | 4 req/min, 500/day | `VT_API_KEY` |
| AbuseIPDB | abuseipdb.com/account/api | 1000 req/day | `ABUSEIPDB_KEY` |
| Shodan | account.shodan.io | 100 queries/mo | `SHODAN_API_KEY` |
| urlscan.io | urlscan.io/user/signup | 1000 private/day | `URLSCAN_KEY` |
| AlienVault OTX | otx.alienvault.com | Unlimited | `OTX_KEY` |
| PhishTank | phishtank.org/api_register | 1000/day | `PHISHTANK_KEY` |
| Google Safe Browsing | console.cloud.google.com | 10k/day | `GSB_KEY` |

All keys stored in `.env`, never hardcoded. Load via `python-dotenv`. Lure gracefully skips any enrichment source whose key is absent.

---

*Last updated: February 2026. Revisit quarterly — phishing kit ecosystem and enrichment API landscape evolve rapidly. The LLM integration section should be reviewed monthly given the pace of development.*
