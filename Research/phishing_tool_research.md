# Phishing Analysis Tool — Deep Research Brief
**For: Mac Calarco | Project Codename: TBD (Lure / Decoy / Bait)**
**Date: February 2026**

---

## 1. The Threat Landscape in 2026

This tool is being built at a critical inflection point. The threat landscape has fundamentally shifted:

- **82.6% of phishing emails** analyzed between Sept 2024–Feb 2025 contained AI-generated content (KnowBe4, 2025)
- **64% of US companies** faced a Business Email Compromise (BEC) scam in 2024
- AI-generated phishing achieves a **60% victim click rate** — on par with human-crafted lures (Harvard research)
- **LLM-powered runtime assembly** is now an emerging vector: attackers embed prompts in webpages that call legitimate LLM APIs to generate polymorphic phishing JavaScript at runtime, making each visit syntactically unique and nearly undetectable by network analysis (Palo Alto Unit42, 2026)
- Research paper *Phish-Master* (Nov 2025) demonstrated a 99% filter evasion rate using Chain-of-Thought LLM prompting against enterprise-level email filters

**What this means for your tool:** Standard regex-based detection is increasingly insufficient. The tool needs behavioral/NLP analysis layers to catch AI-crafted emails that have no typos, clean headers, and no known-bad URLs.

---

## 2. Core Architecture

```
INPUT (.eml / .msg / raw paste)
        │
        ▼
┌─────────────────────┐
│   HEADER ANALYZER   │  SPF, DKIM, DMARC, relay path, spoofing
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│   IOC EXTRACTOR     │  URLs, IPs, hashes, emails, domains (defanged too)
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  THREAT ENRICHMENT  │  VirusTotal, URLScan, AbuseIPDB, PhishTank, OTX
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ ATTACHMENT ANALYZER │  Hash lookup, YARA rules, macro detection, PDF JS
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│   NLP/ML ENGINE     │  Urgency detection, AI-generated text signals,
│                     │  brand impersonation, Cialdini principle scoring
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  SCORING ENGINE     │  Weighted 0-100 phishing risk score
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│     REPORTER        │  JSON, HTML, SARIF, STIX/TAXII export
└─────────────────────┘
```

---

## 3. Libraries — The Core Stack

### Email Parsing
| Library | Purpose | Notes |
|---------|---------|-------|
| `email` | Parse .eml files | Python stdlib, no install needed |
| `extract-msg` | Parse Outlook .msg files | Fills the gap most tools miss |
| `mailparser` | High-level email parsing | Good for header normalization |

### IOC Extraction
| Library | Purpose | Stars |
|---------|---------|-------|
| `iocextract` (InQuest) | Extract & defang IOCs from text | Industry standard |
| `iocsearcher` (malicialab) | IOC extraction from PDF/HTML/Word | Broader format support |
| `tldextract` | Domain parsing | Better than manual regex |
| `dnspython` | DNS lookups, MX/SPF record validation | Essential for header auth |

### Attachment Analysis
| Library | Purpose | Notes |
|---------|---------|-------|
| `oletools` | Office macro detection, OLE analysis | Most referenced in SOC tooling |
| `yara-python` | YARA rule matching against attachments | Critical for malware sig matching |
| `pdfminer.six` | PDF text/JS extraction | Extract embedded JavaScript |
| `pefile` | PE file analysis | For .exe attachments |
| `hashlib` | MD5/SHA256 hashing | Python stdlib |

### URL & Domain Analysis
| Library | Purpose | Notes |
|---------|---------|-------|
| `requests` / `httpx` | URL following, redirect chains | httpx for async |
| `whois` | Domain age/registration lookup | WHOIS enrichment |
| `Levenshtein` | Edit distance for homoglyph detection | Fast fuzzy matching |
| `unicodedata` | IDN/Punycode homograph detection | Unicode lookalike detection |

### NLP / ML
| Library | Purpose | Notes |
|---------|---------|-------|
| `transformers` (HuggingFace) | LLM-based text classification | AI-generated text detection |
| `scikit-learn` | Classical ML classification (RF, SVM) | Lightweight alternative |
| `nltk` / `spacy` | Urgency/sentiment/NLP analysis | Keyword + linguistic features |
| `lingua-py` | Language detection | Flags non-native language patterns |

### Reporting & Output
| Library | Purpose | Notes |
|---------|---------|-------|
| `jinja2` | HTML report templating | Clean report generation |
| `stix2` | STIX/TAXII IOC export | Enterprise-grade, rare in entry tools |
| `rich` | Terminal output | Consistent with your other tools |

---

## 4. Threat Intelligence APIs

### Tier 1 — Essential (Free Tiers Available)
| API | What It Does | Free Tier | Priority |
|-----|-------------|-----------|----------|
| **VirusTotal** | File/URL/hash scanning across 70+ AV engines | 500 req/day | Critical |
| **URLScan.io** | URL behavioral scan + screenshot | 1,000 req/day | Critical |
| **AbuseIPDB** | IP reputation, community-reported malicious IPs | 1,000 req/day | Critical |
| **PhishTank** | Community phishing URL database | Free | Critical |
| **Google Safe Browsing** | Real-time URL blacklist | Free (10k/day) | High |

### Tier 2 — High Value
| API | What It Does | Free Tier | Priority |
|-----|-------------|-----------|----------|
| **AlienVault OTX** | Community threat intelligence, IOC pulses | Free | High |
| **URLhaus (abuse.ch)** | Malicious URL database | Free | High |
| **EmailRep.io** | Email address reputation scoring | Free tier | High |
| **HaveIBeenPwned** | Check if sender email is in breach data | Free | Medium |
| **MalwareBazaar** | Malicious file hash lookups | Free | Medium |

### Tier 3 — Differentiators
| API | What It Does | Notes |
|-----|-------------|-------|
| **Shodan** | Sender IP infrastructure context | You already use this |
| **CriminalIP** | OSINT-based threat intelligence | Newer, good free tier |
| **SSL Labs** | Certificate analysis on linked domains | Free |
| **WHOIS APIs** | Domain age/registration data | Multiple free options |

**Key insight:** VirusTotal is being absorbed into Google Threat Intelligence (GTI) with pricing increases in 2026. Build your abstraction layer so API providers are swappable — this is an architectural decision that will matter.

---

## 5. Top GitHub Repos to Study

| Repo | Stars | What to Learn From It |
|------|-------|-----------------------|
| **emalderson/ThePhish** | ~1k | Full pipeline architecture: TheHive+Cortex+MISP integration, case management workflow |
| **elceef/dnstwist** | 5.6k | Homograph/typosquatting detection engine — study their domain permutation logic |
| **ninoseki/mihari** | ~1k | IOC hunting framework — structured enrichment pipeline |
| **InQuest/iocextract** | ~700 | Defanged IOC extraction — use this directly as a dependency |
| **Neo23x0/yarGen** | ~1k | YARA rule generation — reference for building your YARA matching module |
| **decalage2/oletools** | 2.7k | Office macro analysis — use directly as dependency |
| **phishai/phish-detect** | — | ML-based phishing detection patterns |
| **ThreatPatrol/AI-Generated-Phishing-Email-Detection** | — | SpamAssassin + YARA + Python for AI-generated email detection — directly relevant |

---

## 6. Header Analysis — What to Check

This is the bread and butter of SOC Level 1 email analysis. Your tool should validate all of these:

**Authentication Headers (SPF / DKIM / DMARC)**
- Parse `Authentication-Results` header
- Check `Received-SPF` for pass/fail/softfail
- Validate DKIM signature presence and domain alignment
- Check DMARC policy: none / quarantine / reject
- Flag: `From` domain ≠ `Return-Path` domain = spoofing indicator

**Routing Analysis**
- Parse full `Received` chain — build relay hop list
- Flag geographic anomalies (email claiming to be from Microsoft but routed through Nigerian IP)
- Check sender IP against AbuseIPDB and ASN data
- Identify forwarding services used to obscure origin

**Header Anomalies to Flag**
- Missing or malformed `Message-ID`
- `X-Mailer` signatures matching known phishing kits
- Unusual `Reply-To` ≠ `From` (classic BEC setup)
- `X-Originating-IP` in suspicious ASN
- Timestamp anomalies (sent at 3am in claimed sender's timezone)

---

## 7. NLP / Behavioral Analysis — The 2026 Differentiator

This is where most open-source tools are weak and where AI-generated phishing has changed the game.

**Cialdini Principle Detection**
Research shows LLM-generated phishing explicitly uses persuasion principles. Score emails for:
- **Authority** — "Your IT department requires...", "CEO requests..."
- **Urgency/Scarcity** — "Your account will be suspended in 24 hours"
- **Social Proof** — "All employees have completed this step"
- **Fear** — "Unusual sign-in activity detected"
- **Reciprocity** — "We've credited your account, please verify"

**AI-Generated Text Signals**
This is cutting edge — detecting LLM-written phishing:
- Unnaturally consistent grammatical perfection (no human makes zero errors)
- Statistical analysis of sentence length variance (LLMs produce more uniform distributions)
- Semantic coherence scoring (LLM text is often *too* relevant and on-topic)
- Use HuggingFace's `roberta-base-openai-detector` or similar models
- Note: this is an arms race — LLMs are getting better at mimicking human imperfection

**Brand Impersonation Detection**
Build a fingerprint database for top impersonation targets:
- Microsoft 365 / Azure AD login pages
- DocuSign signature requests
- DHL / FedEx / UPS delivery notifications
- PayPal / banking alerts
- AWS account notifications
- LinkedIn connection requests

For each: store expected sender domains, common subject patterns, logo hash fingerprints, typical link structures.

---

## 8. Attachment Analysis Pipeline

```
Attachment received
        │
        ├── Hash (MD5/SHA256) → VirusTotal + MalwareBazaar lookup
        │
        ├── File type detection (magic bytes, not extension)
        │
        ├── .docx/.xlsx/.pptx → oletools macro extraction
        │         └── Flag: Auto-open macros, shell commands, URLs in macros
        │
        ├── .pdf → pdfminer JS extraction + embedded URL extraction
        │         └── Flag: /OpenAction, /AA, /JavaScript, /Launch
        │
        ├── .exe/.dll → pefile analysis
        │         └── Flag: Packed/obfuscated, suspicious imports
        │
        └── All types → YARA rule matching
                  └── Use: Florian Roth's signature-base (actively maintained)
```

**YARA Rule Sources to Bundle**
- `Neo23x0/signature-base` — Florian Roth's comprehensive ruleset, frequently updated
- `Yara-Rules/rules` — Community maintained
- PhishingKit YARA rules from `mitchellkrogza/Phishing.Database`

---

## 9. Campaign Correlation Engine

This is your biggest differentiator — most tools analyze one email. Yours clusters them.

**Shared Infrastructure Indicators**
When analyzing multiple emails, cluster by:
- Same sender IP or IP range (CIDR)
- Same registrar + registration date window
- Identical or near-identical email headers (minus timestamps)
- Shared URL infrastructure (same hosting IP, same domain registrar)
- Similar attachment hashes or YARA matches
- Identical `X-Mailer` or `Message-ID` format patterns

**Implementation approach**
- Store all analyzed emails in SQLite with extracted IOCs
- Run similarity clustering using MinHash/LSH for fuzzy matching at scale
- Output: "This email shares infrastructure with 3 previously analyzed emails — possible campaign"
- This is what SOC analysts do manually every day — you're automating it

---

## 10. Cutting-Edge Detection: 2026-Specific Threats

**Adversarial Phishing Techniques to Detect**

1. **LLM Runtime Assembly** (Unit42, Jan 2026) — webpages using live LLM API calls to generate polymorphic phishing JS. Detection: behavioral analysis of redirect chains, flagging pages that call LLM API domains (api.openai.com, api.anthropic.com) on landing.

2. **Redirect Chain Abuse** — attackers chain redirects through legitimate services (Yahoo, Twitter/X, Google AMP) to bypass URL blacklists. Your tool should follow ALL redirect hops and evaluate the final destination, not just the initial URL.

3. **QR Code Phishing (Quishing)** — increasingly common in email attachments; traditional URL scanners miss them entirely. Add QR code extraction from images using `pyzbar` or `qreader`.

4. **Punycode/IDN Homograph Attacks** — `paypaI.com` (capital i) vs `paypal.com`. `dnstwist` handles this but you should implement directly.

5. **AI-Generated BEC without URLs** — pure social engineering with no links or attachments; only detectable via NLP/behavioral analysis. Most tools fail here entirely.

6. **Trusted Platform Abuse** — phishing links hosted on SharePoint, Google Drive, OneDrive, Dropbox — all have good reputations and bypass URL filters. Flag: links to legitimate platforms requesting credential input.

---

## 11. Scoring Engine Design

**Weighted Risk Score (0–100)**

| Category | Max Points | Key Signals |
|----------|-----------|-------------|
| Header Authentication | 25 | SPF fail (-10), DKIM fail (-10), DMARC none/fail (-5) |
| Sender Reputation | 20 | IP on AbuseIPDB (-15), EmailRep low score (-10), WHOIS < 30 days (-10) |
| URL/Domain Analysis | 20 | VT detections (-15), URLScan malicious (-15), homoglyph detected (-10) |
| NLP/Behavioral | 20 | Urgency language (-8), AI-generated signals (-8), brand impersonation (-10) |
| Attachment Risk | 15 | Macro detected (-12), VT hash hit (-15), YARA match (-12) |

**Score Bands**
- 0–20: Clean
- 21–40: Suspicious (review recommended)
- 41–65: Likely Phishing (manual investigation required)
- 66–85: High Confidence Phishing
- 86–100: Critical — block and escalate

---

## 12. Output Formats

Consistent with your existing toolchain:

- **JSON** — machine-readable full report with all IOCs, enrichment, scores
- **SARIF** — CI/CD pipeline integration (consistent with Restless, GitExpose, Corsair)
- **HTML** — analyst-facing report with IOC table, score visualization, redirect chain visualization
- **STIX 2.1 / TAXII** — enterprise-grade IOC export; almost no entry-level tools do this; huge differentiator for hiring conversations
- **CSV** — quick IOC export for ingestion into SIEMs

---

## 13. Integrations to Reuse from Prizm

You already built GitHub/Jira/Slack/Discord integrations in Prizm. Reuse directly:
- **Slack/Discord** — post phishing alert with risk score and summary
- **Jira** — auto-create security ticket with IOC table
- **MISP** — if you want enterprise credibility, add MISP export (ThePhish does this well — study their implementation)

---

## 14. Recommended Build Order

**Phase 1 — Core Pipeline (Week 1–2)**
- .eml/.msg parser
- Header authentication checker (SPF/DKIM/DMARC)
- Basic IOC extraction (iocextract)
- VirusTotal + URLScan + AbuseIPDB enrichment
- JSON output + basic scoring
- CLI: `lure analyze email.eml`

**Phase 2 — Attachment + YARA (Week 3)**
- oletools macro detection
- pdfminer JS extraction
- YARA rule matching (bundle Florian Roth's signature-base)
- Hash enrichment pipeline

**Phase 3 — NLP/ML Layer (Week 4–5)**
- Urgency/Cialdini keyword scoring
- Brand impersonation fingerprinting (top 10 targets)
- Homoglyph/IDN detection (dnstwist logic)
- Redirect chain following

**Phase 4 — Campaign Correlation (Week 5–6)**
- SQLite persistence layer
- Clustering engine for shared infrastructure
- `lure correlate` command

**Phase 5 — Polish (Week 7)**
- HTML report (Jinja2)
- STIX 2.1 export
- SARIF output
- Slack/Jira integrations (port from Prizm)
- README + demo GIF

---

## 15. Differentiators vs Existing Tools

| Feature | ThePhish | PhishTool | Your Tool |
|---------|---------|-----------|-----------|
| No external dependencies (TheHive/Cortex) | ❌ | ❌ | ✅ |
| CLI-first, lightweight | ❌ | ❌ | ✅ |
| AI-generated email detection | ❌ | ❌ | ✅ |
| Campaign correlation | ❌ | Limited | ✅ |
| STIX 2.1 export | ✅ | ❌ | ✅ |
| SARIF output | ❌ | ❌ | ✅ |
| QR code phishing detection | ❌ | ❌ | ✅ |
| Cialdini persuasion scoring | ❌ | ❌ | ✅ |
| YARA rule matching | Via Cortex | ❌ | ✅ |
| Jira/Slack integration | Via TheHive | ❌ | ✅ |
| Open source, zero cost | ✅ | ❌ | ✅ |

---

## 16. Interview Talking Points This Tool Creates

Every SOC Level 1 interview asks: *"Walk me through how you'd analyze a suspicious email."*

Most candidates: "I'd check the headers manually, paste URLs into VirusTotal, maybe run it through Hybrid Analysis..."

You: "I built a tool for this. You feed it the .eml file and it automatically validates SPF/DKIM/DMARC, extracts all IOCs, enriches them against VirusTotal, URLScan, AbuseIPDB, and PhishTank simultaneously, runs YARA rules against any attachments, scores it 0–100 across five categories including NLP-based urgency and AI-generation detection, and outputs a full HTML report plus STIX IOC export in about 15 seconds."

That ends the conversation — in the best way.

---

*Research compiled February 2026 | Sources: Unit42, KnowBe4, MDPI/Applied Sciences, Berkeley CLTC, SOCRadar, GitHub Topics*
