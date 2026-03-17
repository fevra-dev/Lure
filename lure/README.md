# 🎣 Lure — Phishing Analysis & IOC Extraction Platform

**Fevra Security Portfolio · v1.0.0 · February 2026**

Lure compresses the 15–45 minute manual L1/L2 SOC email triage workflow into a sub-90-second automated analysis with a complete, structured verdict report.

---

## Pipeline

```
.eml / .msg
    │
    ▼  A: parser.py        — SPF · DKIM · DMARC · Received chain · Reply-To
    ▼  B: extractor.py     — URLs · IPs · Domains · Hashes · Attachments
    ▼  C: scanner.py       — YARA attachment scanning (Phase 2)
    ▼  D: enricher.py      — VirusTotal · AbuseIPDB · Shodan · urlscan.io (Phase 3)
    ▼  E: scorer.py        — Weighted signal engine → CLEAN / SUSPICIOUS / PHISHING (Phase 4)
    ▼  F: reporter.py      — JSON · HTML · STIX 2.1 · TheHive · MISP (Phase 4+)
```

## Phase 1 Status: ✅ Complete

- [x] Email parsing: `.eml` (RFC 5322) and `.msg` (OLE Compound)
- [x] Header forensics: SPF, DKIM, DMARC validation
- [x] Received chain walking to find true originating IP
- [x] Reply-To mismatch detection
- [x] Homograph domain detection (Unicode mixed-script)
- [x] IOC extraction: URLs, IPs, domains, hashes, emails, crypto wallets
- [x] Defanged IOC handling (`hxxps://`, `[.]`, `(dot)` etc.)
- [x] HTML body extraction from `href`/`src` attributes (avoids anchor text trap)
- [x] Attachment static analysis: VBA macros (olevba), PDF elements (pdfid)
- [x] Multi-hop redirect chain following
- [x] Pydantic v2 data models throughout
- [x] Typer CLI with Rich terminal output
- [x] Full pytest test suite (no API keys required)

## Quick Start

```bash
# Install dependencies
pip install -e ".[dev]"

# Copy and fill in API keys
cp .env.example .env

# Analyze an email
lure analyze suspicious_email.eml

# Analyze with JSON output
lure analyze suspicious_email.eml --format json

# Run tests (no API keys needed)
pytest tests/ -v

# Validate configuration
lure config validate
```

## Example Output

```
╭─────────────────────────────────────────────╮
│ 🎣 Lure — Phishing Analysis                 │
│ Analyzing: invoice_urgent.eml               │
╰─────────────────────────────────────────────╯

┌─────────────────────────────────────────────┐
│ 🚨  CONFIRMED_MALICIOUS   Score: 9.5        │
└─────────────────────────────────────────────┘

📧 Header Analysis
  From          security@paypa1.com
  Subject       Urgent: Verify Your Account
  Originating IP 185.220.101.45
  SPF           FAIL ✗
  DKIM          NONE
  DMARC         FAIL ✗
  Received hops 2
  Reply-To ⚠    attacker@protonmail.com (≠ From domain)

⚠ Anomalies detected:
  • Reply-To domain 'protonmail.com' differs from From domain 'paypa1.com'
  • Homograph domain detected: 'paypa1.com' contains mixed Unicode scripts

🔍 IOCs Extracted (14 total)
  IPs: 185.220.101.45
  Domains: paypa1.com, protonmail.com, evil-cdn.xyz
  URLs: 3 extracted
  Hashes: 1

📎 Attachments (1)
  ⚠ invoice.zip
    ⚠ Nested archive: invoice.zip/invoice.doc
```

## API Keys

All enrichment APIs have free tiers. See `.env.example` for links and rate limits.

| Service | Free Tier | Required for |
|---|---|---|
| VirusTotal | 4 req/min | URL/hash reputation |
| AbuseIPDB | 1000/day | IP reputation |
| Shodan | 100/month | IP infrastructure context |
| urlscan.io | 1000/day | DOM-level phishing detection |
| AlienVault OTX | Unlimited | Community threat intel |

Lure gracefully skips any enrichment source whose key is absent — never crashes.

## Phase Roadmap

| Phase | Status | Deliverable |
|---|---|---|
| 1: Foundation + Parser + Extractor | ✅ Complete | Header forensics + IOC extraction |
| 2: YARA Scanner | 🔜 Next | Attachment malware detection |
| 3: Enrichment Layer | 📅 Weeks 5-6 | VT + AbuseIPDB + Shodan + urlscan |
| 4: Scoring + SOC Integration | 📅 Weeks 7-8 | Verdict engine + TheHive + MISP |
| 5: LLM + MCP Server | 📅 Weeks 9-10 | AI verdicts + Claude Code integration |

## Security Notes

- **Ollama**: Bind to `127.0.0.1` only. Set `OLLAMA_HOST=127.0.0.1` — 1,100+ Ollama servers were exposed publicly (Cisco Talos, Sept 2025).
- **API keys**: Store only in `.env`, never in code or git history.
- **Attachments**: Lure performs static analysis only — never executes attachment content.
