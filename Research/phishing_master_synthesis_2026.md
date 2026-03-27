# Phishing Defence Portfolio: Master Research Synthesis 2026
### All Sources · All Concepts · Best Ideas · Strongest Tool Recommendations

> **Sources synthesised:** Gem-phish-last-research · Phishing-gemini_Research · Phishing_ideas_-_gem · Phishing_grok_1 · Phishing_grok2 · Grok-fish-ideas · Grok-fish-ideas-2 · phishing_portfolio_ideas_2026 · Deep Research Results 2026  
> **Compiled:** February 2026 · For defensive cybersecurity portfolio use

---

## Table of Contents

1. [The Threat Landscape — What All Sources Agree On](#1-threat-landscape)
2. [Core Statistics — Best Numbers Across All Reports](#2-core-statistics)
3. [Technique Deep Dives — Synthesised from All Sources](#3-technique-deep-dives)
4. [Tool Concepts — Every Idea Ranked and Compared](#4-tool-concepts)
5. [THE RECOMMENDATION — The Strongest Single Tool to Build](#5-the-recommendation)
6. [Alternative Suite: 3-Tool Combination Strategy](#6-three-tool-suite)
7. [ML Model Selection Guide](#7-ml-model-selection)
8. [Dataset Directory — All Training Data](#8-dataset-directory)
9. [API Reference — All Useful Endpoints](#9-api-reference)
10. [GitHub Repositories — Bases to Fork](#10-github-repositories)
11. [Detection Rules — Ready-to-Use Sigma, YARA, Suricata, KQL](#11-detection-rules)
12. [Threat Actor Intelligence](#12-threat-actor-intelligence)
13. [Gaps — What No Tool Covers Yet](#13-gaps)
14. [Portfolio Presentation Strategy](#14-portfolio-presentation)

---

## 1. Threat Landscape

### What All 7 Sources Unanimously Agree On

Every source from every AI confirms the same fundamental shift: phishing in 2026 is no longer about fake pages on sketchy domains. The entire attack surface has moved to **legitimate infrastructure, identity layers, and AI-generated content**. The five pillars every source cites:

| Pillar | What Changed | Why It Matters |
|--------|-------------|---------------|
| **AI Polymorphism** | 82.6% of phishing emails contain AI-generated content | Signature-based detection is dead |
| **Trusted Platform Abuse** | 68–77% of bypassed attacks use legitimate SaaS | Domain reputation is dead |
| **AiTM / MFA Bypass** | Tycoon 2FA, Evilginx3 defeat TOTP, push, SMS MFA | Standard MFA is dead against proxied sessions |
| **Identity-first attacks** | "Log in, don't break in" — stolen cookies, device codes, OAuth tokens | Perimeter security is dead |
| **Legitimate infrastructure** | Cloudflare Workers, Vercel, Netlify host 68% of phishing | IP/domain blocklists are dead |

### The Velocity Problem (Consistent Across All Sources)
- One malicious email every **19 seconds** (up from one every 42 seconds in 2024)
- **76%** of campaign URLs are unique per recipient
- **82%** of malicious files have unique hashes
- Average phishing page lifespan: **hours to low single-digit days**
- eCrime breakout time (access → ransomware): **29 minutes**

---

## 2. Core Statistics

### Aggregated Best Stats from All Sources — Cite These in Your Portfolio

| Metric | Figure | Best Source |
|--------|--------|-------------|
| AI content in phishing emails | **82.6%** | KnowBe4 Q1 2025, confirmed by all sources |
| Unique URLs per campaign | **76%** | Cofense 2026 |
| TPA attacks impersonating Microsoft/Google/DocuSign | **77%** | StrongestLayer Jan 2026 |
| Cloudflare Workers/Vercel/Netlify phishing share | **68%** | Multiple sources |
| Quishing surge (2023–2025) | **400%** | Multiple sources |
| QR code phishing share of all phishing | **12%** | Barracuda 2025 |
| Mobile users targeted by quishing | **68%** | Multiple sources |
| AI phishing click rate vs. human-written | **54% vs 12%** | IBM X-Force / Hoxhunt |
| Tycoon 2FA incidents (2025) | **64,000+** | ANY.RUN |
| Tycoon 2FA PhaaS market share (early 2025) | **89%** | Barracuda |
| Crypto drainer losses (2025) | **$83.85M** | Scam Sniffer (down 83% from 2024) |
| Bybit heist (TraderTraitor/Lazarus) | **$1.5B** | FBI / Wiz Research |
| EIP-7702 phishing losses (Aug 2025) | **$2.54M+ confirmed / $12M+ total** | Scam Sniffer |
| ClickFix initial access share | **47%** | Microsoft MDRR 2025 |
| SVG phishing surge Q4'24→Q1'25 | **245%** | KnowBe4 |
| SVG % of malicious attachments (peak Mar 4, 2025) | **29.5%** | KnowBe4 |
| Enterprise tooling gap on TPA/QR/AiTM | **20–30% miss rate** | Multiple sources |
| Scattered Spider M&S breach profit impact | **£300M** | Computer Weekly |
| APT42 using Gemini for reconnaissance | **Confirmed** | Google GTIG Feb 2026 |

---

## 3. Technique Deep Dives

### 3.1 Generative AI-Powered Phishing

**The pipeline used by sophisticated actors (from Gem research + Grok1):**

1. **OSINT Harvest** — LinkedIn scraping, Hunter.io, breach datasets, company press releases
2. **Persona Crafting** — LLM few-shot prompting synthesises writing style, references real co-workers and projects
3. **Polymorphic Generation** — Every email variant is unique: subject, body, HTML structure, embedded images, sender display name
4. **Dynamic Landing** — Bot detection serves benign page; real victims get credential-harvesting interface

**Key LLM fingerprints to detect (all sources agree):**
- **Low perplexity** — AI text is unnaturally fluent. Human text has high perplexity (unpredictable word choices)
- **Low burstiness** — `variance(sentence_lengths) / mean(sentence_lengths)` AI text <0.3, human text >0.6 (arXiv:2301.11305)
- **High Cialdini trigger density** — urgency, authority, scarcity keywords appear 2–3× more than in human-written email
- **Uniform vocabulary diversity** — AI uses moderately varied but structurally consistent vocabulary

**Adversarial evasion now deployed by attackers (Gem-phish-last-research):**
- Intentional word splitting to break perplexity scoring
- Subtle spelling "corrections" to break statistical uniformity
- Mixing AI-generated body with human-written subject lines

**Best detection approach from all research:**
- Local LLM perplexity scoring (Ollama + Phi-3 Mini or Llama 3.2 3B) — no data leaves device
- XGBoost ensemble with burstiness + Cialdini features + header anomaly score
- LIME/SHAP explainability to highlight suspicious urgency keywords

---

### 3.2 Trusted Platform Abuse (TPA)

**The standard 2026 TPA kill chain (StrongestLayer Jan 2026 via Gem + Grok sources):**

```
Legitimate Calendly invite
    → hCaptcha gate (on trusted domain)
        → JotForm redirect
            → Cloudflare Worker
                → Tycoon 2FA reverse proxy for Microsoft 365
```

Every domain in this chain has reputation score zero. Traditional SEG: bypassed entirely.

**Most abused platforms (ranked by all sources):**
1. **DocuSign** — >20% of TPA attacks. API abused to send fake invoices via authorised envelopes (pass SPF/DKIM by design)
2. **Calendly + Google Calendar** — Fake invites; invisible to email gateways
3. **Cloudflare Workers / Vercel / Netlify** — 68% of phishing pages. Free tier, automatic TLS, global CDN
4. **JotForm / Typeform / Google Forms / Canva / Notion** — Embedded redirect pages
5. **Zoom / Atlassian Jira** — Chained for malware delivery (ScreenConnect via Zoom docs)
6. **Helpdesk platforms** — Zendesk, Zoho Desk, Freshdesk, HubSpot, Intercom, Salesforce Service Cloud

**What detection must focus on (consensus across all sources):**
- Redirect chain **depth and composition** — not domain reputation
- Terminal domain characteristics — `*.vercel.app` or `*.workers.dev` with `<form>` elements
- **`finance keyword` + `DocuSign sender` + `external sender`** SIEM correlation
- TLS certificate age of the terminal domain (<7 days = high risk)

**Sigma rule trigger (from Gem-phish-last-research):**
```yaml
title: Tycoon 2FA Proxy Redirect Detection
status: experimental
logsource:
  category: proxy
detection:
  selection_uri:
    url|contains:
      - '/pq'
      - '/rs'
      - '/yz'
      - '/12'
      - '/twofaselected'
  selection_tld:
    url|endswith:
      - '.es'
      - '.ru'
      - '.za.com'
  condition: selection_uri and selection_tld
level: high
```

---

### 3.3 AiTM — Adversary-in-the-Middle

**Tycoon 2FA 5-Stage Architecture (confirmed: Sekoia, Barracuda, CYFIRMA, Cybereason):**

| Stage | Technical Action | Evasion Active |
|-------|-----------------|----------------|
| 1 — CAPTCHA Gate | Cloudflare Turnstile, hCaptcha, custom image challenges | Bot rejection, sandbox detection |
| 2 — Credential Relay | Live POST to real Microsoft 365 / Gmail | Debugger check → redirect to Tesla.com if detected |
| 3 — MFA Relay | Real MFA challenge forwarded; OTP captured in transit | DOM Vanishing Act — JS removes itself from DOM |
| 4 — Cookie Harvest | Session cookies captured post-authentication | AES-CBC payload encryption (added May 2025) |
| 5 — Replay | Cookies used from separate attacker IP | Domain rotation every 24–48h (.es, .ru, .za.com) |

**May 2025 technical updates (from Gem-phish-last-research):**
- AES-CBC encryption of C2 payloads — defeated static payload signature matching
- Full browser fingerprinting: timezone, WebGL renderer, canvas, fonts, plugins
- Shifted between AES and RC4 across different campaigns (CYFIRMA)
- QR code delivery added to template library

**Only reliable defence (all sources unanimously agree):**  
FIDO2/WebAuthn hardware keys. The proxy cannot relay origin-bound public key cryptography. All other MFA — TOTP, push, SMS — is defeated by AiTM.

---

### 3.4 Quishing (QR Code Phishing)

**Why SEGs fail (from all sources):**
- QR codes in PDF attachments are not decoded by most email gateways
- Physical mail / printed invoices deliver QR codes outside email scanning entirely
- Mobile users (68% of targets) lack corporate endpoint protection
- Split and nested QR codes bypass OCR-only scanners

**The pixel-structural insight (Grok-fish-ideas-2 + Gem research — highest value finding):**  
Research by fouadtrad (2025, AUC 0.9133) proves malicious QR structural patterns can be detected **before URL decoding**. This is critical — following the URL risks fingerprinting the scanner. Pre-decode detection is the correct approach.

**15 pixel-structural features to extract (from fouadtrad research):**
- Visual density, error correction level patterns, finder pattern uniformity
- Module size variance, quiet zone dimensions, version encoding patterns
- Pixel noise distribution, contrast ratio, symmetry score

---

### 3.5 EIP-7702 / Web3 Phishing

**The EIP-7702 attack (Ethereum Pectra upgrade, May 7, 2025):**

Allows any regular wallet (EOA) to temporarily behave like a smart contract by signing an **authorization tuple** — a compact pointer that installs arbitrary contract code. The victim sees nothing unusual.

**Inferno Drainer kill chain (Scam Sniffer, confirmed):**
1. Fake DeFi interface (Uniswap clone, airdrop claim)
2. Transaction type `0x04` (set code transaction) presented
3. Victim signs — appears as routine permission
4. Authorization triggers invisible `execute()` call
5. Batch drain: dozens of tokens approved and swept in single transaction
6. Cross-chain: auto-detects chain IDs, sweeps Ethereum + BSC + Polygon + Base

**Key confirmed numbers:**
- 97%+ of EIP-7702 delegations in the wild use malicious sweeper code (Wintermute / Dune Analytics)
- Known malicious delegator: `0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B` (Inferno)
- $2.54M confirmed (Scam Sniffer) / $12M+ total (August 2025)

---

### 3.6 ClickFix / FakeCaptcha

**Now the #1 initial access method (47% share, Microsoft MDRR 2025)**

**Kill chain:**
1. Victim reaches malicious page (phishing email, malvertising, compromised site)
2. Fake Cloudflare/Google CAPTCHA renders
3. JavaScript silently writes malicious command to clipboard when user clicks the checkbox
4. Page instructs: *"Press Win+R, paste the code, press Enter"*
5. Payload executes: `mshta.exe`, PowerShell `-WindowStyle Hidden`, `curl | bash`

**Most common 2025 payloads:** Lumma Stealer, NetSupport RAT, Latrodectus, AsyncRAT, MintsLoader

**Working Splunk SPL detection rule (Michael Haag, Splunk, Nov 2025):**
```sql
| tstats count min(_time) as firstTime max(_time) as lastTime
    FROM datamodel=Endpoint.Processes
    WHERE Processes.process_name='powershell.exe'
        AND Processes.process=*-WindowStyle*Hidden*
        AND (Processes.process=*verification*
            OR Processes.process=*captcha*
            OR Processes.process=*mshta*)
| eval firstTime=strftime(firstTime,'%Y-%m-%dT%H:%M:%S')
| table Processes.dest Processes.user Processes.process firstTime lastTime
```

---

### 3.7 SVG-Based Phishing

**Key stats:**
- 47,000% surge in SVG phishing volume (Sublime Security, May 2025)
- 245% increase Q4'24 → Q1'25 (KnowBe4)
- 6.6% of all malicious attachments; peaked at **29.5% on March 4, 2025**
- MITRE formally assigned technique **T1027.017 (SVG Smuggling)**

**Why it works:** SVGs have MIME type `image/svg+xml` — email gateways treat them as safe images, despite being XML documents with full JavaScript execution.

**Three confirmed attack patterns:**
1. `<script>` tags with direct JavaScript
2. `<foreignObject>` tags with embedded HTML phishing forms (no external resources needed until submission)
3. Base64-encoded payloads decoded and executed on file open

---

### 3.8 OAuth Device Code Phishing

**Confirmed state-actor adoption (Proofpoint Dec 2025, Microsoft Feb 2025):**

| Actor | Classification | Method |
|-------|---------------|--------|
| Storm-2372 | Russia-aligned | Watering hole + device code |
| APT29 / CozyLarch | Russia-aligned | Fake Cloudflare CAPTCHA → device code |
| UNK_AcademicFlare | Russia-aligned (suspected) | Multi-week rapport → Cloudflare Worker spoof |
| TA2723 | Financially motivated | Salary lures with device codes |

**The 15-minute window:** Device codes expire in 15 minutes — why rapport-building is essential. UNK_AcademicFlare conducted multi-week email conversations before delivering the code.

**KQL detection for Microsoft Sentinel:**
```kql
let DeviceCodeSignins = AADSignInEventsBeta
    | where AuthenticationProtocol == 'deviceCode'
    | where ResultType == 0  // successful
    | project TimeGenerated, UserPrincipalName, IPAddress,
              ClientAppUsed, AppDisplayName, Location;
DeviceCodeSignins
| join kind=leftouter (
    AADSignInEventsBeta
    | where AuthenticationProtocol != 'deviceCode'
    | summarize NormalSigninCount=count() by UserPrincipalName
  ) on UserPrincipalName
| where NormalSigninCount < 10  // rare device code users
| where AppDisplayName in ('Microsoft Office', 'Microsoft Teams',
      'Microsoft Azure PowerShell', 'Microsoft Authentication Broker')
```

---

## 4. Tool Concepts

### Every Tool Idea from All 7 Sources — Compared and Scored

| # | Tool | Sources Mention It | Innovation | Feasibility | Time | Impact |
|---|------|-------------------|-----------|-------------|------|--------|
| 1 | **TPA Sentinel** | All 7 sources | Redirect chain behavioral ML — not domain reputation | ⭐⭐⭐ Medium | 3–4 wks | ★★★★★ |
| 2 | **QuishGuard** | All 7 sources | Pre-decode pixel-structural QR analysis | ⭐⭐⭐⭐ Easy-Med | **1–2 wks** | ★★★★☆ |
| 3 | **GenAI Phish Shield** | 6/7 sources | Local LLM, zero data-leak, perplexity + burstiness | ⭐⭐⭐ Medium | 4–6 wks | ★★★★★ |
| 4 | **DrainerGuard Web3** | 6/7 sources | Pre-signing EIP-7702 simulation, real-time | ⭐⭐ Hard | 4–5 wks | ★★★★★ |
| 5 | **FakeSender Shield** | 6/7 sources | Header cross-ref vs. brand-domain DB + auto abuse report | ⭐⭐⭐⭐ Easy-Med | 2–3 wks | ★★★★☆ |
| 6 | **AiTM Traffic Guardian** | 5/7 sources | mitmproxy + JA3 fingerprint matching for Evilginx3/Tycoon | ⭐ Very Hard | 5–6 wks | ★★★★☆ |
| 7 | **PhishVision Multimodal** | 5/7 sources | On-device ONNX: screenshot + HTML + URL ensemble | ⭐ Very Hard | 6–8 wks | ★★★★☆ |
| 8 | **CTI Pipeline-as-Code** | 6/7 sources | Async STIX 2.1 IOC enrichment, 8 sources, Redis cache | ⭐⭐⭐⭐ Easy-Med | 2–3 wks | ★★★★☆ |
| 9 | **PhishRoBERTa-XAI** | Grok sources | RoBERTa fine-tuned + LITA (LIME + Transformer Attribution) | ⭐⭐⭐ Medium | 3–4 wks | ★★★★☆ |
| 10 | **ClickGrab Defender** | Deep Research | Clipboard injection real-time monitor | ⭐⭐⭐⭐⭐ Very Easy | **1 wk** | ★★★☆☆ |
| 11 | **Multilingual PhishGuard** | 3/7 sources | mBERT/XLM-R for non-English phishing detection | ⭐⭐⭐ Medium | 4–5 wks | ★★★★☆ |
| 12 | **OAuth App Auditor** | Deep Research | Entra ID OAuth permission audit and alert | ⭐⭐⭐⭐ Easy-Med | 2–3 wks | ★★★★☆ |
| 13 | **CertStream Brand Monitor** | 3/7 sources | Real-time CT log typosquat alerting | ⭐⭐⭐⭐ Easy | **1 wk** | ★★★☆☆ |

---

## 5. THE RECOMMENDATION

### The Strongest Single Tool for a Defensive Cyber Resume

> **Build: QuishGuard + CTI Pipeline hybrid, starting with QuishGuard alone**

### Why QuishGuard Wins the Cost-Benefit Analysis

Every single source — across all 7 AIs — consistently names QuishGuard as the **fastest to build, the most visually demonstrable, and the most cited gap in enterprise tooling**. Here is why it beats every other tool for a resume:

| Criterion | QuishGuard | Next Best (TPA Sentinel) |
|-----------|-----------|--------------------------|
| Build time to MVP | **1–2 weeks** | 3–4 weeks |
| Gap documented by vendors | **Barracuda, KnowBe4, StrongestLayer** all confirm SEG blind spot | Less documented |
| Demo impact | **"Scan malicious PDF, see red flag in 2 seconds"** | Abstract redirect graph |
| Dataset available NOW | **9,987 labeled QR images (fouadtrad)** | Must build dataset |
| Unique innovation claim | **Pre-decode pixel analysis** — no competing open-source tool | Some competing work |
| GitHub star potential | **High** — visual, relatable threat | Medium |
| Ties to current headlines | **12% of phishing, 400% surge, 2025 invoices** | Lower media profile |
| ML benchmark available | **AUC 0.9133 (fouadtrad)** — target to beat | None published |

---

### QuishGuard: Complete Technical Blueprint

#### The Core Innovation
Two-stage detection that **never follows the URL**:
1. **Stage 1 (Pixel-Structural ML):** Extract 15 visual features from the QR image with OpenCV + XGBoost → score as malicious/benign without decoding
2. **Stage 2 (Sandboxed Decode):** Only for borderline cases — decode URL in isolated Docker container → submit to VirusTotal/GSB asynchronously

**Why this is a genuine innovation:** Every competing tool (Barracuda, Abnormal, mimecast) decodes the URL first. This risks the scanner's IP being fingerprinted by the phishing page. Pre-decode detection is the correct security architecture.

---

#### Full Tech Stack

```
Email Attachment Input
        ↓
[PDF → Image Layer: PyMuPDF (fitz) at 300 DPI]
        ↓
[QR Extraction: OpenCV findContours + pyzbar detection]
        ↓
[Feature Extraction: 15 pixel-structural features]
 ┌─ Visual density            ┌─ Quiet zone dimensions
 ├─ Error correction pattern  ├─ Finder pattern uniformity
 ├─ Module size variance      ├─ Version encoding pattern
 ├─ Pixel noise distribution  ├─ Contrast ratio
 └─ Symmetry score            └─ Aspect ratio deviations
        ↓
[XGBoost Classifier — trained on fouadtrad 9,987 samples]
        ↓
    BENIGN < 0.4  │  BORDERLINE 0.4–0.7  │  MALICIOUS > 0.7
                  ↓
        [Docker Sandbox: pyzbar decode]
                  ↓
    [Async: VirusTotal + Google Safe Browsing + URLhaus]
                  ↓
[Output: confidence score + decoded URL + verdict + STIX 2.1 IOC]
```

**Libraries:**
```python
# Core
import fitz          # PyMuPDF — best PDF rendering
import cv2           # OpenCV — QR extraction  
import pyzbar        # QR decoding (sandboxed)
import numpy as np   # Feature computation
import xgboost as xgb  # Classification
import aiohttp        # Async API calls
import asyncio        # Concurrent enrichment

# APIs
# VirusTotal v3: /api/v3/urls
# Google Safe Browsing v4: /v4/threatMatches:find
# URLhaus: urlhaus-api.abuse.ch/v1/url/
```

---

#### MVP Implementation (Week 1–2)

**Week 1 deliverable: Python CLI**

```python
import fitz, cv2, numpy as np, pyzbar.pyzbar as pyzbar
import xgboost as xgb, asyncio, aiohttp

def extract_qr_features(image: np.ndarray) -> dict:
    """Extract 15 pixel-structural features without decoding URL."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    _, binary = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
    
    total_pixels = binary.size
    black_pixels = np.sum(binary == 0)
    
    return {
        'visual_density': black_pixels / total_pixels,
        'contrast_ratio': gray.std() / (gray.mean() + 1e-8),
        'pixel_noise': np.var(binary.astype(float)),
        'symmetry_score': compute_symmetry(binary),
        'module_size_variance': compute_module_variance(binary),
        'finder_pattern_score': detect_finder_patterns(binary),
        'quiet_zone_ratio': measure_quiet_zone(binary),
        'aspect_ratio': image.shape[1] / image.shape[0],
        # ... 7 more features
    }

def scan_pdf_for_qr(pdf_path: str) -> list:
    """Extract all QR codes from PDF, return feature vectors."""
    doc = fitz.open(pdf_path)
    results = []
    for page in doc:
        mat = fitz.Matrix(300/72, 300/72)  # 300 DPI
        pix = page.get_pixmap(matrix=mat)
        img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(
            pix.height, pix.width, pix.n)
        
        # OpenCV QR detection
        qr_detector = cv2.QRCodeDetector()
        contours = extract_qr_regions(img)
        
        for region in contours:
            features = extract_qr_features(region)
            results.append(features)
    return results

async def enrich_url(session: aiohttp.ClientSession, url: str) -> dict:
    """Async multi-source enrichment after sandbox decode."""
    tasks = [
        check_virustotal(session, url),
        check_safe_browsing(session, url),
        check_urlhaus(session, url),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {'url': url, 'vt': results[0], 'gsb': results[1], 'urlhaus': results[2]}

# CLI entry point
if __name__ == '__main__':
    import sys
    pdf_path = sys.argv[1]
    model = xgb.Booster()
    model.load_model('quishguard_model.json')
    
    features = scan_pdf_for_qr(pdf_path)
    for f in features:
        score = model.predict(xgb.DMatrix([list(f.values())]))[0]
        verdict = 'MALICIOUS' if score > 0.7 else 'SUSPICIOUS' if score > 0.4 else 'CLEAN'
        print(f"[{verdict}] Confidence: {score:.2%}")
```

**Week 2: Gmail/Outlook add-in + Streamlit demo dashboard**

```python
# Streamlit demo — maximum visual impact for portfolio
import streamlit as st
import plotly.graph_objects as go

st.title("🔍 QuishGuard: QR Phishing Scanner")
st.markdown("*Pre-decode pixel-structural analysis — the URL is never followed*")

uploaded = st.file_uploader("Upload Email Attachment (PDF, PNG, JPG)", 
                              type=['pdf','png','jpg','jpeg'])
if uploaded:
    with st.spinner("Analysing pixel structure..."):
        result = scan_and_classify(uploaded)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Score", f"{result['score']:.1%}")
    col2.metric("Verdict", result['verdict'])
    col3.metric("URLs Found", result['url_count'])
    
    if result['verdict'] == 'MALICIOUS':
        st.error(f"⚠️ Malicious QR detected! URL: {result['decoded_url']}")
        st.json(result['virustotal'])
```

---

#### Benchmark Targets (What to Publish in Your README)

| Metric | fouadtrad baseline | Your target | How to beat it |
|--------|-------------------|-------------|----------------|
| AUC | 0.9133 | **>0.94** | Extended 2025 dataset + additional features |
| False positive rate | ~8.67% | **<5%** | Tune threshold per use case |
| Inference time (pre-decode) | Not benchmarked | **<50ms** | XGBoost on CPU |
| PDF processing | Not included | **<2s per page** | PyMuPDF + async |
| End-to-end with VT | Not included | **<8s** | Async batch API |

**Where to get 2025 samples to extend the dataset:**
- URLhaus tag `quishing` → ~340 confirmed URLs with embedded QR
- Phishing.Database (GitHub) — filter for QR-containing emails
- Generate synthetic malicious samples using PyQRCode (for training balance)

---

## 6. Three-Tool Suite

### If You Want to Go Further: "DefendKit" — 3 Tools, One Cohesive Portfolio

The Grok sources and Gem research both suggest a suite approach. The strongest combination based on all sources:

```
┌─────────────────────────────────────────────────────┐
│              D E F E N D K I T                       │
├──────────────┬──────────────────┬───────────────────┤
│ QuishGuard   │  GenAI Phish     │  CTI Pipeline     │
│ (QR/PDF)     │  Shield          │  as Code          │
│              │  (Email body)    │  (IOC enrichment) │
│ Week 1–2     │  Week 3–6        │  Week 3–5         │
│ Python CLI   │  Gmail add-in    │  GitHub Action    │
│ + Streamlit  │  + Flask API     │  + MISP export    │
└──────────────┴──────────────────┴───────────────────┘
         Shared: STIX 2.1 output · Redis cache · VirusTotal API
```

**Why this trio:**
- Covers three distinct attack surfaces (attachment, email body, SOC enrichment)
- All three use Python — one codebase/developer
- Can share Redis cache and API key management
- CTI Pipeline plugs QuishGuard and GenAI Shield detections into MISP automatically
- Combined GitHub repo shows architectural thinking, not just one-trick demos

---

## 7. ML Model Selection Guide

### Best Model by Task (from All Sources + Deep Research Benchmarks)

| Task | Best Model | Accuracy | Source |
|------|-----------|---------|--------|
| Email body phishing classification | **RoBERTa-base (fine-tuned)** | 99.43% | Melendez et al., Electronics Dec 2024 |
| Fast email classification | **DistilBERT-base (fine-tuned)** | 98.99% | Same paper, 40% fewer params |
| URL + HTML combined | **DeBERTa-v3 (fine-tuned)** | ~99.1% | SecureNet, arXiv:2406.06663 |
| Multilingual phishing | **mT5** | 99.61% | Research benchmark |
| Non-English smishing | **XLM-RoBERTa** | 98.92% | Bengali dataset |
| QR pixel classification | **XGBoost** | 91.33% AUC | fouadtrad 2025 |
| Visual brand recognition | **EfficientNet-B0** | 91.33% | Phishpedia dataset |
| TPA redirect chain anomaly | **Isolation Forest** | Unsupervised | scikit-learn |
| AI text perplexity scoring | **Phi-3 Mini / Llama 3.2 3B** | Best local models | Ollama benchmarks |
| Emerging class detection | **XF-PhishBERT (ModernBERT+MAML)** | 40% F1 improvement | Scientific Reports Dec 2025 |

### XAI (Explainability) — Which to Use Per Tool

| Tool | Best XAI Method | Why |
|------|----------------|-----|
| GenAI Phish Shield | **LIME** | Per-instance word-level highlighting, low compute |
| QuishGuard | **SHAP** | Feature importance across XGBoost model |
| PhishVision | **Integrated Gradients** | Attention heatmap for visual regions |
| CTI Pipeline risk score | **SHAP** | Multi-source weighted score explanation |

### On-Device Deployment Constraints

```
Chrome Extension Manifest V3:
  Memory limit: 30MB
  Recommended model: EfficientNet-B0 INT8 quantised = 8–12MB
  Inference target: <200ms on mid-range hardware
  Storage: Float32 brand embeddings in IndexedDB (not service worker)

Local Ollama Deployment:
  Phi-3 Mini (3.8B): ~2s inference on Apple M1 Pro — best email calibration
  Llama 3.2 3B: ~3s inference — good perplexity scoring
  Gemma 2 2B: ~2.5s — alternative if Phi-3 unavailable
  VRAM: All run on 8GB VRAM minimum

Browser ONNX Runtime Web (v1.17+):
  WebGPU backend for GPU-accelerated inference
  Quantisation: Use onnxruntime quantize_dynamic for INT8
  Target: sub-8MB model size for service worker compatibility
```

---

## 8. Dataset Directory

### All Training Datasets from All Sources

| Dataset | Size | Content | Access | Best For |
|---------|------|---------|--------|---------|
| **fouadtrad QR-Phish-9K** | 9,987 labelled images | QR code images (malicious/benign) | `github.com/fouadtrad/qr-phishing-detection` | QuishGuard training |
| **PhishTank** | 1.1M+ URLs | Community-verified phishing URLs | `phishtank.com/developer_info.php` | URL classifier |
| **URLhaus (abuse.ch)** | 700K+ URLs | Malware/phishing URLs, real-time | `urlhaus.abuse.ch` — bulk CSV | CTI pipeline, URL training |
| **Phishing.Database** | Live, updated | Active phishing domains | `github.com/Phishing-Database` | Domain blocklist |
| **OpenPhish** | Active feed | Brand-targeted phishing URLs | `openphish.com` | Brand targeting analysis |
| **Sting9 Dataset** | 50M messages | High-fidelity AI training set | Research initiative | GenAI phishing detection |
| **Enron Email Dataset** | 517K emails | Legitimate corporate emails | Kaggle | GenAI Shield negative class |
| **Nazario Phishing Corpus** | ~1.3K phishing emails | Classic phishing email text | Public research | GenAI Shield positive class |
| **Scam Sniffer DB** | Live | Crypto drainer sites + contracts | `scamsniffer.io/docs` (API) | DrainerGuard blocklist |
| **ISCX-URL-2016** | ~36K URLs | Classic benchmark dataset | Kaggle | URL classifier baseline |
| **HuggingFace phishing** | Growing | AI-generated phishing emails | `huggingface.co/datasets` search 'phishing' | GenAI Shield training |
| **Chainabuse** | Live | On-chain abuse reports | `chainabuse.com` API | DrainerGuard blocklist |
| **ThreatFox (abuse.ch)** | Live | IOC feed (URLs, IPs, hashes) | `threatfox.abuse.ch/api` | CTI pipeline |
| **MetaMask eth-phishing-detect** | Live (1.2K stars) | Crypto phishing domains | `github.com/MetaMask/eth-phishing-detect` | DrainerGuard domain check |

---

## 9. API Reference

### All Useful APIs from All Sources — With Rate Limits

| API | Endpoint | Free Tier | Auth | Best For |
|-----|---------|-----------|------|---------|
| **VirusTotal v3** | `/api/v3/urls` | 500/day, 4/min | API key | URL malice scoring |
| **Google Safe Browsing v4** | `/v4/threatMatches:find` | 500/day | API key | URL blocking |
| **URLhaus** | `urlhaus-api.abuse.ch/v1/url/` | Unlimited | None | Malicious URL check |
| **ThreatFox** | `threatfox.abuse.ch/api` | Unlimited | None | IOC lookup |
| **PhishTank** | `/check` | 5,000/day | API key | Phishing URL verify |
| **Shodan InternetDB** | `internetdb.shodan.io` | Unlimited (basic) | None | IP reputation |
| **Shodan Search** | `/shodan/host/{ip}` | 1 credit/query | API key ($49/mo) | Infrastructure intel |
| **crt.sh** | `/?q=domain&output=json` | Unlimited | None | CT log domain search |
| **Cloudflare Radar URL Scanner** | `/radar/urlscanner` | Free tier | API key | URL analysis |
| **AbuseIPDB** | `/check/{ip}` | 1,000/day | API key | IP abuse reporting |
| **AlienVault OTX** | `/otx.alienvault.com/api` | Free | API key | Threat intelligence |
| **IPInfo** | `ipinfo.io/{ip}/json` | 50K/month | API key | Geolocation |
| **Alchemy Simulation** | `/simulate/transactions` | Free tier | API key | Web3 tx simulation |
| **Tenderly Fork** | `/api/v1/simulate` | Free tier | API key | Web3 tx simulation |
| **Chainabuse** | `chainabuse.com/api` | Free | API key | Crypto abuse reports |
| **CertStream** | `wss://certstream.calidog.io/` | Free WebSocket | None | Real-time CT events |
| **RDAP** | `rdap.org/domain/{domain}` | Unlimited | None | Domain registration data |
| **Ollama** | `localhost:11434/api/generate` | Local | None | Local LLM inference |

### Optimal Redis TTL Strategy (CTI Pipeline-as-Code)

```python
CACHE_TTL = {
    'virustotal_url':    86400,    # 24h — phishing pages change fast
    'virustotal_domain': 604800,   # 7d — domain reputation stable
    'virustotal_ip':     259200,   # 3d — IP rotation moderate
    'urlhaus':           3600,     # 1h — near-real-time feed
    'shodan_ip':         604800,   # 7d — scan data stable
    'abuseipdb':         43200,    # 12h — moderate volatility
    'crtsh':             86400,    # 24h — CT logs grow slowly
    'otx':               21600,    # 6h — pulse data moderate
}
```

---

## 10. GitHub Repositories

### Best Repos to Fork, Extend, or Reference

| Repo | Stars | Language | What to Do With It |
|------|-------|----------|-------------------|
| `fouadtrad/qr-phishing-detection` | 100+ | Python | **Fork for QuishGuard** — contains dataset + baseline model |
| `emalderson/ThePhish` | 1.3K | Python | Fork as GenAI Phish Shield + FakeSender Shield base |
| `elceef/dnstwist` | 5.6K | Python | Extend with CT log monitoring for brand typosquats |
| `kgretzky/evilginx3` | 13.6K | Go | Study for AiTM Guardian — learn Evilginx phishlet markers |
| `fin3ss3g0d/evilgophish` | 2K | Go | Reference for AiTM red team simulation |
| `simplerhacking/Evilginx3-Phishlets` | 675 | YAML | Extract phishlet markers for YARA/Sigma rules |
| `MetaMask/eth-phishing-detect` | 1.2K | JavaScript | Contribute from DrainerGuard work |
| `revoke-cash/revoke.cash` | 1.4K | TypeScript | Integrate into DrainerGuard |
| `lindsey98/Phishpedia` | 345 | Python | Base for PhishVision Multimodal |
| `lindsey98/PhishIntention` | 200+ | Python | Extension of Phishpedia for PhishVision |
| `MISP/PyMISP` | 700+ | Python | Integration for CTI Pipeline |
| `oasis-open/cti-python-stix2` | 500+ | Python | STIX 2.1 output for CTI Pipeline |
| `certtools/intelmq` | 2K | Python | CTI pipeline orchestration reference |
| `gophish/gophish` | 13.6K | Go | Red team simulation baseline |
| `Phishing-Database/Phishing.Database` | 1.2K | Shell | Live domain blocklist integration |

---

## 11. Detection Rules

### Ready-to-Use Rules from All Sources

#### Sigma — Tycoon 2FA Proxy Redirect (Gem-phish-last-research)
```yaml
title: Tycoon 2FA Proxy Redirect Detection
id: a8f23bc1-4f91-4d2a-b8c3-1e5f7a9d0e12
status: experimental
description: Detects proxy-specific redirect patterns in Tycoon 2FA kit
logsource:
  category: proxy
detection:
  selection_uri:
    url|contains:
      - '/pq'
      - '/rs'
      - '/yz'
      - '/12'
      - '/twofaselected'
  selection_tld:
    url|endswith:
      - '.es'
      - '.ru'
      - '.za.com'
      - '.vercel.app'
      - '.workers.dev'
  condition: selection_uri and selection_tld
falsepositives:
  - Legitimate internal redirects using similar stage names
level: high
tags:
  - attack.credential_access
  - attack.t1111
```

#### Suricata — Tycoon 2FA C2 POST (Gem-phish-last-research)
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"PHISHING Tycoon 2FA C2 Exfiltration";
  content:"POST"; http_method;
  content:"/tdwsch3h8IoKcUOkog9d14CkjDcaR0ZrKSA95UaVbbMPZdxe"; http_uri;
  classtype:trojan-activity;
  sid:2026001; rev:1;
)
```

#### YARA — Evilginx3 Phishlet Marker (Gem-phish-last-research)
```yara
rule Evilginx3_Phishlet_Marker {
  meta:
    description = "Detects Evilginx3 phishlet injection markers in HTML"
    author = "Security Engineering Team"
    date = "2026-02-15"
  strings:
    $s1 = "evilginx" ascii nocase
    $s2 = "window.location.hostname.split" ascii
    $s3 = "placeholder_email" ascii
    $js1 = "myscr" ascii          // obfuscated JS loader pattern
    $js2 = "CryptoJS" ascii       // AES payload decryption
  condition:
    any of ($s*) or all of ($js*)
}
```

#### YARA — Malicious SVG (Stairwell Dec 2025 via Deep Research)
```yara
rule Malicious_SVG_Script_Content {
  meta:
    description = "SVG file containing suspicious script content"
    author = "Stairwell Research"
    date = "2025-12"
    reference = "stairwell.com/resources/are-your-svgs-malicious"
    mitre = "T1027.017"
  strings:
    $svg_header  = '<svg' nocase ascii
    $script_tag  = '<script' nocase ascii
    $foreign_obj = '<foreignObject' nocase ascii
    $base64_data = 'data:text/html;base64,' nocase ascii
    $window_loc  = 'window.location' nocase ascii
    $fetch_call  = 'fetch(' nocase ascii
    $cryptojs    = 'CryptoJS' ascii
  condition:
    $svg_header and (
      ($script_tag and ($window_loc or $fetch_call)) or
      ($foreign_obj and $base64_data) or
      $cryptojs
    )
}
```

#### CertStream Monitor — Brand Typosquat Alerting (Gem-phish-last-research)
```python
import certstream
import logging

def on_certificate_update(message, context):
    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        target_keywords = ['coinbase', 'microsoft', 'docusign', 'metamask',
                           'ledger', 'binance', 'paypal', 'amazon']
        malicious_tlds = ['.es', '.ru', '.xyz', '.workers.dev', 
                          '.vercel.app', '.netlify.app', '.pages.dev']
        
        for domain in all_domains:
            if any(keyword in domain.lower() for keyword in target_keywords):
                if any(tld in domain for tld in malicious_tlds):
                    print(f"[CRITICAL] Typosquat detected: {domain}")
                    # Auto-submit to Cloudflare/Vercel abuse APIs

logging.basicConfig(level=logging.INFO)
certstream.listen_for_events(
    on_certificate_update, 
    url='wss://certstream.calidog.io/'
)
```

#### ClickFix Clipboard Defender (Deep Research — Working Python MVP)
```python
import pyperclip, re, time, tkinter.messagebox as mb

MALICIOUS_PATTERNS = [
    r'powershell.*-[Ww]indow.*[Hh]idden',  # Hidden PS window
    r'mshta\.exe',                           # MSHTA execution
    r'cmd\.exe.*/c.*http',                   # CMD fetching remote payload
    r'curl.*\|.*bash',                       # Pipe to bash
    r'irm.*\|.*iex',                         # PowerShell Invoke-Expression
    r'certutil.*-decode',                    # Certutil decode
    r'regsvr32.*scrobj',                     # Scriptlet abuse
]

prev = ''
while True:
    current = pyperclip.paste()
    if current != prev:
        for pat in MALICIOUS_PATTERNS:
            if re.search(pat, current, re.IGNORECASE):
                mb.showwarning(
                    '⚠️ CLIPBOARD THREAT DETECTED',
                    'A malicious command was detected in your clipboard.\n\n'
                    'Do NOT paste this anywhere.\n\n'
                    'This may be a ClickFix / FakeCaptcha phishing attack.'
                )
                pyperclip.copy('')  # Clear clipboard immediately
                break
        prev = current
    time.sleep(0.3)
```

---

## 12. Threat Actor Intelligence

### MITRE ATT&CK Mappings — Current 2025 (from Gem-phish-last-research + Grok1)

#### Scattered Spider (UNC3944 / Octo Tempest)

| MITRE Technique | TTP | 2025 Evidence |
|----------------|-----|--------------|
| T1566.004 — Spearphishing Voice | Vishing helpdesk, impersonating employees | M&S breach, Co-op, Harrods |
| T1621 — MFA Fatigue | Repeated push notification until acceptance | Multiple targets |
| T1078.004 — Cloud Accounts | Snowflake credentials bulk exfiltration | M&S Snowflake data pull |
| T1486 — Data Encrypted for Impact | DragonForce, Qilin, Akira ransomware | M&S £300M impact |
| T1210 — Remote Service Exploitation | ADCS template abuse for domain certs | Post-M&S confirmed |
| T1056.004 — Credential API Hooking | NTDS.dit AD password hash dump | M&S April 2025 |
| T1562.001 — Disable Security Tools | BYOVD: signed kernel driver → kill EDR | Multiple targets |
| T1534 — Internal Spearphishing | Lateral phishing from compromised accounts | Post-access technique |

**M&S Breach Timeline (verified):**
- **February 2025:** Initial access via helpdesk vishing
- **February–April:** Dwell — NTDS.dit dump, lateral movement
- **April 22, 2025:** Incident goes public
- **April 24, 2025:** DragonForce ransomware deployed on VMware ESXi
- **Impact:** £300M profit impact, £500M stock drop, 46-day online sales suspension

**New TTP (July 29, 2025 advisory — CISA/FBI/NCSC/AUS/CAN):**  
*Reversed social engineering* — impersonating employees calling the third-party IT helpdesk (not IT calling employees). Exploits weaker verification in outsourced helpdesks.

---

#### TraderTraitor / Lazarus Group — Bybit Heist ($1.5B, Feb 2025)

| Date | Action |
|------|--------|
| Feb 4 | Developer machine compromised via malicious Python stock simulator |
| Feb 5 | Attacker accesses Safe{Wallet} AWS environment with stolen session tokens |
| Feb 19 | Malicious JavaScript injected into `app.safe.global` |
| Feb 21 | Bybit employees initiate routine transfer → injected code masks signing interface → 400K ETH redirected |

**MITRE Mapping:**
- `T1195.002` — Supply Chain Compromise: malicious JS in Safe{Wallet}
- `T1566.003` — Spearphishing via Service: fake LinkedIn recruiter lures
- `T1071.001` — C2 via Web Protocols: `getstockprice.com`

---

#### APT42 (Iran) — AI-Enhanced Operations
- **Confirmed use of Gemini** for target reconnaissance, persona crafting, multilingual translation (Google GTIG, Feb 2026)
- Multi-week AI chatbot conversations impersonating procurement agents / journalists
- Targets: Diplomats, journalists, government officials

#### APT29 (Russia) — Device Code Phishing
- `T1660` — Mobile phishing via WhatsApp / Signal
- Device code phishing confirmed against diplomatic organisations
- App-Specific Password abuse to bypass standard MFA (confirmed 2025)

---

## 13. Gaps

### What No Tool Currently Covers (Consensus Across All Sources)

| Gap | Severity | No Open-Source Tool? | Build Opportunity |
|-----|---------|---------------------|-------------------|
| **ClickFix clipboard injection monitor** | Critical | ✅ Confirmed gap | Tool #10 — 1 week |
| **SVG CDR (Content Disarm & Reconstruct)** | High | ✅ Confirmed gap | Tool #11 — 2–3 weeks |
| **OAuth app permission auditor (Entra ID)** | High | ✅ Confirmed gap | Tool #12 — 2–3 weeks |
| **EIP-7702 pre-signing simulation** | High | ✅ Confirmed gap | DrainerGuard Web3 |
| **QR decoding in email gateways at scale** | High | ✅ SEGs still missing | QuishGuard |
| **Real-time AiTM TLS fingerprinting** | High | Partial (Push Security) | AiTM Guardian |
| **Multilingual phishing detection** | Medium | ✅ Confirmed gap | Tool #11 |
| **Crypto address poisoning detector** | Medium | ✅ Confirmed gap | Tool #13 |
| **TPA behavioral redirect graph analysis** | High | ✅ Confirmed gap | TPA Sentinel |
| **Helpdesk platform cross-ref vs. brand DB** | Medium | ✅ Confirmed gap | FakeSender Shield |

**The "Intent Gap" (Gem-phish-last-research — best framing):**  
Current tools focus on **what** (domain, hash) rather than **why** (intent of the sequence). The next generation of detection must operate on behavioral intent analysis — not static signatures.

---

## 14. Portfolio Presentation Strategy

### The 5-Part Formula (from All Sources — Consensus Best Practice)

Every source agrees on this structure for presenting each tool:

**1. Documented Gap (cite the vendor)**
> *"Barracuda's 2025 report confirms most Secure Email Gateways do not decode QR codes embedded in PDF attachments. QuishGuard addresses this specific gap directly."*

**2. Your Innovation vs. Existing Tools**
> *"Every competing tool — Barracuda, Abnormal, Mimecast — decodes the URL first, risking scanner IP fingerprinting. QuishGuard uses pixel-structural analysis to detect malicious QR patterns before any URL is decoded. This is the correct security architecture."*

**3. Live Demo + Published Metrics**
> 2-minute video: scan a malicious invoice PDF → red flag in 2 seconds → confidence score → VirusTotal match  
> Publish: AUC score, false positive rate, inference latency, comparison to fouadtrad baseline

**4. Community Contribution**
> Publish extended 2025 QR dataset on Hugging Face  
> Contribute detection rules (YARA/Sigma) to SigmaHQ  
> Open-source the trained XGBoost model

**5. Write It Up**
> Technical blog post: *"How I Built the First Pre-Decode QR Phishing Detector"*  
> Reference KnowBe4 / Barracuda stats, explain the pixel-structural innovation  
> Cross-post to Medium, LinkedIn, and personal site

---

### Which Employer Wants Which Tool

| Tool | Target Employer | Why |
|------|----------------|-----|
| QuishGuard | Barracuda, Abnormal, Proofpoint, Mimecast | Directly addresses their documented product gap |
| GenAI Phish Shield | Microsoft, Google, Cofense, Darktrace | Privacy-first AI detection is their next product category |
| DrainerGuard Web3 | Chainalysis, Elliptic, TRM Labs, Coinbase Security | EIP-7702 is their most urgent 2025 threat |
| TPA Sentinel | CrowdStrike, SentinelOne, StrongestLayer | Behavioral detection is their differentiator |
| AiTM Guardian | Any enterprise security team, Okta, Duo Security | MFA bypass is their biggest customer complaint |
| CTI Pipeline | Any SOC, MSSP, ISAC member | Automation reduces analyst toil — universal value |
| FakeSender Shield | Microsoft (Defender for O365), Mimecast | Header analysis is in their core product |

---

### Quick-Start Sequence (Prioritised by ROI)

```
Week 1:   QuishGuard MVP (Python CLI + Streamlit demo)
Week 2:   Polish QuishGuard — Gmail add-in, benchmark vs. fouadtrad
Week 3:   Start GenAI Phish Shield — Ollama pipeline + perplexity scorer
Week 4:   GenAI Phish Shield — XGBoost ensemble + LIME explainability
Week 5:   CTI Pipeline-as-Code — async enrichment + STIX output
Week 6:   CTI Pipeline — GitHub Action + Grafana dashboard
Week 7–8: Write up all three — README, blog posts, demo videos
Week 9+:  Pick DrainerGuard or TPA Sentinel based on job targets
```

---

### README Template (for Every Tool)

```markdown
# [Tool Name]

> **[One-line innovation claim]**

## Why This Exists
[Cite 2025–2026 threat intel stat. Link to vendor report.]

## Innovation vs. Existing Tools
| Feature | [Your Tool] | [Competitor] | [Competitor 2] |
|---------|------------|-------------|---------------|
| ...     | ✅         | ❌          | ❌            |

## Accuracy Benchmarks
| Metric | Score | Dataset |
|--------|-------|---------|
| AUC    | X.XX  | [name]  |
| FPR    | X.X%  | [name]  |

## Demo
[GIF or link to 2-minute video]

## Quick Start
```bash
pip install -r requirements.txt
python quishguard.py --scan ./invoice.pdf
```

## Architecture
[Mermaid diagram]

## Dataset
[Link to extended dataset on Hugging Face]
```

---

*Document compiled from: Gem-phish-last-research · Phishing-gemini_Research · Phishing_ideas_-_gem · Phishing_grok_1 · Phishing_grok2 · Grok-fish-ideas · Grok-fish-ideas-2 · phishing_portfolio_ideas_2026 · Deep Research Results 2026*  
*February 2026 — Update quarterly*
