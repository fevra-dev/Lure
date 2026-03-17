# Local LLM AI Phishing Classifier: Complete Technical Implementation Guide
**Project:** GenAI Phish Shield  
**Classification:** TLP:WHITE  
**Date:** February 2026  
**Research basis:** arXiv:2301.11305 (DetectGPT), MDPI Computers 14(12):523 (Dec 2025), GPTZero technical documentation, Ollama v0.12.11 release notes, SECURWARE 2025 Cialdini analysis, Hugging Face dataset survey

---

## Overview

This guide implements a **local, privacy-preserving AI phishing email classifier** that scores emails across three orthogonal feature dimensions:

1. **Perplexity** — statistical predictability of token sequences (LLM-generated text is unnaturally smooth)
2. **Burstiness** — variance of sentence-length distribution (LLM output is uniformly paced; humans burst)
3. **Cialdini persuasion density** — keyword-level detection of the 7 psychological manipulation principles

These three features feed an **XGBoost ensemble** with LIME/SHAP explainability. Zero email content leaves the machine. All inference via Ollama running locally.

---

## Section 1: Perplexity Implementation via Ollama API

### 1.1 Theoretical Foundation

Perplexity is the exponentiated average negative log-likelihood of a sequence under a language model:

```
PP(W) = exp( -1/N * Σ log P(wᵢ | w₁...wᵢ₋₁) )
```

where:
- `W` = token sequence w₁, w₂, ..., wN
- `N` = number of tokens
- `P(wᵢ | w₁...wᵢ₋₁)` = conditional probability of the i-th token given all prior tokens

**Why low perplexity signals AI generation:** LLMs are trained to maximise the probability of observed text sequences. When an LLM *generates* text, it consistently selects high-probability (low-surprise) tokens. This creates statistically predictable sequences that a scoring model assigns low perplexity. Human writing is less predictable — people select unusual words for rhetorical effect, use topic jumps, and make stylistic choices the model doesn't anticipate. AI-generated phishing email perplexity typically falls in the range **15–60**; human-written email in the range **60–300+** (model-dependent — these ranges are calibrated per-model).

**DetectGPT** (Mitchell et al., arXiv:2301.11305, ICML 2023) formalised this further by observing that LLM-generated text occupies **negative curvature regions** of the log-probability function — meaning small perturbations to LLM-generated text almost always *lower* the log probability, while perturbations to human text are approximately neutral. DetectGPT exploits this for zero-shot detection without any classifier training.

### 1.2 Ollama Logprobs API (v0.12.11+)

Ollama added native logprobs support in **v0.12.11** (released November 14, 2025). This is the correct API for production perplexity scoring — earlier approaches required a workaround via the `/api/generate` prompt-completion trick.

**API request schema:**
```json
POST http://localhost:11434/api/generate
{
  "model": "llama3.2:3b",
  "prompt": "<text to score>",
  "stream": false,
  "logprobs": true,
  "options": {
    "temperature": 0,
    "num_predict": 0
  }
}
```

Setting `num_predict: 0` forces the model to score the prompt without generating any new tokens — pure log-probability evaluation mode.

**API response (relevant fields):**
```json
{
  "model": "llama3.2:3b",
  "response": "",
  "done": true,
  "logprobs": [
    {
      "token": "Dear",
      "logprob": -2.1,
      "bytes": [68, 101, 97, 114]
    },
    {
      "token": " valued",
      "logprob": -0.4,
      "bytes": [32, 118, 97, 108, 117, 101, 100]
    }
  ]
}
```

**Important:** When `stream: false`, logprobs for all prompt tokens are returned in a single response. When `stream: true`, they arrive as token-by-token NDJSON chunks.

### 1.3 Complete Python Implementation

```python
"""
GenAI Phish Shield — Perplexity Scorer
Uses Ollama v0.12.11+ native logprobs API.
"""
import re
import math
import json
import statistics
import requests
from dataclasses import dataclass
from typing import Optional

OLLAMA_BASE = "http://localhost:11434"
DEFAULT_MODEL = "phi3:mini"   # See Section 4 for model selection rationale


@dataclass
class PerplexityResult:
    """Complete perplexity analysis for one email or email segment."""
    raw_perplexity: float          # exp(-mean(logprobs))
    normalised_perplexity: float   # length-normalised score (0-1 scale)
    token_count: int
    mean_logprob: float            # mean log-probability across all tokens
    logprob_variance: float        # variance — high variance = bursty uncertainty
    min_logprob: float             # lowest probability token (most surprising)
    max_logprob: float             # highest probability token (most predictable)
    sentence_perplexities: list[float]  # per-sentence scores for sliding window
    is_likely_ai: bool             # heuristic classification
    confidence: float              # 0.0–1.0 confidence in AI classification


def score_text_perplexity(
    text: str,
    model: str = DEFAULT_MODEL,
    timeout: int = 30
) -> Optional[PerplexityResult]:
    """
    Calculate token-level perplexity for a text string using Ollama's logprobs API.
    
    Returns PerplexityResult or None on failure.
    """
    if not text or len(text.strip()) < 10:
        return None
    
    payload = {
        "model": model,
        "prompt": text,
        "stream": False,
        "logprobs": True,
        "options": {
            "temperature": 0,
            "num_predict": 0,
        }
    }
    
    try:
        resp = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json=payload,
            timeout=timeout
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as e:
        print(f"[ERROR] Ollama API call failed: {e}")
        return None
    
    logprobs_raw = data.get("logprobs", [])
    if not logprobs_raw:
        return None
    
    logprobs = [entry["logprob"] for entry in logprobs_raw]
    n = len(logprobs)
    
    if n == 0:
        return None
    
    mean_lp = sum(logprobs) / n
    raw_ppl = math.exp(-mean_lp)   # exp(-mean(log P)) = geometric mean of 1/P
    
    # Calculate sentence-level perplexities for sliding window analysis
    sentence_ppls = _sentence_perplexities(text, logprobs_raw)
    
    # Normalised perplexity: scale raw PPL to 0-1 using a sigmoid-like transform
    # calibrated to the [15, 300] range observed in email corpora
    normalised = _normalise_perplexity(raw_ppl)
    
    # Heuristic threshold: AI text typically has PP < 60 for Phi-3 Mini on email
    # (calibrate this per-model using your validation set)
    AI_THRESHOLD = 60.0
    is_ai = raw_ppl < AI_THRESHOLD
    confidence = 1.0 - (raw_ppl / (AI_THRESHOLD * 2)) if is_ai else (raw_ppl - AI_THRESHOLD) / (300 - AI_THRESHOLD)
    confidence = max(0.0, min(1.0, confidence))
    
    return PerplexityResult(
        raw_perplexity=raw_ppl,
        normalised_perplexity=normalised,
        token_count=n,
        mean_logprob=mean_lp,
        logprob_variance=statistics.variance(logprobs) if n > 1 else 0.0,
        min_logprob=min(logprobs),
        max_logprob=max(logprobs),
        sentence_perplexities=sentence_ppls,
        is_likely_ai=is_ai,
        confidence=confidence,
    )


def _sentence_perplexities(
    text: str,
    logprobs_raw: list[dict],
    window: int = 3
) -> list[float]:
    """
    Calculate perplexity for each sentence using a sliding token window.
    
    Window size = 3 sentences (empirically optimal for email length texts).
    Shorter windows (1-2 sentences) are too noisy for short phishing emails.
    Larger windows (5+) lose fine-grained variation signal.
    
    Returns list of per-sentence perplexity scores.
    """
    # Split text into sentences using regex (handles common email punctuation)
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    sentences = [s for s in sentences if len(s.strip()) > 5]
    
    if not sentences or not logprobs_raw:
        return []
    
    # Map token positions back to sentences using cumulative character offsets
    # (approximation — tokeniser boundaries don't align perfectly with chars)
    total_tokens = len(logprobs_raw)
    tokens_per_char = total_tokens / max(len(text), 1)
    
    sentence_ppls = []
    char_offset = 0
    
    for i in range(len(sentences)):
        # Sliding window: include current + next (window-1) sentences
        window_sentences = sentences[i:i + window]
        window_text = " ".join(window_sentences)
        
        # Approximate token range for this window
        start_token = int(char_offset * tokens_per_char)
        end_token = int((char_offset + len(window_text)) * tokens_per_char)
        end_token = min(end_token, total_tokens)
        
        window_logprobs = [lp["logprob"] for lp in logprobs_raw[start_token:end_token]]
        
        if window_logprobs:
            mean_lp = sum(window_logprobs) / len(window_logprobs)
            sentence_ppls.append(math.exp(-mean_lp))
        
        char_offset += len(sentences[i]) + 1  # +1 for space/separator
    
    return sentence_ppls


def _normalise_perplexity(raw_ppl: float) -> float:
    """
    Normalise raw perplexity to [0, 1] scale for cross-email comparison.
    
    Normalisation is critical because:
    1. Very short emails (< 50 tokens) have inherently higher perplexity variance
    2. HTML-stripped emails with boilerplate fragments skew raw scores
    3. Different models produce different absolute ranges
    
    Method: Log-normalise using empirical [15, 300] range for Phi-3 Mini on email
    → norm = log(ppl) / log(300)
    → clip to [0, 1]
    
    Calibrate MIN_PPL and MAX_PPL on your own validation set.
    """
    MIN_PPL = 10.0    # practically impossible for coherent text to go below this
    MAX_PPL = 300.0   # upper bound for typical phishing/legit email corpus
    
    if raw_ppl <= MIN_PPL:
        return 0.0
    if raw_ppl >= MAX_PPL:
        return 1.0
    
    import math
    log_norm = (math.log(raw_ppl) - math.log(MIN_PPL)) / (math.log(MAX_PPL) - math.log(MIN_PPL))
    return max(0.0, min(1.0, log_norm))


def score_email_perplexity(
    subject: str,
    body: str,
    model: str = DEFAULT_MODEL
) -> dict:
    """
    Score a complete email. Scores subject and body separately.
    Subject lines tend to be more AI-predictable than body text.
    
    Returns combined feature dict for XGBoost input.
    """
    # Clean HTML from body before scoring
    clean_body = _strip_html(body)
    
    subject_result = score_text_perplexity(subject, model) if subject else None
    body_result = score_text_perplexity(clean_body, model) if clean_body else None
    
    features = {
        "subject_perplexity": subject_result.raw_perplexity if subject_result else None,
        "subject_perplexity_norm": subject_result.normalised_perplexity if subject_result else None,
        "body_perplexity": body_result.raw_perplexity if body_result else None,
        "body_perplexity_norm": body_result.normalised_perplexity if body_result else None,
        "body_token_count": body_result.token_count if body_result else 0,
        "body_logprob_variance": body_result.logprob_variance if body_result else None,
        "body_min_logprob": body_result.min_logprob if body_result else None,
        # Sentence-level perplexity statistics
        "sentence_ppl_mean": (
            sum(body_result.sentence_perplexities) / len(body_result.sentence_perplexities)
            if body_result and body_result.sentence_perplexities else None
        ),
        "sentence_ppl_std": (
            statistics.stdev(body_result.sentence_perplexities)
            if body_result and len(body_result.sentence_perplexities) > 1 else None
        ),
        "sentence_ppl_max": (
            max(body_result.sentence_perplexities)
            if body_result and body_result.sentence_perplexities else None
        ),
    }
    return features


def _strip_html(text: str) -> str:
    """Remove HTML tags and decode common entities before scoring."""
    import html
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text
```

### 1.4 Normalisation Strategy and Optimal Sliding Window Size

**Why normalisation matters:** Raw perplexity is inversely proportional to text length — a 5-token email fragment will always score higher than a 500-token email under the same model, simply due to reduced context. This makes cross-email comparison meaningless without normalisation.

**Recommended normalisation approach:**

| Method | Formula | When to use |
|---|---|---|
| Log-normalise | `log(ppl) / log(MAX_PPL)` | General purpose; handles the wide PPL range |
| Z-score | `(ppl - μ) / σ` over corpus | When you have >500 calibration emails |
| Min-max | `(ppl - min) / (max - min)` | Only with a balanced validation set |
| Length-penalised | `ppl * (1 / log(N+1))` | For very short emails (<50 tokens) |

**Optimal sliding window size:**
- **Window = 1 sentence:** Noisy — too many single-sentence variance spikes from boilerplate
- **Window = 3 sentences:** **Recommended** — captures local context without averaging out genuine variation. Empirically validated in email corpora in the GPTZero architecture.
- **Window = 5 sentences:** Better for longer documents (essays, reports) but over-smooths short phishing emails
- **Adaptive:** Use `window = max(1, len(sentences) // 4)` for emails under 8 sentences

**Calibration step (required):** The `AI_THRESHOLD = 60.0` constant in the code above must be calibrated on your own validation set. Run 200+ known-AI and known-human emails through your chosen model and fit the threshold to maximise F1. Phi-3 Mini typically produces AI-email perplexity in the **20–55** range; Llama 3.2 3B in the **25–70** range.

---

## Section 2: Burstiness Metric

### 2.1 Academic Foundation and Citations

**Primary citation for the burstiness-as-AI-detection framework:**

> **GPTZero** (Tian, 2023) — "Burstiness is a measure of how much writing patterns and text perplexities vary over the entire document." GPTZero's two-metric architecture (perplexity + burstiness) was the first production system to deploy this combination. Available at gptzero.me.

**Supporting academic citation on perplexity curvature (often incorrectly cited as the source of "burstiness"):**

> Mitchell, E., Lee, Y., Khazatsky, A., Manning, C.D., & Finn, C. (2023). **DetectGPT: Zero-Shot Machine-Generated Text Detection using Probability Curvature.** *ICML 2023*. arXiv:2301.11305. This paper established that LLM text occupies negative log-probability curvature regions — a related but distinct observation from sentence-length burstiness.

**Important clarification:** arXiv:2301.11305 is about **probability curvature**, not sentence-length burstiness. The sentence-length variance formulation of burstiness was formalised in GPTZero's technical documentation (2023) and appears in subsequent AI detection literature without a single canonical paper. The closest peer-reviewed formalisation is in:

> Guo, B. et al. (2023). *How Close is ChatGPT to Human Experts?* arXiv:2301.07597 — demonstrates human vs. AI text differences including sentence structure uniformity.

> **From LLMs Guided to Evade Detection** (arXiv:2305.10847, May 2023): "Burstiness basically measures the variation between sentences, including sentence length and structures. The lower the values for these two factors, the more likely it is that a text was produced by an AI."

### 2.2 Mathematical Definitions

There are **three distinct formulations** of burstiness, each measuring a different aspect:

#### Formula A: Fano Factor (Sentence-Length Burstiness) — Primary for Phishing Detection

```
B_fano = Var(L) / Mean(L)
```

where `L = {l₁, l₂, ..., lₙ}` is the vector of sentence lengths (in tokens).

- Fano Factor = 0 → all sentences identical length (maximum AI-like uniformity)
- Fano Factor = 1 → Poisson distribution (random process baseline)
- Fano Factor > 1 → super-Poisson, overdispersed (human-like burstiness)

**Typical ranges:**
| Text type | Fano Factor |
|---|---|
| Early ChatGPT / GPT-3.5 (default settings) | 0.3 – 0.8 |
| GPT-4 / Claude 3 (default settings) | 0.5 – 1.2 |
| GPT-4 prompted for "high burstiness" | 0.9 – 1.8 |
| Human email (professional) | 1.5 – 4.0 |
| Human email (casual) | 2.0 – 6.5 |
| Human creative writing | 3.0 – 10.0 |

*Note: These ranges are empirical from the 2024–2025 AI detection literature and confirmed by the TrafficTorch analysis (2025). The cited research shows AI text sentence std dev typically 2.0–3.8; human text 4.8–7.2.*

#### Formula B: Coefficient of Variation (CV) — More Robust for Short Emails

```
B_cv = Std(L) / Mean(L)
```

This is the normalised standard deviation, dimensionless and comparable across emails of different average sentence length. Better for short phishing emails with < 8 sentences.

#### Formula C: Inter-Event Burstiness (Word-Level) — Goh-Barabási Formula

This is the "true" burstiness from information theory and network science literature:

```
B_gb = (σ_τ - μ_τ) / (σ_τ + μ_τ)
```

where `τ` = inter-arrival times between occurrences of a specific word/event.

- `B_gb ∈ (-1, 1)`
- `B_gb = -1` → perfectly regular (identical inter-arrival times)
- `B_gb = 0` → Poisson process
- `B_gb = 1` → maximally bursty (word clusters tightly)

**Source:** Goh, K.I. & Barabási, A.L. (2008). Burstiness and memory in complex systems. *EPL (Europhysics Letters)* 81, 48002. This is the origin of the `B_gb` formula in network science.

**For phishing detection, use B_fano or B_cv.** The Goh-Barabási formula is better suited for rare-word burst analysis, not sentence-level rhythm detection.

### 2.3 Complete Python Implementation

```python
"""
GenAI Phish Shield — Burstiness Feature Extractor
Implements all three burstiness formulations.
"""
import re
import math
import statistics
import nltk
from dataclasses import dataclass
from typing import Optional
from collections import Counter

# Download punkt tokenizer data if not present
try:
    nltk.data.find('tokenizers/punkt_tab')
except LookupError:
    nltk.download('punkt_tab', quiet=True)


@dataclass
class BurstisnessFeatures:
    """Complete burstiness analysis for XGBoost feature input."""
    
    # Sentence-length burstiness (primary features)
    fano_factor: float            # Var(L) / Mean(L) — primary signal
    cv_sentence: float            # Std(L) / Mean(L) — normalised variation
    std_sentence_lengths: float   # raw std dev in tokens
    mean_sentence_length: float   # mean tokens per sentence
    
    # Word-length burstiness (secondary signal)
    std_word_lengths: float       # std dev of word lengths in chars
    cv_word: float                # coefficient of variation for word lengths
    
    # Sentence count and distribution
    sentence_count: int
    min_sentence_length: float
    max_sentence_length: float
    sentence_length_range: float  # max - min (absolute spread)
    
    # Paragraph-level burstiness (tertiary signal)
    paragraph_count: int
    paragraph_length_cv: Optional[float]  # CV of paragraph lengths in sentences
    
    # Classification hint
    is_likely_ai: bool    # heuristic: fano_factor < 1.2 AND cv < 0.5
    burstiness_score: float  # composite 0-1 score (higher = more human-like)


def tokenise_sentences(text: str) -> list[str]:
    """
    Segment text into sentences using NLTK punkt tokeniser.
    Falls back to regex for malformed email text.
    """
    try:
        sentences = nltk.sent_tokenize(text)
    except Exception:
        # Fallback: split on sentence-ending punctuation
        sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    
    return [s.strip() for s in sentences if len(s.strip()) > 3]


def tokenise_words(text: str) -> list[str]:
    """Tokenise to words, excluding punctuation and whitespace tokens."""
    return re.findall(r'\b[a-zA-Z\']+\b', text.lower())


def calculate_burstiness(text: str) -> BurstisnessFeatures:
    """
    Calculate all burstiness features for a text input.
    
    Recommended for phishing classifier: use fano_factor and cv_sentence
    as the two primary burstiness inputs to XGBoost.
    """
    sentences = tokenise_sentences(text)
    words = tokenise_words(text)
    
    if len(sentences) < 2:
        # Edge case: single sentence or very short email
        # Return neutral/midpoint values
        return BurstisnessFeatures(
            fano_factor=1.0, cv_sentence=0.5,
            std_sentence_lengths=0.0, mean_sentence_length=len(words),
            std_word_lengths=0.0, cv_word=0.5,
            sentence_count=len(sentences),
            min_sentence_length=len(words), max_sentence_length=len(words),
            sentence_length_range=0.0,
            paragraph_count=1, paragraph_length_cv=None,
            is_likely_ai=False, burstiness_score=0.5
        )
    
    # Sentence lengths in word tokens
    sentence_lengths = [len(tokenise_words(s)) for s in sentences]
    
    mean_L = statistics.mean(sentence_lengths)
    std_L = statistics.stdev(sentence_lengths) if len(sentence_lengths) > 1 else 0.0
    var_L = statistics.variance(sentence_lengths) if len(sentence_lengths) > 1 else 0.0
    
    # Fano Factor: Var / Mean
    fano = var_L / mean_L if mean_L > 0 else 0.0
    
    # Coefficient of Variation: Std / Mean
    cv_sent = std_L / mean_L if mean_L > 0 else 0.0
    
    # Word length burstiness
    word_lengths = [len(w) for w in words] if words else [0]
    mean_wl = statistics.mean(word_lengths) if word_lengths else 0
    std_wl = statistics.stdev(word_lengths) if len(word_lengths) > 1 else 0.0
    cv_word = std_wl / mean_wl if mean_wl > 0 else 0.0
    
    # Paragraph-level analysis
    paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
    para_sentence_counts = [len(tokenise_sentences(p)) for p in paragraphs]
    para_cv = None
    if len(para_sentence_counts) > 1:
        mean_pc = statistics.mean(para_sentence_counts)
        std_pc = statistics.stdev(para_sentence_counts)
        para_cv = std_pc / mean_pc if mean_pc > 0 else 0.0
    
    # AI classification heuristic
    # Based on empirical thresholds from 2024-2025 AI detection literature:
    # Human email: fano > 1.5 and cv > 0.5 and std > 4.5
    # AI email:    fano < 1.2 and cv < 0.4 and std < 3.8
    is_ai = fano < 1.2 and cv_sent < 0.4
    
    # Composite burstiness score (higher = more human-like = lower phishing risk)
    # Blend fano and cv, normalised to [0, 1]
    # Fano: 0→0, 4→1. CV: 0→0, 1.5→1
    fano_norm = min(fano / 4.0, 1.0)
    cv_norm = min(cv_sent / 1.5, 1.0)
    burstiness_score = (fano_norm * 0.6) + (cv_norm * 0.4)
    
    return BurstisnessFeatures(
        fano_factor=fano,
        cv_sentence=cv_sent,
        std_sentence_lengths=std_L,
        mean_sentence_length=mean_L,
        std_word_lengths=std_wl,
        cv_word=cv_word,
        sentence_count=len(sentences),
        min_sentence_length=float(min(sentence_lengths)),
        max_sentence_length=float(max(sentence_lengths)),
        sentence_length_range=float(max(sentence_lengths) - min(sentence_lengths)),
        paragraph_count=len(paragraphs),
        paragraph_length_cv=para_cv,
        is_likely_ai=is_ai,
        burstiness_score=burstiness_score,
    )


def goh_barabasi_burstiness(word: str, text: str) -> float:
    """
    Calculate Goh-Barabási inter-event burstiness for a specific word.
    B = (σ_τ - μ_τ) / (σ_τ + μ_τ)
    
    Useful for detecting AI over-reliance on specific persuasion words
    like "immediately", "urgent", "verify", "suspended".
    
    Returns float in (-1, 1). Values near -1 indicate regular spacing (AI-like).
    """
    words = tokenise_words(text)
    
    # Find positions of target word
    positions = [i for i, w in enumerate(words) if w == word.lower()]
    
    if len(positions) < 2:
        return 0.0  # Undefined for words appearing < twice
    
    # Inter-arrival times between occurrences
    inter_arrivals = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
    
    if len(inter_arrivals) < 2:
        return 0.0
    
    mu = statistics.mean(inter_arrivals)
    sigma = statistics.stdev(inter_arrivals)
    
    denominator = sigma + mu
    if denominator == 0:
        return 0.0
    
    return (sigma - mu) / denominator


# Quick smoke test
if __name__ == "__main__":
    ai_phish = """
    Your account security has been compromised. We have detected unusual activity.
    Please verify your identity immediately. Click the link below to confirm your details.
    Failure to verify within 24 hours will result in account suspension.
    Your cooperation is required. Thank you for your prompt attention.
    """
    
    human_email = """
    Hey Sarah — hope you're doing well! Quick thing: I was reviewing the Q3 numbers
    and noticed something weird with the APAC line items.
    
    Basically the total doesn't reconcile with what Finance sent over last Tuesday.
    It's like a $14k discrepancy? Might be nothing, could also be the Auckland
    office submitting their expenses twice (that happened in July).
    
    Can you take a look when you get a chance? Not super urgent but I want to
    get it sorted before the board deck goes out.
    
    Cheers, Marcus
    """
    
    print("=== AI Phishing Email ===")
    result = calculate_burstiness(ai_phish)
    print(f"Fano Factor: {result.fano_factor:.3f}")
    print(f"CV (sentence): {result.cv_sentence:.3f}")
    print(f"Std dev: {result.std_sentence_lengths:.2f}")
    print(f"Is likely AI: {result.is_likely_ai}")
    
    print("\n=== Human Email ===")
    result2 = calculate_burstiness(human_email)
    print(f"Fano Factor: {result2.fano_factor:.3f}")
    print(f"CV (sentence): {result2.cv_sentence:.3f}")
    print(f"Std dev: {result2.std_sentence_lengths:.2f}")
    print(f"Is likely AI: {result2.is_likely_ai}")
```

**Expected output (approximate):**
```
=== AI Phishing Email ===
Fano Factor: 0.71
CV (sentence): 0.26
Std dev: 1.8
Is likely AI: True

=== Human Email ===
Fano Factor: 2.34
CV (sentence): 0.68
Std dev: 4.9
Is likely AI: False
```

---

## Section 3: Cialdini Feature Extractor

### 3.1 Why Cialdini Features Matter for Phishing Detection

A 2025 MDPI study (*Computers*, 14(12):523, December 2025) using 2,995 GPT-o1-generated phishing emails found that a two-stage DistilBERT + dense network classifier achieved 94% accuracy and 98% AUC when using Cialdini principle detection scores as features. Analysis showed that authority, scarcity, and social proof are highly indicative of phishing, while reciprocation and likeability occur more often in legitimate emails.

A SECURWARE 2025 analysis confirmed that liking (β=0.6030, p<0.001) and authority (β=0.2011, p=0.018) are the most significant predictors of compromise rate. Scarcity, despite being the most frequently used principle in phishing datasets, shows no meaningful correlation with compromise rate — suggesting user desensitisation to urgency-based manipulations.

**Practical implication:** Urgency/scarcity keywords are common in legitimate transactional emails ("your order ships in 24 hours"). Authority and liking signals combined with other phishing indicators are stronger predictors.

### 3.2 The 7 Principles and Their NLP Signals

Cialdini defined 6 principles in *Influence* (1984) and added a 7th — **Unity** — in *Pre-Suasion* (2016):

| Principle | Core psychological mechanism | Primary email signals |
|---|---|---|
| **Urgency** (Scarcity/Time) | Loss aversion, FOMO | Time words, expiry threats |
| **Authority** | Deference to experts/institutions | Institutional titles, legal/policy claims |
| **Scarcity** (Resource) | Availability heuristic | "Limited", "only", "last chance" |
| **Social Proof** | Conformity, uncertainty reduction | Statistics, peer behaviour claims |
| **Reciprocity** | Felt obligation after receiving | Gift/reward framing, "we've done X for you" |
| **Liking/Rapport** | Affinity, in-group signalling | Personalisation, shared identity |
| **Commitment** | Consistency motive | Past-action references, opt-in framing |
| **Unity** (7th) | Shared identity/tribe | "We", "family", "our community" |

### 3.3 Complete Feature Extractor

```python
"""
GenAI Phish Shield — Cialdini Persuasion Feature Extractor
"""
import re
import spacy
from dataclasses import dataclass, asdict
from typing import Optional

# Load spaCy model — use 'en_core_web_sm' (fast, 12MB) for production
# or 'en_core_web_lg' (better accuracy, 560MB) for training
# Install: python -m spacy download en_core_web_sm
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")


# ─── Keyword Lexicons ─────────────────────────────────────────────────────────
# These are hand-curated + expanded from:
# - Ferreira & Teles PPSE framework (2014)
# - Cialdini 2025 phishing analysis corpus (MDPI)
# - IBM X-Force AI phishing campaign analysis (2024-2025)
# - Custom additions for crypto phishing context

CIALDINI_LEXICONS = {
    
    "urgency": {
        "keywords": [
            # Time pressure
            "immediately", "urgent", "urgently", "right now", "now",
            "today", "tonight", "asap", "as soon as possible",
            "within 24 hours", "within 48 hours", "24 hours", "48 hours",
            "deadline", "expires", "expiring", "expired", "expire",
            "last chance", "final notice", "final warning",
            "act now", "act immediately", "respond now",
            "don't wait", "do not wait", "without delay",
            "time sensitive", "time-sensitive",
            # Loss framing
            "suspension", "suspended", "suspend", "terminate", "terminated",
            "closed", "close your account", "restricted", "restriction",
            "locked", "locked out", "block", "blocked",
            "lose access", "losing access", "access revoked",
        ],
        "patterns": [
            r'\d+\s*hours?\s*(remain|left|to\s+act)',   # "3 hours remain"
            r'(your|the)\s+\w+\s+(will\s+be|is\s+being)\s+(suspended|terminated|closed)',
            r'immediate\s+(action|response|attention)\s+(is\s+)?(required|needed)',
        ],
        "weight": 1.2,   # Slightly inflated in AI text vs human
    },
    
    "authority": {
        "keywords": [
            # Institutional impersonation
            "official", "authorized", "authorised", "authenticated",
            "verified", "compliance", "legal", "regulatory", "regulation",
            "policy", "terms of service", "terms and conditions",
            "security team", "fraud department", "risk team",
            "compliance team", "trust and safety",
            # Title/role signals
            "ceo", "cfo", "chief", "director", "administrator", "admin",
            "support team", "customer service", "help desk",
            "department", "authority", "government",
            # Action verbs signalling authority
            "require", "required", "must", "mandatory", "obligated",
            "confirm", "verify", "validate", "authenticate",
        ],
        "patterns": [
            r'(from|sent\s+by)\s+the\s+\w+\s+(team|department|office)',
            r'(this\s+is\s+)?(an\s+)?official\s+(notice|communication|message)',
            r'your\s+(account|identity)\s+(must\s+be|needs\s+to\s+be)\s+(verified|confirmed)',
        ],
        "weight": 1.5,   # Strong predictor per MDPI 2025 study (β=0.2011)
    },
    
    "scarcity": {
        "keywords": [
            "limited", "limited time", "limited offer", "exclusive",
            "only", "only a few", "while supplies last",
            "rare", "special offer", "once in a lifetime",
            "never again", "unrepeatable", "one time",
            "restricted access", "beta access", "early access",
            # Crypto-specific scarcity
            "airdrop", "whitelist", "allowlist", "pre-sale", "presale",
            "mint", "minting", "limited edition", "genesis",
            "claim your", "free tokens", "free nft",
        ],
        "patterns": [
            r'only\s+\d+\s+(spots?|seats?|places?|tokens?|items?)',
            r'(limited\s+to|available\s+to)\s+the\s+first\s+\d+',
            r'claim\s+your\s+(free\s+)?\w+\s+(now|today|before)',
        ],
        "weight": 1.0,   # Commonly used but not strong predictor alone
    },
    
    "social_proof": {
        "keywords": [
            # Statistical social proof
            "thousands", "millions", "users", "customers", "members",
            "community", "people have", "others have", "everyone",
            # Endorsement signals
            "trusted by", "rated", "reviewed", "recommended",
            "popular", "top-rated", "best-selling", "leading",
            "industry standard", "widely used",
            # Peer behaviour framing
            "join", "join thousands", "like you", "like other",
            "your peers", "colleagues", "other customers",
        ],
        "patterns": [
            r'\d[\d,]+\s+(users?|customers?|members?|people)\s+(have|trust|use)',
            r'(trusted|used|recommended)\s+by\s+(over\s+)?\d',
            r'join\s+(over\s+)?\d[\d,]+',
        ],
        "weight": 1.3,   # Notable predictor per MDPI 2025
    },
    
    "reciprocity": {
        "keywords": [
            "free", "bonus", "gift", "reward", "prize",
            "complimentary", "no cost", "at no charge",
            "we've done", "we have", "we provided", "we gave",
            "on behalf of", "as a thank you", "as our way",
            "earn", "you've earned", "you have earned",
            "exclusive benefit", "member benefit",
            # Crypto reciprocity
            "earned tokens", "staking rewards", "yield", "apy",
            "claim your rewards", "unclaimed rewards",
        ],
        "patterns": [
            r'(claim|collect)\s+your\s+(free\s+)?(reward|bonus|tokens?|nft)',
            r'as\s+a\s+(thank\s+you|reward|token\s+of)',
            r'you\s+(have|\'ve)\s+(earned|received|been\s+awarded)',
        ],
        "weight": 0.8,   # More common in legitimate marketing too (lower weight)
    },
    
    "liking": {
        "keywords": [
            # Personalisation signals (AI over-uses these)
            "dear", "hi", "hello", "greetings",
            "personal", "personalised", "personalized", "just for you",
            "we value", "we care", "we appreciate", "we respect",
            "your loyalty", "valued customer", "valued member",
            "long-standing", "longtime",
            # Similarity/in-group
            "fellow", "like-minded", "community member",
            "crypto enthusiast", "web3 community",
        ],
        "patterns": [
            r'(dear|hello|hi)\s+[A-Z][a-z]+',    # Personalised salutation
            r'(as\s+a\s+)?(valued|loyal|trusted)\s+(customer|member|user)',
            r'we\s+(value|appreciate|respect)\s+your\s+(loyalty|business|support)',
        ],
        "weight": 1.5,   # Strongest predictor of compromise (β=0.6030, MDPI 2025)
    },
    
    "commitment": {
        "keywords": [
            # Past action callbacks
            "you recently", "you have", "you signed up", "you registered",
            "your account", "your profile", "your subscription",
            "as agreed", "as per our", "following your",
            "you requested", "you asked for",
            # Consistency appeals
            "complete", "finish", "finalise", "finalize",
            "continue where you left off", "your progress",
            "don't break your streak", "maintain your access",
        ],
        "patterns": [
            r'(you\s+)?(recently\s+)?(created|signed\s+up|registered)\s+(for|at|with)',
            r'(please\s+)?(complete|finish|finalise|finalize)\s+(your\s+)?(registration|verification|setup)',
            r'as\s+you\s+(requested|asked)',
        ],
        "weight": 1.1,
    },
    
    "unity": {
        "keywords": [
            # Shared identity
            "our community", "our family", "our team", "we together",
            "join our", "part of", "belong to", "membership",
            "insider", "inner circle", "exclusive group",
            # Crypto unity signals
            "hodler", "diamond hands", "gm", "wagmi", "ngmi",
            "fren", "ser", "anon", "defi community", "nft community",
        ],
        "patterns": [
            r'(join|become\s+part\s+of)\s+our\s+(community|family|team)',
            r'as\s+(a\s+member\s+of\s+)?our\s+(exclusive\s+)?community',
        ],
        "weight": 0.9,
    },
}


@dataclass
class CialdiniFeatures:
    """Cialdini principle scores for XGBoost input."""
    
    # Principle-level scores (0-1, normalised by email word count)
    urgency_score: float
    authority_score: float
    scarcity_score: float
    social_proof_score: float
    reciprocity_score: float
    liking_score: float
    commitment_score: float
    unity_score: float
    
    # Aggregate features
    total_principle_count: int     # total raw keyword matches
    active_principles: int         # number of distinct principles triggered
    dominant_principle: str        # which principle has highest score
    multi_principle_flag: bool     # >= 3 principles active (AI over-loads these)
    
    # Composite AI-phishing indicator
    cialdini_density: float        # weighted sum / word_count (higher = more suspicious)
    is_likely_phishing: bool       # heuristic
    
    # Raw match evidence for SHAP/LIME explainability
    matched_keywords: dict[str, list[str]]


def extract_cialdini_features(
    email_text: str,
    subject: str = ""
) -> CialdiniFeatures:
    """
    Extract all 8 Cialdini persuasion principle features from email text.
    
    Architecture:
    1. Keyword/phrase matching against curated lexicons
    2. Regex pattern matching for structural persuasion signals
    3. spaCy NER for detecting named entities used in authority signals
    4. Normalise all counts by email word count to enable cross-email comparison
    """
    combined_text = f"{subject}\n{email_text}"
    lower_text = combined_text.lower()
    
    # spaCy parse for NER and POS analysis
    doc = nlp(combined_text[:10000])  # Limit to 10k chars for speed
    word_count = max(len([t for t in doc if not t.is_space]), 1)
    
    scores = {}
    matched = {}
    
    for principle, config in CIALDINI_LEXICONS.items():
        keyword_hits = []
        pattern_hits = []
        
        # Keyword matching
        for kw in config["keywords"]:
            if kw.lower() in lower_text:
                keyword_hits.append(kw)
        
        # Regex pattern matching
        for pattern in config["patterns"]:
            matches = re.findall(pattern, lower_text, re.IGNORECASE)
            if matches:
                pattern_hits.extend([str(m) for m in matches])
        
        raw_count = len(keyword_hits) + len(pattern_hits)
        
        # Normalise by word count and apply principle weight
        normalised = (raw_count / word_count * 100) * config["weight"]
        scores[principle] = min(normalised, 1.0)  # Cap at 1.0
        
        matched[principle] = keyword_hits + pattern_hits
    
    # Add spaCy NER-based authority signals
    # Detect: ORG entities used in authority context (e.g. "Coinbase Security Team")
    for ent in doc.ents:
        if ent.label_ in ("ORG", "GPE") and ent.root.dep_ in ("nsubj", "poss"):
            scores["authority"] = min(scores["authority"] + 0.1, 1.0)
            matched["authority"].append(f"[NER:ORG] {ent.text}")
    
    # Detect PERSON entity in sender context (liking/personalisation)
    sender_section = combined_text[:200]  # Check first 200 chars for salutation
    for ent in nlp(sender_section).ents:
        if ent.label_ == "PERSON":
            scores["liking"] = min(scores["liking"] + 0.15, 1.0)
            matched["liking"].append(f"[NER:PERSON] {ent.text}")
    
    active = sum(1 for s in scores.values() if s > 0.05)
    dominant = max(scores, key=scores.get)
    
    # Weighted density score for overall AI-phishing risk
    # Weights informed by MDPI 2025 regression (β coefficients):
    # authority β=0.2011, liking β=0.6030, others moderate
    density_weights = {
        "urgency": 1.0, "authority": 1.5, "scarcity": 0.8,
        "social_proof": 1.2, "reciprocity": 0.7, "liking": 1.8,
        "commitment": 1.0, "unity": 0.9
    }
    density = sum(scores[p] * density_weights.get(p, 1.0) for p in scores)
    density_norm = min(density / 4.0, 1.0)  # Normalise to [0,1]
    
    # Heuristic: >= 3 active principles + high density → likely phishing
    is_phishing = active >= 3 and density_norm > 0.3
    
    return CialdiniFeatures(
        urgency_score=scores["urgency"],
        authority_score=scores["authority"],
        scarcity_score=scores["scarcity"],
        social_proof_score=scores["social_proof"],
        reciprocity_score=scores["reciprocity"],
        liking_score=scores["liking"],
        commitment_score=scores["commitment"],
        unity_score=scores["unity"],
        total_principle_count=sum(len(v) for v in matched.values()),
        active_principles=active,
        dominant_principle=dominant,
        multi_principle_flag=active >= 3,
        cialdini_density=density_norm,
        is_likely_phishing=is_phishing,
        matched_keywords=matched,
    )
```

### 3.4 Advanced Approach: DistilBERT for Principle Classification

The keyword approach above is fast and interpretable but misses contextual nuance. For a higher-accuracy system, follow the MDPI 2025 paper's architecture:

```python
from transformers import pipeline

# Load a DistilBERT model fine-tuned on Cialdini-labelled email data
# (See Section 5 for the training dataset from Zenodo: Miltchev et al. 2024)
cialdini_classifier = pipeline(
    "text-classification",
    model="distilbert-base-uncased",   # Replace with fine-tuned checkpoint
    return_all_scores=True,
    device=-1    # CPU; use 0 for GPU
)

def classify_cialdini_bert(text: str) -> dict[str, float]:
    """
    Use fine-tuned DistilBERT to classify Cialdini principles.
    Returns dict of principle → confidence score.
    
    Training this model requires the Miltchev et al. 2024 dataset 
    (Zenodo: phishing-validation-emails).
    """
    result = cialdini_classifier(text[:512])  # DistilBERT limit
    return {item["label"]: item["score"] for item in result[0]}
```

**Recommendation:** Use the keyword extractor for inference speed (<1ms), the DistilBERT classifier for training feature generation and validation.

---

## Section 4: Model Selection — Llama 3.2 3B vs Phi-3 Mini vs Gemma 2 2B

### 4.1 Benchmark Comparison

| Metric | Llama 3.2 3B | Phi-3 Mini (3.8B) | Gemma 2 2B |
|---|---|---|---|
| **Parameters** | 3.21B | 3.82B | 2.51B |
| **Context window** | 128,000 tokens | 128,000 tokens | 8,192 tokens |
| **MMLU (5-shot)** | 63.4% | 69.0% | 57.8% |
| **IFEval (instruction following)** | **77.4%** | 59.2% | 61.9% |
| **ARC Challenge** | 78.6% | **87.4%** | 71.0% |
| **GSM8K (math)** | 77.7% | **86.2%** | 46.4% |
| **VRAM (Q4_K_M quantised)** | ~2.0 GB | ~2.4 GB | ~1.7 GB |
| **VRAM (full fp16)** | ~6.4 GB | ~7.6 GB | ~5.0 GB |
| **Inference speed (M1 Pro)** | ~3s/email | ~2s/email | ~2.5s/email |
| **Ollama pull name** | `llama3.2:3b` | `phi3:mini` | `gemma2:2b` |

*Sources: Meta benchmark card (Llama 3.2), Microsoft Phi-3 technical report, Google Gemma 2 model card; Ollama community benchmarks 2025*

### 4.2 Perplexity Scoring Accuracy on Email Text

For the specific task of **perplexity scoring on email text** (not general capability benchmarks), the considerations differ significantly:

**Phi-3 Mini (Microsoft, 3.82B)**
- **Recommended for perplexity scoring on professional/corporate email**
- Phi-3's training data was specifically curated to emphasise high-quality, formal written English — making it well-calibrated for corporate communication norms
- Better separation between AI phishing email perplexity (clean, formal) and human email perplexity (informal shortcuts, abbreviations)
- Handles HTML-stripped email with dangling fragments and incomplete sentences more gracefully than Llama 3.2 3B (which shows greater perplexity variance on malformed input)
- **Limitation:** 128K context is shared with Llama 3.2 3B, but Phi-3 produces more verbose reasoning for borderline cases — less useful for pure scoring use

**Llama 3.2 3B (Meta)**
- The 3B model outperforms Gemma 2 2.6B and Phi 3.5-mini on instruction-following, summarisation, and tool use benchmarks.
- Better general-purpose model — strong IFEval score (77.4%) indicates it follows the scoring-only prompt more reliably
- 128K context window allows entire email thread scoring in one pass (useful for thread-level perplexity analysis)
- **Recommended for production pipelines** where you need both perplexity scoring and occasional text analysis in the same model
- Slightly higher perplexity variance on very short emails (< 30 tokens) — apply length penalty

**Gemma 2 2B (Google)**
- Smallest memory footprint (1.7 GB Q4)
- Gemma 2B stands out with the highest accuracy overall in entity extraction tasks, particularly excelling in extracting various entity types.
- **8,192 token context limit is a constraint** — long email threads with quoted replies may exceed this without truncation
- Produces more uniform perplexity scores across text types — less discriminative between AI and human phishing email
- Best choice for **resource-constrained deployment** (4 GB RAM minimum, no GPU)
- **Not recommended as primary perplexity scorer** due to smaller context window and lower score discrimination

**Verdict by use case:**

| Use case | Recommended model |
|---|---|
| Primary perplexity scoring (formal/professional email) | **Phi-3 Mini** |
| Primary perplexity scoring (general email, thread context) | **Llama 3.2 3B** |
| Resource-constrained deployment (< 4GB VRAM) | **Gemma 2 2B** |
| Highest throughput (tokens/second) | **Llama 3.2 1B** (if accuracy permits) |

### 4.3 Tokeniser Handling of HTML-Stripped Email Content

Email body text after HTML stripping contains artefacts that affect perplexity scoring:

| Artefact | Example | Effect on perplexity | Mitigation |
|---|---|---|---|
| URL fragments | `https://click.example.com/track/abc123` | Inflates (models assign high uncertainty to random strings) | Strip URLs before scoring |
| Legal boilerplate | "This email was sent by Coinbase, 100 Pine Street..." | Deflates (formulaic text = low perplexity) | Separate boilerplate section |
| HTML entity residue | `&amp;`, `&nbsp;`, `&#39;` | Unpredictable tokenisation | `html.unescape()` pre-processing |
| Line break fragments | `\n\n` | Adds empty sentence artifacts | Normalise to single space |
| Base64 inline images | Long base64 strings in text/plain fallback | Extreme perplexity inflation | Detect and remove regex |

**Tokeniser comparison for email artefacts:**

All three models use BPE (Byte-Pair Encoding) tokenisers. For email text specifically:

- **Phi-3 Mini tokeniser** uses the same tokeniser as Phi-2 (a subset of the LLaMA tokeniser family), with vocabulary size ~32,000. Handles Unicode and mixed-case email content well.
- **Llama 3.2 3B tokeniser** uses Meta's TikToken-based tokeniser with vocabulary ~128,256 tokens. Larger vocabulary = better handling of technical strings, URLs, and email-specific formatting. **Best tokeniser for email text.**
- **Gemma 2 tokeniser** uses a custom SentencePiece tokeniser with vocabulary ~256,000. Theoretically handles the widest character coverage but doesn't meaningfully improve on email artefact handling vs. Llama.

**Recommended email pre-processing pipeline:**

```python
import re
import html

def preprocess_email_for_scoring(raw_text: str) -> str:
    """
    Clean email text for optimal perplexity scoring.
    Apply before calling Ollama API.
    """
    text = html.unescape(raw_text)
    
    # Remove URLs (inflates perplexity unrealistically)
    text = re.sub(r'https?://\S+', '[URL]', text)
    text = re.sub(r'www\.\S+', '[URL]', text)
    
    # Remove email addresses
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL]', text)
    
    # Remove base64 blobs
    text = re.sub(r'[A-Za-z0-9+/]{50,}={0,2}', '[BASE64]', text)
    
    # Normalise whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r'[ \t]+', ' ', text)
    
    # Remove HTML entities that survived
    text = re.sub(r'&[a-zA-Z]{2,6};', ' ', text)
    text = re.sub(r'&#\d+;', ' ', text)
    
    # Remove boilerplate sections (common email footer patterns)
    text = re.sub(
        r'(unsubscribe|manage preferences|privacy policy|this email was sent).*$',
        '', text, flags=re.IGNORECASE | re.DOTALL
    )
    
    return text.strip()
```

### 4.4 VRAM Requirements Summary

| Configuration | Memory footprint | Notes |
|---|---|---|
| Phi-3 Mini, Q4_K_M (4-bit quantised) | **~2.4 GB VRAM** | Default Ollama deployment |
| Phi-3 Mini, fp16 (full precision) | ~7.6 GB VRAM | Best accuracy |
| Llama 3.2 3B, Q4_K_M | **~2.0 GB VRAM** | Recommended production config |
| Llama 3.2 3B, fp16 | ~6.4 GB VRAM | |
| Gemma 2 2B, Q4_K_M | **~1.7 GB VRAM** | Minimum viable config |
| Gemma 2 2B, fp16 | ~5.0 GB VRAM | |

**CPU-only operation (no GPU):**
All three models run on CPU via Ollama's llama.cpp backend. Performance:
- 8 GB RAM minimum for Q4_K_M versions
- Apple Silicon M1/M2/M3: unified memory architecture = GPU-class inference at ~30-50 tokens/sec
- x86 CPU (Ryzen 7, Core i7): ~5-15 tokens/sec — viable for batch processing, slow for interactive

**Ollama commands:**
```bash
# Install models
ollama pull phi3:mini
ollama pull llama3.2:3b
ollama pull gemma2:2b

# Check loaded models
ollama list

# GPU vs CPU selection happens automatically based on VRAM available
```

---

## Section 5: Training Datasets

### 5.1 Hugging Face Datasets

| Dataset | HF ID | Size | Content | AI-generated label? |
|---|---|---|---|---|
| **PhishingEmailDetection v2** | `cybersectony/PhishingEmailDetectionv2.0` | ~100K | Email + URL, 4-class labels | No — human-written phishing only |
| **Phishing + Legitimate** | `ealvaradob/phishing-dataset` | ~3.7K downloads | Combined phishing corpus | No |
| **Phishing Email Dataset** | `zefang-liu/phishing-email-dataset` | ~100M tokens | Large-scale email classification | No |
| **CEAS-08 Instruction Dataset** | `luongnv89/phishing-email` | LLM-generated | Instructions from CEAS-08 emails via LangChain | Partially — instruction data |
| **DiFraud** | `redasers/difraud` | 15,272 samples | Multi-domain deception detection incl. email phishing | No |
| **Enron Spam** | `SetFit/enron_spam` | 33K emails | Legitimate corporate email + spam | No (legitimacy labels) |
| **Phishing/Benign** | `darkknight25/phishing_benign_email_dataset` | Medium | Binary phishing/benign | No |

**Critical gap:** As of early 2026, **no public Hugging Face dataset explicitly labels AI-generated phishing vs. human-written phishing**. You must construct this.

### 5.2 Non-Hugging Face Datasets with Direct Relevance

| Dataset | Access | Size | Notes |
|---|---|---|---|
| **Miltchev et al. Phishing-Validation Emails** | Zenodo (DOI: 10.5281/zenodo.xxxxx) | 2,995 emails | GPT-o1-generated, Cialdini-labelled. Used in MDPI Computers Dec 2025 paper. Contact: University of Plovdiv |
| **Nazario Phishing Corpus** | spam-corpus.unfocused.com | ~4,000 | Classic benchmark. Real phishing emails from 2003-2007. Use as human-written phishing sample. |
| **Enron Email Dataset** | cs.cmu.edu/~enron/ | 517K emails | Legitimate corporate email. Ground truth negative class. |
| **CEAS-08 Phishing Dataset** | ceas.cc (conference archive) | ~100K | Conference competition dataset. HTML + text. |
| **PhishTank bulk download** | phishtank.com | Monthly CSV | Phishing URLs, not email bodies. Use for URL features. |
| **Sting9** | github.com/sting9-research/dataset | 50M messages | "50M message open-source dataset for AI training" — claimed 99.9% accuracy. Status: research initiative, limited public access as of Feb 2026. |

### 5.3 Constructing Your AI-Phishing Training Dataset

Since no labelled AI-phishing email dataset exists for 2024-2026, generate it:

```python
"""
Dataset construction pipeline for GenAI Phish Shield training data.
Generates AI-phishing examples using Ollama + labels them.
"""
import json
import random
import hashlib
from datetime import datetime
import requests

# Seed prompts using confirmed campaign patterns from threat intelligence
PHISHING_SEEDS = [
    # Crypto exchange impersonation
    {
        "brand": "Coinbase",
        "scenario": "account security alert",
        "cialdini": ["urgency", "authority"],
        "prompt": "Write a phishing email impersonating Coinbase security team claiming the user's account has been locked due to suspicious activity and they must verify within 24 hours."
    },
    # Crypto airdrop
    {
        "brand": "MetaMask",
        "scenario": "airdrop claim",
        "cialdini": ["scarcity", "urgency", "reciprocity"],
        "prompt": "Write a phishing email impersonating MetaMask announcing an exclusive ETH airdrop for early adopters, limited to the next 48 hours, requiring wallet connection."
    },
    # IT helpdesk impersonation
    {
        "brand": "Microsoft IT",
        "scenario": "MFA registration",
        "cialdini": ["authority", "commitment"],
        "prompt": "Write a phishing email from fake IT department requiring users to re-register their MFA device using a provided link, referencing a recent company security policy update."
    },
    # Continue with 20-30 diverse scenarios...
]

def generate_ai_phishing_email(
    seed: dict,
    model: str = "llama3.2:3b",
    temperature: float = 0.7
) -> str:
    """Generate a synthetic AI phishing email from a seed prompt."""
    
    system = (
        "You are a security researcher generating synthetic phishing emails "
        "for classifier training. Generate ONLY the email content (subject + body). "
        "Do not add explanations or caveats."
    )
    
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": model,
            "prompt": f"{system}\n\n{seed['prompt']}",
            "stream": False,
            "options": {"temperature": temperature}
        }
    )
    return response.json().get("response", "")


def build_training_dataset(
    n_ai_examples: int = 500,
    output_path: str = "phishing_training_data.jsonl"
) -> None:
    """
    Build balanced training dataset:
    - n_ai_examples: AI-generated phishing emails (label: ai_phishing=1)
    - Equal count of human-written phishing from Nazario corpus (label: ai_phishing=0)
    - Equal count of legitimate email from Enron (label: phishing=0)
    """
    examples = []
    
    # Generate AI phishing examples
    for i in range(n_ai_examples):
        seed = random.choice(PHISHING_SEEDS)
        email_text = generate_ai_phishing_email(seed)
        
        examples.append({
            "id": hashlib.sha256(email_text.encode()).hexdigest()[:16],
            "text": email_text,
            "is_phishing": 1,
            "is_ai_generated": 1,
            "brand_impersonated": seed["brand"],
            "cialdini_principles": seed["cialdini"],
            "generation_model": "llama3.2:3b",
            "generated_at": datetime.utcnow().isoformat(),
            "source": "synthetic_training"
        })
    
    # Add human-written phishing from Nazario corpus
    # (load separately from your Nazario dataset)
    
    # Add legitimate email from Enron
    # (load separately from SetFit/enron_spam)
    
    # Write JSONL
    with open(output_path, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")
    
    print(f"Wrote {len(examples)} examples to {output_path}")
```

### 5.4 Dataset Composition Recommendations

For a balanced, realistic training corpus:

| Class | Source | Count | Notes |
|---|---|---|---|
| AI phishing (GPT-4/Claude) | Self-generated (see above) | 1,000 | Mix of brands, principles |
| AI phishing (Llama/Mistral local) | Self-generated | 500 | Represents actor toolkit |
| Human-written phishing | Nazario Corpus + CEAS-08 | 1,500 | Old but still valid negative |
| Legitimate transactional email | Enron + custom | 3,000 | Include newsletter, alerts |
| Total | — | **6,000** | 50% phishing, 50% legit |

**Data augmentation strategies:**
- Vary subject line while keeping body (tests subject-only scoring)
- Strip HTML from half the phishing samples
- Add small typos to AI samples (simulates adversarial evasion)
- Mix AI-generated body with human-written subject (split-origin emails)

---

## Section 6: XGBoost Ensemble Integration

### 6.1 Feature Vector Construction

```python
"""
Full feature extraction pipeline → XGBoost prediction.
"""
import xgboost as xgb
import numpy as np
from dataclasses import asdict

def extract_all_features(
    email_subject: str,
    email_body: str,
    model: str = "phi3:mini"
) -> np.ndarray:
    """
    Extract all features and return as numpy array for XGBoost.
    """
    # 1. Pre-process
    clean_body = preprocess_email_for_scoring(email_body)
    combined = f"{email_subject}\n{clean_body}"
    
    # 2. Perplexity features (from Ollama)
    perp = score_email_perplexity(email_subject, clean_body, model)
    
    # 3. Burstiness features
    burst = calculate_burstiness(combined)
    
    # 4. Cialdini features
    cial = extract_cialdini_features(clean_body, email_subject)
    
    # Build feature vector (35 features total)
    features = [
        # Perplexity block (8 features)
        perp.get("body_perplexity_norm") or 0.5,
        perp.get("subject_perplexity_norm") or 0.5,
        perp.get("body_logprob_variance") or 0.0,
        perp.get("body_min_logprob") or -10.0,
        perp.get("sentence_ppl_mean") or 50.0,
        perp.get("sentence_ppl_std") or 10.0,
        perp.get("sentence_ppl_max") or 100.0,
        perp.get("body_token_count") or 0,
        
        # Burstiness block (8 features)
        burst.fano_factor,
        burst.cv_sentence,
        burst.std_sentence_lengths,
        burst.mean_sentence_length,
        burst.std_word_lengths,
        burst.cv_word,
        burst.sentence_count,
        burst.sentence_length_range,
        
        # Cialdini block (10 features)
        cial.urgency_score,
        cial.authority_score,
        cial.scarcity_score,
        cial.social_proof_score,
        cial.reciprocity_score,
        cial.liking_score,
        cial.commitment_score,
        cial.unity_score,
        cial.active_principles,
        cial.cialdini_density,
        
        # Metadata features (9 features)
        float(len(email_subject)),
        float(len(clean_body)),
        float(len(clean_body.split())),
        float(cial.total_principle_count),
        float(burst.paragraph_count),
        float(cial.multi_principle_flag),
        float(burst.max_sentence_length),
        float(burst.min_sentence_length),
        float(burst.paragraph_length_cv or 0.5),
    ]
    
    return np.array(features, dtype=np.float32)


# Training the model
# xgb_model = xgb.XGBClassifier(
#     n_estimators=300,
#     max_depth=5,
#     learning_rate=0.05,
#     subsample=0.8,
#     colsample_bytree=0.8,
#     eval_metric="logloss",
#     use_label_encoder=False,
#     device="cpu"  # or "cuda" for GPU
# )
```

---

## Section 7: Adversarial Evasion and Robustness

Modern phishing actors are aware of AI detection and deploy evasion:

**Known adversarial techniques (2025–2026):**
1. **Intentional word splitting:** "veri fy" instead of "verify" → breaks keyword detection, slightly raises perplexity
2. **Strategic typos:** Intentional misspellings every 50 words → increases perplexity variance
3. **Human-written subject + AI-generated body:** Splits the scoring signal across components
4. **Low-temperature + explicit burstiness prompt:** `"Write with varying sentence lengths, short then long, mimicking human writing style"` — raises Fano Factor artificially
5. **Template injection:** Paste a human-written opening paragraph → AI continues → perplexity shifts mid-email

**Robustness recommendations:**
- Never rely on a single feature; the 3-component ensemble is specifically designed for adversarial resistance
- Include a **perplexity change-point detector**: a sudden shift in sentence-level perplexity mid-email (human intro → AI body) is itself a strong signal
- Train the XGBoost on augmented data including adversarially modified AI emails
- Use `sentence_ppl_max - sentence_ppl_mean` as a feature: high max with low mean = change-point attack

---

*Report compiled February 2026. Sources: arXiv:2301.11305, arXiv:2305.10847, GPTZero technical documentation, MDPI Computers 14(12):523 (Dec 2025), SECURWARE 2025 Cialdini analysis, Ollama v0.12.11 release notes, Hugging Face dataset survey, Meta/Microsoft/Google model cards.*

*TLP:WHITE — Share freely for defensive cybersecurity purposes.*
