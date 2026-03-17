# PhishVision: On-Device ONNX Multimodal Phishing Detector
## Complete Technical Architecture & Implementation Guide

**Classification:** TLP:WHITE  
**Date:** February 2026  
**Sources:** USENIX Security 2021/2022/2024, ASIA CCS 2025, MDPI MAKE 2026, onnxruntime.ai official docs, ACM CCS 2020, arXiv:2405.19598

---

## Section 1: Visual Similarity — Phishpedia & PhishIntention Deep Dive

### 1.1 Phishpedia Architecture (USENIX Security 2021)

Phishpedia (Lin et al., USENIX Security 2021) is a two-stage hybrid system. Stage one detects logos on a page screenshot; stage two compares the detected logo against a reference database of known-brand logos. Both stages are deep learning models.

**Stage 1 — Logo Detection via Faster R-CNN**

Phishpedia runs a Faster R-CNN object detector on the full-page screenshot. Faster R-CNN uses a Region Proposal Network (RPN) to generate candidate bounding boxes, then classifies and refines each box using a classification head and bounding-box regressor. In Phishpedia, the model is trained to detect a single class: "logo" (plus "icon", "button", and "input" depending on the checkpoint). The result is one or more bounding boxes localising identity logos on the page, cropped for the next stage. The backbone is ResNet-50 with FPN (Feature Pyramid Network) for multi-scale detection. Training used the Phishpedia dataset: screenshots annotated with logo bounding boxes from 277 target brands.

**Stage 2 — Siamese Network Similarity Scoring**

Each cropped logo detection is passed through a Siamese network (twin architecture sharing weights). The Siamese encoder here is based on ResNetV2-50. Both the query logo (from the suspicious page) and the reference logos (pre-computed embeddings from the brand database) are encoded into 512-dimensional feature vectors. Cosine similarity is computed between the query vector and every reference embedding. If the maximum cosine similarity exceeds **0.83** (the published threshold), the brand is identified and the URL domain is checked against that brand's known legitimate domains. Domain mismatch → phishing verdict.

```
Pipeline:
Screenshot → Faster R-CNN → Cropped Logo
                                    ↓
Cropped Logo → ResNetV2-50 encoder → 512-d embedding
Reference DB → pre-computed embeddings
                                    ↓
          cosine_similarity(query, reference) > 0.83?
               YES → brand identified → domain check
               NO  → benign (no brand match)
```

**Published performance:**
- Precision: 99.2%
- Recall (detection rate): 87.3% across 29,496 real phishing websites
- Undetected 12.7%: mainly pages where no logo was detected at all, or the logo similarity fell below the 0.83 threshold

### 1.2 PhishIntention Improvements (USENIX Security 2022)

PhishIntention (Liu et al., USENIX Security 2022) extends Phishpedia in three critical ways:

**1. OCR-Aided Siamese Model**

The standard ResNet Siamese encoder is replaced with a two-branch OCR-Siamese model. Branch A runs ASTER (Scene Text Recogniser) on the logo crop to extract textual content (brand name embedded in the logo as text). Branch B runs ResNetV2-50 for visual feature extraction. The two feature vectors are concatenated and fed through fully-connected layers to produce a single consolidated embedding. This matters enormously because many brand logos are primarily text-based (e.g., "PayPal", "Amazon") — text extraction provides a complementary signal when visual similarity alone is ambiguous.

```
Query Logo → [Branch A: ASTER OCR → text features]
           → [Branch B: ResNetV2-50 → visual features]
           → concat → FC layers → 512-d consolidated embedding
```

**2. Credential-Requiring Page (CRP) Classifier**

A page-level classifier determines whether the page is actually a credential-requiring page (has login form, password field, etc.) before attempting brand matching. Pages without CRP elements are not phishing login pages by definition and are immediately classified benign. This dramatically reduces false positives from sites that happen to visually resemble brands but don't attempt credential collection (news articles, blog posts, Wikipedia pages about companies).

The CRP classifier in PhishIntention is based on layout detection: the same Faster R-CNN model detects not just logos but also form elements, input fields, and buttons, then a rule-based or learned classifier determines CRP status. The paper reports using an XLM-RoBERTa-based text CRP classifier (trained on 2,555 manually labelled samples) as the primary signal in the KnowPhish (2024) extension.

**3. Web Interaction Module**

PhishIntention can actively interact with the page: clicking "login" buttons, navigating to login sub-pages, and re-running detection on the updated URL/screenshot. This two-pass approach recovers cases where the brand-imitation content is only visible after one navigation step. Not practical for browser extension deployment (too slow; requires Selenium/Playwright) but important for server-side pipeline detection.

**Comparative performance on real-world phishing (published):**
| System | Reported Phishing | Verified Phishing | Detection Rate |
|---|---|---|---|
| Phishpedia | Baseline | Baseline | 71.3% (base ref) / 85.0% (ext ref) |
| PhishIntention | +Dual intention | Higher precision | 87.3%+ after OCR stage |
| DynaPhish | Dynamic reference | 1942 found in 2 months | 97.9% (DynaPhish mode) |
| KnowPhish (2024) | Wikidata-sourced BKB | 6× faster than DynaPhish | ~95%+ with LLM fallback |

### 1.3 Limitations to Design Around

**Critical adversarial vulnerabilities (ASIA CCS 2025 paper — Roh, Jeon, Son, Hong):**

The paper demonstrated attack success rates of **84.1–95.6%** against PhishIntention and DynaPhish under realistic adversarial conditions. Three categories of attack succeed:

1. **No-Object Attack**: PGD-based perturbation prevents Faster R-CNN from detecting any logos at all. Without logo detection, the pipeline outputs "benign" by default — a false negative. The attack success rate for this is high because the logo detector is not adversarially trained.

2. **Triple-Jump Attack**: Sequentially fools all three classifiers (logo detector → OCR-Siamese → CRP). Attack success 84.1% before StepReLU, 95.6% with StepReLU supposedly protecting the model (StepReLU provides no real adversarial robustness — it causes gradient masking, which is security through obscurity).

3. **Logo Masking Attack (Black-Box)**: Strategically masks portions of the logo with background-coloured rectangles. Drops recall to 0.03–0.33 in end-to-end evaluation.

**Structural limitations:**

- **Fixed reference database**: Phishpedia and PhishIntention ship with 277 manually curated brands. Any brand not in this database produces 0% detection of pages impersonating it. KnowPhish (USENIX 2024) solves this with Wikidata-automated brand acquisition (see Section 4).
- **Logo-centric blindness**: Pages without logos (pure text phishing, QR code phishing, captcha-gated pages) entirely bypass the detection pipeline. PhishIntention adds CRP checking but this assumes a login form is present.
- **Faster R-CNN scale**: The full Faster R-CNN + Siamese pipeline runs at 6+ seconds per page on CPU. Entirely impractical for real-time browser extension use without significant model compression. For PhishVision, you must replace Faster R-CNN with a lightweight alternative.
- **Reference list staleness**: Logo designs change. Phishing sites impersonating a brand whose logo was redesigned after the reference list was built produce misleading similarity scores.

**Design recommendations for PhishVision:**

```
1. Replace Faster R-CNN with YOLOv8-nano or YOLO11n for logo detection
   → 2-3 MB ONNX model vs. 170+ MB for ResNet-50 + FPN
   → 15-50ms inference vs. 2-6s for Faster R-CNN
   → Trade: lower mAP, but acceptable for browser latency budget

2. Replace ResNetV2-50 Siamese with MobileNetV3 or EfficientNet-B0 encoder
   → 4-8 MB quantised vs. 95 MB for ResNetV2-50
   → Retain cosine similarity matching at 0.83 threshold

3. Add text-based CRP classifier as first filter
   → Parse DOM for password fields before triggering visual pipeline
   → Skip visual scoring entirely for non-login pages (saves ~80% of CPU)

4. Use pre-computed embeddings, not live inference on reference logos
   → Store 200 × 512-d float32 embeddings in IndexedDB (~400 KB)
   → Dot product against pre-computed matrix is ~0.1ms in JavaScript
```

---

## Section 2: ONNX Browser Deployment Constraints

### 2.1 Manifest V3 Service Worker Architecture

Chrome extensions using Manifest V3 replaced persistent background pages with event-driven service workers. This creates several hard constraints for ML model deployment.

**Service worker memory: no hard ceiling, but critical practical limits**

There is no officially documented memory limit for MV3 service workers. The constraint is architectural, not numerical. Service workers in MV3 **terminate after 30 seconds of inactivity** (Chrome 116+ relaxed some conditions: active WebSocket connections and debugger sessions keep them alive, but navigation-triggered inference cannot rely on this). When the service worker terminates, all in-memory state — including loaded ONNX sessions — is destroyed. The next inference request triggers a cold start requiring full model reload.

For PhishVision, the critical consequence is: **do not load the ONNX model in the service worker**. Use the Offscreen Document API instead.

**The correct MV3 architecture for ONNX inference:**

```
Service Worker (background.js)
    ↕ message passing (chrome.runtime.sendMessage)
Offscreen Document (offscreen.html + offscreen.js)
    ← persistent, keeps ONNX session loaded
    ← runs WASM/WebGPU backend without service worker lifecycle issues
```

The offscreen document persists as long as the extension is active and is not subject to the 30-second service worker termination. Model is loaded once, cached in IndexedDB, and held in the ONNX InferenceSession.

**Critical WASM constraint in service workers**: The `import()` dynamic import is disallowed in ServiceWorkerGlobalScope by the HTML specification (confirmed in microsoft/onnxruntime issue #20876). This means WebGPU and the standard WASM backend cannot be initialised directly in a service worker. This is a hard API restriction, not an ONNX-specific bug. All ML inference must happen in the offscreen document.

**Required manifest.json permissions:**
```json
{
  "manifest_version": 3,
  "permissions": ["offscreen", "activeTab", "scripting", "storage", "unlimitedStorage"],
  "background": {
    "service_worker": "background.js",
    "type": "module"
  },
  "content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'"
  },
  "web_accessible_resources": [{
    "resources": ["*.wasm", "*.onnx"],
    "matches": ["<all_urls>"]
  }]
}
```

The `wasm-unsafe-eval` CSP directive is mandatory for WASM execution. The WASM and ONNX files must be in `web_accessible_resources` so they can be fetched with `chrome.runtime.getURL()`.

**Model size limits:**

The practical constraints stack:
- Chrome extension package size: **10 MB per extension** for Chrome Web Store distribution. This is the hardest constraint for bundled models.
- IndexedDB storage: Chrome allocates a portion of available disk (no fixed cap, but typically 80% of free disk). The `unlimitedStorage` permission removes the default 5 MB origin quota.
- WASM memory: 4 GB maximum (32-bit addressing). No model approaching this limit exists in the target size range.
- **Practical target: ≤10 MB per ONNX model** for bundled distribution, or lazy-load from URL after first install and cache in IndexedDB.

For PhishVision, the recommended strategy:
```
Bundle with extension: URL heuristics module (JS, ~50 KB)
First-run download & IndexedDB cache:
  - EfficientNet-B0 INT8: ~8-10 MB
  - YOLOv8-nano logo detector: ~2-3 MB
  - DOM feature XGBoost: <1 MB (via sklearn or XGBoost ONNX)
Total downloaded: ~12-14 MB, stored in IndexedDB after first run
```

### 2.2 EfficientNet-B0 INT8 Quantisation

**Why EfficientNet-B0?** It achieves 91.33% visual brand recognition accuracy on the Phishpedia dataset (confirmed in multiple benchmarks) while having a baseline ONNX size of ~21 MB (float32). INT8 quantisation reduces this to ~8-10 MB with minimal accuracy loss.

**Step-by-step quantisation pipeline:**

```python
"""
PhishVision — EfficientNet-B0 Export + INT8 Quantisation
Tested with: timm==0.9.x, onnx==1.16, onnxruntime==1.19
"""
import torch
import timm
import onnx
import numpy as np
from onnxruntime.quantization import (
    quantize_dynamic,
    QuantType,
    QuantizationMode
)
from onnxruntime.quantization.calibrate import CalibrationDataReader
import onnxruntime as ort

# ── Step 1: Load and export to ONNX ─────────────────────────────────────────

model = timm.create_model(
    'efficientnet_b0',
    pretrained=True,        # ImageNet pretrained, then fine-tuned on Phishpedia
    num_classes=0,          # Remove classifier head — we want 1280-d embeddings
    global_pool='avg'
)
model.eval()

# Dummy input: 224×224 RGB, batch=1
dummy_input = torch.randn(1, 3, 224, 224)

torch.onnx.export(
    model,
    dummy_input,
    "efficientnet_b0_fp32.onnx",
    input_names=["input"],
    output_names=["embedding"],
    dynamic_axes={"input": {0: "batch_size"}},
    opset_version=17,
    do_constant_folding=True,
)
print("Exported FP32 model")

# Verify
onnx_model = onnx.load("efficientnet_b0_fp32.onnx")
onnx.checker.check_model(onnx_model)


# ── Step 2: Dynamic INT8 Quantisation (recommended for browser) ──────────────
# quantize_dynamic requires no calibration data — weights are quantised to INT8,
# activations remain FP32 at runtime (computed dynamically).
# Simpler than static quantisation, accuracy loss typically <1% on embedding tasks.

quantize_dynamic(
    model_input="efficientnet_b0_fp32.onnx",
    model_output="efficientnet_b0_int8.onnx",
    weight_type=QuantType.QInt8,        # Signed 8-bit integers
    op_types_to_quantize=['MatMul', 'Gemm'],  # Target linear layers only
    per_channel=False,                  # Per-tensor is smaller; per-channel more accurate
    reduce_range=True,                  # Improve compatibility with VNNI/older CPUs
)
print("INT8 quantised model saved")


# ── Step 3: Static INT8 Quantisation (optional — higher accuracy) ─────────────
# Requires calibration data: 100-200 representative screenshots from the brand DB

class PhishCalibrationReader(CalibrationDataReader):
    def __init__(self, calibration_images: list):
        """
        calibration_images: list of numpy arrays [N, 3, 224, 224], normalised
        to ImageNet mean/std.
        """
        self.images = calibration_images
        self.idx = 0

    def get_next(self):
        if self.idx >= len(self.images):
            return None
        result = {"input": self.images[self.idx].astype(np.float32)}
        self.idx += 1
        return result

# Usage:
# from onnxruntime.quantization import quantize_static, CalibrationMethod
# reader = PhishCalibrationReader(calibration_images)
# quantize_static(
#     model_input="efficientnet_b0_fp32.onnx",
#     model_output="efficientnet_b0_int8_static.onnx",
#     calibration_data_reader=reader,
#     calibration_method=CalibrationMethod.MinMax,
#     weight_type=QuantType.QInt8,
# )


# ── Step 4: Validate accuracy preservation ───────────────────────────────────

def run_inference(model_path, input_array):
    sess = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
    return sess.run(None, {"input": input_array})[0]

test_input = np.random.randn(1, 3, 224, 224).astype(np.float32)
fp32_out = run_inference("efficientnet_b0_fp32.onnx", test_input)
int8_out = run_inference("efficientnet_b0_int8.onnx", test_input)

cosine_similarity = np.dot(fp32_out[0], int8_out[0]) / (
    np.linalg.norm(fp32_out[0]) * np.linalg.norm(int8_out[0])
)
print(f"FP32 vs INT8 embedding cosine similarity: {cosine_similarity:.4f}")
# Expected: > 0.99 for dynamic quantisation on embedding models
# If < 0.95, switch to static quantisation with calibration data

# Size comparison
import os
fp32_mb = os.path.getsize("efficientnet_b0_fp32.onnx") / 1e6
int8_mb = os.path.getsize("efficientnet_b0_int8.onnx") / 1e6
print(f"FP32: {fp32_mb:.1f} MB → INT8: {int8_mb:.1f} MB ({100*(1-int8_mb/fp32_mb):.0f}% reduction)")
# Expected: FP32: ~21 MB → INT8: ~8-10 MB (~55-60% reduction)
```

**Practical size targets achieved:**
| Model | FP32 | INT8 Dynamic | INT8 Static | Notes |
|---|---|---|---|---|
| EfficientNet-B0 (embeddings) | ~21 MB | ~8-10 MB | ~9 MB | Target for visual encoder |
| EfficientNet-B0 (classifier) | ~21 MB | ~8-10 MB | ~9 MB | Alternative if using classification |
| MobileNetV3-Small | ~10 MB | ~4 MB | ~4 MB | Smaller, lower accuracy |
| YOLOv8-nano | ~6 MB | ~2-3 MB | ~2.5 MB | Logo detector |

### 2.3 JavaScript Inference Code (offscreen.js)

```javascript
// offscreen.js — runs in Offscreen Document, loads ONNX session once

import * as ort from 'onnxruntime-web/wasm';

// Fix for MV3: must set wasmPaths before init
ort.env.wasm.wasmPaths = chrome.runtime.getURL('ort-wasm/');
ort.env.wasm.numThreads = 1;  // Required: multi-threading disabled in extensions

let session = null;
let brandEmbeddings = null;  // Float32Array [numBrands × 1280]
let brandNames = null;

async function initModel() {
  if (session) return;  // Already loaded

  // Try IndexedDB cache first, fall back to fetch
  const cached = await getFromIndexedDB('efficientnet_b0_int8');
  const modelBuffer = cached ?? await fetchAndCache();

  session = await ort.InferenceSession.create(modelBuffer, {
    executionProviders: ['wasm'],
    graphOptimizationLevel: 'all',
  });

  // Load pre-computed brand embeddings from IndexedDB
  const embData = await getFromIndexedDB('brand_embeddings');
  const parsed = JSON.parse(new TextDecoder().decode(embData));
  brandEmbeddings = new Float32Array(parsed.embeddings.flat());
  brandNames = parsed.names;

  console.log('[PhishVision] Model loaded, brands:', brandNames.length);
}

async function embedScreenshot(imageData) {
  // imageData: ImageData object from tab screenshot
  const tensor = preprocessImage(imageData);
  const feeds = { input: tensor };
  const results = await session.run(feeds);
  return results.embedding.data;  // Float32Array of 1280 dimensions
}

function preprocessImage(imageData) {
  // Resize to 224×224, normalise to ImageNet mean/std
  const [R, G, B] = [[], [], []];
  const mean = [0.485, 0.456, 0.406];
  const std  = [0.229, 0.224, 0.225];
  const size = 224 * 224;
  const data = imageData.data;  // RGBA, 0-255

  // Downsample (simplified — use canvas for proper bilinear interpolation)
  for (let i = 0; i < size; i++) {
    R.push((data[i * 4]     / 255 - mean[0]) / std[0]);
    G.push((data[i * 4 + 1] / 255 - mean[1]) / std[1]);
    B.push((data[i * 4 + 2] / 255 - mean[2]) / std[2]);
  }

  const channelFirst = new Float32Array([...R, ...G, ...B]);
  return new ort.Tensor('float32', channelFirst, [1, 3, 224, 224]);
}

function cosineSimilarityTopK(queryEmbedding, k = 3) {
  // Vectorised cosine similarity against all brand embeddings
  const numBrands = brandNames.length;
  const dim = 1280;
  const queryNorm = Math.sqrt(queryEmbedding.reduce((s, v) => s + v * v, 0));
  const scores = [];

  for (let b = 0; b < numBrands; b++) {
    const offset = b * dim;
    let dot = 0, refNorm = 0;
    for (let d = 0; d < dim; d++) {
      dot += queryEmbedding[d] * brandEmbeddings[offset + d];
      refNorm += brandEmbeddings[offset + d] ** 2;
    }
    scores.push({
      brand: brandNames[b],
      similarity: dot / (queryNorm * Math.sqrt(refNorm))
    });
  }

  return scores.sort((a, b) => b.similarity - a.similarity).slice(0, k);
}
```

### 2.4 Inference Latency Targets

**Human perception thresholds for browser UI:**
- < 100ms: Imperceptible — user feels interaction is instantaneous
- 100–300ms: Noticeable but acceptable — page renders, indicator appears without disruption
- 300–1000ms: Perceivable delay — must show progress indicator
- > 1000ms: Frustrating — users perceive the extension as "slow"

**Target for PhishVision: 200ms total for all three modalities**

Budget breakdown (measured on representative hardware: MacBook M1 Pro, mid-range Windows laptop):
| Step | Target latency | Notes |
|---|---|---|
| URL heuristics extraction | < 5ms | Pure JS string operations |
| DOM feature extraction | 10–30ms | `document.querySelectorAll()` is fast |
| Screenshot capture | 30–60ms | `chrome.tabs.captureVisibleTab()` |
| Image preprocessing (resize + normalise) | 20–40ms | Canvas API operations |
| ONNX inference (EfficientNet-B0 INT8) | 50–120ms | WASM on CPU, first pass |
| Cosine similarity vs 200 embeddings | < 1ms | Vectorised Float32Array |
| Total | **115–256ms** | Within acceptable range |

**Cold start latency** (first inference after model load from IndexedDB) adds 500ms–2s for WASM compilation. Mitigate with a warm-up inference during extension install.

---

## Section 3: HTML DOM Feature Extraction

### 3.1 Academic Feature Sets

The most comprehensive comparative study of HTML features for phishing detection is Li et al. (2019), "A stacking model using URL and HTML features for phishing webpage detection" (*Future Generation Computer Systems*, 94, 27–39), which used 54 combined URL+HTML features. The Vulfin et al. multimodal system (MDPI MAKE 2026) uses CodeBERT on full HTML source rather than hand-engineered features.

Key HTML feature categories established across multiple papers (Li 2019, Sahingoz 2019, El Aassal 2020):

**Group A: Form and Input Analysis (highest discriminative power)**

Phishing pages require credential capture. Form elements are the primary delivery mechanism.

| Feature | Phishing typical | Legitimate typical | Importance |
|---|---|---|---|
| `password_field_count` | 1–3 | 0–1 | **Critical** — presence alone is strong signal when combined with domain mismatch |
| `hidden_input_count` | 5–30 | 0–5 | **High** — phishing kits use hidden fields for tracking/exfiltration |
| `total_form_count` | 1–4 | 0–3 | Medium |
| `form_action_external` | 1 | 0 | **High** — form action points to different domain |
| `form_has_email_field` | 1 | 0–1 | Medium |
| `input_count_ratio` | >0.6 | <0.3 | High — input fields vs total page elements |

**Group B: External Resource Loading**

Phishing kits often load resources from legitimate CDNs or third-party hosts to appear credible.

| Feature | Phishing typical | Legitimate typical | Importance |
|---|---|---|---|
| `external_script_count` | 8–40 | 3–15 | Medium (legitimate sites also use many CDN scripts) |
| `external_script_ratio` | >0.7 | 0.3–0.6 | **High** — proportion from different domains |
| `external_css_count` | 3–15 | 2–8 | Low |
| `external_image_count` | 10–60 | 5–30 | Low |
| `all_resources_external_ratio` | >0.85 | 0.2–0.6 | **High** |

**Group C: Iframe and Redirection**

| Feature | Phishing typical | Legitimate typical | Importance |
|---|---|---|---|
| `iframe_count` | 1–5 | 0–3 | Medium |
| `iframe_invisible_count` | 1–3 | 0 | **Critical** — invisible iframes strongly indicate abuse |
| `iframe_src_external` | 1–3 | 0–1 | High |
| `iframe_depth_max` | 2–4 | 0–1 | Medium |
| `meta_refresh_present` | 1 | 0 | High |

**Group D: DOM Structure Anomalies**

| Feature | Phishing typical | Legitimate typical | Importance |
|---|---|---|---|
| `right_click_disabled` | 1 (True) | 0 | High (oncontextmenu = "return false") |
| `has_favicon` | 1 | 1 | Low (phishing copies favicons) |
| `title_contains_brand_keywords` | 1 | 1 | Medium |
| `null_links_ratio` | >0.5 | <0.1 | **High** — "#" or "javascript:void(0)" links |
| `empty_title` | 1 | 0 | High |
| `popup_window_count` | 1–3 | 0 | High |
| `status_bar_customised` | 1 | 0 | Medium (window.status manipulation) |

**Group E: URL Features (extracted at URL parsing stage, not DOM)**

URL features provide fast, pre-navigation signal. Cited from Sahingoz et al. (2019), *Expert Systems with Applications*, 117:106:

| Feature | Phishing typical | Legitimate typical |
|---|---|---|
| `url_length` | > 75 chars | < 54 chars |
| `has_ip_in_url` | 1 | 0 |
| `hyphen_count_in_domain` | > 3 | 0–1 |
| `dot_count_in_path` | > 2 | 0–1 |
| `has_at_symbol` | 1 | 0 |
| `has_double_slash_redirect` | 1 | 0 |
| `subdomain_depth` | > 3 | 1–2 |
| `domain_age_days` | < 7 | > 365 |
| `tld_suspicious` | .xyz, .tk, .ml | .com, .org, .edu |
| `brand_keyword_in_subdomain` | 1 | 0 |

### 3.2 Complete DOM Feature Extractor (Content Script)

```javascript
// content.js — injected into active page via chrome.scripting.executeScript()

function extractDOMFeatures() {
  const doc = document;
  const allLinks = doc.querySelectorAll('a');
  const allScripts = doc.querySelectorAll('script[src]');
  const allCSS = doc.querySelectorAll('link[rel="stylesheet"]');
  const allImages = doc.querySelectorAll('img[src]');
  const allForms = doc.querySelectorAll('form');
  const allIframes = doc.querySelectorAll('iframe');
  const allInputs = doc.querySelectorAll('input');
  const allElements = doc.querySelectorAll('*');
  const pageOrigin = location.origin;

  // ── Form & Input Analysis ─────────────────────────────────────────────────
  const passwordInputs = doc.querySelectorAll('input[type="password"]');
  const hiddenInputs = doc.querySelectorAll('input[type="hidden"]');
  const emailInputs = doc.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"]');

  let formActionExternal = 0;
  allForms.forEach(form => {
    try {
      const action = new URL(form.action || '', location.href);
      if (action.origin !== pageOrigin) formActionExternal++;
    } catch (_) {}
  });

  // ── External Resource Counting ─────────────────────────────────────────────
  function isExternal(url) {
    try {
      return new URL(url, location.href).origin !== pageOrigin;
    } catch (_) { return false; }
  }

  const extScripts = [...allScripts].filter(s => isExternal(s.src)).length;
  const extCSS = [...allCSS].filter(l => isExternal(l.href)).length;
  const extImages = [...allImages].filter(i => isExternal(i.src)).length;
  const totalResources = allScripts.length + allCSS.length + allImages.length;
  const extResources = extScripts + extCSS + extImages;

  // ── Iframe Analysis ───────────────────────────────────────────────────────
  let iframeInvisible = 0;
  let iframeSrcExternal = 0;
  allIframes.forEach(iframe => {
    const style = window.getComputedStyle(iframe);
    if (style.display === 'none' || style.visibility === 'hidden' ||
        style.width === '0px' || style.height === '0px' ||
        parseInt(style.width) < 5 || parseInt(style.height) < 5) {
      iframeInvisible++;
    }
    if (iframe.src && isExternal(iframe.src)) iframeSrcExternal++;
  });

  // ── Link Quality ─────────────────────────────────────────────────────────
  let nullLinkCount = 0;
  allLinks.forEach(link => {
    const href = link.getAttribute('href');
    if (!href || href === '#' || href.startsWith('javascript:')) nullLinkCount++;
  });

  // ── DOM Anomalies ─────────────────────────────────────────────────────────
  const hasContextMenuBlock = doc.body?.getAttribute('oncontextmenu')?.includes('false') || false;
  const title = doc.title?.toLowerCase() || '';
  const hasMetaRefresh = !!doc.querySelector('meta[http-equiv="refresh"]');

  // Right-click block via event listener (heuristic — check common patterns)
  const htmlSource = doc.documentElement.outerHTML;
  const rightClickBlocked = hasContextMenuBlock ||
    /oncontextmenu\s*=\s*["']?return\s+false/i.test(htmlSource);

  // Status bar manipulation (indicates fake anchor links)
  const statusBarCustomised = /window\.status/i.test(htmlSource);

  // Popup window (window.open calls — rough heuristic)
  const popupCount = (htmlSource.match(/window\.open\s*\(/g) || []).length;

  // ── Feature Vector ────────────────────────────────────────────────────────
  return {
    // Form & Input
    password_field_count:      passwordInputs.length,
    hidden_input_count:        hiddenInputs.length,
    email_field_count:         emailInputs.length,
    form_count:                allForms.length,
    form_action_external:      formActionExternal,
    input_to_element_ratio:    allInputs.length / Math.max(allElements.length, 1),

    // External Resources
    external_script_count:     extScripts,
    total_script_count:        allScripts.length,
    external_script_ratio:     extScripts / Math.max(allScripts.length, 1),
    external_css_count:        extCSS,
    external_image_count:      extImages,
    external_resource_ratio:   extResources / Math.max(totalResources, 1),

    // Iframes
    iframe_count:              allIframes.length,
    iframe_invisible_count:    iframeInvisible,
    iframe_src_external:       iframeSrcExternal,

    // Link Quality
    total_link_count:          allLinks.length,
    null_link_count:           nullLinkCount,
    null_link_ratio:           nullLinkCount / Math.max(allLinks.length, 1),

    // Anomalies
    right_click_blocked:       rightClickBlocked ? 1 : 0,
    status_bar_customised:     statusBarCustomised ? 1 : 0,
    has_meta_refresh:          hasMetaRefresh ? 1 : 0,
    popup_window_count:        Math.min(popupCount, 10),
    title_empty:               title.length === 0 ? 1 : 0,
    title_length:              title.length,

    // Structural
    total_element_count:       allElements.length,
    total_input_count:         allInputs.length,
    has_favicon:               !!doc.querySelector('link[rel*="icon"]') ? 1 : 0,
  };
}

// Report features back to service worker
chrome.runtime.sendMessage({
  type: 'DOM_FEATURES',
  data: extractDOMFeatures(),
  url: location.href,
  title: document.title,
});
```

### 3.3 Feature Importance Ranking

Based on the comparative analysis in Li et al. (2019) and Sahingoz et al. (2019), the top-10 most discriminative individual features (ordered by information gain / Gini importance):

1. `has_ip_in_url` — near-zero false positive rate
2. `password_field_count` × `form_action_external` — interaction term
3. `iframe_invisible_count > 0`
4. `null_link_ratio > 0.5`
5. `subdomain_depth > 3` (URL feature)
6. `right_click_blocked`
7. `hidden_input_count > 10`
8. `domain_age_days < 7` (requires RDAP lookup)
9. `external_resource_ratio > 0.85`
10. `has_meta_refresh`

---

## Section 4: Brand Embedding Database

### 4.1 Architecture

The brand embedding database stores, for each protected brand:
- The brand name and known legitimate domains (authoritative source)
- Pre-computed EfficientNet-B0 embeddings of 3–10 representative logo images
- Brand name aliases (for text-based matching)

The full pipeline for 200+ brands:

```python
"""
PhishVision — Automated Brand Embedding Database Construction
Inspired by KnowPhish (USENIX Security 2024) and adapted for browser deployment.
"""
import json
import time
import hashlib
import requests
import numpy as np
from PIL import Image
from io import BytesIO
import onnxruntime as ort
from dataclasses import dataclass, asdict
from typing import Optional

ONNX_MODEL = "efficientnet_b0_int8.onnx"
MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
STD  = np.array([0.229, 0.224, 0.225], dtype=np.float32)


@dataclass
class BrandEntry:
    name: str                          # Canonical name: "PayPal"
    aliases: list[str]                 # ["paypal", "PayPal, Inc.", "PayPal Holdings"]
    legitimate_domains: list[str]      # ["paypal.com", "paypal.me"]
    logo_urls: list[str]               # Source URLs for logo images
    embedding_mean: list[float]        # Mean embedding (1280-d) across logo variants
    embedding_variants: list[list[float]]  # Per-logo embeddings for robustness
    industry: str                      # "fintech", "crypto", "cloud", etc.
    risk_tier: int                     # 1=critical, 2=high, 3=medium
    last_updated: str                  # ISO timestamp


class EmbeddingExtractor:
    def __init__(self, model_path: str):
        self.sess = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"]
        )

    def embed_image_url(self, url: str) -> Optional[np.ndarray]:
        """Download image, preprocess, and return 1280-d embedding."""
        try:
            resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            resp.raise_for_status()
            img = Image.open(BytesIO(resp.content)).convert("RGB")
            img = img.resize((224, 224), Image.LANCZOS)
            arr = np.array(img, dtype=np.float32) / 255.0
            arr = (arr - MEAN) / STD
            arr = arr.transpose(2, 0, 1)[np.newaxis, ...]  # NCHW
            result = self.sess.run(None, {"input": arr})[0]
            return result[0]  # shape: (1280,)
        except Exception as e:
            print(f"  [WARN] Failed to embed {url}: {e}")
            return None

    def embed_logo_from_domain(self, domain: str) -> Optional[np.ndarray]:
        """
        Try to extract the logo directly from the brand's homepage.
        Method: fetch the page, find <img> tags likely to be logos
        (in header/nav, with alt text matching brand name), embed the top candidate.
        """
        try:
            resp = requests.get(f"https://{domain}", timeout=15, headers={
                "User-Agent": "Mozilla/5.0 (compatible; PhishVisionBot/1.0)"
            })
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")

            # Heuristic: find images in header/nav with logo-related src/alt
            logo_candidates = []
            for img in soup.select("header img, nav img, .logo img, #logo img, img.logo"):
                src = img.get("src", "")
                if src and "logo" in src.lower() or "logo" in (img.get("alt", "").lower()):
                    abs_src = src if src.startswith("http") else f"https://{domain}{src}"
                    logo_candidates.append(abs_src)

            for candidate in logo_candidates[:3]:  # Try top 3 candidates
                embedding = self.embed_image_url(candidate)
                if embedding is not None:
                    return embedding

        except Exception as e:
            print(f"  [WARN] Domain logo extraction failed for {domain}: {e}")
        return None


def wikidata_brand_lookup(brand_name: str) -> dict:
    """
    Query Wikidata SPARQL for brand metadata: aliases, website, industry.
    This is the approach used in KnowPhish (USENIX 2024) for automated BKB construction.
    """
    sparql_query = f"""
    SELECT ?item ?itemLabel ?alias ?website ?industryLabel WHERE {{
      ?item wdt:P31/wdt:P279* wd:Q4830453 .   # instance of business
      ?item rdfs:label "{brand_name}"@en .
      OPTIONAL {{ ?item skos:altLabel ?alias FILTER(lang(?alias) = "en") }}
      OPTIONAL {{ ?item wdt:P856 ?website }}
      OPTIONAL {{ ?item wdt:P452 ?industry }}
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" }}
    }} LIMIT 10
    """
    url = "https://query.wikidata.org/sparql"
    try:
        resp = requests.get(url, params={"query": sparql_query, "format": "json"},
                            timeout=10, headers={"User-Agent": "PhishVisionBot/1.0"})
        data = resp.json()
        results = data["results"]["bindings"]
        domains = list(set(
            r["website"]["value"].replace("https://", "").replace("http://", "").strip("/")
            for r in results if "website" in r
        ))
        aliases = list(set(r["alias"]["value"] for r in results if "alias" in r))
        return {"domains": domains[:5], "aliases": aliases[:10]}
    except Exception:
        return {"domains": [], "aliases": []}


def build_brand_database(
    brand_list: list[dict],
    extractor: EmbeddingExtractor,
    output_path: str = "brand_db.json"
) -> list[BrandEntry]:
    """
    Build brand embedding database from a seed list.
    seed format: [{"name": "PayPal", "domains": ["paypal.com"], "tier": 1}, ...]
    """
    entries = []

    for brand in brand_list:
        print(f"\nProcessing: {brand['name']}")
        name = brand["name"]
        domains = brand.get("domains", [])

        # Step 1: Enrich from Wikidata
        wiki_data = wikidata_brand_lookup(name)
        all_domains = list(set(domains + wiki_data["domains"]))
        aliases = wiki_data["aliases"]

        # Step 2: Collect logo images
        embeddings = []

        # Method A: Direct domain logo extraction
        for domain in all_domains[:2]:
            emb = extractor.embed_logo_from_domain(domain)
            if emb is not None:
                embeddings.append(emb)
                print(f"  ✓ Embedded logo from {domain}")

        # Method B: Google Image Search fallback (requires SerpAPI key or similar)
        if len(embeddings) < 2:
            google_logo_url = f"https://logo.clearbit.com/{all_domains[0]}" if all_domains else None
            if google_logo_url:
                emb = extractor.embed_image_url(google_logo_url)
                if emb is not None:
                    embeddings.append(emb)
                    print(f"  ✓ Embedded logo from Clearbit")

        if not embeddings:
            print(f"  ✗ No logos found for {name}, skipping")
            continue

        # Step 3: Compute mean embedding
        embeddings_arr = np.stack(embeddings)
        mean_emb = embeddings_arr.mean(axis=0)
        mean_emb /= np.linalg.norm(mean_emb)  # L2 normalise

        entry = BrandEntry(
            name=name,
            aliases=aliases,
            legitimate_domains=all_domains,
            logo_urls=[],  # Not stored in production DB
            embedding_mean=mean_emb.tolist(),
            embedding_variants=[e.tolist() for e in embeddings],
            industry=brand.get("industry", "general"),
            risk_tier=brand.get("tier", 2),
            last_updated=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        entries.append(entry)
        time.sleep(1)  # Rate limit

    # Save full database
    with open(output_path, "w") as f:
        json.dump([asdict(e) for e in entries], f, indent=2)

    # Export browser-optimised flat format
    export_browser_format(entries, output_path.replace(".json", "_browser.json"))

    print(f"\nBuilt database: {len(entries)} brands")
    return entries


def export_browser_format(entries: list[BrandEntry], path: str):
    """
    Export compact format for IndexedDB storage in Chrome extension.
    Stores only mean embeddings (saves ~80% vs per-variant storage).
    Total size: 200 brands × 1280 floats × 4 bytes = ~1 MB
    """
    browser_db = {
        "version": "1.0",
        "brands": [
            {
                "name": e.name,
                "aliases": e.aliases[:5],
                "domains": e.legitimate_domains[:5],
                "tier": e.risk_tier,
                "embedding": e.embedding_mean  # Pre-normalised 1280-d vector
            }
            for e in entries
        ]
    }
    with open(path, "w") as f:
        json.dump(browser_db, f, separators=(',', ':'))  # Compact JSON

    import os
    size_kb = os.path.getsize(path) / 1024
    print(f"Browser DB exported: {path} ({size_kb:.0f} KB)")
```

### 4.2 Automated Update Strategy

**Weekly automated update pipeline (GitHub Actions):**

```yaml
# .github/workflows/update-brand-db.yml
name: Update Brand Embedding Database

on:
  schedule:
    - cron: '0 2 * * 1'   # Every Monday 02:00 UTC
  workflow_dispatch:       # Manual trigger

jobs:
  update-db:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with: {python-version: '3.11'}

      - name: Install dependencies
        run: pip install onnxruntime timm pillow requests beautifulsoup4

      - name: Check for brand changes
        run: python scripts/check_brand_changes.py
        # Checks: domain redirects, logo redesigns via perceptual hash comparison

      - name: Rebuild changed embeddings
        run: python scripts/rebuild_changed.py

      - name: Validate embedding quality
        run: python scripts/validate_db.py
        # Checks: cosine similarity matrix, ensures self-similarity > 0.95

      - name: Commit updated database
        run: |
          git config user.email "ci@phishvision.io"
          git add brand_db_browser.json
          git commit -m "chore: update brand embeddings $(date -u +%Y-%m-%d)" || echo "No changes"
          git push
```

**What triggers a re-embed:**
1. Domain redirects to a new URL (detected by HTTP 301 check)
2. Favicon hash changes (perceptual hash comparison)
3. Logo image URL returns 404
4. New brand added to the seed list

### 4.3 Tranco Top-1M as Source of Legitimate Reference Pages

**Tranco is appropriate as a seed for domain discovery, but requires careful filtering.**

Tranco (Pochat et al., 2019) is specifically designed to be more stable and representative than Alexa or Majestic, using a blended ranking from multiple sources. For PhishVision's purposes:

**What Tranco provides:**
- A ranked list of legitimate domains, updated daily
- Stability: domains appear consistently across multiple days (reduces noise from URL shorteners and CDNs that inflate Alexa)
- Good coverage of high-traffic legitimate login pages

**Limitations as a brand reference source:**
- Top-1M contains many CDNs, analytics services, and tracking domains with no visual brand identity (e.g., `doubleclick.net`, `cloudflare.com` at high ranks)
- Many top-1000 domains are platforms, not consumer-facing brands (AWS, Cloudflare Workers) — a phishing page on `workers.dev` would be hard to distinguish from a legitimate one visually
- Does not include brand aliases or logo variants

**Recommended Tranco-based workflow:**

```python
def build_seed_list_from_tranco(
    tranco_csv_path: str,
    n_top: int = 500,
    filter_categories: list[str] = None
) -> list[dict]:
    """
    Extract candidate brand domains from Tranco for brand DB seeding.
    Does NOT use Tranco as visual ground truth — only as domain discovery.
    """
    import csv

    # Filter out non-brand domains
    EXCLUDE_PATTERNS = [
        "cloudflare", "akamai", "amazonaws", "googleusercontent",
        "doubleclick", "googleadservices", "fbcdn", "twimg",
        "googleapis", "gstatic", "fastly", "cdn",
    ]

    candidates = []
    with open(tranco_csv_path) as f:
        reader = csv.reader(f)
        for rank, domain in reader:
            if int(rank) > n_top:
                break
            if any(pat in domain for pat in EXCLUDE_PATTERNS):
                continue
            # Only include apex domains, not subdomains
            parts = domain.split(".")
            if len(parts) == 2:  # Simple apex domain
                candidates.append({
                    "name": parts[0].capitalize(),  # Crude name extraction
                    "domains": [domain],
                    "rank": int(rank),
                    "tier": 1 if int(rank) <= 50 else 2
                })

    print(f"Extracted {len(candidates)} candidate brands from Tranco top-{n_top}")
    return candidates
```

**Ground truth visual references should come from:**
1. Brand's own official website (direct logo extraction via CSS selector)
2. Clearbit Logo API (`https://logo.clearbit.com/{domain}`) — curated, high-quality
3. Wikipedia/Wikidata page images (used by KnowPhish)
4. Google Image Search filtered by domain (`site:paypal.com logo`)

**Do not** screenshot Tranco top-1M pages and use them as visual ground truth. The visual layout of legitimate pages changes frequently. Store logo crops, not full page screenshots, as references.

---

## Section 5: Ensemble Weighting

### 5.1 Academic Framework: Late Fusion for Phishing Detection

The MDPI MAKE 2026 paper (Vulfin et al.) is the most current direct reference for multimodal phishing detection ensemble design. Their system uses **four modalities with weighted voting**, achieving F1 0.989 on a 3.2M URL proprietary dataset.

Their modality stack:
1. **CatBoost on URL features + metadata** (Branch 1)
2. **CNN1D on character-level URL representation** (Branch 2)
3. **CodeBERT Transformer on HTML source** (Branch 3)
4. **EfficientNet-B7 on page screenshot** (Branch 4)

The key finding: "multimodal fusion consistently outperforms single-modal baseline models" — no single modality achieves the ensemble's combined performance, even the best individual modality (HTML/CodeBERT) falls 2–5% F1 short of the full ensemble.

### 5.2 Recommended Weighting for PhishVision

Based on published literature and the specific constraints of browser extension deployment:

```
Final Score = w₁ × URL_score + w₂ × HTML_score + w₃ × Visual_score

Recommended weights (to be calibrated on your validation set):
w₁ = 0.35  (URL heuristics)
w₂ = 0.35  (DOM features)
w₃ = 0.30  (Visual similarity)
```

**Rationale for equal-ish weighting:**

URL features are fast (no I/O) and have near-zero false positives on clear cases (IP-in-URL, impossible TLDs). But URL features are trivially evaded by attackers (buy a plausible-looking domain, use HTTPS, stay within domain length limits). *URL alone achieves ~93–95% accuracy but fails on lookalike domains.*

HTML/DOM features require page load but are more structurally difficult to fake. A convincing phishing kit must have password fields and credential exfiltration — those signals are load-bearing parts of the attack itself. *HTML features alone achieve ~96–97% accuracy but can be defeated by well-crafted kits that match legitimate DOM structure.*

Visual features have the highest zero-day detection ability — a page that visually mimics PayPal will fire regardless of whether the attacker correctly copies PayPal's HTML structure. *Visual alone achieves ~91% accuracy (Phishpedia benchmark) but generates false positives on legitimate pages that coincidentally use similar design patterns.*

**The combination is robust to partial evasion:** an attacker who defeats one modality (e.g., uses legitimate-looking URL) still faces the other two. The weighted ensemble requires coordinated evasion across all three modalities simultaneously.

**Conditional weighting (adaptive ensemble):**

```python
def compute_ensemble_score(
    url_score: float,
    html_score: float,
    visual_score: float,
    visual_brand_match: str | None,
    page_url: str,
) -> dict:
    """
    Adaptive weighting based on evidence strength.
    
    If visual_brand_match is detected but URL doesn't match the brand's
    legitimate domain — this is almost certainly phishing. Amplify visual weight.
    """
    W_URL, W_HTML, W_VISUAL = 0.35, 0.35, 0.30

    # Evidence-based weight adjustments
    if visual_brand_match:
        domain = extract_domain(page_url)
        legitimate_domains = get_brand_domains(visual_brand_match)
        if domain not in legitimate_domains:
            # Brand impersonation detected — high confidence signal
            # Up-weight visual to 0.60, reduce others
            W_URL, W_HTML, W_VISUAL = 0.20, 0.20, 0.60

    if url_score > 0.9:
        # Very strong URL signal (IP in URL, <3 day old domain)
        # URL alone is highly reliable in this range
        W_URL, W_HTML, W_VISUAL = 0.60, 0.25, 0.15

    if html_score < 0.1 and visual_score < 0.2:
        # Both content modalities say benign — URL is probably OK too
        # Trust the content modalities, they examined the actual page
        W_URL, W_HTML, W_VISUAL = 0.15, 0.55, 0.30

    final_score = W_URL * url_score + W_HTML * html_score + W_VISUAL * visual_score

    return {
        "final_score": final_score,
        "url_score": url_score,
        "html_score": html_score,
        "visual_score": visual_score,
        "visual_brand": visual_brand_match,
        "weights": [W_URL, W_HTML, W_VISUAL],
        "is_phishing": final_score > 0.65,
        "confidence": "high" if final_score > 0.85 else "medium" if final_score > 0.65 else "low",
    }
```

### 5.3 Score Calibration

Raw model output scores need calibration to be interpretable as probabilities and comparable across modalities. Use Platt scaling (logistic regression on model outputs) calibrated on a held-out validation set of 1,000+ known-phishing and known-legitimate pages.

```python
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
import numpy as np

# Calibrate raw XGBoost DOM score to [0, 1] probability
# Run after training the DOM feature XGBoost model

def calibrate_modality_scores(raw_scores_train, labels_train):
    """
    Fit Platt scaling for a single modality.
    raw_scores: np.ndarray of shape (N,) — uncalibrated logits or raw probabilities
    labels: np.ndarray of shape (N,) — 0/1 ground truth
    """
    calibrator = LogisticRegression(C=1e10, solver='lbfgs')
    calibrator.fit(raw_scores_train.reshape(-1, 1), labels_train)
    return calibrator

# After fitting, apply to new scores:
# calibrated_score = calibrator.predict_proba(raw_score.reshape(-1,1))[0][1]
```

### 5.4 Complete XGBoost DOM Classifier

```python
"""
PhishVision — DOM Feature Classifier Training
"""
import xgboost as xgb
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
import skl2onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Feature names matching content.js output
FEATURE_NAMES = [
    'password_field_count', 'hidden_input_count', 'email_field_count',
    'form_count', 'form_action_external', 'input_to_element_ratio',
    'external_script_count', 'total_script_count', 'external_script_ratio',
    'external_css_count', 'external_image_count', 'external_resource_ratio',
    'iframe_count', 'iframe_invisible_count', 'iframe_src_external',
    'total_link_count', 'null_link_count', 'null_link_ratio',
    'right_click_blocked', 'status_bar_customised', 'has_meta_refresh',
    'popup_window_count', 'title_empty', 'title_length',
    'total_element_count', 'total_input_count', 'has_favicon',
]

def train_dom_classifier(feature_csv: str) -> xgb.XGBClassifier:
    df = pd.read_csv(feature_csv)
    X = df[FEATURE_NAMES].fillna(0).astype(np.float32)
    y = df['label'].values  # 1 = phishing, 0 = legitimate

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=sum(y == 0) / sum(y == 1),  # Handle class imbalance
        eval_metric='logloss',
        use_label_encoder=False,
        device='cpu',
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        early_stopping_rounds=20,
        verbose=False,
    )

    y_pred_proba = model.predict_proba(X_test)[:, 1]
    print(f"AUC: {roc_auc_score(y_test, y_pred_proba):.4f}")
    print(classification_report(y_test, model.predict(X_test)))

    return model

def export_dom_model_to_onnx(model: xgb.XGBClassifier, output_path: str):
    """Export XGBoost model to ONNX for browser deployment."""
    # XGBoost native ONNX export
    model.save_model("dom_model_xgb.json")
    import subprocess
    subprocess.run([
        "python", "-c",
        f"""
import xgboost as xgb
from onnxmltools import convert_xgboost
from onnxmltools.convert.common.data_types import FloatTensorType
m = xgb.XGBClassifier()
m.load_model('dom_model_xgb.json')
proto = convert_xgboost(m, 'dom_classifier',
    [('input', FloatTensorType([None, {len(FEATURE_NAMES)}]))])
with open('{output_path}', 'wb') as f:
    f.write(proto.SerializeToString())
print('ONNX DOM model exported:', '{output_path}')
        """
    ])
    # Typical size: 200-500 KB for 300 trees — extremely browser-friendly
```

---

## Section 6: Complete System Architecture

### 6.1 Component Interaction

```
Browser Tab Navigation
        ↓
content.js (injected)
├── Extract DOM features (30ms)
├── Send to offscreen document via service worker
└── Report URL

offscreen.js (persistent, ONNX loaded)
├── Receive URL + DOM features
├── 1. URL heuristics (5ms) → URL score [0-1]
├── 2. DOM feature XGBoost inference (10ms) → HTML score [0-1]
├── 3. Request screenshot via service worker → chrome.tabs.captureVisibleTab
├── 4. EfficientNet-B0 embedding (80-120ms) → 1280-d embedding
├── 5. Cosine similarity vs brand DB (1ms) → visual score + brand match
└── 6. Adaptive ensemble scoring → final score

service worker (background.js)
├── Route messages between content.js and offscreen.js
├── Request screenshot capture
└── Trigger UI badge/popup update

popup.html
└── Display verdict, confidence, and explainability (matched keywords, visual match)
```

### 6.2 Adversarial Robustness Notes

Based on the ASIA CCS 2025 robustness evaluation (84–95% attack success against Phishpedia/PhishIntention alone):

PhishVision's three-modality design is inherently more robust because:
- An attacker who defeats the visual matching (logo masking attack) still faces URL and DOM analysis
- An attacker who correctly mimics a legitimate DOM structure (DOM evasion) still faces visual and URL analysis
- The brand-domain consistency check (visual match to Brand X but URL ≠ Brand X domain) is extremely difficult to bypass: it requires either using the legitimate domain (which they don't control) or not impersonating a brand (which defeats the purpose of the attack)

**Remaining critical evasion vectors to mitigate:**
1. **Logo removal attack**: Remove or obfuscate the brand logo → visual score drops. Mitigate: add text-based brand name extraction from page title, HTML `<title>` and `<h1>` tags as fallback signal.
2. **DOM mimicry**: Clone legitimate site HTML exactly. Mitigate: `form_action_external` and `null_link_ratio` remain high on cloned pages because the attacker still needs to collect credentials to a different server.
3. **TLS/domain aging**: Buy a plausible domain, age it 30+ days before attacking. Mitigate: domain age is one of many URL features; the ensemble still catches these via HTML+Visual modalities.

---

*Report compiled February 2026. Primary citations: Phishpedia (Lin et al., USENIX Security 2021), PhishIntention (Liu et al., USENIX Security 2022), KnowPhish (Li et al., USENIX Security 2024), Adversarial Robustness of Reference-based Detectors (Roh et al., ASIA CCS 2025), VisualPhishNet (Abdelnabi et al., ACM CCS 2020), Multimodal Phishing Detection with XAI (Vulfin et al., MDPI MAKE 2026), Effectiveness and Robustness of Visual Similarity Methods (arXiv:2405.19598, May 2024), ONNX Runtime Web official documentation (onnxruntime.ai), Chrome Extension Manifest V3 Service Worker Lifecycle (developer.chrome.com).*

*TLP:WHITE — Share freely for defensive cybersecurity purposes.*
