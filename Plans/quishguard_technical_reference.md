# QuishGuard — Complete Technical Reference
## Pixel-Structural QR Phishing Detection: Engineering Guide

> **Primary source:** Trad, F. & Chehab, A. (2025). *Detecting Quishing Attacks with Machine Learning Techniques Through QR Code Analysis.* arXiv:2505.03451. 8th International Conference on Optimization and Learning, Dubai.  
> **Dataset:** `fouadtrad/Detecting-Quishing-Attacks-with-Machine-Learning-Techniques-Through-QR-Code-Analysis` (CC-BY-4.0)  
> **Split/Nested sources:** Barracuda Threat Spotlight (Aug 20, 2025) · Gabagool/Tycoon 2FA PhaaS analysis · Unit 42 QR Phenomenon (Apr 2025)  
> **Compiled:** February 2026

---

## Table of Contents

1. [Pixel Features — The fouadtrad XGBoost Model](#section-1-pixel-features)
   - [QR v13 Anatomy](#11-qr-version-13-anatomy--the-69×69-grid)
   - [The Feature Set: What the Paper Actually Uses](#12-the-feature-set-what-the-paper-actually-uses)
   - [Which Regions Are Informative](#13-which-regions-carry-phishing-signal)
   - [Complete OpenCV Feature Extraction Code](#14-complete-opencv-feature-extraction-code)
   - [Training the XGBoost Model](#15-training-the-xgboost-model)
   - [Going Beyond Raw Pixels](#16-going-beyond-raw-pixels--handcrafted-structural-features)

2. [Split & Nested QR Evasion](#section-2-split--nested-qr-evasion)
   - [Split QR — Gabagool PhaaS Technique](#21-split-qr--gabagool-phaas-technique)
   - [Nested QR — Tycoon 2FA Technique](#22-nested-qr--tycoon-2fa-technique)
   - [ASCII/HTML QR Codes](#23-asciihtml-qr-codes)
   - [Detection Pipeline for All Three Variants](#24-detection-pipeline-for-all-three-variants)

3. [PDF QR Extraction — Library Comparison](#section-3-pdf-qr-extraction)
   - [How QR Codes Appear in PDFs](#31-how-qr-codes-appear-in-pdfs)
   - [Library Comparison Table](#32-library-comparison)
   - [Recommended Pipeline: PyMuPDF + pdf2image Fallback](#33-recommended-pipeline)
   - [Handling Split QR in PDFs](#34-handling-split-qr-across-two-pdf-image-objects)

4. [Safe Decoding — Sandboxed Docker Architecture](#section-4-safe-decoding--docker-sandbox)
   - [The Threat Model](#41-the-threat-model)
   - [Docker Compose Architecture](#42-docker-compose-architecture)
   - [Container Definitions](#43-container-definitions)
   - [The Scanner Service](#44-the-scanner-service-no-network-access)
   - [The VT Submitter Service](#45-the-vt-submitter-service)
   - [Network Isolation Verification](#46-network-isolation-verification)

5. [Mobile Context Detection](#section-5-mobile-context-detection)
   - [Why QR Phishing Is Mobile-Specific](#51-why-qr-phishing-is-mobile-specific)
   - [UA-Switching Redirect Chains](#52-ua-switching-redirect-chains)
   - [Complete Mobile vs Desktop Comparison Code](#53-complete-mobile-vs-desktop-comparison-code)
   - [Cloudflare Turnstile and Anti-Bot Evasion](#54-cloudflare-turnstile-and-anti-bot-evasion)

---

## SECTION 1: Pixel Features

### 1.1 QR Version 13 Anatomy — The 69×69 Grid

The paper uses **version 13 QR codes exclusively** (69×69 modules). This is deliberate: fixing the version gives every sample an identical grid layout, making pixel positions directly comparable across all 9,987 samples.

A version 13 QR code module count = `4V + 17 = 4(13) + 17 = 69`.

```
┌──────────────────────────────────────────────────┐
│ QR Version 13 — 69×69 Module Grid                │
│                                                  │
│  [0,0]─────────[0,6]  ···  [0,62]────[0,68]      │
│   │ FINDER      │              │ FINDER  │        │
│   │ PATTERN TL  │              │ PATTERN │        │
│   │  7×7        │              │ TR 7×7  │        │
│  [6,0]─────────[6,6]  ···  [6,62]────[6,68]      │
│                                                  │
│  Row 6  ── TIMING PATTERN (cols 8–60) ──         │
│  Col 6  ── TIMING PATTERN (rows 8–60) ──         │
│                                                  │
│  [8,0]─[8,8] FORMAT INFO   [8,62]─[8,68]         │
│                                                  │
│  ┌─────────────────────────────────────────┐     │
│  │        DATA + ECC MODULE REGION         │     │
│  │   (rows 9–60, non-timing cols/rows)     │     │
│  │   This is where phishing signal lives  │     │
│  └─────────────────────────────────────────┘     │
│                                                  │
│  [62,0]────────[62,6]  ALIGNMENT PATTERNS        │
│   │ FINDER      │      (6 alignment patterns     │
│   │ PATTERN BL  │       for version 13)           │
│   │  7×7        │                                │
│  [68,0]────────[68,6]                            │
│                                                  │
│  [68,68] DARK MODULE (always 1) at (4V+9, 8)    │
│          = (61, 8)                               │
└──────────────────────────────────────────────────┘
```

**Fixed structural regions (same in EVERY version 13 QR code with LOW error correction):**

| Region | Positions | Why Fixed |
|--------|-----------|-----------|
| Finder patterns (TL) | rows 0–6, cols 0–6 | Identical in every QR code |
| Finder patterns (TR) | rows 0–6, cols 62–68 | Identical in every QR code |
| Finder patterns (BL) | rows 62–68, cols 0–6 | Identical in every QR code |
| Separators | 1-module border around each finder | Always white |
| Horizontal timing | row 6, cols 8–60 | Alternating 1010... |
| Vertical timing | col 6, rows 8–60 | Alternating 1010... |
| Dark module | (61, 8) | Always black |
| Alignment patterns | 6 patterns per v13 spec | Fixed positions, fixed pattern |
| Format information | rows 8, cols 0–8 and symmetric copies | Encodes ECL + mask |
| Version information | rows 0–5 cols 61–63, rows 61–63 cols 0–5 | Fixed for v13 |

**Variable regions (different in every QR code — this is where URL data lives):**
- All non-fixed modules: data modules + error correction modules
- Arranged in 8-module wide "codeword" columns, reading right-to-left, bottom-to-top

---

### 1.2 The Feature Set: What the Paper Actually Uses

The fouadtrad paper uses **raw pixel values** as features — nothing more complex than that. Each QR code image is flattened into a 1D array and each pixel becomes a feature.

```
Feature vector = flatten(img)  # shape (4761,) for 69×69 image
Feature F_{i,j} = pixel value at row i, column j
Feature range = {0, 255}  # binary QR: 0 = white module, 255 = black module
Total features = 69 × 69 = 4,761
```

The key innovation of the paper is that **it never decodes the QR content** — it treats the image as a pure visual pattern and lets XGBoost learn which pixels correlate with phishing vs benign URLs.

**Why does this work?** URLs have measurable structural properties that propagate into QR encoding:
- Phishing URLs tend to be longer (more data → different error correction codeword patterns)
- Phishing URLs use specific character patterns (random subdomains, long paths, query strings with encoded payloads) that produce different bit sequences
- The masking pattern selected by the encoder (to ensure balanced light/dark modules) differs by content
- Domain-level entropy differences create systematic pixel density differences in data module regions

**After feature selection (the AUC 0.9133 result):**
The authors ran XGBoost feature importance, identified pixels with importance ≈ 0, and removed them. This removes:
- All fixed structural pixels (they are the same in all samples → zero variance → zero predictive power)
- Any pixel that happens not to discriminate between classes in the training set

The remaining selected pixels are predominantly in the **data module region** — the area that encodes the actual URL content.

---

### 1.3 Which Regions Carry Phishing Signal

Based on the paper's Figures 3/4 (important vs unimportant pixels) and QR code structure theory:

```
HIGH IMPORTANCE (dark in Figure 2 feature importance maps):
  ├── Data module columns: rows 9–60, variable cols (the URL encoding area)
  ├── Error correction modules: bottom-right quadrant data area
  ├── Format information region: encodes mask pattern + ECL
  │   (phishing QR codes may show different mask distribution than benign)
  └── Remainder code region: modules that finalize the codeword layout

LOW/ZERO IMPORTANCE (excluded in Figure 4):
  ├── Finder patterns (0–6 rows/cols at corners): ALL identical across samples
  ├── Separator modules: ALL white always
  ├── Timing patterns (row 6, col 6): fixed alternating pattern
  ├── Dark module (61, 8): always 1
  └── Alignment patterns: fixed 5×5 pattern at fixed positions
```

**Critical implication for QuishGuard:** When you normalise QR images to a fixed size before feature extraction, preserve the version-level structure. If you rescale to a non-version-aligned size, the pixel-to-module mapping breaks and feature positions become meaningless.

---

### 1.4 Complete OpenCV Feature Extraction Code

```python
"""
QuishGuard Feature Extraction Pipeline
Implements both raw pixel features (fouadtrad baseline) and 
engineered structural features (QuishGuard extension).
"""

import cv2
import numpy as np
import pickle
from pathlib import Path
from typing import Tuple, Dict, List
from dataclasses import dataclass


# ─── QR v13 Region Definitions ────────────────────────────────────────────────

QR_VERSION = 13
GRID_SIZE  = 69  # 4*13 + 17

# Finder pattern positions (top-left corners of 7×7 patterns)
FINDER_PATTERNS = [
    (0, 0),    # top-left
    (0, 62),   # top-right
    (62, 0),   # bottom-left
]

# Version 13 alignment pattern centres (from ISO/IEC 18004 Table E.1)
# Version 13: positions at rows/cols [6, 26, 46, 66]
ALIGNMENT_CENTRES_V13 = [
    (26, 26), (26, 46), (26, 66),
    (46, 26), (46, 46), (46, 66),
    (66, 26), (66, 46), (66, 66),
]

# Format information module positions (first copy)
FORMAT_INFO_ROW    = list(range(0, 6)) + [7, 8]   # col=8
FORMAT_INFO_COL    = [8] * 8
FORMAT_INFO_COLS   = [0, 1, 2, 3, 4, 5, 7, 8]     # row=8


def get_fixed_module_mask(grid_size: int = GRID_SIZE) -> np.ndarray:
    """
    Returns a boolean mask marking ALL fixed structural positions.
    True = fixed (same in every version-13 QR code).
    False = variable data/ECC module.
    """
    mask = np.zeros((grid_size, grid_size), dtype=bool)
    
    # 1. Finder patterns (7×7) + separators (8×8 including white border)
    for (fr, fc) in FINDER_PATTERNS:
        # 8×8 region including separator
        r0 = max(0, fr - 1)
        r1 = min(grid_size, fr + 8)
        c0 = max(0, fc - 1)
        c1 = min(grid_size, fc + 8)
        mask[r0:r1, c0:c1] = True
    
    # 2. Timing patterns
    mask[6, 8:61] = True   # horizontal timing
    mask[8:61, 6] = True   # vertical timing
    
    # 3. Dark module
    mask[61, 8] = True
    
    # 4. Alignment patterns (5×5 each, including border)
    for (ar, ac) in ALIGNMENT_CENTRES_V13:
        # Check not overlapping finder patterns
        if not mask[ar, ac]:  # Only if centre not already masked
            mask[ar-2:ar+3, ac-2:ac+3] = True
    
    # 5. Format information (both copies)
    # Copy 1: row 8 (cols 0–8) and col 8 (rows 0–8)
    mask[8, 0:9] = True
    mask[0:9, 8] = True
    # Copy 2: col 8 rows 62–68, row 8 cols 62–68 (approximate)
    mask[62:69, 8] = True
    mask[8, 62:69] = True
    
    # 6. Version information (v13 ≥ v7, so present)
    # Top-right: rows 0–5, cols 61–63
    mask[0:6, 61:64] = True
    # Bottom-left: rows 61–63, cols 0–5
    mask[61:64, 0:6] = True
    
    return mask


FIXED_MASK = get_fixed_module_mask()
DATA_MASK  = ~FIXED_MASK  # Variable modules


# ─── Preprocessing ─────────────────────────────────────────────────────────────

def preprocess_qr(img_input, target_size: int = GRID_SIZE) -> np.ndarray:
    """
    Normalise a QR code image to the standard grid size.
    
    Args:
        img_input: numpy array (any size, any channel count) or path
        target_size: grid size in pixels (69 for v13, paper standard)
    Returns:
        Binary uint8 array of shape (target_size, target_size)
        Values: 0 = white module, 255 = black module
    """
    if isinstance(img_input, (str, Path)):
        img = cv2.imread(str(img_input), cv2.IMREAD_GRAYSCALE)
    elif isinstance(img_input, np.ndarray):
        if img_input.ndim == 3:
            img = cv2.cvtColor(img_input, cv2.COLOR_BGR2GRAY)
        else:
            img = img_input.copy()
    else:
        raise ValueError(f"Unsupported input type: {type(img_input)}")
    
    if img is None:
        raise ValueError("Failed to load image")
    
    # Resize to target grid size (INTER_NEAREST preserves binary edges)
    if img.shape != (target_size, target_size):
        img = cv2.resize(img, (target_size, target_size),
                         interpolation=cv2.INTER_NEAREST)
    
    # Binarize: Otsu threshold → clean binary
    _, binary = cv2.threshold(img, 0, 255,
                               cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    
    # Ensure dark=255, light=0 (standard QR orientation)
    dark_fraction = np.mean(binary == 0)
    if dark_fraction > 0.5:          # Image is inverted
        binary = cv2.bitwise_not(binary)
    
    return binary


# ─── Feature 1: Raw Pixel Vector (fouadtrad baseline) ──────────────────────────

def extract_raw_pixel_features(img: np.ndarray) -> np.ndarray:
    """
    Exact replication of fouadtrad paper feature space.
    Flattens 69×69 binary image to 4,761-element feature vector.
    Values: 0 (white) or 255 (black).
    
    To use selected features only (AUC 0.9133 result):
    Load the feature importance mask and apply it after extraction.
    """
    assert img.shape == (GRID_SIZE, GRID_SIZE), \
        f"Expected {GRID_SIZE}×{GRID_SIZE}, got {img.shape}"
    return img.flatten().astype(np.float32)


def extract_selected_pixel_features(
    img: np.ndarray,
    selected_indices: np.ndarray
) -> np.ndarray:
    """
    Apply feature selection — extract only the pixels identified as important
    by the XGBoost/RF/LightGBM importance analysis.
    
    Args:
        img: preprocessed 69×69 binary image
        selected_indices: 1D array of flat pixel indices to keep
                          (derived from feature importance analysis)
    """
    flat = img.flatten().astype(np.float32)
    return flat[selected_indices]


def get_data_module_features(img: np.ndarray) -> np.ndarray:
    """
    Extract only data/ECC module pixels (removes fixed structural regions).
    This is a principled version of fouadtrad's feature selection:
    skip pixels that are identical across ALL version-13 QR codes.
    Reduces from 4,761 to ~2,200 features.
    """
    flat = img.flatten().astype(np.float32)
    data_indices = np.where(DATA_MASK.flatten())[0]
    return flat[data_indices]


# ─── Feature 2: Regional Statistics (QuishGuard extension) ────────────────────

@dataclass
class QRRegionFeatures:
    """Structural region-level features for interpretable detection."""
    # --- Raw pixel baseline ---
    raw_pixels: np.ndarray          # shape (4761,)
    data_pixels: np.ndarray         # shape (~2200,)
    
    # --- Module density by region ---
    density_total: float            # fraction of dark modules (all 69×69)
    density_data: float             # density in data module region only
    density_tl_finder: float        # top-left finder (should be ~0.51)
    density_tr_finder: float        # top-right finder
    density_bl_finder: float        # bottom-left finder
    
    # --- Spatial statistics ---
    row_densities: np.ndarray       # dark module fraction per row (69,)
    col_densities: np.ndarray       # dark module fraction per col (69,)
    
    # --- Quadrant densities ---
    q1_density: float               # top-left quadrant (excluding finders)
    q2_density: float               # top-right quadrant (excluding finder)
    q3_density: float               # bottom-left quadrant (excluding finder)
    q4_density: float               # bottom-right quadrant
    
    # --- Format info region ---
    format_info_pattern: np.ndarray # 15 format information bits (row 8 col 0-8 + col 8 row 0-8)
    
    # --- Module transition statistics ---
    horizontal_transitions: float   # avg dark→light or light→dark per row
    vertical_transitions: float     # avg transitions per column
    
    # --- Block run statistics ---
    mean_run_length: float          # avg consecutive same-colour run
    max_run_length: float           # longest run (indicates solid blocks)
    
    # --- Error correction level inference ---
    inferred_ecl: str               # 'L', 'M', 'Q', 'H' from format bits
    
    # --- Symmetry score ---
    horizontal_symmetry: float      # data region row-to-row correlation
    
    def to_feature_vector(self) -> np.ndarray:
        """Concatenate all scalar features into a single vector."""
        scalars = np.array([
            self.density_total,
            self.density_data,
            self.density_tl_finder,
            self.density_tr_finder,
            self.density_bl_finder,
            self.q1_density, self.q2_density,
            self.q3_density, self.q4_density,
            self.horizontal_transitions,
            self.vertical_transitions,
            self.mean_run_length,
            self.max_run_length,
            self.horizontal_symmetry,
            # ECL as one-hot
            float(self.inferred_ecl == 'L'),
            float(self.inferred_ecl == 'M'),
            float(self.inferred_ecl == 'Q'),
            float(self.inferred_ecl == 'H'),
        ], dtype=np.float32)
        return np.concatenate([
            self.data_pixels / 255.0,      # normalised data pixels
            self.row_densities,             # per-row density (69,)
            self.col_densities,             # per-col density (69,)
            self.format_info_pattern,       # format info bits
            scalars,
        ])


def extract_region_features(img: np.ndarray) -> QRRegionFeatures:
    """
    Extract all structural region features from a preprocessed 69×69 QR image.
    """
    assert img.shape == (GRID_SIZE, GRID_SIZE)
    norm = img.astype(np.float32) / 255.0  # 1.0 = dark, 0.0 = light
    
    # ── Module densities ──────────────────────────────────────────────────────
    density_total  = float(np.mean(norm))
    
    data_region = norm[DATA_MASK]
    density_data = float(np.mean(data_region))
    
    # Finder pattern densities (7×7 inner square only)
    def finder_density(r0, c0):
        patch = norm[r0:r0+7, c0:c0+7]
        return float(np.mean(patch))
    
    density_tl = finder_density(0, 0)
    density_tr = finder_density(0, 62)
    density_bl = finder_density(62, 0)
    
    # ── Spatial statistics ────────────────────────────────────────────────────
    row_densities = norm.mean(axis=1)   # (69,)
    col_densities = norm.mean(axis=0)   # (69,)
    
    # ── Quadrant densities (inner region, skip fixed structural) ──────────────
    mid_r, mid_c = GRID_SIZE // 2, GRID_SIZE // 2
    
    def quadrant_data_density(r_slice, c_slice):
        sub_mask = DATA_MASK[r_slice, c_slice]
        sub_norm = norm[r_slice, c_slice]
        if sub_mask.sum() == 0:
            return 0.0
        return float(sub_norm[sub_mask].mean())
    
    q1 = quadrant_data_density(slice(0, mid_r), slice(0, mid_c))
    q2 = quadrant_data_density(slice(0, mid_r), slice(mid_c, GRID_SIZE))
    q3 = quadrant_data_density(slice(mid_r, GRID_SIZE), slice(0, mid_c))
    q4 = quadrant_data_density(slice(mid_r, GRID_SIZE), slice(mid_c, GRID_SIZE))
    
    # ── Format information bits ───────────────────────────────────────────────
    # First copy: row 8 cols 0-8 (9 bits) + col 8 rows 0-6, 8 (8 bits) = 17 raw
    # but 1 module at (8,6) is always dark, so effective = 15 bits
    fmt_row = img[8, 0:9].astype(np.float32) / 255.0   # (9,)
    fmt_col = np.concatenate([
        img[0:6, 8].astype(np.float32),
        img[7:9, 8].astype(np.float32)
    ]) / 255.0  # (8,) → 6 + 2
    format_bits = np.concatenate([fmt_row, fmt_col])    # (17,)
    
    # Infer error correction level from bits 13-14 of format info
    # (after XOR with mask pattern — simplified inference)
    ecl_bits = img[8, 7:9]  # approximate position of ECL bits
    ecl_code  = (int(ecl_bits[0] > 128) << 1) | int(ecl_bits[1] > 128)
    ecl_map   = {0b01: 'L', 0b00: 'M', 0b11: 'Q', 0b10: 'H'}
    inferred_ecl = ecl_map.get(ecl_code, 'L')
    
    # ── Transition statistics ─────────────────────────────────────────────────
    binary = (img > 127).astype(np.int8)
    
    h_transitions = []
    v_transitions = []
    for r in range(GRID_SIZE):
        row = binary[r, :]
        t = int(np.sum(np.abs(np.diff(row))))
        h_transitions.append(t)
    for c in range(GRID_SIZE):
        col = binary[:, c]
        t = int(np.sum(np.abs(np.diff(col))))
        v_transitions.append(t)
    
    h_trans_mean = float(np.mean(h_transitions))
    v_trans_mean = float(np.mean(v_transitions))
    
    # ── Run-length statistics ─────────────────────────────────────────────────
    all_runs = []
    for r in range(GRID_SIZE):
        row = binary[r, :]
        # Find runs using diff
        changes = np.where(np.diff(row) != 0)[0] + 1
        positions = np.concatenate([[0], changes, [GRID_SIZE]])
        runs = np.diff(positions)
        all_runs.extend(runs.tolist())
    
    mean_run = float(np.mean(all_runs)) if all_runs else 0.0
    max_run  = float(np.max(all_runs))  if all_runs else 0.0
    
    # ── Horizontal symmetry of data region ────────────────────────────────────
    # Measure row-to-row Pearson correlation in data rows
    data_rows = [norm[r, :] for r in range(9, 61) if DATA_MASK[r, :].any()]
    if len(data_rows) > 1:
        corrs = []
        for i in range(len(data_rows) - 1):
            c = float(np.corrcoef(data_rows[i], data_rows[i+1])[0, 1])
            if not np.isnan(c):
                corrs.append(c)
        h_symmetry = float(np.mean(corrs)) if corrs else 0.0
    else:
        h_symmetry = 0.0
    
    return QRRegionFeatures(
        raw_pixels           = img.flatten(),
        data_pixels          = (norm[DATA_MASK] * 255).astype(np.uint8),
        density_total        = density_total,
        density_data         = density_data,
        density_tl_finder    = density_tl,
        density_tr_finder    = density_tr,
        density_bl_finder    = density_bl,
        row_densities        = row_densities,
        col_densities        = col_densities,
        q1_density           = q1,
        q2_density           = q2,
        q3_density           = q3,
        q4_density           = q4,
        format_info_pattern  = format_bits,
        horizontal_transitions = h_trans_mean,
        vertical_transitions   = v_trans_mean,
        mean_run_length      = mean_run,
        max_run_length       = max_run,
        inferred_ecl         = inferred_ecl,
        horizontal_symmetry  = h_symmetry,
    )


# ─── Feature 3: CNN Spatial Features (QuishGuard extension) ───────────────────

def extract_cnn_features(img: np.ndarray, model=None) -> np.ndarray:
    """
    Extract spatial features using a lightweight CNN.
    Falls back to Gabor filter bank if no model provided.
    
    The fouadtrad paper notes CNNs as future work — this is our extension.
    """
    if model is not None:
        # Use trained CNN encoder
        import torch
        tensor = torch.from_numpy(img[None, None].astype(np.float32) / 255.0)
        with torch.no_grad():
            feats = model.encode(tensor)
        return feats.numpy().flatten()
    
    # Fallback: Gabor filter bank captures QR module frequency/orientation
    features = []
    for theta in [0, np.pi/4, np.pi/2, 3*np.pi/4]:
        for sigma in [1, 2]:
            kernel = cv2.getGaborKernel(
                (11, 11), sigma=sigma, theta=theta,
                lambd=4.0, gamma=0.5, psi=0, ktype=cv2.CV_32F
            )
            filtered = cv2.filter2D(img.astype(np.float32), -1, kernel)
            features.extend([
                float(filtered.mean()),
                float(filtered.std()),
                float(filtered.max()),
            ])
    return np.array(features, dtype=np.float32)
```

---

### 1.5 Training the XGBoost Model

```python
"""
Reproduce fouadtrad XGBoost results + QuishGuard extended pipeline.
"""

import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score
import xgboost as xgb


def load_fouadtrad_dataset(dataset_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """Load the fouadtrad dataset from GitHub."""
    with open(f"{dataset_path}/qr_codes_29.pickle", 'rb') as f:
        X_raw = pickle.load(f)   # shape: (9987, 69, 69)
    with open(f"{dataset_path}/qr_codes_29_labels.pickle", 'rb') as f:
        y = pickle.load(f)        # shape: (9987,) — 0=benign, 1=phishing
    
    # Flatten to pixel features — this IS the fouadtrad feature set
    X = X_raw.reshape(len(X_raw), -1).astype(np.float32)
    print(f"Dataset: {X.shape} features, {y.sum()} phishing / {(y==0).sum()} benign")
    return X, y


def train_baseline_xgboost(X: np.ndarray, y: np.ndarray) -> xgb.XGBClassifier:
    """
    Exact reproduction of fouadtrad XGBoost model.
    Hyperparameters from Table 1 of the paper.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    model = xgb.XGBClassifier(
        learning_rate  = 0.2,     # from Table 1
        n_estimators   = 150,     # from Table 1
        use_label_encoder = False,
        eval_metric    = 'auc',
        random_state   = 42,
        n_jobs         = -1,
    )
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False
    )
    
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_pred_proba)
    print(f"Baseline XGBoost AUC: {auc:.4f}  (paper: 0.9083–0.9106)")
    return model


def apply_feature_selection(
    model: xgb.XGBClassifier,
    X: np.ndarray,
    importance_threshold: float = 0.0
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Apply feature importance-based selection (reproduces AUC 0.9133 result).
    Returns selected feature indices and reduced X.
    """
    importances = model.feature_importances_
    selected = np.where(importances > importance_threshold)[0]
    print(f"Feature selection: {len(selected)}/{X.shape[1]} pixels retained "
          f"({len(selected)/X.shape[1]*100:.1f}%)")
    return selected, X[:, selected]


def train_quishguard_model(X: np.ndarray, y: np.ndarray) -> xgb.XGBClassifier:
    """
    QuishGuard extended model with additional structural features.
    Combined pixel + region features.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    model = xgb.XGBClassifier(
        learning_rate   = 0.1,
        n_estimators    = 300,
        max_depth       = 6,
        subsample       = 0.8,
        colsample_bytree= 0.8,
        reg_alpha       = 0.1,    # L1 — helps with many zero-importance pixels
        reg_lambda      = 1.0,
        eval_metric     = 'auc',
        early_stopping_rounds = 20,
        random_state    = 42,
        n_jobs          = -1,
    )
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=50
    )
    
    y_pred = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_pred)
    print(f"QuishGuard extended AUC: {auc:.4f}")
    return model
```

---

### 1.6 Going Beyond Raw Pixels — Handcrafted Structural Features

The raw pixel approach gives AUC 0.9133. The paper itself proposes CNNs and ViTs as future work. Here's what QuishGuard adds on top:

| Feature Group | Features | Rationale |
|---------------|----------|-----------|
| `density_data` | 1 | Phishing URLs → longer → denser data modules |
| `row_densities` | 69 | Row-level dark module profile captures URL length distribution |
| `col_densities` | 69 | Column-level profile captures masking pattern effects |
| `q1–q4_density` | 4 | Quadrant imbalance signals specific URL character distributions |
| `h/v_transitions` | 2 | Transition rate reflects URL character entropy |
| `run_stats` | 2 | Long runs of same colour → URL shortener padding patterns |
| `format_bits` | 17 | ECL and mask pattern differ by URL content and length |
| `gabor_responses` | 24 | Captures module-level frequency/orientation patterns |
| **Total extension** | **188** | Added to ~2,200 selected pixel features |

---

## SECTION 2: Split & Nested QR Evasion

### 2.1 Split QR — Gabagool PhaaS Technique

In this approach, adversaries divide a single malicious QR code into multiple image segments, embedding them separately within phishing emails. When scanned by traditional email security solutions, these fragments appear as unrelated, benign visuals, preventing the system from reconstructing and analyzing the complete code.

**Technical implementation (reconstructed from Barracuda analysis):**

```html
<!-- Actual HTML structure of a split QR phishing email -->
<table cellspacing="0" cellpadding="0" border="0">
  <tr>
    <!-- Top half of QR code — image 1 -->
    <td>
      <img src="cid:qr_top_half.png"
           width="200" height="100"
           style="display:block; margin:0; padding:0; border:0">
    </td>
  </tr>
  <tr>
    <!-- Bottom half of QR code — image 2 -->
    <td>
      <img src="cid:qr_bottom_half.png"
           width="200" height="100"
           style="display:block; margin:0; padding:0; border:0; margin-top:-1px">
    </td>
  </tr>
</table>
```

**How the split is constructed:**

```python
"""
Split QR detector — reverse engineering the Gabagool technique.
"""
import cv2
import numpy as np
from PIL import Image


def detect_and_reconstruct_split_qr(images: List[np.ndarray]) -> List[np.ndarray]:
    """
    Given a list of images extracted from an email/PDF, detect and reconstruct
    split QR codes.
    
    Strategy:
    1. Identify images that look like QR halves (binary, appropriate aspect ratio)
    2. Find pairs that have matching widths and QR-like structure
    3. Attempt vertical and horizontal concatenation
    4. Verify the reconstructed image decodes as a valid QR
    """
    from pyzbar.pyzbar import decode
    
    candidate_halves = []
    for i, img in enumerate(images):
        if img is None or img.size == 0:
            continue
        h, w = img.shape[:2]
        # QR half characteristics: approximately 1:1 to 1:3 aspect ratio
        # (a half-split QR is roughly 1:2)
        aspect = w / h if h > 0 else 0
        if 0.3 < aspect < 4.0:
            # Check if it looks like a QR component (high contrast, binary-ish)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
            _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_OTSU)
            dark_frac = np.mean(binary < 128)
            # QR codes: 30-70% dark modules
            if 0.05 < dark_frac < 0.95:
                candidate_halves.append((i, img, w, h))
    
    reconstructed = []
    # Try all pairs
    for i in range(len(candidate_halves)):
        for j in range(i + 1, len(candidate_halves)):
            idx_a, img_a, w_a, h_a = candidate_halves[i]
            idx_b, img_b, w_b, h_b = candidate_halves[j]
            
            # Vertical split: same width, different heights
            if abs(w_a - w_b) < 5:
                # Try both orderings
                for top, bottom in [(img_a, img_b), (img_b, img_a)]:
                    combined = np.vstack([top, bottom])
                    codes = decode(combined)
                    if codes:
                        reconstructed.append(combined)
                        break
            
            # Horizontal split: same height, different widths
            if abs(h_a - h_b) < 5:
                for left, right in [(img_a, img_b), (img_b, img_a)]:
                    # Resize to same height before hstack
                    target_h = max(left.shape[0], right.shape[0])
                    l = cv2.resize(left, (left.shape[1], target_h))
                    r = cv2.resize(right, (right.shape[1], target_h))
                    combined = np.hstack([l, r])
                    codes = decode(combined)
                    if codes:
                        reconstructed.append(combined)
                        break
    
    return reconstructed
```

---

### 2.2 Nested QR — Tycoon 2FA Technique

In this instance the malicious QR code is embedded within or around a legitimate QR code. The outer QR code points to a malicious URL, while the inner QR code leads to Google. This technique can make it harder for scanners to detect the threat because the results are ambiguous.

**Why most scanners fail:** pyzbar, ZXing, and most commercial decoders return **one result** per image — the first (highest confidence) detection. When the outer malicious QR is larger and clearer, decoders typically return it. But the inner benign QR can confuse some scanners into decoding the inner one instead — the one pointing to Google.

```python
"""
Nested QR detector — decode ALL QR codes in an image, not just the first.
"""
import cv2
import numpy as np
from pyzbar.pyzbar import decode, ZBarSymbol
from zxingcpp import read_barcodes, BarcodeFormat


def decode_all_qr_codes(img: np.ndarray) -> List[Dict]:
    """
    Exhaustive QR decoder: returns ALL detected QR codes in an image,
    including nested/overlapping ones.
    
    Uses multi-scale sliding window + two decoder backends.
    """
    results = []
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    
    # Pass 1: Full image decode (catches outer QR and simple codes)
    for code in decode(img, symbols=[ZBarSymbol.QRCODE]):
        results.append({
            'data':   code.data.decode('utf-8', errors='replace'),
            'bbox':   code.rect,
            'source': 'pyzbar_full',
            'polygon': [(p.x, p.y) for p in code.polygon],
        })
    
    # Pass 2: zxing-cpp (different algorithm — catches codes pyzbar misses)
    try:
        zx_codes = read_barcodes(
            gray,
            formats=BarcodeFormat.QRCode | BarcodeFormat.MicroQRCode
        )
        for code in zx_codes:
            url = code.text
            # Check for duplicates
            if not any(r['data'] == url for r in results):
                results.append({
                    'data':   url,
                    'source': 'zxingcpp_full',
                    'bbox':   None,
                })
    except Exception:
        pass
    
    # Pass 3: Multi-scale crop — extract sub-regions and decode
    h, w = gray.shape
    for scale in [0.5, 0.6, 0.7, 0.8]:
        margin_h = int(h * (1 - scale) / 2)
        margin_w = int(w * (1 - scale) / 2)
        crop = gray[margin_h:h-margin_h, margin_w:w-margin_w]
        if crop.size < 100:
            continue
        for code in decode(crop, symbols=[ZBarSymbol.QRCODE]):
            url = code.data.decode('utf-8', errors='replace')
            if not any(r['data'] == url for r in results):
                results.append({
                    'data':   url,
                    'source': f'pyzbar_crop_{scale}',
                    'bbox':   None,
                })
    
    # Pass 4: OpenCV QR Detector (built-in, different algorithm)
    detector = cv2.QRCodeDetector()
    try:
        data, bbox, _ = detector.detectAndDecode(img)
        if data and not any(r['data'] == data for r in results):
            results.append({'data': data, 'source': 'cv2_detector', 'bbox': bbox})
    except Exception:
        pass
    
    return results


def analyse_nested_qr(results: List[Dict]) -> Dict:
    """
    Classify a multi-decode result as nested QR attack.
    
    Nested QR signature: multiple decoded URLs where one is benign
    (Google, Microsoft, etc.) and another is unknown/suspicious.
    """
    KNOWN_BENIGN_DOMAINS = {
        'google.com', 'microsoft.com', 'apple.com', 'youtube.com',
        'github.com', 'amazon.com', 'linkedin.com', 'twitter.com',
    }
    
    urls      = [r['data'] for r in results if r['data'].startswith('http')]
    benign    = []
    suspicious = []
    
    for url in urls:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower().lstrip('www.')
        if any(domain == d or domain.endswith('.' + d) for d in KNOWN_BENIGN_DOMAINS):
            benign.append(url)
        else:
            suspicious.append(url)
    
    return {
        'is_nested':    len(results) > 1,
        'total_codes':  len(results),
        'benign_urls':  benign,
        'suspicious_urls': suspicious,
        'nested_attack': len(benign) > 0 and len(suspicious) > 0,
    }
```

---

### 2.3 ASCII/HTML QR Codes

A third evasion class — QR codes constructed from HTML/CSS text characters rather than image pixels. These are invisible to image scanners.

```python
def detect_ascii_qr_in_html(html_content: str) -> List[str]:
    """
    Detect QR codes constructed from HTML elements (table cells, divs, spans)
    styled to render as black/white squares.
    
    Pattern: Dense grid of <td> or <div> elements with inline background-color.
    """
    from bs4 import BeautifulSoup
    import re
    
    soup  = BeautifulSoup(html_content, 'html.parser')
    found = []
    
    # Pattern 1: Table-based QR (many <td> with bg color)
    for table in soup.find_all('table'):
        rows = table.find_all('tr')
        if len(rows) < 21:  # Minimum version 1 QR = 21×21
            continue
        # Check if each row has roughly equal cells with color attributes
        cell_counts = [len(row.find_all('td')) for row in rows]
        if len(set(cell_counts)) == 1 and cell_counts[0] >= 21:
            # Looks like a QR grid — extract colour pattern
            grid = []
            for row in rows:
                row_vals = []
                for td in row.find_all('td'):
                    style = td.get('style', '') + td.get('bgcolor', '')
                    is_dark = ('000' in style or 'black' in style.lower()
                               or '#000' in style or 'rgb(0,0,0)' in style)
                    row_vals.append(1 if is_dark else 0)
                grid.append(row_vals)
            if grid:
                # Convert to image and attempt decode
                grid_np = np.array(grid, dtype=np.uint8) * 255
                grid_img = cv2.resize(grid_np, (len(grid[0])*3, len(grid)*3),
                                      interpolation=cv2.INTER_NEAREST)
                codes = decode(grid_img, symbols=[ZBarSymbol.QRCODE])
                for code in codes:
                    found.append(code.data.decode('utf-8', errors='replace'))
    
    return found
```

---

### 2.4 Detection Pipeline for All Three Variants

```
QuishGuard Evasion-Aware Detection Pipeline
─────────────────────────────────────────────────────────────────────────────

INPUT: Email / PDF / attachment bytes
       ↓
STAGE 1: RENDER (catch ASCII/HTML QR codes)
  • Render email HTML with headless browser (Playwright/Pyppeteer)
  • Capture full-page screenshot at 2× DPI
  • Also render at mobile UA (see Section 5)
       ↓
STAGE 2: IMAGE EXTRACTION
  • Extract all image attachments
  • Extract all images from rendered page
  • For PDFs: extract via PyMuPDF (see Section 3)
       ↓
STAGE 3: QR DETECTION & RECONSTRUCTION
  a) Run pyzbar + zxingcpp + cv2.QRCodeDetector on each image
  b) If N images > 1: attempt split QR reconstruction (Section 2.1)
  c) If N decoded URLs > 1 per image: run nested QR analysis (Section 2.2)
  d) If HTML structure detected: run ASCII QR detector (Section 2.3)
       ↓
STAGE 4: PER-CODE PROCESSING
  For each decoded URL (deduplicated):
    • Pixel feature extraction → XGBoost score
    • URL structural analysis (length, entropy, domain age, etc.)
    • Safe decode + VT lookup (see Section 4)
    • Mobile vs desktop content comparison (see Section 5)
       ↓
STAGE 5: FUSION SCORING
  risk_score = max(
    xgboost_pixel_score,        # from Section 1
    url_reputation_score,       # from VirusTotal
    mobile_diff_score,          # from Section 5
    nested_attack_flag * 0.9,   # automatic high risk if nested
  )
       ↓
OUTPUT: {risk: 0.0–1.0, verdict, evidence_list, decoded_urls}
```

---

## SECTION 3: PDF QR Extraction

### 3.1 How QR Codes Appear in PDFs

QR codes in malicious PDFs occur in three distinct forms, each requiring a different extraction approach:

| Type | PDF Representation | Example | Extraction Method |
|------|-------------------|---------|-------------------|
| **Embedded raster** | XObject image (`/Subtype /Image`) — PNG, JPEG, TIFF | Standard QR in DocuSign lure | `page.get_images()` — extract at native resolution |
| **Vector drawn** | PDF content stream drawing commands (line, fill ops) | Split QR in content stream | Render page → rasterise |
| **Split across 2 objects** | Two separate XObject images positioned adjacently | Gabagool split technique | Extract both images, attempt reconstruction |

Analysis reveals the QR code is not a single raster image but is instead partitioned into two image objects within the PDF file. By exploiting advanced evasion techniques—splitting the QR code into two separate images, using non-standard color palettes, and drawing the code directly via PDF content streams—attackers are able to bypass traditional antivirus and PDF-scanning defenses.

### 3.2 Library Comparison

| Library | Speed | Embedded Image Extraction | Rasterised Page | Split QR | Content-Stream QR | Notes |
|---------|-------|--------------------------|-----------------|----------|------------------|-------|
| **PyMuPDF** | ★★★★★ | ★★★★★ — native `page.get_images()`, lossless | ★★★★★ — `page.get_pixmap(dpi=300)` | ★★★★★ — returns multiple image objects | ★★★★★ — full page render catches it | **Best overall.** 0.1s avg page. AGPL/commercial |
| **pdf2image** | ★★★☆☆ | ✗ — page rasterise only | ★★★★★ — Poppler rendering, pixel-perfect | ★★★☆☆ — only if both halves on same page | ★★★★★ — renders content stream accurately | 10–12× slower than PyMuPDF. Simple API |
| **pdfplumber** | ★★★☆☆ | ★★☆☆☆ — can access images but not optimized for it | ★★☆☆☆ — delegates to pdfminer | ★☆☆☆☆ | ★★☆☆☆ | Built on pdfminer. Excellent for text/table extraction — not optimal for QR image extraction |
| **pypdf (pypdf2)** | ★★☆☆☆ | ★★☆☆☆ — basic `/Resources /XObject` access | ✗ — pure Python, no renderer | ✗ | ✗ | PyPDF2 **deprecated**. Use pypdf. 10–20× slower than PyMuPDF for text; no page render |

**Critical note on pypdf2:** The Python PDF ecosystem benchmark (py-pdf/benchmarks) shows PyMuPDF at 0.1s average vs pypdf at 10–20× slower for text extraction. For image extraction from PDFs, pypdf has no rendering capability — it can only access pre-embedded image XObjects, not content-stream-drawn QR codes. **Do not use pypdf2 (deprecated) or pypdf for QR extraction in a production pipeline.**

---

### 3.3 Recommended Pipeline

```python
"""
QuishGuard PDF QR Extraction Pipeline
Primary: PyMuPDF for embedded images + page rendering
Fallback: pdf2image for pages where PyMuPDF rendering diverges
"""

import fitz       # PyMuPDF
import io
import numpy as np
import cv2
from pathlib import Path
from typing import List, Tuple
from pyzbar.pyzbar import decode, ZBarSymbol
from pdf2image import convert_from_bytes


def extract_qr_from_pdf(pdf_path: str, dpi: int = 300) -> List[dict]:
    """
    Comprehensive QR extraction from PDF.
    Handles: embedded images, vector-drawn, split QR, non-standard colours.
    
    Args:
        pdf_path: path to PDF file
        dpi: rendering resolution (300 = sufficient for v13 69×69 QR)
    
    Returns:
        List of dicts with keys: decoded_url, source_img, page_num, method
    """
    results        = []
    all_qr_images  = []  # all extracted images for split QR reconstruction
    
    doc = fitz.open(pdf_path)
    
    for page_num, page in enumerate(doc):
        
        # ── Method 1: Extract embedded image XObjects ─────────────────────────
        image_list = page.get_images(full=True)
        
        for img_idx, img_info in enumerate(image_list):
            xref = img_info[0]
            try:
                base_image = doc.extract_image(xref)
                img_bytes  = base_image["image"]
                img_np     = cv2.imdecode(
                    np.frombuffer(img_bytes, np.uint8),
                    cv2.IMREAD_COLOR
                )
                if img_np is None:
                    continue
                
                all_qr_images.append(img_np)
                
                # Handle non-standard colour QR codes (inverted, coloured)
                for variant in _colour_variants(img_np):
                    codes = decode(variant, symbols=[ZBarSymbol.QRCODE])
                    for code in codes:
                        url = code.data.decode('utf-8', errors='replace')
                        results.append({
                            'decoded_url': url,
                            'source_img':  variant,
                            'page_num':    page_num,
                            'method':      f'embedded_image_p{page_num}_i{img_idx}',
                        })
                
            except Exception as e:
                continue
        
        # ── Method 2: Full page render (catches vector-drawn / content-stream QR)
        try:
            mat = fitz.Matrix(dpi / 72, dpi / 72)
            pix = page.get_pixmap(matrix=mat, colorspace=fitz.csGRAY)
            page_img = np.frombuffer(pix.samples, dtype=np.uint8)
            page_img = page_img.reshape(pix.height, pix.width)
            
            # Scan full rendered page
            page_bgr = cv2.cvtColor(page_img, cv2.COLOR_GRAY2BGR)
            all_qr_images.append(page_bgr)
            
            for variant in _colour_variants(page_bgr):
                codes = decode(variant, symbols=[ZBarSymbol.QRCODE])
                for code in codes:
                    url = code.data.decode('utf-8', errors='replace')
                    if not any(r['decoded_url'] == url for r in results):
                        results.append({
                            'decoded_url': url,
                            'source_img':  page_bgr,
                            'page_num':    page_num,
                            'method':      f'page_render_p{page_num}',
                        })
            
            # ── Method 3: Sliding window QR scan (catches partial/small QR) ──
            h, w = page_img.shape
            for scale in [0.3, 0.5, 0.7]:
                wh = int(w * scale)
                hh = int(h * scale)
                for r in range(0, h - hh + 1, hh // 2):
                    for c in range(0, w - ww + 1, ww // 2):
                        crop = page_bgr[r:r+hh, c:c+ww]
                        codes = decode(crop, symbols=[ZBarSymbol.QRCODE])
                        for code in codes:
                            url = code.data.decode('utf-8', errors='replace')
                            if not any(r2['decoded_url'] == url for r2 in results):
                                results.append({
                                    'decoded_url': url,
                                    'source_img':  crop,
                                    'page_num':    page_num,
                                    'method':      f'sliding_window_p{page_num}',
                                })
        
        except Exception:
            # ── Method 4: Fallback to pdf2image for this page ──────────────────
            try:
                with open(pdf_path, 'rb') as f:
                    pdf_bytes = f.read()
                pil_pages = convert_from_bytes(
                    pdf_bytes, dpi=dpi,
                    first_page=page_num + 1, last_page=page_num + 1
                )
                for pil_img in pil_pages:
                    img_np = np.array(pil_img)
                    codes  = decode(img_np, symbols=[ZBarSymbol.QRCODE])
                    for code in codes:
                        url = code.data.decode('utf-8', errors='replace')
                        if not any(r['decoded_url'] == url for r in results):
                            results.append({
                                'decoded_url': url,
                                'source_img':  img_np,
                                'page_num':    page_num,
                                'method':      f'pdf2image_fallback_p{page_num}',
                            })
            except Exception:
                pass
    
    doc.close()
    
    # ── Method 5: Attempt split QR reconstruction across all collected images ──
    if len(all_qr_images) >= 2:
        reconstructed = detect_and_reconstruct_split_qr(all_qr_images)
        for rec_img in reconstructed:
            codes = decode(rec_img, symbols=[ZBarSymbol.QRCODE])
            for code in codes:
                url = code.data.decode('utf-8', errors='replace')
                if not any(r['decoded_url'] == url for r in results):
                    results.append({
                        'decoded_url': url,
                        'source_img':  rec_img,
                        'page_num':    -1,
                        'method':      'split_qr_reconstruction',
                    })
    
    return results


def _colour_variants(img: np.ndarray) -> List[np.ndarray]:
    """
    Generate colour-normalised variants to handle non-standard QR colours.
    Attackers use non-black/white palettes to confuse optical recognition.
    """
    variants = [img]
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY) if img.ndim == 3 else img
    
    # Standard binary
    _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_OTSU)
    variants.append(binary)
    
    # Inverted (some QR codes are white-on-dark)
    variants.append(cv2.bitwise_not(binary))
    
    # Adaptive threshold (handles non-uniform illumination in printed/scanned QR)
    adaptive = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 11, 2
    )
    variants.append(adaptive)
    
    # Contrast-enhanced
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    _, bin_enh = cv2.threshold(enhanced, 0, 255, cv2.THRESH_OTSU)
    variants.append(bin_enh)
    
    return variants
```

### 3.4 Handling Split QR Across Two PDF Image Objects

```python
def extract_positional_images(pdf_path: str, page_num: int = 0) -> List[dict]:
    """
    Extract images WITH their position on the page — required to detect
    and reconstruct split QR codes that span adjacent image objects.
    
    Returns images sorted by vertical position (top to bottom).
    """
    doc     = fitz.open(pdf_path)
    page    = doc[page_num]
    result  = []
    
    # get_image_rects returns (xref, rect) pairs
    for img_info in page.get_images(full=True):
        xref = img_info[0]
        try:
            base_image = doc.extract_image(xref)
            img_bytes  = base_image["image"]
            img_np     = cv2.imdecode(
                np.frombuffer(img_bytes, np.uint8), cv2.IMREAD_COLOR
            )
            
            # Get bounding rect on page
            rects = page.get_image_rects(xref)
            for rect in rects:
                result.append({
                    'xref':  xref,
                    'image': img_np,
                    'rect':  rect,   # fitz.Rect: x0, y0, x1, y1
                    'y_top': rect.y0,
                    'y_bot': rect.y1,
                    'x_left':rect.x0,
                    'width': rect.x1 - rect.x0,
                    'height':rect.y1 - rect.y0,
                })
        except Exception:
            continue
    
    doc.close()
    
    # Sort by vertical position
    result.sort(key=lambda x: x['y_top'])
    return result


def reconstruct_split_qr_from_positions(images_with_pos: List[dict]) -> List[np.ndarray]:
    """
    Use page position data to precisely reconstruct split QR codes.
    Adjacent images (within 5 page units) with matching widths = split QR.
    """
    reconstructed = []
    
    for i in range(len(images_with_pos) - 1):
        a = images_with_pos[i]
        b = images_with_pos[i + 1]
        
        # Check adjacency: bottom of A ≈ top of B (within 5 pt tolerance)
        is_adjacent_v = abs(a['y_bot'] - b['y_top']) < 5
        is_same_width = abs(a['width'] - b['width']) < 5
        
        if is_adjacent_v and is_same_width:
            if a['image'] is None or b['image'] is None:
                continue
            
            # Scale images to same pixel width before stacking
            target_w = max(a['image'].shape[1], b['image'].shape[1])
            img_a = cv2.resize(a['image'], (target_w, a['image'].shape[0]))
            img_b = cv2.resize(b['image'], (target_w, b['image'].shape[0]))
            
            combined = np.vstack([img_a, img_b])
            reconstructed.append(combined)
    
    return reconstructed
```

---

## SECTION 4: Safe Decoding — Docker Sandbox

### 4.1 The Threat Model

**What leaking the scanner IP enables for the attacker:**
- **IP-based geofencing:** phishing page shows benign content to scanner IPs (AWS/Azure/GCP ranges are blocklisted by most PhaaS kits)
- **IP fingerprinting:** attacker knows their campaign is under automated analysis → deactivate the URL
- **Counter-intelligence:** some phishing kits log all visitors; scanner IP attribution reveals your SOC's network range
- **Payload delivery gating:** real payloads only served to first visit from a given IP

**Solution architecture:** the QR code is decoded purely from bytes (no network required for pyzbar/zxingcpp). The decoded URL string is passed — without ever fetching it — to a sandboxed submission queue. Only the VT API submitter container has outbound internet access, and it submits the URL string to VirusTotal (not fetching the URL itself from your network).

---

### 4.2 Docker Compose Architecture

```yaml
# docker-compose.yml — QuishGuard Safe Decode Pipeline
# 
# Network topology:
#   [inbox] → [scanner] → [redis] → [vt-submitter] → [VirusTotal API]
#                ↑                        ↑
#          NO internet              ONE outbound route
#          NO DNS                   Only: virustotal.com

version: "3.9"

networks:
  # Internal bus — no internet
  internal:
    driver: bridge
    internal: true   # ← KEY: bridge with internal=true has NO external routing
  
  # Restricted egress — only for VT submitter
  vt_egress:
    driver: bridge
    internal: false  # Has internet but firewall rules restrict to VT only

services:

  # ── Redis message queue ───────────────────────────────────────────────────
  redis:
    image: redis:7-alpine
    networks: [internal]
    restart: unless-stopped
    command: redis-server --requirepass "${REDIS_PASSWORD}"
    volumes:
      - redis_data:/data

  # ── PDF/Image Scanner — NO internet access ────────────────────────────────
  scanner:
    build:
      context: ./scanner
      dockerfile: Dockerfile.scanner
    networks:
      - internal          # Can push to Redis only — no internet
    environment:
      REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379"
      QUEUE_IN:  "qg:raw_attachments"
      QUEUE_OUT: "qg:decoded_urls"
    volumes:
      - /tmp/qg_inbox:/inbox:ro   # Read-only: only input files
    restart: unless-stopped
    # Critical security constraints
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:size=256m   # Processing only in tmpfs
    user: "10000:10000"  # Non-root

  # ── VirusTotal Submitter — restricted egress only ─────────────────────────
  vt-submitter:
    build:
      context: ./vt_submitter
      dockerfile: Dockerfile.vt
    networks:
      - internal    # Read from Redis
      - vt_egress   # Submit to VT API
    environment:
      REDIS_URL:   "redis://:${REDIS_PASSWORD}@redis:6379"
      QUEUE_IN:    "qg:decoded_urls"
      QUEUE_OUT:   "qg:vt_results"
      VT_API_KEY:  "${VT_API_KEY}"
      VT_RATE_SEC: "4"  # Public API: 4 requests/minute
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]

  # ── Results Store ─────────────────────────────────────────────────────────
  results-api:
    build:
      context: ./results_api
    networks: [internal]
    environment:
      REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379"
    ports:
      - "127.0.0.1:8080:8080"   # Expose only to localhost
    restart: unless-stopped

volumes:
  redis_data:
```

**iptables rule to restrict vt_egress to VirusTotal API only** (add to host):

```bash
# Get VirusTotal IP ranges
VT_IPS=$(dig +short www.virustotal.com | tr '\n' ' ')

# Allow only VT API endpoints from the vt_egress bridge
BRIDGE_IF=$(docker network inspect quishguard_vt_egress \
            --format '{{.Options.com.docker.network.bridge.name}}')

# Block all egress from this bridge by default
iptables -I DOCKER-USER -i $BRIDGE_IF -j DROP

# Allow VT API (443 only)
for ip in $VT_IPS; do
    iptables -I DOCKER-USER -i $BRIDGE_IF \
        -d $ip -p tcp --dport 443 -j ACCEPT
done

# Allow DNS (for VT hostname resolution)
iptables -I DOCKER-USER -i $BRIDGE_IF -p udp --dport 53 -j ACCEPT
```

---

### 4.3 Container Definitions

```dockerfile
# scanner/Dockerfile.scanner
FROM python:3.12-slim

# Install QR decoding deps (no network capability, no browser)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 libzbar-dev zbar-tools \
    libgl1-mesa-glx libglib2.0-0 \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Install PyMuPDF, pyzbar, zxing-cpp, OpenCV (headless)
COPY requirements.scanner.txt .
RUN pip install --no-cache-dir -r requirements.scanner.txt

COPY scanner_service.py /app/
WORKDIR /app

# Create non-root user
RUN useradd -u 10000 -m -s /bin/false scanner
USER scanner

CMD ["python", "-u", "scanner_service.py"]
```

```dockerfile
# vt_submitter/Dockerfile.vt
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.vt.txt .
RUN pip install --no-cache-dir -r requirements.vt.txt

COPY vt_service.py /app/
WORKDIR /app

RUN useradd -u 10001 -m -s /bin/false vt_submitter
USER vt_submitter

CMD ["python", "-u", "vt_service.py"]
```

---

### 4.4 The Scanner Service (No Network Access)

```python
# scanner/scanner_service.py
"""
QuishGuard Scanner — runs in isolated container with no internet access.
Receives raw PDF/image bytes, decodes QR, pushes decoded URL strings to queue.
NEVER fetches decoded URLs — URL is treated as untrusted string data only.
"""

import os, json, time, hashlib, tempfile
import numpy as np
import redis
from pathlib import Path

REDIS_URL  = os.environ["REDIS_URL"]
QUEUE_IN   = os.environ.get("QUEUE_IN",  "qg:raw_attachments")
QUEUE_OUT  = os.environ.get("QUEUE_OUT", "qg:decoded_urls")

r = redis.from_url(REDIS_URL, decode_responses=False)


def process_attachment(payload: dict) -> list:
    """
    Process a single attachment payload.
    Returns list of decoded URL dicts.
    """
    from scanner_pipeline import extract_qr_from_pdf, decode_all_qr_codes, preprocess_qr, extract_region_features
    import cv2
    
    file_bytes  = bytes.fromhex(payload["hex_bytes"])
    file_type   = payload.get("content_type", "application/pdf")
    email_id    = payload["email_id"]
    sha256      = hashlib.sha256(file_bytes).hexdigest()
    
    decoded_urls = []
    
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(file_bytes)
        tmp_path = f.name
    
    try:
        if "pdf" in file_type.lower():
            qr_results = extract_qr_from_pdf(tmp_path)
        else:
            # Image attachment
            img_np   = cv2.imdecode(np.frombuffer(file_bytes, np.uint8), cv2.IMREAD_COLOR)
            codes    = decode_all_qr_codes(img_np)
            qr_results = codes
        
        for qr in qr_results:
            url   = qr.get("decoded_url") or qr.get("data", "")
            if not url:
                continue
            
            # Extract pixel features — purely local, no network
            src_img = qr.get("source_img")
            pixel_features = None
            if src_img is not None:
                try:
                    proc = preprocess_qr(src_img)
                    feats = extract_region_features(proc)
                    pixel_features = feats.to_feature_vector().tolist()
                except Exception:
                    pass
            
            decoded_urls.append({
                "email_id":        email_id,
                "source_sha256":   sha256,
                "decoded_url":     url,   # Untrusted string — never fetched
                "pixel_features":  pixel_features,
                "extraction_method": qr.get("method", "unknown"),
                "page_num":        qr.get("page_num", -1),
            })
    
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    
    return decoded_urls


def main():
    print("[Scanner] Ready. Waiting for attachments on", QUEUE_IN)
    while True:
        try:
            _, raw = r.blpop(QUEUE_IN, timeout=30)
            if raw is None:
                continue
            
            payload  = json.loads(raw)
            results  = process_attachment(payload)
            
            for res in results:
                r.rpush(QUEUE_OUT, json.dumps(res))
                print(f"[Scanner] Decoded: {res['decoded_url'][:80]}")
        
        except redis.ConnectionError:
            time.sleep(5)
        except Exception as e:
            print(f"[Scanner] Error: {e}")


if __name__ == "__main__":
    main()
```

---

### 4.5 The VT Submitter Service

```python
# vt_submitter/vt_service.py
"""
QuishGuard VT Submitter — submits decoded URL STRINGS to VirusTotal API.
This container has restricted internet access (VT API only).
It NEVER visits the phishing URL — it passes the URL as a string to VT.
"""

import os, json, time, requests
import redis

REDIS_URL  = os.environ["REDIS_URL"]
QUEUE_IN   = os.environ.get("QUEUE_IN",  "qg:decoded_urls")
QUEUE_OUT  = os.environ.get("QUEUE_OUT", "qg:vt_results")
VT_API_KEY = os.environ["VT_API_KEY"]
RATE_SEC   = float(os.environ.get("VT_RATE_SEC", "15"))  # public: 4/min

VT_URL_SCAN    = "https://www.virustotal.com/api/v3/urls"
VT_URL_REPORT  = "https://www.virustotal.com/api/v3/analyses/{id}"

r = redis.from_url(REDIS_URL, decode_responses=False)


def submit_url_to_vt(url: str) -> dict:
    """
    Submit a URL to VirusTotal for analysis.
    Does NOT fetch the URL — passes it as a string to VT's scanning infrastructure.
    VT's sandboxed crawlers visit the URL; your IP is never sent to the phishing page.
    """
    import base64
    
    headers = {
        "accept":       "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey":     VT_API_KEY,
    }
    
    # Step 1: Submit URL for scanning
    resp = requests.post(
        VT_URL_SCAN,
        headers=headers,
        data={"url": url},
        timeout=30,
        # Only connect to virustotal.com — verified by iptables on host
    )
    resp.raise_for_status()
    analysis_id = resp.json()["data"]["id"]
    
    # Step 2: Poll for results (VT queues analysis)
    for attempt in range(8):
        time.sleep(15)
        report_resp = requests.get(
            VT_URL_REPORT.format(id=analysis_id),
            headers={"accept": "application/json", "x-apikey": VT_API_KEY},
            timeout=30,
        )
        report = report_resp.json()
        
        status = report.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            stats  = report["data"]["attributes"]["stats"]
            return {
                "url":           url,
                "vt_analysis_id": analysis_id,
                "malicious":     stats.get("malicious", 0),
                "suspicious":    stats.get("suspicious", 0),
                "harmless":      stats.get("harmless", 0),
                "undetected":    stats.get("undetected", 0),
                "vt_verdict":    "malicious" if stats.get("malicious", 0) >= 3
                                 else "suspicious" if stats.get("suspicious", 0) >= 2
                                 else "clean",
            }
    
    return {"url": url, "vt_verdict": "timeout", "vt_analysis_id": analysis_id}


def main():
    print("[VT Submitter] Ready. Processing", QUEUE_IN)
    last_call = 0.0
    
    while True:
        try:
            _, raw = r.blpop(QUEUE_IN, timeout=30)
            if raw is None:
                continue
            
            payload = json.loads(raw)
            url     = payload.get("decoded_url", "")
            
            if not url:
                continue
            
            # Rate limiting: VT public API = 4 req/min = 15s between calls
            elapsed = time.time() - last_call
            if elapsed < RATE_SEC:
                time.sleep(RATE_SEC - elapsed)
            
            vt_result  = submit_url_to_vt(url)
            last_call  = time.time()
            
            # Merge VT result with scanner payload
            merged = {**payload, **vt_result}
            r.rpush(QUEUE_OUT, json.dumps(merged))
            
            print(f"[VT] {url[:60]} → {vt_result['vt_verdict']} "
                  f"({vt_result.get('malicious', 0)} malicious)")
        
        except redis.ConnectionError:
            time.sleep(5)
        except requests.RequestException as e:
            print(f"[VT] Request error: {e}")
            time.sleep(30)
        except Exception as e:
            print(f"[VT] Error: {e}")


if __name__ == "__main__":
    main()
```

---

### 4.6 Network Isolation Verification

```bash
#!/bin/bash
# Verify scanner container has no internet access

CONTAINER="quishguard_scanner_1"

echo "=== Testing scanner network isolation ==="

# 1. Should fail: direct internet access
docker exec $CONTAINER python -c "
import urllib.request
try:
    urllib.request.urlopen('http://google.com', timeout=5)
    print('FAIL: Scanner can reach internet!')
except Exception as e:
    print(f'PASS: {type(e).__name__} — internet is blocked')
"

# 2. Should fail: DNS resolution
docker exec $CONTAINER python -c "
import socket
try:
    ip = socket.gethostbyname('example.com')
    print(f'FAIL: DNS resolved to {ip}')
except socket.gaierror:
    print('PASS: DNS is blocked')
"

# 3. Should succeed: Redis connection
docker exec $CONTAINER python -c "
import redis
r = redis.from_url('redis://:password@redis:6379')
r.ping()
print('PASS: Redis internal network OK')
"

echo "=== VT submitter egress test ==="
VT_CONTAINER="quishguard_vt-submitter_1"

# Should succeed: VT API
docker exec $VT_CONTAINER python -c "
import requests
r = requests.get('https://www.virustotal.com/api/v3/', 
                 headers={'x-apikey': 'test'}, timeout=10)
print(f'PASS: VT API reachable — status {r.status_code}')
"

# Should fail: Other internet
docker exec $VT_CONTAINER python -c "
import requests
try:
    r = requests.get('http://google.com', timeout=5)
    print(f'FAIL: Non-VT internet reachable')
except Exception as e:
    print(f'PASS: Non-VT internet blocked — {type(e).__name__}')
"
```

---

## SECTION 5: Mobile Context Detection

### 5.1 Why QR Phishing Is Mobile-Specific

After scanning, victims are routed through attacker-controlled redirectors that collect device and identity attributes such as user-agent, OS, IP address, locale, and screen size in order to selectively present mobile-optimized credential harvesting pages impersonating trusted services.

QR phishing is architecturally mobile-first for several reasons:
- QR codes are physically scanned by phone cameras — the initial request always has a mobile UA
- PhaaS kits (Tycoon 2FA, Gabagool) implement explicit UA-based routing in their PHP/Node backend
- Mobile devices are outside corporate EDR and network inspection boundaries
- Phishing pages that look authentic on mobile (small screen, no URL bar in apps) appear obviously fake on desktop
- QR code shorteners convert a static image into a dynamic endpoint. Consequently, the attacker can change the redirect destination at will.

### 5.2 UA-Switching Redirect Chains

```
Mobile scanner visits URL:
  → Redirector (reads User-Agent)
  → If mobile: → Phishing page (login form, brand imitation)
  → If desktop/bot: → Decoy page (Google, brand homepage, 404)

Common redirect chain (Unit 42, 2025):
  QR URL → QR shortener → Cloudflare Turnstile → final phishing page

Bot detection in phishing kits:
  1. User-Agent check: Python/requests, wget, curl → blocked
  2. IP ASN check: AWS/Azure/GCP IP ranges → served benign decoy
  3. Cloudflare Turnstile: CAPTCHA that passes humans, blocks simple crawlers
  4. Headless browser detection: missing canvas API, WebGL, AudioContext
  5. Screen resolution: if width > 1920 or < 320 → suspicious
  6. JavaScript execution required: pages that are blank without JS
```

---

### 5.3 Complete Mobile vs Desktop Comparison Code

```python
"""
QuishGuard Mobile Context Detector
Fetches the decoded URL with both mobile and desktop UAs and compares responses.
All fetches go through a Tor proxy — never from your real IP.
"""

import asyncio
import difflib
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional
from playwright.async_api import async_playwright, Browser, BrowserContext


# User-Agent strings matching real device signatures
UA_MOBILE_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4.1 Mobile/15E148 Safari/604.1"
)
UA_MOBILE_ANDROID = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Mobile Safari/537.36"
)
UA_DESKTOP = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Viewport configurations
VIEWPORT_MOBILE  = {"width": 390,  "height": 844}   # iPhone 15
VIEWPORT_DESKTOP = {"width": 1440, "height": 900}


@dataclass
class UAFetchResult:
    user_agent:      str
    final_url:       str           # After all redirects
    status_code:     int
    redirect_chain:  list
    html_content:    str
    page_title:      str
    form_fields:     list          # input/select/textarea elements found
    has_password_field: bool
    has_login_form:  bool
    has_mfa_field:   bool
    iframe_sources:  list
    external_scripts: list
    content_hash:    str
    screenshot_b64:  Optional[str] = None


@dataclass
class MobileContextAnalysis:
    url:                str
    mobile_result:      Optional[UAFetchResult]
    desktop_result:     Optional[UAFetchResult]
    
    # Comparison signals
    different_final_urls:    bool = False
    different_redirect_chains: bool = False
    mobile_has_login:        bool = False
    desktop_has_login:       bool = False
    mobile_only_login:       bool = False  # Login ONLY on mobile = strong signal
    content_similarity:      float = 1.0  # 1.0 = identical, 0.0 = completely different
    title_differs:           bool = False
    
    # Risk signals
    risk_score:              float = 0.0
    risk_signals:            list = field(default_factory=list)


async def fetch_with_ua(
    url: str,
    user_agent: str,
    viewport: dict,
    browser: Browser,
    timeout_ms: int = 20000,
) -> UAFetchResult:
    """
    Fetch a URL with a specific user-agent using a headless browser.
    Passes through Tor proxy (configured in playwright context).
    """
    redirect_chain = []
    
    context: BrowserContext = await browser.new_context(
        user_agent=user_agent,
        viewport=viewport,
        # Route all traffic through Tor SOCKS5 proxy
        proxy={"server": "socks5://tor-proxy:9050"},
        # Emulate mobile device capabilities for mobile UA
        is_mobile=(viewport["width"] < 800),
        has_touch=(viewport["width"] < 800),
        locale="en-US",
        timezone_id="America/New_York",
        permissions=["geolocation"],
        extra_http_headers={
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    
    page = await context.new_page()
    
    # Track redirects
    page.on("response", lambda r: redirect_chain.append({
        "url":    r.url,
        "status": r.status,
    }) if r.request.is_navigation_request() else None)
    
    try:
        response = await page.goto(
            url,
            timeout=timeout_ms,
            wait_until="networkidle",
        )
        
        # Extract page content
        html    = await page.content()
        title   = await page.title()
        final   = page.url
        status  = response.status if response else 0
        
        # Find form elements
        forms       = await page.query_selector_all("input, select, textarea")
        form_fields = []
        has_pwd     = False
        has_mfa     = False
        
        for elem in forms:
            field_type  = await elem.get_attribute("type")   or ""
            field_name  = await elem.get_attribute("name")   or ""
            field_id    = await elem.get_attribute("id")     or ""
            placeholder = await elem.get_attribute("placeholder") or ""
            
            form_fields.append({
                "type":        field_type,
                "name":        field_name,
                "id":          field_id,
                "placeholder": placeholder,
            })
            
            if field_type.lower() == "password":
                has_pwd = True
            if any(mfa_kw in (field_name + field_id + placeholder).lower()
                   for mfa_kw in ["otp", "mfa", "totp", "code", "token",
                                   "2fa", "verify", "authenticat"]):
                has_mfa = True
        
        has_login = has_pwd or any(
            kw in html.lower()
            for kw in ["sign in", "log in", "login", "password", "username",
                       "email", "credential", "authenticate"]
        )
        
        # Iframes (common in AiTM proxy pages)
        iframes = await page.query_selector_all("iframe")
        iframe_srcs = []
        for iframe in iframes:
            src = await iframe.get_attribute("src") or ""
            if src:
                iframe_srcs.append(src)
        
        # External scripts (fingerprinting scripts)
        scripts = await page.query_selector_all("script[src]")
        ext_scripts = []
        for s in scripts:
            src = await s.get_attribute("src") or ""
            if src and not src.startswith("/"):
                ext_scripts.append(src)
        
        content_hash = hashlib.sha256(html.encode()).hexdigest()
        
        return UAFetchResult(
            user_agent         = user_agent,
            final_url          = final,
            status_code        = status,
            redirect_chain     = redirect_chain,
            html_content       = html,
            page_title         = title,
            form_fields        = form_fields,
            has_password_field = has_pwd,
            has_login_form     = has_login,
            has_mfa_field      = has_mfa,
            iframe_sources     = iframe_srcs,
            external_scripts   = ext_scripts,
            content_hash       = content_hash,
        )
    
    except Exception as e:
        return UAFetchResult(
            user_agent="", final_url=url, status_code=0,
            redirect_chain=redirect_chain, html_content="",
            page_title="", form_fields=[], has_password_field=False,
            has_login_form=False, has_mfa_field=False,
            iframe_sources=[], external_scripts=[], content_hash="",
        )
    
    finally:
        await context.close()


def compute_content_similarity(html_a: str, html_b: str) -> float:
    """Compute similarity ratio between two HTML strings."""
    if not html_a or not html_b:
        return 0.0
    matcher = difflib.SequenceMatcher(
        None,
        html_a[:50000],   # Cap to avoid massive diff on large pages
        html_b[:50000],
        autojunk=False
    )
    return matcher.ratio()


async def analyse_mobile_context(url: str) -> MobileContextAnalysis:
    """
    Full mobile context analysis: fetch with mobile + desktop UA, compare.
    """
    analysis = MobileContextAnalysis(url=url, mobile_result=None, desktop_result=None)
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=[
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",  # Hide Playwright detection
            "--disable-dev-shm-usage",
        ])
        
        # Fetch with both UAs concurrently
        mobile_task  = fetch_with_ua(url, UA_MOBILE_IPHONE,  VIEWPORT_MOBILE,  browser)
        desktop_task = fetch_with_ua(url, UA_DESKTOP,         VIEWPORT_DESKTOP, browser)
        
        mobile_result, desktop_result = await asyncio.gather(
            mobile_task, desktop_task, return_exceptions=True
        )
        
        await browser.close()
    
    if isinstance(mobile_result, Exception) or isinstance(desktop_result, Exception):
        analysis.risk_signals.append("fetch_error")
        analysis.risk_score = 0.5
        return analysis
    
    analysis.mobile_result  = mobile_result
    analysis.desktop_result = desktop_result
    
    # ── Compute comparison signals ─────────────────────────────────────────
    analysis.different_final_urls = (
        mobile_result.final_url != desktop_result.final_url
    )
    
    analysis.different_redirect_chains = (
        [r["url"] for r in mobile_result.redirect_chain] !=
        [r["url"] for r in desktop_result.redirect_chain]
    )
    
    analysis.mobile_has_login  = mobile_result.has_login_form
    analysis.desktop_has_login = desktop_result.has_login_form
    analysis.mobile_only_login = (
        mobile_result.has_login_form and not desktop_result.has_login_form
    )
    
    analysis.content_similarity = compute_content_similarity(
        mobile_result.html_content,
        desktop_result.html_content,
    )
    
    analysis.title_differs = (
        mobile_result.page_title.strip() != desktop_result.page_title.strip()
        and mobile_result.page_title and desktop_result.page_title
    )
    
    # ── Risk scoring ───────────────────────────────────────────────────────
    risk = 0.0
    signals = []
    
    if analysis.mobile_only_login:
        risk += 0.6
        signals.append("mobile_only_login_form")      # Strongest signal
    
    if analysis.different_final_urls:
        risk += 0.4
        signals.append("different_final_url_by_ua")   # UA-based routing
    
    if analysis.different_redirect_chains:
        risk += 0.3
        signals.append("different_redirect_chain_by_ua")
    
    if analysis.content_similarity < 0.3:
        risk += 0.3
        signals.append(f"low_content_similarity_{analysis.content_similarity:.2f}")
    
    if mobile_result.has_password_field and not desktop_result.has_password_field:
        risk += 0.5
        signals.append("password_field_mobile_only")  # Credential harvesting
    
    if mobile_result.has_mfa_field:
        risk += 0.2
        signals.append("mfa_field_detected_mobile")   # AiTM pattern
    
    if analysis.title_differs:
        risk += 0.2
        signals.append("page_title_differs_by_ua")
    
    # Check for known PhaaS signatures in scripts
    phishing_script_indicators = [
        "tycoon", "evilginx", "modlishka", "muraena", "evilproxy",
        "turnstile", "cloudflare-bot", "fp.min.js",  # fingerprinting
    ]
    all_scripts = (
        mobile_result.external_scripts + desktop_result.external_scripts
    )
    for script in all_scripts:
        for indicator in phishing_script_indicators:
            if indicator in script.lower():
                risk += 0.3
                signals.append(f"phishing_script_indicator:{indicator}")
    
    analysis.risk_score   = min(risk, 1.0)
    analysis.risk_signals = signals
    
    return analysis


def mobile_context_risk_label(score: float) -> str:
    if score >= 0.7: return "HIGH — mobile-specific phishing page"
    if score >= 0.4: return "MEDIUM — UA-switching detected"
    return "LOW — consistent behaviour across user agents"
```

---

### 5.4 Cloudflare Turnstile and Anti-Bot Evasion

Another tactic involves attackers adopting Cloudflare Turnstile for user verification, enabling them to evade security crawlers and convincingly redirect targets to a login page.

Most PhaaS kits in 2025 use Turnstile to gate access to the actual phishing page. Simple `requests` or `urllib` fetches receive either a 403 or a benign decoy page. Playwright with proper fingerprint spoofing has much higher success passing Turnstile than raw HTTP clients.

```python
# Playwright stealth additions for anti-bot bypass

async def apply_stealth_patches(context: BrowserContext):
    """
    Apply stealth patches to make Playwright less detectable.
    Important: phishing pages actively fingerprint for headless browsers.
    """
    await context.add_init_script("""
        // Remove Playwright/CDP automation markers
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        
        // Spoof Chrome-specific APIs
        window.chrome = {
            runtime: {},
            loadTimes: function() {},
            csi: function() {},
            app: {},
        };
        
        // Fake plugins array (empty = headless browser)
        Object.defineProperty(navigator, 'plugins', {
            get: () => [
                {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
                {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
                {name: 'Native Client', filename: 'internal-nacl-plugin'},
            ]
        });
        
        // Fake screen properties to match mobile device
        if (window.innerWidth < 800) {
            Object.defineProperty(screen, 'width',  {get: () => 390});
            Object.defineProperty(screen, 'height', {get: () => 844});
        }
        
        // Add touch support for mobile emulation
        if (window.innerWidth < 800) {
            Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 5});
        }
    """)
```

---

## Complete Integration — QuishGuard Pipeline

```python
"""
QuishGuard — Complete Pipeline Integration
Runs locally for testing; production uses Docker Compose (Section 4).
"""

import asyncio
import json
from pathlib import Path


async def analyse_qr_attachment(
    attachment_path: str,
    vt_api_key: str,
    use_tor: bool = False,
) -> dict:
    """
    Full QuishGuard pipeline for a single attachment.
    For production use: push to Docker queue instead of running inline.
    """
    from scanner_pipeline import extract_qr_from_pdf, decode_all_qr_codes
    from scanner_pipeline import preprocess_qr, extract_region_features
    from vt_service import submit_url_to_vt
    import cv2
    import xgboost as xgb
    import pickle
    
    attachment = Path(attachment_path)
    results    = []
    
    # ── Step 1: Extract QR codes ───────────────────────────────────────────
    if attachment.suffix.lower() == ".pdf":
        qr_codes = extract_qr_from_pdf(str(attachment))
    else:
        img = cv2.imread(str(attachment))
        qr_codes = decode_all_qr_codes(img)
    
    if not qr_codes:
        return {"status": "no_qr_found", "attachment": str(attachment)}
    
    # ── Step 2: Pixel feature extraction + XGBoost scoring ─────────────────
    model = xgb.XGBClassifier()
    model.load_model("quishguard_xgboost.json")
    
    for qr in qr_codes:
        url       = qr.get("decoded_url") or qr.get("data", "")
        src_img   = qr.get("source_img")
        
        pixel_risk = 0.5
        if src_img is not None:
            try:
                proc     = preprocess_qr(src_img)
                flat     = proc.flatten().astype(float) / 255.0
                pixel_risk = float(model.predict_proba([flat])[0][1])
            except Exception:
                pass
        
        # ── Step 3: VirusTotal URL submission (string only, no fetch) ───────
        vt_result = {}
        if url and url.startswith("http") and vt_api_key:
            try:
                vt_result = submit_url_to_vt(url)
            except Exception as e:
                vt_result = {"error": str(e)}
        
        # ── Step 4: Mobile context analysis ─────────────────────────────────
        mobile_analysis = {}
        if url and url.startswith("http"):
            try:
                ma = await analyse_mobile_context(url)
                mobile_analysis = {
                    "mobile_risk_score": ma.risk_score,
                    "risk_signals":      ma.risk_signals,
                    "mobile_only_login": ma.mobile_only_login,
                    "content_similarity": ma.content_similarity,
                    "different_final_url": ma.different_final_urls,
                }
            except Exception as e:
                mobile_analysis = {"error": str(e)}
        
        # ── Step 5: Fusion score ─────────────────────────────────────────────
        vt_malicious = vt_result.get("malicious", 0)
        vt_score     = min(vt_malicious / 10.0, 1.0)
        mobile_score = mobile_analysis.get("mobile_risk_score", 0.0)
        
        fusion_score = max(pixel_risk, vt_score, mobile_score)
        
        # Auto-escalate for nested QR attacks
        if qr.get("method", "").startswith("nested"):
            fusion_score = max(fusion_score, 0.85)
        if qr.get("method", "").startswith("split"):
            fusion_score = max(fusion_score, 0.75)
        
        results.append({
            "decoded_url":     url,
            "extraction_method": qr.get("method", "unknown"),
            "pixel_risk":      round(pixel_risk, 4),
            "vt_risk":         round(vt_score, 4),
            "mobile_risk":     round(mobile_score, 4),
            "fusion_score":    round(fusion_score, 4),
            "verdict":         "MALICIOUS" if fusion_score >= 0.7
                               else "SUSPICIOUS" if fusion_score >= 0.4
                               else "BENIGN",
            "vt_detail":       vt_result,
            "mobile_detail":   mobile_analysis,
        })
    
    return {
        "attachment":  str(attachment),
        "qr_count":    len(results),
        "max_score":   max(r["fusion_score"] for r in results) if results else 0.0,
        "results":     results,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python quishguard.py <pdf_or_image> <vt_api_key>")
        sys.exit(1)
    
    result = asyncio.run(analyse_qr_attachment(sys.argv[1], sys.argv[2]))
    print(json.dumps(result, indent=2))
```

---

## Benchmark Targets and Next Steps

| Component | Current Baseline | QuishGuard Target |
|-----------|-----------------|------------------|
| Pixel XGBoost AUC | 0.9133 (fouadtrad, feature-selected) | 0.93+ with region features |
| PDF extraction recall | ~80% (embedded only) | 95%+ with content-stream rendering |
| Split QR detection | 0% (no existing tools) | 90%+ with reconstruction pipeline |
| Nested QR detection | 0% (scanners return first only) | 95%+ with multi-decoder pipeline |
| Mobile vs desktop detection | N/A | 85%+ mobile-specific phishing pages |
| Safe decode IP leakage | Not applicable | Zero IP exposure via Tor + queue architecture |
| Pipeline throughput | N/A | 50+ attachments/minute with Docker scaling |

**Sources:** Trad & Chehab arXiv:2505.03451 (May 2025) · Barracuda Threat Spotlight Split/Nested QR (Aug 2025) · Unit 42 QR Code Phenomenon (Apr 2025) · PyMuPDF benchmarks (py-pdf/benchmarks) · PyMuPDF documentation · Infosecurity Magazine FBI North Korean QR advisory (Jan 2026) · VirusTotal API v3 documentation · Proofpoint Device Code + QR phishing (Dec 2025)
