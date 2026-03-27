# Deep Research: AI-Powered Voice & Video Social Engineering
## Voice Cloning · Deepfake Vishing BEC · Scattered Spider · Defences
### 2024–2026 Technical Intelligence Report

> **Sources:** CISA AA23-320A (updated July 29, 2025) · FBI IC3 · Mandiant/Google GTIG · ReliaQuest · CrowdStrike · Darktrace · CyberArk · HHS TLP:CLEAR Sector Alert · Optery · SpecOps · BankInfoSecurity · CNN · World Economic Forum · PRMIA · PMC/Monash University (audio deepfake detection survey, March 2025) · Speech DF Arena (arXiv, Sept 2025) · Resemble AI · Intel FakeCatcher
> **Compiled:** February 2026

---

## Table of Contents

1. [Voice Cloning Technology](#section-1-voice-cloning-technology)
   - [The Tool Landscape](#11-the-tool-landscape)
   - [Minimum Sample Duration](#12-minimum-sample-duration--the-three-second-myth)
   - [Detection Tool Accuracy](#13-detection-tool-accuracy)
   - [Open-Source Detection Models](#14-open-source-detection-models)
   - [The Detection Arms Race](#15-the-detection-arms-race)

2. [Confirmed Enterprise Deepfake Cases](#section-2-confirmed-enterprise-deepfake-cases)
   - [Arup — $25.6M Hong Kong (Jan 2024)](#21-arup--256m-hong-kong-january-2024)
   - [Ferrari — CEO Impersonation (Jul 2024)](#22-ferrari--ceo-impersonation-july-2024)
   - [WPP CEO — Teams Clone (May 2024)](#23-wpp-ceo--teams-voice-clone-may-2024)
   - [European Energy Conglomerate — $25M (2025)](#24-european-energy-conglomerate--25m-2025)
   - [Swiss Businessman — Swiss Francs (Jan 2026)](#25-swiss-businessman--several-million-chf-january-2026)
   - [North American Bank Coordinated Campaigns (Mar 2025)](#26-north-american-bank-coordinated-campaigns-march-2025)
   - [Full Case Table](#27-full-confirmed-case-table-2019-2026)

3. [Scattered Spider Vishing Playbook](#section-3-scattered-spider-vishing-playbook)
   - [Group Profile](#31-group-profile)
   - [Phase 1: OSINT & Reconnaissance](#32-phase-1-osint--reconnaissance)
   - [Phase 2: Infrastructure Setup](#33-phase-2-infrastructure-setup)
   - [Phase 3: The Helpdesk Call — Full Script Analysis](#34-phase-3-the-helpdesk-call--full-script-analysis)
   - [Phase 4: Handling Challenge Questions](#35-phase-4-handling-challenge-questions)
   - [Phase 5: Reversed Social Engineering (2025 TTP)](#36-phase-5-reversed-social-engineering--new-july-2025-cisa-advisory)
   - [Post-Access Kill Chain](#37-post-access-kill-chain-2025)
   - [2025 Sector Targeting Timeline](#38-2025-sector-targeting-timeline)
   - [MITRE ATT&CK Mapping](#39-mitre-attck-mapping)

4. [Defences](#section-4-defences)
   - [Technical Controls](#41-technical-controls)
   - [Procedural Controls](#42-procedural-controls)
   - [The Verbal Codeword System](#43-the-verbal-codeword-system)
   - [Open-Source Real-Time Detection Tools](#44-open-source-real-time-detection-tools)
   - [Building a Real-Time Audio Deepfake Detector](#45-building-a-real-time-audio-deepfake-detector)
   - [Defences Ranked by Effectiveness](#46-defences-ranked-by-effectiveness)

5. [Portfolio Tool Opportunities](#section-5-portfolio-tool-opportunities)

---

## SECTION 1: Voice Cloning Technology

> **Headline stat:** Modern AI can clone a voice with approximately 85% accuracy from as little as 3–5 seconds of audio (McAfee Security Research). With 3–5 minutes of source material, the result is indistinguishable from the real voice to human listeners in most studies. The barrier to entry has completely collapsed.

---

### 1.1 The Tool Landscape

Voice cloning capability in 2025 spans five tiers, from hobbyist to professional, all publicly accessible.

#### Tier 1 — Commercial APIs (no technical skill required)

| Tool | Sample Needed | Output Quality | Cost | Notable |
|------|--------------|----------------|------|---------|
| **ElevenLabs** | ~1 min (Instant Clone) | Near-professional | Free tier / $5+/mo | Most accessible; dominant in criminal adoption; has AI Speech Classifier for detection |
| **Resemble AI** | 30–60 seconds | Professional | API pricing | Enterprise-grade; also sells Resemble Detect for detection |
| **Microsoft VALL-E** | 3 seconds (prompting mode) | High; preserves acoustic environment | Research/API | First to demonstrate 3-second cloning; emotional tone preservation |
| **Play.ht** | 5–10 seconds | High | $29+/mo | Popular with content creators; frequently abused |
| **Murf AI** | 1–2 minutes | Professional | $29+/mo | Common in BEC reconnaissance toolkits |

#### Tier 2 — Open-Source (technical skill required; no cost)

| Tool | GitHub | Sample Needed | Output Quality | Key Use in Attacks |
|------|--------|--------------|----------------|--------------------|
| **RVC (Retrieval-based Voice Conversion)** | `RVC-Boss/RVC-WebUI` ~20K stars | 5–10 minutes for training | High; real-time capable | Most widely used open-source clone tool in criminal operations; real-time conversion during live calls |
| **OpenVoice** | `myshell-ai/OpenVoice` ~30K stars | 1–5 seconds (zero-shot) | High | Zero-shot capability — no pre-training needed on target voice |
| **Tortoise TTS** | `neonbjb/tortoise-tts` ~13K stars | 6–10 reference clips (~10s each) | Very high; slow | Highest quality open-source; used for pre-recorded vishing lures |
| **Coqui TTS** | `coqui-ai/TTS` ~37K stars | 6 seconds (XTTS v2) | High | XTTS v2 supports 16 languages; multilingual attacks |
| **Bark** | `suno-ai/bark` ~37K stars | Text prompt + voice prompt | High; expressive | Generates laughter, pauses, hesitation — natural conversation simulation |
| **Whisper (OpenAI)** | `openai/whisper` ~75K stars | N/A (ASR, not TTS) | N/A | Used for **transcription** of target audio to extract speech patterns before cloning |
| **Real-Time-Voice-Cloning** | `CorentinJ/Real-Time-Voice-Cloning` ~55K stars | ~5 seconds | Medium-high | Real-time streaming; foundational repo for many derivatives |

#### Tier 3 — Agentic AI Platforms (adversary-as-a-service)

**Xanthorox AI** (documented 2025): Dark web AI platform that automates the full vishing pipeline — OSINT collection, voice cloning from harvested audio, script generation, and live call delivery. Removes the need for manual preparation entirely. Directly implicated in the 1,600%+ vishing surge in early 2025.

---

### 1.2 Minimum Sample Duration — The Three-Second Myth

The "3-second clone" figure is technically accurate for the most capable systems (Microsoft VALL-E, OpenVoice zero-shot) but represents the **floor for recognisable similarity**, not the ceiling for deception quality. The relationship between sample length and output quality is non-linear:

| Sample Duration | What You Can Produce | Deception Effectiveness |
|----------------|---------------------|------------------------|
| **3–5 seconds** | Recognisable voice pattern, basic prosody | ~70% accuracy in studies; fools automated systems; fools humans in short, high-pressure calls |
| **30–60 seconds** | Natural tone, emotional range, cadence | ~85% accuracy; plausible for telephone quality audio |
| **3–5 minutes** | Full character voice with speaking habits, hesitation patterns | Near-indistinguishable over phone; ElevenLabs Instant Clone operates in this range |
| **10–30 minutes** | High-fidelity training set for RVC/fine-tuned models | Indistinguishable from real voice in controlled studies; preserves idiosyncratic speech patterns |
| **Hours (full fine-tune)** | Professional broadcast-quality clone | Used in the Arup attack-level productions |

**Source material availability in 2025 for C-Suite targets:**
- Quarterly earnings calls (30–90 minutes per quarter) — freely downloadable from investor relations pages
- Conference presentations (Davos, industry events, TED/TEDx) — YouTube
- Podcast appearances — common for founders and executives
- Company all-hands recordings — sometimes leaked or shared internally; obtainable via social engineering
- LinkedIn video posts and featured media appearances
- Webinar recordings — often unprotected on Zoom/Teams cloud storage

A median Fortune 500 CEO has **200–500 minutes** of publicly available audio. For most senior executives at any company with an IR department, obtaining adequate training material requires zero technical access.

---

### 1.3 Detection Tool Accuracy

#### Commercial Detection Tools

| Tool | Claimed Accuracy | Method | Limitation |
|------|-----------------|--------|-----------|
| **ElevenLabs AI Speech Classifier** | Detects ElevenLabs-generated audio | Proprietary watermark + spectral analysis | Only reliable for ElevenLabs-generated content; easily defeated by using other tools |
| **Resemble Detect** | "High precision" (no public benchmark) | Spectral analysis + neural classifier | Does not publish EER; accuracy degrades on telephone-quality audio |
| **Intel FakeCatcher** | 96% accuracy (video deepfakes) | Photoplethysmography (blood flow in face); PPG signal analysis | Primarily video-focused; audio component less documented |
| **McAfee Deepfake Detector** | Not independently benchmarked | Local on-device ML; spectral + temporal analysis | Desktop-only; no API for integration |

#### Academic Benchmark — Speech DF Arena (arXiv:2509.02859, Sept 2025)

The most comprehensive independent benchmark across open and proprietary systems, spanning ASVspoof, LibriSeVoc, In-the-Wild, and SONAR datasets:

| System | Type | Pooled EER (%) | Notes |
|--------|------|---------------|-------|
| **Whispeak** | Proprietary | ~3.0% | Best-in-class; consistent across clean and real-world datasets |
| **WavLM-ECAPA** | Open-source | ~4–8% (clean) → **38–50%** (with music/noise) | Strong in clean conditions; catastrophically degrades with background noise |
| **XLSR + SLS** | Open-source | ~7–14% | More robust to augmentation than WavLM-ECAPA |
| **TCM (319M)** | Open-source | ~8–12% | Reasonably consistent; no catastrophic noise failure |
| **AASIST (0.3M)** | Open-source | ~15–25% | Lightweight; high EER but deployable on resource-constrained devices |
| **Whisper Mesonet (7.6M)** | Open-source | ~20–30% | Efficient; moderate accuracy |
| **WavLM ensemble (ASVspoof5)** | Research | 6.56% (eval set 1) / 17.08% (eval set 2) | Competition result; not real-time deployable as-is |

**EER (Equal Error Rate):** The point where false accept rate = false reject rate. A 5% EER means 5% of real voices are flagged as fake AND 5% of fake voices are accepted as real. For enterprise security, the false negative rate (fake accepted as real) is the critical number — and it is much higher than EER in adversarial conditions.

**The critical problem: telephone channel degradation**

Real-world vishing calls are not clean audio. GSM codec compression, background noise, and VoIP transmission artefacts **mimic the same spectral anomalies** that deepfake detection models use to identify synthetic speech. In adversarial conditions (VoIP + background noise + codec compression), the best open-source models see EER degrade to **20–50%** — effectively random chance at the extremes.

---

### 1.4 Open-Source Detection Models

**Best options for deployment in 2025:**

#### Resemblyzer (resemble-ai/Resemblyzer)
- **Function:** Voice encoder producing 256-dimensional embeddings; speaker similarity comparison
- **Use case:** Compare incoming voice to reference embedding of known employee — flag if similarity drops below threshold
- **Speed:** ~1000x real-time on GPU; real-time capable on CPU
- **Limitation:** Detects voice *mismatch* (wrong person), not synthetic generation — a well-trained clone of the target will score as similar to the target

```python
from resemblyzer import VoiceEncoder, preprocess_wav
from pathlib import Path
import numpy as np

encoder = VoiceEncoder()

# Enrol known employee voice from HR verification recording
reference_wav = preprocess_wav(Path("employee_john_doe_reference.wav"))
reference_embed = encoder.embed_utterance(reference_wav)

# During live call — process incoming audio chunk
incoming_wav = preprocess_wav(Path("incoming_call_chunk.wav"))
incoming_embed = encoder.embed_utterance(incoming_wav)

# Cosine similarity: >0.85 = strong match, <0.75 = suspicious
similarity = np.inner(reference_embed, incoming_embed)
print(f"Voice similarity score: {similarity:.3f}")
if similarity < 0.75:
    print("[ALERT] Voice does not match enrolled employee profile")
```

#### AASIST (Audio Anti-Spoofing using Integrated Spectro-Temporal graph)
- **GitHub:** `clovaai/aasist` (~800 stars)
- **Function:** Graph attention network operating on raw waveform; no hand-crafted features
- **Training data:** ASVspoof 2019 LA dataset (19 TTS/VC attack types)
- **EER:** ~0.83% on ASVspoof2019 LA eval (best-in-class for controlled conditions)
- **Real-time:** With 4-second input window, inference ~50ms on GPU
- **Limitation:** Trained on 2019 attacks; generalisation to newer TTS systems (VALL-E, Bark, RVC) is imperfect — the "unseen attack" problem

```python
# Inference with AASIST (simplified)
import torch
import librosa
import numpy as np

# Load pretrained AASIST model
model = torch.load('AASIST.pt', map_location='cpu')
model.eval()

def detect_deepfake(audio_path: str, threshold: float = 0.5) -> dict:
    audio, sr = librosa.load(audio_path, sr=16000, duration=4.0)
    # Pad or trim to 4 seconds (64600 samples at 16kHz)
    audio = librosa.util.fix_length(audio, size=64600)
    
    x = torch.FloatTensor(audio).unsqueeze(0)
    
    with torch.no_grad():
        _, output = model(x, x)  # AASIST takes (x_mel, x_raw)
        score = output[:, 1].item()  # bonafide class score
    
    return {
        'score': score,
        'verdict': 'REAL' if score > threshold else 'SYNTHETIC',
        'confidence': abs(score - threshold) / threshold
    }
```

#### WavLM + ECAPA-TDNN (Best accuracy on clean audio)
- **Front-end:** `microsoft/wavlm-large` (HuggingFace)
- **Back-end:** ECAPA-TDNN classifier
- **EER:** ~4–8% on clean datasets
- **Critical warning:** EER spikes to 38–50% under music/noise augmentation (Speech DF Arena, Sept 2025) — **not suitable for real-world telephone audio without explicit noise-robust fine-tuning**

---

### 1.5 The Detection Arms Race

The fundamental problem with voice deepfake detection in 2025 is generalisation — every detector is trained on a fixed set of known synthesis systems and fails on unseen attacks:

- **AASIST** trained on ASVspoof 2019 (19 attack types from 2018–2019 TTS systems) → unreliable against VALL-E, RVC, Bark, OpenVoice (2022–2025)
- **WavLM ensembles** (ASVspoof 5 challenge, 2024) achieve 6.56% EER in competition conditions → 17–50% in real-world conditions
- **Queen Mary University of London study:** Most people can no longer distinguish real from AI-cloned voices — humans perform at near-chance levels when audio quality is high
- **Adversarial bypass:** Adding low-level noise, pitch shifting, or codec compression to cloned audio degrades most classifier performance significantly

**Bottom line for defensive design:** Voice deepfake detection should be treated as a *supporting signal*, not a primary control. A detector that achieves 95% accuracy still allows 1 in 20 synthetic calls to pass through — in a targeted enterprise attack, this is not acceptable as a sole defence. Combine detection with procedural controls (out-of-band verification, codewords, mandatory callback).

---

## SECTION 2: Confirmed Enterprise Deepfake Cases

> **Scale of the problem:** $200M+ in documented losses in Q1 2025 alone (World Economic Forum / multiple sources). Deepfake fraud in North America surged 1,740% between 2022–2023. Vishing attacks leveraging voice cloning surged 1,600% in early 2025 vs. late 2024. CEO fraud now targets at least 400 companies per day.

---

### 2.1 Arup — $25.6M Hong Kong, January 2024

**The most technically sophisticated and financially significant deepfake attack ever publicly confirmed.**

#### Kill Chain (Complete Reconstruction)

```
PHASE 1 — RECONNAISSANCE (weeks before the call)
  Target selection: Arup Hong Kong finance department employee
  OSINT collection:
    → Arup's publicly available video content: LinkedIn executive videos,
      conference presentations, webinar recordings, Zoom/Teams meeting
      recordings (some accessible from investor/client portals)
    → Organisational structure: identified CFO (UK-based) + senior colleagues
    → Communication patterns: established normal transaction approval workflow
    → Employee identification: isolated finance worker with wire transfer authority

PHASE 2 — TRAINING DATA EXTRACTION
  Source material for deepfake models:
    → Company conference recordings (Arup designs Sydney Opera House,
      Beijing Olympics venues — extensive public media archive)
    → Earnings/briefing calls
    → Industry conference presentations
    → LinkedIn video content
  Models used: Likely GAN or diffusion model for video; neural TTS for audio
  Preparation time: Arup CIO Rob Greig confirmed he replicated a basic version
    himself "in about 45 minutes" with open-source software — attackers likely
    spent weeks producing the polished multi-person version

PHASE 3 — INITIAL CONTACT (spear-phishing email)
  Channel: Email purportedly from UK-based CFO
  Content: Request for "confidential transaction" — framed as secret/sensitive
  Employee response: SUSPICIOUS — correctly identified potential phishing
  Attacker response: Escalated to video call to overcome scepticism

PHASE 4 — THE DEEPFAKE VIDEO CONFERENCE
  Platform: Video conferencing (platform not confirmed; likely Zoom or Teams)
  Participants shown: CFO + multiple senior colleagues — ALL deepfakes
  Duration: Long enough to instruct 15 wire transfers across 5 accounts
  Technical execution:
    → Every participant except the victim was AI-generated in real time
    → Video: GANs/diffusion models synthesising realistic facial movements
    → Audio: Neural TTS cloning CFO and colleagues' voices
    → "On the call, the employee saw and heard individuals who looked and
       sounded exactly like the real CFO and several other colleagues"
       (Hong Kong Police Senior Superintendent Baron Chan Shun-ching)

PHASE 5 — FUND TRANSFER
  Transfers: 15 transactions, 5 different Hong Kong bank accounts
  Total: HKD $200 million ($25.6M USD)
  Timeline: Single day
  Discovery: Employee followed up with actual HQ — executives had no knowledge
    of meeting, transaction, or any "secret" arrangement

PHASE 6 — AFTERMATH
  Arup's IT environment: Fully intact — no malware, no intrusion, no data loss
  Traditional defences operational: firewalls, endpoint protection, MFA, access
    controls — all working perfectly and all irrelevant
  Recovery: Zero — funds dispersed to five HK accounts; investigation ongoing
    as of early 2026; no arrests; no identified perpetrators
```

**Key technical detail confirmed by Hong Kong Police:** The deepfakes were created by "leveraging existing video and audio files of these individuals from online conferences and virtual company meetings."

**The critical lesson (Rob Greig, Arup CIO, World Economic Forum, Feb 2025):** *"This attack used psychology and sophisticated deepfake technology to gain the employee's confidence. Attackers didn't compromise any systems or data. All traditional cybersecurity layers were operating effectively. The attackers never tried to hack the network; instead, they exploited the human."*

---

### 2.2 Ferrari — CEO Impersonation, July 2024

#### Kill Chain

```
PHASE 1 — SETUP
  Method: Attacker created a WhatsApp account using a publicly available
    photo of Ferrari CEO Benedetto Vigna
  Target: A senior Ferrari manager
  Platform: WhatsApp (bypasses corporate email filtering entirely)

PHASE 2 — INITIAL CONTACT
  Channel: WhatsApp message from fake "Vigna" account
  Content: Message claiming an important, confidential acquisition deal was
    underway; required the manager to assist with procedures not previously
    disclosed to regulatory authorities
  Tone: Urgent, secretive, authoritative — invoking CEO authority

PHASE 3 — VOICE CLONING ATTEMPT
  Voice: AI-cloned voice of Benedetto Vigna — recognisable accent and speaking
    style replicated convincingly
  Script elements: References to a confidential deal, urgency, request to
    sign an NDA first before details could be shared

PHASE 4 — THE CALL THAT FAILED
  The targeted manager grew suspicious because of:
    (a) Unusual platform (WhatsApp rather than internal channels)
    (b) The voice had a slight mechanical quality ("strange cadence")
  The manager asked a question that the clone could not answer:
    → "I asked him to name the book we had both just been recommending
       to colleagues" (reported by sources familiar with the case)
  Cloned voice could not provide a plausible answer to this personalised
    challenge question
  Attack aborted — no financial loss
```

**Why this case matters:** It documents both the attack technique *and* a successful defence — a personal challenge question that required shared episodic memory the attacker could not have harvested from public sources. This is the practical origin of the "codeword" defence concept.

---

### 2.3 WPP CEO — Teams Voice Clone, May 2024

**Target:** A senior WPP executive  
**Method:** Attacker created a fake WhatsApp account with publicly available images of WPP CEO Mark Read, then used this account to send a virtual meeting invitation. In the meeting, a voice clone of Read instructed staff to share sensitive access credentials and transfer funds.  
**Result:** The attack was identified before financial loss occurred — the unusual request for credentials from an executive via informal channels triggered suspicion.  
**Technical detail:** The voice was described as "sounding authentic" in early reports; WPP confirmed the incident publicly.

---

### 2.4 European Energy Conglomerate — $25M, 2025

**Date:** Early 2025  
**Method:** Deepfake audio clone of CFO — used for a live, interactive call issuing urgent wire transfer instructions. The clone was sophisticated enough to handle interactive back-and-forth conversation, maintaining the CFO's tone, cadence, and speaking habits.  
**Loss:** $25 million  
**Detail (Veriprajna/Google Cloud):** "The clone was sophisticated enough to handle live, interactive instructions, bypassing multiple human checkpoints through the perceived authority of the executive's voice."  
**Note:** This is a separate incident from Arup; attributed to a European energy firm; exact company not publicly identified.

---

### 2.5 Swiss Businessman — "Several Million CHF", January 2026

**Date:** January 2026  
**Method:** Series of phone calls with a cloned voice of a known business partner. Multiple calls over a period of time to build trust before requesting the transfer.  
**Loss:** "Several million Swiss francs" (amount not precisely disclosed)  
**Notable:** Represents the multi-call, trust-building variant — not a single urgent call but a relationship-building campaign using consistent synthetic voice across multiple interactions.

---

### 2.6 North American Bank Coordinated Campaigns, March 2025

**Date:** March 2025  
**Targets:** Several North American banks  
**Method:** Coordinated campaigns where attackers posed as internal IT support via vishing, harvesting credentials used to launch ransomware attacks on critical systems.  
**Impact:** Ransomware deployment on critical banking infrastructure following successful helpdesk vishing for initial access.

---

### 2.7 Full Confirmed Case Table (2019–2026)

| Case | Date | Method | Loss | Outcome | Source |
|------|------|--------|------|---------|--------|
| UK Energy CEO voice clone | 2019 | Phone call; deepfaked CEO voice | €220,000 | Transferred; partial recovery | Multiple |
| Arup Hong Kong | Jan 2024 | Multi-person real-time deepfake video conference | $25.6M | Unrecovered; investigation ongoing | CNN, WEF, Hong Kong Police |
| Ferrari CEO impersonation | Jul 2024 | WhatsApp + voice clone of Benedetto Vigna | $0 | Defeated by personal challenge question | Bloomberg, Reuters |
| WPP CEO clone | May 2024 | WhatsApp image + Teams voice clone of Mark Read | $0 | Detected before transfer | The Guardian, WPP |
| European energy conglomerate | Early 2025 | Live interactive CFO audio clone | $25M | Unrecovered | Veriprajna, Google Cloud |
| North American banks (coordinated) | Mar 2025 | Internal IT support vishing → credential theft → ransomware | Operational damage | Ransomware deployed | right-hand.ai |
| Swiss businessman | Jan 2026 | Multi-call voice clone of business partner | Several million CHF | Transferred; investigation ongoing | Zamakt, multiple |

---

## SECTION 3: Scattered Spider Vishing Playbook

> **Classification:** Scattered Spider (aliases: UNC3944, Octo Tempest, Storm-0875, Oktapus, Muddled Libra, Scatter Swine, Star Fraud) — FBI/CISA/NCSC/AUS/CAN joint advisory, originally AA23-320A (Nov 16, 2023), updated through July 29, 2025.

---

### 3.1 Group Profile

| Attribute | Detail |
|-----------|--------|
| **Origin** | English-speaking; predominantly Western countries; active since ~2021 |
| **Ages** | Predominantly young adults; several arrested members aged 17–26 |
| **Language** | Native English speakers — critical advantage over non-English criminal groups |
| **Motivation** | Financial — data extortion, BEC fraud, ransomware affiliates |
| **Community** | Part of "The Com" (also "The Comm") — Discord/Telegram hacking collective |
| **Affiliation** | Ransomware affiliate for ALPHV/BlackCat (2023), RansomHub (2024), DragonForce (2025) |
| **Known associates** | LAPSUS$, other Com members |
| **Notable arrests** | Multiple arrests 2023–2024; group continues operations |
| **Key targeting (2025)** | UK retailers (M&S, Co-op, Harrods) → Insurance → Airlines/Transportation → MSPs |

---

### 3.2 Phase 1: OSINT & Reconnaissance

Scattered Spider's vishing calls succeed because they are not improvised — they are the final act of a multi-week intelligence operation. Mandiant investigators confirmed that in multiple cases, attackers arrived at the helpdesk call already possessing:

- Full name and job title of the impersonation target
- Employee ID/badge number
- Date of birth
- Last four digits of Social Security Number
- Manager's name and title
- Names of colleagues and recent internal events
- The organisation's ticketing system (ServiceNow, Jira, etc.)
- Internal terminology and jargon specific to the target company

**Sources of this intelligence (confirmed by CISA, Optery, Mandiant, HHS):**

| Data Source | What It Yields | Acquisition Method |
|-------------|---------------|-------------------|
| **LinkedIn** | Name, title, manager, org chart, employment history, post content | Free scraping; paid tools (Pipl, ContactOut) |
| **Commercial data brokers** | DOB, SSN last-4, phone, home address, previous employers | Paid; ~$30–$100 per report; services include Spokeo, Whitepages, BeenVerified |
| **Previous data breaches** | Passwords, email/username combinations, partial SSNs | Dark web markets (Russia Market — explicitly named in CISA AA23-320A) |
| **Infostealer logs** | Saved browser passwords, session cookies, internal document contents | Dark web; logs from Lumma/RedLine/Raccoon sold per-machine |
| **Company website** | Org structure, executive names, office locations, contact formats | Free |
| **Oracle/Workday/SAP portals** | Employee ID confirmation — Scattered Spider used publicly accessible HR portals to *confirm* employee IDs using DOB + SSN-last-4 to validate their OSINT dossier (ReliaQuest, FBI) | Free; requires DOB + SSN-last-4 (obtained from brokers) |
| **Internal Slack/Teams after first access** | Employee names, project names, internal slang, helpdesk ticketing process | Post-initial-access reconnaissance for follow-on calls |

**The OSINT validation loop (documented ReliaQuest/FBI 2025):**

```
Step 1: Collect DOB + SSN-last-4 from data brokers/breaches
Step 2: Use company's PUBLIC Oracle Cloud / Workday portal
          → Enter DOB + SSN-last-4 on self-service login screen
          → Portal returns: "Your employee ID is XXXXXX"
Step 3: Attacker now has confirmed, validated employee ID
          → Arrives at helpdesk call with verified identity data
          → Can answer any "confirm your employee ID" challenge correctly
```

This is why challenge questions based on information in HR/payroll systems provide **false security** — the information is available through data brokers and can be pre-validated using public-facing HR portals.

---

### 3.3 Phase 2: Infrastructure Setup

Before the call, attackers configure caller ID spoofing and communication channels:

**Call infrastructure:**
- VoIP services configured to display internal company phone numbers (caller ID spoofing via SIP providers with lax enforcement)
- SIM-swapped phones using victim's real phone number (more convincing than VoIP spoofing)
- Slack/Teams/email accounts on domains like `vpn-[companyname].com`, `[companyname]-sso.com`, `[companyname]-helpdesk.com`

**Domain patterns (ReliaQuest analysis of 600+ Scattered Spider domains, Q1 2022–Q1 2025):**
```
Most common keywords: "internal", "connect", "duo", "vpn", "helpdesk",
"servicenow", "corp", "schedule", "okta", "servicedesk", "rsa", "info",
"support", "mfa", "sso", "help", "service"

Domain formats:
  Hyphenated:    SSO-[company].com          → being phased out (detected by monitoring)
  Subdomain:     SSO.[c0mpany].com          → current preference (harder to auto-detect)
  Typosquat:     [c0mpany]sso.com           → ongoing
  No hyphen:     [company]servicedesk.com   → growing
```

**2025 shift:** Scattered Spider moved from hyphenated domains to subdomain-based keywords to evade automated domain impersonation detection.

---

### 3.4 Phase 3: The Helpdesk Call — Full Script Analysis

The following represents a **composite reconstruction** of the Scattered Spider helpdesk call script, synthesised from:  
- CISA AA23-320A (original + July 29, 2025 update)
- HHS TLP:CLEAR Sector Alert (healthcare sector analysis)
- ReliaQuest teardown (logistics firm CFO impersonation)
- SpecOps blog (detailed call analysis)
- Mandiant Frontlines report (May 2025)
- Optery analysis (data broker reconnaissance)
- CrowdStrike 2025 incident observations

> **IMPORTANT NOTE:** This script is documented for defensive awareness purposes only — to enable helpdesk training, policy design, and detection rule development.

---

**Call Opening — Establishing Identity and Urgency**

```
Attacker: "Hi, this is [REAL EMPLOYEE FULL NAME] from [REAL DEPARTMENT].
           I'm having a really bad day — my phone stopped working this morning
           and I'm completely locked out of everything."

[Tone: Friendly, slightly stressed — "someone having a problem", not aggressive]

Helpdesk: "Hi [Name]. Can I get your employee ID?"

Attacker: "[CORRECTLY STATES EMPLOYEE ID — pre-validated via HR portal]"

Helpdesk: "And your date of birth for verification?"

Attacker: "[CORRECTLY STATES DOB — obtained from data broker]"
```

**Why it works at this stage:**
- Correct employee name, ID, and DOB match what the helpdesk system shows
- The helpdesk agent's verification is now "passed" — trust established
- The agent experiences relief at a "straightforward" call that is passing checks

---

**The Core Request**

```
Attacker: "My phone was stolen / broken / lost — I can't receive my MFA codes.
           I need to add a new device to my account so I can get back to work.
           I have a deadline in [X hours / today] for [SPECIFIC REAL PROJECT
           NAME — obtained from LinkedIn or internal Slack after prior access]."

[OR, in the reversed social engineering variant (July 2025 TTP):]

Attacker calls a THIRD-PARTY HELPDESK / MSP posing as the TARGET COMPANY:
           "This is [COMPANY NAME] IT support calling about one of your
            employees — [REAL EMPLOYEE NAME]. We need to reset their access
            as part of an urgent security remediation."
```

**Internal slang deployment (SpecOps analysis):**
```
"Can you just go into Okta and push through a reset like you did last week
 for Mike in Ops? Same deal."

[Uses colleague's real first name — obtained from LinkedIn or Slack]
[References internal tool (Okta) by name — shows familiarity]
[Implies helpdesk agent has done this before — normalises the request]
```

**Building rapport (documented tactic):**
```
Attacker references local context:
"Rough weather today, right? Anyway, really appreciate your help here —
 I've got [REAL MANAGER NAME] breathing down my neck about this deadline."

[Mentioning real manager name creates legitimacy]
[Weather/local reference creates human connection, reduces suspicion]
[Authority pressure (manager name) creates urgency]
```

---

**The Escalation — If Hesitation Is Detected**

If the helpdesk agent hesitates or says they need to follow a verification process:

```
Attacker (authority escalation):
"Look, I understand the process, but I'm literally sitting here locked out
 and [REAL MANAGER NAME] needs this fixed before our call with the client.
 Can you escalate to your supervisor? I don't want to have to call [CISO NAME /
 IT DIRECTOR NAME] directly and explain why this wasn't handled."

[Threat of escalation to senior figure the agent wants to avoid]
[Senior figure name obtained from company website / LinkedIn]
```

If the agent asks for a manager to confirm:

```
Attacker: "Sure, you can call back on my mobile — [GIVES ATTACKER-CONTROLLED
            NUMBER] — but my phone is broken, so it'll go to voicemail. Just
            leave a message and I'll call you right back from a colleague's phone."

[Callback goes to attacker-controlled voicemail — blocks out-of-band verification]
```

---

### 3.5 Phase 4: Handling Challenge Questions

**The most critical documented capability: Scattered Spider correctly answers challenge questions in "almost all observed 2025 incidents" (CrowdStrike).**

**How they handle each challenge type:**

| Challenge Type | Scattered Spider Response | Data Source Used |
|---------------|--------------------------|-----------------|
| "What's your employee ID?" | Correct answer | HR portal self-service confirmation (pre-validated) |
| "What's your date of birth?" | Correct answer | Data broker (Spokeo, Whitepages, BeenVerified) |
| "What are the last four digits of your SSN?" | Correct answer | Data broker or breach data |
| "Who is your manager?" | Correct name | LinkedIn |
| "What's your office location?" | Correct answer | LinkedIn / company website |
| "What project are you working on?" | Plausible answer | LinkedIn posts / Slack (post-access) |
| "What's your corporate credit card number?" | Pause / deflect | "That's what I'm locked out of — I can't check right now" |
| "Can you verify via the authenticator app?" | "My phone is broken/lost/stolen — that's why I'm calling" | Universal deflection — works on any MFA challenge |

**The "phone is broken" universal bypass:** Every identity verification that requires the physical device in the attacker's hands is defeated by the single claim that the device is broken/lost/stolen. The helpdesk's entire purpose in this scenario becomes helping someone who *cannot* use their device — the attack weaponises the exception process.

**Consulting notes during the call:** Analysts observed Scattered Spider operatives pausing for extended periods or asking the helpdesk agent to repeat questions. This indicates real-time reference to a prepared dossier — effectively an OSINT playbook consulted during the call.

---

### 3.6 Phase 5: Reversed Social Engineering — New July 2025 CISA Advisory

The July 29, 2025 CISA/FBI/NCSC/AUS/CAN advisory identified a **new TTP not present in the original 2023 advisory:**

**The standard TTP:** Attacker impersonates an *employee* calling their company's IT helpdesk.

**The 2025 TTP (Reversed Social Engineering):** Attacker impersonates a *company's IT department* calling a *third-party helpdesk/MSP* on behalf of an employee.

```
Standard (pre-2025):
  Attacker → calls TARGET COMPANY helpdesk
  Posing as: Target company employee
  Goal: Get helpdesk to reset MFA / issue new device

NEW (July 2025):
  Attacker → calls THIRD-PARTY MSP / IT CONTRACTOR helpdesk
  Posing as: Target company IT administrator
  Script: "Hi, this is [COMPANY NAME] IT. We need you to assist one of our
           employees — [REAL EMPLOYEE NAME] — with an urgent MFA reset as part
           of a security remediation we're running today."
  Goal: MSP helpdesk resets employee access, believing they're helping
         a legitimate client's IT request
```

**Why it's more effective:**
- Third-party MSP helpdesks have *less context* about the client's internal employees and verification processes
- They are predisposed to comply with requests appearing to come from the client
- The client's own security policies may not govern the MSP's verification procedures
- Creates one more layer of distance between attacker and victim company's internal processes

---

### 3.7 Post-Access Kill Chain (2025)

Once MFA is reset and initial access is obtained, Scattered Spider operates with documented speed:

```
T+0  MFA reset approved by helpdesk
T+0  Attacker enrolls attacker-controlled device in target's MFA
T+1  Attacker logs into corporate SSO (Okta / Microsoft Entra ID)
T+2  Enumerate cloud environment: Azure AD / AWS IAM / GCP IAM roles
T+3  Identify highest-privilege accounts for lateral movement
T+6  Access Salesforce / SharePoint / OneDrive for data collection
T+12 Move to VMware vCenter / ESXi environments
     → Enable SSH, reset root credentials
     → Exfiltrate NTDS.dit (Active Directory database dump)
T+24 Deploy DragonForce / BlackCat / Qilin ransomware on ESXi hypervisors
     → Encrypts all VMs simultaneously
     → Speed prevents detection and interruption

Tools deployed (confirmed 2025):
  - AiTM phishing kits (Evilginx3) for additional credential capture
  - Ngrok / Teleport for C2 (blends with legitimate traffic)
  - AnyDesk / ScreenConnect / TeamViewer for persistence
  - BloodHound / AADInternals for AD enumeration
  - Pastebin for data staging
  - Spectre RAT, Lumma Stealer, AveMaria, Raccoon, VIDAR for credential harvesting
  - SSH transfers to Vultr IPs + S3 uploads for exfiltration
```

**The M&S breach timeline (April–May 2025) — public sector impact estimate:**

| Date | Event |
|------|-------|
| Feb 2025 | Initial access via vishing to helpdesk; NTDS.dit exfiltration begins |
| Feb–Apr 2025 | Dwell period; credential access; lateral movement |
| Apr 22, 2025 | Public disclosure of cyber incident |
| Apr 24, 2025 | DragonForce ransomware deployed on VMware ESXi infrastructure |
| Apr–Jun 2025 | 46-day sales suspension on online/contactless payments |
| June 2025 | Estimated financial impact: £300M profit impact; £500M stock value decline |

---

### 3.8 2025 Sector Targeting Timeline

| Period | Sector | Victims | Notes |
|--------|--------|---------|-------|
| Apr–May 2025 | UK Retail | Marks & Spencer, Co-op, Harrods | Helpdesk vishing + IT contractor compromise |
| May–Jun 2025 | US Retail | Multiple unnamed US retailers | Mandiant warning; formal attribution unconfirmed |
| Jun 2025 | Insurance | Multiple unnamed firms | CyberScoop: "pivots to insurance industry" |
| Jul 2025 | Airlines / Transportation | Multiple named firms (Qantas etc.) | FBI warning; Microsoft July 16, 2025 report; ESXi focus |
| Ongoing | MSPs / IT Contractors | Multiple | "One-to-many" strategy — breach one MSP, access all clients |

---

### 3.9 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Implementation |
|--------|-----------|-----|----------------|
| Reconnaissance | Gather Victim Identity Info | T1589 | Data brokers, LinkedIn, breach data for employee PII |
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | [company]-sso.com, [company]-vpn.com, etc. |
| Resource Development | Establish Accounts: Social Media | T1585.001 | Fake personas for impersonation |
| Initial Access | Phishing: Spearphishing Voice | **T1566.004** | Helpdesk impersonation calls |
| Initial Access | Trusted Relationship | T1199 | Exploit MSP/IT contractor access |
| Credential Access | Multi-Factor Authentication Request Generation | T1621 | MFA fatigue bombing |
| Persistence | Account Manipulation | T1098 | Enrol attacker device in MFA |
| Privilege Escalation | Valid Accounts | T1078 | Use legitimate credentials obtained via vishing |
| Defence Evasion | BYOVD (Bring Your Own Vulnerable Driver) | T1068 | Kill EDR products |
| Lateral Movement | Remote Services | T1021 | RDP, PsExec, GPOs |
| Exfiltration | Exfiltration Over Web Service | T1567 | S3 uploads, Salesforce export |
| Impact | Data Encrypted for Impact | T1486 | DragonForce/BlackCat ransomware on ESXi |

---

## SECTION 4: Defences

> **The fundamental insight (from the Ferrari case):** The only defence that defeated a state-of-the-art voice clone in a confirmed real-world attack was a personal challenge question requiring shared episodic memory — information that cannot be obtained from data brokers, LinkedIn, or public sources.

---

### 4.1 Technical Controls

**FIDO2/WebAuthn hardware keys — highest priority**
- The only authentication method that defeats *both* SIM swapping and the "phone broken" social engineering vector simultaneously
- Hardware keys (YubiKey, Google Titan Key) cannot be enrolled remotely — require physical possession
- MFA reset social engineering is neutralised: there is no "I lost my phone" equivalent for a hardware key that doesn't require the help desk to act
- CISA AA23-320A and every subsequent update explicitly recommends phishing-resistant MFA as the primary mitigation

**Helpdesk identity verification — mandatory out-of-band callback**
```
Policy: Before any MFA reset, password reset, or device enrolment,
         a callback to the employee's known-good number must be completed.

Implementation:
  - Registered callback numbers stored in HR system (not accessible via
    self-service portal where attacker can pre-validate)
  - Callback initiated by the helpdesk agent, not the caller
  - If caller provides a "temporary number" (attacker-controlled): DENY request;
    escalate to security team for review
  - Add 4-hour delay on any MFA device enrolment — alert the real employee
    via secondary channel (corporate email from HR system)
```

**Privileged identity controls**
- Require manager approval (in addition to helpdesk verification) for any MFA reset on accounts with admin/executive roles
- Time-delayed enrolment: new MFA device active only after 4–24 hours with notification to registered email
- Limit self-service HR portal exposure: remove or require additional authentication for portals that confirm employee ID via DOB + SSN-last-4

---

### 4.2 Procedural Controls

**The Dual-Channel Verification Protocol**

For any request involving: MFA reset / password reset / new device enrolment / wire transfer above threshold / account privilege change:

```
Step 1: Initial request received via phone or ticket
Step 2: Helpdesk opens a SEPARATE communication channel to the employee
         → Corporate email sent to on-file address (NOT an address the caller provides)
         → Microsoft Teams/Slack message to verified account
         → SMS to registered number in HR (not the number provided in the call)
Step 3: Employee responds through the secondary channel to confirm request
Step 4: Only after independent confirmation does the helpdesk proceed
Step 5: Log the full call recording + ticket + confirmation for audit
```

**Why this defeats Scattered Spider:**
- The attacker *cannot* access the secondary channels (real employee's email, Teams, registered phone) without already being inside the network
- Attacker cannot provide a "secondary channel" of their own — the policy requires using *pre-registered* contact information
- The real employee sees the unexpected confirmation request and can immediately report it to security

---

### 4.3 The Verbal Codeword System

**Inspired by the Ferrari case — the defence that actually worked in a confirmed real-world deepfake attack.**

**Concept:** Pre-shared secrets that require *episodic memory* — knowledge of specific shared experiences that cannot be reconstructed from public records, data brokers, or even full access to the target's digital communications.

**Implementation levels:**

**Level 1 — Personal codewords (individual)**
- Each executive/privileged user has a personal codeword known only to them and stored in a sealed envelope with HR security
- Any caller claiming to be that person is asked: "Please provide your personal verification codeword"
- A voice clone cannot provide this — it was never in any public recording

**Level 2 — Team/department codewords**
- Rotating 4-digit codes distributed monthly to team members via in-person briefing or physical mail (not email, which can be compromised)
- Required for any wire transfer, MFA reset for executive accounts, or out-of-policy requests
- Helpdesk training: no codeword = no action, regardless of how convincing the call is

**Level 3 — Episodic challenge questions (Ferrari defence)**
- Challenge questions based on shared recent experiences: "What was the title of the book we discussed last Thursday?"
- Only effective when genuinely personal and recent — not "what's your pet's name" (which is in data broker records)
- Requires prior relationship between the caller and the challenged party

**Codeword rotation and distribution:**
```
Frequency: Monthly rotation for high-value accounts
Distribution: Encrypted PDF sent to registered home address
              OR in-person briefing (most secure)
              NOT via email, Teams, Slack, or any digital channel
Storage: Sealed envelope in physical HR security safe
         Hash of codeword in HR system (so verifier can confirm without seeing plaintext)
```

---

### 4.4 Open-Source Real-Time Detection Tools

**Suitable for enterprise deployment (with caveats):**

| Tool | GitHub | Method | Real-Time? | Best Use Case | Key Limitation |
|------|--------|--------|-----------|---------------|----------------|
| **AASIST** | `clovaai/aasist` | Graph attention on raw waveform | ~50ms inference = yes | Pre-recorded audio analysis; call recording retrospective | Trained on 2019 attacks; unseen TTS systems degrade accuracy |
| **Resemblyzer** | `resemble-ai/Resemblyzer` | Speaker embedding comparison | ~1000x real-time | Employee voice verification — "is this the right person?" | Does not detect synthesis; high-quality clone passes as the real person |
| **DF Arena baseline** (XLSR+SLS) | Available via HuggingFace | SSL front-end + SLS backend | ~100ms | Balance of robustness and speed | 7–14% EER in clean; degrades under noise |
| **media-sec-lab/Audio-Deepfake-Detection** | Aggregated repo | Multiple models | Varies | Research baseline; not production-ready | No single model; requires selection |
| **RawGAT-ST** | Research | Spectro-temporal graph | Yes (~50ms) | Complementary to AASIST | Limited generalisation to new attacks |

**Commercial options (for reference):**

| Tool | Method | Best For |
|------|--------|----------|
| Resemble Detect API | Neural classifier | Real-time API call per audio chunk |
| ElevenLabs Speech Classifier | Proprietary | Detecting ElevenLabs-generated audio only |
| Pindrop Pulse | Liveness + acoustic analysis | Contact centre integration; enterprise |
| Nuance Gatekeeper | Speaker biometrics + deepfake detection | Financial services contact centres |

---

### 4.5 Building a Real-Time Audio Deepfake Detector

**Architecture for a production-grade real-time detector suitable as a portfolio project:**

```
INPUT: Live audio stream (WebRTC or SIP RTP)
         ↓
STAGE 1: BUFFERING (accumulate 4-second window)
         → Process every 1 second with 3-second overlap
         → 16kHz mono, normalised
         ↓
STAGE 2: DUAL-MODEL ENSEMBLE
  Model A: AASIST (raw waveform) → bonafide/spoof score_A
  Model B: Resemblyzer speaker similarity vs. enrolled voice → similarity_score_B
           [if no enrolled voice: skip model B]
         ↓
STAGE 3: RISK SCORING
  if score_A < 0.5 (AASIST: synthetic):
    risk += 0.6
  if similarity_score_B < 0.75 (not matching enrolled voice):
    risk += 0.4
  Combined risk: 0.0 – 1.0
         ↓
STAGE 4: ALERTING
  risk < 0.4:  GREEN — likely authentic
  0.4–0.7:     AMBER — suspicious; alert helpdesk supervisor
  risk > 0.7:  RED — likely synthetic; halt call, initiate out-of-band verification
         ↓
STAGE 5: LOGGING
  Store audio chunk + scores to SIEM
  STIX 2.1 IOC output if confirmed attack
  Alert to SOC dashboard (Grafana/Splunk)
```

**Core Python implementation:**

```python
import torch
import numpy as np
import pyaudio
import librosa
from resemblyzer import VoiceEncoder, preprocess_wav
from pathlib import Path
from collections import deque
import threading, queue, time

# ─── Config ───────────────────────────────────────────────────
RATE       = 16000
CHUNK      = 1024
WINDOW_SEC = 4.0
WINDOW_SAMPLES = int(RATE * WINDOW_SEC)

AASIST_THRESHOLD    = 0.5   # Below = synthetic
SIMILARITY_THRESHOLD = 0.75  # Below = voice mismatch
RISK_RED            = 0.7
RISK_AMBER          = 0.4

# ─── Load Models ──────────────────────────────────────────────
aasist_model = torch.load('AASIST.pt', map_location='cpu')
aasist_model.eval()

voice_encoder = VoiceEncoder()

def enrol_employee(audio_path: str) -> np.ndarray:
    """Create reference embedding from HR-verified voice sample."""
    wav = preprocess_wav(Path(audio_path))
    return voice_encoder.embed_utterance(wav)

def aasist_score(audio: np.ndarray) -> float:
    """Return bonafide probability (1.0 = definitely real, 0.0 = definitely fake)."""
    audio = librosa.util.fix_length(audio, size=WINDOW_SAMPLES)
    x = torch.FloatTensor(audio).unsqueeze(0)
    with torch.no_grad():
        _, out = aasist_model(x, x)
        return out[:, 1].item()  # bonafide class

def similarity_score(audio: np.ndarray, reference_embed: np.ndarray) -> float:
    """Cosine similarity between incoming audio and enrolled voice."""
    wav = preprocess_wav(audio)
    embed = voice_encoder.embed_utterance(wav)
    return float(np.inner(embed, reference_embed))

def compute_risk(bonafide_score: float, sim_score: float | None) -> float:
    risk = 0.0
    if bonafide_score < AASIST_THRESHOLD:
        risk += 0.6
    if sim_score is not None and sim_score < SIMILARITY_THRESHOLD:
        risk += 0.4
    return min(risk, 1.0)

def risk_label(risk: float) -> str:
    if risk >= RISK_RED:   return "🔴 RED   — LIKELY SYNTHETIC — HALT CALL"
    if risk >= RISK_AMBER: return "🟡 AMBER — SUSPICIOUS — ALERT SUPERVISOR"
    return                        "🟢 GREEN — LIKELY AUTHENTIC"

class RealTimeDetector:
    def __init__(self, reference_embed=None):
        self.reference_embed = reference_embed
        self.audio_buffer = deque(maxlen=WINDOW_SAMPLES)
        self.alert_queue  = queue.Queue()
        self.running      = False

    def audio_callback(self, in_data, frame_count, time_info, status):
        chunk = np.frombuffer(in_data, dtype=np.float32)
        self.audio_buffer.extend(chunk)
        if len(self.audio_buffer) == WINDOW_SAMPLES:
            audio = np.array(self.audio_buffer)
            threading.Thread(target=self._analyse, args=(audio.copy(),)).start()
        return (in_data, pyaudio.paContinue)

    def _analyse(self, audio: np.ndarray):
        try:
            b_score = aasist_score(audio)
            s_score = (similarity_score(audio, self.reference_embed)
                       if self.reference_embed is not None else None)
            risk    = compute_risk(b_score, s_score)
            label   = risk_label(risk)
            result  = {
                'timestamp':   time.time(),
                'bonafide':    round(b_score, 3),
                'similarity':  round(s_score, 3) if s_score else None,
                'risk':        round(risk, 3),
                'label':       label,
            }
            self.alert_queue.put(result)
            print(f"[{time.strftime('%H:%M:%S')}] Bonafide={b_score:.2f} "
                  f"Sim={s_score:.2f if s_score else 'N/A'} "
                  f"Risk={risk:.2f} | {label}")
        except Exception as e:
            print(f"Analysis error: {e}")

    def start(self):
        self.running = True
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paFloat32, channels=1,
                        rate=RATE, input=True, frames_per_buffer=CHUNK,
                        stream_callback=self.audio_callback)
        stream.start_stream()
        print("[DF Detector] Monitoring live audio...")
        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        stream.stop_stream()
        stream.close()
        p.terminate()

# Usage:
if __name__ == '__main__':
    # Enrol known employee voice from HR-verified recording
    ref_embed = enrol_employee('hr_verified/john_doe_voice.wav')
    detector  = RealTimeDetector(reference_embed=ref_embed)
    detector.start()
```

---

### 4.6 Defences Ranked by Effectiveness

| Defence | Effectiveness | Defeats | Implementation Cost |
|---------|--------------|---------|-------------------|
| **FIDO2/WebAuthn hardware keys** | ★★★★★ | MFA reset social engineering, SIM swap, helpdesk vishing for account takeover | Medium — hardware cost + rollout |
| **Out-of-band mandatory callback** (helpdesk calls registered number) | ★★★★★ | Vishing calls — even with perfect voice clones, attacker cannot access the real employee's registered number | Low — policy + training |
| **Personal codewords** (episodic memory questions) | ★★★★☆ | Deepfake voice clones; works when attacker has complete OSINT dossier | Low — process change |
| **Multi-person approval for wire transfers** | ★★★★☆ | BEC and deepfake video conference fraud (Arup style) | Low — policy change |
| **Delay + notification on MFA enrolment** (4-hour hold + alert to real employee) | ★★★★☆ | Helpdesk vishing; real employee can interrupt attack | Low — configuration |
| **AI deepfake detection (AASIST ensemble)** | ★★★☆☆ | High-quality clone detection in clean conditions; supporting signal | Medium — development + maintenance |
| **Speaker verification (Resemblyzer)** | ★★★☆☆ | Detects wrong person; does NOT detect synthesis of correct person's voice | Low-Medium |
| **Liveness detection (commercial)** | ★★★☆☆ | IDV bypass; contact centre attacks | High — commercial licensing |
| **User awareness training** | ★★☆☆☆ | Obvious attacks; fails against high-quality deepfakes | Low — training cost |
| **Caller ID verification** | ★☆☆☆☆ | Nothing — Scattered Spider spoofs internal numbers | Low — but false security |

---

## SECTION 5: Portfolio Tool Opportunities

Three gaps with zero adequate open-source coverage, each addressable with a 2–4 week build:

---

### Tool Opportunity 1: Helpdesk Vishing Detection Add-On

**Gap:** No open-source tool monitors helpdesk ticketing systems (ServiceNow, Jira Service Management) for Scattered Spider behavioural patterns.

**Innovation:** SIEM correlation rule engine + Python service that monitors:
- Helpdesk tickets for MFA reset requests on C-suite accounts within business hours
- Caller-provided phone numbers not matching HR-registered numbers
- MFA enrolment events within 30 minutes of a helpdesk ticket for the same user
- New device enrolment + first login from non-corporate IP within 2 hours

**Detection logic:**
```python
# Correlated alert: vishing-initiated MFA reset
# Alert if: helpdesk ticket (MFA reset) + new device enrolment + 
#           first-use login from unknown IP all within 2 hours
# MITRE T1566.004 + T1098 + T1078

KQL:
IdentityInfo
| join kind=inner (
    AuditLogs | where OperationName == "Register security info"
    | where TimeGenerated > ago(2h)
  ) on UserPrincipalName
| join kind=inner (
    SigninLogs | where DeviceTrustType == "" // Unknown device
    | where TimeGenerated > ago(2h)
  ) on UserPrincipalName
| where TimeGenerated > ago(2h)
| project UserPrincipalName, MFARegistrationTime, FirstLoginFromNewDevice,
          IPAddress, DeviceDetail
```

**Build time:** 2–3 weeks  
**Portfolio angle:** Directly tied to M&S (£300M impact), documented CISA advisory, all 2025 Scattered Spider incidents

---

### Tool Opportunity 2: Real-Time Voice Deepfake Monitor

**Gap:** No open-source tool provides real-time audio deepfake detection suitable for helpdesk call integration. AASIST exists but is not packaged for production deployment.

**Innovation:** Python service that:
- Integrates with VoIP platforms via SIP/RTP tap
- Runs AASIST + Resemblyzer dual-model analysis on streaming audio
- Outputs risk score to helpdesk agent dashboard in real time
- Logs all scores for post-incident forensic analysis
- STIX 2.1 output for confirmed detections

**Core code:** The Python real-time detector in Section 4.5 above is the complete MVP.

**Build time:** 3–4 weeks  
**Dataset:** ASVspoof5 (2024) + In-The-Wild dataset (2022) + custom recordings  
**Benchmark to beat:** AASIST 0.83% EER (controlled) — build towards robustness in noisy conditions

---

### Tool Opportunity 3: Executive Voice Fingerprint Registry

**Gap:** No open-source tool helps organisations enrol and maintain voice fingerprints of executives and privileged users for comparison during helpdesk calls.

**Innovation:** Web application that:
- HR enrols executives via 60-second voice recording during onboarding
- Stores Resemblyzer 256-dimensional embeddings (not raw audio) — privacy-preserving
- Provides API endpoint: POST /verify — accepts audio chunk, returns similarity score
- Integrates with Okta/Azure AD: adds step to helpdesk workflow "Verify voice before MFA reset"
- Dashboard showing all verification events, scores, flagged calls

**Privacy architecture:** Only embedding vectors stored (256 floats), not audio — no GDPR/CCPA voice data exposure

**Build time:** 2–3 weeks  
**Stack:** Python FastAPI + Resemblyzer + PostgreSQL + React dashboard  
**Portfolio angle:** Addresses the gap explicitly documented in CISA AA23-320A; deployable as open-source alternative to commercial Pindrop/Nuance solutions

---

*Sources: CISA AA23-320A (Nov 2023, updated July 29, 2025) · FBI IC3 2024 Annual Report ($2.77B BEC losses) · Mandiant/Google GTIG "Hello Operator" (June 2025) · ReliaQuest "Scattered Spider" (June 2025) · CrowdStrike Services (July 2025) · Darktrace (July 2025) · CyberArk (July 2025) · HHS TLP:CLEAR Sector Alert (Apr 2024) · Optery "Scattered Spider and Data Brokers" (Aug 2025) · SpecOps "Service Desk Defence" (Nov 2025) · BankInfoSecurity/ReliaQuest "Logistics Firm Teardown" · CNN Arup coverage (Feb + May 2024) · World Economic Forum / Rob Greig, Arup CIO (Feb 2025) · PRMIA Case Study: Arup Deepfake Fraud · PMC/Monash University "Audio Deepfake Detection Survey" (March 2025) · Speech DF Arena arXiv:2509.02859 (Sept 2025) · Resemble AI / AASIST / Resemblyzer documentation · Intel FakeCatcher · McAfee Security Research*  
*Compiled February 2026*
