# Browser Attack Landscape: DEF CON 32/33 & YOBB 2025
## Research-to-Tool Pipeline for the PhishOps Defensive Suite

**Compiled:** February 28, 2026  
**Source conferences:** DEF CON 32 (2024), DEF CON 33 (2025), Black Hat USA 2025, BSides SF 2025, RSAC 2025  
**Primary research group:** SquareX Year of Browser Bugs (YOBB) — 11 disclosures across 2025  
**Framing:** Every vector below is unmitigated or partially mitigated in stock browsers. Each maps to a concrete defensive tool opportunity.

---

## The Core Thesis

SquareX's Year of Browser Bugs project ran all of 2025 and produced 11 separate architectural browser vulnerability disclosures. Taken together with Tóth's DEF CON 33 extension clickjacking work, the FIDO2 CTAP research, and the passkey attacks, a single picture emerges: **the browser is now the primary attack surface, and every security tool built for the network or endpoint layer is architecturally blind to it.**

EDR has zero visibility into browser DOM manipulation. SASE/SSE can be bypassed by hosting phishing infrastructure on trusted CDN domains. DLP cannot inspect data assembled inside a browser tab using modern APIs. Passkeys — positioned as the phishing-resistant future — can be forged at the WebAuthn layer by any malicious extension or XSS payload. The browser is not one attack surface. It is a cluster of eight distinct, undefended attack surfaces operating simultaneously.

The opportunity: **a unified browser-native defensive layer** that instruments all eight surfaces from inside the extension layer, where the attacks live — not from the network layer, where defenders have been watching.

---

## Attack 1: DOM-based Extension Clickjacking
**Source:** Marek Tóth — DEF CON 33, August 9, 2025  
**Status:** 1Password and LastPass unpatched as of January 14, 2026

### What it does
A malicious page manipulates CSS/JS to make a password manager's autofill UI invisible (`body { opacity: 0 }`, `html { opacity: 0 }`, or precision overlays) while displaying a fake "Accept Cookies" button exactly where the invisible trigger sits. One click exfiltrates credit cards, PII, and login credentials including TOTP into an off-screen form.

### Why existing tools miss it
- EDR: zero browser DOM visibility
- SASE: no malicious network traffic — data is read from DOM values and POSTed to attacker CDN
- Password manager itself: the click is `event.isTrusted = true` because the user genuinely clicked

### Defensive tool: AutofillGuard (already scoped)
**New additions from this research:**
- Detect `body.opacity` and `html.opacity` manipulation in real time using `MutationObserver`
- Detect Popover API layer insertion over extension UI elements
- Flag `document.fullscreenElement` changes triggered by a user click (links to Attack 2)
- Add `event.isTrusted` audit: log all clicks that fire on elements with `opacity < 0.1`

---

## Attack 2: Fullscreen Browser-in-the-Middle (BitM)
**Source:** SquareX YOBB — May 2025; SquareX DEF CON 33 Demo Labs  
**Status:** Safari: no fix planned. Chrome/Firefox: transient notification only (dismissible)

### What it does
A phishing page embeds an attacker-controlled remote browser in a hidden popup, then triggers `document.requestFullscreen()` via a fake button click. The popup expands to cover the entire screen — including the URL bar. The victim sees what looks like a legitimate login page (it IS the legitimate login page, rendered in the attacker's remote browser), enters credentials, and the attacker captures the authenticated session. Safari is especially vulnerable because there is no clear visual indicator when the user enters fullscreen mode. Apple was notified but informed researchers there is no plan to address the issue.

### Why existing tools miss it
- The parent page URL is malicious but is invisible — covered by the fullscreen window
- EDRs have zero visibility into the browser and are proven obsolete for detecting any BitM attack. SASE/SSE detection is bypassed by hosting the parent site on trusted domains like AWS and Vercel that are commonly whitelisted.
- The credentials are entered on the *real* login page — so Safe Browsing phishing heuristics see a legitimate site

### Defensive tool opportunity: FullscreenGuard module
**Buildable today as an extension content script:**
- Monitor `document.fullscreenchange` events
- When fullscreen is triggered, check if the trigger element is in the main document or inside an iframe with a cross-origin `src`
- If fullscreen was triggered from a cross-origin iframe, inject a persistent warning banner: "⚠️ This page is running in fullscreen mode triggered by an external frame. Your URL bar is hidden."
- For Safari specifically (where the browser gives no visual cue at all): inject a persistent coloured overlay strip showing the actual parent page URL — something the browser itself refuses to do

**Detection signal for SIEM:**
```kql
// Proxy logs: user lands on page hosted on CDN, then successful auth to enterprise SaaS within 5 minutes
DeviceNetworkEvents
| where RemoteUrl has_any ("vercel.app", "netlify.app", "pages.dev", "render.com", "railway.app")
| where RemoteUrl !contains company_domain
| join kind=inner (SigninLogs | where ResultType == 0) on $left.AccountName == $right.UserPrincipalName
| where datetime_diff('minute', TimeGenerated1, TimeGenerated) between (0 .. 5)
```

---

## Attack 3: Passkeys Pwned — WebAuthn API Hijacking
**Source:** Shourya Pratap Singh, Jonathan Lin, Daniel Seetoh (SquareX) — DEF CON 33 mainstage, August 10, 2025  
**Status:** Architectural — no patch possible without changing WebAuthn spec

### What it does
Attackers can proxy WebAuthn API calls to forge passkey registration and authentication responses. The same technique applies to any website vulnerable to client-side script injection, such as XSS or misconfigured widgets.

The precise attack chain: a malicious extension (or XSS payload) intercepts `navigator.credentials.create()` during passkey registration. It generates its own keypair, sends the attacker's public key to the service provider instead of the user's, and stores the corresponding private key. On subsequent authentication, the extension intercepts `navigator.credentials.get()` and signs the challenge with the attacker's stored private key. Since the server holds the attacker's public key (substituted during registration), authentication succeeds. The legitimate user's passkey never works again — the attacker has permanently replaced it.

### Why this is architecturally unfixable at the browser level
WebAuthn was designed to be phishing-resistant against *network* proxies (AiTM). It was not designed to resist *in-process* DOM or API interception. A malicious extension runs in the same JavaScript context as the webpage. It can wrap any `window.navigator.credentials` call before the browser's internal FIDO2 layer processes it.

### What *is* defensible
- **Hardware-bound passkeys** (FIDO2 hardware keys) are NOT vulnerable — the private key never leaves the hardware token and cannot be intercepted at the software layer
- **Synced passkeys** (Google Password Manager, iCloud Keychain, 1Password) ARE vulnerable because the private key is accessible in software memory
- The attack requires either a malicious extension already installed or an XSS payload — so extension hygiene is the upstream control

### Defensive tool opportunity: PasskeyGuard / WebAuthn Monitor
**Extension-level detection:**
```javascript
// Wrap navigator.credentials to detect API interception attempts
const originalCreate = navigator.credentials.create.bind(navigator.credentials);
navigator.credentials.create = async function(options) {
    // Check if another extension has already wrapped this function
    if (navigator.credentials.create !== originalCreate) {
        reportThreat('WebAuthn API already wrapped — possible passkey interception');
    }
    // Check for known malicious extension IDs in chrome.runtime
    const suspicious = await checkInstalledExtensions();
    if (suspicious.length > 0) {
        warnUser(`⚠️ Extensions with high-risk permissions are installed: ${suspicious.join(', ')}`);
    }
    return originalCreate(options);
};
```

**This cannot fully prevent the attack** (a sufficiently privileged malicious extension loads before AutofillGuard and wraps `navigator.credentials` first). But it can: detect wrapping that happened before AutofillGuard loaded, log the anomaly, and alert the user before they complete passkey registration on a sensitive site.

**ExtHuntr** (open-source from SquareX Recon Village talk) scans installed extensions, analyses permissions, and generates risk scores. This is a ready-made prior art tool to reference and build on.

---

## Attack 4: Browser Syncjacking
**Source:** SquareX YOBB — January 2025  
**Status:** Unpatched architectural issue in Chromium sync model

### What it does
Browser Syncjacking demonstrated that malicious extensions can fully take over user profiles, the browser, and devices with minimal permissions. The technique exploits Chrome's profile sync mechanism. A malicious extension with only minimal permissions (`storage`, `identity`) can add the victim's browser profile to an attacker-controlled Google Workspace account. Once synced, the attacker's Workspace admin has read access to browsing history, saved passwords, open tabs, and can push arbitrary extensions to the victim's browser via enterprise policy — achieving full device access without any exploit.

### The permission abuse that makes it work
The extension calls `chrome.identity.getAuthToken()` (a routine permission) to get an OAuth token, then uses that token to invoke Google's People API to add the victim's account to a managed domain. Chrome's enterprise policy enforcement then gives the Workspace admin remote control.

### Defensive tool opportunity: SyncGuard module
- Monitor `chrome.identity.getAuthToken` calls from extensions that are not in an approved allowlist
- Flag when the browser's managed domain status changes (accessible via `chrome.enterprise.deviceAttributes` — if this API is suddenly callable when it wasn't before, a managed policy was applied)
- Alert: "⚠️ Your browser profile has been added to a managed organisation: [domain]. This may allow remote control of your browser. If you did not do this, remove the extension [name] immediately."

---

## Attack 5: Polymorphic Extensions
**Source:** SquareX YOBB — February 2025  
**Status:** Not addressable by Chrome Web Store review alone

### What it does
Attackers can closely imitate legitimate tools. Examples include password managers and cryptocurrency wallets. Such extensions can steal credentials while appearing trustworthy.

A polymorphic extension ships as an innocuous tool (a colour picker, a tab manager, a productivity tool). After installation and passing Web Store review, it uses the `MutationObserver` API to detect when a legitimate extension's UI appears in the DOM (e.g., Bitwarden's autofill popup). It then dynamically transforms its own UI to pixel-perfectly replicate the legitimate extension's appearance, intercepts the user's master password entry, and exfiltrates it. The extension's code never contains the phishing payload at submission time — it assembles it dynamically after install using legitimate browser APIs.

### Why Web Store review misses it
The polymorphic transformation logic uses only `MutationObserver`, `getComputedStyle`, DOM manipulation, and `fetch` — all legitimate APIs. The target extension ID (e.g., Bitwarden's `nngceckbapebfimnlniiiahkandclblb`) is hardcoded but the malicious behaviour only activates when that specific extension is detected. A static code review sees nothing unusual.

### Defensive tool opportunity: ExtensionFingerprinter
This is the most complex to build but also the most powerful gap to fill:
- Maintain a cryptographic hash database of legitimate extension DOM output signatures (what Bitwarden's popup looks like at pixel level, what 1Password's inline fill UI looks like)
- When any extension injects a UI element into the DOM, compare its rendered appearance against the known-good signatures for the extension ID it claims to belong to
- If a UI claiming to be from extension ID X renders visually differently from X's known signature → alert

An easier first implementation: detect when two extensions both insert UI into the same DOM region within 500ms of each other (the polymorphic extension races the legitimate one to overlay it).

---

## Attack 6: Browser-Native Ransomware
**Source:** SquareX YOBB — March 2025  
**Status:** No browser patch possible — uses legitimate OAuth APIs

### What it does
Via consent phishing (OAuth attacks), the attacker tricks users into granting their malicious app permission to "see, edit, create and delete all Google Drive files". With AI agents, the attacker systematically exfiltrates and deletes all files in the drive, including those shared by colleagues and customers, leaving a ransom note in place threatening to leak the data.

A second variant targets email: the malicious OAuth app requests `read, compose, send and permanently delete all email from Gmail`. The AI agent then scrapes all emails to identify every SaaS app the victim is registered with via welcome/billing emails, systematically resets passwords, logs the victim out of everything, exfiltrates all data, and uploads ransom notes to each service.

This is functionally equivalent to traditional ransomware but: runs entirely in the browser, requires no malware download, no EDR alert fires, no filesystem access, and can be triggered by a single OAuth consent click on what appears to be a legitimate productivity tool.

### Defensive tool opportunity: OAuthGuard module
- Intercept OAuth consent screens before the user clicks "Allow"
- Parse the requested permissions string (`scope` parameter in the OAuth URL)
- Flag high-risk permission combinations:
  - `drive` + `drive.file` + `drive.delete` = CRITICAL (full Drive ransomware capability)
  - `gmail.modify` + `gmail.send` + `gmail.compose` = CRITICAL (full Gmail ransomware capability)
  - `calendar` + `contacts` + `admin` = HIGH
- Present a plain-language warning: "This app is requesting permission to permanently delete all your Google Drive files. This is the full set of permissions needed to execute ransomware against your Google account. Legitimate productivity tools do not need this combination."
- Maintain a live allowlist of known-good OAuth apps (verified publisher, no destructive scopes) and blocklist of known-malicious app IDs

---

## Attack 7: Data Splicing Attacks
**Source:** Jeswin Mathai & Audrey Adeline (SquareX) — BSides SF 2025, RSAC 2025  
**Open-source tool released:** Angry Magpie  
**Status:** Bypasses all Gartner Magic Quadrant DLP vendors as of disclosure

### What it does
Data splicing attacks allow attackers to exfiltrate any sensitive file or clipboard data without detection, circumventing controls put in place by DLP vendors. They exploit newer browser features that were invented long after existing DLP solutions, meaning the data exfiltrated using these techniques is completely uninspected.

The core insight: DLP tools inspect data at the network layer (inspecting HTTP requests) or at the endpoint layer (monitoring file system reads). Data splicing assembles sensitive data *inside the browser tab* using newer APIs — `SharedArrayBuffer`, the `File System Access API`, the Clipboard API with programmatic read, `OffscreenCanvas`, `TransformStream` — and exfiltrates it in a form that DLP solutions do not recognise as a sensitive file transfer. The data arrives at the attacker's endpoint looking like a stream of innocuous API calls, not a file upload.

### Defensive tool opportunity: DataSpliceMonitor
This is a monitoring/alerting tool rather than a blocker, since the APIs themselves are legitimate:
- Instrument `navigator.clipboard.read()` calls — flag when clipboard read is performed by a page with no visible text input context
- Monitor `showSaveFilePicker` / `showOpenFilePicker` File System Access API usage on pages that are not known document editors
- Flag `SharedArrayBuffer` instantiation on pages that have no WebAssembly or multimedia use case
- Produce a "data egress risk score" per tab based on the combination of APIs used
- SIEM integration: export API usage telemetry as structured events for correlation

---

## Attack 8: Last Mile Reassembly Attacks
**Source:** SquareX — DEF CON 32 mainstage, 2024  
**Status:** Bypasses Secure Web Gateways (SWGs) architecturally

### What it does
Secure Web Gateways inspect files in transit at the network layer. Last Mile Reassembly exploits the fact that file assembly and malware activation happen *inside the browser tab* after the SWG has already passed the individual pieces as benign. The attacker sends a malicious payload in fragments across multiple HTTP requests — each fragment passes SWG inspection because no individual piece is malicious. The browser's own JavaScript (or WebAssembly) reassembles the fragments into an executable payload inside the tab's sandbox.

Variants include: splitting a PE executable across multiple image files whose pixel data encodes the binary; using the Web Workers API to reassemble in a background thread; and using the Cache API to store fragments across sessions.

### Why this is hard to defend
SWGs work on individual HTTP transactions. The reassembly logic is JavaScript running inside the browser — invisible to the SWG, invisible to the EDR (since no filesystem write occurs until the final payload executes), and looks like normal web app behaviour.

### Defensive tool opportunity: ReassemblyDetector module
- Monitor `fetch` calls that retrieve multiple resources with unusual MIME types relative to their `Content-Type` headers (e.g., images with suspiciously uniform entropy)
- Flag Web Worker creation on pages with no obvious multimedia/computational use case combined with high-frequency fetch activity
- Monitor `Cache.put()` calls for resources that don't match the page's declared assets
- Combine with domain reputation scoring: reassembly pattern + newly registered domain = HIGH alert

---

## Attack 9: AI Browser Sidebar Spoofing
**Source:** SquareX YOBB — October 2025  
**Status:** Unpatched

### What it does
The AI Browser Sidebar Spoofing attack demonstrated how malicious extensions can inject a pixel-perfect replication of AI sidebars, which provides false instructions that eventually lead to phishing, malicious file download, and even device takeover.

As AI browser sidebars (Copilot, Claude, Gemini sidebar, Perplexity) become standard enterprise tools, a malicious extension replaces or overlays the legitimate AI sidebar with an identical-looking fake. The fake sidebar can then: give false instructions ("To complete this task, please log in to [fake URL]"), exfiltrate anything the user types into it, or silently forward queries to the attacker while presenting manipulated responses. This is social engineering at the AI interaction layer — where users have the highest trust.

### Defensive tool opportunity: SidebarIntegrityChecker
- Maintain cryptographic checksums of the DOM structure, CSS class names, and iframe `src` attributes that belong to each legitimate AI sidebar extension
- On each page load, verify that elements claiming to be part of extension ID X match the known-good structure for X
- Alert when a sidebar's `src` iframe points to a domain not in the extension's declared permissions

---

## Attack 10: FIDO2 CTAP Protocol API Confusion
**Source:** Marco Casagrande & Daniele Antonioli — DEF CON 33 (paper: arxiv.org/pdf/2412.02349)  
**Status:** Affects CTAP1 (U2F) and CTAP2 regardless of transport (NFC/Bluetooth/USB)

### What it does
Issues in the CTAP protocol include the ability to force lockouts of hardware tokens, force factory reset of these tokens, fill credential storage for these tokens, and profile the underlying authenticator to potentially compromise the token or to track the user.

API confusion attacks work by sending CTAP commands with ambiguous type fields that cause the authenticator firmware to misinterpret the operation. A device asking for signature can be tricked into performing a reset. A device asking to enumerate credentials can have its storage overflowed with attacker-controlled entries. Because CTAP transports include Bluetooth and NFC, these attacks can be executed without physical access to the token — a malicious webpage with Web Bluetooth API access can send CTAP commands to a nearby YubiKey.

### Defensive tool opportunity: CTAPGuard
This operates at a different layer from the browser extension model — it requires OS-level CTAP interception. However, a browser extension component can:
- Monitor `navigator.bluetooth.requestDevice()` calls with FIDO service UUID filters
- Monitor `navigator.usb.requestDevice()` calls with FIDO HID usage page filters
- Flag when a webpage (not a system UI prompt) is directly accessing FIDO2 transports
- This is the attack surface: `navigator.bluetooth` gives a webpage direct access to CTAP protocol, which most users don't know

---

## The Unified Tool Architecture: PhishOps Browser Suite

All nine attacks above live in the same architectural space: **the browser DOM and JavaScript execution context.** This means they can all be monitored, detected, and partially blocked by a single Manifest V3 extension that instruments the right browser APIs.

### Proposed Module Stack

```
PhishOps Browser Suite (Manifest V3 Extension)
│
├── AutofillGuard          ← DOM-based Extension Clickjacking (Tóth)
│   ├── body/html opacity monitor (MutationObserver)
│   ├── form submit visibility audit
│   └── extension UI occlusion detector
│
├── FullscreenGuard        ← Fullscreen BitM (SquareX)
│   ├── fullscreenchange event monitor
│   ├── cross-origin iframe fullscreen trigger detection
│   └── persistent URL banner injection (Safari-specific)
│
├── PasskeyGuard           ← WebAuthn API Hijacking (SquareX / Allthenticate)
│   ├── navigator.credentials.create/get wrapper integrity check
│   ├── extension permission risk scorer
│   └── ExtHuntr integration (open-source, SquareX)
│
├── OAuthGuard             ← Browser-Native Ransomware (SquareX)
│   ├── OAuth scope parser and risk classifier
│   ├── destructive scope combination alerting
│   └── OAuth app allowlist/blocklist
│
├── SyncGuard              ← Browser Syncjacking (SquareX)
│   ├── chrome.identity.getAuthToken monitor
│   ├── managed domain status change detector
│   └── suspicious enterprise policy alert
│
├── ExtensionAuditor       ← Polymorphic Extensions (SquareX)
│   ├── extension permission risk scoring
│   ├── dual-extension DOM injection race detector
│   └── visual fingerprint integrity check (v2 feature)
│
├── DataEgressMonitor      ← Data Splicing (SquareX)
│   ├── clipboard API usage auditor
│   ├── File System Access API monitor
│   └── SharedArrayBuffer + high-frequency fetch detector
│
└── CTAPGuard              ← FIDO2 CTAP API Confusion (Casagrande/Antonioli)
    ├── Web Bluetooth FIDO service UUID monitor
    └── WebUSB FIDO HID usage page monitor
```

### What Goes in the Offscreen Document vs. Content Script

Following the MV3 architecture from the AutofillGuard research:

| Component | Location | Reason |
|---|---|---|
| DOM mutation observers | Content script | Must run in page context |
| OAuth scope parser | Content script | Must intercept before redirect |
| ONNX risk scoring models | Offscreen document | WASM can't load in service worker |
| Brand embedding DB | IndexedDB | Persistent, ~1MB for 200 brands |
| Threat telemetry aggregation | Service worker | Event-driven, stateless |
| User alert UI | Side panel or popup | Persistent, not subject to 30s SW timeout |

### Build Priority Order

Ranked by: (a) attack is currently unmitigated, (b) defensive tool doesn't already exist, (c) build complexity is achievable without proprietary infrastructure:

1. **OAuthGuard** — highest impact per line of code. OAuth scope parsing is pure string manipulation. Destructive scope combinations are well-defined. No ML required. Would have prevented all Browser-Native Ransomware attacks. Estimated build: 200 lines of JS.

2. **FullscreenGuard** — `fullscreenchange` event is a standard browser API. Cross-origin iframe detection is straightforward. Safari warning banner is novel and unbuilt anywhere. Estimated build: 150 lines of JS.

3. **AutofillGuard** (existing, extend) — add `body.opacity` MutationObserver and Popover API detection to existing codebase. Estimated extension: 80 lines of JS.

4. **SyncGuard** — `chrome.identity.getAuthToken` monitoring requires the extension itself to have `identity` permission (meta-irony: the attack extension has the same permission). Detect by watching managed domain status. Estimated build: 120 lines of JS.

5. **PasskeyGuard** — wrapping `navigator.credentials` is straightforward but may conflict with legitimate password managers doing the same thing. Needs careful conflict resolution. ExtHuntr is already open-source. Estimated build: 300 lines of JS + ExtHuntr integration.

6. **DataEgressMonitor** — monitoring approach only (can't block legitimate DLP-bypassing APIs). Most useful as SIEM telemetry exporter. Estimated build: 250 lines of JS.

7. **ExtensionAuditor** — permission scoring is buildable; visual fingerprinting of extension UI is complex (requires screenshot comparison, likely needs offscreen document + ML). Phase 1 (permission scoring + DOM injection race detection) is achievable. Estimated Phase 1 build: 400 lines of JS.

8. **CTAPGuard** — Web Bluetooth monitoring is possible but `navigator.bluetooth.requestDevice()` is already user-gated (browser shows a permission prompt). The defensive surface is narrower than it appears. Estimated build: 100 lines of JS for the monitoring component.

---

## The Research Flywheel: DEF CON 34 Signals to Watch

DEF CON 34 CFP is open as of this writing. Based on the trajectory of browser security research, the following attack surfaces are likely to produce new disclosures in 2026:

**MCP API exploitation in browsers.** Researchers discovered a poorly documented MCP API in the Comet browser that allows its embedded extensions to execute arbitrary local commands, including known ransomware, without explicit user permission. As more AI-native browsers ship with embedded MCP servers (Comet, Arc, Dia), the attack surface of browser-to-OS arbitrary command execution will expand. This is DEF CON 34 material.

**AI agent phishing.** Browser AI agents are trained to complete tasks rather than recognise threats, making them more exposed to attacks than human workers. Prompt injection into browser AI agents — where a malicious webpage injects instructions into the agent's context that cause it to exfiltrate data, click on phishing links, or grant OAuth permissions — has been described but not fully exploited in the wild. This is the next major vector.

**Synced passkey exfiltration at scale.** Chad Spensky's DEF CON 33 talk ("Your Passkey is Weak: Phishing the Unphishable") showed that phishing the *synchronisation fabric* (Google Password Manager, iCloud Keychain) gives an attacker access to every synced passkey simultaneously. As enterprise passkey adoption accelerates, this becomes a single point of catastrophic failure. No defensive tool exists specifically for detecting sync fabric phishing.

---

## Connecting to the Existing PhishOps Suite

| Existing Tool | New Attack Covered | Integration Point |
|---|---|---|
| FakeSender Shield (email layer) | Browser-Native Ransomware (OAuth consent sent via phishing email) | OAuthGuard flags the OAuth URL the email link resolves to |
| TPA Sentinel (redirect chain analysis) | Fullscreen BitM (parent page on trusted CDN) | FullscreenGuard adds a browser-layer detection that TPA Sentinel's network layer misses |
| PhishVision (visual similarity) | Polymorphic Extensions (fake password manager UI) | ExtensionAuditor visual fingerprinting extends PhishVision's brand-matching to extension UIs |
| AutofillGuard (DOM layer) | DOM-based Extension Clickjacking | Core module — already designed |
| All tools → PhishOps SIEM | Data Splicing, Last Mile Reassembly | DataEgressMonitor generates the browser-side telemetry that no network tool can see |

---

## Sources

- Marek Tóth: marektoth.com/blog/dom-based-extension-clickjacking/ (DEF CON 33)
- SquareX Year of Browser Bugs full recap: sqrx.com/research (December 2025)
- Passkeys Pwned slides: media.defcon.org/DEF CON 33/... Shourya Pratap Singh Jonny Lin Daniel Seetoh
- Fullscreen BitM: sqrx.com/fullscreen-bitm
- FIDO2 CTAP confusion paper: arxiv.org/pdf/2412.02349
- Your Passkey is Weak: yourpasskeyisweak.com (Chad Spensky, DEF CON 33)
- Angry Magpie (open source DLP bypass simulator): SquareX / BSides SF 2025
- ExtHuntr (open source extension scanner): SquareX / Recon Village DEF CON 33
- IDPro DEF CON 33 analysis: idpro.org/blackhat-and-def-con-2025-thoughts/
- SquareX Security Boulevard YOBB recap: securityboulevard.com (December 2025)
