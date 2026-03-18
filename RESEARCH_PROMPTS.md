# PhishOps — Research Prompts for Next-Gen Detectors

Structured research prompts for each candidate in [CUTTING_EDGE_DETECTORS.md](CUTTING_EDGE_DETECTORS.md). Each prompt follows the methodology from Research_Methodology.md: primary sources first, falsification-first thinking, explicit uncertainty, and cross-domain synthesis (W3C specs, browser source, threat intel, academic security research).

**How to use:** Feed each prompt to a deep-research capable model (Claude, Gemini Deep Research, Perplexity Pro) or use as a structured manual research guide. Each prompt is self-contained. Collect outputs into `Research/` directory as `{detector_name}_research.md`.

---

## 1. WebTransport AiTM Relay

### Primary Research Questions

1. What is the complete WebTransport API surface in Chrome as of 2026? Specifically: constructor signature (`new WebTransport(url, options)`), `.datagrams` (readable/writable streams), `.createBidirectionalStream()`, `.createUnidirectionalStream()`, connection state lifecycle, and error handling. Cite the W3C WebTransport spec (latest Editor's Draft) and Chrome implementation status (chromestatus.com feature entry).

2. How does WebTransport differ from WebSocket at the protocol level that would benefit an AiTM credential relay? Specifically address: (a) unreliable datagrams vs. reliable streams for keystroke forwarding, (b) multiplexed streams for parallel credential + session token exfiltration, (c) 0-RTT connection establishment reducing observable connection setup latency, (d) QUIC's UDP base vs. TCP making network-level interception different. What latency improvement does an attacker gain?

3. Is there any documented evidence (threat intel reports, PhaaS kit analysis, underground forum discussion, GitHub PoC code) of WebTransport being used in phishing infrastructure as of March 2026? Search: Mandiant, CrowdStrike, Proofpoint, Recorded Future threat reports; Google Project Zero; academic papers on USENIX Security, IEEE S&P, ACM CCS 2024-2026; GitHub for `WebTransport` + (`phish` OR `credential` OR `relay` OR `aitm`).

4. What are the browser-side constraints on WebTransport that affect detection feasibility? (a) Does Chrome require valid TLS certificates for WebTransport (unlike WebSocket which works with self-signed in some contexts)? (b) Is there a permissions/CSP directive that controls WebTransport (`connect-src`)? (c) Can a content script's `document_start` wrapper intercept `new WebTransport()` before page scripts cache it? (d) Does the `WebTransport` constructor exist in the content script isolated world, or only in the page world?

5. **Falsification question:** What legitimate uses of WebTransport exist on credential/login pages that would cause false positives? (a) Real-time chat widgets using WebTransport instead of WebSocket, (b) video conferencing on auth pages, (c) analytics platforms migrating to QUIC. How prevalent are these?

### Secondary Research Paths

- Chrome source code: search Chromium code search for `WebTransport` constructor binding to understand wrapping feasibility
- W3C WebTransport Working Group meeting notes for security considerations
- Cloudflare, Fastly, Akamai blog posts on WebTransport adoption metrics
- Compare with our existing WsExfilGuard implementation — what patterns transfer directly, what needs rethinking?

---

## 2. WebGPU Credential Rendering

### Primary Research Questions

1. What is the current state of WebGPU adoption in Chrome as of 2026? Cite chromestatus.com for shipping status, MDN for API documentation, and W3C GPU for the Web Working Group spec. Specifically: `GPUCanvasContext`, `requestAdapter()`, `requestDevice()`, render pipeline creation, and shader module compilation (`createShaderModule` with WGSL).

2. Has any security research documented canvas-based credential harvesting that bypasses DOM inspection? Search: USENIX Security, IEEE S&P, NDSS 2023-2026 proceedings; Black Hat, DEF CON presentations; Offensive Security research blogs. Specifically look for: (a) canvas-rendered login forms, (b) keyboard event capture on canvas elements, (c) WebGL/WebGPU used for phishing page rendering.

3. What technical constraints make canvas-based credential rendering detectable? (a) Can `canvas.toDataURL()` or `canvas.toBlob()` be called from a content script to screenshot the canvas for visual analysis? (b) Does Chrome's content script isolation prevent reading WebGPU canvas content? (c) What is the performance overhead of periodic canvas screenshots (every 2-5 seconds)? (d) Can you detect `keydown`/`keypress` event listeners attached to a `<canvas>` element from a content script?

4. How would an attacker build a canvas-rendered login form? (a) What open-source UI rendering libraries work on canvas/WebGPU (e.g., PixiJS, Three.js UI overlays, custom WGSL shaders)? (b) How would form submission work — the attacker must capture keystrokes via JS events and POST them, which fetch proxies can observe. (c) Would the attacker use a 2D canvas context, WebGL, or WebGPU — what's the minimum complexity path?

5. **Falsification question:** What legitimate pages render interactive UI on canvas with keyboard input? (a) Google Docs (canvas-based editor), (b) Figma, (c) game engines (Unity WebGL), (d) diagram tools. How do we distinguish these from phishing? Key differentiator: legitimate canvas apps have surrounding DOM UI, navigation, toolbars — phishing canvas forms would be a lone canvas with no other interactive DOM elements.

### Secondary Research Paths

- CanvasBlocker browser extension source code — prior art for canvas fingerprint detection
- Google Safe Browsing team publications on visual similarity detection
- PhishIntention (USENIX Security 2022) and similar visual phishing detection papers
- TensorFlow.js / ONNX Runtime Web for lightweight brand logo detection from canvas screenshots

---

## 3. SharedArrayBuffer Covert Channel

### Primary Research Questions

1. What are the exact prerequisites for `SharedArrayBuffer` availability in a browser context as of 2026? (a) `Cross-Origin-Opener-Policy: same-origin` header, (b) `Cross-Origin-Embedder-Policy: require-corp` header, (c) secure context (HTTPS). Cite the HTML spec section on cross-origin isolation. Can a phishing page served over HTTPS set these headers and gain SAB access?

2. Has any published research demonstrated credential exfiltration via SharedArrayBuffer timing side-channels? Search: Spectre/Meltdown follow-up papers (2018-2026), browser side-channel research at USENIX, IEEE S&P, CCS. Specifically: (a) the original SharedArrayBuffer high-resolution timer concern that led to browser mitigations, (b) any post-mitigation attacks that still work, (c) cross-origin data leakage via SAB.

3. What is the practical data bandwidth of a SAB timing covert channel? Can it actually exfiltrate a username + password (50-100 bytes) in a reasonable time (< 30 seconds)? What error rate would be expected? Cite any empirical measurements from academic papers.

4. **Falsification question:** Is this attack vector actually practical for phishing, or is it a theoretical curiosity? (a) The attacker must control both the main page and a cross-origin iframe — does this add enough complexity to be impractical? (b) COOP/COEP headers break many legitimate third-party embeds — would a phishing page with these headers look broken? (c) Are there simpler exfiltration methods available to an attacker who already controls the page?

5. What is the realistic threat timeline? Given that (a) Chrome reduced SAB timer resolution, (b) site isolation mitigates some cross-origin attacks, and (c) simpler exfiltration methods exist — should this detector be deprioritized? What evidence would change this assessment?

### Secondary Research Paths

- Chrome Security team blog posts on SAB mitigations (2018-2026)
- Spectre.js and related browser-based speculative execution attack papers
- Web Platform Tests for SharedArrayBuffer — understand browser behavior edge cases

---

## 4. Speculation Rules Prefetch Hijacking

### Primary Research Questions

1. What is the complete Speculation Rules API specification as of 2026? Cite the WICG Speculation Rules spec. Document: (a) JSON schema for `<script type="speculationrules">`, (b) `prefetch` vs. `prerender` semantics, (c) `source: "document"` vs. `source: "list"` rules, (d) `eagerness` settings, (e) `expects_no_vary_search` parameter. What restrictions does Chrome place on prerender targets?

2. Can Chrome's Speculation Rules prerender cross-origin pages? Cite chromestatus.com and Chrome developer documentation. Specifically: (a) are cross-origin prerenders currently allowed or restricted? (b) what security checks (CSP, COEP, referrer policy) apply to prerendered pages? (c) does the prerendered page's content script environment get PhishOps content scripts injected?

3. **Critical question:** When a prerendered page activates (user navigates to it), do MV3 content scripts from `manifest.json` get injected into the activated page? Or does the prerendered page bypass content script injection because it was rendered in a different browsing context? This determines whether existing PhishOps detectors even see the attack page. Cite Chromium source or Chrome Extensions documentation.

4. Has any security research documented Speculation Rules abuse for phishing or other attacks? Search: Chrome security bugs (bugs.chromium.org), academic papers, security researcher blogs (2023-2026). Also search for: Speculation Rules + security + phishing on Google Scholar and arXiv.

5. Can a content script detect and parse `<script type="speculationrules">` elements? (a) Via MutationObserver at `document_start`, (b) via `document.querySelectorAll('script[type="speculationrules"]')` at `document_idle`, (c) can the JSON body be read via `.textContent`? (d) Can we modify or remove the speculation rules element to block the prerender?

6. **Falsification question:** What is the legitimate adoption of Speculation Rules? (a) Which major sites use it (Google Search, Wikipedia, etc.)? (b) How common are cross-origin prerender rules in legitimate use? (c) Would blocking/flagging all speculation rules with cross-origin prerender targets produce unacceptable false positive rates?

### Secondary Research Paths

- Chrome DevRel documentation on Speculation Rules (web.dev/speculation-rules)
- Chromium source: `third_party/blink/renderer/core/speculation_rules/`
- Chrome Extensions content script injection lifecycle documentation
- Barry Pollard's (Google) talks on Speculation Rules at Chrome Dev Summit

---

## 5. Web Environment Integrity / Anti-Detection Evasion

### Primary Research Questions

1. What specific fingerprinting techniques do PhaaS kits currently use to detect security extensions? Search: (a) PhaaS kit source code analysis from Mandiant, CrowdStrike, Proofpoint, Sekoia reports (2024-2026), (b) GitHub repositories of known phishing kits (Evilginx, Modlishka, Muraena source code), (c) underground forum discussions (documented in threat intel reports). Specifically: do kits check `Function.prototype.toString()` on wrapped APIs? Do they time API calls? Do they check for extension-injected DOM elements?

2. How does Chrome's MV3 content script isolation model affect API wrapping detectability? (a) When a content script wraps `window.fetch` in the page world (via `document_start`), does `Function.prototype.toString.call(fetch)` return `[native code]` or reveal the wrapper? (b) Can we use `world: "MAIN"` in manifest.json content_scripts to inject directly into the page world? (c) What are the security implications of main-world injection?

3. What techniques exist for making JavaScript API wrappers indistinguishable from native implementations? (a) `Proxy` objects with `toString` traps, (b) `Object.defineProperty` with non-enumerable/non-configurable descriptors, (c) matching `.name`, `.length`, `.prototype` exactly, (d) using `Reflect` API for transparent proxying. Cite browser compatibility data for each approach.

4. What academic research exists on detecting API hooking in browser contexts? Search: USENIX Security, IEEE S&P, WWW/WebConf proceedings for "JavaScript API hooking detection" or "browser extension fingerprinting."

5. **Falsification question:** Is perfect stealth achievable, or is this an inherently losing arms race? (a) Can timing side-channels always detect overhead from wrapping? (b) Does Chrome's extension architecture fundamentally leak information about installed extensions? (c) Would it be better to accept detectability and focus on making the attacker's evasion itself a detection signal (meta-detection)?

### Secondary Research Paths

- Google Web Environment Integrity proposal (withdrawn) — what security model did it propose?
- CRXcavator and Extension Monitor tools — how do they fingerprint extensions?
- Nickcool's research on extension detection via web accessible resources probing
- Z-WASP and similar PhaaS evasion documentation from threat intel vendors

---

## 6. Trusted Types Bypass for DOM Injection

### Primary Research Questions

1. What is the Trusted Types API specification as of 2026? Cite the W3C Trusted Types spec. Document: (a) `trustedTypes.createPolicy()` signature and behavior, (b) the "default" policy semantics — what happens when a default policy exists? (c) what DOM sinks are protected (innerHTML, outerHTML, document.write, eval, script.src, etc.)? (d) how does the `require-trusted-types-for 'script'` CSP directive work?

2. What is the current adoption rate of Trusted Types? (a) Which major sites deploy Trusted Types CSP? (Google properties, GitHub, etc.) (b) What percentage of the Alexa/Tranco top 10K use Trusted Types? Search: HTTP Archive data, Scott Helme's security headers reports, Chrome Platform Status usage metrics.

3. Can an attacker's inline script create a default policy before the site's own scripts load? (a) What is the script execution order for inline `<script>` vs. deferred/async scripts? (b) If the attacker injects via a compromised CDN or DOM XSS, can they race the site's policy creation? (c) Does Chrome enforce any restrictions on who can create the default policy?

4. Has any published research documented Trusted Types bypass via default policy abuse? Search: Google Security blog, Chrome Vulnerability Rewards Program, academic papers, PortSwigger Web Security Academy.

5. **Falsification question:** Is this attack surface too narrow to justify a dedicated detector? (a) Only sites with Trusted Types CSP are affected (small percentage), (b) the attacker needs a way to inject script before the site's own policy — which usually means they already have XSS, (c) if they have XSS, Trusted Types bypass is just one of many things they can do. Is this a detector or a hardening recommendation?

### Secondary Research Paths

- Chromium source: `third_party/blink/renderer/core/trustedtypes/`
- Google's Trusted Types documentation and migration guides
- Krzysztof Kotowicz's (Google) publications on Trusted Types security properties

---

## 7. Payment Request API Credential Harvest

### Primary Research Questions

1. What is the Payment Request API specification as of 2026? Cite W3C Payment Request API spec. Document: (a) `new PaymentRequest(methodData, details, options)` constructor, (b) `.show()` and `.canMakePayment()`, (c) `PaymentResponse` object — what data fields are returned (card number, billing address, email, phone)? (d) What payment methods are supported (basic-card, Google Pay, Apple Pay, etc.)?

2. What security controls does Chrome enforce on Payment Request API usage? (a) Is HTTPS required? (b) Does the user see the requesting origin in the payment sheet? (c) Can a page spoof the merchant name displayed in the sheet? (d) Does Chrome show a security warning if the requesting domain doesn't match a registered merchant?

3. Has any security research documented Payment Request API abuse for phishing? Search: academic papers, Chrome bug tracker, security researcher blogs. Also search for: legitimate merchant impersonation via payment sheets.

4. What data can an attacker harvest through the Payment Request API that they couldn't get through a DOM form? (a) Saved payment methods from Chrome autofill, (b) complete billing addresses, (c) phone numbers and emails. Is the trust differential (browser-native UI vs. page form) sufficient to increase conversion rates?

5. **Falsification question:** Does Chrome's UI make the requesting origin sufficiently visible that users would notice a mismatch? (a) Test on current Chrome — what does the payment sheet look like? (b) Is the origin displayed prominently or buried? (c) Would PhishVision brand mismatch + PaymentRequest be more effective than PaymentRequest alone as a signal?

### Secondary Research Paths

- Chrome DevTools payment handler debugging documentation
- W3C Web Payments Working Group security considerations
- EMVCo 3-D Secure interaction with Payment Request API

---

## 8. File System Access API Exfiltration

### Primary Research Questions

1. What is the File System Access API specification as of 2026? Cite the WICG File System Access spec. Document: (a) `showOpenFilePicker()`, `showSaveFilePicker()`, `showDirectoryPicker()` — parameters, return types, (b) `FileSystemFileHandle.getFile()` and `.createWritable()`, (c) `FileSystemDirectoryHandle.entries()`, (d) permission model — does the user see the directory path before granting? Can the page request a specific starting directory?

2. What sensitive files exist on typical desktop systems that an attacker would target? Map by OS: (a) **macOS:** `~/.ssh/`, `~/Library/Keychains/`, `~/Library/Application Support/Google/Chrome/Default/Login Data`, `~/Library/Cookies/`; (b) **Windows:** `%USERPROFILE%\.ssh\`, `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`, `%APPDATA%\`, Windows Credential Manager files; (c) **Linux:** `~/.ssh/`, `~/.config/google-chrome/Default/Login Data`, `~/.gnupg/`.

3. What permissions/prompts does Chrome show when a page calls `showDirectoryPicker()`? (a) Does the user see a native file picker? (b) Can the page pre-select or suggest a directory? (c) Once granted, can the page recursively read all files without additional prompts? (d) Does the permission persist across page navigations or only for the session?

4. Has any documented attack used the File System Access API for data theft? Search: Chrome security bugs, NCC Group / Trail of Bits browser security audits, Nickcool/AlteredSecurity research, conference presentations.

5. **Falsification question:** (a) Is the user prompt sufficient protection — would a social-engineered user really grant directory access? (b) Compare with ClickFix (which tricks users into running PowerShell) — if users will paste and run commands, they'll likely grant file access too. (c) Are there pages that legitimately need `showDirectoryPicker()` (code editors like VS Code web, photo managers)? How do we distinguish?

### Secondary Research Paths

- Chrome permission model documentation for File System Access
- VS Code for the Web source code — how does it use File System Access API?
- SquareX "Year of Browser Bugs" research (2025) — any File System Access findings?

---

## 9. WebCodecs Deepfake Injection

### Primary Research Questions

1. What is the WebCodecs API specification as of 2026? Cite the W3C WebCodecs spec. Document: (a) `VideoEncoder`/`VideoDecoder` — constructor, `configure()`, `encode()`, `decode()`, (b) `VideoFrame` — creation from canvas, ImageBitmap, or decoded output, (c) `MediaStreamTrackGenerator` — creating synthetic `MediaStreamTrack` from `VideoFrame` objects, (d) `MediaStreamTrackProcessor` — consuming a real camera track as `VideoFrame` objects.

2. What is the current state of real-time face-swap technology that runs in-browser? (a) TensorFlow.js face-mesh/face-landmarks-detection models — inference speed on consumer GPU? (b) MediaPipe Face Mesh — can it run in a web worker? (c) Open-source face-swap implementations (DeepFaceLive, SimSwap, FaceFusion) — have any been ported to browser/WebGPU? (d) What is the minimum hardware requirement for real-time (30fps) browser-based face swap?

3. What is the realistic threat timeline for browser-based deepfake injection? (a) Can current consumer hardware (M1 MacBook, mid-range Windows laptop) run real-time face swap in Chrome? (b) What quality level is achievable? (c) Compare with OBS Virtual Camera (which WebRTCGuard detects) — what's the quality and latency delta?

4. Can a content script detect `MediaStreamTrackGenerator` usage? (a) Is the constructor available in the page world for wrapping? (b) When a `MediaStreamTrackGenerator` track is passed to `RTCPeerConnection.addTrack()`, is it distinguishable from a real camera track? (c) Can we detect the processing pipeline (camera → VideoFrame → face swap → VideoFrame → generator → MediaStream) by measuring frame timing jitter?

5. **Falsification question:** (a) Is browser-based face swap good enough in 2026 to fool a human in a live video call? (b) Would attackers prefer native apps (OBS + DeepFaceLive) which are already effective? (c) The browser attack surface is more constrained (no GPU memory sharing, limited VRAM) — is native always better?

### Secondary Research Paths

- Google MediaPipe documentation and performance benchmarks
- DeepFaceLive GitHub — architecture and hardware requirements
- USENIX Security / IEEE S&P papers on deepfake detection (2023-2026)
- W3C MediaStream Recording spec — potential for watermarking real vs. synthetic tracks

---

## 10. Declarative Shadow DOM Phishing

### Primary Research Questions

1. What is the Declarative Shadow DOM specification? Cite the HTML spec section on `<template shadowrootmode>`. Document: (a) `shadowrootmode="open"` vs. `shadowrootmode="closed"` behavior, (b) when the shadow root is created (at parse time, before DOMContentLoaded), (c) can content scripts access open declarative shadow roots via `element.shadowRoot`? (d) for closed shadow roots, is there any way to access the shadow tree after creation?

2. Can `Element.prototype.attachShadow()` be wrapped at `document_start` to intercept imperative shadow root creation? (a) Does wrapping before page scripts prevent cached references? (b) What about declarative shadow roots — they're created by the HTML parser, not by JS — does wrapping `attachShadow` catch them? (c) Can we use `document.querySelectorAll('template[shadowrootmode]')` to find declarative shadow roots, or are the `<template>` elements removed after shadow root creation?

3. What is the current adoption of Shadow DOM on login pages? (a) Do any major auth providers (Google, Microsoft, Apple, Okta) use Shadow DOM in their login forms? (b) What component frameworks use Shadow DOM by default (Lit, Polymer, Stencil, Angular with ViewEncapsulation.ShadowDom)? (c) If major auth providers use Shadow DOM, our detector would need to handle legitimate shadow-DOM login forms without false positives.

4. **Critical implementation question:** How do we recursively find credential fields across all shadow roots? (a) Write a recursive `querySelectorAllDeep()` that walks `element.shadowRoot` for open roots, (b) for closed roots created via wrapped `attachShadow()`, maintain a WeakMap of elements → shadow roots, (c) what is the performance cost of recursive shadow DOM traversal on a complex page?

5. **Falsification question:** (a) Is Shadow DOM actually used by any known phishing kits today? Search PhaaS kit source code analyses. (b) Would a phishing kit author actually benefit from Shadow DOM, or is it unnecessary complexity when they already control the page? (c) The main detection value might be defensive — ensuring our existing detectors aren't blind to shadow DOM — rather than a new attack-specific detector.

### Secondary Research Paths

- Lit framework documentation — Shadow DOM usage patterns
- Chrome DevTools Shadow DOM inspection capabilities
- open-wc.org testing recommendations for Shadow DOM components
- Existing `querySelectorDeep` or `deepQuerySelector` npm packages

---

## 11. Navigation API History Manipulation

### Primary Research Questions

1. What is the Navigation API specification as of 2026? Cite the WICG Navigation API spec. Document: (a) `navigation.navigate(url, options)`, (b) `navigation.intercept({ handler })` — what does interception allow? Can the handler prevent actual navigation while updating the URL bar? (c) `navigation.entries()` and `navigation.currentEntry`, (d) `NavigateEvent` properties.

2. **Critical question:** Does `navigation.intercept()` actually allow URL bar spoofing? (a) Can a page intercept a navigation to `https://accounts.google.com` and prevent the actual navigation while updating the URL bar? (b) Or does interception only work for same-origin navigations? (c) Does Chrome enforce same-origin restrictions on `navigation.navigate()`? Cite the spec's security considerations section.

3. If cross-origin URL bar spoofing is NOT possible via Navigation API (likely), what same-origin manipulation IS possible that could aid phishing? (a) Fake navigation within a compromised site (e.g., WordPress) to make the URL look like a login page, (b) history manipulation to hide the attack path, (c) SPA-style navigation that bypasses PhishOps content script re-injection.

4. Has any security research documented Navigation API abuse? Search: Chrome security bugs, WICG Navigation API GitHub issues (security-labeled), academic papers.

5. **Falsification question:** (a) If cross-origin URL bar spoofing isn't possible, is this detector candidate actually viable? (b) Same-origin manipulation is already possible with History API (`pushState`/`replaceState`) — does Navigation API add new attack surface beyond what already exists? (c) Should we deprioritize this based on browser security model constraints?

### Secondary Research Paths

- Chrome's same-origin policy enforcement for Navigation API
- Comparison with History API attack surface
- Jake Archibald's (Google) Navigation API explainer and security discussion

---

## 12. Interest Groups / FLEDGE Beacon Exfiltration

### Primary Research Questions

1. What is the Protected Audiences API (formerly FLEDGE) specification as of 2026? Cite the WICG Protected Audiences spec. Document: (a) `navigator.joinAdInterestGroup()` — parameters, permissions, (b) what data is stored with the interest group? (c) `navigator.runAdAuction()` — what data flows to the bidding logic URL? (d) `reportWin()`/`reportResult()` — what data can be beaconed to external servers?

2. What data from the joining page is accessible inside the ad auction worklet? (a) Can the interest group's `userBiddingSignals` carry arbitrary data from the phishing page? (b) Can the `biddingLogicUrl` script access this data and beacon it to a third-party server? (c) What are the network access restrictions inside the bidding worklet (k-anonymity, trusted server requirements)?

3. What are Chrome's privacy restrictions that might prevent this attack? (a) k-anonymity requirements on ad requests, (b) network partitioning of auction worklets, (c) the `Permissions-Policy: join-ad-interest-group` header — who can grant this permission? (d) Does Chrome restrict `joinAdInterestGroup` to specific contexts?

4. **Falsification question:** (a) Is the Protected Audiences API restrictive enough that credential exfiltration via auction beacons is practically impossible? (b) The API is designed with privacy sandboxing in mind — Google has specifically tried to prevent arbitrary data exfiltration. (c) Is the bandwidth through auction beacons sufficient to exfiltrate even a username/password? (d) Given the complexity vs. simpler alternatives (fetch, WebSocket, even CSS exfil), would any rational attacker choose this path?

5. What is the adoption trajectory of Protected Audiences? (a) Has Chrome deprecated or restricted the API since the Privacy Sandbox changes? (b) If the API is being rolled back or restricted, this detector candidate may become irrelevant.

### Secondary Research Paths

- Chrome Privacy Sandbox documentation and timeline
- Google's Protected Audiences API GitHub repository issues
- W3C PATCG (Private Advertising Technology Community Group) meeting notes
- EFF and other privacy advocacy analysis of Protected Audiences data flows

---

## Research Execution Checklist

For each detector, ensure the research covers:

- [ ] **API specification** — primary source (W3C spec, WICG proposal, Chrome implementation)
- [ ] **Browser constraints** — same-origin policy, permissions, CSP interaction, content script isolation
- [ ] **Threat evidence** — real-world attack documentation or PoC code
- [ ] **Detection feasibility** — can a content script at `document_start` intercept the API?
- [ ] **False positive surface** — legitimate uses that would trigger false alerts
- [ ] **Signal design** — 3-5 weighted signals following PhishOps scoring model
- [ ] **Implementation complexity** — estimated LoC, new API wrappers needed, testing approach
- [ ] **Falsification outcome** — explicit assessment of whether this detector is worth building

### Source Priority Order

1. W3C / WICG specifications (primary, normative)
2. Chromium source code and chromestatus.com (primary, implementation)
3. Chrome security team publications and bug tracker (primary, security model)
4. Academic papers from top-4 security venues: USENIX Security, IEEE S&P, ACM CCS, NDSS (peer-reviewed)
5. Vendor threat intel reports: Mandiant, CrowdStrike, Proofpoint, Recorded Future, Sekoia (curated, but vendor-biased)
6. Security researcher blogs and conference talks (expert opinion, variable quality)
7. Underground forum analysis (documented in vendor reports, not direct access)
