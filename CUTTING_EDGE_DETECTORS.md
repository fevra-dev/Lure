# Cutting-Edge Phishing Detection — Brainstorm

Research candidates for future PhishOps waves. Each entry describes an emerging attack vector, why existing detectors are blind, and a proposed detection approach.

---

## 1. WebTransport AiTM Relay

**Attack:** Next-gen AiTM kits replace WebSocket with WebTransport (HTTP/3 QUIC datagrams) for lower-latency credential relay. WebTransport supports unreliable datagrams and multiplexed streams — ideal for real-time keystroke forwarding with no head-of-line blocking. Chrome shipped WebTransport in 2022; adoption in PhaaS kits is emerging.

**Why current detectors miss it:** WsExfilGuard wraps `WebSocket` only. WebTransport uses `new WebTransport(url)` — a different constructor with a different API surface (`.datagrams`, `.createBidirectionalStream()`).

**Detection approach:**
- Wrap `WebTransport` constructor at `document_start`
- Monitor `.datagrams.writable` for small payloads on credential pages
- Cross-reference with credential field presence (same pattern as WsExfilGuard)
- Signals: `webtransport_on_credential_page`, `datagram_keystroke_relay`, `cross_origin_webtransport`

---

## 2. WebGPU Credential Rendering

**Attack:** Phishing page renders the credential form entirely on a `<canvas>` via WebGPU/WebGL compute shaders. No DOM password fields exist — the form is drawn pixel-by-pixel. Keystrokes are captured via `keydown` events on the canvas. Bypasses all DOM-based phishing detection (PhishVision, AutofillGuard, credential field selectors).

**Why current detectors miss it:** Every PhishOps detector that checks for `input[type="password"]` or credential field selectors will find nothing. PhishVision scans DOM text — a canvas-rendered form has no text nodes.

**Detection approach:**
- Detect `<canvas>` element with `keydown`/`keypress` listeners + no visible `<input>` fields
- Check if the page title or meta tags suggest a login context
- Monitor `canvas.getContext('webgpu')` or `canvas.getContext('webgl2')` on pages with login keywords in URL/title
- Use `canvas.toDataURL()` or `ImageBitmap` screenshot to run lightweight brand detection
- Signals: `canvas_keydown_no_inputs`, `webgpu_on_login_page`, `canvas_brand_visual_match`

---

## 3. SharedArrayBuffer Covert Channel

**Attack:** Phishing page uses `SharedArrayBuffer` + `Atomics.wait/notify` between a worker and the main thread to exfiltrate credentials through a timing side-channel. The worker performs high-resolution timing measurements and encodes credential data as microsecond-level delays in cross-origin iframe communication. No network requests are made from the page — data exfiltrates entirely through cache timing.

**Why current detectors miss it:** No network-based exfiltration signal. WsExfilGuard, StyleAuditor, and fetch proxies all rely on observing outbound requests.

**Detection approach:**
- Monitor `new SharedArrayBuffer()` allocation on credential pages
- Flag `Atomics.wait()` usage in workers spawned from credential-context pages
- Check if `crossOriginIsolated` is enabled (required for SAB) on a page that shouldn't need it
- Signals: `sab_on_credential_page`, `atomics_timing_in_worker`, `unnecessary_cross_origin_isolation`

---

## 4. Speculation Rules Prefetch Hijacking

**Attack:** Attacker injects `<script type="speculationrules">` to prefetch/prerender attacker-controlled credential pages. When the user navigates (e.g., clicks "Login"), Chrome instantly activates the prerendered attacker page instead of the legitimate login. The swap is invisible — the URL bar shows the attacker's domain but the transition is instantaneous, reducing user suspicion.

**Why current detectors miss it:** Speculation Rules API is new (Chrome 109+). No detector monitors `<script type="speculationrules">` injection. The prerendered page runs in a separate browsing context that content scripts don't see until activation.

**Detection approach:**
- MutationObserver for `<script type="speculationrules">` injection
- Parse the JSON body for `prerender` rules pointing to cross-origin credential pages
- Flag when prerender targets contain login/auth/signin URL patterns
- On page activation (`document.prerendering` transition), re-run PhishVision on the new page
- Signals: `speculation_prerender_cross_origin_login`, `speculation_rules_injected`, `prerender_activation_brand_mismatch`

---

## 5. Web Environment Integrity Evasion

**Attack:** Phishing kits detect the presence of PhishOps (or other security extensions) by probing for the side-effects of API wrapping — e.g., checking if `WebSocket.toString()` returns `function ProxyWebSocket()` instead of `function WebSocket() { [native code] }`, or timing `fetch()` to detect interception overhead. If detected, the kit serves a clean page to evade analysis.

**Why current detectors miss it:** This is an anti-detection arms race. Current wrapping in WsExfilGuard, PasskeyGuard, etc. does not mask the proxy identity.

**Detection approach:**
- Harden all API wrappers: ensure `.toString()` returns `function ${originalName}() { [native code] }`
- Use `Object.defineProperty` to make wrapper properties non-enumerable
- Match `prototype`, `name`, `length` properties exactly
- Add a meta-detector: if page scripts call `.toString()` on security-sensitive APIs (`WebSocket`, `fetch`, `Notification`, `navigator.credentials`), flag as evasion-aware
- Signals: `api_toString_probe_detected`, `timing_probe_on_wrapped_api`

---

## 6. Trusted Types Bypass for DOM Injection

**Attack:** Sites with Trusted Types CSP should block `innerHTML` injection. But PhaaS kits create a default policy via `trustedTypes.createPolicy('default', { createHTML: s => s })` before the site's own policy loads, allowing arbitrary DOM injection through the "default" policy bypass.

**Why current detectors miss it:** EtherHidingGuard wraps `eval` and `document.write` but doesn't monitor Trusted Types policy creation. A kit using the default policy bypass can inject decoded blockchain payloads through `innerHTML` without triggering our eval/write hooks.

**Detection approach:**
- Wrap `trustedTypes.createPolicy()` at `document_start`
- Flag creation of a policy named `'default'` whose `createHTML` function is a passthrough (returns input unchanged)
- Check if the default policy was created before any other policy (suggests attacker, not site owner)
- Signals: `trusted_types_default_passthrough`, `early_default_policy_creation`

---

## 7. Payment Request API Credential Harvest

**Attack:** Instead of a DOM-based login form, phishing page uses the Payment Request API (`new PaymentRequest()`) to display a browser-native payment sheet that collects card numbers, addresses, and contact info. The browser-native UI has higher trust — users are more likely to submit real data.

**Why current detectors miss it:** No detector monitors `PaymentRequest` constructor or `.show()`. AutofillGuard only checks DOM `<input>` fields.

**Detection approach:**
- Wrap `PaymentRequest` constructor at `document_start`
- Check if the requesting page domain mismatches the merchant brand claimed in `PaymentDetailsInit`
- Flag `PaymentRequest.show()` on pages that also trigger PhishVision brand mismatch
- Signals: `payment_request_brand_mismatch`, `payment_request_on_non_merchant`, `payment_request_cross_origin`

---

## 8. File System Access API Exfiltration

**Attack:** After obtaining clipboard/download access through ClickFix-style social engineering, phishing page uses the File System Access API (`window.showOpenFilePicker()`, `window.showDirectoryPicker()`) to trick users into granting read access to sensitive directories (SSH keys, browser profiles, credential stores). Once granted, the page reads file contents and exfiltrates via fetch/WebSocket.

**Why current detectors miss it:** ClipboardDefender monitors clipboard. No detector monitors file system access API.

**Detection approach:**
- Wrap `showOpenFilePicker()`, `showSaveFilePicker()`, `showDirectoryPicker()`
- Flag file access requests on pages with social engineering lure patterns (same patterns as NotificationGuard fake verification)
- Monitor for reads of sensitive file paths (`.ssh/`, `Login Data`, `Cookies`, `keychain`)
- Signals: `file_picker_with_lure_context`, `sensitive_directory_access`, `file_read_then_exfil`

---

## 9. WebCodecs Deepfake Injection

**Attack:** Attacker uses WebCodecs API (`VideoEncoder`/`VideoDecoder`) to perform real-time face-swap on a legitimate camera feed before passing it to `getUserMedia`. Unlike OBS Virtual Camera (detected by WebRTCGuard), this runs entirely in-browser with no virtual camera device. The manipulated stream goes directly into a `MediaStream` via `MediaStreamTrackGenerator`.

**Why current detectors miss it:** WebRTCGuard detects virtual camera *devices* via `enumerateDevices()`. WebCodecs face-swap uses the real camera device — `enumerateDevices()` shows a legitimate hardware camera.

**Detection approach:**
- Monitor `new VideoEncoder()` and `new VideoDecoder()` creation on pages with active `getUserMedia` streams
- Check for `MediaStreamTrackGenerator` usage (synthetic track injection)
- Flag pages that both access camera and load face-mesh/face-landmark ML models (TensorFlow.js, MediaPipe)
- Signals: `webcodecs_with_camera_stream`, `synthetic_track_generator`, `face_ml_model_loaded`

---

## 10. Declarative Shadow DOM Phishing

**Attack:** Phishing page hides credential forms inside declarative Shadow DOM (`<template shadowrootmode="open">`) or closed shadow roots. DOM-walking detectors that traverse `document.querySelectorAll('input')` don't pierce shadow boundaries. The login form is invisible to naive DOM inspection.

**Why current detectors miss it:** AutofillGuard, PhishVision, LLMScorer all use `document.querySelectorAll()` which cannot cross shadow DOM boundaries.

**Detection approach:**
- After DOMContentLoaded, recursively traverse all elements' `.shadowRoot` (open) and detect `<template shadowrootmode>` for declarative shadow DOMs
- Re-run credential field detection inside each shadow root
- For closed shadow roots: wrap `Element.prototype.attachShadow()` at `document_start` to intercept `{ mode: 'closed' }` calls and retain a reference
- Signals: `credential_fields_in_shadow_dom`, `closed_shadow_root_on_login_page`, `shadow_dom_brand_mismatch`

---

## 11. Navigation API History Manipulation

**Attack:** Page uses the new Navigation API (`navigation.navigate()`, `navigation.intercept()`) to fake URL bar changes without actual navigation. The user sees `https://accounts.google.com/signin` in the URL bar while the page content is attacker-controlled. Bypasses PhishVision domain mismatch checks because `location.href` returns the spoofed URL.

**Why current detectors miss it:** ProxyGuard and PhishVision check `window.location` and URL bar — both reflect the spoofed navigation state.

**Detection approach:**
- Wrap `navigation.intercept()` and `navigation.navigate()` at `document_start`
- Compare the intercepted URL with the actual page origin (`document.origin` vs. displayed URL)
- Flag when Navigation API is used to display an auth-provider domain while the actual origin differs
- Signals: `navigation_api_url_spoof`, `intercepted_navigation_to_auth_provider`, `origin_url_mismatch`

---

## 12. Interest Groups / FLEDGE Beacon Exfiltration

**Attack:** Attacker abuses the Protected Audiences API (formerly FLEDGE) `navigator.joinAdInterestGroup()` to register the victim's browser into an "interest group" that later beacons credential data to the attacker's server during ad auctions. Exfiltration happens asynchronously through the ad auction pipeline, completely invisible to network-level monitoring of the phishing page itself.

**Why current detectors miss it:** No detector monitors the Protected Audiences API. The exfiltration happens in a different execution context (ad auction worklet) with no visible network request from the page.

**Detection approach:**
- Wrap `navigator.joinAdInterestGroup()` at `document_start`
- Flag interest group joins on credential pages or pages with phishing signals
- Check if the `biddingLogicUrl` or `trustedBiddingSignalsUrl` points to known C2 infrastructure
- Signals: `interest_group_join_on_credential_page`, `suspicious_bidding_logic_url`, `ad_auction_exfil_pattern`

---

## Priority Ranking

Based on likelihood of real-world adoption and detection gap severity:

| Priority | Candidate | Rationale |
|----------|-----------|-----------|
| 1 | Declarative Shadow DOM Phishing | Trivial to implement, defeats all DOM-walking detectors |
| 2 | Speculation Rules Prefetch Hijacking | Chrome-native, instant page swap, very convincing |
| 3 | WebTransport AiTM Relay | Natural evolution of WebSocket-based kits |
| 4 | Web Environment Integrity Evasion | Arms race — must harden existing wrappers |
| 5 | WebGPU Credential Rendering | High effort for attacker, but completely bypasses DOM detection |
| 6 | File System Access API Exfiltration | ClickFix evolution — more dangerous than clipboard |
| 7 | Navigation API History Manipulation | URL bar spoofing without iframes |
| 8 | Payment Request API Credential Harvest | Browser-native UI, high trust |
| 9 | WebCodecs Deepfake Injection | Advanced, but growing capability |
| 10 | Trusted Types Bypass | Narrow scope, only affects sites with TT CSP |
| 11 | SharedArrayBuffer Covert Channel | Exotic, requires COOP/COEP headers |
| 12 | Interest Groups / FLEDGE Beacon | Very exotic, low current adoption |
