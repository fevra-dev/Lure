# Canvas-rendered credential phishing: threat analysis and detection architecture

**Canvas-based credential rendering is a real but currently unexploited phishing evasion technique that would completely bypass DOM-dependent detectors — yet remains fully detectable through keystroke listener interception and network exfiltration monitoring.** No published security research documents this specific attack vector, making it a genuine gap in both academic literature and defensive tooling. The realistic threat is not WebGPU (which requires 300–500+ lines of code for a simple form) but rather **Canvas 2D** (~155 lines vanilla JS) or **Flutter Web** (~50 lines of Dart), both of which render zero DOM input elements. Critically, even canvas-rendered phishing pages must capture keystrokes via JavaScript event listeners and exfiltrate credentials via fetch/XHR/Beacon — all of which Chrome MV3 extensions can observe through MAIN world content script injection.

---

## WebGPU has reached 82.7% global coverage but is overkill for phishing

WebGPU shipped in **Chrome 113** (April 2023) and achieved cross-browser support on **November 25, 2025**, when Google announced coverage across Chrome, Edge, Firefox, and Safari. As of February 2026, **81.26% of global browser sessions** fully support WebGPU, with an additional 1.44% partial support (Safari desktop), per caniuse.com/StatCounter data. Firefox 141+ supports WebGPU on Windows; Safari 26.0+ on macOS/iOS; Chrome/Edge on all major platforms including Android 12+. Linux support remains incomplete — Chrome 144 added Intel Gen12+ only, and Firefox Linux is Nightly-only.

The WebGPU API surface relevant to rendering follows a verbose initialization chain: `navigator.gpu.requestAdapter()` → `GPUAdapter.requestDevice()` → `canvas.getContext('webgpu')` → `GPUCanvasContext.configure()` → shader compilation via `device.createShaderModule()` with WGSL → render pipeline creation → command encoding → render pass execution. Drawing a single colored rectangle requires approximately **60–100 lines of code** including buffer setup, WGSL vertex/fragment shaders, and pipeline configuration. By comparison, Canvas 2D accomplishes the same with `ctx.fillRect(x, y, w, h)` — one line.

The critical limitation for phishing use is text rendering. **WebGPU provides zero text rendering primitives.** An attacker would need to either render text to an `OffscreenCanvas` using Canvas 2D's `fillText()` then transfer it as a GPU texture (the most common workaround, requiring ~30 additional lines), or implement SDF (Signed Distance Field) font rendering in WGSL shaders (500–1,500 lines). Canvas 2D, by contrast, offers built-in `fillText()`, `strokeText()`, and `measureText()` with full web font support in three lines of code. This complexity differential makes WebGPU a highly improbable choice for phishing — **Canvas 2D is roughly 10× simpler** for rendering a login form.

| Rendering API | Login form LOC | Text rendering | Browser support | Realistic phishing threat |
|---|---|---|---|---|
| Canvas 2D | ~155 (vanilla) / ~40 (with library) | Built-in `fillText()` | ~100% | **HIGH** |
| WebGL | ~200–400 | Glyph atlas required | ~98% | LOW |
| WebGPU | ~300–500+ | No built-in; SDF or texture transfer | ~82.7% | VERY LOW |
| Flutter Web (CanvasKit) | ~50 Dart | Built-in via Skia | ~95% (WebGL) | **HIGH** |

---

## No published research exists on pure canvas credential harvesting

After exhaustive searching across USENIX Security (2022–2026), IEEE S&P, NDSS, Black Hat, DEF CON, and major security research blogs (PortSwigger, NCC Group, Trail of Bits, Project Zero), **no published work specifically addresses rendering a phishing login form entirely within an HTML5 Canvas element to evade DOM-based detection.** No GitHub proof-of-concept repositories exist for this technique. No academic conference talk has presented it. This absence is itself a significant finding — the attack vector exists in a blind spot between well-studied canvas fingerprinting research and well-documented DOM-based phishing evasion techniques.

The closest documented technique is **Browser-in-the-Middle (BitM)** attacks, where tools like EvilnoVNC and CuddlePhish stream a real browser session to the victim via noVNC or WebRTC, rendering it as a `<canvas>` element. The foundational BitM paper (Franco et al., *International Journal of Information Security*, 2021) explicitly notes that "the victim is actually seeing an HTML5 canvas and everything the victim types in is captured by the attacker." Push Security's phishing techniques catalog documents that BitM renders pages "as a canvas element rather than showing the typical DOM structure, preventing many cloned login page-type detections from firing." However, BitM streams an entire browser session rather than constructing a fake form in canvas — a meaningfully different attack architecture with different detection surfaces (VNC/WebRTC traffic patterns, server infrastructure requirements, latency artifacts).

The only real-world canvas phishing element found was **Tycoon 2FA's canvas-rendered CAPTCHA** (2025), which uses HTML5 Canvas to render custom CAPTCHAs replacing Cloudflare Turnstile to reduce detectability. This is limited to CAPTCHA rendering, not full login forms. In the visual phishing detection literature, systems like **PhishIntention** (USENIX Security 2022), **Phishpedia** (USENIX Security 2021), and **VisualPhishNet** (ACM CCS 2020) all work on screenshots and could theoretically detect canvas-rendered phishing visually — but none have been tested against this vector.

---

## Flutter Web is the most realistic attack path, not WebGPU

The minimum-complexity canvas phishing implementation uses **Canvas 2D with vanilla JavaScript at approximately 155–200 lines of code**: `fillRect()` for input boxes, `fillText()` for labels, `drawImage()` for logos, a `keydown` event listener accumulating characters into a JS string variable, `setInterval()` for cursor blinking, coordinate-based click detection for the submit button, and `fetch()` for exfiltration. Using the **CanvasInput library** (originally built for the HTML5 game CasinoRPG), this drops to roughly **40–60 lines** — the library handles cursor blinking, text selection, copy/paste, scrolling, placeholder text, and keyboard callbacks with ~15 lines of configuration per input field.

However, **Flutter Web represents the most sophisticated and realistic threat vector**. Flutter's CanvasKit renderer (Skia compiled to WebAssembly) renders the entire application to a single `<canvas>` element via WebGL with **zero semantic DOM elements** — no `<input>`, `<form>`, `<a>`, or `<h1>` tags exist. A Flutter `TextField` widget behaves identically to a native text input from the user's perspective but produces no DOM input element. A developer familiar with Flutter/Dart could build a pixel-perfect Google or Microsoft login page in **~50–100 lines of Dart** using standard `TextField`, `ElevatedButton`, and `Container` widgets, with Material Design styling, animations, and responsive layout — all on canvas. The tradeoff is a **1.5–3MB CanvasKit WASM payload**, which is anomalous for a simple login page and serves as a detection signal.

Several additional canvas UI frameworks lower the barrier further. **CanvasUI** (from Alibaba and others) reimplements HTML/CSS tags including `<input>` and `<button>` in declarative XML rendered entirely to canvas. **Fabric.js** provides interactive on-canvas text editing with IME support. **Zebkit** offers a complete UI toolkit (text fields, buttons, checkboxes) bypassing the DOM entirely. Notably, **Konva.js** does NOT enable pure-canvas phishing — it falls back to creating a DOM `<textarea>` overlaid on the canvas for text editing, which would be detectable.

All exfiltration paths remain observable by extensions. The attacker must POST credentials via `fetch()`, `XMLHttpRequest`, `navigator.sendBeacon()`, WebSocket, or even `new Image().src` encoding — all of which a Chrome MV3 MAIN world content script can intercept by wrapping `window.fetch`, `XMLHttpRequest.prototype.open`, and the `WebSocket` constructor before page scripts execute.

---

## Chrome MV3 extensions can detect canvas phishing through five technical surfaces

**Surface 1: Canvas content readback.** Content scripts running in Chrome's isolated world **can** call `canvas.toDataURL()` and `canvas.toBlob()` on same-origin, non-tainted canvas elements. WebGPU canvases also support `toDataURL()` readback (a Chromium bug blocking this was resolved). Since a phishing page renders its own content without cross-origin images, the canvas will not be tainted. Performance is manageable: `canvas.toBlob('image/jpeg', 0.7)` on a 1920×1080 canvas takes **8–25ms asynchronously**, and at a 5-second polling interval this represents less than 0.5% CPU overhead.

**Surface 2: Event listener interception.** A MAIN world content script (`world: "MAIN"`, `run_at: "document_start"`) can wrap `EventTarget.prototype.addEventListener` before any page script executes, detecting when `keydown`, `keypress`, or `keyup` listeners are attached to `<canvas>` elements. The wrapped function posts a message to the isolated world content script via `window.postMessage()`, which relays to the extension's service worker via `chrome.runtime.sendMessage()`. The DevTools-only `getEventListeners()` API is **not available** in content scripts — prototype wrapping is the only viable approach.

**Surface 3: Canvas context type detection.** The HTML spec mandates that `getContext()` returns `null` when called with a context type different from the one already initialized. A content script can probe: try `canvas.getContext('2d')`, then `'webgl'`, then `'webgl2'`, then `'webgpu'` — whichever returns non-null is the active context. The caveat: calling `getContext()` on an uninitialized canvas **creates** the context, which is destructive. The non-destructive approach uses a MAIN world script to intercept `HTMLCanvasElement.prototype.getContext` and track which context type was originally requested.

**Surface 4: Network exfiltration monitoring.** MAIN world scripts can wrap `window.fetch` and `XMLHttpRequest.prototype.send` to observe all outbound requests, including credential POST payloads. `navigator.sendBeacon()` fires visible POST requests interceptable via `chrome.webRequest`. WebSocket connection setup is visible, though message content inspection requires constructor wrapping or the Chrome Debugger protocol.

**Surface 5: Visual analysis via offscreen documents.** Chrome MV3's Offscreen Document API enables creating a hidden HTML document with full DOM access, including **WebGPU and WebGL support**. This document can host TensorFlow.js or ONNX Runtime Web for ML inference on canvas screenshots. The proven architecture: content script captures canvas via `toBlob()` → sends to service worker → forwards to offscreen document → runs MobileNet-class inference (~20–100ms on WebGL backend) → returns classification result. Model feasibility: MobileNet V2 at ~3.5MB quantized achieves **20–30ms inference** on a 2018 MacBook Pro via WebGL.

---

## False positives concentrate in browser games, not productivity apps

The "isolated canvas" heuristic — flagging pages where a `<canvas>` element with keyboard listeners exists alongside minimal DOM structure — is **moderately reliable** but requires careful exception handling. Major productivity apps that use canvas all maintain extensive surrounding DOM: **Google Docs** (migrated to canvas rendering in 2021) retains full toolbar, menus, rulers, and sidebars with hundreds of DOM nodes; **Google Sheets** uses canvas for the grid but keeps formula bar, toolbar, and sheet tabs in DOM; **Figma** renders its design surface via WebGL/WebGPU but surrounds it with inspector panels, layer trees, and toolbars. **Monaco Editor** (VS Code web) and **CodeMirror 6** are entirely DOM-based — they do not use canvas at all, eliminating them as false positive sources.

The highest false positive risk comes from **browser games**. Unity WebGL, Godot, and PlayCanvas exports frequently present as a near-fullscreen `<canvas>` element with minimal surrounding DOM and aggressive keyboard capture — Unity's default behavior captures ALL keyboard input regardless of canvas focus. These games appear structurally similar to an isolated canvas phishing page. Differentiation strategies include detecting game engine signatures (UnityLoader.js, `.data`/`.wasm` files for Unity; Godot's characteristic JavaScript runtime), analyzing canvas content complexity (games render complex animated 3D scenes; phishing renders static 2D forms), and checking for login-context keywords in the page title and URL.

The HTTP Archive Web Almanac reports that **3.1% of desktop pages** and 2.6% of mobile pages contain a `<canvas>` element, with an estimated 1.5–2% of all pages combining canvas with keyboard input. The recommended detection heuristic stack combines six signals: (1) canvas presence with keyboard event listeners, (2) low DOM element count outside canvas (<30–50 elements), (3) login-context keywords in URL/title/surrounding DOM, (4) suspicious or newly-registered domain, (5) Canvas 2D context type (phishing is more likely to use 2D than WebGL), and (6) absence of game engine framework markers.

| Application | Uses canvas | Keyboard input | Surrounding DOM | False positive risk |
|---|---|---|---|---|
| Google Docs | ✅ | Hidden textarea | Extensive (menus, toolbar, rulers) | LOW |
| Google Sheets | ✅ | DOM overlay on edit | Extensive | LOW |
| Figma | ✅ WebGL/WebGPU | Custom handlers | Extensive (panels, inspector) | LOW |
| Excalidraw | ✅ Dual canvas | Shortcut keys | Toolbar, panels | LOW |
| Unity WebGL games | ✅ | Aggressive capture | Often minimal | **HIGH** |
| draw.io | ❌ SVG-based | N/A | N/A | N/A |
| Monaco Editor | ❌ DOM-based | Hidden textarea | N/A | N/A |

---

## Five critical user-facing signals expose canvas phishing without any extension

Even without technical detection, canvas-rendered phishing creates distinctive user-experience anomalies that reduce its effectiveness. **Password managers cannot autofill** canvas forms because no DOM `<input type="password">` exists — users expecting 1Password, Bitwarden, or Chrome's built-in autofill to populate credentials will notice its absence. **Browser autofill suggestions don't appear** — no email/username dropdown appears when clicking the "field." **Ctrl+F (Find) cannot locate text** rendered on canvas, since browser search operates on DOM text nodes. **Right-click context menus behave differently** — canvas overrides the default context menu. **Text selection is impossible** — users cannot click-and-drag to select "text" that is actually rendered pixels. These signals collectively make canvas phishing less convincing to attentive users, which partly explains why commodity phishing kits have not adopted this technique despite its DOM evasion benefits.

---

## A practical detection architecture for PhishOps Wave 16

The proposed Canvas Credential Rendering Detector should operate as a multi-signal fusion system rather than relying on any single detection surface. The architecture requires three components deployed across Chrome MV3's execution contexts.

**Component 1: MAIN world interceptor** (`document_start`). Wraps `EventTarget.prototype.addEventListener` to detect keyboard listeners on canvas elements, wraps `HTMLCanvasElement.prototype.getContext` to track context types non-destructively, and wraps `fetch`/`XHR`/`WebSocket`/`sendBeacon` to monitor exfiltration. Communicates with the isolated world script via `window.postMessage()` with a unique message source identifier to prevent spoofing.

**Component 2: Isolated world analyzer** (`document_idle`). Enumerates all `<canvas>` elements, measures DOM complexity (total element count, presence of toolbars/navigation/form elements), checks for login-context keywords, probes canvas dimensions, and — when suspicious signals converge — captures periodic canvas screenshots via `toBlob('image/jpeg', 0.7)` at 5-second intervals. Relays screenshot blobs and signal metadata to the service worker.

**Component 3: Offscreen document ML classifier.** Hosts a quantized MobileNet V2 (~3.5MB) fine-tuned on login page screenshots via TensorFlow.js with WebGL backend. Receives canvas screenshot blobs, runs inference in ~20–100ms, returns a login-form probability score. Phishpedia's approach (logo detection + brand matching via Siamese network) provides the theoretical ceiling for accuracy but is too heavy for in-browser use at ~150MB+; the pragmatic path is a lightweight two-stage pipeline — Stage 1 classifies "is this a login page?" via MobileNet, Stage 2 compares perceptual hashes against known brand login layouts.

The key architectural insight that makes this detector viable: **even when the form is invisible to the DOM, the attacker's kill chain still requires observable JavaScript behaviors**. Keystroke listeners on canvas elements, credential accumulation in JS variables, and network exfiltration via fetch/XHR are all interceptable. The existing PhishOps fetch/XHR proxy detectors remain effective against canvas phishing's exfiltration step — the new detector's role is to identify the *credential capture* step that AutofillGuard and PhishVision currently miss.

---

## Conclusion

Canvas-rendered credential phishing occupies a curious position: technically feasible today, documented nowhere in academic literature, and structurally detectable despite evading all DOM-based defenses. The threat is real but niche — Canvas 2D and Flutter Web represent practical attack paths at **155 and 50 lines of code respectively**, while WebGPU's text rendering complexity (500–1,500 lines for SDF fonts) makes it an implausible phishing technology. The absence of published research, proof-of-concept code, or observed in-the-wild deployment suggests this technique has not yet entered the commodity phishing toolkit ecosystem, likely because the loss of password manager autofill and browser autofill creates UX friction that reduces phishing success rates.

For PhishOps, the detection gap is addressable without exotic technology. The combination of MAIN world `addEventListener` interception, canvas screenshot visual analysis via an offscreen TensorFlow.js classifier, and existing fetch/XHR exfiltration monitoring covers the full kill chain. The "isolated canvas with keyboard listeners on a suspicious domain with login-context keywords" heuristic provides a high-signal, low-cost first gate before triggering computationally expensive visual analysis. Game engine whitelisting (Unity/Godot/PlayCanvas signature detection) addresses the primary false positive vector. This detector should be prioritized as a proactive defense — building it before the technique appears in the wild is significantly preferable to reacting after phishing kits adopt it.