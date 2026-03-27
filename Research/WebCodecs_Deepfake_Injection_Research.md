# WebCodecs deepfake injection: threat assessment for PhishOps

**Browser-based face-swap injection is a pre-emergent threat that does not justify a dedicated detector in 2026, but lightweight sentinel hooks should ship now.** No deep-learning face-swap pipeline runs client-side in any browser today—the compute gap between WebGPU and native CUDA (~5×) keeps real-time quality face-swapping firmly in the domain of native tools like OBS + DeepFaceLive. However, the forensic stealth advantage of browser-based injection (no virtual camera driver, no process footprint, bypasses `enumerateDevices()` detection entirely) makes this a high-value future attack vector that Scattered Spider–class actors will pursue once the performance barrier falls. The correct move is not a standalone "DeepfakeGuard" detector but a thin compound-signal monitor integrated into WebRTCGuard, deployable in **Wave 22–23**, that wraps `MediaStreamTrackGenerator` and `MediaStreamTrackProcessor` constructors and flags synthetic tracks fed to `RTCPeerConnection`.

---

## The WebCodecs API gives attackers all the primitives they need

The W3C WebCodecs specification remains a **Working Draft** (latest: January 29, 2026), managed by the Media Working Group under editors Paul Adenot (Mozilla) and Eugene Zemtsov (Google). Despite missing its original Q2 2025 Recommendation target, the API enjoys **~95.5% global browser coverage**: Chrome 94+, Edge 94+, Firefox 130+, and Safari 26+ (partial support since Safari 16.4). The core classes—`VideoEncoder`, `VideoDecoder`, and `VideoFrame`—are stable and interoperable across browsers.

The critical attack surface lies in the **Insertable Streams APIs** defined in the companion "MediaStreamTrack Insertable Media Processing using Streams" Working Draft (January 15, 2026). Two APIs enable the deepfake pipeline:

`MediaStreamTrackProcessor` consumes a real camera's `MediaStreamTrack` and outputs a `ReadableStream<VideoFrame>`, giving JavaScript per-frame pixel access. `MediaStreamTrackGenerator` accepts a `WritableStream<VideoFrame>` and produces a synthetic `MediaStreamTrack` that can be passed to any consumer—including `RTCPeerConnection.addTrack()`. Together, these APIs create a complete frame-level interception pipeline: **camera → decompose → transform → recompose → WebRTC**.

There is a significant interoperability wrinkle. `MediaStreamTrackGenerator` is **non-standard and Chrome/Edge-only** (available since Chrome 94, still shipping). MDN explicitly marks it as non-standard and recommends its replacement, `VideoTrackGenerator`, which is the W3C-specified version. `VideoTrackGenerator` is **worker-only**, **video-only**, and currently ships only in Safari 18+. Chrome has not yet implemented the standard version. Firefox plans to ship the standard API around mid-2026. For threat modeling purposes, the Chrome-only `MediaStreamTrackGenerator` is the relevant API because Chrome dominates enterprise desktop browsing and is the likely attack target.

The `VideoFrame` constructor accepts `HTMLCanvasElement`, `ImageBitmap`, `OffscreenCanvas`, raw `ArrayBuffer` pixel data, or another `VideoFrame` as input. This means any pixel manipulation pipeline—canvas-based, WebGPU compute, or ONNX model output—can produce frames that feed directly into the synthetic track generator. Codec support spans **VP8, VP9, H.264/AVC, AV1, and HEVC** (platform-dependent), with `VideoEncoder.isConfigSupported()` providing runtime capability detection.

---

## Browser face-swap in 2026: the building blocks exist but the pipeline doesn't

The most critical finding from this research is that **no deep-learning face-swap pipeline runs entirely client-side in a browser as of early 2026**. This is not for lack of components—it is a compute budget problem.

Face detection and landmark tracking run excellently in-browser. MediaPipe Face Mesh delivers **478 landmarks at 5–15ms per frame** on desktop hardware via WebGL or WebGPU, comfortably exceeding 30fps. TensorFlow.js BlazeFace achieves ~5ms detection. These are solved problems. The bottleneck is the face-swap model itself. The dominant open-source swap model, `inswapper_128.onnx` (used by Deep-Live-Cam, FaceFusion, and roop), is **554MB** and requires a multi-model pipeline: face detection (~10–50MB) → face embedding extraction via ArcFace/buffalo_l (~100–200MB) → identity swap → optional face enhancement (~100–500MB). Total payload: **700MB–1.3GB**.

ONNX Runtime Web with the WebGPU execution provider can theoretically load and run `inswapper_128.onnx`. Microsoft's benchmarks show **19× speedups over WASM** for models like Segment Anything. But the persistent **~5× overhead versus native CUDA** means the swap model's native inference time of ~30–50ms balloons to **200–500ms in-browser**. Combined with the rest of the pipeline, this yields **2–5fps**—far below the 30fps needed for a convincing live video call.

WebGPU is necessary but insufficient. While it enables transformer-class models to run in browsers (Llama 3.1 8B quantized at 41 tokens/second on M3 Max), the face-swap use case demands both low latency *and* high throughput on a model architecture that wasn't designed for browser deployment. No one has published a working browser demo of identity-preserving face swap. The only in-browser "face swap" implementations are **geometric warping tools** (clmtrackr's Delaunay triangulation demo, jeelizFaceFilter AR overlays)—technically face manipulation but nowhere near DeepFaceLive quality.

The most plausible near-term path to browser-viable face swap would be a **purpose-built, quantized model** (~50–100MB, INT8/FP16) optimized specifically for WebGPU inference, targeting 10–15fps on high-end consumer GPUs. This does not exist yet. All existing real-time face-swap products are either native desktop applications (DeepFaceLive, Deep-Live-Cam, FaceFusion, Swapface) or cloud-processed web apps (Akool, Wefaceswap).

---

## Real-world deepfake attacks establish the threat class is active

The question is not whether deepfake video call attacks happen—they demonstrably do—but whether browser-based delivery adds meaningful risk over native tools.

The **Arup/Hong Kong case** (January 2024) remains the landmark incident: a finance employee authorized **$25.6 million** across 15 wire transfers after joining a video call where multiple senior executives were AI-generated deepfakes. The employee was initially skeptical of the phishing email but was convinced by the video call. Arup's CIO Rob Greig subsequently demonstrated he could create a real-time deepfake of himself in ~45 minutes using open-source software.

**Scattered Spider** (UNC3944/Octo Tempest) continues to evolve. The CISA/FBI advisory updated July 29, 2025 confirms increasingly sophisticated social engineering including AI-assisted impersonation. The group's attacks on MGM Resorts (~$100M losses, 2023), Marks & Spencer (~£300M profit impact, April 2025), Co-op, and Harrods all began with helpdesk social engineering calls. Mandiant's CTO Charles Carmakal reports "increased usage of AI-generated voice and video to impersonate legitimate employees." The FBI reports voice cloning fraud surged **over 400% in 2025**.

FinCEN Alert FIN-2024-Alert004 (November 2024) explicitly flags **"use of a third-party webcam plugin during a live verification check"** as a deepfake red flag, with a dedicated SAR filing keyword "FIN-2024-DEEPFAKEFRAUD." Deloitte projects GenAI-enabled fraud losses reaching **$40 billion in the US by 2027**.

The current confirmed attack chain uses native tools: DeepFaceLive or Deep-Live-Cam processes webcam video in real time (requiring **RTX 3060+** for 25–30fps at 640×480), OBS captures the output, and OBS Virtual Camera presents it as a system camera device. This pipeline is detectable: OBS Virtual Camera registers via DirectShow/CoreMediaIO and exposes its label through `navigator.mediaDevices.enumerateDevices()`. While label renaming tools exist (OBS VCam Changer, registry edits), metadata-based virtual camera detection achieves strong accuracy according to a December 2025 paper by Kurmankhojayev et al.

---

## Why browser-based injection is the logical next step for attackers

The forensic advantage of browser-based injection over native tools is stark and represents the core strategic concern:

A `MediaStreamTrackGenerator` track **does not appear in `enumerateDevices()`**. It creates an in-memory synthetic track with no system-level device registration, no driver, no process. The resulting `MediaStreamTrack` shows `kind: "video"` and `readyState: "live"`—identical to a real camera track—but with **empty `label`**, **no `deviceId` in `getSettings()`**, and **empty `getCapabilities()`**. For a targeted attack (Scattered Spider calling a helpdesk), the absence of OBS.exe in task manager, no virtual camera driver in the registry, and no suspicious software installation is operationally significant.

The most likely **near-term bridge attack** (achievable in 2026 by state-level actors, 2027 by criminal groups) is a **hybrid approach**: a compromised browser extension captures frames via `MediaStreamTrackProcessor`, sends them to a remote GPU server for deepfake processing, and receives manipulated frames back to inject via `MediaStreamTrackGenerator`. This eliminates the browser-side compute constraint while maintaining full forensic stealth. SquareX's 2025 "Year of Browser Bugs" research demonstrated the foundational attack primitives: Browser Syncjacking (malicious extensions gain full browser/device control with minimal permissions), Polymorphic Extensions (extensions morph to impersonate legitimate tools), and supply-chain compromise (the Cyberhaven incident, December 2024). The `fippo/dynamic-getUserMedia` Chrome extension already demonstrates `getUserMedia` interception and `enumerateDevices` override as a proof of concept.

Against this, three factors constrain the threat timeline. First, **WebGPU's ~5× overhead versus CUDA** makes client-side-only face swap non-viable at call quality in 2026. Second, attackers currently have **no strong incentive to migrate** from native tools that work well—the shift will accelerate only when virtual camera detection becomes widespread in enterprise platforms. Third, the hybrid server-relay approach introduces **network latency** that may produce visible artifacts in live conversation.

---

## Detection from Chrome MV3 is technically strong

A Chrome MV3 extension with a **MAIN-world content script injected at `document_start`** can reliably detect every component of the deepfake injection pipeline. This is the single most important technical finding for PhishOps.

**Constructor interception** works via the `Proxy` construct trap on `window.MediaStreamTrackGenerator`, `window.MediaStreamTrackProcessor`, `window.VideoEncoder`, `window.VideoDecoder`, and `window.VideoFrame`. The MAIN-world script runs before page JavaScript, allowing the extension to save original constructor references in a closure before any attacker code executes. The proven `webrtc-externals` extension by Oleg Obukhov (Oleg Obukhov, fippo) demonstrates this exact pattern for `RTCPeerConnection` prototype method wrapping in production.

The **strongest detection signal is compound pipeline analysis**: simultaneous `getUserMedia()` + `MediaStreamTrackProcessor` creation + `MediaStreamTrackGenerator` creation + the generator's track passed to `RTCPeerConnection.addTrack()`. No legitimate application needs this exact combination unless it is performing real-time video processing injected into a WebRTC call—which is precisely the deepfake pipeline. Individual signals that reinforce the compound detector include:

- **Synthetic track properties**: `track.label === ""`, absent `deviceId` in `getSettings()`, empty `getCapabilities()` — high reliability, medium evasion difficulty (requires Proxy spoofing)
- **ML model loading**: Intercepting `fetch()` and `XMLHttpRequest.open()` for patterns like `.onnx`, `.tflite`, `model.json`, `shard*of*.bin`, `ort-wasm*.wasm` — high feasibility, medium reliability (models could be bundled/obfuscated)
- **WebRTC stats correlation**: `RTCPeerConnection.getStats()` returns `RTCVideoSourceStats` with `trackIdentifier` linkable to flagged synthetic tracks — supplementary signal, no direct `sourceType` field
- **Frame timing jitter**: `requestVideoFrameCallback()` provides `presentationTime` for inter-frame interval analysis; real cameras show hardware-determined regularity (~33.33ms ±0.1ms for 30fps) while processed frames show inference variance — weak standalone signal (can be defeated by buffering), useful as tiebreaker

A critical MV3 limitation: MAIN-world scripts have **no access to `chrome.*` extension APIs**. Communication requires `CustomEvent` DOM messaging to an isolated-world content script, which relays to the service worker. The service worker can supplement detection via `chrome.webRequest.onBeforeRequest` (non-blocking observation of model file downloads) and `chrome.declarativeNetRequest` rules for known ML framework file patterns.

Regarding false positives: legitimate use cases for the `MediaStreamTrackProcessor` → `MediaStreamTrackGenerator` pipeline include background blur/replacement (Google Meet's built-in processing), AR filters, and accessibility tools. The key discriminator is whether the processing is **same-origin first-party** (the video calling platform itself) versus **injected by third-party code or an extension**. The compound detector should weight the source context: processing initiated by the page's own JavaScript on a known video conferencing domain is expected; processing initiated by injected scripts or extension content scripts on those same domains is suspicious.

---

## Academic research confirms detection gaps but offers useful signals

The academic landscape reveals both the promise and limits of deepfake detection for this use case. The **DeepFake-Eval-2024 benchmark** (Chandra et al., TrueMedia.org, March 2025) found that state-of-the-art open-source video detectors suffer a **~50% AUC drop** on in-the-wild deepfakes versus legacy benchmarks. The best commercial detector achieved only ~78% AUC, below the ~90% accuracy of human forensic analysts. The USENIX Security 2024 SoK by Layton et al. showed that in a typical call center scenario, the "best detector" would yield **only 1 true positive out of 333 flagged results**.

However, several signals identified in recent research align with what a browser extension can observe. **Facial Feature Drift** (CVPR 2025, Yan et al.) detects subtle unnatural flickering between consecutive deepfake frames—a temporal signal that could be approximated via `requestVideoFrameCallback`. **Photoplethysmography** (Intel FakeCatcher, claimed 96% accuracy) analyzes blood flow patterns that deepfakes cannot replicate, but requires server-side compute. Lightweight models like **TinyDF** (5.38M parameters, 0.59G FLOPs, 93.84% accuracy on FF++) could theoretically run in-browser via TensorFlow.js, but no implementation exists at frame rate.

No W3C specification addresses camera attestation or synthetic media detection natively. Google's Web Environment Integrity proposal was **abandoned in November 2023** after criticism. C2PA Content Credentials are "being examined by the W3C for browser-level adoption" but apply only to static assets, not live WebRTC streams. The NSA/FBI/CISA January 2025 joint guidance recommends C2PA but acknowledges its limitations—and the USENIX Security 2025 "Chimera" paper demonstrates creating cryptographically signed fake photos that fool both deepfake detectors and C2PA verification.

Commercial solutions like **Reality Defender** (RealMeeting plugin for Zoom/Teams, Gartner-recognized leader) and **Pindrop** ($100M raised for deepfake video detection) operate server-side. No production system performs real-time video deepfake detection entirely client-side in a browser.

---

## Recommendations for PhishOps

**1. A standalone "DeepfakeGuard" detector is NOT justified now.** The browser-based face-swap threat is pre-emergent. No in-browser face-swap pipeline exists at call quality. Native tools (OBS + DeepFaceLive) remain the operational attack vector, and those are detectable through virtual camera enumeration, which PhishOps can already address in WebRTCGuard.

**2. Integrate lightweight sentinel hooks into WebRTCGuard for Wave 22–23.** The implementation cost is low (wrapping 4–5 constructors) and the detection signal is strong. Ship the following as part of WebRTCGuard's existing `RTCPeerConnection` monitoring:

| Signal | Weight | Implementation |
|--------|--------|----------------|
| `MediaStreamTrackGenerator` constructor called | 0.3 | Proxy construct trap |
| `MediaStreamTrackProcessor` constructor called | 0.2 | Proxy construct trap |
| Synthetic track (empty label, no deviceId) passed to `addTrack()` | 0.4 | `addTrack`/`addTransceiver`/`replaceTrack` wrapper |
| Simultaneous `getUserMedia` + Processor + Generator | 0.5 | Compound state machine |
| ML model file fetched (`.onnx`, `.tflite`, `model.json`, `shard*of*.bin`) | 0.2 | `fetch`/`XHR` interception + service worker `webRequest` |
| `VideoTrackGenerator` constructor called (future Safari/Firefox) | 0.3 | Proxy construct trap |

Trigger threshold: cumulative score ≥ 0.7 fires an alert. The compound signal (getUserMedia + Processor + Generator + addTrack with synthetic track) alone reaches 1.4 and is sufficient.

**3. False-positive mitigation requires domain context.** Video conferencing platforms (Google Meet, Zoom, Teams) use `MediaStreamTrackProcessor` for legitimate background blur and effects. The detector should maintain a **allowlist of first-party processing patterns** on known video conferencing origins. Third-party or extension-injected processing on these domains should elevate suspicion. The detector should also check whether the `MediaStreamTrackProcessor` input track and the `MediaStreamTrackGenerator` output track flow through the same origin's JavaScript context.

**4. Timeline assessment: browser-based deepfake injection is a 2027 threat for criminal actors, late 2026 for state-sponsored hybrid attacks.** The hybrid attack (extension captures frames → remote GPU server processes → frames injected back) is architecturally feasible today but requires a compromised extension with camera permissions on the target domain. Pure client-side face-swap at call quality requires either a purpose-built lightweight model (~50–100MB, INT8 quantized) optimized for WebGPU, or a ~3× improvement in WebGPU-to-native performance parity—both plausible by late 2027.

**5. The sentinel hooks serve as an early-warning tripwire.** Even before browser face-swap is viable, the hooks detect any `MediaStreamTrackGenerator`-based track injection into WebRTC calls—including simpler attacks like pre-recorded video injection, static image injection, or server-relayed deepfake streams. This coverage is valuable independent of the face-swap quality question. When browser face-swap does become viable, the detection infrastructure will already be deployed and collecting telemetry on real-world usage patterns of these APIs.

**In sum**: don't build DeepfakeGuard. Extend WebRTCGuard with ~200 lines of MAIN-world constructor wrapping. Monitor the `MediaStreamTrackGenerator` usage telemetry. Revisit for a dedicated detector when WebGPU face-swap demos emerge or when the compound signal starts firing in the wild.