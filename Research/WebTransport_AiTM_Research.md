# WebTransport as an AiTM credential relay vector: threat assessment and detection design

**WebTransport offers attackers meaningful protocol-level advantages over WebSocket for credential relay — up to 400ms less observable latency, multiplexed exfiltration streams, and encrypted transport metadata — but no evidence exists of its adoption in phishing infrastructure as of March 2026.** This gap between theoretical capability and real-world exploitation creates a narrow window for proactive defense. The PhaaS ecosystem remains locked to HTTP/HTTPS reverse proxying due to infrastructure constraints (no major reverse proxy supports WebTransport session forwarding), but QUIC-based C2 frameworks already exist and the migration path is clear. A WebTransportGuard detector is technically feasible using Chrome MV3's MAIN world content script injection and `declarativeNetRequest`, and would generate near-zero false positives today given WebTransport's negligible presence on credential pages.

---

## The complete API surface presents a rich attack toolkit

The W3C WebTransport spec (Working Draft, December 17, 2025) and Chrome's implementation (stable since **Chrome 97**, January 2022) expose a constructor, multiplexed streams, unreliable datagrams, and connection lifecycle hooks that together provide everything a credential relay needs.

The constructor `new WebTransport(url, options)` accepts an HTTPS URL and an options dictionary with security-relevant fields. The **`serverCertificateHashes`** option is the most consequential for attackers: it accepts an array of `{algorithm: "sha-256", value: ArrayBuffer}` objects, allowing connections to servers with **self-signed certificates** — no CA chain required. Certificates must use ECDSA (no RSA), have ≤14-day validity, and the connection must be dedicated (`allowPooling: false`). This means an attacker can spin up ephemeral relay servers with throwaway certificates and connect from victim browsers without triggering certificate warnings. WebKit has formally refused to implement this feature (w3c/webtransport Issue #623), but Chrome and Firefox ship it.

The `options` dictionary also includes `congestionControl` (with a `"low-latency"` hint ideal for real-time relay), `requireUnreliable` (forces HTTP/3, ensuring datagram support), `protocols` (application protocol negotiation, shipped Chrome 143), and a new `headers` field for custom headers on the CONNECT handshake. The `ready` and `closed` promises govern the connection lifecycle through five states: **connecting → connected → draining → closed/failed**. Error handling uses a dedicated `WebTransportError` class extending `DOMException` with `source` ("stream" or "session") and optional `streamErrorCode`.

The **datagrams API** (`transport.datagrams`) returns a `WebTransportDatagramDuplexStream` with a `.readable` stream of `Uint8Array` chunks and a `.createWritable()` factory producing independent writable streams. Datagrams are unreliable and unordered — fire-and-forget delivery bounded by `maxDatagramSize` (path MTU). The **stream API** offers `createBidirectionalStream()` returning a promise of `{readable, writable}` pairs and `createUnidirectionalStream()` returning a `WritableStream`. Both support `sendGroup` and `sendOrder` for prioritization. Critically, the IDL shows `Exposed=(Window,Worker)` — WebTransport is available in Service Workers, Shared Workers, and Dedicated Workers, not just the page context.

---

## Protocol advantages give attackers 100–400ms and encrypted metadata

WebTransport's QUIC foundation provides four distinct advantages over WebSocket's TCP stack for AiTM credential relay, each compounding to create a meaningfully faster and stealthier channel.

**Connection setup latency drops from 2–3 RTT to 0–1 RTT.** WebSocket requires TCP's 3-way handshake (1 RTT), TLS 1.3 handshake (1 RTT), and HTTP upgrade (pipelined into TLS, so effectively 2 RTT total for new connections). QUIC merges transport and crypto handshakes into **1 RTT** for new connections and achieves **0 RTT** for resumed connections using cached session tickets. For a cross-continent relay at 100ms RTT, this eliminates **200–400ms** of observable setup delay per relay leg. On mobile networks (200–250ms RTT), the savings reach **400–750ms** — the difference between a phishing page that "feels right" and one that triggers suspicion.

**Multiplexed streams eliminate head-of-line blocking.** An attacker could dedicate independent streams to parallel tasks: Stream 1 for proxying victim HTTP requests, Stream 2 for returning server responses, Stream 3 for exfiltrating credentials to C2, Stream 4 for session tokens. In WebSocket's single TCP stream, a lost packet stalls everything. In WebTransport, packet loss on the token exfiltration stream has zero impact on the credential relay stream. Under lossy conditions (mobile, VPN), this resilience is substantial.

**Unreliable datagrams optimize keystroke forwarding.** Each keypress can be sent as an independent datagram with no retransmission overhead. If one is lost, the next keystroke (or cumulative input update) carries forward. WebSocket's TCP reliability means a lost keystroke packet forces retransmission before subsequent data flows, introducing **timing jitter** that behavioral analytics can detect.

**QUIC encrypts transport metadata that TCP leaves exposed.** Packet numbers, acknowledgements, stream IDs, and connection options are all encrypted. Only the UDP 5-tuple and initial Connection ID remain visible. Connection migration (changing IP/port mid-session) further complicates tracking. Per CMU SEI research, "QUIC encrypts headers with fixed but unregistered symmetric keys, which must be decrypted by passive security monitors." The practical impact: **Burp Suite cannot intercept QUIC/WebTransport traffic at all** as of early 2026. mitmproxy 11 added experimental QUIC support but Chrome specifically blocks user-added CAs for QUIC connections, forcing fallback to HTTP/2. Leading IDS/IPS tools (Snort, Suricata, Zeek) have limited or no QUIC inspection capability.

Current AiTM kits — Evilginx, EvilProxy ($150–600/month), Tycoon2FA, Modlishka, and the newer Starkiller (headless Chrome Docker containers) — all use standard HTTP/HTTPS reverse proxying. Their bottleneck is TCP's connection overhead: loading a single login page requires connections to 10+ origins, each adding 2–3 RTT. WebTransport could collapse this into a single multiplexed QUIC connection with 0-RTT resumption.

---

## No threat intelligence evidence exists yet, but the migration path is visible

Exhaustive searching across threat intelligence vendors, academic databases, GitHub, CVE repositories, and cybersecurity news yields a clear verdict: **WebTransport has not been adopted in phishing infrastructure as of March 2026.** This absence is confirmed, not an artifact of search limitations — adjacent technologies (QUIC C2, HTTP/HTTPS AiTM) are extensively documented through the same search methodology.

No reports from Mandiant, CrowdStrike, Proofpoint, or Recorded Future mention WebTransport in any phishing context. Microsoft's March 2026 analysis of Tycoon2FA and KrebsOnSecurity's February 2026 coverage of "Starkiller" both describe HTTP/HTTPS-only architectures. Google Project Zero has published nothing on WebTransport security. No USENIX, IEEE S&P, or ACM CCS papers from 2024–2026 address WebTransport abuse. GitHub contains zero repositories combining WebTransport with phishing-related terms. The only WebTransport CVE is **CVE-2024-9399** — a Firefox DoS bug, unrelated to credential theft.

Three factors explain this absence and three signals suggest future adoption:

- **Why not yet:** Reverse proxy infrastructure cannot handle WebTransport (Nginx, HAProxy, Caddy all lack support — w3c/webtransport Issue #525 confirms this). HTTP/HTTPS already works well for current kits. Browser support is ~72% (no Safari), limiting phishing effectiveness.
- **Migration signals:** QUIC C2 exists (Merlin framework added QUIC in 2018). The QUIC-Exfil paper (arXiv, May 2025) demonstrates covert data exfiltration via QUIC connection migration that ML classifiers cannot detect. W3C WebAppSec Issue #656 explicitly identifies WebTransport as a CSP anti-exfiltration gap: "Have control over WebRTC and WebTransport, somehow." Once Nginx/Caddy gain WebTransport proxying capability, the technical barrier drops to near zero.

---

## Detection from Chrome MV3 is feasible but requires a layered approach

Four mechanisms are available to a Chrome MV3 extension for WebTransport detection, each covering different aspects of the threat surface.

**MAIN world constructor wrapping is the primary detection method.** Chrome MV3 supports `"world": "MAIN"` in static manifest content script declarations (since Chrome 111). A content script declared with `"run_at": "document_start"` and `"world": "MAIN"` runs in the page's JavaScript context **before any DOM construction or page script execution**. This allows wrapping the `WebTransport` constructor to intercept all `new WebTransport()` calls, log destination URLs, and monitor stream/datagram creation. Static manifest declarations have priority over dynamically registered scripts, providing the strongest timing guarantee. The `scripting.executeScript` API with `world: 'MAIN'` is unreliable for pre-page-load injection — multiple developers report it fires only after DOMContentLoaded due to async service worker round-trip latency.

The **isolated world** (content script default) shares the DOM but **not** the global scope. `WebTransport` in the isolated world is a separate copy — wrapping it has zero effect on page scripts. Detection code must operate in the MAIN world.

**`declarativeNetRequest` (DNR) provides network-level blocking.** DNR explicitly supports `"webtransport"` as a resource type (confirmed in w3c/webextensions Issue #369). A rule can block WebTransport connections by domain, covering both window and worker contexts — something constructor wrapping alone cannot achieve. DNR operates at Chrome's network stack, independent of JavaScript execution context. The limitation: DNR can block but cannot log connection details in production builds (`onRuleMatchedDebug` is debug-only).

**CSP's `connect-src` covers WebTransport** with a notable addition: connections using `serverCertificateHashes` require the `'unsafe-webtransport-hashes'` keyword in the source list. Without it, hash-based connections are blocked even if the URL matches. An extension could inject restrictive CSP headers via DNR's `modifyHeaders` action to restrict WebTransport destinations.

**Chrome DevTools Protocol** offers the most detailed monitoring (`Network.webTransportCreated`, `webTransportConnectionEstablished`, `webTransportClosed` events), but the `chrome.debugger` API displays an undismissable warning bar, making it impractical for production use.

**The Worker context gap is the most significant limitation.** Since WebTransport is `Exposed=(Window,Worker)`, a page can spawn a dedicated Worker that creates WebTransport connections invisible to main-world constructor wrapping. Only DNR blocking covers this gap. For detection-only (without blocking), CDP is the sole option — but with unacceptable UX. The recommended architecture combines MAIN world wrapping (detection + logging) with DNR rules (blocking + worker coverage).

---

## False positive risk is effectively zero today

Across every major category of legitimate WebTransport usage on credential pages, the current landscape shows negligible adoption.

**No chat widget provider uses WebTransport.** Intercom, Zendesk, Drift, and LiveChat all use WebSockets for real-time communication. No engineering blog posts, documentation, or job listings from these companies reference WebTransport migration. **No analytics platform uses WebTransport** — Google Analytics, Segment, Amplitude, and Mixpanel all use standard HTTP POST requests. **No video conferencing service has deployed WebTransport** — Zoom, Google Meet, and Teams use WebRTC exclusively. The Media over QUIC (MoQ) initiative, which uses WebTransport as its browser transport, remains in early-adopter stage with demonstrations by Cloudflare and Akamai but no production deployment on login pages.

The only confirmed production users of WebTransport are Twitch (limited live video experiments), Meta (experimental `go-media-webtransport-server`), and the Colyseus game framework (preview). None of these would appear on credential/login pages.

Infrastructure support reinforces this assessment: **Nginx, HAProxy, Caddy, and Envoy cannot proxy WebTransport sessions.** Even services wanting to deploy WebTransport face fundamental infrastructure barriers. Safari's complete lack of support (~17% combined desktop+mobile share) prevents any service requiring broad browser coverage from depending on WebTransport.

**Any WebTransport connection on a credential page in 2026 is, by itself, a high-confidence anomaly signal.** This detection logic will require evolution — estimated 2027–2028 for mainstream adoption — at which point domain whitelisting and data-flow analysis will become necessary to distinguish legitimate chat widgets from exfiltration channels.

---

## Recommended WebTransportGuard detector architecture

Based on the research findings, the detector design should mirror the existing WsExfilGuard pattern with WebTransport-specific adaptations across four layers.

The **constructor wrapper layer** should use a static manifest content script (`"world": "MAIN"`, `"run_at": "document_start"`) that stores a reference to the original `WebTransport` constructor, replaces `window.WebTransport` with a proxy, and intercepts every instantiation. The wrapper should capture the destination URL and `serverCertificateHashes` option (hash-pinned connections to unknown servers are especially suspicious), then proxy `createBidirectionalStream()`, `createUnidirectionalStream()`, and `datagrams.createWritable()` to monitor data flow. Messages written to streams or datagrams should be sampled for credential-like patterns (email/password field values, session tokens).

The **network blocking layer** should use DNR rules with `resourceTypes: ["webtransport"]` to block connections to known-malicious domains and cover the Worker context gap. Dynamic rules can be updated via threat intelligence feeds.

The **scoring heuristics** should weight three signals: cross-origin WebTransport connection present (moderate signal), connection coincides with credential field presence on page (strong signal), and `serverCertificateHashes` option used (strong signal — legitimate services use standard PKI). The combination of all three should trigger high-confidence alerting.

The **key differences from WsExfilGuard** are: WebTransport multiplexing means multiple streams must be monitored per connection (vs. WebSocket's single bidirectional stream); unreliable datagrams may carry data that cannot be reliably intercepted via stream wrappers alone; and Worker-spawned connections require DNR as a backstop since constructor wrapping is window-only.

---

## Conclusion

WebTransport represents a credible future attack vector for AiTM credential relay, offering quantifiable advantages in latency (0-RTT vs. 2-3 RTT), parallelism (multiplexed streams), and stealth (encrypted QUIC metadata invisible to most security tools). The protocol is not theoretical — it shipped in Chrome four years ago and the API surface is mature. The absence of current exploitation reflects infrastructure constraints (reverse proxy support), not lack of attacker interest. Detection is technically feasible today through MAIN world constructor wrapping combined with DNR blocking, and the near-zero false positive rate creates an unusually clean signal window that will narrow as adoption grows. Building WebTransportGuard now — before the PhaaS ecosystem migrates — converts a reactive detection problem into a proactive control. The most critical architectural decision is addressing the Worker context gap, where DNR blocking is the only viable MV3 mechanism, since CDP's debugger warning bar makes it unsuitable for production monitoring.