# Speculation Rules API abuse for phishing: a constrained but real threat

**Chrome's cross-site prerender restriction fundamentally limits the Speculation Rules phishing attack described in the PhishOps brainstorm — but does not eliminate it entirely.** Cross-site prerenders (e.g., `legitimate-site.com` prerendering `attacker.com`) are blocked outright in Chrome's implementation, meaning the specific attack model of injecting speculation rules via XSS to prerender a cross-origin phishing page will fail for cross-site targets. However, same-origin and same-site attack variants remain viable, and Chrome MV3 content scripts **do** execute during prerendering, meaning all 38 PhishOps detectors will see attack pages — they are not blind. This report documents the complete API specification, cross-origin restrictions, content script behavior, detection capabilities, and the security research landscape as of March 2026.

---

## The Speculation Rules API in full: schema, semantics, and Chrome limits

The Speculation Rules API, now upstreamed to the HTML Standard from its WICG origins, allows web pages to declare speculative navigations via `<script type="speculationrules">` elements, the `Speculation-Rules` HTTP header, or dynamic JavaScript injection. The complete JSON schema supports two top-level actions — `prefetch` and `prerender` — plus a new `prerender_until_script` action in Chrome 144 origin trial (announced January 2026 by Barry Pollard and Lingqi Chi).

Each rule object supports these fields: `source` (`"list"` or `"document"`, inferred from context), `urls` (explicit URL array for list rules), `where` (CSS selector and URL pattern matching for document rules), `eagerness` (`"immediate"`, `"eager"`, `"moderate"`, `"conservative"`), `expects_no_vary_search` (structured header hint for cache matching), `referrer_policy`, `requires` (currently only `["anonymous-client-ip-when-cross-origin"]` for prefetch), `tag` (exposed via `Sec-Speculation-Tags` header), `target_hint` (`"_self"` or `"_blank"`), and `relative_to` (`"document"` or `"ruleset"`).

The critical semantic difference between prefetch and prerender matters enormously for the attack model. **Prefetch fetches only the HTML document** — no JavaScript execution, no rendering, no subresource loading. **Prerender creates a full hidden browsing context**: JavaScript executes, timers run, network requests fire for all subresources, and the page renders completely in a hidden tab. On activation (user navigation), the prerendered page swaps into the foreground near-instantly. Intrusive APIs — geolocation, camera, notifications, `alert()`/`confirm()` — are deferred until activation or cause prerender cancellation.

Chrome enforces concrete limits on concurrent speculations. For `immediate`/`eager` eagerness: **50 prefetches and 10 prerenders maximum**. For `moderate`/`conservative`: **2 of each**. Oldest speculations are evicted FIFO. Prefetch cache entries expire after approximately 5 minutes. Prerendering is disabled entirely when Chrome's energy saver is active on low battery, when memory is constrained, when the "Preload pages" setting is off (also disabled by uBlock Origin), or in background tabs.

The eagerness settings control trigger timing: `immediate` starts when rules are parsed, `eager` triggers after 10ms hover on desktop or viewport-based heuristics on mobile, `moderate` triggers after 200ms hover or on `pointerdown`, and `conservative` triggers only on `mousedown`/`pointerdown`. Default eagerness is `immediate` for list rules and `conservative` for document rules.

Rules can be added dynamically via JavaScript (`createElement` + `appendChild`), feature-detected via `HTMLScriptElement.supports("speculationrules")`, and delivered through three channels: inline `<script>` elements, the `Speculation-Rules` HTTP header pointing to a JSON file with MIME type `application/speculationrules+json`, or dynamic injection. **Critically, speculation rules in subframes are ignored** — only main-frame rules are honored. Rules in prerendered pages themselves are deferred until activation.

---

## Cross-site prerender is blocked: the attack model's central constraint

The most consequential finding for the PhishOps attack model is Chrome's **strict tiered restriction on cross-origin prerendering**:

| Scenario | Prerender allowed? | Opt-in required? |
|---|---|---|
| Same-origin (`a.com/page1` → `a.com/page2`) | Yes | None |
| Cross-origin, same-site (`a.example.com` → `b.example.com`) | Yes | Target must send `Supports-Loading-Mode: credentialed-prerender` |
| Cross-site (`a.com` → `b.com`) | **No — blocked entirely** | N/A |

**An attacker page on `attacker.com` cannot prerender `bank.com` or any other cross-site domain.** This is a hard architectural restriction in Chrome's Prerender2 implementation, built on the Multiple-Page Architecture (MPArch). Even same-site cross-origin prerenders require the target server to explicitly opt in by serving the `Supports-Loading-Mode: credentialed-prerender` response header. Without it, Chrome cancels the prerender.

Cross-site **prefetch** (not prerender) is partially allowed but constrained: it works only when the user has **no existing cookies** for the destination site, and the referrer policy must be at least as strict as `strict-origin-when-cross-origin`. With the `anonymous-client-ip-when-cross-origin` requirement, Chrome routes cross-origin prefetches through a private Google-operated proxy to hide the user's IP — but this still only fetches the HTML document without executing JavaScript.

Prerendered pages run in a **separate renderer process** from the triggering page, respecting Chrome's site isolation model. Cookies and storage access follow site boundaries — same-site cross-origin prerenders include credentials (hence the opt-in requirement), while cross-site prefetches strip them. The `Sec-Purpose: prefetch;prerender` header accompanies prerender requests, allowing servers to detect and reject speculative loads.

---

## What the attack actually looks like: revised threat scenarios

Given the cross-site restriction, the originally described attack — XSS injection of speculation rules to prerender a cross-origin phishing page — requires revision. Three viable attack variants remain:

**Variant 1: Same-origin prerender after XSS.** If an attacker achieves XSS on `legitimate-site.com`, they can inject speculation rules to prerender same-origin paths they control. On platforms with user-generated content (forums, CMSes, webmail), an attacker could prerender a same-origin path hosting attacker-controlled content that mimics a login page. The prerender activates instantly on link click, and the URL bar still shows `legitimate-site.com` — making this a potent credential-harvesting attack. This is the **most dangerous variant** because the URL remains the legitimate domain throughout.

**Variant 2: Same-site subdomain attack.** If an attacker controls a subdomain on the same eTLD+1 (e.g., `attacker.example.com` targeting users on `app.example.com`), they can prerender their subdomain if it serves `Supports-Loading-Mode: credentialed-prerender`. Since the attacker controls their own server, this opt-in is trivial. The URL bar shows the attacker's subdomain, but the parent domain match may reduce user suspicion.

**Variant 3: Navigation speed enhancement for cross-site phishing.** While prerender is blocked cross-site, an attacker with XSS can inject **prefetch** rules for their phishing domain (if the user has no cookies there — likely for a fresh phishing domain). This pre-fetches only the HTML, but still provides a perceived speed boost when the user clicks a manipulated link. The phishing page loads faster than normal, reducing the user's window to notice the domain change. This is a weaker attack — no instant activation, no JavaScript pre-execution — but still provides attacker advantage.

**CSP as a mitigator:** Sites with strict Content Security Policy can block XSS-injected speculation rules. Chrome recognizes the `inline-speculation-rules` CSP source value, meaning sites can explicitly allowlist inline speculation rules. However, if an attacker bypasses CSP sufficiently to inject arbitrary HTML, they can likely inject speculation rules too.

---

## Content scripts run during prerender: PhishOps detectors are not blind

**This is the critical good news for the PhishOps extension.** Chrome MV3 content scripts **are injected into prerendered pages during prerendering, before activation.** This finding is confirmed by multiple authoritative sources: the WECG meeting minutes (April 2022, Dave Tapuska from Chrome), the Chromium Extensions Google Group (January 2023, confirmed by wOxxOm), and the Chrome Developer Blog's extension instant navigation guide (November 2022).

Both static manifest-declared content scripts and dynamically registered scripts (via `chrome.scripting.registerContentScripts`) execute during the prerender phase. `document_start` scripts run before the prerendered page's own scripts, maintaining their normal injection timing. `document_idle` scripts fire when the prerendered page reaches idle state — also during prerender, not deferred to activation. **Content scripts do not re-run upon activation.** The JavaScript context, including the content script's isolated world, persists across the prerender-to-active transition.

For PhishOps, this means all **38 detectors will execute during prerender**, before the user ever sees the page. This is actually advantageous — the extension can detect phishing before user exposure. However, several engineering considerations apply:

- **No second execution on activation.** Detectors that depend on the page being visible or that fire once must use `document.prerendering` and the `prerenderingchange` event to also run logic at activation time.
- **Messaging lifecycle.** When content scripts send results to the service worker during prerender, `sender.documentLifecycle` will be `"prerender"`. The service worker should defer user-facing warnings until the page activates.
- **Target with `documentId`.** For programmatic injection via `chrome.scripting.executeScript()`, use `documentIds` rather than `tabId` alone, since prerendered pages have non-zero `frameId` for their outermost frame.
- **The `frameId == 0` assumption is broken.** Extensions assuming `frameId == 0` is the main frame will incorrectly handle prerendered pages. Use `frameType === "outermost_frame"` instead.

The extension can detect prerendering state from content scripts using `document.prerendering` (returns `true` during prerender), the `prerenderingchange` event (fires on activation), and `performance.getEntriesByType("navigation")[0]?.activationStart` (non-zero if page was prerendered). From the service worker, `sender.documentLifecycle` and webNavigation events with `DocumentLifecycle === "prerender"` provide the signal.

---

## A content script can fully detect, parse, and neutralize speculation rules

PhishOps can build robust detection of malicious speculation rules using standard DOM APIs available to content scripts:

**Detection** is straightforward. A `MutationObserver` configured at `document_start` with `{childList: true, subtree: true}` on `document.documentElement` catches every `<script type="speculationrules">` element as it's added to the DOM — whether statically in HTML, injected by tag managers, or added dynamically via JavaScript. At `document_idle`, `document.querySelectorAll('script[type="speculationrules"]')` returns all existing elements.

**Parsing** works via `.textContent`. Since `type="speculationrules"` is treated as data (not executable script), `JSON.parse(element.textContent)` yields the full rule structure — including target URLs, eagerness settings, and whether rules specify `prefetch` or `prerender`. The extension can inspect whether targets are same-origin, same-site, or cross-origin, and flag suspicious patterns.

**Neutralization** is confirmed by Chrome's official documentation: **removing a speculation rules `<script>` element cancels associated speculations.** This gives the extension a kill switch. After detecting a suspicious rule, the extension can call `element.remove()` to cancel the prerender immediately. After removal, the browser must process the cancellation before new rules are inserted (requires a new microtask). Note that rules delivered via the `Speculation-Rules` HTTP header cannot be removed from the DOM, but their matching criteria (CSS classes on links) can be manipulated to prevent matching.

`chrome.declarativeNetRequest` can block prefetch/prerender requests by URL pattern using `resourceTypes: ["main_frame"]`, though there is no dedicated "prefetch" or "prerender" resource type. The `Sec-Purpose` request header is set by the browser and cannot be matched in declarativeNetRequest conditions, but it is observable via `chrome.webRequest.onBeforeSendHeaders` in the service worker. No dedicated `chrome.speculationRules` extension API exists.

---

## Legitimate adoption is massive but almost entirely same-origin

Speculation Rules adoption exploded in 2025. **WordPress 6.8** (April 2025) ships speculation rules as a core feature on every WordPress site by default — using `prefetch` with `conservative` eagerness for logged-out users. Given WordPress powers roughly **40% of all websites**, this represents potentially hundreds of millions of sites. The standalone Speculative Loading plugin had over **40,000 active installations** before merging into core. **Google Search** uses cross-origin prefetch (not prerender) for the first two result links via a private proxy. **Cloudflare's Speed Brain** product injects speculation rules at the CDN edge for cached pages. **Astro** added support in version 4.2.

The critical finding for false positive analysis: **legitimate cross-origin prerender is essentially nonexistent.** All major adopters use same-origin prerender or same-origin prefetch with document rules. Google Search uses cross-origin *prefetch* only (not prerender). No major site uses cross-site prerender because Chrome doesn't support it. Flagging or blocking cross-origin prerender speculation rules would produce **near-zero false positives** — making it an ideal heuristic signal for a PhishOps detector.

Cross-origin *prefetch* is slightly more common (Google Search being the primary example), so blocking all cross-origin prefetch would affect search result pre-loading. A tiered approach — block cross-origin prerender aggressively, flag cross-origin prefetch with additional heuristics — would optimize the precision-recall tradeoff.

---

## No prior security research exists on this attack vector

After exhaustive searching across academic databases, security conference proceedings (Black Hat, DEF CON, USENIX Security 2023–2026), PortSwigger Research, NCC Group, Trail of Bits, Google Project Zero, the Chromium bug tracker, and GitHub, **no dedicated security research documents Speculation Rules API abuse for phishing or navigation hijacking.** This attack vector appears genuinely novel and unresearched.

The closest historical precedent is **Chromium Bug #520275** (2015–2019): Ajay Patel discovered that `<link rel="prerender">` on Google Search allowed JavaScript execution on prerendered pages, enabling audio playback via WebSpeech API for social engineering and DoS via infinite loops. It was rated ≥Medium severity and was described as Chrome's "oldest ≥ Medium severity security bug." It was ultimately resolved by deprecating the old `rel="prerender"` mechanism entirely.

The WICG specification repository contains several relevant security discussions: **Issue #91** raises DDoS amplification concerns, **Issue #43** discusses CSP interaction, **Issue #302** warns about stale prefetched pages after authentication state changes, and **Issue #319** (still open) notes the formal spec **lacks security and privacy consideration sections** — a notable gap. Chrome's team states that "both MPArch and this feature in particular underwent significant security review," but no public threat model document exists.

Chrome's built-in mitigations include the cross-site prerender block, the `Supports-Loading-Mode` opt-in requirement for cross-origin same-site prerender, CSP `inline-speculation-rules` source enforcement, subframe rules being ignored, API deferral for intrusive behaviors, concurrent prerender limits, the `Sec-Purpose` header allowing server-side detection, and separate renderer process isolation.

---

## Conclusion: recalibrated priority with clear detection path

The Speculation Rules phishing attack is **more constrained than initially assessed** but remains a valid concern. The cross-site prerender block means the cleanest attack scenario — prerendering a phishing domain from a compromised legitimate site — does not work. The viable threat shifts to **same-origin exploitation** (XSS + prerender of attacker-controlled same-origin content) and **same-site subdomain attacks**, both of which produce more convincing phishing because the URL bar shows a trusted domain.

Three novel insights reshape the PhishOps detection strategy. First, content scripts running during prerender means detectors get **advance warning** — they see the attack page before the user does, creating a detection window that doesn't exist for normal navigations. Second, cross-origin prerender rules are a **near-perfect signal** with essentially zero false positives in legitimate traffic, making them an ideal high-confidence heuristic. Third, the ability to **remove speculation rules elements to cancel prerenders** gives the extension an active defense capability beyond mere detection.

The recommended PhishOps detector should implement a `document_start` MutationObserver that intercepts `<script type="speculationrules">` elements, parses their JSON content, flags or removes rules with cross-origin prerender targets, and reports prerender-state awareness via `document.prerendering` to the service worker. Given the near-absence of prior security research on this vector and the missing formal security considerations in the spec itself, publishing findings from this research would contribute meaningfully to the browser security community.