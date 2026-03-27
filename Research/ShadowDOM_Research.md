# Shadow DOM is not a phishing weapon — but your detectors are still blind to it

**PhishOps should not build a standalone ShadowDOMGuard detector.** No evidence exists of intentional shadow DOM usage in any known phishing kit as of March 2026. The real risk is that PhishOps's existing DOM-walking detectors (AutofillGuard, PhishVision, LLMScorer) silently miss credential fields hidden inside shadow roots — whether placed there by attackers or by legitimate web component frameworks. The correct fix is a shared recursive traversal utility that hardens every existing detector, not a new attack-specific module. Shadow DOM prevalence on the web grew **6.4× between 2022 and 2024** (from 0.39% to 2.51% of pages), making this a reliability issue today rather than a theoretical future concern.

---

## 1. What the HTML parser actually does with `<template shadowrootmode>`

Declarative Shadow DOM is defined in the WHATWG HTML spec at the `<template>` element section. When the HTML parser encounters `<template shadowrootmode="open">` or `<template shadowrootmode="closed">`, it enters normal template insertion mode and parses child content into a DocumentFragment. **At the closing `</template>` tag**, the parser attaches a shadow root to the parent element with the specified mode, moves the template content into that shadow root, and **removes the `<template>` element entirely from the DOM**.

This means `document.querySelectorAll('template[shadowrootmode]')` returns nothing after parsing — the templates are consumed. The shadow root is created **at parse time, before DOMContentLoaded, before any JavaScript runs**. This is a parser-level operation with no JavaScript involvement whatsoever. The `.content` property of the template returns `null` during parsing to prevent early access via scripts or MutationObserver.

For `mode: "open"`, the shadow root is accessible via **`element.shadowRoot`** — this is guaranteed by spec and works identically to imperative `attachShadow({mode: "open"})`. For `mode: "closed"`, `element.shadowRoot` returns `null`. No standard web API allows external access to a closed declarative shadow root. The only mechanisms are `ElementInternals.shadowRoot` (for the custom element's own code), Chrome's privileged **`chrome.dom.openOrClosedShadowRoot()`** extension API, and the Chrome DevTools Protocol with `pierce: true`.

Additional template attributes — `shadowrootclonable`, `shadowrootdelegatesfocus`, `shadowrootserializable` — control cloning, focus delegation, and HTML serialization behavior respectively. The `shadowrootserializable` attribute is notable for the threat model: if set, `Element.getHTML({serializableShadowRoots: true})` can serialize even closed shadow root content. However, this requires the page author to opt in, making it irrelevant for adversarial scenarios where the attacker controls the page.

**Browser support is now universal.** Chrome shipped `shadowrootmode` in version 111 (March 2023), Edge followed immediately (Chromium-based), Safari shipped in 16.4 (March 2023), and Firefox shipped in version 123 (February 2024). Global support stands at **~96%** per Can I Use.

---

## 2. Why `attachShadow()` wrapping fails for declarative roots — and what works instead

The most critical finding for PhishOps: **monkey-patching `Element.prototype.attachShadow()` in a MAIN-world content script does NOT intercept declarative shadow roots.** The HTML parser creates them through an internal code path that never invokes the JavaScript `attachShadow` method. This is explicitly documented in WHATWG DOM issue #1290, which states that overriding `attachShadow` is "an inelegant and brittle monkey patch" that works only for imperative roots.

The following table summarizes detection capability by shadow root type:

| Shadow Root Type | `attachShadow()` wrap | `element.shadowRoot` scan | MutationObserver | CDP `pierce: true` | `chrome.dom.openOrClosedShadowRoot` |
|---|---|---|---|---|---|
| Imperative open | ✅ | ✅ | ❌ | ✅ | ✅ |
| Imperative closed | ✅ (stores ref in WeakMap) | ❌ (returns null) | ❌ | ✅ | ✅ |
| Declarative open | ❌ **parser bypasses JS** | ✅ | ❌ | ✅ | ✅ |
| Declarative closed | ❌ **parser bypasses JS** | ❌ (returns null) | ❌ | ✅ | ✅ |

MutationObserver provides no help — there is no mutation type for "shadow root attached," and MutationObserver does not automatically observe inside shadow trees. A proposal (WHATWG DOM issue #1287) to add cross-shadow-boundary observation exists but is unimplemented. TreeWalker and NodeIterator also do **not** traverse into shadow roots. Standard `querySelectorAll` does not pierce shadow boundaries — this is by design for encapsulation.

The recommended detection strategy combines three layers:

**Layer 1 — MAIN-world `attachShadow` wrapper** (catches imperative roots, including closed):
```javascript
const shadowRoots = new WeakMap();
const origAttach = Element.prototype.attachShadow;
Element.prototype.attachShadow = function(init) {
  const root = origAttach.call(this, init);
  shadowRoots.set(this, root);
  return root;
};
```

**Layer 2 — Recursive `element.shadowRoot` scan** (catches all open roots including declarative):
```javascript
function querySelectorAllDeep(selector, root = document) {
  const results = [...root.querySelectorAll(selector)];
  for (const el of root.querySelectorAll('*')) {
    const sr = el.shadowRoot || shadowRoots.get(el);
    if (sr) results.push(...querySelectorAllDeep(selector, sr));
  }
  return results;
}
```

**Layer 3 — `chrome.dom.openOrClosedShadowRoot()`** (catches declarative closed roots in Chrome/Edge; Firefox equivalent is `Element.openOrClosedShadowRoot` in privileged context). This is the only mechanism that catches the hardest case. Bitwarden's autofill system uses exactly this API.

---

## 3. No major auth provider uses shadow DOM on login pages

An extensive survey of production login pages found that **none of the major identity providers** deploy shadow DOM on their credential forms: not Google (accounts.google.com), Microsoft (login.microsoftonline.com), Apple ID, Okta, Auth0, OneLogin, Duo, or Ping Identity. The reasons are pragmatic — shadow DOM breaks browser autofill, password manager detection, and accessibility tooling. Okta's developer forum explicitly documents that their Sign-In Widget fails when embedded inside a shadow root because it relies on `document.getElementById()`.

The notable exception is **Salesforce Lightning Web Components (LWC)**, which uses shadow DOM by default across all components, including on Experience Cloud sites that may host login pages. Salesforce is transitioning from synthetic shadow (a polyfill) to native shadow DOM starting Spring 2024. This creates a legitimate false-positive risk: a Salesforce-hosted login page with credential fields inside shadow roots is entirely benign.

Other real-world shadow DOM encounters on credential-adjacent pages include **Shopify** (closed shadow DOM on accelerated checkout/Shop Pay buttons), **Home Assistant** (Polymer-based login with shadow DOM, causing widespread password manager incompatibility), **SuperTokens** (provides `useShadowDom: false` config specifically to fix password manager issues), and **AWS Amplify Authenticator** (web components with shadow DOM, triggering 1Password autofill failures).

The **false positive mitigation heuristic** is straightforward: legitimate shadow DOM usage is application-wide and consistent (every component on a Salesforce page uses it), while hypothetical malicious usage would target only credential-collecting elements on an otherwise light-DOM page. A login form inside shadow DOM on a site that doesn't otherwise use web components is a meaningful signal of anomaly.

---

## 4. Phishing kits use entirely different evasion techniques

After searching across security vendor analyses (Proofpoint, Barracuda, Kaspersky, Microsoft Threat Intelligence, Cofense, Group-IB), phishing kit source code analyses (Tycoon 2FA, EvilProxy, Evilginx, GhostFrame, NakedPages, Sneaky 2FA, Cephas, Whisper 2FA), academic literature, and security conference archives, **no evidence of intentional shadow DOM usage in phishing kits was found**.

The single incidental case is the **Bubble.io no-code platform abuse** documented by Kaspersky in March 2025. Phishers used Bubble.io to generate credential-stealing applications, and the platform's generated code happened to include shadow DOM structures. The shadow DOM was a byproduct of the no-code builder, not a deliberate evasion choice.

What phishing kits actually use for evasion is far more effective and well-established: **JavaScript obfuscation** (Unicode invisible characters, Base64+XOR, LZ compression — found in 48% of kits per Barracuda), **CAPTCHA gates** (custom HTML5 Canvas CAPTCHAs, Cloudflare Turnstile — 43%), **anti-debugging** (blocking F12/DevTools, Burp Suite detection), **iframe architectures** (GhostFrame's blob URI image streaming), **multi-stage redirect chains** (up to 9 layers via Azure Blob, Firebase, Google services), and **DOM Vanishing Act** (Tycoon 2FA's technique where malicious JS removes itself from the DOM after execution — often confused with shadow DOM but entirely different).

The threat model analysis is decisive: **shadow DOM provides evasion benefit only against naive DOM-walking content scripts** that use `querySelectorAll` without shadow traversal. It provides zero benefit against Chrome Safe Browsing (URL/screenshot-based), email security gateways (network-level), URL reputation systems, visual similarity detectors, or JavaScript behavior analyzers. Since the attacker already controls the entire page, adding shadow DOM complexity for such narrow evasion gain is irrational when simpler, broader techniques exist.

No academic papers specifically study shadow DOM as a phishing evasion technique. No DEF CON, Black Hat, USENIX Security, or IEEE S&P presentations on this topic were found. The Princeton "Cracking ShadowCrypt" paper (PETS 2018) demonstrated that shadow DOM provides insufficient security guarantees, but this was about defensive shadow DOM usage, not offensive phishing.

---

## 5. Password managers already solved this problem — learn from Bitwarden

Bitwarden's open-source autofill system provides the definitive implementation reference. Their architecture documentation describes a **TreeWalker-based approach** combined with browser-specific privileged APIs:

- **Chrome/Edge**: Uses `chrome.dom.openOrClosedShadowRoot(element)` — this API ignores the open/closed mode distinction and returns the shadow root regardless, working for both declarative and imperative roots
- **Firefox**: Uses `Element.openOrClosedShadowRoot` in the extension's privileged context
- **Safari**: Falls back to `Element.shadowRoot` — only open roots are accessible

Bitwarden's PR #4119 attempted full shadow root autofill traversal but was initially **reverted due to performance regressions** in Firefox/Edge on pages with many input fields (TreeWalker is slower than `querySelectorAll`). This is an important lesson: recursive shadow DOM traversal has measurable cost on complex pages.

Existing open-source libraries provide battle-tested implementations. The **`query-selector-shadow-dom`** npm package (3.6M weekly downloads, MIT license, maintained by WebdriverIO) offers `querySelectorAllDeep(selector)` that recursively walks shadow roots. **`kagekiri`** by Salesforce/Nolan Lawson provides more correct CSS selector parsing using `postcss-selector-parser` and is used by Angular CDK's testing infrastructure. Playwright pierces open shadow DOM by default in all CSS selectors — every descendant combinator automatically crosses shadow boundaries.

**Performance is acceptable for targeted credential searches.** For finding ~5–10 specific input types (`input[type="password"]`, `input[type="email"]`, etc.) across the DOM, even on a complex Lit-based page with 200+ shadow roots, a targeted recursive query completes in under **10ms** on modern hardware. The performance concern applies mainly to broad `querySelectorAll('*')` sweeps across thousands of web components. The mitigation is using targeted selectors, limiting recursion depth to 5 levels (covers all real-world cases), debouncing scans, and caching shadow root references.

---

## 6. Shadow DOM as a defensive tool for PhishOps itself

An important secondary finding: **shadow DOM should be used by PhishOps to protect its own injected UI** from page manipulation. Multiple browser extensions use closed shadow DOM to isolate their UI from host page CSS and JavaScript interference. Bitwarden's inline autofill menu uses shadow DOM for exactly this purpose.

However, the DEF CON 33 presentation by Marek Tóth (August 2025) demonstrated that **all 11 tested password managers** — including those using shadow DOM — were vulnerable to DOM-based extension clickjacking. The attack uses invisible login forms to trigger autofill and steal credentials. The recommendation from security researchers is to combine closed shadow DOM with MutationObservers monitoring for unauthorized style changes. OWASP's Browser Extension Vulnerabilities Cheat Sheet explicitly warns that "even a 'closed' Shadow DOM is not safe if you consider other browser extensions as threats under your security model" because extensions can access closed roots via `openOrClosedShadowRoot()`.

---

## Final assessment and recommendations

**1. Build a shared utility, not a standalone detector.** PhishOps should implement a `deepQuerySelectorAll()` utility function that every existing detector calls instead of raw `querySelectorAll`. This utility recursively traverses open shadow roots and checks the WeakMap of intercepted closed roots. No new "ShadowDOMGuard" detector is warranted because shadow DOM is not an attack technique — it's an encapsulation boundary that existing detectors must be taught to cross.

**2. Specific implementation pattern:**
- MAIN-world script at `document_start`: wrap `attachShadow()` to capture closed imperative roots in a WeakMap
- ISOLATED-world script: use `chrome.dom.openOrClosedShadowRoot()` for comprehensive traversal including declarative closed roots
- Shared `deepQuerySelectorAll(selector, root)` function used by AutofillGuard, PhishVision's DOM analysis, and any future credential-form detectors
- Depth limit of 5 levels, targeted selectors for credential fields, debounced scanning

**3. False positive risk is low but real.** Salesforce LWC sites, Home Assistant, SuperTokens, and AWS Amplify legitimately use shadow DOM on credential pages. The distinguishing heuristic is whether shadow DOM usage is application-wide (legitimate) or isolated to credential-collecting elements (suspicious). Domain reputation and framework fingerprinting (detecting Lit/LWC/Stencil patterns) should supplement this.

**4. No evidence of shadow DOM as a phishing evasion technique in the wild.** Zero intentional usage across all analyzed PhaaS kits. One incidental case via Bubble.io no-code platform. The academic literature has not studied this intersection. This is a theoretical gap, not an active threat.

**5. Priority: Medium-Low among CUTTING_EDGE_DETECTORS candidates.** The shadow DOM traversal utility should be implemented as infrastructure hardening (ensuring existing detectors work on the growing ~2.5% of pages using shadow DOM), not as a high-priority new detection capability. It ranks below techniques addressing active threats like AiTM proxy detection, CAPTCHA-gated phishing, and JavaScript obfuscation evasion, but above purely speculative attack vectors. The implementation effort is low (the core utility is ~20 lines of code plus the `attachShadow` wrapper), making it a good candidate for early infrastructure work that pays compound dividends across all detectors.