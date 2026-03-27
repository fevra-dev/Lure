# Phishing kit evasion vs. browser extension stealth: the detection arms race

**PhaaS kits in 2024–2026 deploy sophisticated anti-analysis but do not yet specifically fingerprint API wrappers via `toString()` probing or timing analysis—creating a strategic window for hardened defenses.** Today's kits focus on bot/sandbox detection (navigator.webdriver, debugger timing, IP reputation, CAPTCHA gating) rather than detecting security extension API hooks. However, the academic literature proves that JavaScript API wrapping is detectable in principle through reflection, timing side-channels, and cross-frame verification. The optimal defensive strategy is not perfect stealth—which is theoretically unbounded in cost—but a dual approach: harden wrappers using Proxy-based techniques that defeat current detection methods, while simultaneously deploying meta-detection that flags pages probing for security tools. This report synthesizes threat intelligence on **7+ PhaaS kits**, **4 open-source frameworks**, **12+ academic papers**, and stealth engineering techniques to define the current state of the art and recommend a concrete defensive posture.

---

## PhaaS kits fingerprint environments, not extensions

Modern PhaaS kits implement layered anti-detection, but their focus is distinguishing real victims from security researchers, sandboxes, and automated crawlers—not detecting browser security extensions specifically. **Tycoon 2FA**, which accounted for **62% of all AiTM phishing blocked by Microsoft** before its March 2026 takedown, exemplifies the current state of the art. Its anti-analysis pipeline performs seven categories of checks: Cloudflare Turnstile or custom HTML5 canvas CAPTCHAs, `navigator.webdriver` detection for Selenium/Puppeteer/Playwright, PhantomJS and Burp Suite signature detection, `debugger` statement timing loops (redirecting to benign sites if DevTools adds >100ms processing lag), IP reputation filtering against datacenter/VPN/Tor databases, geofencing, and extensive browser fingerprinting collecting screen parameters, WebGL renderer, canvas hash, timezone, hardware concurrency, device memory, fonts, and plugins.

The critical finding for the PhishOps Detection Portfolio: **no public threat intelligence reports document PhaaS kits checking `Function.prototype.toString()` on wrapped APIs like fetch or WebSocket, timing API calls to detect interception overhead, or probing `chrome.runtime.sendMessage()` for specific security extension IDs.** Kits check `navigator.webdriver` and `navigator.plugins` for automation markers, but they do not inspect whether `window.fetch` has been replaced with a Proxy or whether `WebSocket` has been wrapped. This represents a significant gap in attacker capabilities—and a window of opportunity for defenders.

Other major kits follow similar patterns. **EvilProxy** emphasizes VM detection and RDP client detection. **Mamba 2FA** collects device and browser fingerprints via a dedicated filtering page, sending data to a server that decides phishing-or-redirect. **Rockstar 2FA** (and its successor **FlowerStorm**) gates with Cloudflare Turnstile and serves car-themed decoy pages to suspicious visitors. **Sneaky 2FA** introduced Browser-in-the-Browser visual spoofing and collects a "qualityScore" from mouse jitter and key press timing. **Starkiller**, the newest kit (February 2026), takes a radical approach: it runs a headless Chrome instance in Docker as a live reverse proxy, rendering the real login page so no template files exist for defenders to fingerprint.

The **dark web anti-bot ecosystem** sells standalone services (Otus Anti-Bot, Remove Red, Limitless Anti-Bot) to PhaaS operators. These services analyze headers, user-agent strings, IP addresses, and mouse movements. If a non-human visitor is detected, they serve Google search pages or dummy websites. Known security crawler user-agents (VirusTotalBot, Palo Alto Expanse scanner) are trivially blocked.

## Open-source frameworks lack extension detection entirely

Analysis of the four major open-source phishing frameworks reveals a consistent pattern: **none include browser extension detection, bot detection, or browser fingerprinting as built-in features**. Evilginx, Modlishka, Muraena, and GoPhish focus exclusively on transparent reverse proxying and credential/session capture. GoPhish parses User-Agent strings for basic OS/browser logging, but a 2016 feature request for plugin detection was only partially implemented and then closed.

All four frameworks provide JavaScript injection capabilities (`js_inject` in Evilginx, `jsRules` in Modlishka, plugin modules in Muraena, template injection in GoPhish) that operators could use to inject custom fingerprinting scripts. This means the capability gap is not architectural—it's that the current PhaaS market has not yet prioritized extension detection as a feature.

The browser fingerprinting library **CreepJS** is the most relevant tool in this space. It explicitly detects JavaScript prototype tampering ("prototype lies"), fingerprints extension code modifications, and identifies specific tools including uBlock Origin, NoScript, Privacy Badger, JShelter, DuckDuckGo Privacy Essentials, and puppeteer-extra. CreepJS checks whether `Function.prototype.toString` returns expected native code patterns and identifies wrapper functions injected by privacy extensions. If PhaaS kit developers adopt CreepJS-style prototype lie detection, the PhishOps extension's API wrappers would become immediately detectable without hardening.

## Proxy-based wrapping defeats current toString checks in Chrome

The technical foundation for stealth API wrapping rests on a critical V8 behavior: **when `Function.prototype.toString` is called on a JavaScript Proxy wrapping a native function, Chrome returns `"function fetch() { [native code] }"`—the same string as the unwrapped native function.** This means a Proxy-based wrapper passes the most common detection check without any additional patching.

```javascript
const fetchProxy = new Proxy(window.fetch, {
  apply(target, thisArg, args) {
    // interception logic
    return Reflect.apply(target, thisArg, args);
  }
});
window.fetch = fetchProxy;
// window.fetch.toString() → "function fetch() { [native code] }" ✓
```

A naive function replacement (non-Proxy) fails this check—`toString()` reveals the wrapper source code. The `.bind()` trick produces `"function () { [native code] }"` but leaks via `fetch.name` returning `"bound fetch"` instead of `"fetch"`. Only the Proxy approach transparently passes `toString()`, `typeof`, `name`, and `length` checks simultaneously.

However, **five residual detection vectors** survive even Proxy-based wrapping:

**Reference equality (`===`)** is the most fundamental. A Proxy is never `===` to its target. If any page script captures `const origFetch = window.fetch` before the wrapper installs, then `window.fetch === origFetch` returns `false` after proxying. There is no mechanism in JavaScript to intercept the `===` operator. The only defense is injecting at `document_start` before any page script executes.

**Error stack traces** reveal Proxy-related frames like `"at Reflect.apply"` or `"at Object.apply"`. The puppeteer-extra-plugin-stealth project addresses this with `stripProxyFromErrors`, which wraps every Proxy trap in try/catch and filters Proxy-revealing lines from `err.stack`.

**Cross-frame (iframe) verification** is the hardest vector to defeat. A detection script can create a fresh iframe, obtain its `Function.prototype.toString`, and call it on the suspected function—bypassing any `toString` patching in the main frame. Defense requires intercepting `document.createElement('iframe')` or proxying `HTMLIFrameElement.prototype.contentWindow` to patch `toString` in newly created iframes before page code accesses them.

**Timing side-channels** exploit the 36–80x overhead of Proxy traps on microbenchmarks. However, for real-world operations like `fetch()` (dominated by network latency) or `WebSocket` construction, the overhead is negligible. Chrome Zero demonstrated only **1.54% median JavaScript runtime overhead** from defensive API wrapping on Alexa Top 10 sites. Post-Spectre timer resolution of **100µs in Chrome** with random jitter further limits timing attack precision, though statistical accumulation over many calls could theoretically detect overhead.

**`Proxy` constructor interception** allows detection scripts to override `window.Proxy` to log all Proxy creation—but only if they run before the wrapper. Running at `document_start` mitigates this.

## The academic consensus: perfect stealth is practically infeasible

A decade of academic research across USENIX Security, IEEE S&P, NDSS, CCS, and WWW establishes that **browser extension undetectability is an unsolved problem with strong evidence suggesting practical infeasibility** for extensions that meaningfully interact with web page content. No formal impossibility proof exists, but the cumulative evidence is compelling.

The research trajectory reveals an escalating arms race. **XHOUND** (IEEE S&P 2017) established DOM-based fingerprinting, finding 9.2% of the top 10,000 Chrome extensions detectable through DOM modifications. **Carnus** (NDSS 2020) expanded to behavioral fingerprinting via HTTP request patterns and postMessage exchanges, fingerprinting **29,428 unique extensions**. **Fingerprinting in Style** (USENIX Security 2021) discovered CSS-based detection, identifying 4,446 extensions through injected stylesheets—24% not detectable by prior techniques. **Chronos** (CCS 2022) introduced continuous monitoring via MutationObserver, capturing ephemeral modifications and detecting **11,219 unique extensions** (66.9% increase over prior work). Most recently, **Peeking through the Window** (CCS 2024) demonstrated JavaScript namespace fingerprinting, detecting 3,398 extensions through global variable pollution and stack traces—using the same API-hooking technique that web pages could use to detect security extensions.

The best defensive system, **Simulacrum** (USENIX Security 2022), achieves **95.37% protection** through "DOM Reality Shifting"—maintaining a parallel clean DOM that web page queries are routed through while extension modifications only appear in the user-visible DOM. But even Simulacrum cannot protect extensions that inject scripts into the page's execution context (40 extensions in their study used this pattern), which is precisely what MAIN-world content scripts do.

The timing side-channel literature is particularly relevant. **Fantastic Timers** (USENIX Security 2017) demonstrated that nanosecond-resolution timing is achievable in all browsers through multiple alternative timing sources, even after Spectre mitigations. **Sanchez-Rola et al.** (USENIX Security 2017) achieved **100% detection rate** for extension presence using timing side-channels on WAR resource access. The **Latex Gloves** paper (NDSS 2019) showed that Firefox's randomized extension IDs can paradoxically *exacerbate* fingerprinting by creating unique per-user fingerprints—demonstrating that naive mitigations can backfire.

For the PhishOps extension specifically, the most relevant finding is from the CCS 2024 paper: web pages can overwrite globally accessible APIs to capture extension invocations. This is the mirror image of what the PhishOps detectors do—and it means that in principle, a phishing page could wrap `fetch` *before* the extension, or detect that `fetch` has been wrapped by checking behavioral differences.

## The stealth engineering playbook from puppeteer-extra-plugin-stealth

The puppeteer-extra-plugin-stealth project represents the most mature open-source implementation of JavaScript stealth techniques, with ~17 evasion modules and 504 lines of core utility functions. Its architecture provides a battle-tested template for hardening the PhishOps extension's API wrappers.

The five critical techniques are **`patchToString`** (replacing `Function.prototype.toString` with a Proxy that returns native-looking strings for wrapped functions), **`redirectToString`** (redirecting a proxy's toString to return the original object's representation), **`stripProxyFromErrors`** (wrapping every trap in try/catch and filtering Proxy-revealing lines from stack traces), **`replaceWithProxy`** (an all-in-one method combining Proxy creation, property replacement via defineProperty, and toString patching), and **`preloadCache`** (caching `Reflect.get`, `Reflect.apply`, and native `Function.toString` string before any modifications to prevent recursive lookups and external tampering).

The recommended implementation pattern for PhishOps detectors:

1. Execute at `document_start` in MAIN world, before any page scripts
2. Cache all native references immediately (`Reflect.apply`, `Reflect.get`, native toString string)
3. Create Proxy with only an `apply` trap using cached `Reflect.apply`
4. Replace the property via `Object.defineProperty` matching the original descriptor
5. Patch `Function.prototype.toString` using a Proxy that intercepts calls on wrapped functions
6. Wrap `stripProxyFromErrors` around all traps to sanitize error stack traces
7. Optionally intercept iframe creation to patch toString in new frames

This combination passes toString checks, typeof checks, name/length property checks, hasOwnProperty checks, prototype chain verification, and error stack analysis. The remaining vectors—reference equality (mitigated by document_start timing), cross-frame verification (mitigated by iframe interception), and timing analysis (negligible for network-bound operations like fetch)—represent acceptable residual risk.

## Meta-detection is the dominant defensive strategy

Game-theoretic analysis from the adversarial machine learning literature (Xu et al., ACM Computing Surveys 2021) and Stackelberg security game models establish that **perfect stealth is a losing strategy due to unbounded escalating costs, while meta-detection provides bounded cost with asymmetric advantage to the defender.**

The core insight is that an attacker who probes for security tools creates an observable signal. If a phishing page calls `Function.prototype.toString.call(window.fetch)` and checks for `[native code]`, or measures `fetch()` execution time across 1,000 iterations, or attempts to access `chrome-extension://` URLs for known security extension IDs—each of these behaviors is itself suspicious and can be detected by the very extension being probed.

This creates an **attacker's dilemma**: not probing means accepting uncertainty about whether security tools are present (and risk having credentials intercepted), while probing means creating detectable behavioral signals. The defender gains information from the attacker's probing regardless of whether the wrapping is ultimately detected. This is structurally analogous to quantum key distribution, where the act of measurement disturbs the system being measured.

The **recommended dual strategy** for the PhishOps Detection Portfolio:

- **Layer 1 (Stealth):** Harden all API wrappers using the Proxy + toString patch + stack sanitization approach. This defeats all currently deployed PhaaS kit detection methods and raises the bar for future detection.
- **Layer 2 (Meta-detection):** Add a new detector that monitors for suspicious probing behavior—pages that call `Function.prototype.toString` on security-sensitive APIs (`fetch`, `WebSocket`, `navigator.credentials`, `eval`), create iframes and immediately access their `Function.prototype`, run timing loops on wrapped APIs, or attempt WAR probing of known security extension IDs. Flag such behavior as an **evasion-aware phishing signal** with high confidence.
- **Layer 3 (Randomization):** Vary the wrapping implementation across sessions or domains to prevent attackers from building reliable detection heuristics. Use Proxy on some visits, direct function wrapping on others, or vary the properties left observable.

The game-theoretic prediction is that rational attackers will respond to meta-detection by attempting to make their probing indistinguishable from normal page behavior—which is significantly harder and more expensive than simple toString checks, shifting the cost burden to the attacker.

## Google's WEI withdrawal and the political limits of attestation

Google's **Web Environment Integrity (WEI)** proposal, introduced in April 2023 and withdrawn November 2, 2023, represents the theoretical endpoint of the detection arms race: hardware-rooted attestation that browser environments are unmodified. Rather than cat-and-mouse fingerprinting, WEI would have allowed websites to request cryptographically signed tokens from OS-level attesters (e.g., Google Play) certifying device integrity. Any browser modification—including security extensions—could have been flagged.

The proposal drew immediate condemnation from Mozilla ("contradicts our principles"), Brave ("we won't ship it"), Vivaldi ("toxic to the open web"), and the EFF. Critics correctly identified that while the explainer claimed extensions would still be allowed, websites could refuse to serve users whose attestation indicated non-standard environments. The withdrawal demonstrates that **social and political constraints** are as important as technical ones in the detection arms race. Even a technically sound attestation mechanism is infeasible if it threatens the open web ecosystem. Its replacement, the Android WebView Media Integrity API, is narrowly scoped to embedded streaming media.

For extension developers, WEI's withdrawal is strategically significant: it means the "nuclear option" of environment attestation is off the table for the foreseeable future, preserving the space for extension-based security tools to operate.

## Firefox offers marginally better stealth properties

Firefox's extension isolation model provides two advantages over Chrome for stealth. First, Firefox uses **per-installation random UUIDs** for `moz-extension://` URLs rather than Chrome's fixed extension IDs, making WAR-based fingerprinting significantly harder across browser instances. BrowserLeaks confirms that the timing side-channel for extension detection via WAR probing is "impossible in Firefox" due to this randomization.

Second, Firefox's **Xray vision** system allows content scripts to see the original native version of DOM objects, not page-redefined versions. This means content scripts are less likely to create detectable discrepancies when interacting with the DOM. Chrome's isolated worlds provide clean separation but still expose DOM mutations to page scripts via MutationObserver.

However, **both browsers remain vulnerable** to DOM-based detection (MutationObserver), CSS injection detection (getComputedStyle), behavioral fingerprinting (e.g., detecting ad blocking effects), and JavaScript namespace pollution when scripts execute in the page's main world. Chrome MV3's `use_dynamic_url` for web accessible resources partially addresses WAR probing, but adoption remains very low—BrowserLeaks found that "very few extensions that use web-accessible resources also enable this feature."

## Conclusion

The PhaaS ecosystem's current anti-detection capabilities are sophisticated but narrowly focused on bot/sandbox detection rather than security extension fingerprinting. This creates a **strategic window** for the PhishOps Detection Portfolio: hardened Proxy-based API wrappers will defeat all currently deployed detection methods, and no open-source phishing framework includes extension-specific detection code. The threat horizon, however, is clear—CreepJS-style prototype lie detection is openly available, and the CCS 2024 academic literature explicitly demonstrates JavaScript namespace fingerprinting of extension behavior.

Three novel insights emerge from this research. First, the `document_start` + MAIN world + Proxy approach is more stealthy than previously assumed, because V8's `Function.prototype.toString` implementation transparently returns `[native code]` for Proxy-wrapped functions without any toString patching—though patching provides defense-in-depth against edge cases. Second, the meta-detection approach (flagging pages that probe for security tools) inverts the arms race by making the attacker's reconnaissance itself a detection signal, creating an asymmetric information advantage for defenders. Third, the PhishOps extension should enable `use_dynamic_url: true` for all web accessible resources in its MV3 manifest immediately—this single configuration change eliminates the highest-confidence extension detection vector (WAR probing) at zero engineering cost.

The optimal posture is not stealth alone or meta-detection alone, but **both simultaneously**: make wrappers as hard to detect as current engineering allows, while treating detection attempts as high-confidence phishing signals. The attacker faces a dilemma; the defender gains information either way.