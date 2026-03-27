# Navigation API adds zero phishing surface — deprioritize NavigationGuard

**The Navigation API cannot spoof cross-origin URLs, and its same-origin manipulation capabilities are identical to the History API's `pushState`/`replaceState`.** PhishOps should not build a dedicated NavigationGuard detector. The security delta between the Navigation API and the History API is effectively zero for phishing purposes. Two real CVEs (CVE-2022-4908 and CVE-2026-20643) have exposed implementation bugs in origin-boundary enforcement, but both were browser-level flaws — not spec design weaknesses — and both are patched. The correct investment is a unified **SPA Navigation Monitor** that detects suspicious same-origin URL changes from *both* APIs through `chrome.webNavigation.onHistoryStateUpdated`, which fires for both pushState and Navigation API interceptions.

---

## The Navigation API spec explicitly blocks cross-origin interception

The Navigation API graduated from WICG incubation into the **WHATWG HTML Living Standard** and reached Baseline Newly Available status in **January 2026**. Chrome shipped it in version 102 (May 2022), Edge followed on the same Chromium base, Firefox shipped in version 147 (~late 2025), and Safari in version 26.2 (~early 2026). Global browser support sits at roughly **88.78%**.

The API's security model is anchored on a single property: **`NavigateEvent.canIntercept`**. This boolean governs whether `event.intercept()` can be called, and it returns `false` for any cross-origin navigation. Calling `intercept()` when `canIntercept` is `false` throws a `SecurityError DOMException`. The WICG explainer states this explicitly:

> "Navigation interception can only update the URL bar to perform single-page app navigations to the same extent as `history.pushState()` does: the destination URL must only differ from the page's current URL in path, query, or fragment components. Thus, the navigate event does not allow URL spoofing by updating the URL bar to a cross-origin destination while providing your own origin's content."

The `canIntercept` rules for `http`/`https` URLs require scheme, host, and port to match exactly — only path, query, and fragment may differ. For `file` URLs, only query and fragment may differ. For all other schemes, only fragment changes are interceptable. Cross-document traversals (back/forward) also set `canIntercept` to `false`, even when same-origin. Additionally, `navigation.navigate()` explicitly throws a `SecurityError` for `javascript:` URLs, which is stricter than the History API. **There is no mechanism in the Navigation API to display a URL bar origin different from the page's actual origin.**

The spec's non-goals include: preventing user trapping (back button interception is disallowed), exposing cross-origin history entries, and exposing other frames' entries. The `navigation.entries()` method returns only same-origin, same-frame entries. History entry `key` and `id` values are per-session, per-frame, per-origin UUIDs that cannot be used for cross-site tracking.

---

## Two CVEs exposed implementation bugs, not spec design flaws

Despite the spec's sound security model, browser implementations have stumbled on origin-boundary enforcement in the Navigation API — producing two notable CVEs.

**CVE-2022-4908** (Chrome, discovered September 2022, disclosed October 2023) was a Same-Origin Policy bypass where calling `navigation.entries()` on an iframe navigated to `about:blank` leaked the **full URL history array** from the previous cross-origin document. Unlike `history.length` which only reveals a count, `navigation.entries()` exposed complete URLs — potentially including OAuth tokens, session identifiers, and PII in query parameters. Security researcher Johan Carlsson (joaxcar) discovered this, and it was nominated for PortSwigger's Top 10 Web Hacking Techniques of 2023. Fixed in Chrome 107.

**CVE-2026-20643** (WebKit/Safari, disclosed March 17, 2026, CVSS 5.4) was a same-origin policy bypass where `canIntercept` incorrectly returned `true` for cross-port navigations (e.g., `localhost:3000` → `localhost:3001`). The root cause was a **same-site vs. same-origin confusion** in WebKit's `NavigateEvent` dispatch code — it checked whether the target was same-site instead of verifying strict origin equality on scheme, host, username, password, and port. This allowed a malicious page to intercept navigations across port boundaries, maintaining its JavaScript execution context across what should have been an origin boundary. Patched in Safari Technology Preview 238 and delivered via Apple's Background Security Improvements.

A third issue, **Chromium #40060957**, is listed as "Navigation API can be used to bypass multiple CSP" but details remain restricted behind login. These bugs reinforce that the Navigation API is a *new implementation surface* where origin checks can go wrong, but they do not indicate the spec itself enables phishing attacks. Both public CVEs involved failures in same-origin enforcement — the web's fundamental security boundary — rather than novel URL spoofing vectors.

---

## Same-origin attack surface is identical to the 15-year-old History API

Every same-origin URL manipulation scenario achievable with the Navigation API is already achievable with `history.pushState()`, which has existed since ~2010. On a compromised WordPress site with XSS, an attacker can already execute `history.pushState({}, '', '/wp-admin/login.php')` and replace the DOM with a phishing form — no Navigation API required. The Navigation API's `navigation.navigate('/login')` or `event.intercept()` with a handler that renders fake content produces the exact same result through a different code path.

Eric Lawrence (Microsoft Defender team) confirmed this equivalence in his March 2024 analysis "pushState and URL Blocking" (updated April 2025): **"The new Navigation API appears to behave much like pushState."** His research demonstrated that both APIs create "virtual navigations" that bypass SafeBrowsing, SmartScreen, Chrome's URLBlocklist enterprise policy, and Defender's Network Protection. Both also bypass `chrome.webNavigation.onBeforeNavigate` in browser extensions. Lawrence cites Adam Barth's 2008 paper "Beware Finer-Grained Origins" to argue that path-level URL security is fundamentally unenforceable within the same origin — the security boundary is the origin itself.

The comparison across specific capabilities:

| Capability | History API | Navigation API | New risk? |
|---|---|---|---|
| Change URL path/query within same origin | Yes (`pushState`) | Yes (`navigate()`, `intercept()`) | No |
| Replace page content alongside URL change | Yes (DOM manipulation) | Yes (handler callback) | No |
| Spam back-button history entries | Yes (repeated `pushState`) | More restricted (spec anti-trapping design) | **Nav API is safer** |
| Cross-origin URL spoofing | Impossible | Impossible | No |
| Bypass `webNavigation.onBeforeNavigate` | Yes | Yes | No |
| Detectable via `onHistoryStateUpdated` | Yes | Yes | No |

The Navigation API does expose more *readable* information about history entries (`navigation.entries()` returns full URLs vs. `history.length` returning only a count), and it provides `traverseTo(key)` for key-based traversal. But neither capability creates a new phishing vector — they are observability and ergonomics improvements for legitimate SPA developers. Critically, the spec **does not allow programmatic creation, deletion, or rearrangement of history entries** (this is an explicit open issue, #9 on the WICG repo, still unresolved). The Navigation API is actually *more restricted* than the History API for history manipulation abuse because it was designed with anti-trapping principles from the start.

---

## Content script re-injection gap is not Navigation API-specific

Chrome MV3 content scripts inject **only when a new document is created** — on cross-document navigations. They never re-inject on same-document navigations, regardless of mechanism. This creates an identical gap for both APIs:

- **`history.pushState()` / `replaceState()`** → same-document → no re-injection
- **Navigation API `intercept()`** → converts cross-document to same-document → no re-injection
- **Navigation API `navigate()` without interception** → cross-document → content scripts DO inject
- **Hash/fragment changes** → same-document → no re-injection

Chrome's own tutorial explicitly acknowledges this: "developer.chrome.com is a SPA so can update the address bar and render new content without reloading. Our content script won't be reinjected when this happens." This gap has existed since SPAs adopted pushState-based routing and is **not new or specific to the Navigation API**.

The detection surface for a PhishOps extension is well-defined. `chrome.webNavigation.onHistoryStateUpdated` fires for both pushState and Navigation API same-document navigations, making it the primary detection hook. `chrome.tabs.onUpdated` with URL monitoring provides a redundant fallback. Inside the content script itself, a `MutationObserver` on the DOM can detect content replacement regardless of which API triggered the URL change. Chrome 106+ also introduced `documentId`, a UUID that persists across same-document navigations but changes on cross-document ones, enabling precise document lifecycle tracking.

| Extension event | Catches pushState? | Catches Navigation API intercept()? |
|---|---|---|
| `webNavigation.onHistoryStateUpdated` | Yes | Yes |
| `tabs.onUpdated` (URL change) | Yes | Yes |
| `webNavigation.onBeforeNavigate` | **No** | **No** |
| `webNavigation.onCommitted` | No (same-doc) | No (same-doc) |

---

## PhishOps should build a unified SPA Navigation Monitor instead

The evidence strongly supports **deprioritizing the NavigationGuard detector** and investing instead in a broader SPA Navigation Monitor that covers both APIs uniformly. The reasoning is straightforward:

- **Zero security delta.** The Navigation API adds no URL manipulation capability beyond `pushState`. Every attack scenario maps 1:1 to an existing History API attack.
- **Same detection hooks.** `webNavigation.onHistoryStateUpdated` and `tabs.onUpdated` catch both APIs identically. A single detector covers both.
- **Framework adoption is still History API-first.** As of March 2026, React Router v7 and Vue Router v5 still use `history.pushState` internally. Until frameworks migrate, the History API remains the dominant SPA routing mechanism. Targeting Navigation API alone would miss the vast majority of real-world SPA navigations.
- **The real threat is origin compromise, not API choice.** Same-origin URL manipulation (whether via pushState or Navigation API) only matters when an attacker has XSS or controls a subdomain. The detection logic should focus on suspicious URL changes and DOM mutations — heuristics that are API-agnostic.

A unified SPA Navigation Monitor should use `chrome.webNavigation.onHistoryStateUpdated` as its primary trigger, `tabs.onUpdated` as redundancy, and content-script-side `MutationObserver` to detect DOM replacement. It should apply heuristics to flag suspicious transitions — such as a sudden change to login-like paths (`/login`, `/signin`, `/wp-admin`) accompanied by form injection — regardless of whether the underlying URL change came from pushState, replaceState, or the Navigation API. This approach is **both more effective and lower-cost** than a Navigation API-specific detector.

---

## Conclusion

The Navigation API is a developer ergonomics improvement for SPA routing, not a security escalation. **Cross-origin URL bar spoofing is impossible by design** — `canIntercept` enforces the same origin restrictions as `pushState`, and the spec authors explicitly designed against it. The two real CVEs (Chrome's history entry leak and WebKit's cross-port interception bug) demonstrate that *implementation* of origin checks can fail, but these are browser-vendor bugs, not attack vectors an extension can or should defend against. The content script re-injection gap is identical to the pre-existing pushState gap. PhishOps should deprioritize NavigationGuard and build a unified SPA Navigation Monitor that treats all same-origin URL manipulation — pushState, replaceState, and Navigation API — as a single detection surface, keyed on `webNavigation.onHistoryStateUpdated` and DOM mutation observation.