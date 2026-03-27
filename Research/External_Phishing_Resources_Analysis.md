# External Phishing Resources Analysis for PhishOps/lur3

> **Date:** 2026-03-26
> **Purpose:** Evaluate external phishing APIs, tools, and projects for features applicable to lur3's 45-detector browser extension architecture.

---

## Resources Reviewed

| # | Resource | Type | Status |
|---|----------|------|--------|
| 1 | [RapidAPI Phishing Detection](https://rapidapi.com/marianojaozamis/api/phishing-detection) | Cloud API | Active |
| 2 | [RapidAPI Cybersecurity/Phish Search](https://rapidapi.com/search/Cybersecurity?term=phish&sortBy=ByRelevance) | API Marketplace | Active |
| 3 | [PhishStats API](https://phishstats.info/) | Free Threat Intel API | Active |
| 4 | [urlscan.io API](https://urlscan.io/) | Scan & Intel API | Active |
| 5 | [phishnet.cc](https://phishnet.cc/) | Phishing Intel Platform | Active |
| 6 | [olizimmermann/phishnet](https://github.com/olizimmermann/phishnet) | OSS Kit Hunter | Active |
| 7 | [olizimmermann/phishcollector](https://github.com/olizimmermann/phishcollector) | OSS Collection Framework | Active |

---

## 1. PhishStats API

**What it is:** Free phishing intelligence API with ~no auth requirement, providing structured records of known phishing URLs with rich metadata.

**Base endpoint:** `https://api.phishstats.info/api/phishing`

**Data per record:**
- URL, redirect URL, hash
- IP, ASN, BGP, ISP, geolocation (country, region, city, lat/long)
- Domain age (`domain_registered_n_days_ago`), host/domain rank
- Technology stack, HTTP server, OS, open ports
- SSL issuer, subject, fingerprint
- Detection verdicts: Google Safe Browsing, VirusTotal, abuse.ch
- Page title, page text, screenshot URL, tags, threat score
- Frequency: `n_times_seen_ip`, `n_times_seen_host`, `n_times_seen_domain`

**Query capabilities:**
- Filter: `_where=(field,operator,value)` with AND/OR logic
- Sort: `_sort=field` (prefix `-` for descending)
- Paginate: `_p=page&_size=records` (max 100/page)
- Rate limit: 20 requests/minute

### Applicability to lur3

| Feature | Value for PhishOps | Integration Concept |
|---------|-------------------|---------------------|
| **Domain age scoring** | HIGH | Supplement proxy_guard and phishvision with domain registration recency. Newly registered domains visiting credential pages = strong signal. |
| **IP frequency data** | HIGH | `n_times_seen_ip` indicates known-bad infrastructure. Could feed a lightweight blocklist or scoring boost in the service worker. |
| **SSL fingerprint matching** | MEDIUM | Cross-reference SSL fingerprints seen on current page against known phishing infrastructure fingerprints from PhishStats. |
| **Technology detection** | MEDIUM | Phishing kits cluster on specific tech stacks (e.g., certain PHP frameworks). Could inform heuristics. |
| **Google SafeBrowsing + VT verdicts** | LOW | We already do client-side detection; external verdicts are confirmatory, not primary. Useful for telemetry enrichment in a SOC deployment. |
| **Screenshot URLs** | LOW | Not useful for real-time detection, but valuable for post-incident investigation dashboards. |

**Recommended integration:** Background service worker periodically pulls recent high-score entries, builds a compact domain/IP blocklist in `chrome.storage.local`. Content scripts check current page domain against this hot list as a supplementary signal (not primary detection).

---

## 2. urlscan.io API

**What it is:** URL scanning and search platform with deep page analysis. Industry-standard tool used by SOCs worldwide.

**Key endpoints:**
- `POST /api/v1/scan/` - Submit URL for scanning (returns UUID)
- `GET /api/v1/result/{uuid}/` - Full scan results
- `GET /api/v1/search/?q={query}` - ElasticSearch query syntax

**Authentication:** API key via `API-Key` header

**Search capabilities:** ElasticSearch Query String syntax, max 10,000 results per query, cursor-based pagination via `search_after`.

**Result data includes:** Screenshots, DOM snapshots, full network request logs, page content analysis, technology detection, threat verdicts.

**Rate limiting:** Fixed-window (minute/hour/day UTC reset), HTTP 429 with `X-Rate-Limit-*` headers.

**Auto-ingestion sources:** OpenPhish, PhishTank, CertStream, Twitter, URLhaus.

### Applicability to lur3

| Feature | Value for PhishOps | Integration Concept |
|---------|-------------------|---------------------|
| **On-demand URL scanning** | HIGH | When PhishOps triggers a high-confidence alert, auto-submit the URL to urlscan.io for deep analysis. Enriches telemetry with third-party forensic evidence. |
| **Search for known phishing infrastructure** | HIGH | Query urlscan.io for domains/IPs matching current suspicious page. If already tagged as phishing in their corpus, boost confidence score. |
| **DOM snapshots** | MEDIUM | Post-detection, fetch DOM snapshot for forensic comparison. Useful in SOC deployment for incident response. |
| **Network request logs** | MEDIUM | Useful for validating AiTM proxy detection (proxy_guard) against known relay infrastructure patterns. |
| **Screenshot comparison** | LOW | Post-incident only; our phishvision does real-time brand detection already. |

**Recommended integration:** Two modes:
1. **Reactive enrichment:** On high-severity detection events, submit URL to urlscan.io and attach result UUID to telemetry payload. SOC analysts get one-click forensic drill-down.
2. **Proactive lookup:** Before committing to a full alert, query search API for `page.domain:{domain}` to check if already flagged. Fast confidence multiplier.

---

## 3. phishnet.cc (Platform)

**What it is:** Real-time phishing intelligence platform tracking phishing kits, URLs, and hosting infrastructure. Run by oz-security.io.

**Data available:**
- Live feed of tracked phishing URLs (downloadable `feed.txt`)
- Phishing kit discovery tracking (24h, 7d, 30d trends)
- Top hosting IPs, countries, ASNs, most-targeted brands
- Defanged URLs with metadata (IP, geolocation, ASN, page title, timestamps, HTTP status)

### Applicability to lur3

| Feature | Value for PhishOps | Integration Concept |
|---------|-------------------|---------------------|
| **Live URL feed** | HIGH | Ingest `feed.txt` as a threat intel source. Build domain/path pattern blocklist. Updated per collection run = near-real-time coverage. |
| **Most-targeted brands** | MEDIUM | Feed brand targeting trends into phishvision's brand list priority. If Microsoft is #1 targeted this week, weight Microsoft impersonation signals higher. |
| **Hosting infrastructure patterns** | MEDIUM | ASN/IP clustering data could improve proxy_guard's infrastructure fingerprinting. Known-bad ASNs = risk multiplier. |
| **Kit discovery data** | LOW | More relevant for threat intel reporting than real-time browser detection. |

**Recommended integration:** Periodic feed ingestion (hourly/daily) into a compact URL pattern set stored in extension storage. Could also power a future "threat landscape" panel in the popup UI.

---

## 4. olizimmermann/phishnet (OSS Tool)

**What it is:** Python-based threat intelligence aggregator. Collects phishing URLs from multiple feeds, hunts for phishing kits, extracts forensic metadata.

**Key capabilities:**
- **Feed aggregation** with deduplication across TXT/CSV sources
- **Kit hunting:** Walks URL path segments looking for archive files (.zip, .rar, .tar.gz, .7z) via magic byte validation
- **HTTP/TLS fingerprinting:** Status codes, redirect chains, headers, TLS cert details (issuer, validity, SANs, fingerprints)
- **HTML analysis:** Page titles, form action endpoints (credential exfil targets)
- **IP geolocation** via ipinfo.io
- **Notifications:** Telegram/Slack alerts with per-run summaries
- **Auto-submission** to urlscan.io
- **Two-phase processing:** Kit hunt first, then metadata crawl only for kit-positive URLs

**Tech stack:** Python 3.11+, SQLite, ThreadPoolExecutor

**Database schema (30+ columns):** HTTP metadata, TLS details, network data, page analysis, kit hunt results, urlscan tracking.

### Applicability to lur3

| Feature | Value for PhishOps | Integration Concept |
|---------|-------------------|---------------------|
| **Form action endpoint extraction** | HIGH | The concept of extracting credential exfiltration targets from `<form action>` is directly applicable. We do this in several guards already, but phishnet's systematic approach of cataloging exfil endpoints could feed a known-bad exfil domain list. |
| **Redirect chain analysis** | HIGH | Phishing uses multi-hop redirects. phishnet's chain-following logic could inspire a redirect chain depth/pattern detector in the service worker via `webNavigation.onBeforeNavigate` + `webRequest`. |
| **TLS fingerprint database** | MEDIUM | Catalog of SSL fingerprints from confirmed phishing infrastructure. Could be cross-referenced at connection time. |
| **Kit path-walking algorithm** | LOW | Interesting for offensive research but not applicable to a browser extension's real-time detection model. |
| **Feed aggregation pattern** | MEDIUM | The multi-source deduplication approach is a good model for how lur3 could aggregate multiple threat feeds (PhishStats + phishnet.cc + urlscan.io) into a unified local blocklist. |

**Key takeaway:** The form-action exfil target database concept is the most transferable idea. Building a known-bad credential submission endpoint list (harvested from tools like phishnet) would give PhishOps a fast-lookup signal: "this page submits credentials to a known phishing exfil domain."

---

## 5. olizimmermann/phishcollector (OSS Framework)

**What it is:** Research framework for systematically collecting, analyzing, and tracking phishing infrastructure. Headless browser-based with deep page inspection.

**Key capabilities:**
- **Headless Chromium** with JS execution, randomized UAs, anti-bot evasion
- **Full capture:** HTML, screenshots, network requests, JS/CSS assets
- **Site fingerprinting:** IP/ASN/geolocation, TLS certs, WHOIS, tech stack ID
- **Link discovery:** Spidering, robots.txt, sitemap analysis, wordlist fuzzing
- **Threat intel integration:** URLhaus (abuse.ch), VirusTotal v3 API
- **PHISHING_PATTERNS:** Regex rules for credential harvesting, obfuscation, exfiltration, anti-bot detection, kit indicators
- **TECH_SIGNATURES:** Technology detection across HTML, headers, cookies, URLs
- **Favicon hashing:** mmh3 (Shodan-compatible format)

**Tech stack:** Python (FastAPI, SQLAlchemy, Playwright), PostgreSQL, Docker Compose

### Applicability to lur3

| Feature | Value for PhishOps | Integration Concept |
|---------|-------------------|---------------------|
| **PHISHING_PATTERNS regex rules** | HIGH | Their categorized regex patterns (credential harvesting, obfuscation, exfiltration, anti-bot, kit indicators) could be adapted for content script scanning. Compare against our existing heuristics in llm_scorer, agentintentguard, etc. to find detection gaps. |
| **Favicon hashing (mmh3)** | HIGH | Favicon hash matching is a fast, reliable brand impersonation signal. If a page's favicon hash matches a known brand but the domain doesn't, it's a strong phishing indicator. Directly enhances phishvision. |
| **TECH_SIGNATURES detection** | MEDIUM | Technology fingerprinting across HTML/headers/cookies could help identify phishing kit frameworks. A PhaaS kit using a specific jQuery version or PHP pattern = risk signal. |
| **Anti-bot detection patterns** | MEDIUM | Phishing pages that detect bots/scanners are more sophisticated. Detecting anti-bot code on a credential page is itself a phishing signal (legitimate sites don't usually anti-bot their login pages). |
| **Form field analysis** | MEDIUM | Their credential field detection logic could supplement autofill_guard's approach. |
| **Network request logging** | LOW | We already monitor network activity via webRequest API. |

**Key takeaway:** Two high-value ideas:
1. **Favicon hash matching** - fast, deterministic brand impersonation signal
2. **Categorized phishing pattern regexes** - audit our detection coverage against their pattern library to find blind spots

---

## 6. RapidAPI Phishing Detection API

**What it is:** Cloud-hosted phishing URL classification API on RapidAPI marketplace.

**Note:** Page content could not be fully extracted (JS-rendered SPA). Based on the API's category and typical RapidAPI phishing detection offerings:

### Applicability to lur3

| Feature | Value for PhishOps | Integration Concept |
|---------|-------------------|---------------------|
| **URL classification endpoint** | LOW | Cloud API dependency adds latency and requires API keys. lur3's strength is fully client-side, zero-latency detection. Would only be useful as a secondary validation layer in a SOC deployment. |
| **ML-based URL scoring** | LOW | We already have llm_scorer for content analysis. URL-level ML scoring adds marginal value on top of our 45 behavioral detectors. |

**Not recommended** as a primary integration. The latency and API key requirement conflict with lur3's zero-dependency, offline-capable design philosophy.

---

## Synthesis: Priority Integration Roadmap

### Tier 1 - High Value, Low Effort

| Integration | Source | Effort | Impact |
|-------------|--------|--------|--------|
| **Known-bad domain/IP hot list** | PhishStats API + phishnet.cc feed | Low | Adds reputation-based signal layer. Service worker periodically fetches, stores compact set in `chrome.storage.local`. Content scripts check current domain against it. |
| **Favicon hash matching** | PhishCollector concept | Medium | Deterministic brand impersonation detection. Hash the current page's favicon, compare against known brand favicon hashes. Enhances phishvision significantly. |
| **Known-bad exfil endpoint list** | phishnet form-action database concept | Low | Fast lookup: "does this page submit credentials to a known phishing exfil domain?" Supplements existing form monitoring in autofill_guard, ws_exfil_guard, canvas_exfil_guard. |

### Tier 2 - High Value, Medium Effort

| Integration | Source | Effort | Impact |
|-------------|--------|--------|--------|
| **urlscan.io reactive enrichment** | urlscan.io API | Medium | On high-severity alerts, auto-submit URL for deep analysis. Attach result UUID to telemetry. SOC gets one-click forensic drill-down. Requires API key config. |
| **Domain age scoring** | PhishStats API | Medium | Query domain registration recency for suspicious pages. Newly registered domain + credential form = high-confidence signal. |
| **Phishing pattern regex audit** | PhishCollector PHISHING_PATTERNS | Medium | Compare our detection rules against their categorized pattern library. Identify coverage gaps in obfuscation detection, kit indicators, anti-bot patterns. |

### Tier 3 - Medium Value, Higher Effort

| Integration | Source | Effort | Impact |
|-------------|--------|--------|--------|
| **Redirect chain depth analysis** | phishnet concept | Medium | Track multi-hop redirect chains in service worker. Deep chains to credential pages = phishing signal. |
| **TLS fingerprint matching** | PhishStats + phishnet | High | Cross-reference page SSL fingerprints against known-bad infrastructure. Complex to implement in extension context. |
| **Anti-bot code detection** | PhishCollector patterns | Low | Detecting anti-bot/anti-analysis code on credential pages as a supplementary phishing signal. |
| **Brand targeting trend weighting** | phishnet.cc analytics | Low | Dynamically weight brand impersonation signals based on current most-targeted brands. |

---

## Architecture Considerations

### Current lur3 Design Principles
- **Fully client-side** - no external dependencies for core detection
- **Zero-latency** - all 45 detectors run locally in content scripts / service worker
- **Offline-capable** - works without network connectivity
- **Privacy-first** - no URLs sent externally during detection

### Integration Constraints
Any external API integration must respect these principles:

1. **External lookups are supplementary, never blocking.** Core detection must work without network. API enrichment runs async, after local detection completes.
2. **No URL exfiltration during browsing.** External queries should use domain/IP/hash lookups, not full URLs, to preserve user privacy.
3. **Cached locally.** Threat intel feeds should be pulled periodically and stored in `chrome.storage.local`, not queried per-page-load.
4. **Graceful degradation.** If API is unreachable, detection quality stays at current baseline (45 detectors). External signals only boost confidence, never required.
5. **API keys optional.** Free-tier APIs (PhishStats, phishnet.cc feed) preferred. Paid APIs (urlscan.io) only in SOC deployment mode.

### Proposed New Component: ThreatIntelSync

A lightweight service worker module that:
1. Runs on extension install and every N hours thereafter
2. Pulls from PhishStats API (recent high-score entries) + phishnet.cc feed.txt
3. Builds compact lookup sets: bad domains, bad IPs, bad exfil endpoints, brand favicon hashes
4. Stores in `chrome.storage.local` under a `threatIntel` key
5. Content scripts query this store as a supplementary signal (adds +weight to risk scores, never sole trigger)

---

## Competitive Differentiation

What these tools do that lur3 does NOT (and whether we should care):

| Capability | Tools That Have It | Should lur3 Add It? |
|------------|-------------------|---------------------|
| Phishing kit archive download/analysis | phishnet, phishcollector | No - offensive research tool, not browser defense |
| Headless browser page rendering | phishcollector | No - we run IN the browser, we have the live DOM |
| Multi-feed aggregation pipeline | phishnet | Partially - lightweight version for threat intel sync |
| WHOIS/registration data lookup | phishcollector | Yes (via PhishStats domain age field) - high-value signal |
| Form action exfil endpoint cataloging | phishnet | Yes - directly applicable to our form monitoring guards |
| Favicon hash matching | phishcollector | Yes - fast brand impersonation signal for phishvision |
| URL reputation scoring | PhishStats, RapidAPI | Partially - local cache of known-bad, not per-request API calls |

What lur3 does that NONE of these tools do:
- Real-time in-browser behavioral detection (45 specialized detectors)
- WebAuthn/Passkey credential substitution detection
- Canvas-rendered phishing detection
- WebTransport AiTM relay detection
- Service Worker persistence detection
- Extension supply chain auditing
- Agentic AI intent monitoring
- Speculation Rules API abuse detection

**lur3's competitive advantage is real-time behavioral detection. These external resources are best used as supplementary intelligence layers, not replacements for any existing detector.**

---

## Summary

The most actionable takeaways from this review:

1. **PhishStats API** is the single most useful resource - free, rich data, no auth required. Domain age + IP frequency + known-bad infrastructure data directly supplements our detection.

2. **phishnet.cc live feed** is the easiest win - a downloadable URL feed that can be ingested into a local blocklist with minimal code.

3. **Favicon hashing** from PhishCollector's approach is a novel detection signal we don't currently have - deterministic, fast, and hard for attackers to evade.

4. **urlscan.io** is the best post-detection enrichment platform for SOC deployments, but adds complexity (API keys, async polling) that should be optional.

5. **The RapidAPI offerings** add minimal value given lur3's client-side architecture. Cloud API latency and key management conflict with our design principles.
