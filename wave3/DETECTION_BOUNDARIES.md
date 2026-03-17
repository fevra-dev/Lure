# KitRadar — Detection Boundaries
## What KitRadar Can and Cannot Fingerprint
**Module: KitRadar · Last Updated: March 2026**

---

## Summary

KitRadar's fingerprinting model detects PhaaS kits by matching structural patterns
in phishing page HTML — Cloudflare Turnstile injection signatures, React bundle
identifiers, session path prefixes, iframe injection patterns, and anti-bot page
structures. This model is highly effective against **static-template PhaaS kits**
and has zero effectiveness against **live-proxy PhaaS kits**. This document draws
the explicit boundary between these two categories.

---

## In-Scope: Static-Template PhaaS Kits

These kits serve HTML pages assembled from pre-built templates. The template
structure — DOM skeleton, JavaScript bundle signatures, injected UI elements —
is consistent across deployments and detectable by pattern matching.

| Kit Family | Status | Primary Fingerprint |
|---|---|---|
| **Tycoon 2FA** | ✅ Active fingerprints | Cloudflare Turnstile `cf-turnstile` injection + React SPA bundle hash signature |
| **Mamba 2FA** | ✅ Active fingerprints | React bundle fingerprint distinct from Tycoon; shared anti-bot page structure |
| **GhostFrame** | ✅ Active fingerprints | Cross-origin iframe injection with session token in URL path |
| **Whisper2FA** | ✅ Active fingerprints | Static HTML template with predictable asset naming convention |
| **Evilginx phishlets** | ✅ Active fingerprints | Hex session token path prefix `^/[a-f0-9]{8,16}/` on fresh domain |
| **EvilProxy** | ✅ Active fingerprints | Reverse proxy cookie stripping + session token in `X-` header pattern |

### Tycoon 2FA — Europol Takedown Note (March 2026)

Europol dismantled the primary Tycoon 2FA operator group in a recent operation
("Europol Dismantles Tycoon 2FA: Inside the Takedown of a 64,000-Attack
Phishing-as-a-Service Platform"). **This does not reduce the value of KitRadar's
Tycoon 2FA fingerprints.** The following remain true post-takedown:

- Existing Tycoon 2FA kits continue to circulate among lower-tier operators
- The kit's source code and panel have been forked by successor groups
- Detection fingerprints identify the *kit architecture*, not the operator —
  forks retain the same structural signatures unless specifically modified
- The Tycoon 2FA takedown, combined with the Starkiller emergence, illustrates
  the bifurcation of the PhaaS market: commodity kits (Tycoon class) are being
  eliminated by law enforcement while premium live-proxy kits (Starkiller class)
  emerge as high-end replacements. KitRadar covers the former; ProxyGuard and
  Sentinel cover the latter.

**Action required:** Keep Tycoon 2FA fingerprints active. Add a note in fingerprint
documentation that the primary operator group was dismantled but the kit remains
in circulation via forks.

---

## Out-of-Scope: Live-Proxy PhaaS Kits (Starkiller Class)

### What Makes Starkiller Undetectable by KitRadar

**Starkiller** (Abnormal AI, February 25, 2026; operator group: Jinkusu) represents
a fundamentally different architecture that eliminates KitRadar's detection surface.

**How Starkiller works:**
When an attacker selects a target brand, Starkiller spins up a Docker container
running a headless Chrome instance that loads the **real** brand website live and
acts as a reverse proxy. The victim is authenticating against the actual login page
— through attacker-controlled infrastructure.

**Why KitRadar produces zero signal:**
KitRadar's detection model requires consistent structural patterns in phishing page
HTML. Starkiller has no templates. Every page load is a live proxy of the real site,
producing perfect pixel-identical output with no injected elements, no custom bundle
hashes, no session path prefixes to match. The attack explicitly renders a perfect
clone *because it IS the original page*.

```
KitRadar detection surface:
  Static DOM fingerprints ──────────────► ZERO SIGNAL (no static DOM)
  JavaScript bundle hashes ─────────────► ZERO SIGNAL (original site JS)
  Injected UI elements ─────────────────► ZERO SIGNAL (unmodified original)
  Session path prefix patterns ─────────► ZERO SIGNAL (session managed by proxy)
  Anti-bot page structures ─────────────► ZERO SIGNAL (original site anti-bot)
```

### Detection Shifts to Infrastructure and Behavioral Layer

Starkiller-class kits are detectable — but through different modules and different
signals than KitRadar uses.

| Detection Layer | Module | Signal |
|---|---|---|
| **URL delivery** (before page loads) | **ProxyGuard** | `@`-symbol userinfo URL masking (`microsoft.com@attacker.ru`) — Starkiller's built-in URL masker (Wave 1, Plan A) |
| **Post-compromise identity** | **Sentinel KQL** | Impossible-travel sign-in: two authenticated sessions from geographically impossible locations within <30 minutes of cookie harvest (Wave 2, Plan D) |
| **Pre-authentication resistance** | **CTAPGuard** | Token binding + FIDO2 origin verification — passkeys bound to `microsoft.com` cannot be replayed to `attacker.ru` even through a Starkiller proxy |
| **OAuth session validation** | **OAuthGuard** | Session token scope audit post-auth; anomalous scope grants |

### Documented Detection Boundary Statement

> **KitRadar does not detect and will never detect Starkiller-class real-time
> headless Chrome reverse proxy kits.** This is not a gap to be closed in KitRadar
> — it is an architectural constraint of template-based fingerprinting that applies
> to any kit operating via live DOM proxying. Detection for this kit class is handled
> by ProxyGuard (URL layer), Sentinel KQL (identity layer), and CTAPGuard (auth layer).
> Claiming KitRadar detects Starkiller-class kits would be inaccurate.

This boundary is documented here to:
1. Accurately scope the portfolio's detection claims to interviewers and reviewers
2. Prevent false confidence that KitRadar's template fingerprints provide coverage
   against the fastest-growing premium PhaaS category
3. Direct operators to the correct detection modules for Starkiller-class incidents

---

## Evilginx Session Path Extension

The Evilginx session path pattern (`^/[a-f0-9]{8,16}/`) is structurally detectable
because Evilginx requires manual phishlet configuration — the session identifier
is injected into URL paths in a consistent format. Add as a secondary rule alongside
the Gophish `rid=` detector in ProxyGuard:

```python
EVILGINX_SESSION_PATH = re.compile(r'^/[a-f0-9]{8,16}(/|$)')
```

This is distinct from Starkiller — Evilginx injects a traceable path component that
KitRadar and ProxyGuard can fingerprint. Starkiller does not.

---

*KitRadar Detection Boundaries · PhishOps Detection Portfolio · March 2026*
*TLP:WHITE — Unrestricted Distribution*
