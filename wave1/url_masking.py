"""
proxyguard/detectors/url_masking.py

Detects Starkiller PhaaS @-symbol URL masking on the mitmproxy request() hook.

Attack technique:
    https://microsoft.com@attacker-proxy.ru/login
    ^^^^^^^^^^^^^^^^^^^^^^^^^ — browser displays this (userinfo component)
                               ^^^^^^^^^^^^^^^^^ — browser resolves THIS as the actual host

    RFC 3986 §3.2.1: the userinfo component precedes the host in the authority.
    Browsers resolve the actual host (after @) but display the userinfo prominently.
    Starkiller PhaaS (Abnormal AI, February 25 2026, operator group "Jinkusu") ships
    a built-in URL masker exploiting this — confirmed undetected by Chrome, Edge,
    Brave, Firefox, Mullvad on Windows 11 as of Feb 19, 2026.

Detection fires on the mitmproxy request() hook — BEFORE any page content is returned.
This is the earliest possible interception point in the kill chain.

References:
    - Abnormal AI / Callie Baron, Piotr Wojtyla — Feb 25, 2026
    - RFC 3986 §3.2.1 — URI authority userinfo
"""

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger("phishops.proxyguard.url_masking")

# ---------------------------------------------------------------------------
# High-value brand domains commonly impersonated in Starkiller campaigns.
# Matching is substring-based against the displayed_as (userinfo) portion only.
# ---------------------------------------------------------------------------
HIGH_VALUE_BRANDS: frozenset[str] = frozenset({
    "microsoft.com",
    "microsoftonline.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "chase.com",
    "wellsfargo.com",
    "linkedin.com",
    "outlook.com",
    "office.com",
    "live.com",
    "dropbox.com",
    "docusign.com",
})

# TLDs / ccTLDs frequently used by Starkiller operators for attacker infrastructure.
# Matched against the actual resolved hostname (after @).
SUSPICIOUS_TLDS: tuple[str, ...] = (
    ".ru", ".cn", ".xyz", ".top", ".tk", ".ml", ".ga", ".cf",
    ".pw", ".cc", ".su", ".icu", ".online",
)

# Risk score assigned to any URL containing a userinfo (@ component) before further
# amplification. Userinfo has near-zero legitimate use in browser-navigated URLs.
_USERINFO_BASELINE_SCORE = 0.70

# Blocking threshold — at or above this score the proxy returns HTTP 403.
# Logging-only alert for scores between _USERINFO_BASELINE_SCORE and this threshold.
BLOCK_THRESHOLD = 0.85


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
@dataclass
class UrlMaskingResult:
    detected: bool
    displayed_as: str   # Fake brand part shown to user (username[:password] from userinfo)
    actual_host: str    # Real destination hostname resolved by the browser (after @)
    risk_score: float   # 0.0–1.0, rounded to 2 d.p.
    signals: list[str]


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------
def detect_userinfo_masking(url: str) -> UrlMaskingResult:
    """
    Detect Starkiller-style userinfo @ masking in a URL.

    Args:
        url: Full URL string from the HTTP request. May be malformed.

    Returns:
        UrlMaskingResult — detected=True if a userinfo component (@) is present.

    Guarantees:
        - Never raises. Returns UrlMaskingResult(detected=False, ...) on any parse error.
        - risk_score is always in [0.0, 1.0].
        - signals always contains at least one entry.
    """
    logger.debug("[URL_MASKING] detect_userinfo_masking url=%s", url[:120])

    try:
        parsed = urlparse(url)

        # ------------------------------------------------------------------ #
        # Step 1 — Check for userinfo component (username or password)
        # ------------------------------------------------------------------ #
        if parsed.username is None and parsed.password is None:
            logger.debug("[URL_MASKING] No userinfo component found url=%s", url[:80])
            return UrlMaskingResult(
                detected=False,
                displayed_as="",
                actual_host="",
                risk_score=0.0,
                signals=["no_userinfo"],
            )

        # ------------------------------------------------------------------ #
        # Step 2 — Userinfo is present — primary detection trigger
        # Build the displayed_as string (what the victim sees in browser UI)
        # ------------------------------------------------------------------ #
        displayed_as = parsed.username or ""
        if parsed.password:
            displayed_as += f":{parsed.password}"
        actual_host = parsed.hostname or ""

        signals: list[str] = ["userinfo_present"]
        base_score: float = _USERINFO_BASELINE_SCORE

        # ------------------------------------------------------------------ #
        # Step 3 — Brand impersonation amplifier
        # If the displayed_as portion contains a known high-value brand domain,
        # the attacker is explicitly crafting the URL to mislead the victim.
        # ------------------------------------------------------------------ #
        displayed_lower = displayed_as.lower()
        matched_brand = next(
            (brand for brand in HIGH_VALUE_BRANDS if brand in displayed_lower), None
        )
        if matched_brand:
            base_score += 0.20
            signals.append(f"brand_impersonation:{displayed_lower}")
            logger.warning(
                "[URL_MASKING] Brand impersonation detected displayed_as=%s actual_host=%s",
                displayed_as, actual_host,
            )

        # ------------------------------------------------------------------ #
        # Step 4 — Suspicious TLD amplifier
        # Starkiller operators routinely register attacker infrastructure on
        # newly-available or low-cost TLDs associated with high abuse rates.
        # ------------------------------------------------------------------ #
        actual_host_lower = actual_host.lower()
        matched_tld = next(
            (tld for tld in SUSPICIOUS_TLDS if actual_host_lower.endswith(tld)), None
        )
        if matched_tld:
            base_score += 0.10
            signals.append(f"suspicious_tld:{actual_host}")

        # ------------------------------------------------------------------ #
        # Step 5 — Finalise score and emit
        # ------------------------------------------------------------------ #
        risk_score = round(min(base_score, 1.0), 2)

        logger.warning(
            "[URL_MASKING] ALERT detected displayed_as=%r actual_host=%r "
            "risk_score=%.2f signals=%s",
            displayed_as, actual_host, risk_score, signals,
        )

        return UrlMaskingResult(
            detected=True,
            displayed_as=displayed_as,
            actual_host=actual_host,
            risk_score=risk_score,
            signals=signals,
        )

    except Exception as exc:  # pragma: no cover — safety net
        logger.error("[URL_MASKING] unexpected error url=%s err=%s", url[:120], exc)
        return UrlMaskingResult(
            detected=False,
            displayed_as="",
            actual_host="",
            risk_score=0.0,
            signals=["detector_error"],
        )
