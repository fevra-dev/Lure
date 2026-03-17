"""
proxyguard/detectors/html_smuggling.py

Detects HTML smuggling loader patterns in HTTP response bodies.
Fires on the mitmproxy response() hook for text/html and text/javascript content types.

Threat context:
  HTML smuggling encodes a credential-harvesting page as a base64 blob inside a JavaScript
  atob() call, then renders it via Blob + URL.createObjectURL(). The payload never appears
  as HTML in network logs or on disk — it bypasses every gateway filter. ProxyGuard at the
  HTTP response layer is the only interception point before victim interaction.

  References:
    - Mandiant 2025: HTML smuggling used in >40% of enterprise-targeting phishing kits
    - MSTIC 2024: NOBELIUM / Midnight Blizzard HTML smuggling campaigns
    - Unit 42 2025: TA4557 HTML smuggling for remote access trojan delivery
"""

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("phishops.proxyguard.html_smuggling")

# ---------------------------------------------------------------------------
# Detection patterns — co-occurrence model
#
# Design rationale:
#   Real-world HTML smuggling kits NEVER call createObjectURL(new Blob(atob(...)))
#   in a single expression. They always store intermediate results in variables:
#     var data = atob('...');
#     var blob = new Blob([data], {type: 'text/html'});
#     var url  = URL.createObjectURL(blob);   ← variable, not inline new Blob
#     location.href = url;
#
#   A single regex spanning the full chain would require re.DOTALL over many KB
#   and produce fragile false-negative results. Instead, patterns are granular
#   signals that compound additively — each fires independently and their scores
#   accumulate toward the 0.65 alert threshold.
#
# Each entry: (pattern_name, compiled_regex, risk_contribution)
# Final score = sum of all matched contributions, capped at 1.0.
# Alert threshold: >= 0.65
# ---------------------------------------------------------------------------
HTML_SMUGGLING_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    (
        # Core signal: atob() call with a non-trivial base64 argument (≥4 chars).
        # Legitimate uses of atob() in production code are rare and typically
        # do not create Blob documents — context from other patterns disambiguates.
        "ATOB_CALL",
        re.compile(
            r'\batob\s*\(\s*[\'"`][A-Za-z0-9+/=_\-]{4,}[\'"`]\s*\)',
            re.IGNORECASE,
        ),
        0.40,
    ),
    (
        # Core signal: any createObjectURL() call. Matched broadly — co-occurrence
        # with ATOB_CALL and NEW_BLOB_CONSTRUCT is what triggers the alert.
        # Broad matching captures both inline (createObjectURL(new Blob(...))) and
        # variable-based (createObjectURL(blob)) forms — the dominant real-world pattern.
        "BLOB_CREATEOBJECTURL",
        re.compile(r'createObjectURL\s*\(', re.IGNORECASE),
        0.30,
    ),
    (
        # Amplifier: new Blob() constructor present.
        # ATOB_CALL(0.40) + BLOB_CREATEOBJECTURL(0.30) + NEW_BLOB_CONSTRUCT(0.15) = 0.85
        "NEW_BLOB_CONSTRUCT",
        re.compile(r'\bnew\s+Blob\s*\(', re.IGNORECASE),
        0.15,
    ),
    (
        # Amplifier: navigation to a blob URL (location, window.open).
        # Covers both assignment form (location.href = url) and
        # function call form (location.assign(url), window.open(url)).
        "BLOB_NAVIGATE",
        re.compile(
            r'(?:location\.href\s*=|location\.assign\s*\(|location\.replace\s*\(|window\.open\s*\()',
            re.IGNORECASE,
        ),
        0.20,
    ),
    (
        # Amplifier: synthetic anchor click — standard file-download trigger
        # for blob: navigations that bypass pop-up blockers.
        "DYNAMIC_ANCHOR_CLICK",
        re.compile(
            r'createElement\s*\(\s*[\'"]a[\'"]\s*\).*?\.click\s*\(\s*\)',
            re.DOTALL | re.IGNORECASE,
        ),
        0.20,
    ),
    (
        # Amplifier: large base64 literal (≥200 chars) — payload carrier.
        # Alone = low signal; combined with Blob patterns = high confidence.
        "LARGE_BASE64_STRING",
        re.compile(
            r'[\'"`][A-Za-z0-9+/]{200,}={0,2}[\'"`]',
            re.IGNORECASE,
        ),
        0.15,
    ),
    (
        # High-confidence standalone: Windows mshta.exe scriptblock smuggling.
        # No legitimate web page uses mshta.exe:javascript: — zero false positives.
        "MSHTA_SCRIPTBLOCK",
        re.compile(r'mshta\.exe.*?javascript:', re.IGNORECASE),
        0.65,
    ),
]

# Maximum response body bytes to scan (50 KB).
# Avoids excessive CPU on large JS bundles while covering all known smuggling loaders
# (which are typically <10 KB of scaffolding + a large base64 blob).
_BODY_SCAN_LIMIT = 51_200

# Alert threshold — risk scores below this return detected=False
_ALERT_THRESHOLD = 0.65


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------
@dataclass
class HtmlSmugglingResult:
    detected: bool
    pattern_name: str        # Primary matched pattern name, e.g. "ATOB_BLOB_CREATEOBJECTURL"
    risk_score: float        # 0.0–1.0, rounded to 2 d.p.
    signals: list[str]       # Human-readable list of matched signal descriptions
    matched_snippet: str     # First 120 chars of the first matched region (safety-truncated)


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------
def scan_response_body(body: str, content_type: str) -> HtmlSmugglingResult:
    """
    Scan an HTTP response body for HTML smuggling loader patterns.

    Args:
        body:         Decoded response body text. Function internally caps at 50 KB.
        content_type: Value of the Content-Type response header (may include charset).

    Returns:
        HtmlSmugglingResult — detected=True only when risk_score >= 0.65.

    Guarantees:
        - Never raises. All exceptions are caught and returned as a clean result.
        - risk_score is always in [0.0, 1.0].
        - signals always contains at least one entry.
        - matched_snippet is always <= 120 chars.
    """
    logger.debug(
        "[HTML_SMUGGLING] scan_response_body called content_type=%s body_len=%d",
        content_type, len(body),
    )

    try:
        # ------------------------------------------------------------------ #
        # Step 1 — Content-type gate
        # Only inspect HTML and JavaScript responses. Images, JSON, CSS, etc.
        # cannot be HTML smuggling loaders by definition.
        # ------------------------------------------------------------------ #
        ct_lower = content_type.lower()
        if "html" not in ct_lower and "javascript" not in ct_lower:
            logger.debug(
                "[HTML_SMUGGLING] content_type_skipped content_type=%s", content_type,
            )
            return HtmlSmugglingResult(
                detected=False,
                pattern_name="",
                risk_score=0.0,
                signals=["content_type_skipped"],
                matched_snippet="",
            )

        # ------------------------------------------------------------------ #
        # Step 2 — Truncate body to 50 KB scan window
        # ------------------------------------------------------------------ #
        body_slice = body[:_BODY_SCAN_LIMIT]
        logger.debug(
            "[HTML_SMUGGLING] Scanning %dB of response body", len(body_slice),
        )

        # ------------------------------------------------------------------ #
        # Step 3 — Run all patterns, compound risk scores
        # ------------------------------------------------------------------ #
        total_risk: float = 0.0
        matched_signals: list[str] = []
        matched_snippet: str = ""

        for name, pattern, contribution in HTML_SMUGGLING_PATTERNS:
            match = pattern.search(body_slice)
            if match:
                total_risk += contribution
                matched_signals.append(f"{name}:+{contribution}")
                if not matched_snippet:
                    # Capture the first 120 chars of the first matched region
                    matched_snippet = body_slice[match.start(): match.start() + 120]
                logger.info(
                    "[HTML_SMUGGLING] pattern_match name=%s contribution=%.2f",
                    name, contribution,
                )

        # ------------------------------------------------------------------ #
        # Step 4 — Score and threshold
        # ------------------------------------------------------------------ #
        risk_score = round(min(total_risk, 1.0), 2)

        if risk_score >= _ALERT_THRESHOLD:
            primary_pattern = matched_signals[0].split(":")[0] if matched_signals else ""
            logger.warning(
                "[HTML_SMUGGLING] ALERT risk_score=%.2f signals=%s snippet=%r",
                risk_score, matched_signals, matched_snippet[:60],
            )
            return HtmlSmugglingResult(
                detected=True,
                pattern_name=primary_pattern,
                risk_score=risk_score,
                signals=matched_signals if matched_signals else ["unknown"],
                matched_snippet=matched_snippet,
            )

        # Clean path
        logger.debug("[HTML_SMUGGLING] clean risk_score=%.2f", risk_score)
        return HtmlSmugglingResult(
            detected=False,
            pattern_name="",
            risk_score=risk_score,
            signals=matched_signals if matched_signals else ["no_pattern_match"],
            matched_snippet="",
        )

    except Exception as exc:  # pragma: no cover — safety net
        logger.error("[HTML_SMUGGLING] unexpected error: %s", exc, exc_info=True)
        return HtmlSmugglingResult(
            detected=False,
            pattern_name="",
            risk_score=0.0,
            signals=["detector_error"],
            matched_snippet="",
        )
