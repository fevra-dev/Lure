"""
proxyguard/proxy_guard.py

ProxyGuard — mitmproxy addon entry point.
Intercepts HTTP requests and responses, runs all detector modules,
emits structured telemetry to Microsoft Sentinel via emit_to_sentinel().

Detector pipeline (request hook):
  1. Gophish rid= campaign fingerprint
  2. [NEW] Starkiller @-symbol URL userinfo masking

Detector pipeline (response hook):
  1. [NEW] HTML smuggling loader (atob + Blob + createObjectURL)

To run:
  mitmproxy --mode transparent -s proxyguard/proxy_guard.py
"""

import logging
from mitmproxy import http

from detectors.gophish_fingerprint import detect_gophish_tracking_param
from detectors.url_masking import detect_userinfo_masking, BLOCK_THRESHOLD as URL_MASK_BLOCK
from detectors.html_smuggling import scan_response_body

logger = logging.getLogger("phishops.proxyguard")


# ---------------------------------------------------------------------------
# Sentinel emit helper (stub — real implementation in sentinel/emit.py)
# ---------------------------------------------------------------------------
def emit_to_sentinel(event: dict) -> None:
    """
    Emit a structured event to the ProxyPhishingEvents_CL custom Sentinel table.
    Stub implementation logs to stdout; replace with DCR HTTP Data Collection API call.
    """
    logger.info("[SENTINEL_EMIT] %s", event)


def get_domain_age(domain: str) -> int:
    """
    Return domain age in days from a cached WHOIS lookup.
    Returns -1 if unavailable (treated as unknown in scoring).
    Stub — replace with a real WHOIS cache backed by a local SQLite store.
    """
    return -1


# ---------------------------------------------------------------------------
# mitmproxy hooks
# ---------------------------------------------------------------------------
def request(flow: http.HTTPFlow) -> None:
    """
    Inspect every outbound HTTP request.
    Runs URL-layer detectors that must fire BEFORE any response is received.
    """
    url = flow.request.pretty_url
    domain = flow.request.host

    logger.debug("[PROXY_GUARD] request hook url=%s", url[:120])

    # ------------------------------------------------------------------ #
    # Detector 1 — Gophish rid= campaign fingerprint (EXISTING)
    # ------------------------------------------------------------------ #
    domain_age = get_domain_age(domain)
    gophish_result = detect_gophish_tracking_param(url, domain_age_days=domain_age)
    if gophish_result.detected:
        logger.warning(
            "[PROXY_GUARD] gophish_fingerprint fired param=%s risk=%.2f url=%s",
            gophish_result.param_name, gophish_result.risk_score, url[:120],
        )
        emit_to_sentinel({
            "eventType":      "GOPHISH_CAMPAIGN_FINGERPRINT",
            "destinationUrl": url[:500],
            "destinationHost": domain,
            "trackingParam":  gophish_result.param_name,
            "trackingValue":  gophish_result.param_value[:16],
            "domainAgeDays":  domain_age,
            "riskScore":      gophish_result.risk_score,
            "signals":        gophish_result.signals,
            "clientIp":       flow.client_conn.peername[0],
        })
        if gophish_result.risk_score > 0.85:
            flow.response = http.Response.make(
                403,
                b"<html><body><h2>Page blocked by ProxyGuard</h2>"
                b"<p>Phishing campaign infrastructure detected.</p></body></html>",
                {"Content-Type": "text/html"},
            )
            return  # No further processing needed for this request

    # ------------------------------------------------------------------ #
    # Detector 2 — Starkiller @-symbol URL userinfo masking (NEW Wave 1)
    # ------------------------------------------------------------------ #
    masking_result = detect_userinfo_masking(url)
    if masking_result.detected:
        logger.warning(
            "[PROXY_GUARD] url_masking fired url=%s actual_host=%s risk=%.2f",
            url[:120], masking_result.actual_host, masking_result.risk_score,
        )
        emit_to_sentinel({
            "eventType":      "URL_USERINFO_MASKING",
            "destinationUrl": url[:500],
            "displayedAs":    masking_result.displayed_as[:100],
            "actualHost":     masking_result.actual_host,
            "riskScore":      masking_result.risk_score,
            "signals":        masking_result.signals,
            "clientIp":       flow.client_conn.peername[0],
            "technique":      "Starkiller_URL_Masker",
        })
        # Block at high confidence — URL masking has near-zero legitimate use
        if masking_result.risk_score >= URL_MASK_BLOCK:
            flow.response = http.Response.make(
                403,
                b"<html><body><h2>Request blocked by ProxyGuard</h2>"
                b"<p>URL masking detected (Starkiller PhaaS technique).</p></body></html>",
                {"Content-Type": "text/html"},
            )
            logger.warning(
                "[PROXY_GUARD] BLOCKED url_masking risk=%.2f url=%s",
                masking_result.risk_score, url[:120],
            )


def response(flow: http.HTTPFlow) -> None:
    """
    Inspect every HTTP response body.
    Runs content-layer detectors after the full response is received.
    """
    url = flow.request.pretty_url
    logger.debug("[PROXY_GUARD] response hook url=%s", url[:120])

    # ------------------------------------------------------------------ #
    # Detector 3 — HTML smuggling loader (atob + Blob + createObjectURL) (NEW Wave 1)
    # ------------------------------------------------------------------ #
    if not flow.response or not flow.response.content:
        return

    content_type = flow.response.headers.get("content-type", "")

    try:
        body_text = flow.response.content.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("[PROXY_GUARD] html_smuggling body decode failed: %s", exc)
        return

    if not body_text:
        return

    smuggling_result = scan_response_body(body_text, content_type)
    if smuggling_result.detected:
        logger.warning(
            "[PROXY_GUARD] html_smuggling fired pattern=%s risk=%.2f url=%s",
            smuggling_result.pattern_name, smuggling_result.risk_score, url[:120],
        )
        emit_to_sentinel({
            "eventType":      "HTML_SMUGGLING_LOADER",
            "destinationUrl": url[:500],
            "patternName":    smuggling_result.pattern_name,
            "riskScore":      smuggling_result.risk_score,
            "signals":        smuggling_result.signals,
            "matchedSnippet": smuggling_result.matched_snippet,
            "clientIp":       flow.client_conn.peername[0],
        })
