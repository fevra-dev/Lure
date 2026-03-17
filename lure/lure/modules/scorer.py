"""
lure/modules/scorer.py
Scoring Engine — Pipeline Stage E

Evaluates all upstream analysis results and produces a weighted risk score
with a categorical verdict.

Signals are additive: each rule checks a specific condition from the
AnalysisResult and contributes its weight to the total score. The total
is then mapped to a verdict via the thresholds in LureSettings:

    < 3.0                  → CLEAN
    3.0 – 4.99             → SUSPICIOUS
    5.0 – 7.99             → LIKELY_PHISHING
    >= 8.0                 → CONFIRMED_MALICIOUS

Integration:
    pipeline.py:99 → from lure.modules.scorer import score
    Signature: score(result: AnalysisResult, settings: LureSettings) -> RiskScore
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lure.models import AuthResult, RiskScore, Signal, Verdict

if TYPE_CHECKING:
    from lure.config import LureSettings
    from lure.models import AnalysisResult

log = logging.getLogger(__name__)

# =============================================================================
# URL shortener domains (checked against extracted IOC domains)
# =============================================================================

_URL_SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly",
    "adf.ly", "short.link", "rebrand.ly", "cutt.ly", "tiny.cc", "is.gd",
})

# =============================================================================
# Suspicious TLDs heavily used in phishing campaigns
# =============================================================================

_SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "click", "loan", "work", "date", "racing",
    "download", "gq", "ml", "tk", "cf", "ga",
})


# =============================================================================
# Signal definitions
# =============================================================================

def _evaluate_signals(result: AnalysisResult) -> list[Signal]:
    """
    Evaluate all scoring signals against the analysis result.
    Returns a list of Signal objects for signals that fired.
    """
    fired: list[Signal] = []
    ha = result.header_analysis

    # ── SPF_FAIL ─────────────────────────────────────────────────────────
    if ha and ha.spf == AuthResult.FAIL:
        fired.append(Signal(
            name="SPF_FAIL",
            weight=2.0,
            trigger="SPF authentication failed for sender domain",
            evidence=ha.spf_details,
        ))

    # ── DKIM_FAIL ────────────────────────────────────────────────────────
    if ha and ha.dkim == AuthResult.FAIL:
        fired.append(Signal(
            name="DKIM_FAIL",
            weight=1.5,
            trigger="DKIM signature verification failed",
            evidence=ha.dkim_details,
        ))

    # ── DMARC_FAIL ───────────────────────────────────────────────────────
    if ha and ha.dmarc == AuthResult.FAIL:
        fired.append(Signal(
            name="DMARC_FAIL",
            weight=2.0,
            trigger="DMARC policy evaluation failed",
            evidence=f"policy={ha.dmarc_policy}" if ha.dmarc_policy else None,
        ))

    # ── REPLY_TO_MISMATCH ────────────────────────────────────────────────
    if ha and ha.reply_to_mismatch:
        fired.append(Signal(
            name="REPLY_TO_MISMATCH",
            weight=2.5,
            trigger="Reply-To domain differs from From domain",
            evidence=f"from={ha.from_domain} reply_to={ha.reply_to_domain}",
        ))

    # ── HOMOGRAPH_DOMAIN ─────────────────────────────────────────────────
    if ha and ha.is_homograph:
        fired.append(Signal(
            name="HOMOGRAPH_DOMAIN",
            weight=4.0,
            trigger="Sender domain contains mixed Unicode scripts (homograph attack)",
            evidence=ha.homograph_domain,
        ))

    # ── SUSPICIOUS_ATTACHMENT ────────────────────────────────────────────
    if result.attachments:
        for att in result.attachments:
            if att.macro_suspicious or att.pdf_suspicious:
                fired.append(Signal(
                    name="SUSPICIOUS_ATTACHMENT",
                    weight=3.0,
                    trigger=f"Attachment '{att.filename}' flagged as suspicious",
                    evidence="; ".join(att.risk_reasons[:3]) if att.risk_reasons else None,
                ))
                break  # Only fire once even with multiple suspicious attachments

    # ── URL_SHORTENER ────────────────────────────────────────────────────
    if result.iocs:
        shortener_domains = [
            d for d in result.iocs.domains
            if d.lower() in _URL_SHORTENERS
        ]
        if shortener_domains:
            fired.append(Signal(
                name="URL_SHORTENER",
                weight=1.0,
                trigger="URL shortener domain found in email",
                evidence=", ".join(shortener_domains[:3]),
            ))

    # ── SUSPICIOUS_TLD ───────────────────────────────────────────────────
    if result.iocs:
        sus_tld_domains = []
        for domain in result.iocs.domains:
            tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
            if tld in _SUSPICIOUS_TLDS:
                sus_tld_domains.append(domain)
        if sus_tld_domains:
            fired.append(Signal(
                name="SUSPICIOUS_TLD",
                weight=1.5,
                trigger="Domain with suspicious TLD found in email",
                evidence=", ".join(sus_tld_domains[:3]),
            ))

    # ── MANY_ANOMALIES ───────────────────────────────────────────────────
    if ha and len(ha.anomalies) >= 3:
        fired.append(Signal(
            name="MANY_ANOMALIES",
            weight=1.0,
            trigger=f"{len(ha.anomalies)} header anomalies detected",
            evidence="; ".join(ha.anomalies[:3]),
        ))

    # ── NO_AUTH_HEADERS ──────────────────────────────────────────────────
    if ha:
        no_auth = (
            ha.spf in (AuthResult.UNKNOWN, AuthResult.NONE)
            and ha.dkim in (AuthResult.UNKNOWN, AuthResult.NONE)
            and ha.dmarc in (AuthResult.UNKNOWN, AuthResult.NONE)
        )
        if no_auth:
            fired.append(Signal(
                name="NO_AUTH_HEADERS",
                weight=1.5,
                trigger="No SPF, DKIM, or DMARC authentication results present",
            ))

    # ── YARA_MATCH ───────────────────────────────────────────────────────
    if result.yara_matches and result.yara_matches.total_matches > 0:
        rules = [m.rule_name for m in result.yara_matches.matches[:3]]
        fired.append(Signal(
            name="YARA_MATCH",
            weight=4.0,
            trigger=f"{result.yara_matches.total_matches} YARA rule(s) matched",
            evidence=", ".join(rules),
        ))

    return fired


# =============================================================================
# Public interface
# =============================================================================

def score(result: AnalysisResult, settings: LureSettings) -> RiskScore:
    """
    Score an AnalysisResult and produce a RiskScore with verdict.

    Args:
        result: Complete AnalysisResult from upstream pipeline stages
        settings: LureSettings with scoring thresholds

    Returns:
        RiskScore with total_score, verdict, and signals_fired
    """
    signals = _evaluate_signals(result)

    total = sum(s.weight for s in signals)
    total = round(total, 2)

    # Map total score to verdict using configurable thresholds
    if total >= settings.threshold_confirmed_malicious:
        verdict = Verdict.CONFIRMED_MALICIOUS
    elif total >= settings.threshold_likely_phishing:
        verdict = Verdict.LIKELY_PHISHING
    elif total >= settings.threshold_suspicious:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    risk_score = RiskScore(
        total_score=total,
        verdict=verdict,
        signals_fired=signals,
        signals_evaluated=11,  # Total number of signal rules checked
    )

    log.info(
        "Scoring complete: total=%.1f verdict=%s signals_fired=%d/%d",
        total, verdict.value, len(signals), risk_score.signals_evaluated,
    )

    return risk_score
