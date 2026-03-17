"""
tests/test_scorer.py
Unit tests for the scoring engine (Pipeline Stage E).

Tests scoring signals against synthetic AnalysisResult objects
built from the conftest fixtures.
"""
from __future__ import annotations

import pytest

from lure.config import LureSettings
from lure.models import (
    AnalysisResult,
    AttachmentAnalysis,
    AuthResult,
    HeaderAnalysis,
    IOCSet,
    RiskScore,
    Signal,
    Verdict,
    YARAMatch,
    YARAMatchSet,
)
from lure.modules.scorer import score


@pytest.fixture
def settings():
    """Default LureSettings for scoring tests."""
    return LureSettings(
        threshold_suspicious=3.0,
        threshold_likely_phishing=5.0,
        threshold_confirmed_malicious=8.0,
    )


def _make_result(**kwargs) -> AnalysisResult:
    """Helper to create a minimal AnalysisResult."""
    defaults = dict(
        email_file="test.eml",
        email_hash="abc123",
    )
    defaults.update(kwargs)
    return AnalysisResult(**defaults)


# =============================================================================
# Verdict threshold tests
# =============================================================================

class TestVerdictThresholds:

    def test_clean_email_scores_zero(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(
                spf=AuthResult.PASS,
                dkim=AuthResult.PASS,
                dmarc=AuthResult.PASS,
            ),
        )
        risk = score(result, settings)
        assert risk.total_score == 0.0
        assert risk.verdict == Verdict.CLEAN
        assert len(risk.signals_fired) == 0

    def test_suspicious_threshold(self, settings):
        """SPF_FAIL (2.0) + DKIM_FAIL (1.5) = 3.5 → SUSPICIOUS"""
        result = _make_result(
            header_analysis=HeaderAnalysis(
                spf=AuthResult.FAIL,
                dkim=AuthResult.FAIL,
                dmarc=AuthResult.PASS,
            ),
        )
        risk = score(result, settings)
        assert risk.total_score == 3.5
        assert risk.verdict == Verdict.SUSPICIOUS

    def test_likely_phishing_threshold(self, settings):
        """SPF_FAIL (2.0) + DMARC_FAIL (2.0) + REPLY_TO_MISMATCH (2.5) = 6.5 → LIKELY_PHISHING"""
        result = _make_result(
            header_analysis=HeaderAnalysis(
                spf=AuthResult.FAIL,
                dkim=AuthResult.PASS,
                dmarc=AuthResult.FAIL,
                reply_to_mismatch=True,
                from_domain="bank.com",
                reply_to_domain="attacker.ru",
            ),
        )
        risk = score(result, settings)
        assert risk.total_score == 6.5
        assert risk.verdict == Verdict.LIKELY_PHISHING

    def test_confirmed_malicious_threshold(self, settings):
        """SPF_FAIL (2.0) + DMARC_FAIL (2.0) + HOMOGRAPH (4.0) = 8.0 → CONFIRMED_MALICIOUS"""
        result = _make_result(
            header_analysis=HeaderAnalysis(
                spf=AuthResult.FAIL,
                dkim=AuthResult.PASS,
                dmarc=AuthResult.FAIL,
                is_homograph=True,
                homograph_domain="\u0440\u0430ypal.com",
            ),
        )
        risk = score(result, settings)
        assert risk.total_score == 8.0
        assert risk.verdict == Verdict.CONFIRMED_MALICIOUS


# =============================================================================
# Individual signal tests
# =============================================================================

class TestIndividualSignals:

    def test_spf_fail_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(spf=AuthResult.FAIL),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "SPF_FAIL" in names
        spf_sig = next(s for s in risk.signals_fired if s.name == "SPF_FAIL")
        assert spf_sig.weight == 2.0

    def test_dkim_fail_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(dkim=AuthResult.FAIL),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "DKIM_FAIL" in names

    def test_dmarc_fail_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(dmarc=AuthResult.FAIL, dmarc_policy="reject"),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "DMARC_FAIL" in names
        dmarc_sig = next(s for s in risk.signals_fired if s.name == "DMARC_FAIL")
        assert "reject" in (dmarc_sig.evidence or "")

    def test_reply_to_mismatch_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(
                reply_to_mismatch=True,
                from_domain="corp.com",
                reply_to_domain="attacker.ru",
            ),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "REPLY_TO_MISMATCH" in names

    def test_homograph_domain_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(
                is_homograph=True,
                homograph_domain="\u0440\u0430ypal.com",
            ),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "HOMOGRAPH_DOMAIN" in names
        sig = next(s for s in risk.signals_fired if s.name == "HOMOGRAPH_DOMAIN")
        assert sig.weight == 4.0

    def test_suspicious_attachment_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(),
            attachments=[
                AttachmentAnalysis(
                    filename="evil.doc",
                    macro_suspicious=True,
                    risk_reasons=["Contains suspicious VBA macro code"],
                ),
            ],
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "SUSPICIOUS_ATTACHMENT" in names

    def test_suspicious_attachment_fires_once_for_multiple(self, settings):
        """Only fires once even with multiple suspicious attachments."""
        result = _make_result(
            header_analysis=HeaderAnalysis(),
            attachments=[
                AttachmentAnalysis(filename="a.doc", macro_suspicious=True),
                AttachmentAnalysis(filename="b.pdf", pdf_suspicious=True),
            ],
        )
        risk = score(result, settings)
        count = sum(1 for s in risk.signals_fired if s.name == "SUSPICIOUS_ATTACHMENT")
        assert count == 1

    def test_url_shortener_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(),
            iocs=IOCSet(domains=["bit.ly", "example.com"]),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "URL_SHORTENER" in names

    def test_suspicious_tld_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(),
            iocs=IOCSet(domains=["phishing-site.xyz", "normal.com"]),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "SUSPICIOUS_TLD" in names

    def test_many_anomalies_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(
                anomalies=["anomaly1", "anomaly2", "anomaly3"],
            ),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "MANY_ANOMALIES" in names

    def test_no_auth_headers_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(
                spf=AuthResult.UNKNOWN,
                dkim=AuthResult.NONE,
                dmarc=AuthResult.UNKNOWN,
            ),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "NO_AUTH_HEADERS" in names

    def test_yara_match_signal(self, settings):
        result = _make_result(
            header_analysis=HeaderAnalysis(),
            yara_matches=YARAMatchSet(matches=[
                YARAMatch(
                    rule_name="phishops_clickfix",
                    ruleset="phishing_custom",
                    scan_target="body_html",
                ),
            ]),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "YARA_MATCH" in names
        sig = next(s for s in risk.signals_fired if s.name == "YARA_MATCH")
        assert sig.weight == 4.0


# =============================================================================
# Edge cases
# =============================================================================

class TestEdgeCases:

    def test_no_header_analysis(self, settings):
        """Scorer handles missing header_analysis gracefully."""
        result = _make_result()
        risk = score(result, settings)
        assert risk.verdict == Verdict.CLEAN
        assert risk.total_score == 0.0

    def test_no_iocs(self, settings):
        """Scorer handles missing IOCs gracefully."""
        result = _make_result(
            header_analysis=HeaderAnalysis(spf=AuthResult.FAIL),
        )
        risk = score(result, settings)
        # Only SPF_FAIL should fire
        assert risk.total_score == 2.0

    def test_signals_evaluated_count(self, settings):
        result = _make_result(header_analysis=HeaderAnalysis())
        risk = score(result, settings)
        assert risk.signals_evaluated == 11

    def test_spf_softfail_does_not_trigger_spf_fail(self, settings):
        """SPF softfail is NOT the same as fail — should not fire SPF_FAIL signal."""
        result = _make_result(
            header_analysis=HeaderAnalysis(spf=AuthResult.SOFTFAIL),
        )
        risk = score(result, settings)
        names = [s.name for s in risk.signals_fired]
        assert "SPF_FAIL" not in names

    def test_score_is_rounded(self, settings):
        """Total score should be rounded to 2 decimal places."""
        result = _make_result(
            header_analysis=HeaderAnalysis(
                spf=AuthResult.FAIL,  # 2.0
                dkim=AuthResult.FAIL,  # 1.5
            ),
        )
        risk = score(result, settings)
        assert risk.total_score == 3.5
        # Verify it's cleanly rounded
        assert risk.total_score == round(risk.total_score, 2)
