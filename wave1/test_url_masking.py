"""
proxyguard/tests/test_url_masking.py

Unit tests for the URL userinfo masking detector.
All test data is inline — no network calls.

Run: pytest proxyguard/tests/test_url_masking.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detectors.url_masking import detect_userinfo_masking


# ---------------------------------------------------------------------------
# Happy-path: masking patterns must fire
# ---------------------------------------------------------------------------

def test_brand_masking_fires():
    """Core Starkiller pattern: microsoft.com in userinfo, .ru attacker domain"""
    result = detect_userinfo_masking("https://microsoft.com@attacker-proxy.ru/login")
    assert result.detected is True
    # Brand(0.20) + Suspicious TLD(0.10) + baseline(0.70) = 1.00 → capped at 1.0
    assert result.risk_score >= 0.85
    assert result.actual_host == "attacker-proxy.ru"
    assert "microsoft.com" in result.displayed_as


def test_google_impersonation():
    """Google brand in userinfo"""
    result = detect_userinfo_masking("https://google.com@evil-site.xyz/signin")
    assert result.detected is True
    assert result.risk_score >= 0.85
    assert result.actual_host == "evil-site.xyz"
    assert any("brand_impersonation" in s for s in result.signals)


def test_paypal_impersonation_suspicious_tld():
    """PayPal brand + .top TLD"""
    result = detect_userinfo_masking("https://paypal.com@login-secure.top/verify")
    assert result.detected is True
    assert result.risk_score >= 0.85
    assert any("suspicious_tld" in s for s in result.signals)


def test_userinfo_without_brand_still_fires():
    """Any userinfo in URL is suspicious even without a brand match"""
    result = detect_userinfo_masking("https://user123@somesite.xyz/account")
    assert result.detected is True
    assert result.risk_score >= 0.70  # baseline 0.70 + suspicious TLD 0.10
    assert "userinfo_present" in result.signals


def test_userinfo_with_password_fires():
    """Username:password style userinfo must also be detected"""
    result = detect_userinfo_masking("https://admin:password@attacker.ru/panel")
    assert result.detected is True
    assert "admin:password" in result.displayed_as


def test_userinfo_no_brand_no_suspicious_tld_baseline_score():
    """Userinfo present but no brand match and no suspicious TLD — baseline only"""
    result = detect_userinfo_masking("https://someuser@legitimatelooking.com/path")
    assert result.detected is True
    assert result.risk_score == 0.70   # baseline only, no amplifiers


# ---------------------------------------------------------------------------
# Negative cases: must NOT fire
# ---------------------------------------------------------------------------

def test_clean_microsoft_url_does_not_fire():
    """Normal OAuth URL with no userinfo must not trigger"""
    result = detect_userinfo_masking(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        "?client_id=abc&response_type=code"
    )
    assert result.detected is False
    assert result.risk_score == 0.0


def test_clean_google_url_does_not_fire():
    result = detect_userinfo_masking("https://accounts.google.com/o/oauth2/auth?client_id=x")
    assert result.detected is False


def test_no_userinfo_clean():
    result = detect_userinfo_masking("https://google.com/search?q=test")
    assert result.detected is False
    assert result.risk_score == 0.0


def test_plain_domain_clean():
    result = detect_userinfo_masking("https://example.com")
    assert result.detected is False
    assert result.risk_score == 0.0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_curl_style_auth_url_is_detected():
    """API auth URL with credentials — detected (allowlist is proxy_guard.py responsibility)"""
    result = detect_userinfo_masking("https://admin:s3cr3t@api.internal.corp/endpoint")
    assert result.detected is True
    # Internal domain handling (allowlist) is proxy_guard.py's job — detector just flags it

def test_malformed_url_returns_clean_no_raise():
    """Malformed URLs must not raise — return clean result"""
    result = detect_userinfo_masking("not a url at all %%%")
    assert result.detected is False
    assert result.risk_score == 0.0


def test_empty_url_returns_clean_no_raise():
    result = detect_userinfo_masking("")
    assert result.detected is False


def test_signals_always_populated():
    """signals list must never be empty"""
    result = detect_userinfo_masking("https://clean.example.com/path")
    assert isinstance(result.signals, list)
    assert len(result.signals) >= 1


def test_actual_risk_score_for_spec_example():
    """
    Spot-check from the verification checklist:
    detect_userinfo_masking("https://microsoft.com@attacker.com/login") → risk_score=0.90
    
    baseline=0.70 + brand=0.20 = 0.90 (attacker.com has no suspicious TLD so no +0.10)
    """
    result = detect_userinfo_masking("https://microsoft.com@attacker.com/login")
    assert result.detected is True
    assert result.risk_score == 0.90, (
        f"Expected 0.90 per spec (baseline=0.70 + brand=0.20), got {result.risk_score}"
    )
