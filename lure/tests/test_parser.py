"""
tests/test_parser.py
Tests for lure/modules/parser.py — email parsing and header forensics.

All tests run without real API keys.
DNS calls are mocked via conftest.py fixtures.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from lure.models import AuthResult, FileType
from lure.modules.parser import (
    _is_homograph,
    _is_private_ip,
    _parse_address,
    _parse_received_chain,
    _find_originating_ip,
    _parse_auth_results,
    HeaderAnalysis,
)


# =============================================================================
# Address parsing
# =============================================================================

class TestParseAddress:
    def test_standard_format(self):
        display, domain = _parse_address("John Doe <john@example.com>")
        assert domain == "example.com"
        assert display == "John Doe"

    def test_bare_email(self):
        display, domain = _parse_address("john@example.com")
        assert domain == "example.com"

    def test_subdomain_normalized(self):
        """Domain extraction should return registered domain, not full FQDN."""
        _, domain = _parse_address("sender@mail.paypal.com")
        assert domain == "paypal.com"

    def test_empty_returns_none(self):
        display, domain = _parse_address("")
        assert display is None
        assert domain is None

    def test_no_at_sign(self):
        display, domain = _parse_address("not-an-email")
        assert domain is None

    def test_quoted_display_name(self):
        _, domain = _parse_address('"Paypal Security" <security@paypal.com>')
        assert domain == "paypal.com"


# =============================================================================
# Private IP detection
# =============================================================================

class TestPrivateIP:
    def test_rfc1918_10(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert _is_private_ip("185.220.101.45") is False

    def test_another_public(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_invalid_ip_returns_false(self):
        assert _is_private_ip("not-an-ip") is False


# =============================================================================
# Received chain parsing
# =============================================================================

class TestReceivedChain:
    def test_single_hop(self):
        received = [
            "from mail.evil.com (unknown [185.220.101.45]) "
            "by mx.company.com (Postfix) with ESMTP; "
            "Mon, 24 Feb 2026 09:00:00 +0000"
        ]
        hops = _parse_received_chain(received)
        assert len(hops) == 1
        assert hops[0].from_host == "mail.evil.com"
        assert hops[0].from_ip == "185.220.101.45"
        assert hops[0].by_host == "mx.company.com"

    def test_multiple_hops(self):
        received = [
            "from mx.company.com by mbox.company.com with LMTP; Mon, 24 Feb 2026 09:00:05 +0000",
            "from relay.isp.com (relay.isp.com [203.0.113.50]) by mx.company.com with ESMTPS; Mon, 24 Feb 2026 09:00:03 +0000",
            "from mail.evil.com (unknown [185.220.101.45]) by relay.isp.com with ESMTP; Mon, 24 Feb 2026 09:00:01 +0000",
        ]
        hops = _parse_received_chain(received)
        assert len(hops) == 3

    def test_originating_ip_found(self):
        received = [
            "from mx.company.com by mbox.company.com with LMTP",
            "from mail.evil.com (evil [185.220.101.45]) by mx.company.com with ESMTP",
        ]
        hops = _parse_received_chain(received)
        orig_ip = _find_originating_ip(hops)
        assert orig_ip == "185.220.101.45"

    def test_skips_private_ips(self):
        """Internal relay IPs should not be returned as originating IP."""
        received = [
            "from mx.company.com (192.168.1.5) by mbox.company.com",
            "from external.attacker.com (external.attacker.com [91.234.56.78]) by mx.company.com",
        ]
        hops = _parse_received_chain(received)
        orig_ip = _find_originating_ip(hops)
        assert orig_ip == "91.234.56.78"

    def test_with_protocol_extracted(self):
        received = ["from a.com by b.com with ESMTPS id abc123"]
        hops = _parse_received_chain(received)
        assert hops[0].with_protocol == "ESMTPS"


# =============================================================================
# Authentication-Results parsing
# =============================================================================

class TestAuthResultsParsing:
    def test_all_pass(self):
        analysis = HeaderAnalysis()
        _parse_auth_results(
            "mx.example.com; spf=pass; dkim=pass; dmarc=pass",
            analysis
        )
        assert analysis.spf == AuthResult.PASS
        assert analysis.dkim == AuthResult.PASS
        assert analysis.dmarc == AuthResult.PASS

    def test_spf_fail_dmarc_fail(self):
        analysis = HeaderAnalysis()
        _parse_auth_results(
            "mx.example.com; spf=fail (IP not authorized); dkim=none; dmarc=fail",
            analysis
        )
        assert analysis.spf == AuthResult.FAIL
        assert analysis.dkim == AuthResult.NONE
        assert analysis.dmarc == AuthResult.FAIL

    def test_spf_softfail(self):
        analysis = HeaderAnalysis()
        _parse_auth_results(
            "mx.example.com; spf=softfail; dmarc=fail",
            analysis
        )
        assert analysis.spf == AuthResult.SOFTFAIL

    def test_dmarc_policy_extracted(self):
        analysis = HeaderAnalysis()
        _parse_auth_results(
            "mx.example.com; dmarc=fail policy=quarantine",
            analysis
        )
        assert analysis.dmarc_policy == "quarantine"

    def test_case_insensitive(self):
        analysis = HeaderAnalysis()
        _parse_auth_results(
            "mx.example.com; SPF=PASS; DKIM=PASS; DMARC=PASS",
            analysis
        )
        assert analysis.spf == AuthResult.PASS

    def test_empty_header(self):
        analysis = HeaderAnalysis()
        _parse_auth_results("", analysis)
        assert analysis.spf == AuthResult.UNKNOWN


# =============================================================================
# Homograph detection
# =============================================================================

class TestHomographDetection:
    def test_pure_latin_clean(self):
        assert _is_homograph("paypal.com") is False

    def test_cyrillic_a_detected(self):
        # Cyrillic 'а' (U+0430) mixed with Latin
        domain = "p\u0430ypal.com"  # Cyrillic а
        assert _is_homograph(domain) is True

    def test_cyrillic_o_detected(self):
        # Cyrillic 'о' (U+043E) mixed with Latin
        domain = "g\u043e\u043egle.com"
        assert _is_homograph(domain) is True

    def test_greek_omicron(self):
        # Greek omicron looks like Latin o
        domain = "g\u03bfgle.com"  # Greek ο
        assert _is_homograph(domain) is True

    def test_all_latin_not_flagged(self):
        for domain in ["google.com", "paypal.com", "microsoft.com", "apple.com"]:
            assert _is_homograph(domain) is False, f"{domain} should not be flagged"

    def test_unicode_domain_normalized(self):
        # Pure unicode domain (same script throughout) should not flag
        assert _is_homograph("россия.рф") is False  # All Cyrillic


# =============================================================================
# End-to-end parser tests (using fixture .eml files)
# =============================================================================

class TestParserEndToEnd:
    def test_spf_fail_email(self, eml_spf_fail, mock_no_dns):
        """Email with SPF fail in Authentication-Results is parsed correctly."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email

        email_file = EmailFile.from_path(eml_spf_fail)
        analysis, mime_parts = parse_email(email_file)

        assert analysis.spf == AuthResult.FAIL
        assert analysis.dmarc == AuthResult.FAIL
        assert analysis.from_addr is not None
        assert "legitimate-bank.com" in (analysis.from_addr or "")
        assert analysis.originating_ip == "185.220.101.45"

    def test_reply_to_mismatch_detected(self, eml_reply_to_mismatch, mock_no_dns):
        """Reply-To mismatch is correctly flagged as anomaly."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email

        email_file = EmailFile.from_path(eml_reply_to_mismatch)
        analysis, mime_parts = parse_email(email_file)

        assert analysis.reply_to_mismatch is True
        assert analysis.reply_to is not None
        assert "gmail.com" in analysis.reply_to
        assert len(analysis.anomalies) >= 1

    def test_clean_email_passes(self, eml_clean, mock_no_dns):
        """Legitimate email with passing auth shows no anomalies."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email

        email_file = EmailFile.from_path(eml_clean)
        analysis, mime_parts = parse_email(email_file)

        # Auth results from the Authentication-Results header
        assert analysis.spf == AuthResult.PASS
        assert analysis.dkim == AuthResult.PASS
        assert analysis.dmarc == AuthResult.PASS
        assert analysis.reply_to_mismatch is False
        assert analysis.is_homograph is False

    def test_mime_parts_extracted(self, eml_spf_fail, mock_no_dns):
        """MIME parts are correctly extracted from a multipart email."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email

        email_file = EmailFile.from_path(eml_spf_fail)
        analysis, mime_parts = parse_email(email_file)

        assert len(mime_parts) >= 1
        # Should find the HTML body
        html_parts = [p for p in mime_parts if "html" in p.get("content_type", "")]
        assert len(html_parts) == 1

    def test_attachment_detected(self, eml_vba_macro, mock_no_dns):
        """Email with attachment — MIME part is marked as attachment."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email

        email_file = EmailFile.from_path(eml_vba_macro)
        analysis, mime_parts = parse_email(email_file)

        attachments = [p for p in mime_parts if p.get("is_attachment")]
        assert len(attachments) >= 1
        assert any("Annual_Review" in (p.get("filename") or "") for p in attachments)

    def test_received_hops_counted(self, eml_spf_fail, mock_no_dns):
        """Received chain hops are counted correctly."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email

        email_file = EmailFile.from_path(eml_spf_fail)
        analysis, _ = parse_email(email_file)

        assert analysis.received_hops == 1
        assert len(analysis.routing) == 1
        assert analysis.routing[0].from_ip == "185.220.101.45"

    def test_subject_extracted(self, eml_spf_fail, mock_no_dns):
        from lure.models import EmailFile
        from lure.modules.parser import parse_email

        email_file = EmailFile.from_path(eml_spf_fail)
        analysis, _ = parse_email(email_file)

        assert analysis.subject == "Urgent: Verify Your Account"

    def test_email_file_from_path(self, eml_clean):
        """EmailFile.from_path correctly identifies file type and computes hash."""
        from lure.models import EmailFile, FileType

        email_file = EmailFile.from_path(eml_clean)
        assert email_file.file_type == FileType.EML
        assert len(email_file.sha256) == 64
        assert email_file.size_bytes > 0

    def test_file_not_found_raises(self, tmp_path):
        from lure.models import EmailFile
        with pytest.raises(FileNotFoundError):
            EmailFile.from_path(tmp_path / "nonexistent.eml")
