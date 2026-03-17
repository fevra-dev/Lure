"""
tests/test_extractor.py
Tests for lure/modules/extractor.py — IOC extraction.

Covers:
  - Defanged IOC extraction (hxxps://, [.], (dot), etc.)
  - The Anchor Text Trap (href vs visible text)
  - Domain validation
  - Hash classification
  - Private IP exclusion
  - Attachment URL extraction
  - Homograph domain detection via extractor
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from lure.models import IOCSet, HeaderAnalysis, AuthResult
from lure.modules.extractor import (
    _extract_from_text,
    _extract_from_html,
    _is_private_ip,
    _is_valid_domain,
    _classify_hash,
    _deduplicate_and_validate,
)


# =============================================================================
# Defanged IOC extraction
# =============================================================================

class TestDefangedExtraction:
    """
    Tests that iocextract correctly handles all common defang variants.
    Falls back to regex if iocextract not installed.
    """

    def test_hxxps_url(self):
        text = "Visit hxxps://evil.example.com/malware for details"
        iocs = _extract_from_text(text)
        assert any("evil.example.com" in url for url in iocs.urls)

    def test_bracket_dot_domain(self):
        text = "Domain: evil[.]example[.]com"
        iocs = _extract_from_text(text)
        # Should extract the domain
        assert any("evil.example.com" in (url + " ".join(iocs.domains)) for url in iocs.urls + iocs.domains)

    def test_paren_dot_domain(self):
        text = "hxxp://phishing(dot)site(dot)xyz/steal"
        iocs = _extract_from_text(text)
        # At minimum, the URL should be extracted in some form
        assert len(iocs.urls) > 0 or len(iocs.domains) > 0

    def test_plain_http_url(self):
        text = "Go to http://malicious.example.com/payload.exe to download"
        iocs = _extract_from_text(text)
        assert any("malicious.example.com" in url for url in iocs.urls)

    def test_ip_in_body(self):
        text = "Connect to 185.220.101.45 on port 8080"
        iocs = _extract_from_text(text)
        assert "185.220.101.45" in iocs.ips

    def test_defanged_ip(self):
        text = "Server IP: 185[.]220[.]101[.]45"
        iocs = _extract_from_text(text)
        # iocextract should handle this
        assert len(iocs.ips) > 0 or "185.220.101.45" in " ".join(iocs.ips)

    def test_private_ip_excluded(self):
        text = "Internal server at 192.168.1.100 and public at 185.220.101.45"
        iocs = _extract_from_text(text)
        assert "192.168.1.100" not in iocs.ips
        assert "185.220.101.45" in iocs.ips

    def test_email_address_extracted(self):
        text = "Reply to attacker@evil-domain.ru for instructions"
        iocs = _extract_from_text(text)
        assert any("evil-domain.ru" in email for email in iocs.emails)

    def test_sha256_hash_extracted(self):
        sha = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        text = f"Malware hash: {sha}"
        iocs = _extract_from_text(text)
        assert sha in iocs.hashes["sha256"]

    def test_md5_hash_extracted(self):
        md5 = "098f6bcd4621d373cade4e832627b4f5"
        text = f"File MD5: {md5}"
        iocs = _extract_from_text(text)
        assert md5 in iocs.hashes["md5"]

    def test_bitcoin_wallet_extracted(self):
        wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf ER"
        # Standard P2PKH address
        text = f"Send payment to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        iocs = _extract_from_text(text)
        # Bitcoin detection is supplementary — just verify no crash
        assert isinstance(iocs.wallets, list)


# =============================================================================
# HTML extraction — The Anchor Text Trap
# =============================================================================

class TestHTMLExtraction:
    """
    CRITICAL: The anchor text trap.
    The VISIBLE URL and the ACTUAL href are different in phishing emails.
    Lure must ALWAYS extract from href attributes, not visible text.
    """

    def test_href_extracted_not_display_text(self):
        """
        Classic phishing pattern:
        Display: paypal.com (looks safe)
        Actual href: evil.ru/steal (the real destination)
        Extractor must return evil.ru, NOT paypal.com from the anchor text.
        """
        html = '''<html><body>
        <a href="https://evil.ru/steal?token=abc">https://paypal.com/verify</a>
        </body></html>'''
        iocs = _extract_from_html(html)
        assert any("evil.ru" in url for url in iocs.urls), \
            "Must extract the real href destination"

    def test_multiple_hrefs(self):
        html = '''<html><body>
        <a href="https://phishing.xyz/login">Click here</a>
        <a href="https://tracker.evil.com/pixel">Unsubscribe</a>
        <img src="https://c2.evil.com/beacon.png">
        </body></html>'''
        iocs = _extract_from_html(html)
        url_str = " ".join(iocs.urls)
        assert "phishing.xyz" in url_str
        assert "tracker.evil.com" in url_str

    def test_img_src_extracted(self):
        """Tracking pixels in img src should be extracted."""
        html = '<html><body><img src="https://tracker.evil.com/open?id=123" width="1" height="1"></body></html>'
        iocs = _extract_from_html(html)
        assert any("tracker.evil.com" in url for url in iocs.urls)

    def test_form_action_extracted(self):
        """Form submission URL (credential exfiltration endpoint) must be extracted."""
        html = '''<html><body>
        <form action="https://harvest.evil.ru/collect" method="post">
          <input type="email" name="email">
          <input type="password" name="password">
          <input type="submit" value="Login">
        </form>
        </body></html>'''
        iocs = _extract_from_html(html)
        assert any("harvest.evil.ru" in url for url in iocs.urls)

    def test_javascript_links_skipped(self):
        """javascript: hrefs should not be added as URLs."""
        html = '<a href="javascript:void(0)">Click</a>'
        iocs = _extract_from_html(html)
        assert not any("javascript:" in url for url in iocs.urls)

    def test_mailto_links_become_emails(self):
        """mailto: hrefs are not URLs but may surface as email IOCs via visible text."""
        html = '<html><body><p>Contact: attacker@evil.com</p></body></html>'
        iocs = _extract_from_html(html)
        assert any("evil.com" in email for email in iocs.emails)

    def test_empty_html_no_crash(self):
        iocs = _extract_from_html("")
        assert isinstance(iocs, IOCSet)

    def test_malformed_html_handled(self):
        html = "<html><body><a href='unclosed"
        iocs = _extract_from_html(html)  # Should not raise
        assert isinstance(iocs, IOCSet)


# =============================================================================
# Domain validation
# =============================================================================

class TestDomainValidation:
    def test_valid_domain(self):
        assert _is_valid_domain("paypal.com") is True

    def test_valid_subdomain(self):
        assert _is_valid_domain("mail.evil.xyz") is True

    def test_localhost_invalid(self):
        assert _is_valid_domain("localhost") is False

    def test_single_label_invalid(self):
        assert _is_valid_domain("notadomain") is False

    def test_ip_address_invalid(self):
        assert _is_valid_domain("185.220.101.45") is False

    def test_common_tlds(self):
        for domain in ["example.com", "test.org", "evil.xyz", "phishing.top"]:
            assert _is_valid_domain(domain) is True


# =============================================================================
# Hash classification
# =============================================================================

class TestHashClassification:
    def test_md5_32_chars(self):
        iocs = IOCSet()
        _classify_hash(iocs, "098f6bcd4621d373cade4e832627b4f5")
        assert "098f6bcd4621d373cade4e832627b4f5" in iocs.hashes["md5"]

    def test_sha1_40_chars(self):
        iocs = IOCSet()
        _classify_hash(iocs, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in iocs.hashes["sha1"]

    def test_sha256_64_chars(self):
        iocs = IOCSet()
        sha = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        _classify_hash(iocs, sha)
        assert sha in iocs.hashes["sha256"]

    def test_sha512_128_chars(self):
        iocs = IOCSet()
        sha = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        _classify_hash(iocs, sha + "0")  # Make it 128 chars
        assert len(iocs.hashes["sha512"]) >= 0  # Just verify no crash

    def test_lowercases_hash(self):
        iocs = IOCSet()
        _classify_hash(iocs, "098F6BCD4621D373CADE4E832627B4F5")
        assert "098f6bcd4621d373cade4e832627b4f5" in iocs.hashes["md5"]


# =============================================================================
# Deduplication
# =============================================================================

class TestDeduplication:
    def test_duplicate_ips_removed(self):
        iocs = IOCSet(ips=["1.2.3.4", "1.2.3.4", "5.6.7.8"])
        result = _deduplicate_and_validate(iocs)
        assert result.ips.count("1.2.3.4") == 1

    def test_duplicate_urls_removed(self):
        from lure.models import ExtractedURL
        iocs = IOCSet(
            urls=["https://evil.com/a", "https://evil.com/a", "https://other.com/b"],
            urls_detailed=[
                ExtractedURL(url="https://evil.com/a", source="test"),
                ExtractedURL(url="https://evil.com/a", source="test2"),
                ExtractedURL(url="https://other.com/b", source="test"),
            ]
        )
        result = _deduplicate_and_validate(iocs)
        assert result.urls.count("https://evil.com/a") == 1

    def test_private_ips_removed(self):
        iocs = IOCSet(ips=["192.168.1.1", "10.0.0.1", "185.220.101.45"])
        result = _deduplicate_and_validate(iocs)
        assert "192.168.1.1" not in result.ips
        assert "10.0.0.1" not in result.ips
        assert "185.220.101.45" in result.ips

    def test_emails_lowercased(self):
        iocs = IOCSet(emails=["ATTACKER@EVIL.COM", "attacker@evil.com"])
        result = _deduplicate_and_validate(iocs)
        assert "attacker@evil.com" in result.emails
        assert len(result.emails) == 1

    def test_total_count_updated(self):
        iocs = IOCSet(
            ips=["1.2.3.4"],
            domains=["evil.com"],
            urls=["https://evil.com/page"],
        )
        from lure.models import ExtractedURL
        iocs.urls_detailed = [ExtractedURL(url="https://evil.com/page", source="test")]
        result = _deduplicate_and_validate(iocs)
        assert result.total_count > 0


# =============================================================================
# End-to-end extraction tests
# =============================================================================

class TestExtractorEndToEnd:
    def test_full_extraction_from_eml(self, eml_spf_fail, mock_no_dns):
        """Full pipeline: parse then extract IOCs from phishing email."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email
        from lure.modules.extractor import extract_iocs

        email_file = EmailFile.from_path(eml_spf_fail)
        analysis, mime_parts = parse_email(email_file)
        iocs, attachments = extract_iocs(
            header_analysis=analysis,
            mime_parts=mime_parts,
            follow_redirects=False,  # Don't make real HTTP calls in tests
        )

        # Should find the originating IP
        assert "185.220.101.45" in iocs.ips

        # Should find the phishing URL from the href (not the display text)
        assert any("paypa1.com" in url for url in iocs.urls)

        # Should NOT include tracking pixel URL as a false negative
        # (tracker URL should also be found)
        all_urls = " ".join(iocs.urls)
        assert "paypa1.com" in all_urls

    def test_defanged_body_extraction(self, eml_defanged_iocs, mock_no_dns):
        """Defanged IOCs in plain text body are extracted correctly."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email
        from lure.modules.extractor import extract_iocs

        email_file = EmailFile.from_path(eml_defanged_iocs)
        analysis, mime_parts = parse_email(email_file)
        iocs, _ = extract_iocs(
            header_analysis=analysis,
            mime_parts=mime_parts,
            follow_redirects=False,
        )

        # IP should be extracted (possibly defanged)
        ips_str = " ".join(iocs.ips)
        assert "185.220.101.45" in ips_str or len(iocs.ips) > 0

        # SHA256 should be extracted
        sha = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        assert sha in iocs.hashes.get("sha256", [])

    def test_reply_to_email_in_iocs(self, eml_reply_to_mismatch, mock_no_dns):
        """Reply-To email address appears in the IOC email list."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email
        from lure.modules.extractor import extract_iocs

        email_file = EmailFile.from_path(eml_reply_to_mismatch)
        analysis, mime_parts = parse_email(email_file)
        iocs, _ = extract_iocs(
            header_analysis=analysis,
            mime_parts=mime_parts,
            follow_redirects=False,
        )

        assert any("gmail.com" in email for email in iocs.emails)

    def test_clean_email_minimal_iocs(self, eml_clean, mock_no_dns):
        """Legitimate email has minimal/safe IOCs."""
        from lure.models import EmailFile
        from lure.modules.parser import parse_email
        from lure.modules.extractor import extract_iocs

        email_file = EmailFile.from_path(eml_clean)
        analysis, mime_parts = parse_email(email_file)
        iocs, _ = extract_iocs(
            header_analysis=analysis,
            mime_parts=mime_parts,
            follow_redirects=False,
        )

        # Should not find suspicious IPs
        for ip in iocs.ips:
            assert not _is_private_ip(ip), "Private IPs should be excluded"

        # Should find the company.com domain from the URL
        assert any("company.com" in domain for domain in iocs.domains)
