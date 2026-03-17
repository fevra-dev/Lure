"""
tests/conftest.py
Shared pytest fixtures for all Lure test modules.

Design rule: All tests run without real API keys.
  - DNS calls are mocked via unittest.mock
  - HTTP calls are intercepted via responses/pytest-httpx
  - Real .eml files in tests/samples/ are used for integration testing
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

SAMPLES_DIR = Path(__file__).parent / "samples"


# =============================================================================
# .eml file fixtures
# =============================================================================

@pytest.fixture
def sample_dir() -> Path:
    return SAMPLES_DIR


@pytest.fixture
def eml_spf_fail(tmp_path) -> Path:
    """Email with SPF hardfail in Authentication-Results."""
    content = b"""From: ceo@legitimate-bank.com
To: victim@company.com
Subject: Urgent: Verify Your Account
Date: Mon, 24 Feb 2026 09:00:00 +0000
Message-ID: <test001@evil.example>
Reply-To: attacker@protonmail.com
X-Originating-IP: 185.220.101.45
Received: from mail.evil.example (unknown [185.220.101.45])
    by mx.company.com (Postfix) with ESMTP id ABC123;
    Mon, 24 Feb 2026 09:00:00 +0000 (UTC)
Authentication-Results: mx.company.com;
    spf=fail (sender IP is 185.220.101.45) smtp.mailfrom=legitimate-bank.com;
    dkim=none;
    dmarc=fail (p=reject; sp=reject; dis=reject) header.from=legitimate-bank.com
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Click here to verify: <a href="https://paypa1.com/verify?token=abc123">Verify Now</a></p>
<p>If you did not request this, ignore this email.</p>
<img src="https://tracker.evil.com/pixel.png" width="1" height="1">
</body></html>
"""
    p = tmp_path / "spf_fail_dmarc_fail.eml"
    p.write_bytes(content)
    return p


@pytest.fixture
def eml_reply_to_mismatch(tmp_path) -> Path:
    """Email with Reply-To domain mismatch."""
    content = b"""From: payroll@acme.corp
To: employee@acme.corp
Subject: Payroll Update Required
Date: Mon, 24 Feb 2026 10:00:00 +0000
Message-ID: <test002@relay.example>
Reply-To: accounting.update@gmail.com
Received: from relay.example (relay.example [203.0.113.42])
    by mx.acme.corp (Postfix) with ESMTPA id DEF456;
    Mon, 24 Feb 2026 10:00:00 +0000 (UTC)
Authentication-Results: mx.acme.corp;
    spf=pass smtp.mailfrom=acme.corp;
    dkim=pass header.d=acme.corp;
    dmarc=pass
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Dear Employee,

Please update your direct deposit information by clicking the link below.
This is urgent and must be completed by end of day.

hxxps://acme-payroll[.]update-portal[.]xyz/verify

Best regards,
Payroll Department
"""
    p = tmp_path / "reply_to_mismatch.eml"
    p.write_bytes(content)
    return p


@pytest.fixture
def eml_defanged_iocs(tmp_path) -> Path:
    """Email body with heavily defanged IOCs."""
    content = b"""From: security@alerts.com
To: user@example.com
Subject: Security Alert
Date: Mon, 24 Feb 2026 11:00:00 +0000
Message-ID: <test003@alerts.com>
Received: from smtp.alerts.com (smtp.alerts.com [198.51.100.10])
    by mx.example.com with ESMTPS;
    Mon, 24 Feb 2026 11:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Suspicious activity detected from:
- hxxps://evil[.]example[.]com/malware
- 185[.]220[.]101[.]45
- hxxp://phishing(dot)site/steal?id=12345
- http://normal-looking-url.xyz/page
SHA256: a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
MD5: 098f6bcd4621d373cade4e832627b4f5

Contact us at: security-alerts@evil-domain.ru
"""
    p = tmp_path / "defanged_iocs.eml"
    p.write_bytes(content)
    return p


@pytest.fixture
def eml_homograph(tmp_path) -> Path:
    """Email with Cyrillic homograph in sender domain."""
    # \u0440 = Cyrillic 'р', \u0430 = Cyrillic 'а' — looks identical to Latin
    content = "From: security@\u0440\u0430ypal.com\r\nTo: victim@company.com\r\nSubject: Verify your account\r\nDate: Mon, 24 Feb 2026 12:00:00 +0000\r\nMessage-ID: <test004@homograph.test>\r\nReceived: from mail.attacker.ru (mail.attacker.ru [91.234.56.78])\r\n    by mx.company.com with ESMTP;\r\n    Mon, 24 Feb 2026 12:00:00 +0000\r\nAuthentication-Results: mx.company.com;\r\n    spf=fail;\r\n    dmarc=fail\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nYour account needs verification.\r\n"
    p = tmp_path / "homograph_domain.eml"
    p.write_bytes(content.encode("utf-8"))
    return p


@pytest.fixture
def eml_clean(tmp_path) -> Path:
    """Legitimate email with all auth passing."""
    content = b"""From: newsletter@company.com
To: subscriber@example.com
Subject: Monthly Newsletter - February 2026
Date: Mon, 24 Feb 2026 08:00:00 +0000
Message-ID: <newsletter.2026.02@company.com>
Received: from smtp.company.com (smtp.company.com [203.0.113.100])
    by mx.example.com (Postfix) with ESMTPS id XYZ789;
    Mon, 24 Feb 2026 08:00:00 +0000
Authentication-Results: mx.example.com;
    spf=pass smtp.mailfrom=company.com;
    dkim=pass header.d=company.com;
    dmarc=pass
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<h1>Monthly Newsletter</h1>
<p>Welcome to our February 2026 newsletter.</p>
<p>Visit our website: <a href="https://www.company.com/news">Read More</a></p>
</body></html>
"""
    p = tmp_path / "clean_legitimate.eml"
    p.write_bytes(content)
    return p


@pytest.fixture
def eml_vba_macro(tmp_path) -> Path:
    """Email with a Word attachment reference (no actual OLE file — tests attachment detection)."""
    content = b"""From: hr@company-hr.net
To: employee@target.com
Subject: Annual Review Document - Action Required
Date: Mon, 24 Feb 2026 13:00:00 +0000
Message-ID: <test005@hr.example>
Received: from mail.company-hr.net (unknown [45.142.212.100])
    by mx.target.com with ESMTP;
    Mon, 24 Feb 2026 13:00:00 +0000
Authentication-Results: mx.target.com;
    spf=fail;
    dmarc=fail
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary001"

--boundary001
Content-Type: text/plain; charset=utf-8

Please review the attached performance document.
Enable macros when prompted.

--boundary001
Content-Type: application/vnd.ms-word; name="Annual_Review.doc"
Content-Disposition: attachment; filename="Annual_Review.doc"
Content-Transfer-Encoding: base64

q83vze8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

--boundary001--
"""
    p = tmp_path / "vba_macro_word.eml"
    p.write_bytes(content)
    return p


# =============================================================================
# Mock fixtures
# =============================================================================

@pytest.fixture
def mock_spf_fail():
    """Mock pyspf to return fail result."""
    with patch("lure.modules.parser.spf") as mock_spf:
        mock_spf.check2.return_value = ("fail", 550, "SPF FAIL: IP not in sender policy")
        yield mock_spf


@pytest.fixture
def mock_spf_pass():
    """Mock pyspf to return pass result."""
    with patch("lure.modules.parser.spf") as mock_spf:
        mock_spf.check2.return_value = ("pass", 250, "SPF PASS")
        yield mock_spf


@pytest.fixture
def mock_dkim_pass():
    """Mock dkimpy to return pass."""
    with patch("lure.modules.parser._check_dkim") as mock:
        from lure.models import AuthResult
        mock.return_value = (AuthResult.PASS, "DKIM signature verified")
        yield mock


@pytest.fixture
def mock_dkim_fail():
    """Mock dkimpy to return fail."""
    with patch("lure.modules.parser._check_dkim") as mock:
        from lure.models import AuthResult
        mock.return_value = (AuthResult.FAIL, "DKIM verification failed")
        yield mock


@pytest.fixture
def mock_dmarc_fail():
    """Mock checkdmarc to return fail."""
    with patch("lure.modules.parser._check_dmarc") as mock:
        from lure.models import AuthResult
        mock.return_value = (AuthResult.FAIL, "policy=reject", "reject")
        yield mock


@pytest.fixture
def mock_no_dns():
    """Mock all DNS-dependent functions to avoid real network calls."""
    with patch("lure.modules.parser._check_spf") as mock_spf, \
         patch("lure.modules.parser._check_dkim") as mock_dkim, \
         patch("lure.modules.parser._check_dmarc") as mock_dmarc:
        from lure.models import AuthResult
        mock_spf.return_value = (AuthResult.UNKNOWN, "mocked")
        mock_dkim.return_value = (AuthResult.UNKNOWN, "mocked")
        mock_dmarc.return_value = (AuthResult.UNKNOWN, "mocked", None)
        yield
