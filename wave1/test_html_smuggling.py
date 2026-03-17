"""
proxyguard/tests/test_html_smuggling.py

Unit tests for the HTML smuggling detector.
All test data is inline — no network calls, no external dependencies.

Run: pytest proxyguard/tests/test_html_smuggling.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detectors.html_smuggling import scan_response_body, HtmlSmugglingResult


# ---------------------------------------------------------------------------
# Happy-path: core attack patterns must fire
# ---------------------------------------------------------------------------

def test_atob_blob_fires():
    """Core smuggling pattern: atob() + createObjectURL(new Blob(...))"""
    body = """
    var payload = atob('PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
    var blob = new Blob([payload], {type: 'text/html'});
    var url = URL.createObjectURL(blob);
    window.location.assign(url);
    """
    result = scan_response_body(body, "text/html")
    assert result.detected is True, "atob+Blob+createObjectURL must fire"
    assert result.risk_score >= 0.65
    assert (
        "ATOB_BLOB_CREATEOBJECTURL" in result.pattern_name
        or any("ATOB" in s for s in result.signals)
    ), f"Expected ATOB pattern in signals, got: {result.signals}"


def test_mshta_scriptblock_fires():
    """Windows-specific smuggling via mshta — should hit 0.65 threshold alone"""
    body = 'var cmd = "mshta.exe javascript:a=new ActiveXObject(\'Wscript.Shell\');a.Run()"'
    result = scan_response_body(body, "text/html")
    assert result.detected is True, "MSHTA_SCRIPTBLOCK must fire (contribution=0.65)"
    assert result.risk_score >= 0.65
    assert any("MSHTA" in s for s in result.signals)


def test_combined_patterns_escalate():
    """Multiple patterns together must compound above threshold"""
    body = """
    var d = atob('PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
    var b = new Blob([d], {type:'text/html'});
    var u = URL.createObjectURL(b);
    var a = document.createElement('a');
    a.href = u;
    a.click();
    """
    result = scan_response_body(body, "text/html")
    assert result.detected is True
    # ATOB(0.70) + DYNAMIC_ANCHOR(0.30) = 1.0 (capped)
    assert result.risk_score >= 0.80, f"Compounded score should be >= 0.80, got {result.risk_score}"
    assert len(result.signals) >= 2, "Multiple patterns should produce multiple signals"


def test_blob_navigate_then_anchor_compounds():
    """BLOB_CREATEOBJECTURL(0.30) + BLOB_NAVIGATE(0.20) + DYNAMIC_ANCHOR_CLICK(0.20) = 0.70 → ALERT"""
    body = """
    var blobUrl = URL.createObjectURL(myBlob);
    window.open(blobUrl, '_blank');
    var a = document.createElement('a');
    a.href = blobUrl;
    a.click();
    """
    result = scan_response_body(body, "text/html")
    assert result.detected is True
    assert result.risk_score >= 0.65, f"Three-pattern compound must alert, got {result.risk_score}"


def test_snippet_captured_on_alert():
    """matched_snippet must be non-empty and <= 120 chars when detected"""
    body = "var x = atob('dGVzdA=='); var b = URL.createObjectURL(new Blob([x]));"
    result = scan_response_body(body, "text/html; charset=utf-8")
    assert result.detected is True
    assert 0 < len(result.matched_snippet) <= 120


# ---------------------------------------------------------------------------
# Negative cases: must NOT fire
# ---------------------------------------------------------------------------

def test_clean_body_does_not_fire():
    """Normal HTML login page must not trigger detection"""
    body = """
    <!DOCTYPE html>
    <html><body>
      <h1>Sign In</h1>
      <form action="/login" method="post">
        <input type="text" name="username">
        <input type="password" name="password">
        <button type="submit">Login</button>
      </form>
    </body></html>
    """
    result = scan_response_body(body, "text/html")
    assert result.detected is False
    assert result.risk_score < 0.65


def test_wrong_content_type_skipped():
    """Non-HTML/JS content types must be skipped entirely — even if body would match"""
    body = "atob('abc') createObjectURL(new Blob"  # would match if checked
    result = scan_response_body(body, "image/png")
    assert result.detected is False
    assert "content_type_skipped" in result.signals


def test_json_content_type_skipped():
    """JSON responses must be skipped"""
    body = '{"atob": "test", "createObjectURL": "fakeBlob"}'
    result = scan_response_body(body, "application/json; charset=utf-8")
    assert result.detected is False
    assert "content_type_skipped" in result.signals


def test_dynamic_anchor_click_alone_is_low_confidence():
    """createElement('a') + click() alone must NOT reach 0.65 threshold (score=0.20)"""
    body = """
    var a = document.createElement('a');
    a.href = '/download/report.pdf';
    document.body.appendChild(a);
    a.click();
    """
    result = scan_response_body(body, "text/javascript")
    assert result.detected is False, f"Anchor click alone (0.20) must not alert, got {result.risk_score}"
    assert result.risk_score == 0.20


def test_large_base64_alone_is_below_threshold():
    """A large base64 string alone (0.15) must NOT alert"""
    b64 = "A" * 600  # trivially matches LARGE_BASE64_STRING pattern
    body = f'var data = "{b64}";'
    result = scan_response_body(body, "text/javascript")
    assert result.detected is False
    assert result.risk_score == 0.15


def test_blob_navigate_createobjecturl_below_threshold():
    """BLOB_CREATEOBJECTURL(0.30) + BLOB_NAVIGATE(0.20) = 0.50 — below 0.65 threshold"""
    body = """
    var blobUrl = URL.createObjectURL(theBlob);
    location.href = blobUrl;
    """
    result = scan_response_body(body, "text/html")
    assert result.detected is False, (
        f"BLOB_CREATEOBJECTURL+BLOB_NAVIGATE alone (0.50) must not alert, got {result.risk_score}"
    )
    assert result.risk_score == 0.50


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_body_returns_clean():
    result = scan_response_body("", "text/html")
    assert result.detected is False
    assert result.risk_score == 0.0


def test_50kb_cap_does_not_crash():
    """Body larger than 50 KB must not crash and must still detect if pattern is in first 50 KB"""
    # Put the smuggling payload in first 100 chars, pad to 200 KB
    prefix = "var p=atob('PHg+'); var b=new Blob([p]); URL.createObjectURL(b);"
    body = prefix + ("X" * 200_000)
    result = scan_response_body(body, "text/html")
    assert result.detected is True  # Pattern was in first 50 KB


def test_charset_suffix_in_content_type_not_skipped():
    """Content-Type with charset suffix must still be scanned"""
    body = "var p=atob('PHg+'); URL.createObjectURL(new Blob([p]));"
    result = scan_response_body(body, "text/html; charset=utf-8")
    assert result.detected is True


def test_javascript_content_type_is_scanned():
    """application/javascript must be scanned"""
    body = "atob('PHNjcmlwdA=='); URL.createObjectURL(new Blob(['x']));"
    result = scan_response_body(body, "application/javascript")
    assert result.detected is True


def test_signals_always_populated():
    """signals list must never be empty — even on clean result"""
    result = scan_response_body("<html>clean</html>", "text/html")
    assert isinstance(result.signals, list)
    assert len(result.signals) >= 1
