"""
lure/modules/parser.py
Email Parsing & Header Forensics Engine — Pipeline Stage A

Responsibilities:
  - Parse .eml (RFC 5322) and .msg (OLE Compound) files
  - Validate SPF, DKIM, DMARC authentication
  - Walk Received chain to find true originating IP
  - Detect Reply-To mismatches, homograph domains
  - Extract all MIME parts for downstream processing

Design rules:
  - NEVER trust relay-added Authentication-Results headers
  - Only consume the topmost Authentication-Results (added by final receiving MTA)
  - SPF softfail (~all) is NOT the same as hardfail (-all) — weight differently
  - DKIM failure in a forwarding chain is expected — weight DMARC alignment more
"""
from __future__ import annotations

import logging
import re
import unicodedata
from email import policy as email_policy
from email.headerregistry import Address
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Optional

import tldextract

from lure.models import (
    AuthResult,
    EmailFile,
    FileType,
    HeaderAnalysis,
    RoutingHop,
)

log = logging.getLogger(__name__)

# =============================================================================
# Regex patterns
# =============================================================================

# Extract IPv4 from a Received header
_IP_RE = re.compile(
    r"(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)"
)

# Parse key parts of a Received header
_RECEIVED_RE = re.compile(
    r"from\s+(?P<from_host>\S+)"
    r"(?:\s+\((?P<paren_content>[^)]*)\))?"
    r".*?by\s+(?P<by_host>\S+)",
    re.IGNORECASE | re.DOTALL,
)

# Protocol extraction
_WITH_RE = re.compile(r"\bwith\s+(\S+)", re.IGNORECASE)

# Authentication-Results parser
_AUTH_RESULT_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|permerror|temperror)",
    re.IGNORECASE,
)

# Known URL shortener domains
_URL_SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly",
    "adf.ly", "short.link", "rebrand.ly", "cutt.ly", "tiny.cc",
})

# Suspicious TLDs used heavily in phishing
_SUSPICIOUS_TLDS = frozenset({
    "xyz", "top", "click", "loan", "work", "date", "racing",
    "download", "gq", "ml", "tk", "cf", "ga",
})

# VBA macro high-risk keywords
_VBA_HIGH_RISK = frozenset({
    "Shell", "WScript", "CreateObject", "AutoOpen", "Document_Open",
    "Environ", "URLDownloadToFile", "PowerShell", "cmd.exe",
    "mshta.exe", "wscript.exe", "cscript.exe",
})


# =============================================================================
# Public interface
# =============================================================================

def parse_email(email_file: EmailFile) -> tuple[HeaderAnalysis, list[dict]]:
    """
    Parse an email file and perform header forensics.

    Returns:
        (HeaderAnalysis, mime_parts)
        mime_parts: list of dicts with keys: filename, content_type, payload (bytes)
    """
    path = Path(email_file.path)

    if email_file.file_type == FileType.MSG:
        return _parse_msg(path)
    else:
        return _parse_eml(path)


# =============================================================================
# EML parsing
# =============================================================================

def _parse_eml(path: Path) -> tuple[HeaderAnalysis, list[dict]]:
    """Parse an RFC 5322 .eml file."""
    raw = path.read_bytes()

    parser = BytesParser(policy=email_policy.compat32)
    msg = parser.parsebytes(raw)

    analysis = HeaderAnalysis()
    mime_parts: list[dict] = []

    # ── Sender info ───────────────────────────────────────────────────────
    analysis.from_addr = _clean_header(msg.get("From", ""))
    analysis.from_display_name, analysis.from_domain = _parse_address(analysis.from_addr)

    reply_to_raw = _clean_header(msg.get("Reply-To", ""))
    if reply_to_raw:
        analysis.reply_to = reply_to_raw
        _, analysis.reply_to_domain = _parse_address(reply_to_raw)
        if (
            analysis.from_domain
            and analysis.reply_to_domain
            and analysis.from_domain.lower() != analysis.reply_to_domain.lower()
        ):
            analysis.reply_to_mismatch = True
            analysis.anomalies.append(
                f"Reply-To domain '{analysis.reply_to_domain}' differs from "
                f"From domain '{analysis.from_domain}'"
            )

    # ── Subject / meta ────────────────────────────────────────────────────
    analysis.subject = _clean_header(msg.get("Subject", ""))
    analysis.date = _clean_header(msg.get("Date", ""))
    analysis.message_id = _clean_header(msg.get("Message-ID", ""))
    analysis.x_mailer = _clean_header(msg.get("X-Mailer", ""))
    analysis.x_originating_ip = _extract_ip_from_header(
        msg.get("X-Originating-IP", "") or msg.get("X-Sender-IP", "")
    )

    # ── Raw headers dict ─────────────────────────────────────────────────
    analysis.raw_headers = _collect_headers(msg)

    # ── Received chain ────────────────────────────────────────────────────
    received_headers = msg.get_all("Received") or []
    analysis.received_hops = len(received_headers)
    analysis.routing = _parse_received_chain(received_headers)
    analysis.originating_ip = _find_originating_ip(analysis.routing)
    if analysis.routing:
        analysis.originating_host = analysis.routing[-1].from_host

    # Anomaly: unusually long chain
    if analysis.received_hops > 8:
        analysis.anomalies.append(
            f"Unusually long Received chain: {analysis.received_hops} hops (>8 is suspicious)"
        )

    # ── Authentication-Results (from topmost MTA only) ────────────────────
    auth_results_headers = msg.get_all("Authentication-Results") or []
    if auth_results_headers:
        # Topmost = first in list = added by the final receiving server
        analysis.authentication_results_raw = auth_results_headers[0]
        _parse_auth_results(auth_results_headers[0], analysis)
    else:
        log.debug("No Authentication-Results header found")

    # ── Independent SPF check ─────────────────────────────────────────────
    if analysis.spf == AuthResult.UNKNOWN and analysis.originating_ip and analysis.from_domain:
        analysis.spf, analysis.spf_details = _check_spf(
            analysis.originating_ip, analysis.from_addr or "", analysis.from_domain
        )

    # ── Independent DKIM check ───────────────────────────────────────────
    if analysis.dkim == AuthResult.UNKNOWN:
        analysis.dkim, analysis.dkim_details = _check_dkim(raw)

    # ── DMARC policy lookup ───────────────────────────────────────────────
    if analysis.from_domain:
        analysis.dmarc, analysis.dmarc_details, analysis.dmarc_policy = _check_dmarc(
            analysis.from_domain, analysis.spf, analysis.dkim, analysis.spf_details
        )

    # ── Homograph detection ───────────────────────────────────────────────
    if analysis.from_domain:
        if _is_homograph(analysis.from_domain):
            analysis.is_homograph = True
            analysis.homograph_domain = analysis.from_domain
            analysis.anomalies.append(
                f"Homograph domain detected: '{analysis.from_domain}' contains mixed Unicode scripts"
            )

    # ── Additional anomaly checks ─────────────────────────────────────────
    _check_routing_anomalies(analysis)

    # ── MIME parts extraction ─────────────────────────────────────────────
    mime_parts = _extract_mime_parts(msg)

    log.info(
        "Parsed email: from=%s spf=%s dkim=%s dmarc=%s hops=%d iocs_surfaces=%d",
        analysis.from_addr, analysis.spf.value, analysis.dkim.value,
        analysis.dmarc.value, analysis.received_hops, len(mime_parts),
    )

    return analysis, mime_parts


# =============================================================================
# MSG parsing
# =============================================================================

def _parse_msg(path: Path) -> tuple[HeaderAnalysis, list[dict]]:
    """
    Parse an Outlook .msg file (OLE Compound format).
    Requires: extract-msg library.
    NEVER use msgconvert — it introduces header artifacts.
    """
    try:
        import extract_msg  # type: ignore
    except ImportError:
        raise ImportError(
            "extract-msg is required for .msg parsing: pip install extract-msg"
        )

    msg = extract_msg.openMsg(str(path))

    analysis = HeaderAnalysis()
    mime_parts: list[dict] = []

    try:
        # Sender info
        analysis.from_addr = msg.sender or ""
        _, analysis.from_domain = _parse_address(analysis.from_addr)

        reply_to = getattr(msg, "replyTo", None) or ""
        if reply_to:
            analysis.reply_to = reply_to
            _, analysis.reply_to_domain = _parse_address(reply_to)
            if (
                analysis.from_domain
                and analysis.reply_to_domain
                and analysis.from_domain.lower() != analysis.reply_to_domain.lower()
            ):
                analysis.reply_to_mismatch = True
                analysis.anomalies.append(
                    f"Reply-To domain '{analysis.reply_to_domain}' differs from "
                    f"From domain '{analysis.from_domain}'"
                )

        analysis.subject = msg.subject or ""
        analysis.date = str(msg.date) if msg.date else ""
        analysis.message_id = getattr(msg, "messageId", "") or ""

        # Extract transport headers if present
        transport_headers = getattr(msg, "header", None) or ""
        if transport_headers:
            # Parse the transport headers block like an EML fragment
            fake_eml = f"Subject: x\r\n{transport_headers}\r\n\r\n".encode()
            parser = BytesParser(policy=email_policy.compat32)
            fake_msg = parser.parsebytes(fake_eml)

            received_headers = fake_msg.get_all("Received") or []
            analysis.received_hops = len(received_headers)
            analysis.routing = _parse_received_chain(received_headers)
            analysis.originating_ip = _find_originating_ip(analysis.routing)

            auth_results = fake_msg.get_all("Authentication-Results") or []
            if auth_results:
                analysis.authentication_results_raw = auth_results[0]
                _parse_auth_results(auth_results[0], analysis)

        # Body
        if msg.body:
            mime_parts.append({
                "filename": None,
                "content_type": "text/plain",
                "payload": msg.body.encode("utf-8", errors="replace"),
                "is_attachment": False,
            })
        if msg.htmlBody:
            html_body = msg.htmlBody
            if isinstance(html_body, bytes):
                html_body = html_body.decode("utf-8", errors="replace")
            mime_parts.append({
                "filename": None,
                "content_type": "text/html",
                "payload": html_body.encode("utf-8", errors="replace"),
                "is_attachment": False,
            })

        # Attachments
        for att in msg.attachments:
            try:
                data = att.data
                if data:
                    mime_parts.append({
                        "filename": att.longFilename or att.shortFilename or "attachment",
                        "content_type": "application/octet-stream",
                        "payload": data,
                        "is_attachment": True,
                    })
            except Exception as e:
                log.warning("Failed to extract .msg attachment: %s", e)

        # Homograph check
        if analysis.from_domain and _is_homograph(analysis.from_domain):
            analysis.is_homograph = True
            analysis.homograph_domain = analysis.from_domain
            analysis.anomalies.append(
                f"Homograph domain detected: '{analysis.from_domain}'"
            )

    finally:
        msg.close()

    return analysis, mime_parts


# =============================================================================
# Authentication helpers
# =============================================================================

def _parse_auth_results(header_value: str, analysis: HeaderAnalysis) -> None:
    """
    Parse an Authentication-Results header into the HeaderAnalysis model.
    This header is added by the receiving MTA and is the ground truth.
    Format: spf=pass; dkim=fail; dmarc=pass policy=quarantine
    """
    if not header_value:
        return

    for match in _AUTH_RESULT_RE.finditer(header_value):
        protocol = match.group(1).lower()
        result = match.group(2).lower()

        if protocol == "spf":
            analysis.spf = _str_to_auth_result(result)
            # Extract reason / envelope-from
            reason_match = re.search(
                r'spf=\S+\s+\(([^)]+)\)', header_value, re.IGNORECASE
            )
            if reason_match:
                analysis.spf_details = reason_match.group(1).strip()

        elif protocol == "dkim":
            analysis.dkim = _str_to_auth_result(result)
            selector_match = re.search(
                r"header\.s=(\S+)", header_value, re.IGNORECASE
            )
            if selector_match:
                analysis.dkim_details = f"selector={selector_match.group(1)}"

        elif protocol == "dmarc":
            analysis.dmarc = _str_to_auth_result(result)
            policy_match = re.search(
                r"policy(?:\.applied)?=(\S+)", header_value, re.IGNORECASE
            )
            if policy_match:
                analysis.dmarc_policy = policy_match.group(1).rstrip(";")


def _check_spf(ip: str, sender: str, domain: str) -> tuple[AuthResult, Optional[str]]:
    """
    Perform an independent SPF lookup.
    Returns (result, explanation).
    Requires: pyspf (import spf)
    """
    try:
        import spf  # type: ignore

        result, code, explanation = spf.check2(
            i=ip,
            s=sender,
            h=domain,
        )
        log.debug("SPF check: ip=%s sender=%s result=%s", ip, sender, result)
        return _str_to_auth_result(result.lower()), explanation

    except ImportError:
        log.warning("pyspf not installed — SPF validation skipped")
        return AuthResult.UNKNOWN, "pyspf not installed"
    except Exception as e:
        log.warning("SPF check failed: %s", e)
        return AuthResult.UNKNOWN, str(e)


def _check_dkim(raw_email: bytes) -> tuple[AuthResult, Optional[str]]:
    """
    Perform an independent DKIM signature verification.
    Returns (result, details).
    Requires: dkimpy
    """
    try:
        from dkim import DKIM  # type: ignore

        d = DKIM(raw_email, logger=logging.getLogger("dkim"))
        result = d.verify()
        if result:
            return AuthResult.PASS, "DKIM signature verified"
        else:
            return AuthResult.FAIL, "DKIM signature verification failed"

    except ImportError:
        log.warning("dkimpy not installed — DKIM validation skipped")
        return AuthResult.UNKNOWN, "dkimpy not installed"
    except Exception as e:
        log.debug("DKIM check error (may be expected for non-DKIM emails): %s", e)
        return AuthResult.NONE, str(e)


def _check_dmarc(
    domain: str,
    spf: AuthResult,
    dkim: AuthResult,
    spf_details: Optional[str],
) -> tuple[AuthResult, Optional[str], Optional[str]]:
    """
    Evaluate DMARC for a domain.
    Uses checkdmarc to get the policy, then applies alignment logic.
    Returns (result, details, policy).
    """
    try:
        import checkdmarc  # type: ignore

        results = checkdmarc.check_domains([domain], skip_tls=True)
        if not results:
            return AuthResult.NONE, f"No DMARC record for {domain}", None

        dmarc_data = results[0].get("dmarc", {})
        if dmarc_data.get("error"):
            return AuthResult.NONE, dmarc_data["error"], None

        policy = dmarc_data.get("tags", {}).get("p", {}).get("value", "none")
        record = dmarc_data.get("record", "")

        # Simple alignment check: if either SPF or DKIM passes, DMARC passes
        if spf in (AuthResult.PASS,) or dkim == AuthResult.PASS:
            return AuthResult.PASS, f"record={record}", policy
        else:
            return AuthResult.FAIL, f"policy={policy} neither SPF nor DKIM passed", policy

    except ImportError:
        log.warning("checkdmarc not installed — DMARC validation skipped")
        return AuthResult.UNKNOWN, "checkdmarc not installed", None
    except Exception as e:
        log.debug("DMARC check error: %s", e)
        return AuthResult.UNKNOWN, str(e), None


# =============================================================================
# Received chain parsing
# =============================================================================

def _parse_received_chain(received_headers: list[str]) -> list[RoutingHop]:
    """
    Walk the Received headers bottom-to-top (list index reversed).
    Bottom = first hop from sender (last in list).
    Top = final delivery to mailbox (first in list).
    """
    hops = []
    for i, raw in enumerate(received_headers):
        hop = RoutingHop(index=i, raw=raw[:200])

        match = _RECEIVED_RE.search(raw)
        if match:
            hop.from_host = match.group("from_host")
            paren = match.group("paren_content") or ""
            # IPs in Received headers are in brackets: [1.2.3.4]
            ip_match = _IP_RE.search(paren) or _IP_RE.search(raw)
            if ip_match:
                hop.from_ip = ip_match.group(1)
            hop.by_host = match.group("by_host")

        with_match = _WITH_RE.search(raw)
        if with_match:
            hop.with_protocol = with_match.group(1)

        # Try to extract timestamp
        # Received headers typically end with: ; Day, DD Mon YYYY HH:MM:SS +ZZZZ
        ts_match = re.search(r";\s+(.{20,40})$", raw.strip())
        if ts_match:
            hop.timestamp = ts_match.group(1).strip()

        hops.append(hop)

    return hops


def _find_originating_ip(routing: list[RoutingHop]) -> Optional[str]:
    """
    Find the true originating IP from the Received chain.
    The originating IP is in the LAST hop (first contact with controlled infrastructure).
    Skip private/loopback IPs — they're internal relays.
    """
    # Iterate from last hop (closest to sender) backwards
    for hop in reversed(routing):
        if hop.from_ip and not _is_private_ip(hop.from_ip):
            return hop.from_ip
    # If all IPs are private (internal relay chain), return the last one anyway
    for hop in reversed(routing):
        if hop.from_ip:
            return hop.from_ip
    return None


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is RFC 1918 private, loopback, or link-local."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


# =============================================================================
# Anomaly detection
# =============================================================================

def _check_routing_anomalies(analysis: HeaderAnalysis) -> None:
    """Add anomaly flags based on routing analysis."""

    # Check for Tor exit node usage (common heuristic: relay with no rDNS)
    for hop in analysis.routing:
        if hop.from_ip and not hop.from_host:
            analysis.anomalies.append(
                f"Relay IP {hop.from_ip} has no reverse DNS — may be residential or Tor"
            )
            break

    # Check for unauthenticated SMTP relays
    for hop in analysis.routing:
        if hop.with_protocol and "SMTP" in hop.with_protocol.upper():
            if "ESMTPA" not in hop.with_protocol.upper() and "ESMTPS" not in hop.with_protocol.upper():
                analysis.anomalies.append(
                    f"Unauthenticated relay: hop {hop.index} used {hop.with_protocol} (no AUTH)"
                )
                break

    # SPF softfail — note but don't flag as hard failure
    if analysis.spf == AuthResult.SOFTFAIL:
        analysis.anomalies.append(
            "SPF softfail (~all): domain's SPF policy suggests IP is not authorised "
            "but doesn't hard-fail. Common in phishing infrastructure."
        )


def _is_homograph(domain: str) -> bool:
    """
    Detect Unicode homograph attacks by checking for mixed scripts.
    Legitimate domains use a single script. Attackers mix Cyrillic/Greek/etc
    with Latin to create visually identical lookalike domains.

    E.g.: pаypal.com (Cyrillic 'а') vs paypal.com (Latin 'a')
    """
    # Handle IDN / punycode
    try:
        if domain.startswith("xn--"):
            domain = domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        pass

    scripts: set[str] = set()
    for char in domain.replace(".", "").replace("-", ""):
        if not char.isalpha():
            continue
        char_name = unicodedata.name(char, "UNKNOWN")
        if "LATIN" in char_name:
            scripts.add("LATIN")
        elif "CYRILLIC" in char_name:
            scripts.add("CYRILLIC")
        elif "GREEK" in char_name:
            scripts.add("GREEK")
        elif "ARMENIAN" in char_name:
            scripts.add("ARMENIAN")
        elif "GEORGIAN" in char_name:
            scripts.add("GEORGIAN")
        elif "CHEROKEE" in char_name:
            scripts.add("CHEROKEE")
        elif "ARABIC" in char_name:
            scripts.add("ARABIC")
        elif "HEBREW" in char_name:
            scripts.add("HEBREW")
        elif "THAI" in char_name:
            scripts.add("THAI")
        elif "DEVANAGARI" in char_name:
            scripts.add("DEVANAGARI")
        elif "CJK" in char_name:
            scripts.add("CJK")

    return len(scripts) > 1


# =============================================================================
# MIME part extraction
# =============================================================================

def _extract_mime_parts(msg: EmailMessage) -> list[dict]:
    """
    Walk the MIME tree and collect all parts for downstream processing.
    Returns a flat list of dicts.
    """
    parts = []

    if msg.is_multipart():
        for part in msg.walk():
            _collect_part(part, parts)
    else:
        _collect_part(msg, parts)

    return parts


def _collect_part(part, parts: list) -> None:
    """Collect a single MIME part into the parts list."""
    content_type = part.get_content_type()
    filename = part.get_filename()
    disposition = part.get_content_disposition()

    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None

    if payload is None:
        return

    parts.append({
        "filename": filename,
        "content_type": content_type,
        "payload": payload,
        "is_attachment": disposition == "attachment" or filename is not None,
        "charset": part.get_content_charset(),
    })


# =============================================================================
# Utility helpers
# =============================================================================

def _clean_header(value: str) -> str:
    """Normalize a header value — strip whitespace and folding."""
    if not value:
        return ""
    # Remove RFC 2822 header folding (CRLF + whitespace)
    value = re.sub(r"\r?\n\s+", " ", value)
    return value.strip()


def _parse_address(addr_str: str) -> tuple[Optional[str], Optional[str]]:
    """
    Parse 'Display Name <email@domain.com>' into (display_name, domain).
    Returns (None, None) on failure.
    """
    if not addr_str:
        return None, None

    # Try to extract email address from angle brackets
    bracket_match = re.search(r"<([^>]+)>", addr_str)
    if bracket_match:
        email = bracket_match.group(1).strip()
    else:
        email = addr_str.strip()

    # Extract display name
    display_match = re.match(r'^(.+?)\s*<', addr_str)
    display_name = display_match.group(1).strip().strip('"') if display_match else None

    # Extract domain
    if "@" in email:
        domain = email.split("@", 1)[1].lower().rstrip(">")
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            return display_name, f"{ext.domain}.{ext.suffix}"
        return display_name, domain

    return display_name, None


def _extract_ip_from_header(value: str) -> Optional[str]:
    """Extract first valid IP from a header value."""
    if not value:
        return None
    match = _IP_RE.search(value)
    return match.group(1) if match else None


def _str_to_auth_result(s: str) -> AuthResult:
    """Convert a string auth result to the AuthResult enum."""
    mapping = {
        "pass": AuthResult.PASS,
        "fail": AuthResult.FAIL,
        "softfail": AuthResult.SOFTFAIL,
        "neutral": AuthResult.NEUTRAL,
        "none": AuthResult.NONE,
        "permerror": AuthResult.PERMERROR,
        "temperror": AuthResult.TEMPERROR,
    }
    return mapping.get(s.lower(), AuthResult.UNKNOWN)


def _collect_headers(msg) -> dict[str, list[str]]:
    """Collect all headers as a dict[header_name, list[values]]."""
    headers: dict[str, list[str]] = {}
    for key, value in msg.items():
        key_lower = key.lower()
        if key_lower not in headers:
            headers[key_lower] = []
        headers[key_lower].append(_clean_header(value))
    return headers
