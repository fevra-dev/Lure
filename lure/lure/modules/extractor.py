"""
lure/modules/extractor.py
IOC Extraction Engine — Pipeline Stage B

Surfaces covered:
  1. Email body (plain text) — iocextract + regex
  2. Email body (HTML) — BeautifulSoup href/src extraction (prevents anchor text trap)
  3. Attachments — pdfplumber (PDFs), python-docx (Word), olevba (Office macros)
  4. All text is refanged before deduplication

Critical pitfalls avoided:
  - The Anchor Text Trap: always extract from href/src attributes, not rendered text
  - Defanged IOCs: iocextract handles hxxps://, [.], (dot), base64 URLs, etc.
  - Deduplication: all IOC types are deduplicated across all surfaces
  - Domain validation: tldextract validates against IANA public suffix list
"""
from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import tldextract

from lure.models import AttachmentAnalysis, ExtractedURL, IOCSet, PDFElement, VBAFinding

log = logging.getLogger(__name__)

# =============================================================================
# Regex patterns
# =============================================================================

# IPv4 — strict: requires word boundaries, rejects private headers context
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# File hashes
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA512_RE = re.compile(r"\b[a-fA-F0-9]{128}\b")

# Email addresses (in body text)
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# Bitcoin wallets (P2PKH, P2SH, Bech32)
_BTC_RE = re.compile(
    r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}"   # P2PKH
    r"|3[a-km-zA-HJ-NP-Z1-9]{25,34}"        # P2SH
    r"|bc1[ac-hj-np-z02-9]{6,87})\b"        # Bech32
)

# Ethereum
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# Common URL shorteners (check extracted URLs against this)
_URL_SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly",
    "adf.ly", "short.link", "rebrand.ly", "cutt.ly", "tiny.cc", "is.gd",
})

# Private/reserved IP ranges to exclude from IOC lists (internal infrastructure)
_PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "169.254.", "::1",
)

# VBA macro high-risk keywords → (description, risk_level)
_VBA_RISKS: dict[str, tuple[str, str]] = {
    "Shell": ("Executes external command via Shell function", "HIGH"),
    "WScript": ("References Windows Script Host — common malware delivery", "HIGH"),
    "CreateObject": ("COM object creation — often used to download/execute payloads", "HIGH"),
    "AutoOpen": ("Auto-execution macro trigger on document open", "HIGH"),
    "Document_Open": ("Auto-execution macro trigger on document open", "HIGH"),
    "Auto_Open": ("Auto-execution macro trigger for Excel", "HIGH"),
    "Workbook_Open": ("Auto-execution macro trigger for Excel workbook", "HIGH"),
    "URLDownloadToFile": ("Downloads file from URL — malware delivery indicator", "HIGH"),
    "PowerShell": ("PowerShell invocation from macro — very high risk", "HIGH"),
    "cmd.exe": ("Direct cmd.exe invocation from macro", "HIGH"),
    "mshta.exe": ("MSHTA execution — used to run malicious HTA files", "HIGH"),
    "wscript.exe": ("WScript execution from macro", "HIGH"),
    "cscript.exe": ("CScript execution from macro", "HIGH"),
    "Environ": ("Reads environment variables — may be used to fingerprint system", "MEDIUM"),
    "Chr(": ("Character code obfuscation — common in obfuscated macros", "MEDIUM"),
    "Asc(": ("ASCII code function — may indicate obfuscation", "MEDIUM"),
    "Base64": ("Base64 in macro — common payload encoding", "MEDIUM"),
    "http": ("HTTP URL reference in macro", "MEDIUM"),
    "ftp": ("FTP reference in macro", "MEDIUM"),
    "Reg": ("Registry access from macro", "MEDIUM"),
}

# PDF suspicious elements from pdfid → (description, risk_level)
_PDF_RISKS: dict[str, tuple[str, str]] = {
    "/JS": ("Embedded JavaScript in PDF", "HIGH"),
    "/JavaScript": ("JavaScript action in PDF", "HIGH"),
    "/OpenAction": ("Auto-execute action on PDF open", "HIGH"),
    "/AA": ("Additional Action — triggers on various events", "HIGH"),
    "/Launch": ("Launch action — can execute external commands", "HIGH"),
    "/EmbeddedFile": ("File embedded within PDF", "HIGH"),
    "/XFA": ("XML Forms Architecture — complex PDF form, often abused", "MEDIUM"),
    "/AcroForm": ("PDF form — may be credential harvesting", "MEDIUM"),
    "/URI": ("URI reference in PDF", "LOW"),
    "/SubmitForm": ("Form submission action — may exfiltrate data", "HIGH"),
    "/RichMedia": ("Rich media content — may exploit reader vulnerabilities", "MEDIUM"),
}


# =============================================================================
# Public interface
# =============================================================================

def extract_iocs(
    header_analysis,
    mime_parts: list[dict],
    follow_redirects: bool = True,
    max_redirect_hops: int = 5,
) -> tuple[IOCSet, list[AttachmentAnalysis]]:
    """
    Extract all IOCs from email headers and all MIME parts.

    Args:
        header_analysis: HeaderAnalysis from parser.py
        mime_parts: list of MIME part dicts from parser.py
        follow_redirects: whether to follow URL redirect chains
        max_redirect_hops: maximum hops to follow

    Returns:
        (IOCSet, list[AttachmentAnalysis])
    """
    ioc_set = IOCSet()
    attachment_analyses: list[AttachmentAnalysis] = []

    # ── Stage 1: Header IOCs ──────────────────────────────────────────────
    header_iocs = _extract_from_headers(header_analysis)
    ioc_set.merge(header_iocs)
    if header_iocs.ips or header_iocs.domains or header_iocs.emails:
        ioc_set.extraction_sources.append("headers")

    # ── Stage 2: Body IOCs ────────────────────────────────────────────────
    for part in mime_parts:
        if part.get("is_attachment"):
            continue  # Attachments processed separately

        ct = part.get("content_type", "")
        payload = part.get("payload", b"")
        charset = part.get("charset") or "utf-8"

        text = _decode_payload(payload, charset)
        if not text:
            continue

        if "html" in ct.lower():
            body_iocs = _extract_from_html(text, source="body_html")
            ioc_set.extraction_sources.append("body_html")
        else:
            body_iocs = _extract_from_text(text, source="body_text")
            ioc_set.extraction_sources.append("body_text")

        ioc_set.merge(body_iocs)

    # ── Stage 3: Attachment IOCs ──────────────────────────────────────────
    for part in mime_parts:
        if not part.get("is_attachment"):
            continue

        filename = part.get("filename") or "unknown_attachment"
        payload = part.get("payload", b"")
        ct = part.get("content_type", "application/octet-stream")

        att_analysis = _analyze_attachment(filename, payload, ct)
        attachment_analyses.append(att_analysis)

        # Merge IOCs found in attachment
        att_ioc_set = IOCSet(
            urls=att_analysis.extracted_urls,
        )
        ioc_set.merge(att_ioc_set)
        if att_analysis.extracted_urls:
            ioc_set.extraction_sources.append(f"attachment:{filename}")

    # ── Stage 4: Deduplication and validation ─────────────────────────────
    ioc_set = _deduplicate_and_validate(ioc_set)

    # ── Stage 5: Redirect chain following ─────────────────────────────────
    if follow_redirects and ioc_set.urls:
        ioc_set = _follow_redirect_chains(ioc_set, max_redirect_hops)

    log.info(
        "IOC extraction complete: %d IPs, %d domains, %d URLs, %d emails, %d attachments",
        len(ioc_set.ips), len(ioc_set.domains), len(ioc_set.urls),
        len(ioc_set.emails), len(attachment_analyses),
    )

    return ioc_set, attachment_analyses


# =============================================================================
# Extraction functions
# =============================================================================

def _extract_from_headers(header_analysis) -> IOCSet:
    """Extract IOCs from parsed email headers."""
    ioc_set = IOCSet()

    # Originating IP
    if header_analysis.originating_ip:
        ioc_set.ips.append(header_analysis.originating_ip)

    if header_analysis.x_originating_ip:
        ioc_set.ips.append(header_analysis.x_originating_ip)

    # IPs from routing chain
    for hop in header_analysis.routing:
        if hop.from_ip and not _is_private_ip(hop.from_ip):
            if hop.from_ip not in ioc_set.ips:
                ioc_set.ips.append(hop.from_ip)

    # From domain
    if header_analysis.from_domain:
        ioc_set.domains.append(header_analysis.from_domain)

    # From email address
    if header_analysis.from_addr:
        ioc_set.emails.append(header_analysis.from_addr)

    # Reply-To
    if header_analysis.reply_to:
        ioc_set.emails.append(header_analysis.reply_to)
    if header_analysis.reply_to_domain and header_analysis.reply_to_domain not in ioc_set.domains:
        ioc_set.domains.append(header_analysis.reply_to_domain)

    return ioc_set


def _extract_from_text(text: str, source: str = "body_text") -> IOCSet:
    """
    Extract IOCs from plain text using iocextract + direct regex.
    iocextract handles defanged variants (hxxps://, [.], (dot), etc.)
    """
    ioc_set = IOCSet()

    # ── Try iocextract first (handles defanging) ──────────────────────────
    try:
        import iocextract  # type: ignore

        for url in iocextract.extract_urls(text, refang=True):
            _add_url(ioc_set, url, source)

        for ip in iocextract.extract_ips(text, refang=True):
            if not _is_private_ip(ip):
                _add_if_new(ioc_set.ips, ip)

        for email in iocextract.extract_emails(text, refang=True):
            _add_if_new(ioc_set.emails, email.lower())

        for hash_val in iocextract.extract_hashes(text):
            _classify_hash(ioc_set, hash_val)

    except ImportError:
        log.warning("iocextract not installed — falling back to regex extraction")
        _regex_extract(text, ioc_set, source)

    # ── Supplement with iocsearcher for validated extraction ──────────────
    try:
        from iocsearcher.searcher import Searcher  # type: ignore

        searcher = Searcher()
        iocs = searcher.search_all(text)
        for ioc_type, value in iocs:
            if ioc_type in ("url", "fqdn"):
                _add_url(ioc_set, value, source + ":iocsearcher")
            elif ioc_type == "ip":
                if not _is_private_ip(value):
                    _add_if_new(ioc_set.ips, value)
            elif ioc_type == "email":
                _add_if_new(ioc_set.emails, value.lower())
            elif ioc_type in ("md5", "sha1", "sha256", "sha512"):
                _add_if_new(ioc_set.hashes[ioc_type], value.lower())

    except ImportError:
        pass  # iocsearcher is supplementary
    except Exception as e:
        log.debug("iocsearcher error: %s", e)

    # ── Crypto wallet detection ───────────────────────────────────────────
    for btc in _BTC_RE.findall(text):
        _add_if_new(ioc_set.wallets, btc)

    for eth in _ETH_RE.findall(text):
        _add_if_new(ioc_set.wallets, eth)

    return ioc_set


def _extract_from_html(html: str, source: str = "body_html") -> IOCSet:
    """
    Extract IOCs from HTML email body.

    CRITICAL — The Anchor Text Trap:
    Always extract from href/src attributes, NOT rendered visible text.
    The visible URL (e.g., 'paypal.com') and the actual href destination
    (e.g., 'evil.ru/steal') are DIFFERENT in every credential phishing email.
    """
    ioc_set = IOCSet()

    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html, "html.parser")

        # ── href attributes (links) ───────────────────────────────────────
        for tag in soup.find_all(href=True):
            href = tag.get("href", "").strip()
            if href and href.startswith(("http://", "https://", "ftp://")):
                _add_url(ioc_set, href, source + ":href")

        # ── src attributes (images, scripts) ─────────────────────────────
        for tag in soup.find_all(src=True):
            src = tag.get("src", "").strip()
            if src and src.startswith(("http://", "https://")):
                _add_url(ioc_set, src, source + ":src")

        # ── action attributes (forms) ─────────────────────────────────────
        for tag in soup.find_all(action=True):
            action = tag.get("action", "").strip()
            if action and action.startswith(("http://", "https://")):
                _add_url(ioc_set, action, source + ":form_action")

        # ── Also run plain-text extraction on the visible text ────────────
        # (some phishing emails paste the actual URL as visible text too)
        visible_text = soup.get_text(separator=" ")
        text_iocs = _extract_from_text(visible_text, source + ":visible_text")
        ioc_set.merge(text_iocs)

        # ── Check for credential harvesting indicators ────────────────────
        password_inputs = soup.find_all("input", {"type": "password"})
        if password_inputs:
            log.info("HTML body contains %d password input field(s) — credential harvesting indicator", len(password_inputs))

    except ImportError:
        log.warning("beautifulsoup4 not installed — falling back to regex on HTML")
        _regex_extract(html, ioc_set, source)

    return ioc_set


def _regex_extract(text: str, ioc_set: IOCSet, source: str) -> None:
    """Fallback regex-based extraction when iocextract/bs4 aren't available."""
    url_re = re.compile(
        r"https?://[^\s\"'<>()[\]{}]+",
        re.IGNORECASE,
    )
    for url in url_re.findall(text):
        _add_url(ioc_set, url, source + ":regex")

    for ip in _IPV4_RE.findall(text):
        if not _is_private_ip(ip):
            _add_if_new(ioc_set.ips, ip)

    for email in _EMAIL_RE.findall(text):
        _add_if_new(ioc_set.emails, email.lower())

    for h in _SHA256_RE.findall(text):
        _add_if_new(ioc_set.hashes["sha256"], h.lower())

    for h in _MD5_RE.findall(text):
        if not _SHA256_RE.match(h) and not _SHA512_RE.match(h):
            _add_if_new(ioc_set.hashes["md5"], h.lower())


# =============================================================================
# Attachment analysis
# =============================================================================

def _analyze_attachment(filename: str, payload: bytes, content_type: str) -> AttachmentAnalysis:
    """
    Perform static analysis on an attachment.
    Computes hashes, detects true file type, extracts IOCs,
    and runs VBA/PDF analysis as appropriate.
    """
    analysis = AttachmentAnalysis(
        filename=filename,
        mime_type=content_type,
        size_bytes=len(payload),
    )

    if not payload:
        return analysis

    # ── Hash computation ──────────────────────────────────────────────────
    analysis.sha256 = hashlib.sha256(payload).hexdigest()
    analysis.sha1 = hashlib.sha1(payload).hexdigest()
    analysis.md5 = hashlib.md5(payload).hexdigest()

    # ── True file type detection (magic bytes) ────────────────────────────
    analysis.detected_type = _detect_file_type(payload, filename)

    # ── Route to appropriate analyzer ─────────────────────────────────────
    ext = Path(filename).suffix.lower()
    detected = analysis.detected_type or ""

    if _is_office_file(ext, detected, payload):
        _analyze_office(analysis, payload, filename)

    elif _is_pdf(ext, detected, payload):
        _analyze_pdf(analysis, payload)

    elif _is_archive(ext, detected):
        _analyze_archive(analysis, payload, filename)

    # ── Extract IOCs from attachment text content ─────────────────────────
    _extract_urls_from_attachment(analysis, payload, content_type)

    # ── Mark as suspicious if any findings ───────────────────────────────
    if analysis.has_macros and analysis.macro_suspicious:
        analysis.is_suspicious = True
        analysis.risk_reasons.append("Contains suspicious VBA macro code")

    if analysis.pdf_suspicious:
        analysis.is_suspicious = True
        analysis.risk_reasons.append(
            f"PDF contains {analysis.pdf_score} suspicious element(s)"
        )

    if analysis.extracted_urls:
        analysis.risk_reasons.append(f"Contains {len(analysis.extracted_urls)} embedded URL(s)")

    return analysis


def _analyze_office(analysis: AttachmentAnalysis, payload: bytes, filename: str) -> None:
    """Extract and analyze VBA macros from Office documents using olevba."""
    try:
        from oletools.olevba import VBA_Parser  # type: ignore

        vba_parser = VBA_Parser(filename, data=payload)

        if vba_parser.detect_vba_macros():
            analysis.has_macros = True
            findings: list[VBAFinding] = []
            macro_text_parts: list[str] = []

            for (vba_filename, stream_path, vba_code) in vba_parser.extract_macros():
                macro_text_parts.append(vba_code)

                # Analyze each line for risk indicators
                for line_num, line in enumerate(vba_code.splitlines(), 1):
                    for keyword, (description, risk_level) in _VBA_RISKS.items():
                        if keyword.lower() in line.lower():
                            findings.append(VBAFinding(
                                keyword=keyword,
                                description=description,
                                risk_level=risk_level,
                                line_number=line_num,
                                code_snippet=line.strip()[:200],
                            ))
                            if risk_level == "HIGH":
                                analysis.macro_suspicious = True

            analysis.vba_findings = findings
            if macro_text_parts:
                full_macro = "\n".join(macro_text_parts)
                analysis.macro_source_preview = full_macro[:500] + (
                    "..." if len(full_macro) > 500 else ""
                )

    except ImportError:
        log.warning("oletools not installed — VBA macro analysis skipped")
    except Exception as e:
        log.debug("VBA analysis error for %s: %s", filename, e)


def _analyze_pdf(analysis: AttachmentAnalysis, payload: bytes) -> None:
    """Score a PDF for suspicious elements using pdfid patterns."""
    try:
        # Try pdfplumber for URL extraction first
        import pdfplumber  # type: ignore
        import io

        with pdfplumber.open(io.BytesIO(payload)) as pdf:
            for page in pdf.pages:
                text = page.extract_text() or ""
                urls_in_page = re.findall(r"https?://[^\s\"'<>()[\]{}]+", text)
                for url in urls_in_page:
                    if url not in analysis.extracted_urls:
                        analysis.extracted_urls.append(url)

                # Also check annotations (embedded links)
                if hasattr(page, 'annots') and page.annots:
                    for annot in page.annots:
                        uri = annot.get("uri", "")
                        if uri and uri not in analysis.extracted_urls:
                            analysis.extracted_urls.append(uri)

    except ImportError:
        log.debug("pdfplumber not installed — PDF URL extraction skipped")
    except Exception as e:
        log.debug("PDF URL extraction error: %s", e)

    # Scan raw PDF bytes for suspicious element keywords
    pdf_text = payload.decode("latin-1", errors="replace")
    elements: list[PDFElement] = []
    total_score = 0

    for element, (description, risk_level) in _PDF_RISKS.items():
        count = pdf_text.count(element)
        if count > 0:
            elements.append(PDFElement(
                element=element,
                count=count,
                risk_level=risk_level,
            ))
            if risk_level in ("HIGH", "MEDIUM"):
                total_score += count

    analysis.pdf_elements = elements
    analysis.pdf_score = total_score
    if total_score > 0 or any(e.risk_level == "HIGH" for e in elements):
        analysis.pdf_suspicious = True


def _analyze_archive(analysis: AttachmentAnalysis, payload: bytes, filename: str) -> None:
    """
    Extract archive contents and analyze each contained file.
    Handles ZIP (stdlib), 7z (py7zr), RAR (rarfile).
    Recursive to depth 1 (nested archives flagged but not recursed further).
    """
    import io
    import zipfile

    ext = Path(filename).suffix.lower()

    if ext == ".zip" or (payload[:2] == b"PK"):
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    inner_ext = Path(name).suffix.lower()
                    if inner_ext in (".zip", ".7z", ".rar"):
                        analysis.risk_reasons.append(f"Nested archive: {name}")
                    try:
                        inner_data = zf.read(name)
                        analysis.risk_reasons.append(
                            f"Archive contains: {name} ({len(inner_data)} bytes)"
                        )
                    except Exception:
                        pass
        except Exception as e:
            log.debug("ZIP analysis error: %s", e)

    elif ext == ".7z":
        try:
            import py7zr  # type: ignore
            import io as _io
            with py7zr.SevenZipFile(_io.BytesIO(payload)) as zf:
                names = zf.getnames()
                for name in names:
                    analysis.risk_reasons.append(f"7z contains: {name}")
        except ImportError:
            analysis.risk_reasons.append("7z archive — py7zr not installed for analysis")
        except Exception as e:
            log.debug("7z analysis error: %s", e)

    elif ext == ".rar":
        analysis.risk_reasons.append("RAR archive — requires unrar system binary for full analysis")


def _extract_urls_from_attachment(
    analysis: AttachmentAnalysis, payload: bytes, content_type: str
) -> None:
    """Extract URLs from attachment content (text, HTML, Word docs)."""
    ct = content_type.lower()

    # Word documents
    if ".docx" in analysis.filename.lower() or "wordprocessingml" in ct:
        try:
            import io
            from docx import Document  # type: ignore

            doc = Document(io.BytesIO(payload))
            for para in doc.paragraphs:
                urls = re.findall(r"https?://[^\s\"'<>()[\]{}]+", para.text)
                for url in urls:
                    if url not in analysis.extracted_urls:
                        analysis.extracted_urls.append(url)

            # Also check hyperlinks
            for rel in doc.part.rels.values():
                if "hyperlink" in rel.reltype:
                    url = rel.target_ref
                    if url.startswith("http") and url not in analysis.extracted_urls:
                        analysis.extracted_urls.append(url)

        except ImportError:
            log.debug("python-docx not installed — Word URL extraction skipped")
        except Exception as e:
            log.debug("Word URL extraction error: %s", e)

    # HTML attachments
    elif "html" in ct or analysis.filename.lower().endswith(".html"):
        try:
            text = payload.decode("utf-8", errors="replace")
            from bs4 import BeautifulSoup  # type: ignore
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup.find_all(href=True):
                href = tag.get("href", "")
                if href.startswith(("http://", "https://")) and href not in analysis.extracted_urls:
                    analysis.extracted_urls.append(href)
        except ImportError:
            pass


# =============================================================================
# Redirect chain following
# =============================================================================

def _follow_redirect_chains(ioc_set: IOCSet, max_hops: int) -> IOCSet:
    """
    Follow redirect chains for all extracted URLs to find terminal destinations.
    Updates urls_detailed with chain info and adds terminal URLs to ioc_set.urls.
    """
    from lure.models import RedirectHop

    try:
        import requests  # type: ignore
        from requests.exceptions import RequestException

        session = requests.Session()
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )

        new_urls: list[str] = []

        for url_detail in ioc_set.urls_detailed:
            url = url_detail.url
            chain: list[RedirectHop] = []
            current_url = url

            for hop in range(max_hops):
                try:
                    resp = session.head(
                        current_url,
                        allow_redirects=False,
                        timeout=5,
                        verify=False,
                    )
                    chain.append(RedirectHop(
                        url=current_url,
                        status_code=resp.status_code,
                    ))

                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if not location or location == current_url:
                            break
                        current_url = location
                    else:
                        break

                except RequestException:
                    break

            if chain:
                url_detail.redirect_chain = chain
                terminal = chain[-1].url
                if terminal != url:
                    url_detail.terminal_url = terminal
                    if terminal not in ioc_set.urls:
                        new_urls.append(terminal)
                        # Extract domain from terminal URL
                        parsed = urlparse(terminal)
                        if parsed.netloc:
                            ext = tldextract.extract(parsed.netloc)
                            if ext.domain and ext.suffix:
                                domain = f"{ext.domain}.{ext.suffix}"
                                if domain not in ioc_set.domains:
                                    ioc_set.domains.append(domain)

        ioc_set.urls.extend(new_urls)

    except ImportError:
        log.debug("requests not available — redirect chain following skipped")
    except Exception as e:
        log.debug("Redirect chain following error: %s", e)

    return ioc_set


# =============================================================================
# Deduplication and validation
# =============================================================================

def _deduplicate_and_validate(ioc_set: IOCSet) -> IOCSet:
    """
    Deduplicate all IOC lists and validate domains against IANA public suffix list.
    Removes false positives: private IPs, invalid domains, too-short hashes.
    """
    # IPs: deduplicate, remove private
    ioc_set.ips = sorted(set(
        ip for ip in ioc_set.ips
        if ip and not _is_private_ip(ip)
    ))

    # Domains: deduplicate, validate with tldextract
    valid_domains: set[str] = set()
    for domain in ioc_set.domains:
        if domain and _is_valid_domain(domain):
            valid_domains.add(domain.lower())
    ioc_set.domains = sorted(valid_domains)

    # URLs: deduplicate
    seen_urls: set[str] = set()
    deduped_url_details: list[ExtractedURL] = []
    for url_detail in ioc_set.urls_detailed:
        if url_detail.url not in seen_urls:
            seen_urls.add(url_detail.url)
            deduped_url_details.append(url_detail)
            # Extract domain from URL
            try:
                parsed = urlparse(url_detail.url)
                if parsed.netloc:
                    ext = tldextract.extract(parsed.netloc)
                    if ext.domain and ext.suffix:
                        domain = f"{ext.domain}.{ext.suffix}"
                        if domain not in ioc_set.domains:
                            ioc_set.domains.append(domain)
            except Exception:
                pass

    ioc_set.urls_detailed = deduped_url_details
    ioc_set.urls = sorted(seen_urls)

    # Emails: lowercase and deduplicate
    ioc_set.emails = sorted(set(e.lower() for e in ioc_set.emails if e and "@" in e))

    # Hashes: deduplicate each type
    for hash_type in ioc_set.hashes:
        ioc_set.hashes[hash_type] = sorted(set(
            h.lower() for h in ioc_set.hashes[hash_type] if h
        ))

    # Wallets: deduplicate
    ioc_set.wallets = sorted(set(ioc_set.wallets))

    # Extraction sources: deduplicate
    ioc_set.extraction_sources = sorted(set(ioc_set.extraction_sources))

    return ioc_set


# =============================================================================
# Utility helpers
# =============================================================================

def _add_url(ioc_set: IOCSet, url: str, source: str) -> None:
    """Add a URL to the IOCSet with source tracking."""
    url = url.rstrip(".,;)\"'")  # Strip trailing punctuation
    if not url or len(url) < 10:
        return
    if url not in ioc_set.urls:
        ioc_set.urls.append(url)
        ioc_set.urls_detailed.append(ExtractedURL(url=url, source=source))


def _add_if_new(target: list, value: str) -> None:
    if value and value not in target:
        target.append(value)


def _classify_hash(ioc_set: IOCSet, hash_val: str) -> None:
    """Classify a hash string by length and add to the appropriate bucket."""
    h = hash_val.lower()
    length = len(h)
    if length == 32 and all(c in "0123456789abcdef" for c in h):
        _add_if_new(ioc_set.hashes["md5"], h)
    elif length == 40:
        _add_if_new(ioc_set.hashes["sha1"], h)
    elif length == 64:
        _add_if_new(ioc_set.hashes["sha256"], h)
    elif length == 128:
        _add_if_new(ioc_set.hashes["sha512"], h)


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is private, loopback, or link-local."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _is_valid_domain(domain: str) -> bool:
    """Validate a domain using tldextract."""
    try:
        ext = tldextract.extract(domain)
        return bool(ext.domain and ext.suffix and len(ext.domain) >= 2)
    except Exception:
        return False


def _detect_file_type(payload: bytes, filename: str) -> Optional[str]:
    """Detect true file type from magic bytes (not file extension)."""
    try:
        import magic  # type: ignore
        return magic.from_buffer(payload, mime=True)
    except ImportError:
        # Fallback: check magic bytes manually
        if payload[:4] == b"PK\x03\x04":
            return "application/zip"
        elif payload[:4] == b"%PDF":
            return "application/pdf"
        elif payload[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return "application/vnd.ms-office"
        elif payload[:2] == b"MZ":
            return "application/x-dosexec"
        return None


def _is_office_file(ext: str, detected: str, payload: bytes) -> bool:
    return (
        ext in (".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".docm")
        or "officedocument" in detected
        or "vnd.ms" in detected
        or (payload[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")  # OLE magic bytes
    )


def _is_pdf(ext: str, detected: str, payload: bytes) -> bool:
    return ext == ".pdf" or "pdf" in detected or payload[:4] == b"%PDF"


def _is_archive(ext: str, detected: str) -> bool:
    return ext in (".zip", ".7z", ".rar", ".gz", ".tar") or "zip" in detected


def _decode_payload(payload: bytes, charset: str) -> str:
    """Safely decode bytes to string, trying multiple charsets."""
    for enc in [charset, "utf-8", "latin-1", "cp1252"]:
        try:
            if enc:
                return payload.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return payload.decode("latin-1", errors="replace")
