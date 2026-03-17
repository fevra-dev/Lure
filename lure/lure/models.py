"""
lure/models.py
All Pydantic v2 data models for the Lure pipeline.
Every inter-module data transfer uses these typed models.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, model_validator


# =============================================================================
# Enums
# =============================================================================

class FileType(str, Enum):
    EML = "eml"
    MSG = "msg"
    UNKNOWN = "unknown"


class AuthResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    UNKNOWN = "unknown"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    LIKELY_PHISHING = "LIKELY_PHISHING"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"

    @property
    def color(self) -> str:
        return {
            Verdict.CLEAN: "green",
            Verdict.SUSPICIOUS: "yellow",
            Verdict.LIKELY_PHISHING: "orange",
            Verdict.CONFIRMED_MALICIOUS: "red",
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Verdict.CLEAN: "✅",
            Verdict.SUSPICIOUS: "⚠️",
            Verdict.LIKELY_PHISHING: "🎣",
            Verdict.CONFIRMED_MALICIOUS: "🚨",
        }[self]


# =============================================================================
# Input Models
# =============================================================================

class EmailFile(BaseModel):
    """Validated input model for an email file."""
    path: str
    file_type: FileType
    sha256: str
    size_bytes: int
    filename: str

    @classmethod
    def from_path(cls, path: str | Path) -> "EmailFile":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Email file not found: {path}")

        data = p.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()

        suffix = p.suffix.lower().lstrip(".")
        if suffix == "eml":
            file_type = FileType.EML
        elif suffix == "msg":
            file_type = FileType.MSG
        else:
            # Try to detect from content
            file_type = FileType.EML if b"Received:" in data[:500] else FileType.UNKNOWN

        return cls(
            path=str(p.resolve()),
            file_type=file_type,
            sha256=sha256,
            size_bytes=len(data),
            filename=p.name,
        )


# =============================================================================
# Header / Auth Models
# =============================================================================

class RoutingHop(BaseModel):
    """Represents one hop in the email Received chain."""
    index: int
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    timestamp: Optional[str] = None
    raw: Optional[str] = None


class HeaderAnalysis(BaseModel):
    """Complete header forensics output from parser.py."""

    # Sender info
    from_addr: Optional[str] = None
    from_display_name: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    reply_to_mismatch: bool = False

    # Subject / meta
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    x_mailer: Optional[str] = None
    x_originating_ip: Optional[str] = None

    # True origin (from Received chain)
    originating_ip: Optional[str] = None
    originating_host: Optional[str] = None

    # Auth results
    spf: AuthResult = AuthResult.UNKNOWN
    spf_details: Optional[str] = None
    dkim: AuthResult = AuthResult.UNKNOWN
    dkim_details: Optional[str] = None
    dmarc: AuthResult = AuthResult.UNKNOWN
    dmarc_details: Optional[str] = None
    dmarc_policy: Optional[str] = None  # none / quarantine / reject

    # Auth result header (as added by receiving MTA)
    authentication_results_raw: Optional[str] = None

    # Routing
    received_hops: int = 0
    routing: list[RoutingHop] = Field(default_factory=list)

    # Anomaly flags
    anomalies: list[str] = Field(default_factory=list)
    is_homograph: bool = False
    homograph_domain: Optional[str] = None

    # Raw headers for reference
    raw_headers: dict[str, list[str]] = Field(default_factory=dict)


# =============================================================================
# IOC Models
# =============================================================================

class RedirectHop(BaseModel):
    """One hop in a URL redirect chain."""
    url: str
    status_code: Optional[int] = None


class ExtractedURL(BaseModel):
    """A URL with metadata about where it was found."""
    url: str
    source: str  # "body_html_href", "body_text", "attachment:filename.pdf", etc.
    defanged_original: Optional[str] = None
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    terminal_url: Optional[str] = None  # Final destination after redirects


class IOCSet(BaseModel):
    """
    Complete, deduplicated IOC set extracted from an email.
    All lists contain unique values only.
    """
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    urls_detailed: list[ExtractedURL] = Field(default_factory=list)
    hashes: dict[str, list[str]] = Field(
        default_factory=lambda: {"md5": [], "sha1": [], "sha256": [], "sha512": []}
    )
    emails: list[str] = Field(default_factory=list)
    wallets: list[str] = Field(default_factory=list)  # crypto wallet addresses

    # Metadata about extraction
    total_count: int = 0
    extraction_sources: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def compute_total(self) -> "IOCSet":
        self.total_count = (
            len(self.ips)
            + len(self.domains)
            + len(self.urls)
            + sum(len(v) for v in self.hashes.values())
            + len(self.emails)
            + len(self.wallets)
        )
        return self

    def merge(self, other: "IOCSet") -> "IOCSet":
        """Merge another IOCSet into this one, deduplicating."""
        self.ips = sorted(set(self.ips) | set(other.ips))
        self.domains = sorted(set(self.domains) | set(other.domains))
        self.urls = sorted(set(self.urls) | set(other.urls))
        self.emails = sorted(set(self.emails) | set(other.emails))
        self.wallets = sorted(set(self.wallets) | set(other.wallets))
        for hash_type in self.hashes:
            self.hashes[hash_type] = sorted(
                set(self.hashes[hash_type]) | set(other.hashes.get(hash_type, []))
            )
        # Merge detailed URLs (deduplicate by url value)
        existing_urls = {u.url for u in self.urls_detailed}
        for u in other.urls_detailed:
            if u.url not in existing_urls:
                self.urls_detailed.append(u)
                existing_urls.add(u.url)
        self.extraction_sources = sorted(
            set(self.extraction_sources) | set(other.extraction_sources)
        )
        return self


# =============================================================================
# Attachment Models
# =============================================================================

class VBAFinding(BaseModel):
    """Finding from VBA macro analysis via olevba."""
    keyword: str
    description: str
    risk_level: str  # "HIGH", "MEDIUM", "LOW"
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None


class PDFElement(BaseModel):
    """Suspicious element found in PDF by pdfid."""
    element: str  # /JS, /OpenAction, /Launch, etc.
    count: int
    risk_level: str


class AttachmentAnalysis(BaseModel):
    """Static analysis result for a single attachment."""
    filename: str
    mime_type: Optional[str] = None
    detected_type: Optional[str] = None  # From python-magic (may differ from MIME)
    size_bytes: int = 0
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None

    # Office document analysis
    has_macros: bool = False
    macro_suspicious: bool = False
    vba_findings: list[VBAFinding] = Field(default_factory=list)
    macro_source_preview: Optional[str] = None  # First 500 chars of macro code

    # PDF analysis
    pdf_suspicious: bool = False
    pdf_elements: list[PDFElement] = Field(default_factory=list)
    pdf_score: int = 0  # Sum of suspicious element counts

    # Extracted IOCs from this attachment
    extracted_urls: list[str] = Field(default_factory=list)

    # YARA matches (populated in Phase 2)
    yara_matches: list[str] = Field(default_factory=list)

    # Overall attachment risk
    is_suspicious: bool = False
    risk_reasons: list[str] = Field(default_factory=list)


# =============================================================================
# YARA Models (Phase 2 — stubs here)
# =============================================================================

class YARAMatch(BaseModel):
    """A single YARA rule match."""
    rule_name: str
    ruleset: str
    scan_target: str  # "header", "body", "attachment:filename"
    strings_matched: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    meta: dict = Field(default_factory=dict)


class YARAMatchSet(BaseModel):
    """All YARA matches across the email."""
    matches: list[YARAMatch] = Field(default_factory=list)
    total_matches: int = 0

    @model_validator(mode="after")
    def compute_total(self) -> "YARAMatchSet":
        self.total_matches = len(self.matches)
        return self


# =============================================================================
# Scoring Models (Phase 4 — stubs here)
# =============================================================================

class Signal(BaseModel):
    """A single fired risk signal with its weight contribution."""
    name: str
    weight: float
    trigger: str  # Human-readable description of what triggered it
    evidence: Optional[str] = None  # Specific evidence value


class RiskScore(BaseModel):
    """Output of the scoring engine."""
    total_score: float = 0.0
    verdict: Verdict = Verdict.CLEAN
    signals_fired: list[Signal] = Field(default_factory=list)
    signals_evaluated: int = 0


# =============================================================================
# Root Result Model
# =============================================================================

class AnalysisResult(BaseModel):
    """
    Root output model for a complete Lure analysis.
    This is what gets serialized to JSON, HTML, and STIX.
    """
    lure_version: str = "1.0.0"
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Input file info
    email_file: str
    email_hash: str
    file_type: FileType = FileType.EML

    # Pipeline stage outputs
    header_analysis: Optional[HeaderAnalysis] = None
    iocs: Optional[IOCSet] = None
    attachments: list[AttachmentAnalysis] = Field(default_factory=list)
    yara_matches: Optional[YARAMatchSet] = None
    enrichment: Optional[dict] = None  # EnrichmentResult added in Phase 3
    risk_score: Optional[RiskScore] = None

    # Final outputs
    verdict: Optional[Verdict] = None
    verdict_color: Optional[str] = None
    analyst_summary: Optional[str] = None  # LLM-generated in Phase 5

    # Pipeline metadata
    pipeline_stages_completed: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    def to_summary_dict(self) -> dict:
        """Returns a compact dict for terminal display."""
        return {
            "file": self.email_file,
            "hash": self.email_hash[:16] + "...",
            "verdict": self.verdict.value if self.verdict else "INCOMPLETE",
            "score": self.risk_score.total_score if self.risk_score else 0.0,
            "spf": self.header_analysis.spf.value if self.header_analysis else "?",
            "dkim": self.header_analysis.dkim.value if self.header_analysis else "?",
            "dmarc": self.header_analysis.dmarc.value if self.header_analysis else "?",
            "ioc_count": self.iocs.total_count if self.iocs else 0,
            "attachments": len(self.attachments),
            "anomalies": self.header_analysis.anomalies if self.header_analysis else [],
        }
