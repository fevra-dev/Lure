"""
lure/modules/scanner.py
YARA Scanner — Pipeline Stage C

Compiles YARA rules once at import time and scans email body, HTML,
and attachment content for malware and phishing indicators.

Integration:
    pipeline.py:72 → from lure.modules.scanner import scan_email
    Signature: scan_email(mime_parts, attachments) -> YARAMatchSet

Rule sources:
    1. lure/rules/phishing_custom.yar — PhishOps custom rules (always loaded)
    2. External rulesets (Neo23x0/signature-base, etc.) — optional, loaded if present

If yara-python is not installed, this module raises ImportError which
pipeline.py catches gracefully.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

try:
    import yara  # type: ignore
except ImportError:
    raise ImportError(
        "yara-python is required for YARA scanning: pip install yara-python"
    )

from lure.models import YARAMatch, YARAMatchSet

if TYPE_CHECKING:
    from lure.models import AttachmentAnalysis

log = logging.getLogger(__name__)

# =============================================================================
# Rule compilation (once at import)
# =============================================================================

_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"
_compiled_rules: yara.Rules | None = None


def _compile_rules() -> yara.Rules | None:
    """
    Compile all .yar files from the rules directory.
    Returns compiled Rules object or None if no rules found.
    """
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    rule_files: dict[str, str] = {}

    if _RULES_DIR.exists():
        for yar_file in sorted(_RULES_DIR.glob("*.yar")):
            namespace = yar_file.stem
            rule_files[namespace] = str(yar_file)
            log.debug("Loading YARA ruleset: %s from %s", namespace, yar_file)

    if not rule_files:
        log.warning("No YARA rule files found in %s", _RULES_DIR)
        return None

    try:
        _compiled_rules = yara.compile(filepaths=rule_files)
        log.info("Compiled %d YARA ruleset(s)", len(rule_files))
        return _compiled_rules
    except yara.Error as e:
        log.error("YARA compilation failed: %s", e)
        return None


def _get_rules() -> yara.Rules | None:
    """Get compiled rules, compiling on first access."""
    global _compiled_rules
    if _compiled_rules is None:
        return _compile_rules()
    return _compiled_rules


# =============================================================================
# Scanning
# =============================================================================

def _scan_data(data: bytes, scan_target: str, rules: yara.Rules) -> list[YARAMatch]:
    """
    Scan a single data buffer against compiled YARA rules.

    Args:
        data: Raw bytes to scan
        scan_target: Label for the scan target (e.g. 'body_text', 'attachment:doc.pdf')
        rules: Compiled YARA rules

    Returns:
        List of YARAMatch objects for matches found
    """
    if not data or len(data) == 0:
        return []

    matches: list[YARAMatch] = []

    try:
        yara_matches = rules.match(data=data, timeout=30)

        for m in yara_matches:
            strings_matched = []
            if hasattr(m, 'strings'):
                for s in m.strings:
                    if hasattr(s, 'instances'):
                        for instance in s.instances:
                            strings_matched.append(str(instance))
                    elif hasattr(s, 'identifier'):
                        strings_matched.append(s.identifier)

            matches.append(YARAMatch(
                rule_name=m.rule,
                ruleset=m.namespace if hasattr(m, 'namespace') else 'default',
                scan_target=scan_target,
                strings_matched=strings_matched[:10],  # Cap for payload size
                tags=list(m.tags) if hasattr(m, 'tags') else [],
                meta=dict(m.meta) if hasattr(m, 'meta') else {},
            ))

    except yara.TimeoutError:
        log.warning("YARA scan timed out for %s (%d bytes)", scan_target, len(data))
    except yara.Error as e:
        log.warning("YARA scan error for %s: %s", scan_target, e)

    return matches


# =============================================================================
# Public interface
# =============================================================================

def scan_email(
    mime_parts: list[dict],
    attachments: list[AttachmentAnalysis] | None = None,
) -> YARAMatchSet:
    """
    Scan all email components against YARA rules.

    Scans in order:
        1. Email body parts (text/plain, text/html)
        2. Attachment payloads

    Args:
        mime_parts: MIME parts from parser.py (list of dicts with 'payload', 'content_type', etc.)
        attachments: AttachmentAnalysis objects from extractor.py

    Returns:
        YARAMatchSet with all matches
    """
    rules = _get_rules()
    if rules is None:
        log.info("No YARA rules available — skipping scan")
        return YARAMatchSet()

    all_matches: list[YARAMatch] = []

    # ── Scan body parts ──────────────────────────────────────────────────
    for i, part in enumerate(mime_parts):
        if part.get("is_attachment"):
            continue

        payload = part.get("payload", b"")
        if not payload:
            continue

        ct = part.get("content_type", "text/plain")
        if "html" in ct.lower():
            target = f"body_html_{i}"
        else:
            target = f"body_text_{i}"

        matches = _scan_data(payload, target, rules)
        all_matches.extend(matches)

        if matches:
            log.info("YARA: %d match(es) in %s", len(matches), target)

    # ── Scan attachments ─────────────────────────────────────────────────
    for part in mime_parts:
        if not part.get("is_attachment"):
            continue

        payload = part.get("payload", b"")
        filename = part.get("filename") or "unknown"

        if not payload:
            continue

        target = f"attachment:{filename}"
        matches = _scan_data(payload, target, rules)
        all_matches.extend(matches)

        if matches:
            log.info("YARA: %d match(es) in %s", len(matches), target)

    result = YARAMatchSet(matches=all_matches)

    log.info(
        "YARA scan complete: %d total match(es) across %d parts",
        result.total_matches, len(mime_parts),
    )

    return result
