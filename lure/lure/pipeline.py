"""
lure/pipeline.py
Pipeline Orchestrator — wires all modules together sequentially.

Phase completion tracking ensures each stage's output is available
to downstream stages before they run.
"""
from __future__ import annotations

import logging
from pathlib import Path

from lure.config import get_settings
from lure.models import AnalysisResult, EmailFile

log = logging.getLogger(__name__)


def analyze(path: str | Path, enrich: bool = True, llm: bool = False) -> AnalysisResult:
    """
    Run the full Lure analysis pipeline on a single email file.

    Args:
        path: Path to .eml or .msg file
        enrich: Whether to run threat intel enrichment (Phase 3+)
        llm: Whether to run LLM verdict explanation (Phase 5+)

    Returns:
        AnalysisResult with all completed pipeline stages
    """
    settings = get_settings()

    # ── Input validation ──────────────────────────────────────────────────
    email_file = EmailFile.from_path(path)
    result = AnalysisResult(
        email_file=email_file.filename,
        email_hash=email_file.sha256,
        file_type=email_file.file_type,
    )

    # ── Stage A: Email parsing & header forensics ─────────────────────────
    try:
        from lure.modules.parser import parse_email
        header_analysis, mime_parts = parse_email(email_file)
        result.header_analysis = header_analysis
        result.pipeline_stages_completed.append("A:parser")
        log.info("✓ Stage A: header forensics complete")
    except Exception as e:
        log.error("Stage A (parser) failed: %s", e)
        result.errors.append(f"Parser error: {e}")
        return result

    # ── Stage B: IOC extraction ───────────────────────────────────────────
    try:
        from lure.modules.extractor import extract_iocs
        ioc_set, attachment_analyses = extract_iocs(
            header_analysis=header_analysis,
            mime_parts=mime_parts,
            follow_redirects=True,
            max_redirect_hops=settings.max_redirect_hops,
        )
        result.iocs = ioc_set
        result.attachments = attachment_analyses
        result.pipeline_stages_completed.append("B:extractor")
        log.info("✓ Stage B: IOC extraction complete (%d total IOCs)", ioc_set.total_count)
    except Exception as e:
        log.error("Stage B (extractor) failed: %s", e)
        result.errors.append(f"Extractor error: {e}")

    # ── Stage C: YARA scanning (Phase 2) ─────────────────────────────────
    try:
        from lure.modules.scanner import scan_email  # type: ignore
        yara_matches = scan_email(mime_parts, result.attachments)
        result.yara_matches = yara_matches
        result.pipeline_stages_completed.append("C:scanner")
        log.info("✓ Stage C: YARA scanning complete (%d matches)", yara_matches.total_matches)
    except ImportError:
        result.warnings.append("YARA scanner not available (Phase 2 — install yara-python)")
    except Exception as e:
        log.warning("Stage C (scanner) failed: %s", e)
        result.warnings.append(f"Scanner warning: {e}")

    # ── Stage D: Enrichment (Phase 3) ────────────────────────────────────
    if enrich:
        try:
            from lure.modules.enricher import enrich_iocs  # type: ignore
            enrichment = enrich_iocs(result.iocs, settings)
            result.enrichment = enrichment
            result.pipeline_stages_completed.append("D:enricher")
            log.info("✓ Stage D: enrichment complete")
        except ImportError:
            result.warnings.append("Enrichment module not available (Phase 3)")
        except Exception as e:
            log.warning("Stage D (enricher) failed: %s", e)
            result.warnings.append(f"Enrichment warning: {e}")

    # ── Stage E: Scoring (Phase 4) ────────────────────────────────────────
    try:
        from lure.modules.scorer import score  # type: ignore
        risk_score = score(result, settings)
        result.risk_score = risk_score
        result.verdict = risk_score.verdict
        result.verdict_color = risk_score.verdict.color
        result.pipeline_stages_completed.append("E:scorer")
        log.info("✓ Stage E: scoring complete (score=%.1f verdict=%s)",
                 risk_score.total_score, risk_score.verdict.value)
    except ImportError:
        result.warnings.append("Scorer not available (Phase 4)")
    except Exception as e:
        log.warning("Stage E (scorer) failed: %s", e)
        result.warnings.append(f"Scorer warning: {e}")

    # ── Stage F: LLM explanation (Phase 5) ───────────────────────────────
    if llm:
        try:
            from lure.llm.ollama_client import generate_analyst_summary  # type: ignore
            summary = generate_analyst_summary(result, settings)
            result.analyst_summary = summary
            result.pipeline_stages_completed.append("F:llm")
            log.info("✓ Stage F: LLM analyst summary generated")
        except ImportError:
            result.warnings.append("LLM module not available (Phase 5 — install ollama + instructor)")
        except Exception as e:
            log.warning("Stage F (LLM) failed: %s", e)
            result.warnings.append(f"LLM warning: {e}")

    log.info(
        "Pipeline complete: %d stages, %d errors, %d warnings",
        len(result.pipeline_stages_completed),
        len(result.errors),
        len(result.warnings),
    )

    return result
