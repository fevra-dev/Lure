"""
lure/cli.py
CLI entrypoint — built with Typer + Rich.
"""
from __future__ import annotations

import json
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

app = typer.Typer(
    name="lure",
    help="🎣 Lure — Phishing Analysis & IOC Extraction Platform",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


class OutputFormat(str, Enum):
    json = "json"
    html = "html"
    stix = "stix"
    all = "all"
    text = "text"


# =============================================================================
# lure analyze
# =============================================================================

@app.command()
def analyze(
    email_path: Path = typer.Argument(..., help="Path to .eml or .msg file", exists=True),
    format: OutputFormat = typer.Option(OutputFormat.text, "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (stdout if omitted)"),
    no_enrich: bool = typer.Option(False, "--no-enrich", help="Skip threat intel enrichment"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM verdict explanation"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug logging"),
):
    """
    Analyze a single .eml or .msg email file.

    Runs the full Lure pipeline: header forensics → IOC extraction →
    YARA scanning → enrichment → verdict scoring → report.
    """
    import logging
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    console.print(Panel.fit(
        f"[bold cyan]🎣 Lure — Phishing Analysis[/bold cyan]\n"
        f"[dim]Analyzing:[/dim] [white]{email_path.name}[/white]",
        border_style="cyan",
    ))

    with console.status("[cyan]Running analysis pipeline...[/cyan]", spinner="dots"):
        from lure.pipeline import analyze as run_pipeline
        result = run_pipeline(
            path=email_path,
            enrich=not no_enrich,
            llm=not no_llm,
        )

    # ── Output ────────────────────────────────────────────────────────────
    if format == OutputFormat.text:
        _print_text_report(result)
    elif format == OutputFormat.json:
        json_output = result.model_dump_json(indent=2, default=str)
        if output:
            output.write_text(json_output)
            console.print(f"[green]✓ JSON report saved to:[/green] {output}")
        else:
            console.print_json(json_output)
    elif format == OutputFormat.all:
        _print_text_report(result)
        if output:
            json_out = output.with_suffix(".json")
            json_out.write_text(result.model_dump_json(indent=2, default=str))
            console.print(f"[green]✓ JSON saved:[/green] {json_out}")

    # ── Errors / Warnings ─────────────────────────────────────────────────
    for err in result.errors:
        console.print(f"[red]❌ Error:[/red] {err}")
    for warn in result.warnings:
        console.print(f"[yellow]⚠ Warning:[/yellow] {warn}")


def _print_text_report(result) -> None:
    """Print a rich terminal report."""
    from rich.columns import Columns

    # ── Verdict banner ────────────────────────────────────────────────────
    verdict = result.verdict
    if verdict:
        verdict_colors = {
            "CLEAN": "green",
            "SUSPICIOUS": "yellow",
            "LIKELY_PHISHING": "dark_orange",
            "CONFIRMED_MALICIOUS": "red",
        }
        verdict_emojis = {
            "CLEAN": "✅",
            "SUSPICIOUS": "⚠️",
            "LIKELY_PHISHING": "🎣",
            "CONFIRMED_MALICIOUS": "🚨",
        }
        color = verdict_colors.get(verdict.value, "white")
        emoji = verdict_emojis.get(verdict.value, "❓")
        score = result.risk_score.total_score if result.risk_score else 0.0

        console.print(Panel(
            f"[bold {color}]{emoji}  {verdict.value}  [/bold {color}]"
            f"[dim]  Score: {score:.1f}[/dim]",
            border_style=color,
            expand=True,
        ))
    else:
        console.print(Panel("[dim]⚙ Analysis Incomplete[/dim]", border_style="dim"))

    # ── Header analysis ───────────────────────────────────────────────────
    if result.header_analysis:
        h = result.header_analysis
        console.print("\n[bold]📧 Header Analysis[/bold]")

        header_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        header_table.add_column("Field", style="dim", width=20)
        header_table.add_column("Value")

        header_table.add_row("From", h.from_addr or "—")
        header_table.add_row("Subject", (h.subject or "—")[:80])
        header_table.add_row("Date", h.date or "—")
        header_table.add_row("Originating IP", h.originating_ip or "—")

        # Auth badges
        def auth_badge(result_val) -> str:
            if result_val is None:
                return "[dim]UNKNOWN[/dim]"
            v = result_val.value.upper()
            if v == "PASS":
                return "[green]PASS ✓[/green]"
            elif v in ("FAIL",):
                return "[red]FAIL ✗[/red]"
            elif v == "SOFTFAIL":
                return "[yellow]SOFTFAIL ~[/yellow]"
            elif v == "NONE":
                return "[dim]NONE[/dim]"
            return f"[dim]{v}[/dim]"

        header_table.add_row("SPF", auth_badge(h.spf))
        header_table.add_row("DKIM", auth_badge(h.dkim))
        header_table.add_row("DMARC", auth_badge(h.dmarc))
        header_table.add_row("Received hops", str(h.received_hops))

        if h.reply_to_mismatch:
            header_table.add_row(
                "Reply-To ⚠",
                f"[red]{h.reply_to}[/red] [dim](≠ From domain)[/dim]"
            )

        console.print(header_table)

        if h.anomalies:
            console.print("[bold yellow]⚠ Anomalies detected:[/bold yellow]")
            for anomaly in h.anomalies:
                console.print(f"  [yellow]•[/yellow] {anomaly}")

    # ── IOC summary ───────────────────────────────────────────────────────
    if result.iocs:
        iocs = result.iocs
        console.print(f"\n[bold]🔍 IOCs Extracted[/bold] [dim]({iocs.total_count} total)[/dim]")

        if iocs.ips:
            console.print(f"  [cyan]IPs:[/cyan] {', '.join(iocs.ips[:5])}"
                          + (" ..." if len(iocs.ips) > 5 else ""))
        if iocs.domains:
            console.print(f"  [cyan]Domains:[/cyan] {', '.join(iocs.domains[:5])}"
                          + (" ..." if len(iocs.domains) > 5 else ""))
        if iocs.urls:
            console.print(f"  [cyan]URLs:[/cyan] {len(iocs.urls)} extracted")
            for url in iocs.urls[:3]:
                console.print(f"    [dim]•[/dim] {url[:100]}")
        if any(iocs.hashes.values()):
            total_hashes = sum(len(v) for v in iocs.hashes.values())
            console.print(f"  [cyan]Hashes:[/cyan] {total_hashes}")

    # ── Attachments ───────────────────────────────────────────────────────
    if result.attachments:
        console.print(f"\n[bold]📎 Attachments[/bold] ({len(result.attachments)})")
        for att in result.attachments:
            risk_indicator = "[red]⚠[/red]" if att.is_suspicious else "[green]✓[/green]"
            console.print(
                f"  {risk_indicator} [bold]{att.filename}[/bold] "
                f"[dim]({att.detected_type or att.mime_type})[/dim]"
            )
            if att.has_macros:
                console.print(
                    f"    [red]⚠ Macros detected[/red] "
                    f"({len(att.vba_findings)} suspicious keywords)"
                )
            if att.pdf_suspicious:
                console.print(f"    [red]⚠ Suspicious PDF elements[/red] (score: {att.pdf_score})")
            for reason in att.risk_reasons[:3]:
                console.print(f"    [dim]• {reason}[/dim]")

    # ── Signals fired ─────────────────────────────────────────────────────
    if result.risk_score and result.risk_score.signals_fired:
        console.print(f"\n[bold]⚡ Signals Fired[/bold] ({len(result.risk_score.signals_fired)})")
        sig_table = Table(box=box.SIMPLE, show_header=True)
        sig_table.add_column("Signal", style="dim")
        sig_table.add_column("Weight", justify="right")
        sig_table.add_column("Trigger")
        for sig in result.risk_score.signals_fired:
            sig_table.add_row(sig.name, f"{sig.weight:.1f}", sig.trigger[:80])
        console.print(sig_table)

    # ── Pipeline stages ───────────────────────────────────────────────────
    stages_str = " → ".join(result.pipeline_stages_completed)
    console.print(f"\n[dim]Pipeline: {stages_str}[/dim]")


# =============================================================================
# lure ioc
# =============================================================================

@app.command()
def ioc(
    indicator: str = typer.Argument(..., help="IOC to look up (IP, URL, domain, or hash)"),
    format: OutputFormat = typer.Option(OutputFormat.text, "--format", "-f"),
):
    """
    Enrich a single IOC on-demand against all configured threat intel APIs.
    """
    console.print(f"[cyan]Looking up:[/cyan] {indicator}")
    console.print("[dim]Enrichment module available in Phase 3[/dim]")


# =============================================================================
# lure config validate
# =============================================================================

@app.command(name="config")
def config_cmd(
    action: str = typer.Argument("validate", help="Action: validate"),
):
    """Validate configuration, API keys, and dependencies."""
    if action == "validate":
        _validate_config()


def _validate_config() -> None:
    from lure.config import get_settings
    settings = get_settings()

    console.print(Panel.fit("[bold]🔧 Lure Configuration Validator[/bold]", border_style="cyan"))

    # API keys
    console.print("\n[bold]API Keys[/bold]")
    keys = settings.api_keys_configured()
    for service, configured in keys.items():
        status = "[green]✓ configured[/green]" if configured else "[dim]✗ not set (will skip)[/dim]"
        console.print(f"  {service:<25} {status}")

    # Dependencies
    console.print("\n[bold]Dependencies[/bold]")
    deps = [
        ("mail-parser", "mailparser"),
        ("extract-msg", "extract_msg"),
        ("pyspf", "spf"),
        ("dkimpy", "dkim"),
        ("checkdmarc", "checkdmarc"),
        ("iocextract", "iocextract"),
        ("iocsearcher", "iocsearcher"),
        ("beautifulsoup4", "bs4"),
        ("pdfplumber", "pdfplumber"),
        ("oletools", "oletools"),
        ("tldextract", "tldextract"),
        ("yara-python", "yara"),
        ("requests", "requests"),
        ("rich", "rich"),
    ]
    for pkg_name, import_name in deps:
        try:
            __import__(import_name)
            console.print(f"  [green]✓[/green] {pkg_name}")
        except ImportError:
            console.print(f"  [red]✗[/red] {pkg_name} [dim](pip install {pkg_name})[/dim]")

    # Ollama
    console.print("\n[bold]LLM (optional)[/bold]")
    console.print(f"  Ollama URL: {settings.ollama_url}")
    console.print(f"  Model: {settings.ollama_model}")
    console.print(
        "  [dim]To enable: install ollama + instructor, ensure Ollama is running on localhost[/dim]"
    )


# =============================================================================
# lure rules
# =============================================================================

rules_app = typer.Typer(name="rules", help="Manage YARA rule sets")
app.add_typer(rules_app)


@rules_app.command(name="update")
def rules_update(
    ruleset: str = typer.Option("all", help="Ruleset to update: all|signature-base|inquest|reversinglabs"),
):
    """Pull latest YARA rules from GitHub."""
    console.print("[yellow]YARA rule management — available in Phase 2[/yellow]")


@rules_app.command(name="learn")
def rules_learn(
    sample: Path = typer.Argument(..., exists=True, help="Confirmed phishing sample"),
    name: Optional[str] = typer.Option(None, help="Rule name"),
):
    """Generate a YARA rule from a confirmed phishing sample."""
    console.print("[yellow]Rule generation (--learn mode) — available in Phase 2[/yellow]")


# =============================================================================
# lure cache
# =============================================================================

cache_app = typer.Typer(name="cache", help="Manage enrichment cache")
app.add_typer(cache_app)


@cache_app.command(name="clear")
def cache_clear(
    older_than: Optional[int] = typer.Option(None, help="Clear entries older than N hours"),
):
    """Clear enrichment cache entries."""
    console.print("[yellow]Cache management — available in Phase 3[/yellow]")


# =============================================================================
# lure batch
# =============================================================================

@app.command()
def batch(
    directory: Path = typer.Argument(..., help="Directory containing .eml/.msg files", exists=True),
    output_dir: Optional[Path] = typer.Option(None, help="Directory for output files"),
    campaign_name: Optional[str] = typer.Option(None, help="Campaign identifier"),
):
    """
    Analyze all .eml and .msg files in a directory.
    Groups results by campaign correlation.
    """
    eml_files = list(directory.glob("*.eml")) + list(directory.glob("*.msg"))
    if not eml_files:
        console.print(f"[yellow]No .eml or .msg files found in {directory}[/yellow]")
        raise typer.Exit(1)

    console.print(f"[cyan]Found {len(eml_files)} email files to analyze[/cyan]")

    results = []
    for email_path in eml_files:
        console.print(f"  Analyzing: [dim]{email_path.name}[/dim]")
        try:
            from lure.pipeline import analyze as run_pipeline
            result = run_pipeline(email_path)
            results.append(result)

            verdict = result.verdict.value if result.verdict else "INCOMPLETE"
            color_map = {
                "CLEAN": "green", "SUSPICIOUS": "yellow",
                "LIKELY_PHISHING": "dark_orange", "CONFIRMED_MALICIOUS": "red",
                "INCOMPLETE": "dim"
            }
            color = color_map.get(verdict, "white")
            console.print(f"    [{color}]{verdict}[/{color}]")

        except Exception as e:
            console.print(f"    [red]Error: {e}[/red]")

    # Summary
    verdicts = {}
    for r in results:
        v = r.verdict.value if r.verdict else "INCOMPLETE"
        verdicts[v] = verdicts.get(v, 0) + 1

    console.print(f"\n[bold]Batch Summary[/bold] ({len(results)} emails)")
    for verdict, count in sorted(verdicts.items()):
        console.print(f"  {verdict}: {count}")


# =============================================================================
# MCP server (Phase 5 stub)
# =============================================================================

serve_app = typer.Typer(name="serve", help="Start Lure as a service")
app.add_typer(serve_app)


@serve_app.command(name="mcp")
def serve_mcp(
    port: int = typer.Option(3000, help="MCP server port"),
):
    """Start Lure MCP server for agent integration (Phase 5)."""
    console.print(f"[yellow]MCP server — available in Phase 5[/yellow]")
    console.print(f"[dim]Will expose lure_analyze_email, lure_lookup_ioc, lure_get_verdict as MCP tools[/dim]")


# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    app()
