"""
agentaudit CLI — red-teaming tool for AI security systems.

Entry point for all command-line operations. Uses Click for command
structure and Rich for terminal output.

Commands:
    attack  — Run an automated attack against a target system.
    audit   — Audit an ACP connector for vulnerabilities.
    report  — Generate a Markdown or JSON report from attack results.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

# Add the project root to sys.path so modes/ can be imported
_HERE = Path(__file__).resolve().parent.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))


def _console() -> "Console":
    """Return a Rich Console, falling back to plain output if Rich is not installed."""
    if _HAS_RICH:
        return Console()
    # Minimal fallback
    class _PlainConsole:
        def print(self, msg: str, **kwargs: object) -> None:
            click.echo(str(msg))
        def rule(self, title: str = "", **kwargs: object) -> None:
            click.echo(f"\n--- {title} ---")
    return _PlainConsole()  # type: ignore[return-value]


console = _console()


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option("0.1.0")
def cli() -> None:
    """agentaudit — CLI red-teaming tool for AI security systems."""


# ---------------------------------------------------------------------------
# attack command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--target",
    required=True,
    type=click.Choice(["activguard", "fedunlearn", "ragshield"]),
    help="Target system to attack.",
)
@click.option(
    "--mode",
    required=True,
    type=click.Choice(["probe_bypass", "rag_bypass", "unlearn_bypass"]),
    help="Attack mode.",
)
@click.option(
    "--model",
    default="local",
    show_default=True,
    help="LLM for attack generation (local | gpt-4 | claude). 'local' uses built-in templates.",
)
@click.option(
    "--iterations",
    default=10,
    show_default=True,
    type=click.IntRange(1, 1000),
    help="Number of attack iterations.",
)
@click.option(
    "--vuln-class",
    default="idor",
    show_default=True,
    type=click.Choice(["idor", "sqli", "ssrf", "auth_bypass", "path_traversal"]),
    help="Vulnerability class to target.",
)
@click.option(
    "--output",
    "-o",
    default="terminal",
    show_default=True,
    type=click.Choice(["terminal", "json", "markdown"]),
    help="Output format.",
)
@click.option(
    "--save-to",
    default=None,
    help="Save results to this file path (e.g. results.json or report.md).",
)
def attack(
    target: str,
    mode: str,
    model: str,
    iterations: int,
    vuln_class: str,
    output: str,
    save_to: str | None,
) -> None:
    """Launch an automated attack against the target system."""
    from agentaudit.attacker import AttackLoop
    from agentaudit.reporter import AuditReporter

    if output != "json":
        console.print(f"\n[bold]agentaudit[/bold] attacking [cyan]{target}[/cyan] "
                      f"via [yellow]{mode}[/yellow] ({iterations} iterations)")
        console.print(f"Vulnerability class: [magenta]{vuln_class}[/magenta]\n")

    try:
        loop = AttackLoop(target=target, mode=mode, iterations=iterations)
        results = loop.run(vuln_class=vuln_class)
    except Exception as exc:
        console.print(f"[red]Attack failed: {exc}[/red]")
        sys.exit(1)

    # Attach mode/target for reporting
    results.setdefault("mode", mode)
    results.setdefault("target", target)

    reporter = AuditReporter(attacker_name=f"agentaudit ({mode})")

    if output == "terminal":
        _print_attack_summary(results)
    elif output == "json":
        click.echo(reporter.to_json(results))
    elif output == "markdown":
        click.echo(reporter.markdown(results))

    if save_to:
        reporter.save(results, save_to)
        console.print(f"\nResults saved to [green]{save_to}[/green]")

    # Exit non-zero if bypasses were found (useful for CI)
    if results["bypasses_found"] > 0:
        sys.exit(2)


# ---------------------------------------------------------------------------
# audit command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--connector",
    required=True,
    help="ACP connector identifier or URL to audit.",
)
@click.option(
    "--stix-inject",
    default=None,
    help="Path to a malformed STIX bundle JSON file to inject.",
)
def audit(connector: str, stix_inject: str | None) -> None:
    """Audit an ACP connector for vulnerabilities."""
    console.print(f"\nAuditing ACP connector: [cyan]{connector}[/cyan]")

    if stix_inject:
        stix_path = Path(stix_inject)
        if not stix_path.exists():
            console.print(f"[red]STIX file not found: {stix_inject}[/red]")
            sys.exit(1)
        try:
            with open(stix_path) as f:
                stix_data = json.load(f)
        except json.JSONDecodeError as exc:
            console.print(f"[red]Invalid JSON in STIX file: {exc}[/red]")
            sys.exit(1)

        console.print(f"Loaded STIX bundle: {len(stix_data.get('objects', []))} objects")
        findings = _audit_stix_bundle(connector, stix_data)
        if findings:
            console.print(f"\n[red]Found {len(findings)} potential issue(s):[/red]")
            for finding in findings:
                console.print(f"  [yellow]![/yellow] {finding}")
        else:
            console.print("[green]No obvious STIX injection issues detected.[/green]")
    else:
        console.print("[yellow]No STIX bundle provided. Run with --stix-inject to test injection.[/yellow]")
        console.print(f"Basic connectivity audit for connector {connector!r} would run here.")


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--input",
    "-i",
    required=True,
    help="Path to attack results JSON file.",
)
@click.option(
    "--output",
    "-o",
    default="report.md",
    show_default=True,
    help="Output report file path (.md or .json).",
)
def report(input: str, output: str) -> None:
    """Generate an audit report from attack results."""
    from agentaudit.reporter import AuditReporter

    input_path = Path(input)
    if not input_path.exists():
        console.print(f"[red]Input file not found: {input}[/red]")
        sys.exit(1)

    try:
        with open(input_path) as f:
            results = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Failed to read {input}: {exc}[/red]")
        sys.exit(1)

    reporter = AuditReporter(attacker_name=results.get("tool", "agentaudit"))
    reporter.save(results, output)
    console.print(f"Report written to [green]{output}[/green]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_attack_summary(results: dict) -> None:
    """Print a Rich-formatted attack summary to the terminal."""
    bypasses = results["bypasses_found"]
    iterations = results["iterations"]
    bypass_rate = results["bypass_rate"]

    color = "red" if bypasses > 0 else "green"
    console.print(f"\n[{color}]Bypasses found: {bypasses} / {iterations}[/{color}]")
    console.print(f"Bypass rate    : {bypass_rate:.2%}")

    if bypasses > 0:
        console.print(f"\n[bold red]Findings:[/bold red]")
        for i, finding in enumerate(results.get("findings", []), 1):
            console.print(
                f"  [{i}] Strategy: {finding.get('strategy', '?')} | "
                f"Class: {finding.get('vuln_class', '?')}"
            )
            code_preview = finding.get("code", "")[:120].replace("\n", " ")
            console.print(f"      Code: {code_preview}...")

        redbench = results.get("new_redbench_entries", [])
        if redbench:
            console.print(
                f"\n[green]{len(redbench)} new redbench entr{'y' if len(redbench)==1 else 'ies'} "
                f"generated.[/green]"
            )
    else:
        console.print("\n[green]Target appears robust — no bypasses found.[/green]")


def _audit_stix_bundle(connector: str, stix_data: dict) -> list[str]:
    """Basic STIX bundle audit: look for unexpected types and oversized objects."""
    findings: list[str] = []
    objects = stix_data.get("objects", [])
    if not isinstance(objects, list):
        findings.append("'objects' field is not an array — malformed STIX bundle")
        return findings
    for obj in objects:
        if not isinstance(obj, dict):
            findings.append("Non-dict object in STIX bundle")
            continue
        obj_type = obj.get("type", "unknown")
        if obj_type not in (
            "indicator", "malware", "attack-pattern", "course-of-action",
            "report", "threat-actor", "campaign", "bundle",
            "identity", "relationship", "sighting",
        ):
            findings.append(f"Unexpected STIX object type: {obj_type!r}")
        # Check for embedded scripts in description fields
        desc = str(obj.get("description", ""))
        if "<script" in desc.lower() or "javascript:" in desc.lower():
            findings.append(f"Potential XSS in description of object {obj.get('id', '?')!r}")
        # Check for oversized objects (potential DoS)
        obj_size = len(str(obj))
        if obj_size > 100_000:
            findings.append(
                f"Object {obj.get('id', '?')!r} is {obj_size:,} bytes — potential DoS vector"
            )
    return findings


if __name__ == "__main__":
    cli()
