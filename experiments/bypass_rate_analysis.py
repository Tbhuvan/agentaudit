"""
bypass_rate_analysis.py — Bypass rate sweep across all strategies × vuln classes.

Runs ProbeBypassAttack with a simulated probe (always available) and
optionally with a real ActivGuard probe at http://localhost:8000.

Matrix:
    5 bypass strategies  × 5 vulnerability classes = 25 attack configurations.
    Each configuration: 10 bypass attempts.

Output:
    - ASCII table printed to stdout.
    - experiments/results/bypass_rate_analysis.json

Usage:
    python experiments/bypass_rate_analysis.py
    python experiments/bypass_rate_analysis.py --url http://localhost:8000
    python experiments/bypass_rate_analysis.py --probe ~/.activguard/hf_probe.pkl
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path bootstrap — make project root importable regardless of cwd
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from modes.probe_bypass import ProbeBypassAttack, _BYPASS_TEMPLATES  # noqa: E402
from modes.real_probe_connector import RealProbeConnector  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s  %(name)s  %(message)s",
)
logger = logging.getLogger("bypass_rate_analysis")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VULN_CLASSES: list[str] = ["idor", "sqli", "ssrf", "path_traversal", "auth_bypass"]
ATTEMPTS_PER_CONFIG: int = 10


def _collect_strategies_for_class(vuln_class: str) -> list[str]:
    """Return the strategy names available for a vuln_class."""
    return [desc for desc, _code in _BYPASS_TEMPLATES.get(vuln_class, [])]


def _all_strategies() -> list[str]:
    """Return a deduplicated list of strategy names across all vuln classes."""
    seen: list[str] = []
    for vc in VULN_CLASSES:
        for s in _collect_strategies_for_class(vc):
            if s not in seen:
                seen.append(s)
    return seen


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def run_analysis(
    connector: RealProbeConnector,
    attempts_per_config: int = ATTEMPTS_PER_CONFIG,
) -> dict[str, Any]:
    """
    Run the full 5×5 bypass rate sweep.

    Args:
        connector: RealProbeConnector to use (real or simulated).
        attempts_per_config: Number of bypass attempts per (strategy, vuln_class) pair.
            Within a single ProbeBypassAttack.run() call the attack cycles through
            all available strategies, so we run `attempts_per_config` iterations
            and then pull per-strategy rates from bypass_rate_vs_strategy.

    Returns:
        Dict with keys: probe_type, timestamp, vuln_classes, strategies,
        per_class_per_strategy (nested dict), summary_table (list of rows),
        overall_bypass_rate (float).

    Raises:
        TypeError: If connector is not a RealProbeConnector.
    """
    if not isinstance(connector, RealProbeConnector):
        raise TypeError(
            f"connector must be a RealProbeConnector, got {type(connector).__name__}"
        )

    probe_type = "real" if connector.is_real() else "simulated"
    logger.info("Probe type: %s", probe_type)

    all_strategies = _all_strategies()
    # per_class_per_strategy[vuln_class][strategy] = bypass_rate (0.0–1.0)
    per_class_per_strategy: dict[str, dict[str, float]] = {
        vc: {s: 0.0 for s in all_strategies} for vc in VULN_CLASSES
    }

    total_attempts = 0
    total_bypasses_count = 0

    for vuln_class in VULN_CLASSES:
        logger.info("  Attacking vuln_class=%s ...", vuln_class)
        attacker = ProbeBypassAttack(
            n_iterations=attempts_per_config,
            real_connector=connector,
        )
        results = attacker.run(vuln_class=vuln_class)

        total_attempts += results["n_iterations"]
        total_bypasses_count += results["n_bypasses"]

        brvs: dict[str, float] = results.get("bypass_rate_vs_strategy", {})
        for strategy, rate in brvs.items():
            if strategy in per_class_per_strategy[vuln_class]:
                per_class_per_strategy[vuln_class][strategy] = rate
            else:
                # Strategy is specific to this vuln_class; store it anyway
                per_class_per_strategy[vuln_class][strategy] = rate

        logger.info(
            "    bypass_rate=%.1f%%  strategy_effectiveness=%.1f%%",
            results["bypass_rate"] * 100,
            results.get("strategy_effectiveness", 0.0) * 100,
        )

    # Build summary: per-strategy overall rate
    strategy_overall: dict[str, float] = {}
    for strategy in all_strategies:
        rates = [
            per_class_per_strategy[vc].get(strategy)
            for vc in VULN_CLASSES
            if per_class_per_strategy[vc].get(strategy) is not None
        ]
        strategy_overall[strategy] = round(sum(rates) / len(rates), 4) if rates else 0.0

    # Per-class overall rate
    class_overall: dict[str, float] = {}
    for vc in VULN_CLASSES:
        rates = [v for v in per_class_per_strategy[vc].values() if v is not None]
        class_overall[vc] = round(sum(rates) / len(rates), 4) if rates else 0.0

    overall_bypass_rate = (
        round(total_bypasses_count / total_attempts, 4) if total_attempts else 0.0
    )

    return {
        "probe_type": probe_type,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "attempts_per_config": attempts_per_config,
        "vuln_classes": VULN_CLASSES,
        "strategies": all_strategies,
        "per_class_per_strategy": per_class_per_strategy,
        "strategy_overall": strategy_overall,
        "class_overall": class_overall,
        "overall_bypass_rate": overall_bypass_rate,
        "total_attempts": total_attempts,
        "total_bypasses": total_bypasses_count,
    }


# ---------------------------------------------------------------------------
# Table renderer
# ---------------------------------------------------------------------------

_COL_HEADERS: dict[str, str] = {
    "idor": "IDOR",
    "sqli": "SQLi",
    "ssrf": "SSRF",
    "path_traversal": "Path",
    "auth_bypass": "Auth",
}


def _pct(v: float | None) -> str:
    """Format a float as a percentage string, right-aligned in 5 chars."""
    if v is None:
        return "  N/A"
    return f"{v * 100:4.0f}%"


def render_table(analysis: dict[str, Any]) -> str:
    """
    Render the bypass rate matrix as a fixed-width ASCII table.

    Args:
        analysis: Result dict from run_analysis().

    Returns:
        Multi-line string ready for printing.
    """
    strategies: list[str] = analysis["strategies"]
    vuln_classes: list[str] = analysis["vuln_classes"]
    per_class: dict[str, dict[str, float]] = analysis["per_class_per_strategy"]
    strategy_overall: dict[str, float] = analysis["strategy_overall"]
    class_overall: dict[str, float] = analysis["class_overall"]
    overall: float = analysis["overall_bypass_rate"]
    probe_type: str = analysis["probe_type"]

    # Column widths
    strat_w = max(len(s) for s in strategies + ["Overall bypass rate"]) + 2
    col_headers = [_COL_HEADERS.get(vc, vc[:6]) for vc in vuln_classes]
    col_w = max(len(h) for h in col_headers + ["Overall"]) + 2

    sep = "-" * (strat_w + col_w * (len(vuln_classes) + 1) + len(vuln_classes) + 2)

    lines: list[str] = []
    lines.append(f"\nBypass Rate Analysis  [probe_type={probe_type}]")
    lines.append(sep)

    # Header row
    header = f"{'Strategy':<{strat_w}}"
    for h in col_headers:
        header += f"| {h:>{col_w - 2}} "
    header += f"| {'Overall':>{col_w - 2}} "
    lines.append(header)
    lines.append(sep)

    # Data rows — one per strategy
    for strategy in strategies:
        row = f"{strategy:<{strat_w}}"
        for vc in vuln_classes:
            val = per_class[vc].get(strategy)
            row += f"| {_pct(val):>{col_w - 2}} "
        row += f"| {_pct(strategy_overall.get(strategy)):>{col_w - 2}} "
        lines.append(row)

    lines.append(sep)

    # Overall row
    overall_row = f"{'Overall bypass rate':<{strat_w}}"
    for vc in vuln_classes:
        overall_row += f"| {_pct(class_overall.get(vc)):>{col_w - 2}} "
    overall_row += f"| {_pct(overall):>{col_w - 2}} "
    lines.append(overall_row)
    lines.append(sep)

    lines.append(
        f"\nTotal: {analysis['total_bypasses']} bypasses / "
        f"{analysis['total_attempts']} attempts"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Save result
# ---------------------------------------------------------------------------


def save_result(analysis: dict[str, Any], output_path: Path) -> None:
    """
    Write the analysis dict to a JSON file, creating parent dirs if needed.

    Args:
        analysis: Result dict from run_analysis().
        output_path: Destination .json path.

    Raises:
        OSError: If the file cannot be written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, indent=2)
    logger.info("Results saved to %s", output_path)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bypass rate sweep: 5 strategies × 5 vuln classes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url",
        default=None,
        metavar="URL",
        help="ActivGuard proxy URL (e.g. http://localhost:8000). "
             "Falls back to simulation if unreachable.",
    )
    parser.add_argument(
        "--probe",
        default=None,
        metavar="PATH",
        help="Path to a .pkl probe file. Used when --url is not provided.",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=ATTEMPTS_PER_CONFIG,
        metavar="N",
        help=f"Bypass attempts per configuration (default {ATTEMPTS_PER_CONFIG}).",
    )
    parser.add_argument(
        "--output",
        default=str(_PROJECT_ROOT / "experiments" / "results" / "bypass_rate_analysis.json"),
        metavar="PATH",
        help="Output JSON file path.",
    )
    return parser.parse_args()


def main() -> None:
    """Entry point for the bypass rate analysis script."""
    args = _parse_args()

    # Build the connector — raises ValueError early if probe_path is bad
    probe_path: str | None = args.probe
    activguard_url: str | None = args.url

    logger.info("Initialising RealProbeConnector ...")
    connector = RealProbeConnector(
        probe_path=probe_path,
        activguard_url=activguard_url,
    )

    if not connector.is_real():
        logger.info("Using simulated probe (no real probe reachable)")
    else:
        logger.info("Connected to real probe (backend=%s)", connector._backend)

    logger.info(
        "Running analysis: %d vuln classes × %d strategies, %d attempts each",
        len(VULN_CLASSES),
        len(_all_strategies()),
        args.attempts,
    )

    analysis = run_analysis(connector=connector, attempts_per_config=args.attempts)

    print(render_table(analysis))

    output_path = Path(args.output)
    save_result(analysis, output_path)
    print(f"\nJSON results written to: {output_path}")


if __name__ == "__main__":
    main()
