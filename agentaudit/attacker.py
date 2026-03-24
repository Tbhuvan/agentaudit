"""
Core adversarial attack loop for agentaudit.

Orchestrates the selected attack mode across multiple iterations,
accumulates findings, and generates redbench entries for any bypasses found.

Adversarial feedback loop:
    agentaudit attacks ActivGuard
        → finds bypass → adds to redbench
        → ActivGuard retrained/updated
        → agentaudit attacks again
        → robustness improves over iterations
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AttackFinding:
    """
    A single bypass found during the attack loop.

    Attributes:
        finding_id: UUID.
        iteration: Which iteration produced this finding.
        target: The system being attacked.
        mode: The attack mode used.
        vuln_class: Vulnerability class targeted.
        code: The bypass code that succeeded.
        strategy: The bypass strategy used.
        notes: Explanation of why this is a bypass.
        timestamp: When the bypass was found.
    """

    finding_id: str
    iteration: int
    target: str
    mode: str
    vuln_class: str
    code: str
    strategy: str
    notes: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "iteration": self.iteration,
            "target": self.target,
            "mode": self.mode,
            "vuln_class": self.vuln_class,
            "code": self.code,
            "strategy": self.strategy,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat(),
        }


class AttackLoop:
    """
    Core adversarial loop: attack → evaluate → learn → attack again.

    If an iteration finds a bypass, it is logged to self._findings and
    a new redbench entry is generated. Each subsequent iteration can
    build on successful strategies (promotion heuristic).

    Example:
        >>> loop = AttackLoop(target="activguard", mode="probe_bypass", iterations=20)
        >>> results = loop.run(vuln_class="idor")
        >>> print(f"Bypasses: {results['bypasses_found']}")
        >>> print(f"Bypass rate: {results['bypass_rate']:.2%}")
    """

    def __init__(
        self,
        target: str,
        mode: str,
        iterations: int = 10,
    ) -> None:
        """
        Initialise the attack loop.

        Args:
            target: Target system name ("activguard" | "fedunlearn" | "ragshield").
            mode: Attack mode ("probe_bypass" | "rag_bypass" | "unlearn_bypass").
            iterations: Maximum number of attack iterations.

        Raises:
            ValueError: If target, mode, or iterations are invalid.
        """
        valid_targets = {"activguard", "fedunlearn", "ragshield"}
        valid_modes = {"probe_bypass", "rag_bypass", "unlearn_bypass"}

        if target not in valid_targets:
            raise ValueError(
                f"Unknown target {target!r}. Valid: {sorted(valid_targets)}"
            )
        if mode not in valid_modes:
            raise ValueError(
                f"Unknown mode {mode!r}. Valid: {sorted(valid_modes)}"
            )
        if not isinstance(iterations, int) or iterations < 1:
            raise ValueError(f"iterations must be a positive integer, got {iterations}")

        self.target = target
        self.mode = mode
        self.iterations = iterations
        self._findings: list[AttackFinding] = []
        self._redbench_entries: list[dict[str, Any]] = []
        self._iteration_results: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, vuln_class: str = "idor") -> dict[str, Any]:
        """
        Run the full adversarial attack loop.

        Each iteration:
          1. Selects a strategy (cycling through available strategies).
          2. Generates a bypass candidate.
          3. Evaluates against the target.
          4. If bypass found: records finding + generates redbench entry.

        Args:
            vuln_class: Vulnerability class to target.

        Returns:
            Dict with keys: bypasses_found (int), iterations (int),
            bypass_rate (float), findings (list[dict]),
            new_redbench_entries (list[dict]).

        Raises:
            TypeError: If vuln_class is not a string.
        """
        if not isinstance(vuln_class, str):
            raise TypeError(f"vuln_class must be str, got {type(vuln_class).__name__}")

        self._findings.clear()
        self._redbench_entries.clear()
        self._iteration_results.clear()

        attacker = self._build_attacker()
        if self.mode == "unlearn_bypass":
            # UnlearnBypassAttack uses pattern_id, not vuln_class
            pattern_id_map = {
                "idor": "idor_original_1",
                "sqli": "sqli_original_1",
                "ssrf": "ssrf_original_1",
                "auth_bypass": "idor_original_1",
                "path_traversal": "idor_original_1",
            }
            pattern_id = pattern_id_map.get(vuln_class, "idor_original_1")
            raw_results = attacker.run(unlearned_pattern_id=pattern_id)
        else:
            raw_results = attacker.run(vuln_class=vuln_class)

        # Convert raw bypass results to AttackFinding objects
        for i, bypass in enumerate(raw_results.get("bypasses", [])):
            finding = AttackFinding(
                finding_id=str(uuid.uuid4()),
                iteration=i,
                target=self.target,
                mode=self.mode,
                vuln_class=vuln_class,
                code=bypass.get("code", ""),
                strategy=bypass.get("strategy", "unknown"),
                notes=bypass.get("notes", ""),
            )
            self._findings.append(finding)

            # Generate redbench entry
            redbench_entry = self._make_redbench_entry(finding)
            self._redbench_entries.append(redbench_entry)

        bypass_count = len(self._findings)
        bypass_rate = bypass_count / self.iterations if self.iterations else 0.0

        return {
            "bypasses_found": bypass_count,
            "iterations": self.iterations,
            "bypass_rate": round(bypass_rate, 4),
            "findings": [f.to_dict() for f in self._findings],
            "new_redbench_entries": self._redbench_entries,
            "raw_results": raw_results,
        }

    def get_findings(self) -> list[AttackFinding]:
        """Return all findings from the last run."""
        return list(self._findings)

    def get_redbench_entries(self) -> list[dict[str, Any]]:
        """Return redbench entries generated from successful bypasses."""
        return list(self._redbench_entries)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _iteration(self, i: int, attacker: Any, vuln_class: str) -> dict[str, Any] | None:
        """
        Run one attack iteration.

        Returns a finding dict if a bypass was found, else None.
        """
        result = attacker.run(vuln_class=vuln_class)
        if result.get("n_bypasses", 0) > 0:
            return result
        return None

    def _build_attacker(self) -> Any:
        """Instantiate the appropriate attacker for the selected mode."""
        if self.mode == "probe_bypass":
            from modes.probe_bypass import ProbeBypassAttack
            return ProbeBypassAttack(n_iterations=self.iterations)
        elif self.mode == "rag_bypass":
            from modes.rag_bypass import RAGBypassAttack
            return RAGBypassAttack(n_iterations=self.iterations)
        elif self.mode == "unlearn_bypass":
            from modes.unlearn_bypass import UnlearnBypassAttack
            return UnlearnBypassAttack(n_iterations=self.iterations)
        raise ValueError(f"Unknown mode: {self.mode!r}")

    def _make_redbench_entry(self, finding: AttackFinding) -> dict[str, Any]:
        """Create a redbench-compatible dict from an AttackFinding."""
        cwe_map = {
            "idor": "CWE-639",
            "sqli": "CWE-89",
            "ssrf": "CWE-918",
            "auth_bypass": "CWE-306",
            "path_traversal": "CWE-22",
        }
        return {
            "id": f"auto-{finding.vuln_class}-{finding.finding_id[:8]}",
            "cwe": cwe_map.get(finding.vuln_class, "CWE-Unknown"),
            "severity": "high",
            "label": "vulnerable",
            "language": "python",
            "code": finding.code.strip(),
            "description": (
                f"Auto-discovered bypass via agentaudit {self.mode} on {self.target}. "
                f"Strategy: {finding.strategy}. "
                f"Original notes: {finding.notes}"
            ),
            "fix": "Apply appropriate defensive pattern for this vulnerability class.",
            "attack_scenario": (
                f"Adversarial bypass discovered by agentaudit in iteration "
                f"{finding.iteration}. The target system {self.target!r} "
                f"classified this as safe despite the vulnerability."
            ),
            "source": "agentaudit",
            "target": self.target,
            "mode": self.mode,
            "strategy": finding.strategy,
        }
