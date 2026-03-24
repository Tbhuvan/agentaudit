"""
Tests for agentaudit CLI and core components.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Ensure project root is on path for modes imports
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from click.testing import CliRunner

from agentaudit.cli import cli
from agentaudit.attacker import AttackLoop, AttackFinding
from agentaudit.reporter import AuditReporter
from modes.probe_bypass import ProbeBypassAttack
from modes.rag_bypass import RAGBypassAttack
from modes.unlearn_bypass import UnlearnBypassAttack


# ---------------------------------------------------------------------------
# CLI — attack command
# ---------------------------------------------------------------------------


class TestCLIAttack:
    def test_attack_runs_successfully(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["attack", "--target", "activguard", "--mode", "probe_bypass",
             "--iterations", "3", "--vuln-class", "idor"],
        )
        # May exit 0 (no bypasses) or 2 (bypasses found) — both are valid
        assert result.exit_code in (0, 2), result.output

    def test_attack_invalid_target(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["attack", "--target", "notarget", "--mode", "probe_bypass"],
        )
        assert result.exit_code != 0

    def test_attack_invalid_mode(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["attack", "--target", "activguard", "--mode", "notamode"],
        )
        assert result.exit_code != 0

    def test_attack_json_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["attack", "--target", "activguard", "--mode", "probe_bypass",
             "--iterations", "2", "--vuln-class", "idor", "--output", "json"],
        )
        assert result.exit_code in (0, 2)
        # JSON should be parseable
        try:
            parsed = json.loads(result.output)
            assert isinstance(parsed, dict)
        except json.JSONDecodeError:
            pytest.fail(f"Output is not valid JSON: {result.output[:200]}")

    def test_attack_saves_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        out_file = str(tmp_path / "results.json")
        result = runner.invoke(
            cli,
            ["attack", "--target", "activguard", "--mode", "probe_bypass",
             "--iterations", "2", "--vuln-class", "idor",
             "--output", "json", "--save-to", out_file],
        )
        assert result.exit_code in (0, 2)
        assert Path(out_file).exists()

    def test_attack_markdown_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["attack", "--target", "fedunlearn", "--mode", "unlearn_bypass",
             "--iterations", "2", "--vuln-class", "idor", "--output", "markdown"],
        )
        assert result.exit_code in (0, 2)
        assert "agentaudit" in result.output.lower() or "bypass" in result.output.lower()


# ---------------------------------------------------------------------------
# CLI — report command
# ---------------------------------------------------------------------------


class TestCLIReport:
    def test_report_from_json(self, tmp_path: Path) -> None:
        # Write a minimal results JSON
        results = {
            "tool": "agentaudit",
            "bypasses_found": 1,
            "iterations": 5,
            "bypass_rate": 0.2,
            "findings": [
                {
                    "finding_id": "abc123",
                    "iteration": 1,
                    "target": "activguard",
                    "mode": "probe_bypass",
                    "vuln_class": "idor",
                    "code": "User.objects.get(id=user_id)",
                    "strategy": "indirect_lookup",
                    "notes": "Probe said safe",
                }
            ],
            "new_redbench_entries": [],
        }
        input_file = tmp_path / "results.json"
        input_file.write_text(json.dumps(results))
        output_file = tmp_path / "report.md"

        runner = CliRunner()
        result = runner.invoke(
            cli, ["report", "--input", str(input_file), "--output", str(output_file)]
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "agentaudit" in content

    def test_report_missing_input(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--input", "nonexistent.json"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# AttackLoop
# ---------------------------------------------------------------------------


class TestAttackLoop:
    def test_construction_valid(self) -> None:
        loop = AttackLoop(target="activguard", mode="probe_bypass", iterations=5)
        assert loop.target == "activguard"
        assert loop.mode == "probe_bypass"
        assert loop.iterations == 5

    def test_invalid_target(self) -> None:
        with pytest.raises(ValueError, match="Unknown target"):
            AttackLoop(target="notarget", mode="probe_bypass")

    def test_invalid_mode(self) -> None:
        with pytest.raises(ValueError, match="Unknown mode"):
            AttackLoop(target="activguard", mode="notamode")

    def test_invalid_iterations(self) -> None:
        with pytest.raises(ValueError):
            AttackLoop(target="activguard", mode="probe_bypass", iterations=0)

    def test_run_returns_expected_structure(self) -> None:
        loop = AttackLoop(target="activguard", mode="probe_bypass", iterations=3)
        results = loop.run(vuln_class="idor")
        assert "bypasses_found" in results
        assert "iterations" in results
        assert "bypass_rate" in results
        assert "findings" in results
        assert "new_redbench_entries" in results
        assert isinstance(results["bypasses_found"], int)
        assert isinstance(results["bypass_rate"], float)

    def test_bypass_rate_in_range(self) -> None:
        loop = AttackLoop(target="activguard", mode="probe_bypass", iterations=5)
        results = loop.run(vuln_class="idor")
        assert 0.0 <= results["bypass_rate"] <= 1.0

    def test_redbench_entries_match_findings(self) -> None:
        loop = AttackLoop(target="activguard", mode="probe_bypass", iterations=5)
        results = loop.run(vuln_class="idor")
        assert len(results["new_redbench_entries"]) == results["bypasses_found"]

    def test_redbench_entry_has_required_fields(self) -> None:
        loop = AttackLoop(target="activguard", mode="probe_bypass", iterations=10)
        results = loop.run(vuln_class="idor")
        for entry in results.get("new_redbench_entries", []):
            assert "id" in entry
            assert "cwe" in entry
            assert "code" in entry
            assert "label" in entry
            assert entry["label"] == "vulnerable"

    def test_type_error_on_bad_vuln_class(self) -> None:
        loop = AttackLoop(target="activguard", mode="probe_bypass", iterations=3)
        with pytest.raises(TypeError):
            loop.run(vuln_class=123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ProbeBypassAttack
# ---------------------------------------------------------------------------


class TestProbeBypassAttack:
    def test_construction(self) -> None:
        attack = ProbeBypassAttack(n_iterations=5)
        assert attack.n_iterations == 5

    def test_invalid_iterations(self) -> None:
        with pytest.raises(ValueError):
            ProbeBypassAttack(n_iterations=0)

    def test_generate_bypass_candidates(self) -> None:
        attack = ProbeBypassAttack()
        candidates = attack.generate_bypass_candidates("idor", n=5)
        assert len(candidates) == 5
        assert all(isinstance(c, str) for c in candidates)

    def test_invalid_vuln_class_raises(self) -> None:
        attack = ProbeBypassAttack()
        with pytest.raises(ValueError, match="Unknown vulnerability class"):
            attack.generate_bypass_candidates("xss", n=3)

    def test_evaluate_bypass_structure(self) -> None:
        attack = ProbeBypassAttack()
        code = "user = User.objects.get(id=user_id)\nreturn user"
        result = attack.evaluate_bypass(code, "idor")
        assert "bypassed" in result
        assert "probe_said" in result
        assert "ground_truth" in result
        assert "method" in result

    def test_run_returns_structure(self) -> None:
        attack = ProbeBypassAttack(n_iterations=5)
        results = attack.run(vuln_class="idor")
        assert "n_bypasses" in results
        assert "bypass_rate" in results
        assert "attempts" in results
        assert len(results["attempts"]) == 5

    def test_generate_redbench_entries(self) -> None:
        attack = ProbeBypassAttack(n_iterations=10)
        attack.run(vuln_class="idor")
        entries = attack.generate_redbench_entries()
        # Entries should match bypass count
        bypass_count = sum(1 for r in attack._results if r.bypassed)
        assert len(entries) == bypass_count

    @pytest.mark.parametrize("vuln_class", ["idor", "sqli", "ssrf", "path_traversal", "auth_bypass"])
    def test_all_vuln_classes(self, vuln_class: str) -> None:
        attack = ProbeBypassAttack(n_iterations=3)
        results = attack.run(vuln_class=vuln_class)
        assert results["vuln_class"] == vuln_class


# ---------------------------------------------------------------------------
# AuditReporter
# ---------------------------------------------------------------------------


class TestAuditReporter:
    _sample_results = {
        "bypasses_found": 2,
        "iterations": 10,
        "bypass_rate": 0.2,
        "findings": [
            {
                "finding_id": "abc",
                "iteration": 1,
                "target": "activguard",
                "mode": "probe_bypass",
                "vuln_class": "idor",
                "code": "User.objects.get(id=user_id)",
                "strategy": "indirect_lookup_via_var",
                "notes": "Probe said safe",
                "timestamp": "2026-01-01T00:00:00+00:00",
            }
        ],
        "new_redbench_entries": [],
        "mode": "probe_bypass",
        "target": "activguard",
    }

    def test_markdown_returns_string(self) -> None:
        reporter = AuditReporter()
        md = reporter.markdown(self._sample_results)
        assert isinstance(md, str)
        assert "agentaudit" in md.lower() or "bypass" in md.lower()

    def test_markdown_contains_findings(self) -> None:
        reporter = AuditReporter()
        md = reporter.markdown(self._sample_results)
        assert "indirect_lookup_via_var" in md

    def test_to_json_valid(self) -> None:
        reporter = AuditReporter()
        json_str = reporter.to_json(self._sample_results)
        parsed = json.loads(json_str)
        assert "bypasses_found" in parsed
        assert parsed["bypasses_found"] == 2

    def test_save_markdown(self, tmp_path: Path) -> None:
        reporter = AuditReporter()
        out = tmp_path / "report.md"
        reporter.save(self._sample_results, str(out))
        assert out.exists()
        assert "agentaudit" in out.read_text().lower() or "bypass" in out.read_text().lower()

    def test_save_json(self, tmp_path: Path) -> None:
        reporter = AuditReporter()
        out = tmp_path / "report.json"
        reporter.save(self._sample_results, str(out))
        assert out.exists()
        json.loads(out.read_text())  # should not raise

    def test_invalid_results_raises(self) -> None:
        reporter = AuditReporter()
        with pytest.raises(ValueError):
            reporter.markdown({"invalid": True})

    def test_type_error_on_non_string_name(self) -> None:
        with pytest.raises(TypeError):
            AuditReporter(attacker_name=42)  # type: ignore[arg-type]
