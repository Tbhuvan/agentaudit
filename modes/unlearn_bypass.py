"""
Unlearn bypass attack mode: attempts to bypass a federated unlearning protocol
by generating code that is semantically equivalent to an unlearned vulnerable
example but differs syntactically in ways the unlearning procedure did not cover.

Attack model:
    - The target (FedUnlearn) claims to have "forgotten" a specific vulnerability
      pattern after an unlearning request from a data contributor.
    - This attack generates semantic variants of the unlearned pattern and
      checks whether the model still detects them (residual knowledge).
    - A successful bypass = the model detects the original pattern but FAILS
      to detect the semantic variant, indicating incomplete unlearning.

This is fundamentally a membership inference + unlearning verification problem.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any


@dataclass
class UnlearnBypassResult:
    """
    Result of a single unlearn bypass attempt.

    Attributes:
        attempt_id: UUID for this attempt.
        original_pattern: The pattern that was reportedly unlearned.
        variant_code: The semantic variant of the unlearned pattern.
        strategy: The variant generation strategy.
        detector_verdict_original: Detector verdict on the original code.
        detector_verdict_variant: Detector verdict on the variant.
        bypass: True if original is detected but variant is not (residual knowledge gap).
        notes: Human-readable explanation.
    """

    attempt_id: str
    original_pattern: str
    variant_code: str
    strategy: str
    detector_verdict_original: str
    detector_verdict_variant: str
    bypass: bool
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "original_pattern": self.original_pattern[:200],
            "variant_code": self.variant_code,
            "strategy": self.strategy,
            "detector_verdict_original": self.detector_verdict_original,
            "detector_verdict_variant": self.detector_verdict_variant,
            "bypass": self.bypass,
            "notes": self.notes,
        }


# Known "unlearned" patterns — would be supplied by the attacker from the
# unlearning request dataset or inferred through membership inference.
_UNLEARNED_ORIGINALS = [
    {
        "id": "idor_original_1",
        "code": "user = User.objects.get(id=user_id)\nreturn UserSerializer(user).data",
    },
    {
        "id": "sqli_original_1",
        "code": 'cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))',
    },
    {
        "id": "ssrf_original_1",
        "code": "response = requests.get(url)\nreturn response.json()",
    },
]

# Variant generation strategies: each is a transform applied to the original code
_VARIANT_STRATEGIES: list[tuple[str, str]] = [
    ("rename_identifiers", "Rename variables and functions to shift token distribution"),
    ("add_docstring", "Surround with extensive docstrings and type hints"),
    ("add_logging", "Add logging calls around the vulnerable operation"),
    ("split_to_helper", "Move vulnerable operation to a separately defined helper"),
    ("use_getattr", "Replace attribute access with getattr()"),
    ("list_comprehension", "Wrap in a list comprehension for single-item result"),
]


class UnlearnBypassAttack:
    """
    Tests whether a federated unlearning protocol has completely forgotten
    a target vulnerability pattern by probing with semantic variants.

    Attack loop:
      1. Obtain the original code that was submitted for unlearning.
      2. Generate N semantic variants that preserve the vulnerability.
      3. Submit both original and variants to the (post-unlearning) detector.
      4. If original is caught but a variant is not → unlearning is incomplete.
         This is a "partial unlearning bypass".

    Attributes:
        detector: Optional callable for the target detector post-unlearning.
        n_iterations: Number of variant attempts per original pattern.
    """

    def __init__(
        self,
        detector: Any | None = None,
        n_iterations: int = 10,
    ) -> None:
        """
        Initialise the unlearn bypass attacker.

        Args:
            detector: Optional callable `(code: str) -> dict`.
            n_iterations: Number of variant attempts per original.

        Raises:
            ValueError: If n_iterations is not a positive integer.
        """
        if not isinstance(n_iterations, int) or n_iterations < 1:
            raise ValueError(f"n_iterations must be a positive integer, got {n_iterations}")
        self.detector = detector
        self.n_iterations = n_iterations
        self._results: list[UnlearnBypassResult] = []

    def run(self, unlearned_pattern_id: str = "idor_original_1") -> dict[str, Any]:
        """
        Run the unlearn bypass attack.

        Args:
            unlearned_pattern_id: ID of the unlearned pattern to attack.

        Returns:
            Dict with n_bypasses, bypass_rate, bypasses, and all attempts.

        Raises:
            ValueError: If the pattern ID is not found.
        """
        original = self._get_original(unlearned_pattern_id)
        if original is None:
            raise ValueError(
                f"Unlearned pattern {unlearned_pattern_id!r} not found. "
                f"Available: {[o['id'] for o in _UNLEARNED_ORIGINALS]}"
            )

        self._results.clear()
        original_code = original["code"]

        # Check how the detector handles the original
        orig_verdict = self._query_detector(original_code).get("label", "safe")

        bypass_count = 0
        for i in range(self.n_iterations):
            strategy_name, strategy_desc = _VARIANT_STRATEGIES[i % len(_VARIANT_STRATEGIES)]
            variant_code = self._generate_variant(original_code, strategy_name)
            variant_verdict = self._query_detector(variant_code).get("label", "safe")
            bypass = orig_verdict == "vulnerable" and variant_verdict == "safe"
            if bypass:
                bypass_count += 1

            self._results.append(
                UnlearnBypassResult(
                    attempt_id=str(uuid.uuid4()),
                    original_pattern=original_code,
                    variant_code=variant_code,
                    strategy=strategy_name,
                    detector_verdict_original=orig_verdict,
                    detector_verdict_variant=variant_verdict,
                    bypass=bypass,
                    notes=(
                        f"{'PARTIAL UNLEARN BYPASS' if bypass else 'No bypass'}: "
                        f"original={orig_verdict}, variant={variant_verdict}, "
                        f"strategy={strategy_name}"
                    ),
                )
            )

        bypass_rate = bypass_count / self.n_iterations if self.n_iterations else 0.0
        return {
            "pattern_id": unlearned_pattern_id,
            "original_verdict": orig_verdict,
            "n_iterations": self.n_iterations,
            "n_bypasses": bypass_count,
            "bypass_rate": round(bypass_rate, 4),
            "bypasses": [r.to_dict() for r in self._results if r.bypass],
            "attempts": [r.to_dict() for r in self._results],
        }

    def _get_original(self, pattern_id: str) -> dict[str, str] | None:
        """Retrieve an unlearned pattern by ID."""
        for o in _UNLEARNED_ORIGINALS:
            if o["id"] == pattern_id:
                return o
        return None

    def _generate_variant(self, original: str, strategy: str) -> str:
        """Apply a variant strategy to the original code."""
        uid = str(uuid.uuid4()).replace("-", "_")[:6]
        if strategy == "rename_identifiers":
            return original.replace("user", f"entity_{uid}").replace("User", f"Entity_{uid}")
        if strategy == "add_docstring":
            return (
                f'"""\nData retrieval function.\nInternal use only.\n"""\n'
                + original
            )
        if strategy == "add_logging":
            return (
                f"import logging\n_log = logging.getLogger(__name__)\n"
                f"_log.debug('Starting retrieval')\n"
                + original
                + f"\n_log.debug('Retrieval complete')"
            )
        if strategy == "split_to_helper":
            return f"def _helper_{uid}(pk):\n    return " + original.split("\n")[0] + f"\nresult = _helper_{uid}(user_id)"
        if strategy == "use_getattr":
            return original.replace(".get(", ".__class__.objects.get(")
        if strategy == "list_comprehension":
            return f"result = [{original.strip()} for _ in [1]][0]"
        return original

    def _query_detector(self, code: str) -> dict[str, Any]:
        """Query the detector (or simulate)."""
        if self.detector is not None:
            try:
                return self.detector(code)
            except Exception:
                pass
        return self._simulated_detector(code)

    def _simulated_detector(self, code: str) -> dict[str, Any]:
        """Simulated post-unlearning detector: weakened for the original pattern."""
        # Detects most patterns but not the renamed/obfuscated variants
        if re.search(r"\bUser\.objects\.get\s*\(id=", code):
            return {"label": "vulnerable", "confidence": 0.9}
        if re.search(r'cursor\.execute\s*\(\s*".*"\s*\+', code):
            return {"label": "vulnerable", "confidence": 0.85}
        if re.search(r"requests\.get\s*\(\s*url\s*\)", code):
            return {"label": "vulnerable", "confidence": 0.8}
        # Unlearned variants evade detection
        return {"label": "safe", "confidence": 0.7}
