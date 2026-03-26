"""
RealProbeConnector — unified interface for connecting to real vulnerability
detection systems, with automatic fallback to simulation.

Connection priority:
    1. ActivGuard HTTP proxy  (activguard_url provided)  → POST /scan
    2. Pickle probe file      (probe_path provided)       → load + infer
    3. Simulated probe        (fallback)                  → regex patterns

The simulated fallback mirrors the logic in ProbeBypassAttack._simulated_probe
so that experiments can run without any external dependencies.
"""

from __future__ import annotations

import logging
import pickle
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Simulated-probe obvious patterns (kept in sync with probe_bypass._simulated_probe)
_SIMULATED_PATTERNS: list[str] = [
    r"objects\.get\s*\(\s*id\s*=",
    r"execute\s*\(\s*f['\"]",
    r"requests\.get\s*\(\s*url\s*\)",
    r"open\s*\(\s*filename\s*\)",
    r"verify_signature.*False",
]


class RealProbeConnector:
    """
    Wraps a real ActivGuard probe or falls back to simulation.

    Provides a single .predict(code) entry-point regardless of which backend
    is available, making it straightforward to swap in a real probe without
    changing experiment code.

    Attributes:
        probe_path: Path to a .pkl probe file, or None.
        activguard_url: Base URL of a running ActivGuard proxy, or None.
    """

    def __init__(
        self,
        probe_path: str | None = None,
        activguard_url: str | None = None,
    ) -> None:
        """
        Initialise the connector and attempt to load whatever backend is available.

        Connection priority:
          1. activguard_url  — HTTP POST to /scan
          2. probe_path      — load pickle, run inference
          3. simulation      — regex-based fallback (always succeeds)

        Args:
            probe_path: Path to a .pkl probe file, e.g. ~/.activguard/hf_probe_v2.pkl
            activguard_url: URL of a running ActivGuard proxy, e.g. http://localhost:8000

        Raises:
            ValueError: If probe_path is provided but the file does not exist.
        """
        if probe_path is not None and not Path(probe_path).exists():
            raise ValueError(
                f"probe_path does not exist: {probe_path!r}. "
                "Pass a valid .pkl path or leave probe_path=None to use simulation."
            )

        self.probe_path: str | None = probe_path
        self.activguard_url: str | None = activguard_url.rstrip("/") if activguard_url else None

        self._loaded_probe: Any = None   # holds deserialized probe object
        self._backend: str = "simulation"  # "http" | "pickle" | "simulation"

        self._initialise_backend()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict(self, code: str) -> dict[str, Any]:
        """
        Score a code snippet for vulnerability.

        Args:
            code: Python source code to evaluate.

        Returns:
            Dict with keys:
              label      — "vulnerable" | "safe"
              confidence — float in [0, 1]
              source     — "http" | "pickle" | "simulation"

        Raises:
            TypeError: If code is not a string.
        """
        if not isinstance(code, str):
            raise TypeError(f"code must be str, got {type(code).__name__}")

        if self._backend == "http":
            return self._predict_http(code)
        if self._backend == "pickle":
            return self._predict_pickle(code)
        return self._predict_simulation(code)

    def is_real(self) -> bool:
        """
        Return True if this connector is backed by a real probe.

        Returns:
            True when backend is "http" or "pickle", False for "simulation".
        """
        return self._backend in ("http", "pickle")

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _initialise_backend(self) -> None:
        """Attempt to connect to the highest-priority available backend."""
        # Priority 1: HTTP proxy
        if self.activguard_url is not None:
            if self._try_http_connection():
                self._backend = "http"
                logger.info("RealProbeConnector: using HTTP backend at %s", self.activguard_url)
                return

        # Priority 2: Pickle probe
        if self.probe_path is not None:
            if self._try_load_pickle():
                self._backend = "pickle"
                logger.info("RealProbeConnector: using pickle backend from %s", self.probe_path)
                return

        # Priority 3: Simulation
        self._backend = "simulation"
        logger.info("RealProbeConnector: using simulated probe (no real probe available)")

    def _try_http_connection(self) -> bool:
        """
        Probe the ActivGuard /scan endpoint with a trivial payload to confirm
        it is reachable. Returns True on success.
        """
        try:
            import urllib.request
            import urllib.error
            import json as _json

            payload = _json.dumps({"code": "x = 1"}).encode()
            req = urllib.request.Request(
                f"{self.activguard_url}/scan",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = resp.read()
                result = _json.loads(body)
                if "label" in result:
                    return True
        except Exception as exc:
            logger.debug("HTTP probe unavailable (%s: %s)", type(exc).__name__, exc)
        return False

    def _try_load_pickle(self) -> bool:
        """Load the probe pickle. Returns True on success."""
        try:
            with open(self.probe_path, "rb") as fh:  # type: ignore[arg-type]
                self._loaded_probe = pickle.load(fh)  # noqa: S301
            return True
        except Exception as exc:
            logger.warning("Could not load pickle probe %r: %s", self.probe_path, exc)
        return False

    # ------------------------------------------------------------------
    # Backend predict helpers
    # ------------------------------------------------------------------

    def _predict_http(self, code: str) -> dict[str, Any]:
        """POST to the ActivGuard /scan endpoint and normalise the response."""
        import urllib.request
        import urllib.error
        import json as _json

        payload = _json.dumps({"code": code}).encode()
        req = urllib.request.Request(
            f"{self.activguard_url}/scan",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
                result = _json.loads(body)
                label = result.get("label", "safe")
                if label not in ("vulnerable", "safe"):
                    label = "safe"
                return {
                    "label": label,
                    "confidence": float(result.get("confidence", 0.5)),
                    "source": "http",
                }
        except Exception as exc:
            logger.warning("HTTP probe request failed, falling back to simulation: %s", exc)
            fallback = self._predict_simulation(code)
            fallback["source"] = "http_fallback_simulation"
            return fallback

    def _predict_pickle(self, code: str) -> dict[str, Any]:
        """
        Run inference on the loaded pickle probe.

        The probe is expected to expose a callable interface. Two conventions
        are supported:
          - probe(code)                    → dict with "label" / "confidence"
          - probe.predict([code])          → array-like of label strings
        """
        probe = self._loaded_probe
        label = "safe"
        confidence = 0.5

        try:
            if callable(probe):
                result = probe(code)
                if isinstance(result, dict):
                    label = result.get("label", "safe")
                    confidence = float(result.get("confidence", 0.5))
                elif isinstance(result, str):
                    label = result
            elif hasattr(probe, "predict"):
                preds = probe.predict([code])
                label = str(preds[0]) if preds else "safe"
                if hasattr(probe, "predict_proba"):
                    proba = probe.predict_proba([code])
                    confidence = float(max(proba[0])) if proba is not None else 0.5
            else:
                logger.warning(
                    "Pickle probe does not expose a known interface; using simulation."
                )
                return self._predict_simulation(code)
        except Exception as exc:
            logger.warning("Pickle probe inference failed, using simulation: %s", exc)
            fallback = self._predict_simulation(code)
            fallback["source"] = "pickle_fallback_simulation"
            return fallback

        if label not in ("vulnerable", "safe"):
            label = "safe"

        return {"label": label, "confidence": confidence, "source": "pickle"}

    def _predict_simulation(self, code: str) -> dict[str, Any]:
        """
        Regex-based simulated probe — detects only the most obvious patterns.

        Mirrors ProbeBypassAttack._simulated_probe so that results are
        comparable between the connector and the attack class.
        """
        for pattern in _SIMULATED_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return {"label": "vulnerable", "confidence": 0.9, "source": "simulation"}
        return {"label": "safe", "confidence": 0.85, "source": "simulation"}
