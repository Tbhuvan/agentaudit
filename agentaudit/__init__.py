"""
agentaudit — CLI red-teaming tool for AI security systems.

Actively attacks ActivGuard and FedUnlearn using an adversarial loop:
  1. Generate candidate bypass code using template mutations and heuristics.
  2. Evaluate whether the bypass fools the target detector.
  3. Log successful bypasses to redbench for continuous benchmark expansion.
  4. Iterate — each round refines the attack strategy.

The adversarial feedback loop:
    agentaudit attacks ActivGuard
        → finds bypass → adds to redbench
        → ActivGuard retrained/updated
        → agentaudit attacks again
        → robustness improves over iterations

Quick start:
    agentaudit attack --target activguard --mode probe_bypass --vuln-class idor
    agentaudit report --input results.json --output report.md
"""

from .attacker import AttackLoop
from .reporter import AuditReporter

__all__ = ["AttackLoop", "AuditReporter"]
__version__ = "0.1.0"
__author__ = "Bhuvan Garg"
__description__ = "CLI red-teaming tool for AI security systems"
