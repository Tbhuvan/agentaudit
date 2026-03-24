<div align="center">

# AgentAudit

**Adversarial red-teaming CLI for LLM security tools**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)

</div>

---

## Overview

AgentAudit is a red-teaming tool that systematically attacks LLM security defences to find bypasses. It implements an adversarial feedback loop: AgentAudit attacks → finds bypasses → defence is retrained → AgentAudit attacks again.

If your security tool can't survive AgentAudit, it can't survive production.

```
agentaudit attacks ActivGuard
    → finds bypass → adds to redbench
    → ActivGuard retrained/updated
    → agentaudit attacks again
    → robustness improves over iterations
```

## Attack Modes

| Mode | Target Layer | Strategy |
|------|-------------|----------|
| `probe_bypass` | Activation probe (Layer 1) | Syntactic mutation, lambda/getattr obfuscation, class delegation |
| `rag_bypass` | Semantic RAG (Layer 2) | Rare ORMs, false context injection, abstraction elevation |
| `unlearn_bypass` | Federated unlearning | Semantic variants of unlearned patterns, rename/split/add-context |

### `probe_bypass` — Evading Activation Probes
Generates code mutations that are semantically vulnerable but avoid probe detection:
- Syntactic mutation (variable renaming, code restructuring)
- Lambda/getattr obfuscation
- Class delegation attacks
- Encoding-based evasion

### `rag_bypass` — Evading Semantic RAG
Crafts code that avoids matching vulnerability antipatterns:
- Synonym substitution
- Control flow obfuscation
- Split-responsibility patterns

### `unlearn_bypass` — Evading Federated Unlearning
Tests whether "unlearned" vulnerability patterns can be recovered:
- Gradient-based recovery attacks
- Membership inference on unlearned samples
- Relearning from partial information

## Usage

```bash
pip install -e ".[dev]"

# Attack ActivGuard's activation probe via IDOR bypass
agentaudit attack --target activguard --mode probe_bypass --vuln-class idor --iterations 20

# Attack RAG-based detection
agentaudit attack --target ragshield --mode rag_bypass --vuln-class sqli --output json

# Audit an ACP connector
agentaudit audit --connector oasis-ctia-connector --stix-inject malformed.json

# Generate a report from saved results
agentaudit report --input results.json --output report.md
```

## Output

AgentAudit produces structured JSON and Markdown reports:
- Bypass success rate per attack technique
- Minimum perturbation required for evasion
- Recommendations for defence hardening
- Successful bypasses automatically generate redbench entries (closes the research loop)

Exit code `2` when bypasses are found — useful for CI integration.

## Project Structure

```
agentaudit/
├── agentaudit/
│   ├── cli.py            # Click CLI entry point
│   ├── attacker.py       # AttackLoop orchestrator
│   └── reporter.py       # Markdown/JSON report generation
├── modes/
│   ├── probe_bypass.py   # ProbeBypassAttack (template-based syntactic mutation)
│   ├── rag_bypass.py     # RAGBypassAttack (rare framework / false-context obfuscation)
│   └── unlearn_bypass.py # UnlearnBypassAttack (semantic variants)
├── tests/                # Test suite
└── README.md
```

## Tests

```bash
pytest tests/ -v --cov=agentaudit --cov=modes
```

## Research Context

Part of the [ActivGuard](https://github.com/Tbhuvan/activguard) research programme. AgentAudit provides robustness evaluation for all ActivGuard layers, ensuring defences are hardened against adversarial evasion before deployment.

## License

Apache License 2.0
