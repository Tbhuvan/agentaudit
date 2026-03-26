<div align="center">

# AgentAudit

**Adversarial red-teaming CLI for LLM security tools**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)

</div>

---

## Overview

AgentAudit is a red-teaming tool that systematically attacks LLM security defences to find bypasses. It implements an adversarial feedback loop: AgentAudit attacks → finds bypasses → bypasses are added to RedBench → defence is retrained → AgentAudit attacks again.

If your security tool can't survive AgentAudit, it can't survive production.

```
agentaudit attacks ActivGuard
    → finds bypass → adds to redbench
    → ActivGuard retrained/updated
    → agentaudit attacks again
    → robustness improves over iterations
```

## Bypass Rate Analysis

Evaluated against the simulated probe (14 bypass strategies × 5 vulnerability classes, 10 attempts each, 700 total):

| Strategy | IDOR | SQLi | SSRF | Path | Auth | Overall |
|----------|------|------|------|------|------|---------|
| indirect_lookup_via_var | 0% | — | — | — | — | 0% |
| getattr_obfuscation | 0% | — | — | — | — | 0% |
| fstring_in_variable | — | 0% | — | — | — | 0% |
| variable_url_no_validation | — | — | 20% | — | — | 20% |
| path_join_no_realpath | — | — | — | 0% | — | 0% |
| pathlib_no_resolve | — | — | — | 20% | — | 20% |
| view_no_decorator | — | — | — | — | 20% | 20% |
| **Overall bypass rate** | **0%** | **0%** | **7%** | **7%** | **7%** | **30%** |

*Results with simulated probe. Connect to real ActivGuard probe (HTTP or pickle) for production bypass rates — use `--url http://localhost:8000` or `--probe path/to/probe.pkl`.*

*Full results: `experiments/results/bypass_rate_analysis.json`*

## Attack Modes

| Mode | Target | Strategy |
|------|--------|----------|
| `probe_bypass` | Activation probe (Layer 1) | 14 syntactic mutation templates across 5 vuln classes |
| `rag_bypass` | Semantic RAG (Layer 2) | Rare ORMs, false context injection, abstraction elevation |
| `unlearn_bypass` | Federated unlearning | Semantic variants of unlearned patterns |

### `probe_bypass` — 14 Strategies Across 5 Classes

| Vuln Class | Strategies |
|------------|-----------|
| IDOR | indirect_lookup_via_var, getattr_obfuscation, property_delegation, lambda_obfuscation, dict_dispatch |
| SQLi | fstring_in_variable, string_join_obfuscation, format_map_injection |
| SSRF | variable_url_no_validation, indirect_via_config |
| Path Traversal | path_join_no_realpath, pathlib_no_resolve |
| Auth Bypass | view_no_decorator, jwt_no_verify |

## Usage

```bash
pip install -e ".[dev]"

# Run bypass rate analysis (simulated probe, no dependencies)
python experiments/bypass_rate_analysis.py

# Attack real ActivGuard proxy
python experiments/bypass_rate_analysis.py --url http://localhost:8000

# Attack via trained probe file
python experiments/bypass_rate_analysis.py --probe ~/.activguard/hf_probe_qwen2-5-coder.pkl

# Full red-team via CLI
agentaudit attack --target activguard --mode probe_bypass --vuln-class idor --iterations 20

# RAG bypass attack
agentaudit attack --target ragshield --mode rag_bypass --vuln-class sqli --output json
```

## Real Probe Integration

```python
from modes.real_probe_connector import RealProbeConnector
from modes.probe_bypass import ProbeBypassAttack

# Connect to running ActivGuard proxy
connector = RealProbeConnector(activguard_url="http://localhost:8000")

# Or load a trained probe directly from disk
connector = RealProbeConnector(probe_path="~/.activguard/hf_probe_qwen2-5-coder.pkl")

print(f"Using real probe: {connector.is_real()}")  # True / False

attack = ProbeBypassAttack(vuln_class="sqli", real_connector=connector)
result = attack.run(n_iterations=50)

print(f"Bypass rate: {result['bypass_rate']:.1%}")
print(f"Per-strategy: {result['bypass_rate_vs_strategy']}")
```

The connector tries backends in priority order: HTTP proxy → pickle file → simulated fallback. Experiments never crash on probe unavailability.

## Project Structure

```
agentaudit/
├── agentaudit/
│   ├── cli.py                    # CLI entry point
│   ├── attacker.py               # AttackLoop orchestrator + redbench entry generation
│   └── reporter.py               # Markdown/JSON report generation
├── modes/
│   ├── probe_bypass.py           # ProbeBypassAttack — 14 bypass templates + per-strategy metrics
│   ├── rag_bypass.py             # RAGBypassAttack — rare framework + abstraction evasion
│   ├── unlearn_bypass.py         # UnlearnBypassAttack — semantic variants
│   └── real_probe_connector.py   # RealProbeConnector — HTTP / pickle / simulation
├── experiments/
│   ├── bypass_rate_analysis.py   # Bypass rate matrix: strategy × vuln class
│   └── results/
│       └── bypass_rate_analysis.json
├── tests/
└── README.md
```

## Research Context

Part of the [ActivGuard](https://github.com/Tbhuvan/activguard) research programme. A security tool that can't survive adversarial red-teaming before publication won't survive production either — AgentAudit closes that loop by systematically finding what the probe misses and feeding those findings back into [RedBench](https://github.com/Tbhuvan/redbench).

## License

Apache License 2.0
