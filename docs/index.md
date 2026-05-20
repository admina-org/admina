# Admina Documentation

**Admina** is the open framework for building AI applications that are governed by design.

Every AI interaction is governed: PII redacted, injections blocked, loops broken, actions audited, EU AI Act compliance tracked.

## Key Components

| Component | Description |
|-----------|-------------|
| **SDK** | In-process governance via `GovernedModel`, `GovernedData`, `GovernedAgent`, `ComplianceKit` |
| **Proxy** | Network-level MCP governance proxy with dual Rust/Python engine |
| **Plugins** | 9 extensible plugin types with builtin implementations |
| **CLI** | Project scaffolding and local dev stack management |
| **Dashboard** | Real-time governance visibility |

## Install

```bash
pip install -e .                # SDK only (lightweight)
pip install -e ".[proxy]"       # Proxy + infra deps
pip install -e ".[full]"        # Everything
```

## Quick Example

```python
from admina import GovernedModel
from admina.plugins.builtin.adapters.ollama import OllamaAdapter

adapter = OllamaAdapter(host="http://localhost:11434")
model = GovernedModel(model_name="llama3.1:8b", adapter=adapter)
response = await model.ask("Summarize this document")
```

## Building the docs

```bash
uv run mkdocs serve     # Live preview at http://127.0.0.1:8000
uv run mkdocs build     # Static site in site/
```

## Regenerating API reference

```bash
uv run python scripts/generate_docs.py
```
