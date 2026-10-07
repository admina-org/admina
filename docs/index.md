# Admina Documentation

**The open framework for building AI applications that are governed by design.**

Every AI interaction is governed: PII redacted, injections blocked, loops broken, actions
audited, EU AI Act compliance tracked. Works in-process (SDK) and over the network (proxy).

> 💡 **Looking for the 30-second pitch?** Start with the [README](https://github.com/admina-org/admina#readme).
> Want to chat with the codebase? Try [Ask DeepWiki](https://deepwiki.com/admina-org/admina).

## Where to start

| If you want to... | Go to |
|---|---|
| Run admina in 2 minutes | [Quickstart](guides/quickstart.md) |
| Understand the architecture | [Architecture](guides/architecture.md) |
| Deploy air-gapped / on-prem | [Air-gapped deployment](guides/airgapped-deployment.md) |
| Wire admina into LangChain / CrewAI / n8n | [Integrations](guides/integrations.md) |
| Browse the API reference | [SDK API](api/sdk.md) |
| Explore the code via AI wiki | [DeepWiki](https://deepwiki.com/admina-org/admina) |

## Key components

| Component | Description |
|-----------|-------------|
| **SDK** | In-process governance via `GovernedModel`, `GovernedData`, `GovernedAgent`, `ComplianceKit` |
| **Proxy** | Network-level MCP governance proxy with dual Rust/Python engine |
| **Plugins** | 9 extensible plugin types with builtin implementations |
| **CLI** | Project scaffolding and local dev stack management |
| **Dashboard** | Real-time governance visibility |

## Install

```bash
pip install "admina[proxy]"   # Recommended: SDK + proxy + dashboard
pip install "admina[full]"    # + NLP (spaCy) + telemetry (OTEL)
pip install admina            # SDK only — embed it in another service
```

> Distribution name and import name: `admina` (up to 0.13.x the
> distribution was `admina-framework`; see the
> [package name guide](guides/package-name.md)).

## 30-second example

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
