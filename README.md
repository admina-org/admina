# Admina — Governed AI Development Framework

**Install once, get governed AI. The open framework for building AI applications that are governed by design.**

Admina gives you an SDK, a transparent proxy, a plugin system, a CLI, and a dashboard — all in one install. Every AI interaction is governed: PII redacted, injections blocked, loops broken, actions audited, EU AI Act compliance tracked. Works in-process (SDK) and over the network (proxy). Zero code changes to add governance to existing applications.

> ⚖️ **Compliance disclaimer.** Admina is a self-assessment and
> defense-in-depth tool. The EU AI Act gap-analysis and risk
> classification features are **decision-support aids, not legal
> advice**. They do not replace the conformity assessment required
> under EU AI Act Art. 43 for high-risk systems, nor the involvement
> of a notified body where the regulation requires one.
>
> **EU AI Act timeline (after the Omnibus VII agreement of 7 May 2026):**
> Art. 5 prohibitions in force since 2 February 2025; GPAI obligations
> in force since 2 August 2025; Art. 50 transparency for synthetic
> content and the new NCII / synthetic-CSAM prohibition apply from
> 2 December 2026; **Annex III high-risk obligations from 2 December
> 2027** (postponed from 2 Aug 2026); Annex I high-risk from 2 August
> 2028 (postponed from 2 Aug 2027). The full machine-readable timeline
> ships with Admina as `admina.domains.compliance.eu_ai_act.EU_AI_ACT_DEADLINES`.
> See [`MODEL_CARD.md`](MODEL_CARD.md) for the full scope, limitations,
> and known failure modes of every Admina component.

[![PyPI version](https://img.shields.io/pypi/v/admina-framework.svg)](https://pypi.org/project/admina-framework/)
[![PyPI downloads](https://img.shields.io/pypi/dm/admina-framework.svg)](https://pypi.org/project/admina-framework/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-green.svg)](https://python.org)
[![Rust](https://img.shields.io/badge/Rust-Engine-orange.svg)](core-rust/)
[![CI](https://github.com/admina-org/admina/actions/workflows/ci.yml/badge.svg)](https://github.com/admina-org/admina/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-admina.org-blue.svg)](https://admina.org/docs)
[![Version](https://img.shields.io/badge/version-0.9.0-blue.svg)](CHANGELOG.md)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-lightgrey.svg)](CONTRIBUTING.md#supported-platforms)

```python
from admina import GovernedModel, GovernedData, GovernedAgent, ComplianceKit
from admina.plugins.builtin.adapters.ollama import OllamaAdapter
from admina.plugins.builtin.connectors.chromadb import ChromaDBConnector

# Every call is governed: PII redacted, injections blocked, audited
adapter = OllamaAdapter(host="http://localhost:11434")
model = GovernedModel(model_name="llama3.1:8b", adapter=adapter)
response = await model.ask("Summarize this document")

# Data governance: residency enforcement, PII classification
connector = ChromaDBConnector(host="localhost", port=8000)
data = GovernedData(connector=connector, residency_zone="eu")
await data.ingest(documents)

# Agent governance: validate every tool call before execution
async def my_upstream(method, params, **kw): ...  # your MCP/HTTP client
agent = GovernedAgent(upstream=my_upstream)
result = await agent.call("tools/call", {"name": "read_file", "arguments": {}})

# Compliance: EU AI Act gap analysis and risk classification
kit = ComplianceKit()
report = kit.gap_analysis(risk_category="high", current_compliance={...})
```

## Quick Start

### Install from PyPI

```bash
# Recommended for new users: SDK + proxy + dashboard.
# Lets you run `admina dev` and see the dashboard out of the box.
pip install "admina-framework[proxy]"

# Everything (proxy + NLP + telemetry). Use this if you also want
# spaCy-based NER for PII detection or OpenTelemetry export.
pip install "admina-framework[full]"
python -m spacy download en_core_web_sm   # for [full] only

# Optional: Rust-accelerated engine (auto-detected at runtime).
pip install admina-core

# Advanced: SDK only (no proxy, no dashboard, no `admina dev`).
# Use this when embedding the SDK into another service and you don't
# need the local dev server.
pip install admina-framework
```

> The PyPI distribution name is `admina-framework`; the Python import
> name is `admina` (e.g. `from admina import GovernedModel`). This is
> a normal Python pattern — same as `python-dateutil` → `import dateutil`.

> The Rust engine is an optional accelerator. `pip install admina-framework`
> ships only the pure-Python implementation; Admina auto-detects the
> Rust engine at runtime and falls back to the Python implementation
> if it's not installed.

### Or install from source

```bash
git clone https://github.com/admina-org/admina.git
cd admina

# Recommended: proxy + dashboard + infra deps (enables `admina dev`)
pip install -e ".[proxy]"

# Everything (proxy + NLP + telemetry)
pip install -e ".[full]"

# CLI workflow
admina init my-project   # Scaffold a governed AI project
cd my-project            # admina dev runs from the project directory
admina dev               # Start the local proxy + dashboard

# Full stack via Docker (no [proxy] extra required)
./scripts/bootstrap-secrets.sh   # Auto-generate .env with random credentials
docker compose up --build        # Credentials printed at bootstrap

# Note: To use the OllamaAdapter, install Ollama (https://ollama.ai)
# and pull a model first: ollama pull llama3.1:8b

# Advanced: SDK only (no proxy, no dashboard)
pip install -e .
python -c "from admina import GovernedModel; print('SDK ready')"
```

Dashboard: [http://localhost:3000](http://localhost:3000) | API docs: [http://localhost:8080/docs](http://localhost:8080/docs)

## Architecture

Admina is organized into 4 governance domains:

| Domain | What it governs | Key features |
|--------|----------------|--------------|
| **Data Sovereignty** | Where data lives and how it's protected | PII redaction (spaCy + regex), residency zones, data classification |
| **AI Infrastructure** | LLM and RAG stack | Ollama backend, ChromaDB vectors, Open WebUI, GPU auto-detect |
| **Agent Security** | What agents can do | Injection firewall (Rust), loop breaker, proxy governance |
| **Compliance** | Regulatory obligations | EU AI Act (Art. 6-15), forensic black box (SHA-256 chain), OTEL |

Every governance feature works in **dual mode** — both via SDK (in-process) and proxy (network):

```
SDK Mode:                           Proxy Mode:
  your code                           AI Agent
    |                                   |
  GovernedModel.ask()               POST /mcp
    |                                   |
  [governance pipeline]             [governance pipeline]
    |                                   |
  Ollama / OpenAI                   MCP Server / LLM
```

## The 4 Governance Domains

| Domain | Capabilities | Engine |
|--------|-------------|--------|
| **Agent Security** | Anti-injection firewall (15 regex + heuristic scoring), loop breaker (TF-IDF cosine similarity) | Rust + Python |
| **Data Sovereignty** | PII redaction (email, SSN, credit cards, IBAN, phone, IP), residency enforcement, data classification | Rust + spaCy NER |
| **Compliance** | EU AI Act risk classification (Art. 6) and gap analysis (Art. 9-15), forensic black box (SHA-256 hash chain), OTEL native spans | Rust + Python |
| **AI Infrastructure** | LLM engine (Ollama, OpenAI), RAG pipeline (ChromaDB), Open WebUI | Python |

All governance domains operate **bidirectionally** — scanning both outbound requests and inbound responses.

## SDK

Four governed primitives, each with async + sync interfaces:

```python
from admina import GovernedModel, GovernedData, GovernedAgent, ComplianceKit
```

| Primitive | Purpose | Governance applied |
|-----------|---------|-------------------|
| `GovernedModel` | LLM calls (Ollama, OpenAI) | PII redaction on prompts and responses, event audit |
| `GovernedData` | Data ingestion and queries | PII classification, residency enforcement, access audit |
| `GovernedAgent` | MCP/A2A agent calls | Firewall, PII, loop breaker — full proxy pipeline in-process |
| `ComplianceKit` | Regulatory compliance | EU AI Act risk classification, gap analysis, report generation |

## Plugin System

9 plugin interfaces, auto-discovered from `plugins/builtin/` or installed via CLI:

| Interface | Builtin implementations |
|-----------|------------------------|
| Model Adapter | Ollama, OpenAI |
| Data Connector | ChromaDB, Filesystem |
| Governance Domain | GuardrailsAI (toxic, jailbreak, bias, PII) |
| Compliance Template | EU AI Act |
| Transport Adapter | MCP, HTTP REST |
| Forensic Store | Filesystem, S3-compatible (boto3), MinIO (legacy) |
| Auth Provider | API Key |
| PII Engine | spaCy + Regex |
| Alert Channel | Log, Webhook |

```bash
admina plugin list                    # List registered plugins
admina plugin install ./my-plugin     # Install a custom plugin
admina plugin create my-domain        # Scaffold a new plugin
```

## CLI

```bash
admina init my-project     # Scaffold project with admina.yaml + docker-compose.yml
admina dev                 # Local mode: proxy + dashboard on :3000 (no Docker)
admina dev --stack         # Docker stack: + redis + clickhouse + minio + grafana
admina dev --with-llm      # --stack + ollama + chromadb + open-webui
admina plugin list         # List all registered plugins
admina plugin install X    # Install a plugin from path or registry
admina plugin create X     # Scaffold a new plugin from template
```

`admina dev` defaults to a **single-process local mode** with zero Docker
dependency: one uvicorn serves the proxy API and the dashboard SPA on the
same port. Use `--stack` for the production-like Docker compose, or
`--with-llm` to also boot local LLM services.

## Forensic backend — choose deliberately

The forensic blackbox (the SHA-256 hash chain that makes the audit trail
tamper-evident) supports four backends. Read this before picking one for
production.

| Backend | License | When to use | Caveats |
|---------|---------|-------------|---------|
| **`memory`** *(default)* | n/a | Local development, tests, demos | Records are LOST on restart — no audit persistence. Loud warning at startup. |
| **`filesystem`** | n/a | Single-host on-prem, air-gapped, smaller deployments | Persistence depends on the host filesystem; not ideal for HA. Requires `FORENSIC_BASE_DIR`. |
| **`s3`** *(boto3)* | Apache 2.0 (boto3) | Production / HA / multi-region | Works with **any S3-compatible service** — AWS S3, Cloudflare R2, Backblaze B2, **SeaweedFS** (Apache 2.0), **Garage** (AGPLv3), **Ceph RGW** (LGPLv2). Recommended new default. |
| **`minio`** *(legacy)* | see below ⚠️ | Backwards compatibility with existing MinIO clusters | Two distinct concerns; read the disclaimer. |

> ⚠️ **MinIO disclaimer — what users of Admina need to know.**
>
> MinIO has two separate licensing/maintenance issues that can affect
> downstream users of Admina, even though Admina itself is Apache 2.0:
>
> 1. **MinIO Server is AGPLv3.** If you deploy MinIO Server as part of a
>    network-accessible service (e.g. a SaaS that exposes Admina's
>    dashboard or API to the public Internet), AGPLv3's network clause
>    can be read to require you to publish the source code of the
>    *combined* application that interacts with MinIO over the network.
>    The MinIO commercial license removes this obligation, but is paid.
>    This is **not** an Admina obligation — Apache 2.0 is permissive —
>    but it is an obligation MinIO Server itself imposes on whoever
>    runs it.
> 2. **The MinIO Python SDK has been archived.** No more security
>    patches, no support for new Python releases. Continuing to depend
>    on it is a supply-chain risk.
>
> **Recommendation:** for new deployments, use `FORENSIC_BACKEND=s3`.
> The `boto3` client is Apache 2.0 and works against any S3-compatible
> service. Two open-source FOSS-friendly options that don't trigger the
> AGPL network clause for typical Admina deployments:
> - **SeaweedFS** (Apache 2.0, S3 gateway, lightweight, single binary)
> - **Garage** (AGPLv3, but as a backend — Garage's AGPL applies to
>   Garage itself, not to applications that connect to it via S3 API)
>
> Existing MinIO deployments keep working through `FORENSIC_BACKEND=minio`,
> but plan a migration. The `minio` backend will be removed in a future
> release.

## Dashboard

Real-time governance dashboard on port 3000:

- **Governance Score** — 0-100 composite metric (data residency, audit coverage, attack rate, forensic integrity, EU AI Act compliance)
- **Live Feed** — streaming governance events via WebSocket
- **Compliance Gaps** — EU AI Act gap analysis with article-level detail
- **Infrastructure Health** — proxy, Redis, MinIO, ClickHouse, OTEL status

API backend: `GET /api/dashboard/score`, `/feed`, `/compliance`, `/sovereignty`, `/infra`, `/models`

## Configuration

Admina uses `admina.yaml` as the primary config file (with `.env` fallback for backward compatibility):

```bash
cp admina.yaml.example admina.yaml   # Copy and customize
```

See [`admina.yaml.example`](admina.yaml.example) for all options including domains, AI infra, plugins, dashboard, forensic storage, alert channels, and integrations.

### Environment variables (Docker / .env)

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMINA_API_KEY` | *(empty)* | API key for all endpoints |
| `UPSTREAM_MCP_URL` | `http://localhost:9000` | Default upstream MCP server |
| `REDIS_URL` | `redis://localhost:6379/0` | Session state + rate limiting |
| `MINIO_SECRET_KEY` | *(required)* | MinIO secret key for forensic storage |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## Integrations

### GuardrailsAI

ML-based content validation (toxic language, jailbreak, bias, PII via Presidio) as a governance domain plugin:

```bash
# Upstream guardrails-ai is currently in PyPI quarantine. Install it
# manually from your local mirror or wheel cache; once available, the
# plugin in admina/plugins/builtin/guards/guardrailsai_guard.py will
# detect it automatically.
pip install <your-guardrails-ai-wheel>
```

Enable in `admina.yaml` under `agent_security.domains.guardrailsai`. All inference runs locally by default — no data leaves the deployment perimeter.

### OpenClaw

Govern OpenClaw agent actions through the Admina proxy. Every tool call, shell command, and API request is validated before execution:

```bash
cd integrations/openclaw/admina-governance
chmod +x setup.sh && ./setup.sh
```

The skill uses `POST /api/v1/validate` (pre-action) and `POST /api/v1/audit` (post-action) endpoints.

### n8n

Community nodes for n8n workflow automation:

| Node | Purpose |
|------|---------|
| **Admina Govern** | Inline governance check — validates workflow data, blocks injections, redacts PII |
| **Admina Audit** | Logs workflow events to forensic black box with EU AI Act risk classification |
| **Admina Dashboard** | Trigger node — fires on governance events via WebSocket |

Install: `npm install n8n-nodes-admina` in your n8n instance.

### Cheshire Cat AI

Govern all Cheshire Cat interactions via three Python hooks (`agent_fast_reply`, `before_cat_sends_message`, `before_cat_recalls_memories`):

```bash
cd integrations/cheshirecat/admina-plugin
./setup.sh    # Start Admina sidecar
# Copy plugin into Cheshire Cat plugins/ directory
```

### LangChain

Drop-in callback handler — governs every LLM call and tool invocation in-process:

```python
from admina.integrations.langchain.callbacks import AdminaCallbackHandler

handler = AdminaCallbackHandler()
llm = ChatOpenAI(callbacks=[handler])
```

### CrewAI

Step and task callbacks for multi-agent governance:

```python
from admina.integrations.crewai.callbacks import admina_step_callback, admina_task_callback

agent = Agent(role="Researcher", step_callback=admina_step_callback)
crew = Crew(agents=[agent], tasks=[task], task_callback=admina_task_callback)
```

See [full integration docs](docs/guides/integrations.md) for details.

## Hybrid Python + Rust Engine

The Rust core engine is an optional accelerator. `pip install admina-framework`
ships only the pure-Python implementation; to enable the Rust engine
build `admina_core` separately (`maturin develop --release
--manifest-path core-rust/Cargo.toml`, see [CONTRIBUTING.md](CONTRIBUTING.md)).
At runtime Admina auto-detects whichever is available and falls back
transparently to Python if the Rust extension is not installed.

Measured numbers below assume the Rust engine is loaded:

```
Component          Rust (median)   P95        P99
-----------------  -------------   ---------  ---------
Firewall (regex)   2.08us          2.33us     2.50us
PII Scanner        0.62us          0.67us     0.71us
Loop Breaker       2.38us          2.67us     2.75us
Hash Chain         1.00us          1.12us     1.25us
-----------------  -------------   ---------  ---------
4-Domain pipeline  6.25us          7.04us     7.29us
```

<details>
<summary>Rust vs Python comparison (click to expand)</summary>

```
Component          Python (median)   Rust (median)   Speedup
-----------------  ---------------   -------------   --------
Firewall           7.79us            2.08us          3.7x
PII (regex-only)   8.21us            0.62us          13.2x
PII (with spaCy)   1 992us           0.62us          3 213x
Loop (sklearn)     505us             2.38us          212x
-----------------  ---------------   -------------   --------
Full pipeline      2 261us           5.21us          434x
```

</details>

## Traffic Simulator

Generate realistic governance traffic to test and demo the platform:

```bash
# Start the proxy
docker compose up -d

# Default: 60s at 2 req/s
python scripts/simulate.py

# Intense: 5 minutes at 10 req/s
python scripts/simulate.py --duration 300 --rate 10
```

Generates a weighted mix of: clean MCP requests, injection attempts, PII content, loop triggers, REST validate/audit calls, EU AI Act classifications, and dashboard reads. Colored terminal output with per-event action and summary counters.

## Project Structure

```
admina/
+-- admina/                 SDK package (GovernedModel, GovernedData, GovernedAgent, ComplianceKit)
|   +-- plugins/            Plugin base classes + registry
+-- domains/                4 governance domains
|   +-- data_sovereignty/   PII, residency, classification
|   +-- ai_infra/           LLM engine, RAG pipeline, Web UI
|   +-- agent_security/     Firewall, loop breaker, proxy
|   +-- compliance/         EU AI Act, forensic, OTEL
+-- plugins/builtin/        Reference plugin implementations
|   +-- adapters/           Ollama, OpenAI
|   +-- connectors/         ChromaDB, Filesystem
|   +-- domains/            GuardrailsAI
|   +-- compliance/         EU AI Act template
|   +-- transports/         MCP, HTTP REST
|   +-- forensic/           MinIO, Filesystem
|   +-- auth/               API Key
|   +-- pii/                spaCy + Regex
|   +-- alerts/             Log, Webhook
+-- proxy/                  FastAPI proxy + Rust engine bridge
|   +-- api/                Dashboard + integration REST endpoints
+-- cli/                    CLI commands (init, dev, plugin)
+-- core/                   Config, types, event bus
+-- core-rust/              Rust governance engines (PyO3)
+-- dashboard/              Real-time governance web UI
+-- integrations/
|   +-- openclaw/           OpenClaw governance skill
|   +-- n8n/                n8n community nodes
+-- tests/                  800+ tests (pytest)
+-- docker-compose.yml      Full stack deployment (9 containers)
```

## API

```bash
# Health check (always public)
curl http://localhost:8080/health

# Governance stats
curl http://localhost:8080/api/stats -H "X-API-Key: $ADMINA_API_KEY"

# Proxy an MCP call (all governance domains applied)
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{...}}'

# Validate content (REST API for integrations)
curl -X POST http://localhost:8080/api/v1/validate \
  -H "Content-Type: application/json" \
  -d '{"content": "Check this text for governance issues"}'

# Audit an action (forensic logging)
curl -X POST http://localhost:8080/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"event": {"action": "llm_call", "status": "success"}}'

# EU AI Act risk classification
curl -X POST http://localhost:8080/api/compliance/classify \
  -H "Content-Type: application/json" \
  -d '{"description":"AI credit scoring","use_case":"lending","data_types":["financial"]}'

# Dashboard governance score
curl http://localhost:8080/api/dashboard/score
```

## Infrastructure & Services

The full stack (`docker compose up`) runs 9 containers:

| Port | Service | Description |
|------|---------|-------------|
| `8080` | Proxy | MCP proxy + REST API + OpenAPI docs |
| `3000` | Dashboard | Real-time governance web UI |
| `3001` | Grafana | Metrics dashboards |
| `9090` | MinIO Console | Forensic storage browser |
| `4317` | OTEL Collector | OTLP gRPC ingestion |

ClickHouse and Redis are internal only (not exposed to host).

## Project documents

- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup, testing, and pull request workflow
- [MODEL_CARD.md](MODEL_CARD.md) — transparency artifact for every Admina governance component (intended use, scope, limitations, known failure modes), aligned with EU AI Act Art. 13 and NIST AI RMF
- [ROADMAP.md](ROADMAP.md) — planned milestones from 0.9.x to 1.0 and beyond
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [SECURITY.md](SECURITY.md) — coordinated disclosure policy
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1

Admina is Apache 2.0. Contributions are welcome.

## License

Copyright © 2025–2026 [Stefano Noferi](https://github.com/stefanoferi) & Admina contributors

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

---

<p align="center">
  <img src="https://admina.org/admina-heimdall-the-governance-owl.png" alt="Heimdall — the Governance Owl" width="80" /><br/>
  <em>Heimdall — the Governance Owl</em><br/><br/>
  <strong>admina.org</strong> · Created by Stefano Noferi · Pisa, Italy
</p>
