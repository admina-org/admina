# Changelog

All notable changes to Admina are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Admina is pre-1.0: the public API is feature-complete and production-ready,
but may still evolve in response to early-adopter feedback before the 1.0
stability commitment. See [ROADMAP.md](ROADMAP.md) for planned milestones.

---

## [0.9.0] — 2026-05-20

First public release. Admina is a governed AI development framework
composed of an SDK, a transparent proxy, a plugin system, a CLI, and a
dashboard — delivered as a single install with a hybrid Python + Rust
engine.

### Core

- `GovernanceRequest` / `GovernanceResponse` — protocol-agnostic
  governance primitives decoupled from any wire format (MCP, REST,
  in-process SDK, framework callback)
- `AdminaConfig` loader reading `admina.yaml` with `.env` fallback
- Async `EventBus` with per-type and wildcard subscriptions, consumed by
  the OTEL exporter, forensic logger, dashboard live feed, and alert
  channels
- `RiskLevel` enum centralised in `core.types` as the single source of
  truth across all domains

### Governance domains

Four domains, applied bidirectionally on requests and responses:

- **Agent Security** — injection firewall (15-regex fast path +
  heuristic scoring) and loop breaker (TF-IDF cosine similarity)
- **Data Sovereignty** — PII redaction (spaCy NER + regex for email,
  phone, SSN, credit card, IBAN, IP), residency-zone enforcement, data
  classification
- **Compliance** — EU AI Act risk classification (Article 6) and gap
  analysis against Articles 9–15, forensic black box (SHA-256 hash
  chain + MinIO), OpenTelemetry native spans. Timeline tracks the
  **Omnibus VII** agreement (Council/Parliament, 7 May 2026):
  Annex III high-risk postponed to 2 December 2027, Annex I to
  2 August 2028, Art. 50 transparency to 2 December 2026, plus a new
  Art. 5 prohibition on non-consensual intimate imagery / synthetic
  CSAM from 2 December 2026. Exposed as
  `EU_AI_ACT_DEADLINES` dict alongside `EU_AI_ACT_ENFORCEMENT_DEADLINE`.
- **AI Infrastructure** — opt-in `LLMEngine` (Ollama / vLLM with GPU
  auto-detection), `RAGPipeline` (ChromaDB / Milvus with configurable
  chunking), `WebUI` (Open WebUI container with built-in / OIDC / LDAP
  auth)

### SDK

Four governed primitives with async and sync interfaces:

- `GovernedModel` — wraps any LLM with automatic PII redaction, audit
  trail, and event emission; Ollama and OpenAI adapters built-in
- `GovernedData` — enforces residency zones, classification, and PII
  scrubbing on every ingest and query
- `GovernedAgent` — wraps MCP / tool-calling agents with firewall, loop
  detection, and PII layers in-process
- `ComplianceKit` — EU AI Act risk classification, gap analysis, and
  structured report generation

Top-level imports: `from admina import GovernedModel, GovernedData,
GovernedAgent, ComplianceKit`. `py.typed` marker and full type hints.

### Proxy

- FastAPI proxy on port 8080 with JSON-RPC 2.0 `POST /mcp` passthrough
  and bidirectional inspection
- REST API for integrations:
  `POST /api/v1/validate`, `POST /api/v1/audit`,
  `POST /api/compliance/classify`,
  `GET /health`, `GET /governance/status`, `GET /api/stats`,
  `GET /api/forensic/verify`
- Rate limiting via Redis, session tracking, CORS middleware
- Internal service ports (ClickHouse, Redis) bound to `127.0.0.1`

### Plugin system

Nine plugin interfaces with entry-point discovery and manual registration:

- `BaseModelAdapter`, `BaseDataConnector`, `BaseGovernanceGuard`,
  `BaseComplianceTemplate`, `BaseTransportAdapter`, `BaseForensicStore`,
  `BaseAuthProvider`, `BasePIIEngine`, `BaseAlertChannel`

Built-in reference implementations: Ollama, OpenAI, ChromaDB,
filesystem, MCP, HTTP/REST, MinIO, API key, spaCy + regex, log,
webhook, EU AI Act template.

Optional: GuardrailsAI guard (toxic language, jailbreak, bias, PII) —
local-only inference. The PyPI distribution `guardrails-ai` is
currently in quarantine, so the `[guardrailsai]` extra is not shipped
in 0.9.0; the plugin remains in the codebase and auto-detects a
locally-installed copy of the `guardrails` package.

### CLI

- `admina init <project>` — scaffolds `admina.yaml`, `docker-compose.yml`,
  `.env`, and an example `main.py` ready to run without Docker
- `admina dev` — three execution modes:
  - **Default**: zero-Docker local mode — one uvicorn process serves both
    the proxy API and the bundled dashboard on `:3000` (with auto-fallback
    to the next free port if `:3000` is in use)
  - `--stack`: Docker Compose stack (proxy + dashboard + redis + clickhouse
    + minio + otel-collector + grafana)
  - `--with-llm`: `--stack` plus ollama + chromadb + open-webui
  - `--public` / `--host 0.0.0.0`: listen on all interfaces for LAN access;
    prints every reachable URL
- `admina plugin list | install | create` — plugin lifecycle management;
  `list` shows the source file path of each plugin
- `admina doctor` — environment diagnostic (Python, Rust engine, plugin
  discovery, config validity, infra reachability)

### Dashboard

- Alpine.js SPA bundled in the wheel under `admina/dashboard/static/` and
  served by FastAPI directly in local mode (no nginx needed)
- Admina Score (0–100 live runtime composite), live event feed via
  WebSocket, EU AI Act compliance gap view, data sovereignty map, model
  status
- OISG (Open / Intelligent / Secure / Governed) adequacy widget:
  2×2 quadrant map with total score and 20-criteria checklist, under a
  dedicated "Instance Configuration" section that distinguishes static
  capability assessment from live runtime metrics
- Backend endpoints: `/api/dashboard/score`, `/feed`, `/compliance`,
  `/sovereignty`, `/infra`, `/models`, `/oisg`
- Cookie-based session for the bundled dashboard (HttpOnly `admina_session`)
  so the SPA authenticates without nginx header injection; in Docker mode
  nginx still forwards `X-API-Key` to the proxy

### Integrations

- **LangChain** — `AdminaCallbackHandler` governs every LLM call and
  tool invocation in-process
- **CrewAI** — `admina_step_callback` and `admina_task_callback` for
  multi-agent governance
- **n8n** — community nodes package `n8n-nodes-admina` with
  `AdminaGovern`, `AdminaAudit`, `AdminaDashboard`
- **OpenClaw** — `admina-governance` skill routing all agent actions
  through the proxy before execution
- **Cheshire Cat AI** — three Python hooks (`agent_fast_reply`,
  `before_cat_sends_message`, `before_cat_recalls_memories`) with a
  sidecar setup script

### Performance

Hybrid Python + Rust engine via PyO3. Measured median overhead on the
full four-domain pipeline: 6.25 µs (P95 7.04 µs, P99 7.29 µs).
Benchmark suite under `scripts/benchmark.py` with reproducible Docker
environment in `docker-compose.benchmark.yml`.

### Tooling

- `uv`-managed environment (`uv sync --group dev`) with `uv.lock` for
  deterministic dependency resolution
- Python 3.11+ (pinned via `.python-version`)
- `ruff` for lint + format, `bandit` for security linting, `safety` for
  dependency vulnerability scanning
- `pytest` with coverage gate at 70%
- GitHub Actions: CI (lint, test, coverage, security scan) and release
  workflow with multi-platform wheel builds (Linux x86_64 / aarch64,
  macOS x86_64 / arm64) and automated PyPI publish on tag

### Documentation

- `README.md` with quickstart, architecture overview, and integration
  catalog
- `CONTRIBUTING.md` with supported platforms, test commands, and plugin
  development guide
- `SECURITY.md` with coordinated disclosure policy
- `CODE_OF_CONDUCT.md` based on Contributor Covenant 2.1
- MkDocs site configuration (`mkdocs.yml`) for hosted documentation

---

[0.9.0]: https://github.com/admina-org/admina/releases/tag/v0.9.0
