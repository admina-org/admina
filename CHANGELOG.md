# Changelog

All notable changes to Admina are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Admina is pre-1.0: the public API is feature-complete and production-ready,
but may still evolve in response to early-adopter feedback before the 1.0
stability commitment. See [ROADMAP.md](ROADMAP.md) for planned milestones.

---

## [Unreleased]

Hardening release (0.9.x stabilisation).

### Added

- **Opt-in `[rust]` extra.** `pip install "admina-framework[rust]"`
  pulls the `admina-core` Rust accelerator wheel from PyPI, so
  `import admina_core` succeeds and the engine bridge auto-detects it.
  The Rust engine is opt-in (not a default dependency); the default
  install runs the pure-Python engines, which currently have broader
  firewall detection coverage.

### Changed

- **Rust firewall risk model: per-pattern severity.** `RustFirewall`
  now assigns a per-pattern `RiskLevel` and reports the max over matched
  patterns, mirroring the Python `InjectionFirewall` (previously the tier
  was derived from the match count, so a single match reported `medium`).
  On the internal evasion corpus the Rust firewall blocks 7/14 attacks at
  HIGH+, with no new false positives. Full Rust↔Python detection parity
  (evasion normalisation + multilingual patterns) is tracked for 0.10.

### Documentation

- README install and Performance sections state the Rust engine is
  opt-in via `[rust]` and document the firewall detection trade-off
  between the two engines.

---

## [0.9.3] — 2026-05-23

UX hotfix for first-time users. Removes every cryptic "module not
found" error from the install → init → dev path: every failure now
prints an actionable upgrade command, and the README leads with the
install that actually makes `admina dev` work.

### Fixed

- **`admina dev` no longer crashes with `ModuleNotFoundError: uvicorn`
  when the `[proxy]` extra is missing.** Local-mode dev now does an
  early check and prints an actionable message: which extras to
  install, or how to fall back to the Docker stack. No traceback.
- **`admina doctor` no longer reports "All checks passed" when
  `admina dev` is guaranteed to fail.** Missing `[proxy]` is now a
  surfaced issue with the exact upgrade command.
- **`admina doctor` extras table fixed.** `numpy` and `scikit-learn`
  are now correctly grouped under `[proxy]` (where they actually
  belong since 0.9.2), not `[nlp]`.
- **`admina doctor` spaCy diagnostic is venv-safe.** Previously
  suggested `python -m spacy download en_core_web_sm`, which on uv
  managed virtualenvs silently installs into a different interpreter
  (the one that owns `pip` on PATH). The new message points at the
  canonical `python -m spacy download` command **and** the direct
  wheel URL (`uv pip install <github-url>`) so users on either tool
  have a path that lands the model in the right venv. The missing
  model is now a soft warning (PII redaction still works in
  regex-only mode), not a `doctor` failure.
- **`admina init` "Next steps" adapts to the install.** Only suggests
  `admina dev` when `[proxy]` is installed; only suggests `admina dev
  --stack` when Docker is on PATH. Missing prerequisites are surfaced
  inline with the upgrade command. `python main.py` is always shown
  because the SDK works with any install.

### Docs

- README Quick Start leads with `pip install
  "admina-framework[proxy]"` (the install that makes `admina dev`
  work). `pip install admina-framework` (SDK only) is demoted to an
  "Advanced" footnote for users embedding the SDK without the local
  dev server.

---

## [0.9.2] — 2026-05-22

Hotfix release. Fixes three day-one bugs that prevented new users from
seeing a working `admina dev` after `pip install`.

### Fixed

- **`admina dev` now boots with `[proxy]` only.** Previous versions
  crashed at startup with `ModuleNotFoundError: No module named 'spacy'`
  unless the `[nlp]` extra was also installed. spaCy is now imported
  lazily; without it, PII redaction runs in regex-only mode (still
  covers email, phone, SSN, IBAN, IP, credit card and EU national IDs).
- **`numpy` and `scikit-learn` moved from `[nlp]` to `[proxy]`.** They
  are core dependencies of the LoopBreaker (proxy guardrail), not
  NLP-specific. `pip install admina-framework[proxy]` now installs
  everything the proxy actually needs.
- **Dashboard no longer blanks out when one endpoint fails.**
  `/api/dashboard/infra` previously returned HTTP 500 when
  `UPSTREAM_MCP_URL` was empty or unreachable, which (via `Promise.all`
  in the SPA) blanked every widget. The endpoint now reports
  `not_configured` / `unreachable` cleanly, and the dashboard uses
  `Promise.allSettled` so a single failing endpoint never wipes the
  rest of the UI.
- **`admina doctor` no longer prints tracebacks for missing optional
  plugin dependencies.** A plugin whose import fails because of a
  missing optional dep now logs a single `Skipping plugin … — optional
  dependency '…' not installed` line. Real plugin bugs still log a full
  traceback.

### Internal

- Funding link in `.github/FUNDING.yml` points to the dedicated sponsor
  landing page (`https://admina.org/sponsor/`).
- **admina-core bumped to 0.9.2 (sync release)** — no Rust changes,
  but the crate / wheel / sdist versions now track admina-framework so
  the two artefacts always carry the same number on PyPI, crates.io,
  and ghcr.io. From this release on, every published artefact in the
  monorepo (admina-framework, admina-core, admina-proxy image,
  admina-dashboard image) ships with the same version. A new CI job
  (`scripts/check-versions.py`) blocks PRs that drift the manifests
  out of alignment.

---

## [0.9.1] — 2026-05-21

Hotfix release.

### Fixed

- **admina-core**: now ships as a single `abi3-py311` wheel and uses
  `dynamic_lookup` on macOS, so the same artefact loads cleanly on any
  Python 3.11+ interpreter.
- **admina-framework[nlp]**: the `en_core_web_sm` spaCy model is no
  longer declared as a direct dependency (PyPI does not accept URL-pinned
  deps in published wheels). After installing the `[nlp]` extra, run
  `python -m spacy download en_core_web_sm`.
- **Release pipeline**: the admina-core wheel matrix temporarily
  excludes Intel Mac (`macos-13`) due to runner availability. Intel Mac
  users install from sdist.

### Notes

- `admina-core 0.9.0` is yanked; install `admina-core 0.9.1` or later.
- `admina-framework 0.9.0` continues to work standalone (pure-Python
  governance pipeline) — upgrading is only required if you also install
  `admina-core`.

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

[Unreleased]: https://github.com/admina-org/admina/compare/v0.9.3...HEAD
[0.9.3]: https://github.com/admina-org/admina/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/admina-org/admina/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/admina-org/admina/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/admina-org/admina/releases/tag/v0.9.0
