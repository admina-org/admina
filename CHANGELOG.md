# Changelog

All notable changes to Admina are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Admina is pre-1.0: the public API is feature-complete and production-ready,
but may still evolve in response to early-adopter feedback before the 1.0
stability commitment. See [ROADMAP.md](ROADMAP.md) for planned milestones.

---

## [Unreleased]

### Fixed

- **`ADMINA_GOVERNANCE_MODE` is now honoured.** The proxy `Settings` field
  declared no alias, so pydantic bound it to the bare name `GOVERNANCE_MODE`
  and — because the model is configured with `extra="ignore"` — the
  prefixed variable was silently discarded with no error, despite being the
  name advertised by the field's own comment, `admina.yaml.example`,
  `admina doctor`, and the dashboard. It now declares
  `validation_alias="ADMINA_GOVERNANCE_MODE"`, matching the
  `ADMINA_GUARD_FAIL_MODE` precedent. **Note:** the undocumented bare
  `GOVERNANCE_MODE` variable is no longer accepted; a deployment relying on
  it silently reverts to the `enforce` default, so switch it to the prefixed
  name. The bare `LOOP_*` and `INJECTION_*` variables are unaffected — those
  are read directly from the environment by `admina/core/config.py` and stay
  unprefixed.
- `make status` and `scripts/generate_docs.py` referenced top-level
  `proxy/`, `domains/`, `sdk/`, `core/` and `plugins/` directories that have
  not existed since the package was consolidated under `admina/`. Both now
  use the real paths, and `engine_status` is imported from `admina.engines`.

## [0.11.0] — 2026-07-15

Streaming, gateway, and PII-engine release. Adds response streaming with
inline PII redaction on `GovernedModel`, an OpenAI-compatible governance
gateway, a selectable Microsoft Presidio PII engine, an HMAC-signed
forensic chain-state file, and a configurable guard fail mode. Includes one
breaking change — the `/api/v1/validate` action `MODIFY` is renamed to
`REDACT` (permitted under the pre-1.0 posture: the public API may still
evolve before the 1.0 stability commitment).

### Added

- **Configurable guard fail mode** (`ADMINA_GUARD_FAIL_MODE=open|closed`,
  default `open`). When a pluggable governance guard raises, `open` keeps the
  current behavior (the guard is skipped and recorded as an `ERROR` check);
  `closed` turns the exception into a `BLOCK`. Enforced on the request-side
  pipeline of every governed surface — SDK `GovernedModel.ask()` and
  `.stream()`, the MCP proxy (`mcp_proxy`), and the OpenAI-compatible gateway
  (`/v1/chat/completions`) — and, MCP-proxy-only, on response inspection —
  where a fail-closed block also writes an explicit forensic `ERROR` record,
  since the request-side record is written before response inspection runs.
- Forensic chain-state file (`_chain_state.json`) can be signed with
  HMAC-SHA256. Set `ADMINA_FORENSIC_STATE_KEY` (or pass `state_signing_key=`)
  to enable: on restore a valid signature is trusted (fast path); a missing or
  invalid signature is treated as untrusted — a CRITICAL event is logged and
  the chain state is reconstructed from the immutable records instead of the
  (potentially rewritten) state file. With no key set the state file is
  unsigned: baseline truncation protection via record reconstruction is
  retained, and signing is recommended in production. Applies to
  `ForensicBlackBox` (filesystem + S3 backends) and the `FilesystemForensicStore`
  plugin; the signature is stored in a `_chain_state.json.sig` sidecar.
- **SDK streaming.** `GovernedModel.stream(prompt)` yields PII-redacted
  response deltas as an async iterator, with the full governance outcome in
  `GovernedModel.last_stream_result`. The pre-stream gate matches `ask()`:
  a blocked prompt yields no deltas and reports `action="BLOCK"` (no
  exception).
- **`StreamRedactor`** (`admina.sdk.StreamRedactor`) — a windowed
  recomposition buffer that redacts PII spanning streamed-delta boundaries.
  `window_chars` must exceed the longest expected entity.
- **`BaseModelAdapter.send_stream()`** — an async-iterator streaming method
  on the adapter contract. Real streaming for the OpenAI, Ollama, vLLM, and
  Anthropic adapters; the Mistral, Gemini, and Bedrock adapters use the base
  single-chunk fallback pending a follow-on.
- **Presidio PII engine.** Microsoft Presidio is selectable as the PII engine
  via `ADMINA_PII_ENGINE=presidio` or `pii_engine: presidio` in `admina.yaml`,
  behind the new `[presidio]` extra. Presidio performs detection only; Admina
  keeps its own masking, so the output format is identical to the default
  `spacy-regex` engine (per-category masks, e.g. `[EMAIL]`, `[PERSON]`).
  Languages EN + IT. The default engine is unchanged (`spacy-regex`). The
  redteam efficacy suite measures Presidio as a third PII column with
  version/language mode-pinning.
- **OpenAI-compatible governance gateway** — a new `/v1` HTTP surface on
  the proxy (`POST /v1/chat/completions`, streaming and non-streaming, plus
  `GET /v1/models`). Requests are forwarded to a configurable upstream
  (`ADMINA_GATEWAY_UPSTREAM`) over httpx while the canonical governance
  pipeline runs inline: prompts are firewall-checked and PII-redacted before
  they reach the upstream, streamed responses are redacted through a
  windowed recomposition buffer, and a blocked request returns a synthetic
  completion (or SSE stream) with `finish_reason: "content_filter"` instead
  of a raw HTTP error. Every request is written to the forensic log. This is
  the proxy's first SSE surface. Protected by the existing credential check
  (`Authorization: Bearer` / `X-API-Key`).

### Breaking

- **`/api/v1/validate` renames the `MODIFY` action to `REDACT`.** When a
  request is allowed but PII was redacted, the response `action` is now
  `"REDACT"` (was `"MODIFY"`); `redacted_content` is populated on `REDACT`
  exactly as before. This aligns the REST vocabulary with the internal
  `GovernanceAction.REDACT` value. The `CIRCUIT_BREAK → BLOCK` mapping is
  unchanged. No compatibility shim is carried: the in-repo n8n node,
  CheshireCat plugin, and OpenClaw skill are updated in the same change,
  and external callers must switch to `REDACT`. Admina is pre-1.0, so the
  public API may still evolve before the 1.0 stability commitment.

### Fixed

- The proxy `/mcp` forensic record now carries `would_action` — the shadow
  decision recorded in `observe` / `dry-run` mode — matching the
  ClickHouse analytics record. Previously the shadow decision reached only
  ClickHouse, leaving the hash-chained audit trail without it.

## [0.10.1] — 2026-06-17

Security patch release. Updates two dependencies flagged by upstream
advisories. No API or behaviour changes.

### Security

- **cryptography** updated to 49.0.0 (from 47.0.0), resolving the
  high-severity advisory affecting `< 48.0.1`. The dependency constraint
  ceiling is widened from `<48` to `<50`.
- **pyo3** — the Rust binding behind the optional `admina-core` accelerator
  — updated 0.24 → 0.29, resolving the high + medium RUSTSEC advisory
  affecting `< 0.29.0`. The binding is migrated to the pyo3 0.29 `attach`
  API (`Python::with_gil` → `Python::attach`, `PyObject` → `Py<PyAny>`).
  No functional change: the Rust engines remain at parity with the Python
  implementations, verified by the full suite with `admina-core` installed.

## [0.10.0] — 2026-06-16

Model-adapter and governance-unification release. Five new provider
adapters, configurable retry/backoff on the governed primitives, a uniform
engine-selection switch across proxy/SDK/integrations, and a set of auth,
forensic, and correctness hardening fixes.

### Added

- **Five new model adapters**, each a built-in plugin that lazy-imports its
  provider SDK so the dependency is only required when the adapter is used:
  - **Anthropic** — `admina-framework[anthropic]`.
  - **Mistral** — `admina-framework[mistral]`; wraps `mistralai` chat
    completions (`ADMINA_MISTRAL_API_KEY` / `ADMINA_MISTRAL_MODEL`).
  - **AWS Bedrock** — `admina-framework[bedrock]`; wraps the `boto3`
    Converse API using the standard AWS credential chain
    (`ADMINA_BEDROCK_REGION` / `ADMINA_BEDROCK_MODEL`).
  - **Google Gemini** — `admina-framework[gemini]`; wraps `google-genai`
    generate-content (`ADMINA_GEMINI_API_KEY` / `ADMINA_GEMINI_MODEL`).
  - **vLLM** — an OpenAI-compatible adapter pointed at a local vLLM server
    (`http://localhost:8000/v1` by default; `ADMINA_VLLM_BASE_URL` /
    `ADMINA_VLLM_MODEL`, model required).
- **Per-provider packaging extras** `[anthropic]`, `[mistral]`, `[bedrock]`,
  `[gemini]`, `[openai]`, `[ollama]`, plus the `[adapters]` roll-up (all
  providers) and the `[all]` roll-up (`[proxy,nlp,telemetry,adapters]`).
- **Configurable retry/backoff on the governed primitives.** `RetryPolicy`
  and a vendored `run_with_retry` executor (no new dependency) let
  `GovernedModel`, `GovernedAgent`, and `GovernedData` retry transient
  upstream/connector failures, opt-in via `retry=RetryPolicy(...)` (default
  is unchanged: a single attempt). Tunable with `ADMINA_RETRY_*` env knobs;
  callers and adapters can mark errors with `RetryableUpstreamError` /
  `TerminalUpstreamError`. `GovernedData` never retries past a residency
  refusal (raised before the region is contacted).
- **`ADMINA_ENGINE=auto|python|rust`** selects the governance-engine backend
  uniformly across proxy, SDK, and integrations (an unrecognized value
  raises). Engines (firewall, PII, loop breaker) are now acquired through a
  single `admina.engines` package.
- **Typed firewall config:** `agent_security.firewall.custom_patterns` and
  `agent_security.firewall.disabled_categories`. The `admina.yaml` `plugins:`
  list and a new `plugin_config:` block are wired into plugin discovery and
  instantiation; a plugin whose `__init__` accepts a `config` parameter
  receives its block.
- **Forensic chain verification is now reachable**, reporting hash-chain
  integrity via `admina doctor` and `GET /api/v1/forensic/verify`
  (verification was previously never invoked by any wired path).

### Changed

- **Behavior change — `GovernedModel.ask()` now runs full governance by
  default.** It runs the injection firewall on the prompt and any pluggable
  guards (was PII-only) and can return `action="BLOCK"` with empty text;
  `GovernedResponse` gains an `action` field (default `"ALLOW"`). Opt out per
  stage with `GovernedModel(firewall_enabled=False, governance_guards=...,
  loop_detection=...)`. Loop detection runs only when a `session_id` is
  supplied per call.
- **SDK and LangChain/CrewAI callbacks now acquire engines via
  `admina.engines`.** They gain Rust acceleration for the firewall and loop
  breaker under `ADMINA_ENGINE=auto` when `admina-core` is installed, and they
  now honor `admina.yaml` firewall overrides (`custom_patterns` /
  `disabled_categories`) — both previously proxy-only. PII redaction stays on
  the Python engine by default for full recall (the Rust scanner does not
  cover EU national IDs or NER person/org names); Rust PII is opt-in via
  `ADMINA_ENGINE=rust`.
- **One canonical governance pipeline.** `POST /mcp`, `POST /api/v1/validate`,
  and the SDK governed primitives now all run the same pipeline in the same
  order (loop → firewall → PII → guards). `GovernedAgent` keeps a stable
  per-instance session so loop detection works across calls.

### Security

- **Closed a fail-open default.** A proxy started with no `ADMINA_API_KEY` no
  longer authenticates every request as admin: the keyless built-in API-key
  provider is now fail-closed and is not loaded. With no key and no auth
  providers, protected requests are rejected unless
  `ALLOW_UNAUTHENTICATED=true` is explicitly set, and the proxy logs a loud
  startup warning.
- **Dashboard live WebSocket authentication and origin checks.** The live
  feed now validates the signed `admina_session` session cookie (it
  previously compared the signed token against the raw API key and always
  failed when a key was set), and the WebSocket upgrade enforces an Origin
  allow-list (`CORS_ORIGINS`) to mitigate Cross-Site WebSocket Hijacking.
  Absent-Origin (non-browser) clients still require a valid credential; `'*'`
  in `CORS_ORIGINS` opts into allowing any origin.
- **Built-in API-key provider accepts the signed dashboard cookie** (it
  previously treated the cookie as a raw key and rejected valid browser
  sessions). HTTP, WebSocket, and provider auth now share one credential
  verifier so they cannot drift.
- **Forensic store hardening.** The store now reconstructs its hash-chain
  state from the persisted records when the state file is missing or corrupt,
  instead of silently restarting from GENESIS (which forked or overwrote the
  audit trail); a corrupt state file is logged at ERROR. Concurrent writes are
  serialized to prevent chain forks, and `verify_chain` anchors against the
  persisted record count and chain head so a truncated tail is detected as
  invalid. The `FilesystemForensicStore` plugin gets the same hardening.

### Fixed

- **EU AI Act gap analysis no longer reports a false `COMPLIANT`.** Each
  requirement's declared checks are padded to the canonical count, so
  supplying a bool or a short check-list no longer inflates the compliance
  score (unspecified checks count as unmet); `generate_report` also accepts a
  bare `bool` in `current_compliance` without raising `TypeError`.
- **Credit-card PII detection now validates the Luhn checksum** (Python
  engine), eliminating false positives on arbitrary 16-digit numbers.
- **PII scanning covers dict keys, not only values.** The proxy now redacts
  PII in dict-shaped MCP tool results (previously only plain-string results
  were redacted), and the plugin PII engine merges overlapping detections into
  non-overlapping spans before redaction (no text corruption or leftover
  fragments). `GovernedData.ingest()` classifies the actual ingested content
  rather than misclassifying an opaque source locator (file path, URL) as
  content; opaque sources are flagged `source_scanned=false`.
- **`/api/v1/validate` delegates to the canonical pipeline.** It honors
  `GOVERNANCE_MODE` (observe/dry-run), normalizes `risk_level` casing, and
  reports loop detection (CIRCUIT_BREAK) as `action="BLOCK"` to REST consumers
  (the consumer contract is preserved for n8n / CheshireCat / OpenClaw). Note:
  on a blocked request the `checks` object no longer carries a
  `pii_redaction` entry (PII is not run after a block) — read it with
  `.get()`.
- **Config and observability fixes.** `admina.yaml` `schema_version` is now
  parsed (was silently ignored); OISG criterion S2 reads the configured API
  key; and observe / dry-run "would-have-blocked" decisions now persist to the
  audit trail and reach the dashboard policy-suggestion engine (previously
  always zero).
- **Plugin and scaffolding fixes.** Built-in plugins register under their
  declared `name` (e.g. `ollama`, `apikey`) instead of a lower-cased class
  name; `admina plugin new` scaffolds working plugins (async methods matching
  every ABC, correct `admina-framework` dependency floor, Python 3.11
  requirement, and an `admina.plugins` entry-point); and `admina init`
  scaffolds docker-compose image tags from the framework version instead of a
  hardcoded stale tag.
- **A pluggable governance guard that violates its contract** is now logged at
  ERROR and recorded in the decision's checks (was a silent skip), so a broken
  guard is visible in the audit trail.
- **OpenAI and Ollama adapters offload their blocking SDK calls** via
  `asyncio.to_thread` (consistent with the new adapters), so the event loop is
  not blocked and per-attempt retry timeouts can fire.

### Internal

- `admina/proxy/engine_bridge.py` is now a re-export shim over
  `admina.engines`. The duplicated SDK adapter/connector ABCs were removed —
  `admina.sdk` re-exports the canonical `admina.plugins.base` definitions — and
  the dashboard SPA is single-sourced from the packaged copy.

### Documentation

- Corrected the MODEL_CARD engine-equivalence claim (the Rust and Python
  firewall/PII engines differ — measured, not equivalent) and aligned the
  documented governance pipeline order (loop → firewall → PII → guards).

## [0.9.5] — 2026-06-07

Stabilisation release (0.9.x).

### Removed

- **Legacy MinIO-SDK forensic backend.** The `minio` Python SDK (archived
  upstream) is no longer a dependency, and `FORENSIC_BACKEND=minio` is gone.
  MinIO servers remain fully supported through the `s3` backend (boto3) —
  point `FORENSIC_S3_ENDPOINT` at the server. `FORENSIC_BACKEND=minio` now
  routes to the `s3` backend with a migration warning. The unused
  `MinIOForensicStore` plugin and the `MINIO_*` settings/secrets were
  removed; the dev `docker-compose.yml` and `admina init` templates use the
  filesystem backend.

### Changed

- **Default forensic store is now `filesystem`** in `admina.yaml` and the
  generated project templates (was `minio`).

### Documentation

- README image and file links are now absolute (GitHub raw / blob URLs) so
  they render on PyPI. README, guides, and templates describe the
  `filesystem` / `s3` backends; MinIO is documented as one of the
  S3-compatible servers reachable via the `s3` backend.

### Internal

- Silence third-party deprecation warnings (OpenTelemetry SelectableGroups,
  Starlette TestClient httpx) via pytest `filterwarnings`; the SDK
  import-isolation test uses the modern `find_spec` finder API.

## [0.9.4] — 2026-06-06

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

- **Forensic store consolidated on one hash-chain model.**
  `ForensicBlackBox` (the proxy's audit trail) now implements the
  `BaseForensicStore` plugin interface (`append` / `verify_chain(last_n)` /
  `store_name`); its previous list-based `verify_chain(records)` is renamed
  `verify_records(records)`. The unused colon-string hash-chain bridge
  (`get_hash_chain`, `_PythonHashChainBridge`, `_RustHashChainBridge`) is
  removed from `proxy/engine_bridge.py` — the proxy never used it. **Breaking:**
  callers of `ForensicBlackBox.verify_chain(records)` should use
  `verify_records(records)`; `engine_bridge.get_hash_chain()` is gone.

### Documentation

- README install and Performance sections state the Rust engine is
  opt-in via `[rust]` and document the firewall detection trade-off
  between the two engines.

### Internal

- Raise the test coverage gate from 70% to 78% (current coverage 80%)
  to lock in the forensic and firewall test additions.

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

[Unreleased]: https://github.com/admina-org/admina/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/admina-org/admina/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/admina-org/admina/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/admina-org/admina/compare/v0.9.5...v0.10.0
[0.9.5]: https://github.com/admina-org/admina/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/admina-org/admina/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/admina-org/admina/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/admina-org/admina/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/admina-org/admina/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/admina-org/admina/releases/tag/v0.9.0
