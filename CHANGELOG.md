# Changelog

All notable changes to Admina are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Admina is pre-1.0: the public API is feature-complete and production-ready,
but may still evolve in response to early-adopter feedback before the 1.0
stability commitment. See [ROADMAP.md](ROADMAP.md) for planned milestones.

---

## [Unreleased]

## [0.13.1] — 2026-10-06

Patch release: the compose file of `admina init` binds the dashboard, OTEL
and the local LLM services to loopback and has no default passwords; a
forensic store with signed records refuses to start without its key in
`closed` mode; the egress walk reaches the governance scan depth (32);
distinct block reasons on `/mcp`; the Admina Score and OISG read the chain
status and the dashboard switches; documentation aligned with the code of
0.13.0. Upgrading is recommended.

### Security

- `admina init` writes a compose file with the dashboard on
  `127.0.0.1:3000`, signed in with `ADMINA_DASHBOARD_PASSWORD` and the API
  key as in the repository `docker-compose.yml`. OTEL (4317, 4318), Ollama,
  ChromaDB and Open WebUI are published on `127.0.0.1` only. ClickHouse and
  Grafana have no default passwords: `CLICKHOUSE_PASSWORD` and
  `GRAFANA_ADMIN_PASSWORD` come from the `.env` that `admina dev` writes,
  and `docker compose` stops when they are not set. The generated `.env`
  holds the secrets of the vault, and no placeholder key.
- A forensic store that holds signed records (an integer `signed_from` in
  its chain state, or the `_chain_state.json.sig` sidecar) and starts
  without `ADMINA_FORENSIC_STATE_KEY` raises `ForensicKeyError` under
  `ADMINA_FORENSIC_FAIL_MODE=closed`, and the proxy does not start. Under
  `open` it logs a warning at every start and writes unsigned records, as
  in 0.13.0. To drop the key on purpose, move the store aside.

### Changed

- The JSON-RPC error of a blocked `/mcp` call carries a `data.reason` per
  cause: `injection_detected` (firewall), `scan_depth_exceeded`,
  `egress_refused`, `guard_blocked` (a request guard, also a guard error
  under `ADMINA_GUARD_FAIL_MODE=closed`) and `response_blocked` (a response
  guard). In 0.13.0 every block reported `injection_detected`. `code` and
  `message` are unchanged.
- `agent_security.firewall.heuristic_threshold` is checked by the
  configuration (a finite number greater than 0) whichever firewall engine
  runs: an invalid value raises `ConfigSchemaError` (`ConfigFileError` for
  the file named by `ADMINA_CONFIG`). The Rust engine ignored it.
- The Admina Score gives no `interactions_audited` (+25) and
  `forensic_chain_valid` (+10) points, and OISG G2 is not satisfied, when
  the forensic chain status is `invalid`. The "no blocked requests"
  criterion counts since the proxy started; the dashboard label says so.
- OISG G4 follows `ADMINA_DASHBOARD_ENABLED` and `ADMINA_ENABLED_SURFACES`,
  as the dashboard itself does, and G4 and O3 count OTEL only when the
  exporter exports spans (`OTEL_ENABLED`).
- `admina dev` local mode uses the forensic backend of `FORENSIC_BACKEND` or
  of `admina.yaml`, and memory when neither sets one; it set
  `FORENSIC_BACKEND=memory`. The startup banner names the backend and its
  source.
- The proxy of the `admina init` compose file reaches the MCP server at
  `UPSTREAM_MCP_URL`, default `http://host.docker.internal:9000`.

### Fixed

- The egress walk of tool-call arguments goes as deep as the governance
  scan (`SCAN_DEPTH`, 32 levels). It stopped at 6, so under
  `ADMINA_EGRESS_MODE=enforce` a call nested 7 to 31 levels deep passed the
  firewall and was refused by egress.
- The `413` of `MAX_REQUEST_TOKENS` on `/mcp` carries the `event_id` in
  `error.data`, as the other `/mcp` errors do.
- `admina init` with modules that do not include compliance writes a valid
  compose file: the proxy depended on a ClickHouse service that was not in
  the file.
- `admina plugin list` lists the MCP transport adapter (`mcp`).
- The LangChain and CrewAI callbacks raise an `ImportError` that names the
  `[proxy]` extra and `loop_detection=False` when scikit-learn is missing;
  their READMEs install `[proxy,nlp]`.
- The dashboard suggestions name `LOOP_MAX_CONSECUTIVE` and
  `LOOP_SIMILARITY_THRESHOLD`, and say to raise the similarity threshold to
  detect fewer loops.
- The `# HELP` of `admina_avg_latency_ms` describes the mean request
  duration since startup, upstream included.
- `admina.yaml.example`: `admina egress suggest-allowlist --since 7` (a
  number of days), and no `agent_security.firewall.mode` key, which nothing
  reads; the governance mode is `ADMINA_GOVERNANCE_MODE`.

### Documentation

- The `[0.13.0]` entries, the 0.13 upgrade guide, MODEL_CARD, ROADMAP and
  README describe what the code of 0.13.0 does:
  - `?api_key=` is accepted only on the WebSocket upgrade of
    `/api/dashboard/live`, never on HTTP;
  - the 32-level scan-depth block applies to `/mcp` and to the gateway
    with the firewall on, not to `POST /api/v1/validate`;
  - `submitted_by` is `user:api_key_user` when the `apikey` provider is
    loaded, and `api_key` when the key comes only from
    `ADMINA_API_KEY_FILE` or `.env`;
  - the `401` and `413` of `/v1/chat/completions` carry `X-Admina-Ruleset`
    and not `X-Admina-Version`;
  - streams pass through unchanged only while PII redaction is off;
  - an invalid `from_seq` of `GET /api/v1/forensic/verify` is answered
    `422`;
  - the gateway has been counted in `admina_requests_total` since 0.12.2,
    and the dashboard feed without ClickHouse has no `/api/v1/validate`
    events;
  - the ruleset hash includes `admina_version` (and `admina_core_version`
    on Rust), so a pinned `gateway.prescan_rulesets` is recomputed after
    every upgrade;
  - `ADMINA_ENABLED_SURFACES` takes `gateway`, `mcp`, `integration`,
    `compliance` and `dashboard`.
- MODEL_CARD §5b states which strings egress reads as destinations (a
  string that begins with a URL, an IP literal as the whole string, every
  `image_url`, the `params` of every `/mcp` method); §3 states that
  `disabled_categories` takes any category name, pack and custom ones
  included.
- ROADMAP 0.12.0 states the egress coverage of each surface.

## [0.13.0] — 2026-10-05

Minor release: an OpenAI-compatible gateway for embedded deployments
(named upstream routes with keys, streams passed through unchanged while
PII redaction is off, upstream errors propagated, request limits, the
governance pipeline in worker threads, the governance outcome on every
response, request ids and W3C trace context, request and completion
records with hashes, the whole chat completion body in the scan), secrets
from files, `ADMINA_CONFIG`, `ADMINA_ENABLED_SURFACES`, the
`proxy-minimal` extra and an offline mode, linear-time pattern matching,
signed release images with a `-slim` variant, egress checks per surface, a
forensic store that writes atomically, signs each record, verifies from a
checkpoint and exports JSON Lines, PII engines from other packages with
value-only redaction and an `[OMISSIS]` mask style, per-surface request
metrics and governance events without request text, stable firewall
pattern ids with pattern packs and Italian baseline patterns, a schema
check of admina.yaml, the engines in use on `/health`, an OISG score from
external evidence, `admina redteam` on external corpora, a scan depth of
32 levels with a block past it on `/mcp` and the gateway, EU AI Act
classification of Italian, French and German descriptions, a versioned
ruleset document, and an upgrade guide (`docs/guides/upgrade-0.13.md`).
Upgrading is recommended; read the guide first, since several defaults and
failure modes change.

### Security

- Firewall patterns match in linear time on long inputs. Categories, risk
  levels and matching results are unchanged.
- PII redaction and the spaCy + regex PII engine match e-mail addresses in
  linear time on long inputs. Detected spans are unchanged.

- Each forensic record is signed: `record_sig` is the HMAC-SHA256 (64
  lowercase hex characters) of the ASCII characters of its `record_hash`,
  under a key derived from the chain-state key (`ADMINA_FORENSIC_STATE_KEY`
  or `_FILE`): HMAC-SHA256 of `admina-forensic/1 record signature` under that
  key; `record_sig_alg` is `hmac-sha256`. A record written without a key has
  `record_sig_alg: "none"` and no `record_sig`. `record_hash` is the SHA-256
  of `json.dumps(record, sort_keys=True, default=str)` of the record without
  `record_hash`, `record_sig` and `record_sig_alg`
  (`forensic_integrity.HASH_EXCLUDED_FIELDS`); for a record without the two
  signature fields it is computed as before. Verification with the key
  (the store's own, or `state_key` of `verify_directory()`, or the key in
  the environment of `admina forensic verify`) checks every signature
  (reason `signature_invalid`) and requires one from the chain state's new
  `signed_from` on (reason `unsigned`); it reports `signed`, `unsigned` and
  `signatures_verified`. Records written before a key was set are reported
  as unsigned. `record_signing_key()` and `sign_record_hash()` are in
  `admina.domains.compliance.forensic_integrity`.
- `ADMINA_FORENSIC_STATE_KEY_FILE` inside the forensic directory is refused
  (`SecretFileError`): the key that signs the chain state and the records is
  kept outside the store.
- The forensic chain state is rebuilt only from verified records. At
  startup a chain state that is missing (with records) or whose HMAC does
  not verify is rebuilt only when every stored record verifies with the key
  from record 1 on (sequence, hashes, links, signatures); the rebuild is
  logged at `CRITICAL` and recorded as a signed record of type
  `chain_state_rebuilt` (`EventType.CHAIN_STATE_REBUILT`, with `cause`,
  `records_verified`, `head_hash`). Without a key, or when a record does not
  verify, or when the last record of a valid chain state is missing or
  differs, the chain is invalid: `chain_status` is `invalid`, a `CRITICAL`
  log names the reason and the record, no record is written (in `closed`
  mode governed requests are answered `503`), and verification is never
  valid. A record found after the last saved chain state is counted only
  when it verifies and links to it.
- Verification requires contiguous sequence numbers from 1: a record
  missing before the first one found, between two records or before the
  chain state's count is reported as `missing_record`, and a sequence
  number that does not match its file, comes twice or out of order as
  `sequence_gap`. `verify_directory()` also checks the chain state's HMAC
  with the key and reports `state_missing` and `state_invalid`;
  `verify_bucket()` does the same for an S3 bucket, and `admina doctor`
  uses it, writing nothing.
- `GET /health` reports `forensic_chain`: `ok`, `rebuilt`, `invalid` (then
  `status` is `degraded`), or `null` without a stored chain.
- A record signature is valid only as 64 lowercase hex characters: any
  other `record_sig` is reported as `signature_invalid`, with or without the
  key. The HMAC sidecar of the chain state (`_chain_state.json.sig`, white
  space around it left out) is read as 64 lowercase hex ASCII characters;
  any other content, text that is not ASCII or bytes that are not UTF-8
  included, is an invalid chain-state signature (`state_invalid`; at
  startup the state is then rebuilt from verified records, or the chain is
  invalid). Signatures are compared in constant time as ASCII bytes
  (`forensic_integrity.hex_digest_matches()` and `stored_hex_digest()`), in
  the forensic store, `verify_directory()`, `verify_bucket()` and the
  built-in `filesystem` forensic store plugin.
- `POST /api/v1/audit` stamps each record: `source` is always
  `api_v1_audit` (a `source` sent by the caller is kept as `client_source`)
  and `submitted_by` is the credential the request was admitted with
  (`api_key`, `append_key`, `user:<id>` for an auth provider's user, or
  `unauthenticated`). With `ADMINA_API_KEY` in the environment the built-in
  `apikey` auth provider admits an API-key request, which is stamped
  `user:api_key_user`; `api_key` is the stamp when the key comes only from
  `ADMINA_API_KEY_FILE` or `.env` and no auth provider is loaded.
  `ADMINA_AUDIT_APPEND_KEY` (or `_FILE`) is a key accepted by this route
  only, besides the API key; every other route refuses it. Unset (the
  default), the route needs the API key. An `event_type` of the records the
  proxy writes itself (`mcp_request`, `mcp_response`, `gateway_request`,
  `gateway_response`, `gateway_response_scan`, `policy_violation`,
  `chain_state_rebuilt`; `integration.PROXY_RECORD_TYPES`, compared without
  case and surrounding white space) is refused with `400`, and nothing is
  recorded.
- PII redaction reads text values and keeps the structure around them.
  `_deep_redact` (MCP tool parameters and results, `GovernedAgent`) passes
  the values of a dict to the PII engine and keeps its keys;
  `redact_keys=True`, and `GovernedAgent(redact_keys=True)`, redacts the
  keys too. The gateway redacts the text of each chat message
  (`redact_chat_params` of `admina.domains.governance`, the new
  `redact_params` argument of `run_pipeline`): `content`, as a string or as
  the `text` of each part, reasoning and refusal text, and tool call
  `arguments`; roles, names, tool call ids, image and audio parts are
  forwarded as received. A request whose PII redaction masked text but
  returned no list of messages is blocked in every governance mode,
  answered as `ADMINA_GATEWAY_BLOCK_STATUS` says with
  `X-Admina-Action: BLOCK`, recorded with `checks["pipeline"]`
  (`{"action": "ERROR", "error": "redacted_messages_missing"}`) and logged
  as an error.
- A mask of Admina already in the text (a placeholder: the `mask` of a
  category of `PII_CATEGORIES`, such as `[IBAN]` or `[LOCATION]`, a category
  name in square brackets, such as `[IP_ADDRESS]`, or `[OMISSIS]`) is not
  masked again: the NER step of the `spacy-regex` engine, the `presidio`
  engine and `PIIEngineBridge` mask a detected span only outside the
  placeholders. Other text in square brackets is masked like any other text
  (`masking.placeholder_pattern()`).
- The `presidio` engine masks overlapping detections as one span, their
  union, with the category and mask of the first.
- The `governance.decision` event of an `/mcp` request carries names,
  counts and hashes (`admina.proxy.decisions.Decision`): its metadata is
  `surface`, `event_id` (of the request's forensic record), `domain` (the
  part of the pipeline that decided), `latency_us`, `categories` (firewall
  category names), `pii_count`, `request_sha256` (the SHA-256 of the
  JSON-RPC request as the proxy serialises it) and, in `observe` and
  `dry-run` mode, `would_action`. The dashboard live feed, the OpenTelemetry
  exporter (a span attribute `admina.meta.<key>` per key) and the alert
  channels read this metadata.
- A blocked `/mcp` request sends one alert to each alert channel, built from
  its `governance.decision` event: `details` is the event's metadata.
- An exception raised while a request or a response is governed on the
  gateway, `/mcp` or `POST /api/v1/validate` (by a governance guard, the PII
  engine, the pipeline or the upstream exchange) is logged by its class
  name, and at `DEBUG` with the frames of its traceback, without its message
  (`admina.core.exception_log`). The `error` of a guard's `ERROR` check
  (`checks["guard_<name>"]`, request or response side, in the forensic
  records and the ClickHouse `details`) is the exception's class name. An
  `/mcp` request whose governance pipeline raises is answered `500`
  (JSON-RPC `-32603`, `Internal proxy error`), and so is one that raises
  after the upstream answered; a `POST /api/v1/validate` request whose
  pipeline raises is answered `500` (`{"detail": "Internal Server
  Error"}`).
- The firewall of the gateway scans every string of a chat completion
  request, keys included: the messages (content, names, tool calls), the
  tool definitions (`tools`), `response_format` and any other field of the
  body. The `arguments` of a tool call (and of a legacy `function_call`) are
  scanned as the JSON they hold, each string separately, and as they are
  when they are not JSON. `ADMINA_GATEWAY_SCAN_ROLES` and
  `X-Admina-Scan-Policy` narrow the messages only. With the firewall on, a
  request whose body has a string nested more than 32 levels deep, or tool
  call arguments nested deeper than the JSON parser reads, is blocked in
  `enforce` mode
  (`would_action` in `observe` and `dry-run`), with `checks.scan_depth =
  {"action": "BLOCK", "reason": "depth_limit_exceeded"}` in its record.
  `request_texts()` of `admina.domains.agent_security.scan_policy` collects
  the texts and reports `truncated`; `run_pipeline(scan_truncated=True)`
  blocks.
- `ADMINA_GATEWAY_MODELS_ALLOWLIST` applies to `POST /v1/chat/completions`
  too: a request for a model outside the list, or without a model, is
  answered `403` (`{"error": {"message", "type": "invalid_request_error",
  "param": "model", "code": "model_not_allowed"}}`) before any governance
  check, forensic record or upstream call. An empty list (the default) lets
  every model through.
- The dashboard container of `docker-compose.yml` (`dashboard/`) adds
  `ADMINA_API_KEY` only to the dashboard's read-only routes
  (`/api/dashboard/*`, its live feed, `/api/stats`); `/mcp` and the other
  `/api/` routes are forwarded as received, with the caller's own key. With
  `ADMINA_API_KEY` set the container does not start without
  `ADMINA_DASHBOARD_PASSWORD` (HTTP Basic Auth), and it refuses a key with
  characters other than letters, digits and `. _ ~ + / = -`. Without the
  key it sends no key header, and the dashboard page signs in with the key.
  Compose publishes the dashboard on `127.0.0.1:3000`.
- PII redaction builds the masked text in one pass over the detected spans
  (`masking.replace_spans()`), in the regex and NER steps of `PIIRedactor`,
  the `presidio` engine and the spaCy + regex PII engine: its time grows
  linearly with the length of the text, however many spans it masks. The
  masked text is unchanged.

- **A rebuilt forensic chain state stays visible.** After the chain state
  was rebuilt from the records, `forensic_chain` was `rebuilt` until the
  next restart, then `ok`: removing the last records together with the
  chain state left no lasting trace. The chain state now keeps the rebuild
  (`rebuilt`: cause, record count, time) and `/health` reports `rebuilt`
  until it is acknowledged.
- **A forensic record whose JSON repeats a key does not verify**
  (`hash_mismatch`). The hash was computed on the record as Python's parser
  reads it, which keeps the last of the repeated values, while another
  parser of an exported record can keep the first.
- **`/mcp` refuses text it cannot scan.** The pipeline of `/mcp` and
  `/api/v1/validate` scanned and redacted strings down to 6 levels of
  nesting and let deeper text through unscanned and unredacted: an
  injection nested in five objects inside a tool call's `arguments` was
  allowed. The pipeline now scans and redacts 32 levels deep, as the
  gateway does, and on `/mcp`, with the firewall or PII redaction on, a
  request holding text deeper than that is blocked in `enforce` mode (a
  would-be block in `observe` and `dry-run`), with `checks.scan_depth =
  {"action": "BLOCK", "reason": "depth_limit_exceeded"}`.
  `admina.domains.governance.SCAN_DEPTH` is the limit. `POST
  /api/v1/validate` takes a string `content` only (see Changed), so its
  body never reaches that depth and the block does not apply there.
- The Presidio PII engine (`ADMINA_PII_ENGINE=presidio`) asks the analyzer
  only for the entity types it maps to Admina categories. It ran every
  Presidio recognizer and discarded the other results; the URL recognizer
  took about 1.2 ms per character on text with many dots (80 seconds on
  64,000 characters). Detected spans are unchanged.

### Added

- Local make targets that mirror the CI jobs: `make ci-local`, `make ci-linux`
  and `make ci-audit` (see `make help`). `make ci-linux` runs its container on
  the CPUs in `CI_LINUX_CPUS` (default `0-3`, the size of a hosted runner).
- Pattern timing probe, `admina.domains.agent_security.pattern_timing`:
  `probe_pattern()` returns the worst search time of a regular expression on
  generated 64k-character inputs (trigger words followed by runs of spaces,
  tabs, commas or newlines, and repeated triggers); `measure_pattern()` also
  names the slowest input. Use it to check
  `agent_security.firewall.custom_patterns` before deploying them.
- Named upstream routes for the OpenAI-compatible gateway.
  `ADMINA_GATEWAY_UPSTREAMS` (`name=url[,name=url…]`) or `gateway.upstreams`
  in `admina.yaml` (`<name>: {url, api_key_file}`) define the routes; the
  environment variable, when set, replaces the YAML routes.
  `gateway.default_upstream` names the route used when a request names none
  (default: the first route). A request selects a route with the
  `X-Admina-Upstream` header on `POST /v1/chat/completions` and
  `GET /v1/models`; an unknown route name gets a 400 response in the OpenAI
  error format (`invalid_request_error`, code `unknown_upstream`) before
  any governance check or forensic record. Without named routes the gateway
  has one route, `default`, to `ADMINA_GATEWAY_UPSTREAM`. The
  `gateway_request` forensic record carries the route name (`upstream`).
- Upstream API keys for the OpenAI-compatible gateway, sent as
  `Authorization: Bearer <key>`: `ADMINA_GATEWAY_UPSTREAM_API_KEY` or
  `ADMINA_GATEWAY_UPSTREAM_API_KEY_FILE` for every route, overridden per
  route by `ADMINA_GATEWAY_UPSTREAM_<NAME>_API_KEY[_FILE]` (`<NAME>`: route
  name in upper case) or by the route's `api_key_file`. Key files are read
  once at startup, with one trailing newline removed. The proxy does not
  start when a key file is missing, unreadable or empty, when a key is set
  both directly and as a file, when a route is malformed or when
  `default_upstream` names no route. Keys are masked in the settings
  representation and are not logged. Without a key no `Authorization`
  header is sent. The caller's `Authorization`, `X-API-Key`, `Cookie` and
  `X-Admina-Upstream` headers are not forwarded upstream.
- `admina.core.secretfile`: `read_secret_file()` and `resolve_secret()`
  resolve a secret setting given directly or as `<SETTING>_FILE`.
- Request body cap on every route: `ADMINA_MAX_REQUEST_BYTES` (default
  10 MiB, `0` = no limit). A body over the cap gets 413 before it is
  parsed: at once when its `Content-Length` is over the cap, otherwise as
  soon as the bytes read go over it. The 413 body is in the OpenAI error
  format on `/v1` (`invalid_request_error`, code `request_too_large`) and
  `{"detail": ...}` elsewhere.
- Upstream timeouts and connection pool of the OpenAI-compatible gateway,
  which has an HTTP client of its own: `ADMINA_GATEWAY_TIMEOUT_CONNECT` and
  `ADMINA_GATEWAY_TIMEOUT_READ` (default 30 seconds),
  `ADMINA_GATEWAY_TIMEOUT_TOTAL` (the whole upstream exchange; default 0),
  `ADMINA_GATEWAY_MAX_CONNECTIONS` (default 100) and
  `ADMINA_GATEWAY_MAX_KEEPALIVE_CONNECTIONS` (default 20). A timeout of 0
  means no limit. A timeout before the response starts gets 504 and any
  other transport failure 502, with an OpenAI-style error body (type
  `upstream_error`, code `upstream_timeout` or `upstream_error`) that
  carries no exception text. A failure during a stream ends it with one
  `data: {"error": ...}` event and no `data: [DONE]`.
- `ADMINA_GATEWAY_STREAM_MODE`, or `gateway.stream_mode` in `admina.yaml`
  (the environment variable wins): `passthrough` (default) or `governed`.
- `ADMINA_GATEWAY_MAX_PROMPT_CHARS` (default `0`, no limit): the longest
  message text of `POST /v1/chat/completions`, in characters (the text of
  every message). A longer request gets 413 (`invalid_request_error`, code
  `prompt_too_long`) before any governance check. `MAX_REQUEST_TOKENS`
  applies to `/mcp` only.
- `admina.core.jcs.canonicalize()`: the RFC 8785 (JSON Canonicalization
  Scheme) serialisation of a JSON value, as UTF-8 bytes.
- `ruleset_sha256()` (`admina.domains.agent_security.ruleset`): the SHA-256,
  as 64 lowercase hex characters, of the RFC 8785 serialisation of
  `{"admina_version", "engine", "builtin", "pattern_packs",
  "custom_patterns", "disabled_categories", "heuristic_threshold_milli"}`,
  an object of strings and integers only. `builtin` lists the active builtin
  patterns (`{regex, category, risk_level}`, in order, without those of a
  disabled category) for the `python` engine and is
  `{"admina_core_version": ...}` for the `rust` engine; `custom_patterns`
  are the entries as the firewall loads them; `disabled_categories` are
  sorted without duplicates; `heuristic_threshold_milli` is the threshold ×
  1000, rounded. The module imports neither FastAPI nor the proxy.
  `agent_security.firewall.pattern_packs` (a list of names) is read from
  `admina.yaml` and is part of the hash.
- The proxy computes `ruleset_sha256()` at startup for the engine its
  firewall runs on. Every `POST /v1/chat/completions` response carries it in
  `X-Admina-Ruleset`, the 401 of authentication and the 413 of the request
  size limit included; an unexpected failure before the response starts gets
  a 500 in the OpenAI error format (code `internal_error`) with the header.
  `GET /v1/admina/ruleset` (API key required) returns it with `engine`,
  `admina_core_version`, `admina_version`, `accepted_prescan_rulesets`,
  `prescan_tags`, `scan_roles` and `scan_policy_enabled`.
- Scan scope of the gateway. `ADMINA_GATEWAY_SCAN_ROLES` (default
  `system,user,assistant,tool`) sets the message roles the firewall scans;
  messages with any other role are always scanned. With
  `ADMINA_GATEWAY_SCAN_POLICY_ENABLED=true` (default `false`) a request can
  narrow the scan with `X-Admina-Scan-Policy: v1; roles=user,tool;
  prescanned=source,document; ruleset=<sha256>`: only the listed roles, and
  without the text of `<tag …>…</tag>` blocks of the listed tags that are
  also in `gateway.prescan_tags` of `admina.yaml`. The policy applies only
  when `ruleset` is the proxy's own or one in `gateway.prescan_rulesets`;
  otherwise, when the header is malformed, or while scan policies are off,
  the request is scanned in full. Unclosed, nested or stray tags leave the
  whole text to the scan. Any caller that holds the API key can send the
  header, so scan policies are for deployments where every such caller is
  trusted to scan what it declares (see the README). The `gateway_request`
  forensic record carries the outcome as `prescan` (`accepted`, `status`,
  `roles`, `tags`, `ruleset`), and `/metrics` counts
  `admina_prescan_accepted_total`, `admina_prescan_ruleset_mismatch_total`,
  `admina_prescan_malformed_total` and `admina_prescan_ignored_total`.
- `ADMINA_GATEWAY_PIPELINE_WORKERS` (default `0`, the number of CPUs): the
  worker threads that run the gateway's governance pipeline, the most
  requests governed at once. `ADMINA_GATEWAY_PIPELINE_TIMEOUT` (default `0`,
  no limit): seconds a request waits for its governance decision, the wait
  for a thread included; past it the request is blocked in every governance
  mode and recorded with `checks.pipeline` (`time_budget_exceeded`). The
  same budget bounds the PII redaction of each completion and stream line.
- `admina_event_loop_lag_seconds` on `/metrics`: a histogram of how late the
  event loop wakes up a task that sleeps 0.1 s at a time.
- `ADMINA_GATEWAY_SCAN_RESPONSE` (default `false`): the firewall also checks
  the content of each choice of a chat completion. A non-streaming completion
  flagged in `enforce` mode, or whose check runs over the time budget, is
  replaced by the block message; a streamed completion is checked after it
  has been sent and the outcome is only recorded. Each check writes a
  forensic record of type `gateway_response_scan`, linked to the request
  record by `request_event_id`.
- `scripts/bench_gateway.py`: time to the first chunk added by the gateway
  and event loop lag on a retrieval-augmented trace, per firewall engine.

- `ADMINA_CONFIG`: the `admina.yaml` to load, for example
  `/etc/admina/admina.yaml`. When it is set, `load_config()` reads exactly
  that file, and so do the proxy, the firewall overrides, the egress policy
  and the PII engine selection; a missing, unreadable or invalid file raises
  `admina.core.config.ConfigFileError` and the proxy does not start. Unset
  or empty, the search in the current directory and in the package
  directory is unchanged. Explicit `yaml_path` and `search_paths` arguments
  still take precedence.
- `ADMINA_API_KEY_FILE` and `ADMINA_FORENSIC_STATE_KEY_FILE`: files holding
  the API key and the forensic chain-state key, read once at startup with
  one trailing newline removed. A missing, unreadable or empty file, or a
  key set both directly and as a file, stops the proxy; the error names the
  setting and the path, not the key. The built-in filesystem forensic store
  plugin reads `ADMINA_FORENSIC_STATE_KEY_FILE` too.
  `admina.core.secretfile.secret_from_env()` resolves such a pair of
  environment variables.
- `ADMINA_ENABLED_SURFACES`: the surfaces the proxy serves, comma-separated
  (empty = all): `gateway` (`/v1/*`), `mcp` (`/mcp`, `/mcp/*`),
  `integration` (`/api/v1/*`), `compliance` (`/api/compliance/*`) and
  `dashboard` (`/api/dashboard/*` with the live feed and the browser
  sign-in, `/api/stats`, `/api/events`, the dashboard shell). The routes of
  a disabled surface are not mounted and answer 404 before authentication;
  `/health` and `/metrics` are always served. An unknown surface name stops
  the proxy. The startup banner lists the enabled surfaces.
- `GET /health` reports `mode` (governance mode), `surfaces` (enabled
  surfaces), `ruleset_sha256` (the active firewall ruleset, as in
  `X-Admina-Ruleset`) and `forensic_writable` (filesystem backend: a probe
  file created, written, fsynced and removed in `FORENSIC_BASE_DIR`; `s3`:
  the result of the last record write, `null` before the first; `memory`:
  `null`). The write check runs at most once every 10 s, on a thread of its
  own; concurrent calls share it, and a check that takes longer than 1 s
  reports `false`. The other fields, `engine` included, are unchanged.
  Example (`ADMINA_ENABLED_SURFACES=gateway`, filesystem backend, Rust
  engine):

  ```json
  {
    "status": "healthy",
    "service": "admina-proxy",
    "version": "0.13.0",
    "mode": "enforce",
    "surfaces": ["gateway"],
    "ruleset_sha256": "<64 hex>",
    "forensic_writable": true,
    "engine": {
      "engine": "rust",
      "rust_available": true,
      "rust_version": "0.13.0",
      "selection": "auto",
      "active": "rust",
      "pii_active": "python"
    },
    "timestamp": "2026-09-27T18:35:14.481520+00:00"
  }
  ```

- `ForensicBlackBox.writable()`: the write check behind `forensic_writable`.
- `proxy-minimal` extra: the proxy without Redis, ClickHouse, boto3, typer
  and the numpy/scikit-learn stack of the Python loop breaker. It serves
  the gateway surface (`ADMINA_ENABLED_SURFACES=gateway`, with `REDIS_URL`
  and `CLICKHOUSE_HOST` empty); with the `mcp` or `integration` surface
  enabled and neither `proxy` nor `rust` installed, the proxy does not
  start and says which extra to install.
- `ADMINA_LOG_FORMAT=json`: one JSON object per log line (`timestamp`,
  `level`, `logger`, `message`, and `exception` when there is one),
  uvicorn's own lines included. Other record attributes are not written.
  `text` (default) keeps the current format.
- `ADMINA_METRICS_REQUIRE_AUTH` and `ADMINA_API_DOCS_REQUIRE_AUTH` (default
  `false`): put `/metrics`, and `/docs`, `/redoc`, `/openapi.json`, behind
  the API key.
- `DASHBOARD_COOKIE_SECURE=auto`: the dashboard session cookie is `Secure`
  over HTTPS and, over plain HTTP, whenever the dashboard is addressed by a
  host other than `localhost`, a `*.localhost` name or a loopback address.
  `true` and `false` (default) keep their meaning; the usual boolean
  spellings are accepted and any other value stops the proxy.

- `slim` target of the proxy Dockerfile, published as
  `ghcr.io/admina-org/admina-proxy:<version>-slim`: the `proxy` extra and
  the Rust engine, without the `nlp` and `telemetry` extras and without the
  dashboard files.
- The release images are pushed with an SBOM and a max-mode provenance
  attestation and signed with cosign, keyless through GitHub OIDC (the
  `cosign verify` command is in `.github/workflows/release-docker.yml`).
  They carry `org.opencontainers.image.*` labels, the proxy images also
  `org.admina.engine=rust`, and the `LICENSE` and `NOTICE` files in
  `/usr/share/licenses/admina/`.

- Governance outcome headers on the responses of `POST /v1/chat/completions`
  once the request has its event id, streaming or not, upstream errors,
  timeouts and failures in the gateway included: `X-Admina-Event-Id`,
  `X-Admina-Action` (`ALLOW` or `BLOCK`), `X-Admina-Risk`,
  `X-Admina-Categories` (the names of the firewall categories that matched,
  comma-separated; never text) and `X-Admina-Record-Hash` (the `record_hash`
  of the request record, written before the request is forwarded);
  `X-Admina-Would-Action` in `observe` and `dry-run` mode. Every response
  the route handler sends carries `X-Admina-Version`; the 401 of
  authentication, the 413 of the request size limit and the 500 of a
  failure before the response starts carry `X-Admina-Ruleset` only. A
  request body with a value JSON cannot encode for the upstream request
  (`NaN`, an unpaired surrogate) is answered `400` with `"code":
  "invalid_request_body"`; any other failure in the gateway `500` with
  `"type": "server_error"`.
- `ADMINA_GATEWAY_BLOCK_STATUS`: `200` (default: the block message as a
  completion) or `403` (`{"error": {"message", "type": "governance_blocked",
  "param", "code": "governance_blocked", "categories"}}`, streaming or not).
- `ADMINA_GATEWAY_REQUEST_ID_HEADER`, `ADMINA_GATEWAY_RECORD_HEADERS` and
  `ADMINA_GATEWAY_FORWARD_HEADERS`: the header recorded as `request_id`, the
  headers recorded in `context` and the headers forwarded upstream (all empty
  by default). Credentials cannot be listed; nor, for forwarding, connection
  and body headers or `X-Admina-*`. Forwarded values outside ASCII are sent
  as the bytes received.
- W3C trace context on the gateway: a valid `traceparent` is recorded as
  `trace_id` and, when listed, forwarded with `tracestate`. With
  OpenTelemetry on, each chat completion has a `gateway.chat.completions`
  span, a child of the caller's span.
- `gateway_request` record fields: `request_id`, `trace_id`, `context`,
  `request_sha256` (the SHA-256 of the RFC 8785 canonical form of the
  `messages` forwarded upstream; test vectors in
  `tests/fixtures/jcs_vectors.json`), `ruleset_sha256`, `categories`, and
  `would_action` in `observe` and `dry-run` mode.
- A `gateway_response` forensic record (`EventType.GATEWAY_RESPONSE`) for
  each gateway chat completion, with the `event_id` of its request, written
  once the response has ended: `response_sha256` (the bytes sent to the
  client, counted as a stream goes out), `finish_reason`, `usage`,
  `duration_ms`, `status_code`, `upstream_status_code`, `cancelled` and
  `error` (the exception class only).
- `admina.core.trace_context` (W3C `traceparent` and `tracestate` parsing)
  and `OTELGovernanceExporter.start_span()`.
- `agent_security.egress.surfaces` in `admina.yaml`: the surfaces the egress
  stage runs on, among `gateway` (the text of the chat messages of
  `POST /v1/chat/completions`), `mcp` (the arguments of `/mcp` tool calls),
  `integration` (`/api/v1/validate`) and `sdk` (`GovernedModel.ask()` and
  `stream()`). Unset: every surface; an empty list: none. Names are
  case-insensitive; an unknown name, or a value that is not a list, stops
  the proxy at startup and raises `ValueError` in the SDK. With `gateway`
  left out, the gateway does not evaluate the text of chat messages for
  destinations and its records have no `checks.egress`.
  `admina.domains.agent_security.egress` adds `EGRESS_SURFACES`,
  `parse_egress_surfaces()` and `egress_policy_for()`.
- `ADMINA_GATEWAY_FORWARD_FIELDS`, `ADMINA_GATEWAY_MAX_N` and
  `ADMINA_GATEWAY_MAX_COMPLETION_TOKENS` (all off by default: the body is
  forwarded as received): the top-level fields of a chat completion
  forwarded upstream (`model`, `messages`, `stream` and the fields of a limit
  that is set always are), the largest `n`, and the largest `max_tokens` and
  `max_completion_tokens`. Larger values are lowered to the limit, and a
  request that sets neither token field is forwarded with `max_tokens` set to
  it. While a limit is set, a value of its fields other than an integer of at
  least 1 (absent and `null` aside) is answered `400` (`{"error": {"message",
  "type": "invalid_request_error", "param": <field>, "code":
  "invalid_value"}}`) before any governance check, forensic record or
  upstream call. The firewall scans the request as received; the forwarded
  `messages` and `request_sha256` do not change. `admina.proxy.gateway_body`
  holds `ForwardSettings`.
- `ForensicBlackBox(fail_mode=...)`: `open` (the default) logs a record, or
  a chain state after it, that cannot be written and `record()` returns
  `stored: false` with no sequence number or hash; `closed` raises
  `ForensicWriteError`. `accepting_records()` is false after a failed write
  until a write succeeds again.
- Forensic chain verification reads one record at a time, in sequence
  order, in constant memory, on a worker thread. `verify_chain()` (and the
  synchronous `verify()`) take `from_seq` or a `checkpoint`
  `(sequence_number, record_hash)` to verify only the records after it, and
  return, besides `valid`, `records` and `last_hash`: `reason` and
  `sequence_number` (the first failure) and `checkpoint` (where to resume).
  Reason codes: `hash_mismatch` (a record is not a JSON object, or its
  `record_hash` is not the hash of its content), `link_broken`
  (`previous_hash` is not the hash of the record before it, `GENESIS` for
  record 1), `missing_record` (there is no record with the next sequence
  number: before the first one found, between two records, or before the
  chain state's count), `state_mismatch` (the record at the chain state's
  count is not its head) and `checkpoint_mismatch` (the record at the
  checkpoint's sequence number has another `record_hash`).
  `admina.domains.compliance.forensic_integrity`
  (`compute_record_hash()`, `canonical_record()`, `verify_entries()`) and
  `admina.domains.compliance.forensic_files` (record keys, `atomic_write()`)
  are public.
- `ADMINA_FORENSIC_FAIL_MODE`: `open` (default) or `closed`. In `closed`
  mode a request whose forensic record cannot be written is answered `503`
  and not forwarded: the gateway with `{"error": {"message", "type":
  "server_error", "param": null, "code": "forensic_unavailable"}}`, `/mcp`
  with a JSON-RPC error (`-32603`), `POST /api/v1/audit` with `503`;
  `POST /api/v1/validate` answers `503` until a record is written again; and
  a `filesystem` or `s3` backend that cannot be opened at startup stops the
  proxy (`ForensicBackendError`). In `open` mode the failure is logged and
  the request served.
- The proxy reads `domains.compliance.forensic.backend` (or its older name
  `storage`) and `base_dir` from `admina.yaml` when `FORENSIC_BACKEND` and
  `FORENSIC_BASE_DIR` are not set; the environment's values win, and a value
  set in both places with different values is logged at startup. An unknown
  backend in `admina.yaml` stops the proxy. `admina.proxy.forensic_backend`
  builds the store.
- `GET /api/v1/forensic/verify` takes `from_seq` or `checkpoint=SEQ:HASH`
  and verifies from there. Both together, a malformed `checkpoint` or one
  whose `SEQ` has more than 19 digits are answered `400`; a `from_seq` that
  is not an integer or is below 1 is answered `422` (request validation).
- `admina forensic export --from-seq N --format jsonl [--dir DIR] [--out
  FILE|-]`: the records of a filesystem store from sequence number N on, in
  sequence order, one per line, each the bytes of its file followed by a
  newline. `admina forensic verify [--from-seq N | --checkpoint SEQ:HASH]`
  prints the verification result as JSON and exits with 0 (valid) or 1.
  Both read `--dir` (default `$FORENSIC_BASE_DIR`) and write nothing to it;
  so does `verify_directory()` of `admina.domains.compliance.forensic`, and
  `admina doctor` now uses it for the filesystem backend.
- `GET /health` `status` is `degraded` while forensic records cannot be
  written (`forensic_writable` false, or the last record or chain-state
  write failed); `healthy` otherwise.

- PII engines of other packages: `get_pii_engine` (`ADMINA_PII_ENGINE`,
  `pii_engine` in `admina.yaml`) looks a name up among the built-in engines,
  then among the entry points of the `admina.pii_engines` group, each naming
  a `BasePIIEngine` subclass or a callable that returns one (a `config`
  parameter receives the engine's `plugin_config` block). An unknown name
  raises `ValueError` listing the built-in and the registered engines, and
  the proxy does not start. `admina.engines.PIIEngineBridge` is the
  synchronous `PIIBridge` of a `BasePIIEngine`: it runs `detect` and
  `redact` on an event loop of the engine's own, from any thread, and
  returns `redacted_text`, `entities` (type, offsets, length, engine name;
  never the text), `categories` and `count`. `BasePIIEngine` gains
  `special_categories`, `sentence_categories` and `sentences(text)`.
- `ADMINA_PII_MASK_STYLE` (`pii_mask_style` in `admina.yaml`): `typed` (the
  default, each span replaced by the mask of its type) or `omissis` (each
  span replaced by `[OMISSIS]`, in every engine, in requests, responses and
  streamed responses). In `omissis`, the `sentence_categories` of an engine
  have their whole sentence replaced (the engine's `sentences`, by default
  `sentence_spans` of `admina.domains.data_sovereignty.masking`), and
  `StreamRedactor` releases a stream from such an engine a whole sentence at
  a time, holding at most `max_hold_chars` (default 4096). Any other value
  raises `ValueError`.
- `DataClassifier` classifies the special categories of personal data of
  GDPR art. 9 and 10 (`SPECIAL_CATEGORIES`) and those passed as
  `special_categories` (such as an engine's) as `restricted`; category
  names are compared case-insensitively.
- `ADMINA_PRESIDIO_NLP_MODELS` (`it:blank,en:en_core_web_sm`) and
  `presidio.nlp_models` in `admina.yaml`: the spaCy pipeline of each
  language of the `presidio` engine, an installed model or `blank` (a
  tokenizer with no model and no NER). Unset, `en_core_web_sm` and
  `it_core_news_sm` are used when installed. A configured model that is not
  installed, or a malformed setting, stops the engine; models are never
  downloaded. `get_presidio_pii_engine()` keeps one engine per mask style
  and pipelines.
- `ADMINA_OFFLINE` (default `false`): `true` sets `HF_HUB_OFFLINE`,
  `TRANSFORMERS_OFFLINE` and `HF_DATASETS_OFFLINE` to `1` before a PII engine
  is built and when the proxy starts, and the proxy starts without the
  OpenTelemetry exporter (`OTELGovernanceExporter(enabled=False)`). Values
  other than true/false (`1`/`0`, `yes`/`no`, `on`/`off`) raise `ValueError`.
- The IBAN category of the `spacy-regex` engine covers the IBAN registry:
  an IBAN is masked when it has the length of its country (Italy: 27
  characters), compact or with single spaces, and a valid mod-97 checksum
  (`admina.domains.data_sovereignty.iban`). The PHONE category also covers
  Italian mobile and landline numbers, with `+39`, `0039` or without.
- The gateway and `POST /api/v1/validate` record their governance decisions
  as `/mcp` does (`admina.proxy.main.record_decision`): each governed
  request emits one `governance.decision` event (live feed, OpenTelemetry,
  one alert per `BLOCK` or `CIRCUIT_BREAK`) and, with ClickHouse
  configured, stores one `governance_events` row (`gateway_request`, or
  `validate_request`, the new `EventType.VALIDATE_REQUEST`). A gateway
  request is recorded once its response has ended: its row has
  `response_hash` (the SHA-256 of the response sent), and a completion
  answered with the block message after the upstream answered is a `BLOCK`
  of `domain` `response_firewall` or `response_pii`. The event of a
  `/api/v1/validate` request has a new `event_id`, and the body's
  `session_id` without CR/LF, cut to 128 characters.
- `/metrics` serves, for the gateway, `/mcp` and `/api/v1/validate`
  (surfaces `gateway`, `mcp`, `integration`):
  `admina_request_duration_seconds{surface}`, a histogram of the time from
  the arrival of a request to the end of its response, and
  `admina_governance_duration_seconds{surface}`, a histogram of the time
  the governance pipeline took (`admina.proxy.request_metrics`).
- `OTEL_ENABLED` (default `true`): with the `telemetry` extra installed and
  `ADMINA_OFFLINE` off, the proxy exports its spans to `OTEL_ENDPOINT`, as
  before; `false` builds no exporter, so nothing is exported and no
  connection is made for telemetry.
- Stable firewall pattern ids. Every builtin pattern has an id
  (`firewall.BUILTIN_PATTERNS`, `firewall.BUILTIN_PATTERN_IDS`):
  `<category>.<language>.<n>` for the categories of 0.12 (`en` for the
  English patterns, `it`, `fr`, `es` and `de` for `multilang_evasion`, for
  example `instruction_override.en.1` and `multilang_evasion.it.1`) and
  `<category>.<n>` for the `it_*` categories. An id never changes and is
  never reused. `custom_patterns` entries get `custom.<n>`, in their order.
  Each entry of the fast path's `patterns` carries the `id` of the pattern
  that matched, so the forensic `checks` do too; `InjectionFirewall.pattern_ids`
  lists the ids a firewall applies.
- `agent_security.firewall.disabled_patterns`: ids of patterns the firewall
  leaves out (Python engine; `disabled_categories` is unchanged). An id that
  names no pattern is logged as a warning and ignored; a value that is not
  a list of strings is a configuration error. Like `custom_patterns`, it
  makes `get_firewall()` use the Python firewall when the Rust engine is
  selected.
- `agent_security.firewall.heuristic_threshold` sets the deep-path score
  from which the Python firewall flags a text (default `0.5`, the value it
  used before; a value that is not a finite number greater than 0 stops
  `get_firewall()` with `ValueError`). `INJECTION_DEEP_PATH_ENABLED=false`
  turns the deep path off on either engine: `check()` then returns the
  fast-path result. `get_firewall(deep_path_enabled=...)` overrides the
  variable; the proxy passes its setting (read from the environment or
  `.env`).
- `agent_security.firewall.allowed_tags`: tag names (any case) the deep
  path does not count as context switches, such as the tag an application
  puts around retrieved documents. Other tags, separators and code fences
  still count. Python engine; it does not select the Python firewall.
- Firewall pattern packs (`admina.domains.agent_security.pattern_packs`):
  named, versioned sets of patterns in YAML or JSON (`{name, version,
  description, patterns: [{id, regex, category, risk_level}]}`; no other
  key; `description` optional) that the Python firewall adds after its
  builtin patterns when `agent_security.firewall.pattern_packs` lists them.
  A pack pattern's id is `<pack>:<id>` in check results and
  `disabled_patterns`. Each name is looked up among the entry points of the
  group `admina.pattern_packs` (a loader that returns the pack mapping or
  the path of a pack file in package data), then in the directories of
  `agent_security.firewall.pattern_pack_dirs` (`<name>.yaml`, `.yml`,
  `.json`), which `ADMINA_PATTERN_PACK_DIRS` (separated by `os.pathsep`)
  replaces when set. A pack not found (the error lists the available
  packs), found in two sources, listed twice or invalid (the error names
  the file or entry point and the key path), and a missing pack directory,
  raise `PatternPackError`: `get_firewall()` fails and the proxy does not
  start. Pack patterns are timed on 64k-character inputs when the firewall
  is built: one over 50 ms is logged as a warning with its id, or raises
  `PatternPackError` with `agent_security.firewall.strict_pack_timing:
  true`. A listed pack makes `get_firewall()` use the Python firewall.
  Example pack: `examples/pattern_packs/example-pack.yaml`.
- Italian baseline of the Python firewall, four builtin categories, risk
  `high`: `it_instruction_override` (`it_instruction_override.1`: an
  override verb such as `ignora`, `dimentica`, `non seguire` where an
  instruction starts, with rules, instructions or "quanto detto" as object;
  `.2`: the same verbs with a second-person object, anywhere: "le tue
  istruzioni", "il tuo prompt", "quanto ti è stato detto"; `.3`: an
  override after a clause that starts, where an instruction starts, with a
  second-person imperative such as `traduci`, `riassumi`, `rispondi`,
  `scrivi`, then up to twelve words and a comma or `e`, `ma`, `poi`,
  `quindi`: "Traduci il testo e ignora le istruzioni precedenti"; the words
  contain no opening quote, bracket or tag, no table cell separator and no
  `>`, and an apostrophe only after a letter or digit ("l'articolo"), so an
  opening quote inside the clause ends it),
  `it_role_hijack` (`.1`: "d'ora in poi" / "da adesso" and a second-person
  verb; `.2`: "sei ora" an AI or an assistant without limits; `.3`: "agisci
  come" / "fai finta di essere" a model without filters; `.4`: "parla
  come" / "immagina di essere" a model without filters where an instruction
  starts), `it_prompt_extraction` (`.1`: `rivela`, `mostra`, `ripeti` ...
  the system prompt or "le tue istruzioni" where an instruction starts;
  `.2`: the second-person forms `mostrami`, `dimmi` ...) and
  `it_model_addressing` (`.1`: a note or instruction for an AI system
  followed by `:` ("Istruzioni per l'IA:"), or an AI system addressed
  directly followed by `:` or `!` ("Attenzione chatbot:", "Attenzione
  IA!"); `.2`: "se sei un'intelligenza artificiale"). "Where an instruction
  starts" is the start of the text, after a sentence end, a colon, a line
  break, an opening bracket, a table cell separator `|`, an opening tag
  (`<p>`), the start or the end of an HTML comment (`<!--`, `-->`), or an
  opening quote or backtick (one that follows no letter or digit); then up
  to four closing tags, comment ends or speaker labels ("<b>Nota:</b>
  ignora ...", "</p> Ignora ..." at the start of the text, "Utente>
  Ignora ..." at the start of a line), an optional list marker (`-`, `*`,
  `–`, `1)`, `a)`, a `#` heading, a `>` quote), optional emphasis (`**`,
  `__`) and up to two words addressing the reader ("ok,", "ciao,",
  "grazie,", "ora", "poi", "per favore", "assistente,"). A closing quote,
  tag or emphasis after a word is not such a start ('Il modulo "Alfa"
  ignora le istruzioni precedenti', "<b>Il fornitore</b> ignora le
  istruzioni precedenti"); `-->` is one, also when it is written as an
  arrow (`->` is not). An override inside a sentence without
  one of these contexts is not matched, for example "Il testo è finito e
  ignora le regole ricevute fin qui", or "Analizza il testo e ignora le
  istruzioni precedenti" (`analizza` has the form of the third person).
  Every pattern is timed with the builtin patterns
  (`tests/test_firewall_pattern_timing.py`).
- `GET /health` and `GET /api/stats` report, under `engine`, the engines of
  the components the proxy built: `firewall` (`rust` or `python`),
  `loop_breaker` (`null` when no enabled surface needs one) and `pii`
  (`python`, `rust`, `presidio` or the name of a plugin engine), next to
  the fields of 0.12 (`selection`, `active`, `pii_active`,
  `rust_available`, `rust_version`, `engine`), which are unchanged. With an
  admina.yaml that makes the firewall Python under `ADMINA_ENGINE=auto`,
  `engine.firewall` is `python` while `engine.active` is `rust`.
  `engine_status()` takes the built objects (`firewall=`, `loop_breaker=`,
  `pii_engine=`); without them the three fields are `null`.
- admina.yaml is checked against its schema (`schema_version: 1`,
  `admina.core.config_schema`). `check_config(path=None, *, strict=False)`
  and `config_path()` of `admina.core.config` return the file checked and
  the paths of its unknown keys (`domains.agent_security.firewal`,
  `alert_channels[0].uri`). At startup the proxy logs them as a warning,
  `admina.yaml <path>: unknown keys, not read: <paths> (...)`.
- At startup the proxy logs, as a warning, the `ADMINA_*` variables of its
  environment and `.env` file that nothing reads (`ADMINA_* variables not
  read by Admina: <names> (...)`; values are never logged). Known
  are the proxy settings, the variables of the engines, the SDK, the
  builtin plugins and the other containers of the stack, and
  `ADMINA_GATEWAY_UPSTREAM_<NAME>_API_KEY[_FILE]`. Not reported:
  `ADMINA_<NAME>_...` for each entry point `<name>` of `admina.plugins`,
  `admina.pii_engines` and `admina.pattern_packs` (upper case, other
  characters than letters and digits as `_`), and the prefixes of
  `ADMINA_ENV_ALLOW_PREFIXES` (comma-separated).
- `ADMINA_CONFIG_STRICT` (default `false`): `true` makes unknown admina.yaml
  keys (`ConfigSchemaError`) and unknown `ADMINA_*` variables
  (`UnknownVariablesError`, a `ValueError`) stop the proxy at startup.
- `admina.engines.PYTHON_ONLY_FIREWALL_KEYS` (`custom_patterns`,
  `disabled_categories`, `disabled_patterns`, `pattern_packs`) and
  `admina.engines.EngineSelectionError` (a `ValueError`).
- The loop breaker and PII bridges name their engine (`engine` attribute),
  as the firewall bridges do.
- `compute_oisg_score_from_evidence(evidence)`
  (`admina.domains.compliance.oisg_evidence`, also exported by
  `admina.domains.compliance`): the OISG adequacy score of the 20 criteria
  of `oisg.CRITERIA` (same ids and labels) from evidence that the caller
  supplies, `{"schema_version": 1, "criteria": {"o1": {"status", "reason",
  "evidence_ref"}, ...}}` with an entry for every criterion (JSON Schema
  `admina/domains/compliance/schemas/oisg-evidence.schema.json`, read by
  `evidence_schema()`; dataclasses `OISGEvidence` and `CriterionEvidence`).
  A status is `satisfied`, `partial`, `accepted_gap` (a known gap,
  accepted with a `reason`, which is required and not blank) or
  `not_applicable`. Scoring: `satisfied` is worth 5 points, `partial` 2.5,
  `accepted_gap` 0; `not_applicable` criteria are left out and each
  pillar is rescaled to 25 over the criteria that apply; a pillar without
  any has no score (`null`) and the total is rescaled to 100 over the other
  pillars. Scores are rounded half up to one decimal, and the level is
  `get_level()` of the total. A missing or unknown criterion, an unknown
  status or key, an `accepted_gap` without a reason, and evidence where
  every criterion is `not_applicable` raise `OISGEvidenceError` (a
  `ValueError`; `problems` names each key). The result,
  `OISGEvidenceResult` (an `OISGResult`), carries the `status`, `reason`,
  `evidence_ref` and `points` of each criterion and the number of
  `applicable` criteria of each pillar, and exports as JSON (`to_json()`,
  read back by `from_dict()`) and Markdown (`to_markdown()`, a table per
  pillar). `compute_oisg_score()` is unchanged.
- `admina redteam`: the detection-efficacy scorecard as a command of the
  package, with the options of `scripts/redteam.py` (`--engine`, `--corpus`,
  `--format`, `--out`) and `--corpora-dir DIR`, `--config FILE` (default
  `$ADMINA_CONFIG`), `--baseline FILE`, `--gate` and `--write-baseline
  [FILE]` (default `baseline.json` next to `--out`). With `--baseline` or
  `--gate` the run is compared with the baseline (with `--gate` alone, the
  packaged one) and the result is printed on standard error. Exit status: 0;
  1 when `--gate` finds a regression (a lower recall or a new false
  positive, or a corpus that ran only on engines the baseline does not
  declare); 2 when an option, a corpus, the configuration or the baseline is
  not valid, or when `--engine rust` cannot run a selected corpus
  (`admina-core` is not installed, or `--config` sets a key that only the
  Python firewall applies). `scripts/redteam.py` runs this command; there
  `--baseline` without a file writes the baseline, as `--write-baseline`
  does.
- `run_suite()` of `admina.redteam` takes `corpora_dir`, `baseline` and
  `config`; without them the scorecard is unchanged.
  - `corpora_dir`: a directory of external corpora, `<name>.jsonl` files
    whose rows have the format of the packaged corpus of their detector
    (rows with `messages`: loop breaker; with `expected_types`: PII;
    otherwise the firewall, `label` `attack` or `benign`), each listed in the
    directory's `SHA256SUMS`, which is verified before the run
    (`load_external_corpora()`). They run after the packaged corpora, under
    their names (the name of a packaged corpus is refused), and `corpora=`
    selects them by name; an unknown name in `corpora=` raises `ValueError`.
    The scorecard's `external_corpora` holds `dir` and the detector of each.
  - `baseline`: a baseline file (or its mapping) compared with the run by
    `compare()`, limited to the selected corpora and engines; a corpus that
    ran without the Python engine is also a failure when the baseline
    declares none of the engines it ran on. The scorecard's `gate` holds
    `baseline`, `failures` and `notes`. `BASELINE_PATH` is the packaged
    baseline.
  - `engines`: a selected corpus that none of the selected engines can run
    raises `ValueError` naming the corpora and the reason (with `["rust"]`:
    `admina-core` is not installed, or `config` sets a key of
    `PYTHON_ONLY_FIREWALL_KEYS`).
  - `config`: an admina.yaml whose `agent_security.firewall` settings
    (custom patterns, pattern packs and their directories, disabled
    categories and patterns, heuristic threshold, allowed tags) build the
    Python injection firewall as the proxy does; the Rust engine runs on the
    injection corpora only when the file sets none of
    `PYTHON_ONLY_FIREWALL_KEYS`. The PII and loop detectors keep their
    defaults. The scorecard's `config` holds `path` and `python_only_keys`.
  The Markdown scorecard names the external corpora and the configuration.
  `InjectionAdapter(config)` and `all_detectors(firewall_config)` take the
  `FirewallConfig`, and the adapter builds the firewall of each engine once.

- `ruleset_document()` in `admina.domains.agent_security.ruleset`: the
  canonical JSON text whose SHA-256 is `ruleset_sha256()`, to compare two
  rulesets member by member. `GET /v1/admina/ruleset` returns it as
  `ruleset_document`, with `ruleset_format`.
- **EU AI Act risk classification in Italian, French and German.**
  `classify_risk()` also matches the phrases of
  `admina.domains.compliance.ai_act_terms` (Art. 5 practices, the areas of
  Annex III, the cases of Art. 50) on whole words of a normalised text, so
  a description of a CV-screening system in Italian is `high` rather than
  `minimal`. `EUAIActCompliance(term_languages=[...], extra_terms={...})`
  narrows the languages and adds terms of the caller. The result adds
  `matched_terms` and `matched_areas`. The English keyword lists and their
  results are unchanged; a non-English description can now get a higher
  class than before.
- An upgrade guide from 0.12 to 0.13: `docs/guides/upgrade-0.13.md`.
- `admina forensic acknowledge-rebuild` and
  `ForensicBlackBox.acknowledge_rebuild()`: verify the whole chain with the
  key and clear the `rebuilt` status of a chain whose state was rebuilt.
- `admina.sdk.active_ruleset_sha256()`: the ruleset hash of the firewall the
  SDK builds from `admina.yaml`, on the engine `get_firewall()` selects. For
  the same file and `ADMINA_ENGINE` it is the value the proxy reports in
  `X-Admina-Ruleset`.

### Changed

- The gateway runs the governance pipeline (firewall, PII redaction, egress
  analysis, governance guards) and the PII redaction of completions in
  worker threads instead of the event loop. Governance guards run there
  too: one guard instance can be called by several threads at once, each
  call on the event loop of its thread, so a guard must be thread-safe and
  must not keep loop-bound objects across calls (see `BaseGovernanceGuard`).
- A gateway request whose governance pipeline raises is blocked in every
  governance mode and recorded as `checks.pipeline` (`{"action": "ERROR",
  "error": "<exception class>"}`; 0.12 answered 500). Guard contract errors
  still follow `ADMINA_GUARD_FAIL_MODE`.
- A completion whose PII redaction runs over the time budget or raises is
  not sent: a non-streaming completion is replaced by the block message, and
  a stream ends with one `data: {"error": ...}` event (code
  `response_redaction_failed`) without `data: [DONE]`.
- `GuardrailsAIGuard` runs one validation at a time.
- `run_pipeline()` takes the texts the firewall scans (`scan_texts`); by
  default it scans every string of the body, as before.
- A malformed entry of `agent_security.firewall.custom_patterns` skips only
  that entry.

- **Streamed chat completions pass through unchanged.** With
  `ADMINA_GATEWAY_STREAM_MODE=passthrough` (the default) and PII redaction
  off, the gateway forwards the upstream SSE bytes as they are, every field
  included, each event as soon as it is complete (0.12 re-emitted
  `choices[0].delta.content` only). With PII redaction on, or in
  `governed` mode, each chunk is parsed and re-serialised.
- The governed stream path sends one chunk for each upstream chunk, with
  all of its fields: ids, choice indexes, roles, tool calls, finish
  reasons and the final `usage` chunk. With PII redaction on, every string
  of a choice is redacted, per choice and per field across chunks:
  `content` (a string or a list of parts), reasoning text, tool and
  function call `arguments` and any other field. The values of `index`,
  `id`, `type`, `role`, `name` and `finish_reason` and the chunk identity
  are kept; `logprobs` and `token_ids` are sent as `null`; other strings
  outside the choices and SSE comment lines are redacted as whole values;
  values nested more than 16 levels deep are dropped. `data: [DONE]` is
  sent when the upstream sends it.
- Upstream errors (4xx, 5xx) reach the client of the gateway with their
  status, body and content type, streaming or not. A non-streaming body is
  forwarded unchanged unless PII redaction is on; with redaction on, a
  successful response that is not a JSON object gets 502 (code
  `upstream_invalid_response`), and in a JSON response every string is
  redacted as a whole value under the same rules as the governed stream
  (structural values and identity kept, `logprobs` and `token_ids` of each
  choice `null`). `GET /v1/models` forwards the upstream body unchanged
  when no allow-list is set.

- `redis` is imported only for a `REDIS_URL` with a Redis scheme and
  `clickhouse_connect` only for a non-empty `CLICKHOUSE_HOST`; `boto3`
  stays limited to `FORENSIC_BACKEND=s3`. With `REDIS_URL` and
  `CLICKHOUSE_HOST` empty there is no connection attempt. A backend that is
  configured while its package is missing is logged as a warning and left
  off.
- The loop breaker is built only when the `mcp` or `integration` surface is
  enabled, the coordination detector with its quarantine refresh loop only
  with `mcp`, and the gateway's pipeline threads only with `gateway`.
  Without the loop breaker `/api/stats` reports `"loop_breaker": {}` and the
  startup banner `Loop Breaker: OFF`.
- The container entrypoint accepts `ADMINA_API_KEY` or `ADMINA_API_KEY_FILE`
  and prints only whether the key is set, not any of its characters.
- Validation errors of the proxy settings name the setting without echoing
  the configured values.

- The release workflows run the CI workflow on the tagged commit and
  publish only when it passes. A PEP 440 pre-release tag (for example
  `v1.2.0rc1`) makes a GitHub pre-release, and the `latest` image tags
  move only with a final release.
- The proxy and dashboard images pin their base images by digest. The
  proxy image build fails when the Rust engine does not build (previously
  the image fell back to the Python engines).
- `uv.lock` resolves `admina-core` from `./core-rust` (`[tool.uv.sources]`),
  so `uv sync --extra rust` or `--all-extras` builds the Rust engine of the
  same checkout and needs a Rust toolchain; a sync without the `rust` extra
  does not. The published package metadata keeps the version range of the
  `rust` extra. The CI python-tests job, `make ci-python` and
  `make ci-linux` test against this engine.
- `scripts/check-versions.py` compares versions in their PEP 440 spelling
  (`1.2.0-rc.1` in the Cargo files matches `1.2.0rc1`) and also checks the
  `admina-core` entry of `uv.lock`.

- `ADMINA_ENGINE=rust` without `admina-core` installed is an error: the
  engine factories (`get_firewall()`, `get_loop_breaker()`,
  `get_pii_engine()`, the SDK included) and `engine_status()` raise
  `EngineSelectionError` ("ADMINA_ENGINE=rust, but admina-core is not
  installed: install admina-framework[rust], or set ADMINA_ENGINE=python
  (or auto) to run the Python engines") and the proxy does not start (it
  ran the Python engines, with a warning). Migration: install the `[rust]`
  extra, or set `ADMINA_ENGINE=auto` (Rust when installed) or `python`.
- `ADMINA_ENGINE=rust` with a non-empty
  `agent_security.firewall.custom_patterns`, `disabled_categories`,
  `disabled_patterns` or `pattern_packs` in admina.yaml is an error:
  `get_firewall()` raises `EngineSelectionError` naming the keys
  ("ADMINA_ENGINE=rust, but admina.yaml sets
  agent_security.firewall.custom_patterns, which only the Python firewall
  applies: remove them, or set ADMINA_ENGINE=python (or auto) to run the
  Python firewall") and the proxy does not start (it ran the Python
  firewall, with a warning). Migration: remove these keys from the file
  used with `ADMINA_ENGINE=rust`, or set `auto` (the Python firewall runs
  with them, as before) or `python`. `pattern_pack_dirs`,
  `strict_pack_timing`, `heuristic_threshold` and `allowed_tags` do not
  select an engine. Under `auto` the warning names the keys that are set.
- A value of the wrong type in admina.yaml is an error naming the key:
  `load_config()` raises `ConfigSchemaError` (a `ValueError`; a file named
  by `ADMINA_CONFIG` gives a `ConfigFileError`, as for other invalid files),
  for example "admina.yaml /etc/admina/admina.yaml:
  domains.agent_security.loop_breaker.window_size: must be an integer", and
  the proxy does not start. The engine factories that read admina.yaml
  (`get_firewall()`, `get_pii_engine()`, `pii_mask_style()`,
  `get_egress_policy()`, the SDK included) raise the same error, whatever
  key it names (`get_egress_policy()` gave an empty allowlist for a value
  it could not read); `admina plugin list` exits with it, and
  `admina doctor` reports it under plugin discovery. The values of
  `gateway` and `presidio` are
  checked by their readers, as before; empty values (null) and the
  free-form blocks (`plugin_config`, `integrations`,
  `agent_security.domains`, the entries of `custom_patterns`) are not
  checked. Migration: fix the value the error names.
- The startup banner reports the engine selection and the engines that run,
  and the settings that switch the firewall and PII redaction on the
  gateway and `/mcp`: "Engine selection: ADMINA_ENGINE=auto (admina-core
  <version>)" and "Firewall: ON (rust engine) | PII Redaction: OFF (gateway
  and /mcp) | Loop Breaker: ON (rust engine)" (they were "Engine: RUST
  v<version>" and "Firewall: ON | PII Redaction: ON | Loop Breaker: ON",
  whatever the engines and settings).
- `admina_engine_info` has the labels `engine` and `firewall` (the
  firewall's engine; `engine` was `rust` whenever `admina-core` was
  installed), `loop_breaker` (`none` when none is built), `pii`,
  `pii_redaction` (`on`, `off`), `rust_available`, `rust_version`,
  `selection` and `version`.
- README and MODEL_CARD describe the firewall as a heuristic signal, give
  the pattern counts of each engine (44 builtin patterns on Python, 15 on
  Rust), the engine selection and the official image (the Rust firewall
  and loop breaker under `auto`, no spaCy model), and state what the
  engine microbenchmark measures; the full Docker Compose stack runs 8
  containers.

- `admina_requests_total` has the labels `surface` (`gateway`, `mcp`,
  `integration`) and `action` (`ALLOW`, `BLOCK`, `REDACT`, `CIRCUIT_BREAK`,
  `ERROR`), with a sample for each enabled surface and action from startup;
  `sum(admina_requests_total)` counts what the unlabelled counter counted
  (`/mcp` and, since 0.12.2, the gateway), plus `/api/v1/validate`, less the
  `/mcp` requests whose body is not JSON (answered `400` before they are
  governed).
  `admina_requests_blocked_total`, `admina_requests_allowed_total`,
  `admina_requests_redacted_total`, `admina_avg_latency_ms` (now the mean
  duration of the counted requests) and the `requests_*` counters of
  `/api/stats` count every governed surface, so the dashboard score counts
  gateway blocks too.
- An `/mcp` request is recorded (counted on `/metrics`, its
  `governance.decision` event, its ClickHouse row) once it has been
  answered, with the action of its response: a response that a governance
  guard blocks (its `inspect_response` verdict, or its contract error with
  `ADMINA_GUARD_FAIL_MODE=closed`) makes the request a `BLOCK` of `domain`
  `response_guard`, with the guard's `risk_level` (`HIGH` for a contract
  error). It is counted in `admina_requests_total{surface="mcp",
  action="BLOCK"}` and `admina_requests_blocked_total` only, and sends one
  alert.
- The ClickHouse `request_hash` of an `/mcp` row is the whole SHA-256 (64
  hexadecimal characters), the `request_sha256` of its event.
- Each gateway chat completion writes two forensic records,
  `gateway_request` and then `gateway_response`; count `gateway_request`
  records to count requests.
- A non-streaming completion blocked by the response scan, or whose PII
  redaction did not finish, is answered as `ADMINA_GATEWAY_BLOCK_STATUS`
  says, with `X-Admina-Action: BLOCK`.
- A chat completion request whose JSON body is not an object is answered
  `400` (`Invalid JSON body`).
- The filesystem forensic store writes each record, `_chain_state.json` and
  `_chain_state.json.sig` atomically and durably: to a temporary file in the
  same directory (`.<name>.<random>.tmp`, never read as a record), fsynced,
  renamed into place, then the directory fsynced; a new directory is fsynced
  in its parent. Files keep the permissions a new file gets. A record never
  goes into an hour directory earlier than the one of the record before it.
- A forensic record that cannot be written (filesystem or S3) is not counted:
  the next record takes its sequence number, so the stored chain has no gap.
- `FORENSIC_BACKEND=filesystem` without a directory (or with one that
  cannot be created), and `FORENSIC_BACKEND=s3` without boto3 or with S3 not
  reachable, no longer fall back to the in-memory store: in `open` mode the
  proxy starts with a store that records nothing (`UnavailableForensicStore`,
  `forensic_writable: false`) and logs an error; in `closed` mode it does not
  start. A directory that exists but cannot be written is logged at startup
  (and stops the proxy in `closed` mode).
- The S3 forensic store reads its chain state and records with the retries
  of its writes (`FORENSIC_S3_MAX_RETRIES`, `FORENSIC_S3_BASE_DELAY_S`), and
  an object is missing only when S3 answers that it does not exist
  (`NoSuchKey`). Any other error still there after the retries is a read
  error, as for a file of the filesystem store: a chain state that cannot
  be read is not used, and a record that cannot be read at startup keeps
  the backend from opening (as above). `verify_bucket()` raises such an
  error instead of reporting the chain state missing.
- `POST /api/v1/audit` answers `{"recorded": false, "error": ...}` when the
  record could not be written; `/mcp` sends no `X-Admina-Forensic-Hash` then.
- The `admina init` template leaves the forensic backend to
  `FORENSIC_BACKEND` and `FORENSIC_BASE_DIR` (the lines in `admina.yaml` are
  comments).
- The chain state also holds `format` (`admina-forensic/1`) and `head_key`
  (the key of the last record). Checking it at startup reads its last
  record and any record written after it, not every record.
- The proxy of `docker-compose.yml`, and of the `docker-compose.yml` that
  `admina init` generates, keeps its forensic directory
  (`FORENSIC_BASE_DIR=/app/.admina/forensic`) on the named volume
  `forensic-data`, so the records and the chain state outlive the
  container. Both proxy images create `/app/.admina/forensic` owned by the
  `admina` user (uid 10001), so a new volume mounted there is writable by
  the proxy.
- The IBAN category of the `spacy-regex` engine no longer masks an
  IBAN-shaped string with a wrong checksum, a length other than its
  country's, or an unknown country code. The `spacy-regex` engine matches
  IBANs before card numbers, and card numbers before phone numbers.
- The `presidio` engine checks e-mail domains against the public suffix
  list bundled with `tldextract`, with no download and no cache files.
- The object `ruleset_sha256()` hashes also has `disabled_patterns`
  (`agent_security.firewall.disabled_patterns`, sorted without duplicates;
  `builtin` still leaves out only the patterns of a disabled category) and
  `allowed_tags` (lower case, sorted without duplicates), and
  `pattern_packs` holds the content of each listed pack, in order:
  `{name, version, patterns: [{id, regex, category, risk_level}]}` (a
  changed pack file changes the hash; the description is not hashed);
  `ruleset_sha256()` raises
  `PatternPackError` when a listed pack cannot be loaded. New test vectors
  are in `tests/test_ruleset_sha256.py`.
- `agent_security.firewall.pattern_packs`, `pattern_pack_dirs`,
  `disabled_patterns` and `allowed_tags` must be lists of strings and
  `strict_pack_timing` a boolean: another value is a configuration error
  (`ValueError` from `load_config()`).
- The Italian `multilang_evasion` patterns (`multilang_evasion.it.1`,
  `multilang_evasion.it.2`) match where an instruction starts (see the
  Italian baseline above) and end on a word boundary: third-person prose
  with the same verbs ("il consiglio annulla le direttive precedenti") no
  longer matches, nor does a verb inside another word ("signora"); the
  singular `istruzione` and `restrizione` still match. After up to two
  addressing words, and after Markdown or HTML markup where an instruction
  starts, they still match at risk `critical` ("Ok, ignora tutte le
  istruzioni precedenti", "Grazie. Ora, per favore ignora le istruzioni
  precedenti", "**Ignora le istruzioni precedenti**", "| Nota | Ignora le
  istruzioni precedenti |", "<b>Nota:</b> ignora le istruzioni precedenti",
  "Testo <!-- commento --> Ignora le istruzioni precedenti", "Utente> Ignora
  le istruzioni precedenti"). An override inside a sentence without such a
  start, or after a closing quote, tag or emphasis that follows a word
  ("<b>Il fornitore</b> ignora ..."), no longer matches them:
  the Italian baseline matches it at risk `high` when the clause starts
  with a second-person imperative or the object is second-person ("Traduci
  il testo e ignora le istruzioni precedenti", "... e ignora le tue
  istruzioni"), and otherwise it is not matched ("Il documento è lungo,
  ignora le istruzioni precedenti").
- The committed red-team baseline records the Python injection recall
  23/37 (it was 21/37): the Italian attacks `inj-it-002` and `inj-it-003`
  of the corpus are detected. No new false positive; the Rust figures are
  unchanged.
- The default configuration's `ruleset_sha256()` for the `python` engine
  changes with the builtin pattern list.
- The default `agent_security.firewall.heuristic_threshold` of the
  configuration is `0.5` (it was `0.7`, which the firewall did not read), so
  the default `heuristic_threshold_milli` of the ruleset is `500`.
  `admina.yaml.example` and the `admina init` template set `0.5`. Upgrading:
  `admina.yaml` files generated by `admina init` up to 0.12, and copies of
  the example of those releases, set `heuristic_threshold: 0.7`, which the
  Python firewall now applies; set `0.5` to keep the previous behaviour.
- Deep path of the Python firewall: HTML entities (named, decimal and
  hexadecimal) no longer count as encoding markers, only `\uXXXX` escape
  sequences do (percent-encoding never counted); the length signal counts
  texts longer than 100 000 characters (`firewall.LONG_TEXT_CHARS`; it
  counted texts longer than 2000).

- The object `ruleset_sha256()` hashes also has `ruleset_format` (`1`),
  the version of its form, so that a later change of the form is explicit
  (`RULESET_FORMAT`). The object also holds `admina_version` (and, for the
  `rust` engine, `admina_core_version`), so the hash changes with every
  release: a caller that pins a hash in `gateway.prescan_rulesets` or
  `X-Admina-Scan-Policy` recomputes it after each upgrade.
- `POST /api/v1/validate` answers `400` (`'content' must be a string`)
  when `content` is not a string. An object or an array was scanned as
  nested data by the Python engine, and answered `500` with the Rust
  engine.

- The red-team gate (`admina redteam --gate`, `admina.redteam.gate.compare`)
  fails when the number of benign samples of a detector (`fp_samples`)
  differs from the baseline, with a message that asks for a new baseline:
  false-positive counts are compared only over the same benign samples.

### Deprecated

- **The API key in the query string (`?api_key=`).** It is accepted only on
  the WebSocket upgrade of the dashboard live feed (`/api/dashboard/live`),
  where a browser cannot set headers; the first connection that
  authenticates with it logs a warning, once per process, without the key.
  HTTP requests never accept it: they send `X-API-Key` or
  `Authorization: Bearer`. A URL ends up in access logs, proxy logs and
  browser history. A later release will refuse it on the live feed too.

### Fixed

- The auth middleware runs the request handler once, after the first auth
  provider that returns a user. An exception raised by the handler gets
  the application's 500 response and is not retried with another provider.

- **`GovernedModel.ask()` and `stream()` work with the SDK alone**
  (`pip install admina-framework`, without numpy and scikit-learn). They
  built the Python loop breaker on every call, loop detection on or off,
  and failed with `ModuleNotFoundError: numpy`; the loop breaker is now
  built only when loop detection runs. When it runs without those
  packages, the `ImportError` names `admina-framework[proxy]` (or `[rust]`).

- The `role_hijacking` pattern of the Rust firewall (`admina-core`) matches
  whole words only. It matched "act as" inside longer words, so English
  text such as "impact assessment" or "the AI Act asks" was reported as a
  role-hijacking attempt. Attacks written with whole words ("act as",
  "you are now", "pretend you are", "from now on you") are still matched.

- **The dashboard feed, trend and suggestions work without ClickHouse.**
  `/api/dashboard/feed`, `/api/dashboard/trend` and
  `/api/dashboard/suggestions` used to answer empty, with
  `"error": "ClickHouse not available"`, when no ClickHouse was configured,
  as in an embedded deployment. They now read the recent records of the
  forensic black box: one event per governed request of `/mcp` and the
  gateway, in the same columns as a ClickHouse row, and the answer carries
  `"source": "forensic_recent"`. `POST /api/v1/validate` writes no forensic
  record, so its requests appear only in the ClickHouse rows.
  `ForensicBlackBox.recent_records()` keeps the last 1,000 records written
  by the running proxy, in memory, with every backend; records written
  before a restart are not read back. The WebSocket live feed keeps
  reading the event bus.

- The dashboard's EU AI Act countdown shows the deadline it counts down
  to. The date next to the countdown was a fixed "August 2, 2026", while
  the number of days came from the `enforcement_deadline` of
  `/api/dashboard/compliance` (2 December 2027 for Annex III); both now
  read that field.

- **The dashboard's EU AI Act help shows a command that works.** The
  example `curl` for `POST /api/compliance/gap-analysis` targeted
  `http://localhost:8080`; it now targets the origin that served the page,
  and the help states that the route accepts `POST` only (a `GET`, such as
  opening the address in the browser, answers `405 Method Not Allowed`).

### Notes

- As of 0.12.1, Admina is developed with AI assistance (Claude). Commits
  written with it carry a `Co-Authored-By` trailer that names the
  assistant, and every change is reviewed and tested by the maintainers.
  See "AI-Assisted Contributions" in `CONTRIBUTING.md`.
- The timing tests of `tests/test_firewall_pattern_timing.py` carry the
  `benchmark` marker and are excluded from CI (`-m "not benchmark"`): on
  shared macOS runners their time ratios and budgets vary between runs.
  They run with `pytest -m benchmark tests/test_firewall_pattern_timing.py`.

## [0.12.2] — 2026-10-05

Patch release: the OpenAI-compatible gateway on the event bus, in the
request counters and in ClickHouse; the dashboard feed, trend and
suggestions without ClickHouse; the Presidio engine on text with many
dots; and whole-word matching of the Rust `role_hijacking` pattern.
Upgrading is recommended.

### Security

- The Presidio PII engine (`ADMINA_PII_ENGINE=presidio`) asks the analyzer
  only for the entity types it maps to Admina categories. It ran every
  Presidio recognizer and discarded the other results; the URL recognizer
  took about 1.2 ms per character on text with many dots (80 seconds on
  64,000 characters). Detected spans are unchanged.

### Fixed

- The `role_hijacking` pattern of the Rust firewall (`admina-core`) matches
  whole words only. It matched "act as" inside longer words, so English
  text such as "impact assessment" or "the AI Act asks" was reported as a
  role-hijacking attempt. Attacks written with whole words ("act as",
  "you are now", "pretend you are", "from now on you") are still matched.

- **The OpenAI-compatible gateway now publishes governance decisions on
  the event bus.** Every `/v1/chat/completions` request emits one
  `GOVERNANCE_DECISION` event (`domain="gateway"`) for allow, block and
  redaction outcomes; a streaming request emits it once, when the stream
  completes. The dashboard live feed, bus-driven alerts and the OTel
  exporter therefore see gateway traffic, as they already did for `/mcp`.
  Emission is fire-and-forget (no added latency, a failing subscriber
  cannot fail the request) and the event metadata carries the decision
  only, never the request or response content.

- **The OpenAI-compatible gateway now counts its requests and stores its
  governance events.** `/v1/chat/completions` requests update the proxy
  counters of `/api/stats` and `/metrics` (`requests_total`,
  `requests_allowed`, `requests_blocked`, `requests_redacted` and the
  average latency) as `/mcp` requests do, so the dashboard no longer shows
  zero requests for gateway-only traffic. With ClickHouse configured, each
  request also gets its `governance_events` row (event type
  `gateway_request`, method `chat.completions`): the governance checks and
  a truncated hash of the prompt, never the prompt. A failing analytics
  store is logged and never fails the request.

- **The dashboard feed, trend and suggestions work without ClickHouse.**
  `/api/dashboard/feed`, `/api/dashboard/trend` and
  `/api/dashboard/suggestions` used to answer empty, with
  `"error": "ClickHouse not available"`, when no ClickHouse was configured.
  They now read the recent records of the forensic black box: one event
  per governed request (`/mcp` and the gateway), in the same columns as a
  ClickHouse row, and the answer carries `"source": "forensic_recent"`.
  `ForensicBlackBox.recent_records()` keeps the last 1,000 records written
  by the running proxy, in memory, with every backend; records written
  before a restart are not read back. The WebSocket live feed keeps
  reading the event bus.

- **The dashboard's EU AI Act help shows a command that works.** The
  example `curl` for `POST /api/compliance/gap-analysis` targeted
  `http://localhost:8080`; it now targets the origin that served the page,
  and the help states that the route accepts `POST` only (a `GET`, such as
  opening the address in the browser, answers `405 Method Not Allowed`).

### Notes

- As of 0.12.1, Admina is developed with AI assistance (Claude). Commits
  written with it carry a `Co-Authored-By` trailer that names the
  assistant, and every change is reviewed and tested by the maintainers.
  See "AI-Assisted Contributions" in `CONTRIBUTING.md`.

## [0.12.1] — 2026-10-05

Patch release: hardened dashboard session handling. Upgrading is
recommended.

### Security

- **Hardened dashboard session handling.** The bundled dashboard now signs
  in by exchanging the API key for a browser session at
  `POST /api/dashboard/session`. The session cookie
  (`admina_dashboard_session`) is `HttpOnly`, `SameSite=Strict`, `Secure`
  over HTTPS (or with `DASHBOARD_COOKIE_SECURE=true`), scoped to `/api/`,
  signed with a key derived from `ADMINA_API_KEY` and valid for one hour by
  default. It is accepted only for read-only requests to the dashboard API
  (`/api/dashboard/*`, `/api/stats`, the live feed); the MCP proxy, the
  OpenAI-compatible gateway and the integration and compliance APIs require
  the API key. A live-feed connection opened with a session is closed when
  the session expires. Sessions issued by earlier releases are no longer
  accepted.
- `SECURITY.md` lists 0.12.x as the supported release line.

### Added

- `ADMINA_DASHBOARD_ENABLED` (default `true`): `false` stops serving the
  bundled dashboard (`/`, `/vendor/*`, `/heimdall.png`) and its sign-in
  endpoint. `dashboard.enabled: false` in `admina.yaml`, previously
  ignored by the proxy, now has the same effect. The `/api/dashboard/*`
  data API remains available with the API key.
- `ADMINA_API_DOCS_ENABLED` (default `true`): `false` stops serving
  `/docs`, `/redoc` and `/openapi.json`.
- `ADMINA_DASHBOARD_SESSION_TTL` (default `3600`, 60 to 43200 seconds):
  lifetime of a dashboard browser session.
- The dashboard shows a sign-in form, signs out from the top bar and asks
  to sign in again when the session expires. The bundled dashboard page is
  served with `X-Frame-Options: DENY` and `Cache-Control: no-store`.

### Changed

- **The bundled dashboard asks for the API key** once per session (in an
  `admina dev` project, `admina password show` displays it). The dashboard
  of the Docker stack, served by nginx, is unaffected: nginx already
  presents the key to the proxy.
- The built-in `apikey` auth provider authenticates the API key only
  (`X-API-Key` or `Authorization: Bearer`) and no longer reads cookies;
  dashboard sessions are handled by the proxy.
- `verify_credential()` in `admina.proxy.main` considers the dashboard
  session only when called with `allow_session=True`.

### Notes

- Starting with this release, Admina is developed with AI assistance
  (Claude). Commits written with it carry a `Co-Authored-By` trailer that
  names the assistant, and every change is reviewed and tested by the
  maintainers. See "AI-Assisted Contributions" in `CONTRIBUTING.md`.

## [0.12.0] — 2026-09-23

Minor release: destination-based egress control on tool calls and a
cross-agent coordination detector. Egress enforcement is opt-in:
`ADMINA_EGRESS_MODE` defaults to `observe`, under which destinations and
quarantines are recorded and no call is refused.

### Added

- **Destination-based egress control on tool calls.** A new pipeline stage
  extracts destinations from tool-call arguments — independently of the
  HTTP method, since a method is an assertion made by the resource being
  called, not a security boundary — and checks them against an operator
  allowlist. Configured under `domains.agent_security.egress` in
  `admina.yaml`: `enabled` (default `true`), `allow` (exact hosts,
  `*.suffix` wildcards, or CIDR ranges), and `read_only_tools` (tool names
  exempt from the payload-bearing classification). The mode is controlled
  by `ADMINA_EGRESS_MODE=observe|enforce`, defaulting to `observe` so that
  upgrading a deployment does not silently turn on default-deny; the
  global governance mode is a ceiling, so `observe`/`dry-run` governance
  never lets egress block regardless of this variable. The recorded
  `checks["egress"]` entry carries the destinations seen, whether the call
  is payload-bearing, and — on a block — which destination(s) among
  possibly several caused it.

  **Coverage is not uniform across surfaces.** The stage runs on five
  governed surfaces, but only the MCP proxy passes tool-call arguments.
  `POST /api/v1/validate`, the OpenAI-compatible gateway
  (`POST /v1/chat/completions`) and SDK `GovernedModel.ask()` / `.stream()`
  pass prompt text, where a destination is found only if a URL appears in
  the prompt itself. `GovernedAgent.call()` has **no** egress control at
  all: it carries tool-call-shaped params but reimplements the governance
  sequence inline instead of calling the pipeline. Treat this as an MCP
  control; see `MODEL_CARD.md` §5b for the per-surface table.

  **A destination is declared by the argument name.** For a value without
  a scheme, only these keys make it a destination: `url`, `uri`, `host`,
  `hostname`, `endpoint`, `address`, `server`, `target`, `base_url`,
  `api_url`, `webhook`. A scheme-less host under any other key —
  `callback_url`, `destination`, or any tool-specific name — is not seen,
  produces no record, and passes in both modes. A full URL (containing
  `://`) or an IP literal is still recognised under any key name.

  **Under `enforce`, arguments nested deeper than the scan limit are
  refused.** The walk over the arguments stops at a fixed depth (6, shared
  with the firewall and PII walks). A region it never reached could have
  held a destination, so the call is treated as having an undeterminable
  target and denied — and that outranks any destination resolved higher up,
  so an allowlisted host at the top of the arguments does not buy passage
  for one buried below the limit. The refusal is explicit: the decision
  reason reads *"unresolvable destination: arguments nested past the scan
  depth limit"* and `evidence.scan_truncated` is `true` in the forensic
  record. This affects `enforce` only; `observe` records it and does not
  block.
- **`admina egress suggest-allowlist`** — builds a candidate allowlist from
  destinations recorded during `observe` mode by scanning local forensic
  records (`--forensic-dir`, defaulting to `$FORENSIC_BASE_DIR` and then to
  `.admina/forensic`; `--since DAYS`, default `7`). Prints a ready-to-paste
  `admina.yaml` block; promoting an entry to the allowlist stays a human
  decision. Note that `FORENSIC_BACKEND` defaults to `memory`, which
  persists nothing — an observation window intended to produce an allowlist
  needs `FORENSIC_BACKEND=filesystem` (with `FORENSIC_BASE_DIR`) or `=s3`
  set before it starts.
- **Cross-agent coordination detector.** A two-phase check that finds
  agents writing to a destination the operator never declared. An
  always-on fan-in trigger counts distinct agent ids making write-shaped
  calls to one destination (`domains.agent_security.egress.fanin`:
  `window_seconds`, default 3600; `min_agents`, default 5) and reports
  `suspected` once the threshold is crossed. If
  `ADMINA_EGRESS_FINGERPRINT_KEY` is set, a second phase compares keyed
  content shingles of what each call carries — the payload values, not the
  request envelope, and each value fingerprinted on its own rather than
  joined, so that the header block, bearer token and content type a whole
  fleet sends unchanged cannot pool into the run of shared text a match
  requires — between agents; a match needs 12 shared shingles and 0.4
  containment across the whole payload, met either by one coherent run
  inside a single pair of fields or, for a tool that splits its message
  over several short arguments, by the two calls being near-copies of one
  another — 0.9 containment over the smaller payload and 0.4 over the
  larger, since containment alone says nothing about the larger side and a
  call carrying only a shared template scores 1.0 against any call
  carrying that template beside its own message. Before anything is
  compared it discounts text
  that `min_agents - 1` distinct *other* agents have already sent toward
  that destination — a fleet's header block or instruction preamble is not
  one agent quoting another, and counting senders rather than calls is what
  keeps an agent from making its own message ambient by repeating it — and
  text the reading agent has sent there itself. A match against another
  agent's prior
  output escalates the verdict to `confirmed` and quarantines the
  destination for write-shaped calls fleet-wide — every agent, not only
  the ones involved — until `quarantine_ttl_seconds` (default 86400) lapses
  or an operator lifts it. The quarantine refuses calls under
  `ADMINA_EGRESS_MODE=enforce`; under the default `observe` it is recorded,
  logged, listed by `admina egress quarantine list` and written to the
  forensic chain with the agents and the matching peer, and the call
  proceeds — the same mode gate the allowlist has. Every verdict the
  detector concludes, not only `confirmed`, leaves a forensic-chain record
  marked `QUARANTINE` or `OBSERVE`, a `policy_violation` bus event and an
  `admina_coordination_verdicts_total{status="…"}` counter on `/metrics`:
  at the shipped fan-in defaults a same-text cascade across a whole fleet
  reports `suspected` rather than quarantining, and the record is where
  that detection is kept. **Without that key, the detector never
  escalates past `suspected`**: echo confirmation does not run at all
  rather than falling back to unkeyed, dictionary-attackable hashes.
  Destinations meant to receive coordinated writes are exempted via
  `coordination_declared`. Two new CLI commands operate on the quarantine
  set: `admina egress quarantine list` and `admina egress quarantine lift
  <destination>`. **This feed is MCP-proxy-only**: like the egress stage
  it rides on, only `admina/proxy/main.py` calls the detector — the
  OpenAI-compatible gateway, `POST /api/v1/validate`, and the SDK
  primitives do not feed it, so coordination conducted through those
  surfaces is not seen. See `MODEL_CARD.md` §5c for the full limitations,
  including behaviour with no Redis (`degraded`, not `none`).

### Changed

- **Adapter SDK ceilings widened.** The `openai` extra now accepts
  `openai>=1.0,<4` (was `<3`) and the `anthropic` extra
  `anthropic>=0.39,<2` (was `<1`). The calls the adapters make
  (`chat.completions.create`, `messages.create`) are unchanged in the new
  majors; the lockfile resolves openai 3.7.0 and anthropic 1.3.0.
- **The `[rust]` extra accepts admina-core 0.12.x** (`<0.13`, was `<0.12`).
  The engine-bridge ABI is unchanged.

### Fixed

- **`/metrics` emitted `# HELP` and `# TYPE` once per sample rather than
  once per metric family.** `admina_firewall_detections_total` carries one
  sample per detection category, so a proxy that had recorded detections
  in two or more categories served an exposition that Prometheus rejects,
  failing the whole scrape and every Admina metric in it. Metadata is now
  emitted once per family.

## [0.11.1] — 2026-07-16

Patch release: dependency security updates, an information-disclosure fix,
and two configuration/tooling corrections. No API changes.

### Security

- **API responses no longer carry exception text.** The dashboard services
  endpoint returned `str(exc)` from failed Redis and ClickHouse health
  checks, and `POST /api/v1/validate` returned the raw exception text of a
  guard that broke its contract. Either could echo a host, port or a
  credential embedded in a connection URL back to the caller. Both now
  report a generic reason; the detail is logged server-side and the
  forensic records keep the full text, so the audit trail is unchanged.
- **cryptography** updated to 50.0.0, resolving the high-severity advisory
  affecting `< 50.0.0`. The dependency ceiling is widened from `<50` to
  `<51`.
- **setuptools** updated to 83.0.0 and **pymdown-extensions** to 11.0.1,
  resolving two moderate advisories reported against the lockfile.

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

[Unreleased]: https://github.com/admina-org/admina/compare/v0.13.1...HEAD
[0.13.1]: https://github.com/admina-org/admina/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/admina-org/admina/compare/v0.12.2...v0.13.0
[0.12.2]: https://github.com/admina-org/admina/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/admina-org/admina/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/admina-org/admina/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/admina-org/admina/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/admina-org/admina/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/admina-org/admina/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/admina-org/admina/compare/v0.9.5...v0.10.0
[0.9.5]: https://github.com/admina-org/admina/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/admina-org/admina/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/admina-org/admina/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/admina-org/admina/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/admina-org/admina/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/admina-org/admina/releases/tag/v0.9.0
