# Changelog

All notable changes to Admina are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Admina is pre-1.0: the public API is feature-complete and production-ready,
but may still evolve in response to early-adopter feedback before the 1.0
stability commitment. See [ROADMAP.md](ROADMAP.md) for planned milestones.

---

## [Unreleased]

### Security

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
- `POST /api/v1/audit` stamps each record: `source` is always
  `api_v1_audit` (a `source` sent by the caller is kept as `client_source`)
  and `submitted_by` is the credential the request was admitted with
  (`api_key`, `append_key`, `user:<id>` for an auth provider's user, or
  `unauthenticated`). `ADMINA_AUDIT_APPEND_KEY` (or `_FILE`) is a key
  accepted by this route only, besides the API key; every other route
  refuses it. Unset (the default), the route needs the API key.

### Added

- Governance outcome headers on the responses of `POST /v1/chat/completions`
  once the request has its event id, streaming or not, upstream errors,
  timeouts and failures in the gateway included: `X-Admina-Event-Id`,
  `X-Admina-Action` (`ALLOW` or `BLOCK`), `X-Admina-Risk`,
  `X-Admina-Categories` (the names of the firewall categories that matched,
  comma-separated; never text) and `X-Admina-Record-Hash` (the `record_hash`
  of the request record, written before the request is forwarded);
  `X-Admina-Would-Action` in `observe` and `dry-run` mode. Every response of
  the route carries `X-Admina-Version`. A request body with a value JSON
  cannot encode for the upstream request (`NaN`, an unpaired surrogate) is
  answered `400` with `"code": "invalid_request_body"`; any other failure in
  the gateway `500` with `"type": "server_error"`.
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
  (not both; a malformed value is answered `400`) and verifies from there.
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

### Changed

- Each gateway chat completion writes two forensic records,
  `gateway_request` and then `gateway_response`; count `gateway_request`
  records to count requests.
- A non-streaming completion blocked by the response scan, or whose PII
  redaction did not finish, is answered as `ADMINA_GATEWAY_BLOCK_STATUS`
  says, with `X-Admina-Action: BLOCK`.
- A chat completion request whose JSON body is not an object is answered
  `400` (`Invalid JSON body`).
- The firewall of the gateway scans every string of a chat completion
  request, keys included: the messages (content, names, tool calls), the
  tool definitions (`tools`), `response_format` and any other field of the
  body. The `arguments` of a tool call (and of a legacy `function_call`) are
  scanned as the JSON they hold, each string separately, and as they are
  when they are not JSON. `ADMINA_GATEWAY_SCAN_ROLES` and
  `X-Admina-Scan-Policy` narrow the messages only. A request whose body has
  a string nested more than 32 levels deep, or tool call arguments nested
  deeper than the JSON parser reads, is blocked in `enforce` mode
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

## [0.13.0rc1] — 2026-09-27

Release candidate of 0.13.0: an OpenAI-compatible gateway for embedded
deployments (named upstream routes with keys, streams passed through
unchanged, upstream errors propagated, request limits, the governance
pipeline in worker threads, the firewall ruleset hash on every response),
secrets from files, `ADMINA_CONFIG`, `ADMINA_ENABLED_SURFACES` and the
`proxy-minimal` extra, linear-time pattern matching, and signed release
images with a `-slim` variant. Installers take it only when asked:
`pip install --pre admina-framework` or `admina-framework==0.13.0rc1`.

### Security

- Firewall patterns match in linear time on long inputs. Categories, risk
  levels and matching results are unchanged.
- PII redaction and the spaCy + regex PII engine match e-mail addresses in
  linear time on long inputs. Detected spans are unchanged.

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
    "version": "0.13.0rc1",
    "mode": "enforce",
    "surfaces": ["gateway"],
    "ruleset_sha256": "b9ddba234d55b532c2be464124c01a9d906e9fb7f492729807e0a7eadb39faa0",
    "forensic_writable": true,
    "engine": {
      "engine": "rust",
      "rust_available": true,
      "rust_version": "0.13.0-rc.1",
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
  `v0.13.0rc1`) makes a GitHub pre-release, and the `latest` image tags
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
  (`0.13.0-rc.1` in the Cargo files matches `0.13.0rc1`) and also checks the
  `admina-core` entry of `uv.lock`.

### Fixed

- The auth middleware runs the request handler once, after the first auth
  provider that returns a user. An exception raised by the handler gets
  the application's 500 response and is not retried with another provider.

## [0.12.1] — 2026-MM-DD

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

[Unreleased]: https://github.com/admina-org/admina/compare/v0.13.0rc1...HEAD
[0.13.0rc1]: https://github.com/admina-org/admina/compare/v0.12.1...v0.13.0rc1
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
