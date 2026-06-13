# Defect audit — confirmed findings (annex to the 0.10.0 plan)

Read-only multi-agent audit, 10 finder lenses + 2-lens adversarial verification per finding.
Status: **60 findings verified** (below). 143 further candidates were never verified
(their verifiers were cut off by a session limit) — retained in the raw JSON only, not listed here.
1 finding refuted and killed; 3 uncertain (split verdicts).

Raw data: workflow run wf_209ba397-db1 (task w2vty07e6).


## CRITICAL (1)

### FilesystemForensicStore silently resets the hash chain and overwrites existing forensic records when _chain_state.json is missing or corrupt
- **Where:** `admina/plugins/builtin/forensic/filesystem.py:77` · **Category:** bug · **Finder:** plugins
- **Impact:** A single lost/corrupted ~100-byte state file (e.g., crash during _persist_chain_state, accidental deletion) causes the supposedly append-only forensic log to silently destroy and replace its own historical records on the next append, restarting from previous_hash=GENESIS. Audit-trail data loss with no error or warning emitted.
- **Evidence:** filesystem.py:139-148: `if state_file.exists(): try: ... except (OSError, json.JSONDecodeError): pass` — a missing or truncated state file leaves `self._chain_head = "GENESIS"` and `self._record_count = 0`. Then append() at line 77-81: `record_file = self._base_dir / f"{self._record_count:08d}.json"; record_file.write_text(...)` — write_text unconditionally overwrites the existing `00000001.json`, `00000002.json`, ... `_persist_chain_state` (line 153 `state_file.write_text(...)`) is also non-atomic, so a crash mid-write produces exactly the corrupt-state trigger.


## HIGH (13)

### OllamaAdapter.send() is async but performs blocking synchronous HTTP inference, freezing the event loop
- **Where:** `admina/plugins/builtin/adapters/ollama.py:98` · **Category:** bug · **Finder:** plugins
- **Impact:** Every governed model call blocks the entire asyncio event loop for the full inference duration (seconds to minutes for local LLMs). Any async application embedding GovernedModel (FastAPI services, the proxy) stalls all concurrent requests while one prompt runs. The ollama package ships ollama.AsyncClient, so the async contract is implementable.
- **Evidence:** ollama.py:62 creates the synchronous client `self._client = ollama.Client(host=self._host)` and ollama.py:97-98 inside `async def send`: `start = time.monotonic(); response = client.chat(model=model, messages=messages, **kwargs)` — a blocking network call (no await, no executor offload), despite the BaseModelAdapter contract being `async def send` (base.py:74). It is awaited directly on the loop at admina/sdk/governed_model.py:184 `adapter_result = await self._adapter.send(...)`.

### OpenAIAdapter.send() is async but uses the synchronous OpenAI client, blocking the event loop
- **Where:** `admina/plugins/builtin/adapters/openai.py:113` · **Category:** bug · **Finder:** plugins
- **Impact:** Same as the Ollama adapter: any async consumer freezes its event loop for the entire remote completion round-trip on every governed call, serializing all traffic in the host application.
- **Evidence:** openai.py:77 `self._client = openai.OpenAI(**kwargs)` (sync client, not AsyncOpenAI) and openai.py:112-113 inside `async def send`: `start = time.monotonic(); response = client.chat.completions.create(model=model, messages=messages, **kwargs)` — blocking HTTP call with no await/executor, violating the async `BaseModelAdapter.send` contract (base.py:74) consumed via `await self._adapter.send(...)` (sdk/governed_model.py:184).

### WebhookAlertChannel.send_alert() does blocking urlopen inside async — stalls the proxy event loop up to the webhook timeout
- **Where:** `admina/plugins/builtin/alerts/webhook.py:98` · **Category:** bug · **Finder:** plugins
- **Impact:** Each governance alert delivered to a slow/unreachable webhook blocks the entire proxy event loop for up to 10 seconds — all in-flight MCP/REST traffic stalls, directly contradicting the proxy's low-latency governance design. A degraded alert endpoint becomes a self-inflicted denial of service.
- **Evidence:** webhook.py:98 inside `async def send_alert`: `with urlopen(req, timeout=self._timeout) as resp:` — urllib's synchronous urlopen with default timeout 10s (line 60 `int(os.environ.get("ADMINA_ALERT_WEBHOOK_TIMEOUT", "10"))`). The proxy dispatches alerts as event-loop tasks: admina/proxy/main.py:1263 `_spawn(_fire_alerts(state.alert_channels, _alert))` and main.py:1503 `await ch.send_alert(alert)` — the coroutine runs on the same loop serving all requests.

### Signed dashboard session cookie is rejected by the actual auth path; _verify_dashboard_token is unreachable, breaking the bundled dashboard when a key is set
- **Where:** `admina/plugins/builtin/auth/apikey.py:137` · **Category:** bug · **Finder:** proxy-auth
- **Impact:** In bundled mode (`admina dev`, no nginx — the default local experience that auto-generates an ADMINA_API_KEY per main.py:631), every dashboard `/api/*` fetch returns 401 and the dashboard renders empty/Disconnected. The signed-cookie feature added to make this work is non-functional end-to-end.
- **Evidence:** Because the auto-loaded APIKeyAuthProvider handles auth first (main.py:579-595), the middleware's signed-token verifier `_verify_dashboard_token(request.cookies.get(_DASHBOARD_COOKIE, ""))` (main.py:609; helper main.py:494-512) is never reached. The plugin instead pulls the cookie as if it were the raw key: `key = cookies.get("admina_session", "")` (apikey.py:135-138) and then `if not provided or not secrets.compare_digest(provided, self._api_key): raise PermissionError` (apikey.py:87-88). But GET / mints `_issue_dashboard_token()` into that cookie — `base64("<exp>.<hmac>")` (main.py:485-491)  […]

### verify_chain() cannot detect tail truncation of the forensic log — it never anchors against the persisted chain head or record count
- **Where:** `admina/plugins/builtin/forensic/filesystem.py:99` · **Category:** security · **Finder:** plugins
- **Impact:** Deleting the last K record files (the classic way to hide recent governance events) leaves an internally consistent prefix, so verify_chain reports valid: True even though the store holds the data (chain_head, record_count) needed to detect the truncation. Forensic tamper-evidence guarantee is broken for tail deletion.
- **Evidence:** filesystem.py:95-130: `files = sorted(self._base_dir.glob("[0-9]*.json")); ... prev_hash: str | None = None; for fp in files: ... if prev_hash is not None and rec.get("previous_hash") != prev_hash: return {"valid": False, ...}` — the loop only checks pairwise linkage and per-record hashes among the files that still exist. The final `prev_hash` is never compared to `self._chain_head` (in memory and in _chain_state.json), `len(files)` is never compared to `self._record_count`, and the first record's `previous_hash` is never checked against "GENESIS". The success path returns `{"valid": True, "re […]

### PII engine produces overlapping matches (no regex-vs-regex dedup, one-sided NER check) and redact() corrupts text on overlaps, can leave PII fragments
- **Where:** `admina/plugins/builtin/pii/spacy_regex.py:124` · **Category:** bug · **Finder:** plugins
- **Impact:** For realistic EU inputs (IBANs are core to Admina's target market), redaction output is mangled — adjacent legitimate text is eaten and/or digits of the PII span can survive outside the placeholder. A PII-redaction component that can emit partially unredacted or corrupted text in its primary EU use case.
- **Evidence:** detect() has no overlap handling between regex patterns (lines 100-112 just append all finditer hits per type), and the only dedup is NER-vs-regex and one-sided: line 124 `overlap = any(m["start"] <= ent.start_char < m["end"] for m in matches)` — checks only the entity's start. Concrete overlap: an IBAN like "DE89 3704 0044 0532 0130" matches both the IBAN pattern (line 38) and CREDIT_CARD `\b(?:\d{4}[-\s]?){3}\d{4}\b` (line 36) on its inner "3704 0044 0532 0130". redact() then splices by stored indices in reverse (lines 152-154 `text = text[: m["start"]] + placeholder + text[m["end"] :]`), wh […]

### WebSocket live-feed auth compares the signed cookie against the raw API key, so cookie-authenticated WS connections always fail
- **Where:** `admina/proxy/api/dashboard.py:232` · **Category:** bug · **Finder:** proxy-auth
- **Impact:** The dashboard live feed (`WS LIVE`) never connects in bundled mode when ADMINA_API_KEY is set, regardless of a valid session cookie; users see a permanently reconnecting `WS OFF` feed.
- **Evidence:** `provided = (websocket.headers.get("X-API-Key") or websocket.query_params.get("api_key") or websocket.cookies.get("admina_session") or "")` then `if not provided or not secrets.compare_digest(provided, expected): await websocket.close(code=1008)` where `expected = ADMINA_API_KEY` (dashboard.py:220-233). The `admina_session` cookie holds a signed token (`base64("<exp>.<hmac>")`, main.py:485-491), never equal to the raw key, so `compare_digest` always returns False and the socket is closed. The WS handler was not updated when the cookie became a signed token; its own docstring still claims `the  […]

### observe/dry-run "would-have-blocked" analytics never populate — suggestion engine always says "safe to switch to enforce"
- **Where:** `admina/proxy/governance.py:126` · **Category:** bug · **Finder:** proxy-pipeline
- **Impact:** Observe/dry-run mode exists precisely to show operators what enforce mode WOULD block before they flip the switch. Because `cat_would_blocked` is always empty, the `would_block_in_enforce` suggestions never fire and the endpoint always emits `observe_clean` ("Observe mode ... with zero would-have-blocked events. Safe to switch to enforce."), even when enforce would block large volumes of traffic. An operator following this guidance flips to enforce and breaks legitimate traffic, the exact failure the observe workflow is meant to prevent.
- **Evidence:** In run_pipeline the downgraded decision is recorded only on the dataclass: `result.would_action = result.action` (governance.py:126). It is never copied into `result.checks`. The forensic record and ClickHouse row are built solely from checks: main.py:1281-1283 `"checks": {k: safe_serialize(v) for k, v in governance_result["checks"].items()}` and main.py:1302 `details=governance_result["checks"]`. The dashboard suggestions endpoint then reads it back out of that details JSON: dashboard.py:613 `if d.get("would_action") and not cats:` / dashboard.py:615 `would = (d.get("would_action") or "").upp […]

### ALLOW_UNAUTHENTICATED and the fail-closed 401 branch are dead code; no-API-key default is fail-open (every request authenticated as admin)
- **Where:** `admina/proxy/main.py:621` · **Category:** security · **Finder:** proxy-auth
- **Impact:** An operator who leaves ADMINA_API_KEY unset and relies on the documented `ALLOW_UNAUTHENTICATED: bool = False` (config.py:93) fail-closed default gets a fully open governance proxy: anyone reachable can call /mcp, /api/stats, /api/events, and all compliance endpoints as an admin. The security control intended to prevent this is inert.
- **Evidence:** The middleware tries plugin providers first and returns in every branch: `if state.auth_providers:` ... `if user: ... return await call_next(request)` ... else `return JSONResponse(status_code=401 ...)` (main.py:579-595). `state.auth_providers` is ALWAYS non-empty: `registry.discover()` (registry.py:270 `for py_file in sorted(directory.rglob("*.py"))`) imports `auth/apikey.py` and registers `APIKeyAuthProvider`, and lifespan instantiates every one (`state.auth_providers = _instantiate("auth_provider")`, main.py:142). So steps 2 and 3 are unreachable. Step 3 — `if settings.ALLOW_UNAUTHENTICATED […]

### Bool/short-list compliance input silently drops checks, inflating compliance_score to COMPLIANT
- **Where:** `admina/sdk/compliance_kit.py:239` · **Category:** bug · **Finder:** sdk-core
- **Impact:** An EU AI Act gap report can claim COMPLIANT / 100% while most Art. 9-15 checks were never assessed — exactly the compliance-integrity guarantee the kit is sold on. Any consumer using the bool shorthand documented at compliance_kit.py:225-227 (or a shorter list than the 4 checks) gets a silently overstated compliance posture in reports and COMPLIANCE_CHECK audit events.
- **Evidence:** compliance_kit.py:238-239 normalises a bool to a single-element list: `if isinstance(value, bool): normalised[key] = [value]`. The engine then zips that list against the requirement's full check list (eu_ai_act.py:291-292: `checks = current_compliance.get(req_key, [False] * len(req_info["checks"]))` / `for i, (check_desc, is_met) in enumerate(zip(req_info["checks"], checks))`). Every HIGH_RISK_REQUIREMENTS entry has 4 checks (eu_ai_act.py:152-223), so `[True]` counts 1/1 and the other 3 checks vanish from both total_checks and gaps. Passing `{k: True for k in all 7 requirement keys}` yields to […]

### Firewall scan and PII redaction silently bypassed for params nested >5 levels deep or placed in dict keys
- **Where:** `admina/sdk/governed_agent.py:121` · **Category:** security · **Finder:** sdk-core
- **Impact:** GovernedAgent is the documented governance boundary for agent-to-agent calls ("firewall check, loop detection, PII redaction (bidirectional)", lines 148-150). A malicious or compromised agent can trivially craft JSON-RPC params with 6 levels of nesting (or key-embedded payloads) to smuggle prompt injections past the firewall and exfiltrate PII past the redactor, while the audit trail records a clean ALLOW.
- **Evidence:** _redact_dict: `if depth > 5: return obj, 0` (governed_agent.py:121-122) — strings at depth ≥6 are returned unredacted with count 0. _collect_strings has the same cap (`if depth > 5: return`, lines 98-99), so the same text is never fed to the firewall or loop breaker either. Additionally both helpers only walk values, never keys: `for v in obj.values(): _collect_strings(v, ...)` (line 103) and `out[k] = rv` (line 130) preserve keys verbatim. A params payload like 6 nested dicts around "ignore all previous instructions" or PII in a dict key passes `InjectionFirewall.check` unscanned, is forwarde […]

### Auto-generated per-call session_id makes loop detection a permanent no-op and leaks memory unboundedly
- **Where:** `admina/sdk/governed_agent.py:224` · **Category:** bug · **Finder:** sdk-core
- **Impact:** Users who construct GovernedAgent with default arguments believe loop protection is active (constructor default `loop_detection=True`) but it silently never triggers; meanwhile a long-running service leaks memory proportional to the concatenated text of every request ever processed — an availability problem in exactly the production proxy scenario the SDK targets.
- **Evidence:** governed_agent.py:224: `session_id = kwargs.pop("session_id", None) or str(uuid.uuid4())` — a fresh UUID per call when the caller doesn't pass one. LoopBreaker.check stores the text under that key (`window = self.windows[session_id]; window.append(content)`, loop_breaker.py:122-123) and needs ≥3 entries in the SAME session window to detect anything (`if len(window) < 3: return result`, line 137). With a fresh UUID each call, every window has length 1, so `loop_detection=True` can never fire. Worse, `self.windows` is a `defaultdict(list)` (loop_breaker.py:55) with no automatic eviction — only t […]

### GovernedData.ingest classifies the source locator string, not the ingested content
- **Where:** `admina/sdk/governed_data.py:260` · **Category:** bug · **Finder:** sdk-core
- **Impact:** The module promises "automatic data classification ... PII redaction" (lines 17-18). Anyone ingesting files/URLs (the primary flow for the built-in Filesystem/ChromaDB connectors) gets a meaningless LOW sensitivity in the forensic audit trail while PII-laden documents enter the store unflagged and unredacted — a false governance record for the exact data the residency/classification machinery exists to police.
- **Evidence:** governed_data.py:260-262: `content_for_scan = source if isinstance(source, str) else str(source)` then `pii_result = self._get_pii_redactor().redact(content_for_scan)` / `classification = _classify_content(content_for_scan, pii_result)`. But the connector contract defines source as "A file path, URL, bytes, or provider-specific locator" (plugins/base.py:143) — the actual documents are only read inside `await self._connector.ingest(source, **kwargs)` at line 294. So for the canonical path/URL ingest, the PII scan and sensitivity rating run on a string like "/data/customers.csv", which classifie […]


## MEDIUM (25)

### deep_path imperative-density signal counts distinct words via substring membership, not occurrences
- **Where:** `admina/domains/agent_security/firewall.py:531` · **Category:** bug · **Finder:** domains-security
- **Impact:** Two-sided defect: (a) false positives — ordinary prose/structured tool args containing substrings like 'customer'/'fingerprint' get Signal 1 (+0.3), and combined with special-char/context-switch signals from markdown/JSON can cross the 0.5 block threshold; (b) false negatives — long, densely-imperative injections dilute imp_density below the 0.1 gate, so the deep-path signal that is supposed to catch them never fires.
- **Evidence:** `imp_count = sum(1 for w in IMPERATIVE_WORDS if w in text_lower)` (line 531), then `imp_density = imp_count / word_count` (line 532). `w in text_lower` is a substring test, so words like 'must', 'print', 'output' match inside benign tokens ('customer', 'mustard', 'fingerprint', 'blueprint', 'footprint'). And because it sums distinct presence (capped at len(IMPERATIVE_WORDS)=18) rather than occurrences, a message repeating 'ignore' 100 times yields imp_count=1.

### Homoglyph normalization covers only a small Cyrillic/math subset — Greek and other lookalikes bypass it
- **Where:** `admina/domains/agent_security/firewall.py:37` · **Category:** security · **Finder:** domains-security
- **Impact:** An attacker substituting Greek (or any non-mapped script) lookalikes — e.g. 'ignοre' with a Greek omicron — produces text that neither the raw nor the normalized regex scan matches, defeating the instruction_override/multilang patterns. The map's docstring concedes it is 'a small but high-frequency subset', confirming the gap is real rather than incidental.
- **Evidence:** `_HOMOGLYPHS = str.maketrans({...})` (lines 37-66) maps only a subset of Cyrillic letters plus a few mathematical-bold characters and 'ꞵ'. The NFKC pass at line 125 (`unicodedata.normalize("NFKC", text)`) does NOT fold Greek or Cyrillic base letters (they are distinct, non-compatibility characters). Common Greek homoglyphs (omicron 'ο' U+03BF, alpha 'α', epsilon 'ε', rho 'ρ', iota 'ι', nu 'ν', upsilon 'υ', chi 'χ') are absent from the map and survive normalization unchanged.

### base.py advertises a builtin MCPTransportAdapter that does not exist — mcp.py defines only module functions, so no MCP transport is ever registered
- **Where:** `admina/plugins/base.py:311` · **Category:** docs-drift · **Finder:** plugins
- **Impact:** Anyone resolving the MCP transport through the plugin system (the framework's stated extension mechanism for protocols) finds nothing; the flagship protocol bypasses the very plugin interface its docs present as the built-in example.
- **Evidence:** base.py:310-312: `Default implementations:\n    * ``MCPTransportAdapter`` — JSON-RPC 2.0 (built-in).` But admina/plugins/builtin/transports/mcp.py contains no class at all — only module-level functions (`def parse_request(...)` line 35, `def format_block_response(...)` line 70, etc.) and it never imports BaseTransportAdapter. The proxy consumes it as a plain module (proxy/main.py:44 `import admina.plugins.builtin.transports.mcp as mcp_transport`), so `registry.list("transport_adapter")` contains only the HTTP REST adapter.

### EU AI Act template's YAML error handling catches ValueError, but PyYAML raises yaml.YAMLError — malformed YAML crashes the constructor instead of degrading
- **Where:** `admina/plugins/builtin/compliance/eu_ai_act.py:87` · **Category:** bug · **Finder:** plugins
- **Impact:** The graceful-degradation path (warn and return empty requirements) is unreachable for the failure it was written for; an edited/corrupted eu_ai_act.yaml turns into an unhandled exception in whatever instantiates the template, instead of a logged warning.
- **Evidence:** eu_ai_act.py:85-89: `try:\n    return yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8")) or {}\nexcept (OSError, ValueError) as exc:\n    logger.warning("Failed to load EU AI Act YAML: %s", exc)\n    return {}`. PyYAML parse failures raise yaml.YAMLError subclasses (ScannerError, ParserError), and `yaml.YAMLError` derives from Exception, not ValueError — so the except clause never catches a malformed file and `EUAIActComplianceTemplate()` (line 79-80 `self._data = self._load_yaml()`) raises.

### evaluate() silently drops unevaluated checks via zip truncation, inflating the compliance score
- **Where:** `admina/plugins/builtin/compliance/eu_ai_act.py:142` · **Category:** bug · **Finder:** plugins
- **Impact:** A high-risk system reporting only the checks it passes gets score 1.0 with zero gaps — the gap analysis omits every unreported check instead of treating it as unmet, producing an optimistically wrong EU AI Act compliance posture.
- **Evidence:** eu_ai_act.py:141-142: `checks = compliance.get(req_id, [False] * len(req_info["checks"]))\nfor check_desc, is_met in zip(req_info["checks"], checks):` — the [False]*n default only applies when the requirement key is absent entirely; if the caller supplies a shorter list (e.g. [True] for a 4-check requirement), zip truncates and the remaining 3 checks are excluded from `total`, `gaps`, and `covered`. Score is `round(passed / max(total, 1), 4)` (line 155).

### HTTPRESTTransportAdapter claims to expose POST /api/govern, but register_routes is a no-op and the endpoint is registered nowhere
- **Where:** `admina/plugins/builtin/transports/http_rest.py:92` · **Category:** docs-drift · **Finder:** plugins
- **Impact:** The documented REST governance endpoint for non-MCP callers (n8n, direct API consumers) does not exist anywhere in the application; users following the module docs get 404s, and the ABC's register_routes contract (base.py:363-372) is silently unfulfilled.
- **Evidence:** http_rest.py:17 "Provides a plain ``POST /api/govern`` endpoint" and class docstring line 39 "Exposes ``POST /api/govern`` ...", but register_routes() is: lines 88-92 `def register_routes(self, app: FastAPI) -> None:\n    """Register ``POST /api/govern`` on the FastAPI app."""\n    # Route registration is deferred to the proxy bootstrap;\n    # this method is a no-op when called during plugin discovery.\n    pass`. A repo-wide search for "api/govern" matches only these docstrings — the "proxy bootstrap" never registers the route either.

### format_block_response hardcodes reason "injection_detected" for every BLOCK, including guard and policy blocks
- **Where:** `admina/plugins/builtin/transports/mcp.py:91` · **Category:** consistency · **Finder:** plugins
- **Impact:** Clients and downstream audit consumers receive a factually wrong machine-readable block reason ("injection_detected") for blocks caused by toxicity, PII policy, or other guards — misleading incident triage and any automation keyed on the reason field.
- **Evidence:** mcp.py:83-95: the generic "Format a BLOCK governance response" helper always returns `"data": {"event_id": ..., "reason": "injection_detected", ...}`. It is used for all block types: proxy/main.py:1322 (any `governance_result["action"] == GovernanceAction.BLOCK`) and main.py:1393-1396, where a governance guard (e.g. GuardrailsAI toxicity/bias) blocking a response also returns `mcp_transport.format_block_response(gov_response, body)`.

### Registry cannot extract property-based plugin names — builtins register under lowercased class names, contradicting the documented lookup example
- **Where:** `admina/plugins/registry.py:366` · **Category:** consistency · **Finder:** plugins
- **Impact:** Plugin names are unpredictable and inconsistent across builtins: any consumer or operator following the documented contract (the ABC's `name` property value, e.g. "ollama", or config defaults like "filesystem"/"spacy-regex" in core/config.py:368-370) fails to resolve the plugin. Community plugins that correctly implement the ABC get registered under names their authors never chose.
- **Evidence:** registry.py:359-370: `for klass in cls.__mro__:\n    if attr in klass.__dict__:\n        val = klass.__dict__[attr]\n        if isinstance(val, str):\n            return val\n        # If it's a property, we can't call it without an instance\n        break\n# Fallback: lower-cased class name`. All 9 ABCs declare the name as `@property @abstractmethod` (e.g. base.py:100-103), and most builtins implement it as a property (ollama.py:117-120 `@property def name(self): return "ollama"`), so they register as "ollamaadapter", "openaiadapter", "chromadbconnector", "filesystemforensicstore", "spacyrege […]

### register() docstring promises ValueError on duplicate plugin names, but the implementation silently overwrites — later-discovered plugins can replace builtins
- **Where:** `admina/plugins/registry.py:111` · **Category:** docs-drift · **Finder:** plugins
- **Impact:** Name collisions are silently resolved by replacement: any user-directory file or pip-installed entry-point exposing a plugin named e.g. "webhook" or "log" replaces the builtin alert channel with only a warning-level log line — a quiet substitution vector for governance components, and behavior opposite to the documented API contract.
- **Evidence:** registry.py:97-99 docstring: `Raises: ... ValueError: If the plugin name is already registered for its type.` vs the implementation at lines 111-119: `if name in bucket:\n    logger.warning("Plugin %s/%s already registered — overwriting with %s", ...)\nbucket[name] = cls` — no exception is ever raised. `_scan_entry_points` even guards `except (TypeError, ValueError)` (line 245) for a ValueError that cannot occur. Discovery order is builtin → ~/.admina/plugins → yaml modules → entry-points (lines 188-213), so the last source wins.

### _load_file's narrow exception tuple lets any non-Import error in a user plugin file crash discover() and proxy startup
- **Where:** `admina/plugins/registry.py:294` · **Category:** bug · **Finder:** plugins
- **Impact:** One typo'd or broken file dropped into ~/.admina/plugins prevents the entire proxy from starting (or kills `admina plugin list`), defeating the registry's own isolation intent demonstrated in the entry-point path. The failed module is also left in sys.modules (inserted at line 285 before exec).
- **Evidence:** registry.py:287-296 catches only `ModuleNotFoundError`, then `except (ImportError, AttributeError, RuntimeError): logger.warning("Failed to import plugin file %s", ...)`. Module-level code in a plugin raising anything else — SyntaxError, ValueError, KeyError, FileNotFoundError(OSError), TypeError — propagates out of `spec.loader.exec_module(mod)` (line 286). `~/.admina/plugins/` is scanned by default (lines 203-205) and `state.registry.discover()` runs in the proxy lifespan (admina/proxy/main.py:124). Contrast with `_scan_entry_points`, which deliberately isolates: line 233 `except Exception:  […]

### Documented admina.yaml `plugins:` registration is not wired — no caller ever passes extra_modules to discover()
- **Where:** `admina/plugins/registry.py:21` · **Category:** docs-drift · **Finder:** plugins
- **Impact:** A user who follows the official ABC docstring and lists their plugin module under `plugins:` in admina.yaml gets nothing — the module is never imported, with no warning anywhere, because the configured list never reaches the registry.
- **Evidence:** registry.py:17-21 docstring: "The registry scans three locations ... 3. ``admina.yaml`` ``plugins:`` list — explicit module paths", and base.py:25-26: "registering it in ``admina.yaml`` under the ``plugins:`` section". AdminaConfig parses the field (core/config.py:223 `plugins: list[str] = field(default_factory=list)`), but every discover() call site invokes it bare: admina/proxy/main.py:124 `state.registry.discover()`, admina/cli/main.py:893 `registry.discover()`, cli/main.py:1218 `count = reg.discover()`. A repo-wide search finds no caller passing `extra_modules`.

### WebSocket auth ignores plugin auth providers, diverging from the HTTP middleware
- **Where:** `admina/proxy/api/dashboard.py:220` · **Category:** consistency · **Finder:** proxy-auth
- **Impact:** A deployment configured with ONLY a plugin auth provider (e.g. JWT/LDAP) and no ADMINA_API_KEY can authenticate every HTTP endpoint but can never open the live feed: `expected` is empty and the `elif not ALLOW_UNAUTHENTICATED` branch closes the socket. Conversely the WS cannot honor any plugin credential, so HTTP and WS authorization decisions diverge for the same user.
- **Evidence:** `dashboard_live` only knows about the static key: `expected = getattr(settings, "ADMINA_API_KEY", "") or ""` ... `elif not getattr(settings, "ALLOW_UNAUTHENTICATED", False): await websocket.close(code=1008)` (dashboard.py:220-237). It never consults `state.auth_providers`, which the HTTP middleware uses as its primary auth (main.py:579-595). The `@app.middleware("http")` does not run for WebSocket scope, so this handler is the only gate.

### Dashboard suggestion/trend engine cannot read firewall categories under the Rust engine
- **Where:** `admina/proxy/api/dashboard.py:605` · **Category:** consistency · **Finder:** proxy-pipeline
- **Impact:** When the Rust engine is active, every firewall detection stored in ClickHouse lacks the `patterns`/`fast_path.patterns` structure, so `cats` is always empty and all firewall-category suggestions and trend/surge detections silently produce nothing. Operators on the Rust engine get no policy-tuning guidance at all.
- **Evidence:** The suggestions endpoint extracts firewall categories expecting the Python result shape: `fw = d.get("firewall", {}) or {}; patterns = list(fw.get("patterns") or []); if not patterns and isinstance(fw.get("fast_path"), dict): patterns = list(fw["fast_path"].get("patterns") or []); cats = {p.get("pattern") for p in patterns if p.get("pattern")}` (dashboard.py:605-609). The Rust bridge result has neither `patterns` nor `fast_path` — it returns `matched_patterns` (a list of plain strings): engine_bridge.py:114-122. The same Python-shape assumption is repeated in the trend block at dashboard.py:74 […]

### Rust engine get_stats() keys are not normalized to the Python schema — Prometheus metrics silently report 0
- **Where:** `admina/proxy/engine_bridge.py:124` · **Category:** consistency · **Finder:** proxy-pipeline
- **Impact:** Under the Rust engine, admina_firewall_total_checked, admina_firewall_total_blocked, admina_firewall_detections_total, admina_loop_breaker_total_blocked and admina_pii_total_redacted all export 0 regardless of actual traffic, and /api/stats shows mismatched keys. Dashboards and alerting built on these metrics go blind exactly when the high-throughput Rust engine is in use.
- **Evidence:** The Rust bridges return the raw Rust dict unchanged: `_RustFirewallBridge.get_stats` -> `return self._impl.get_stats()` (engine_bridge.py:124-125), same for PII (157-158) and loop (188-189). Rust uses native key names: firewall `checks_total`/`injections_detected`, no `detections_by_type` (firewall.rs:344-345); PII `total_scans`/`total_redactions` (pii.rs:167-168); loop `total_checks`/`loops_detected` (loop_breaker.rs:166-167). The Prometheus exporter reads the Python names: `fw_stats.get("total_checked")`/`fw_stats.get("total_blocked")` and `for cat,count in (fw_stats.get("detections_by_type" […]

### Observe/dry-run mode redacts PII inconsistently — firewall-flagged requests forwarded with PII intact
- **Where:** `admina/proxy/governance.py:98` · **Category:** consistency · **Finder:** proxy-pipeline
- **Impact:** Within a single observe/dry-run deployment, clean traffic is forwarded PII-redacted but any request that also trips the firewall is forwarded to the upstream with PII fully intact. Operators running observe mode for tuning unknowingly leak PII on precisely the suspicious requests, and the behaviour is internally inconsistent.
- **Evidence:** PII redaction only runs when the action is still ALLOW: `if result.action == GovernanceAction.ALLOW and pii_enabled:` (governance.py:98). When the firewall flags injection, action becomes BLOCK at governance.py:92 BEFORE the PII step, so step 3 is skipped and `result.redacted_body` stays equal to the original `body`. Then the observe/dry-run downgrade resets the action to ALLOW: `result.action = GovernanceAction.ALLOW` (governance.py:133), and main.py forwards `redacted_body` (the un-redacted original) upstream (main.py:1360-1369). A clean request in the same mode DOES get PII redacted (step 3 […]

### Governance guard REDACT action is silently upgraded to a hard BLOCK
- **Where:** `admina/proxy/governance.py:112` · **Category:** consistency · **Finder:** proxy-pipeline
- **Impact:** A guard that asks to REDACT (sanitize and continue) instead causes a full block of the request or response, with no redaction attempted and no record distinguishing the intent. Guards designed around the documented REDACT semantics fail closed in a way callers do not expect, and the block response is labelled `injection_detected` regardless of the real guard reason.
- **Evidence:** Request inspection: `if guard_result.get("action") in ("BLOCK", "REDACT"): result.action = GovernanceAction.BLOCK` (governance.py:112-113). Response inspection does the same and returns a 403: `if guard_result.get("action") in ("BLOCK", "REDACT"): ... return JSONResponse(status_code=403, content=mcp_transport.format_block_response(...))` (main.py:1384-1397). `GovernanceAction.REDACT` is defined in core/types.py:55 but is never produced, and the v1 integration endpoint instead uses a `MODIFY` action for PII (integration.py:105-106).

### Auth middleware catches a narrower exception set than the documented provider failure contract
- **Where:** `admina/proxy/main.py:586` · **Category:** bug · **Finder:** proxy-auth
- **Impact:** A community auth provider that follows the documented contract and raises a non-(ValueError/RuntimeError/OSError) exception on an invalid credential will crash the request with HTTP 500 instead of failing over to the next provider or returning a clean 401, and it short-circuits the remaining providers in the chain. Malformed tokens become 500s, harming both reliability and clean rejection semantics.
- **Evidence:** The provider loop catches only `except (ValueError, RuntimeError, OSError): continue` (main.py:586), but `BaseAuthProvider.authenticate` documents `Raises: Exception: If authentication fails.` (base.py:491-492) and the example providers (JWT decode, etc.) raise library-specific errors. `APIKeyAuthProvider` happens to raise `PermissionError` (a subclass of OSError) so it is caught, but a JWT/OAuth provider raising e.g. `jwt.InvalidTokenError`, `KeyError`, or a bare `Exception` on a bad token is not caught.

### MultiUpstreamRouter inflates per-route request_count 2-3x per forwarded request
- **Where:** `admina/proxy/multi_upstream.py:88` · **Category:** bug · **Finder:** proxy-pipeline
- **Impact:** Each actual upstream request increments a route's request_count two times (path-based routing) or three times (tool-based routing). The per-route `requests` figure surfaced by get_stats()/`/api/stats` is inflated 2-3x, corrupting traffic accounting and any capacity/cost analysis built on it.
- **Evidence:** `resolve()` mutates state as a side effect: `route = self.routes.get(server_name); if route: route.request_count += 1` (multi_upstream.py:88-93). Both `get_upstream_url` (multi_upstream.py:111-117) and `get_upstream_headers` (multi_upstream.py:119-125) call `resolve()`, and `resolve_by_tool` (95-100) also calls `resolve()`. The forward path in main.py invokes all of these for a single request: `tool_route = state.router.resolve_by_tool(tool_name)` (main.py:1346), then `upstream_url = state.router.get_upstream_url(server_name)` (main.py:1351) and `extra_headers = state.router.get_upstream_heade […]

### generate_report bypasses the bool normalisation done by gap_analysis — bool values raise TypeError
- **Where:** `admina/sdk/compliance_kit.py:311` · **Category:** bug · **Finder:** sdk-core
- **Impact:** A user who learned the documented bool shorthand from ComplianceKit.gap_analysis gets an unexplained TypeError from generate_report for the same input — inconsistent contract between the two public methods of the same class, and an uncaught crash instead of the ValueError validation gap_analysis provides.
- **Evidence:** compliance_kit.py:309-312: `gap_result = engine.gap_analysis(classification["risk_category"], current_compliance or {})` forwards the raw user dict to the engine, skipping the bool→list normalisation that the sibling method performs (lines 236-246). The engine executes `zip(req_info["checks"], checks)` (eu_ai_act.py:292), so `generate_report(..., current_compliance={"risk_management": True})` raises `TypeError: zip argument #2 must support iteration`. The same-named parameter is typed `dict[str, list[bool] | bool]` on gap_analysis (line 218) but `dict[str, list[bool]]` on generate_report (line […]

### DATA_ACCESS action=ALLOW emitted before the connector operation runs
- **Where:** `admina/sdk/governed_data.py:278` · **Category:** consistency · **Finder:** sdk-core
- **Impact:** Forensic/audit consumers see ALLOW data-access records for operations that failed or never touched data — the audit trail over-reports data access events and cannot be reconciled against actual connector activity.
- **Evidence:** governed_data.py:278-291 emits `GovernanceEvent(event_type=EventType.DATA_ACCESS, ... action="ALLOW", metadata={"operation": "ingest", ...})` and only afterwards calls `connector_result = await self._connector.ingest(source, **kwargs)` (line 294, no try/except); query() does the same (event at 356-369, connector call at 372). If the connector raises, the audit trail permanently records an allowed, successful-looking data access that never happened, with no compensating failure event.

### Adapter/upstream exception after the request event leaves the audit trail without a terminal event
- **Where:** `admina/sdk/governed_model.py:184` · **Category:** bug · **Finder:** sdk-core
- **Impact:** The docstring claims the primitive "emits governance events for every call" (governed_model.py:17-18,86-87), but every failed call produces a dangling MODEL_CALL/AGENT_REQUEST with no outcome record — auditors cannot distinguish in-flight, failed, or dropped calls, undermining the exactly-once request/response pairing that downstream forensic/OTEL subscribers rely on.
- **Evidence:** ask() emits MODEL_CALL first (governed_model.py:160-168) and only emits MODEL_RESPONSE after the adapter returns (lines 207-224); the adapter call `adapter_result = await self._adapter.send(redacted_prompt, context=context, **kwargs)` (lines 184-188) and the PII calls (173, 195) have no try/except, so any exception propagates raw and no failure/terminal event is ever emitted. Identical pattern in GovernedAgent.call (`upstream_result = await self._upstream(method, redacted_params, **kwargs)`, governed_agent.py:285 — AGENT_REQUEST at 229-237 never gets a matching AGENT_RESPONSE on failure). test […]

### Duplicate BaseModelAdapter/BaseDataConnector ABCs are type-incompatible with the plugin registry
- **Where:** `admina/sdk/governed_model.py:35` · **Category:** consistency · **Finder:** sdk-core
- **Impact:** A developer who subclasses the SDK's BaseModelAdapter (the natural import next to GovernedModel, and the one the SDK's own tests use) gets a TypeError from PluginRegistry.register; conversely, registry-resolved plugins.base subclasses fail mypy against GovernedModel's `adapter: BaseModelAdapter | None` annotation. Two identically-named, independently-maintained interfaces will keep drifting with no mechanism to keep them in sync.
- **Evidence:** governed_model.py:35-58 defines a second `class BaseModelAdapter(ABC)` (exported via `__all__` at line 32) and governed_data.py:35-62 a second `BaseDataConnector`, distinct from the "canonical plugin definition used by the registry" (its own words, lines 39-40) in plugins/base.py:45 and 111. The registry validates strictly against the plugins.base classes: `PLUGIN_TYPES = {"model_adapter": BaseModelAdapter, ...}` (registry.py:51-61) and `if issubclass(cls, base)` (registry.py:70), raising `TypeError(f"{cls.__name__!r} does not extend any known plugin base class")` (registry.py:106) for anythin […]

### Blocking spaCy/sklearn/regex work executed synchronously inside async governance methods
- **Where:** `admina/sdk/governed_model.py:173` · **Category:** bug · **Finder:** sdk-core
- **Impact:** In any concurrent asyncio application (the SDK's stated target — proxies, FastAPI), every governed call stalls the entire event loop for the duration of spaCy model load (hundreds of ms to seconds on first call) plus per-call NER/TF-IDF inference, serialising all other requests and defeating the point of the async API.
- **Evidence:** Inside `async def ask`, `pii_result = self._get_pii_redactor().redact(prompt)` (governed_model.py:173, again at 195) is a synchronous call; the first invocation constructs PIIRedactor, which loads the spaCy model on the spot (`self.nlp = _spacy.load(model_name)`, pii.py:168), and every call runs NER inference (`doc = self.nlp(redacted)`, pii.py:237) on the event loop. GovernedAgent.call likewise runs the firewall regex scan synchronously (`fw_result = self._get_firewall().check(text_to_scan)`, governed_agent.py:243) and the sklearn TF-IDF similarity (`tfidf_matrix = self.vectorizer.fit_transfo […]

### Loop breaker uses materially different algorithms in Python vs Rust
- **Where:** `core-rust/src/loop_breaker.rs:107` · **Category:** consistency · **Finder:** proxy-pipeline
- **Impact:** The same session content and the same window_size/similarity_threshold/max_consecutive config produce different circuit-break decisions depending on which engine is installed. A templated agent loop ('proceed with task 1/2/3 ...') that Python deliberately lets through will trip the Rust circuit breaker (HTTP 429), and conversely Rust's max-over-window can flag pairs Python's average smooths out. This is a behavioural-parity break in a safety-critical component.
- **Evidence:** Python LoopBreaker uses sklearn TF-IDF (ngram (1,2), english stop words, max_features 500), averages pairwise cosine over the last 5 window entries, and applies a deliberate 0.7 damping when the 'variable tokens' (numbers/hex/URLs/UUIDs) differ across messages so legitimate counter/template loops do not trip: pii damping at loop_breaker.py:108-115, average-pairwise at 84-101, window[-5:] at 141. Rust uses plain term-frequency vectors (no IDF, no stop words, no ngrams), takes the MAX cosine over the whole window, and has NO variable-token damping: term_frequencies/cosine_similarity at loop_brea […]

### Rust PII scanner drops EU national IDs and NER that the Python redactor covers
- **Where:** `core-rust/src/pii.rs:28` · **Category:** security · **Finder:** proxy-pipeline
- **Impact:** Installing the Rust extra silently weakens redaction: Italian Codice Fiscale, Spanish DNI/NIE and all NER-detected names/orgs/locations pass through unredacted to the upstream and into forensic/ClickHouse storage. In an EU-first compliance framework this is a real data-sovereignty regression. Downstream consumers that match on the redaction marker also break because the token text differs by engine.
- **Evidence:** Rust `get_pii_patterns()` defines only email, credit_card, ssn, phone, iban, ip_address (pii.rs:28-62). The Python `PIIRedactor` additionally redacts IT_CODICE_FISCALE, ES_DNI_NIE, DE_PERSONALAUSWEIS and spaCy NER categories PERSON/ORG/GPE/LOC/DATE_OF_BIRTH (pii.py:58-106, 235-254). `get_pii_scanner()` auto-selects Rust when available (engine_bridge.py:231-235) with no parity caveat — the bridge advertises Rust as a transparent "10-100x speedup". Mask tokens also diverge: Rust emits `[EMAIL_REDACTED]` / `[CC_REDACTED]` (pii.rs:33,38) vs Python `[EMAIL]` / `[CREDIT_CARD]` (pii.py:63,65).


## LOW (21)

### base.py advertises builtin 'EUAIActTemplate' and 'GDPRTemplate' compliance plugins; neither exists under that name and there is no GDPR template at all
- **Where:** `admina/plugins/base.py:248` · **Category:** docs-drift · **Finder:** plugins
- **Impact:** Users looking up the promised GDPR compliance template (a headline capability for the framework's audience) find that the documented default implementation does not exist.
- **Evidence:** base.py:246-248: `Default implementations:\n    * ``EUAIActTemplate`` — EU AI Act Art. 6-15 (built-in).\n    * ``GDPRTemplate`` — GDPR basics (built-in).` The actual class is `EUAIActComplianceTemplate` (eu_ai_act.py:72), and admina/plugins/builtin/compliance/ contains only __init__.py, eu_ai_act.py and eu_ai_act.yaml — no GDPR BaseComplianceTemplate exists anywhere (the GDPR code in admina/domains/compliance/gdpr.py is a ProcessingActivitiesRegistry, not a compliance template plugin).

### ABC says get_requirements checks are list[callable]; the builtin template returns plain strings
- **Where:** `admina/plugins/base.py:274` · **Category:** consistency · **Finder:** plugins
- **Impact:** Community template authors following the ABC contract will produce callables that no evaluator invokes, while code written against the builtin expects strings — the two documented shapes are incompatible.
- **Evidence:** base.py:272-275: `Returns: A list of dicts, each with ``{"id": str, "title": str, "checks": list[callable]}``.` The only builtin implementation returns YAML strings: eu_ai_act.py:107 `"checks": req_info["checks"]` where the YAML defines checks as prose strings (eu_ai_act.yaml, e.g. `- "Documented risk management process"`), and the implementation's own docstring (eu_ai_act.py:97-98) says `"checks": list[str]`.

### ChromaDBConnector.ingest docstring claims kwargs like collection_name are supported, but kwargs are never read
- **Where:** `admina/plugins/builtin/connectors/chromadb.py:79` · **Category:** docs-drift · **Finder:** plugins
- **Impact:** Callers passing collection_name to ingest() silently write to the default collection instead of the requested one — documented option is a no-op.
- **Evidence:** chromadb.py:79 docstring: `**kwargs: Extra options (``collection_name``, etc.).` — but the method body (lines 84-101) never references kwargs: it always uses `self._get_collection()` bound to `self._collection_name` and returns `"collection": self._collection_name`. (query() does read its documented `top_k` kwarg, line 114.)

### FilesystemConnector.ingest ignores base_dir — paths resolve against CWD while query searches base_dir
- **Where:** `admina/plugins/builtin/connectors/filesystem.py:59` · **Category:** consistency · **Finder:** plugins
- **Impact:** A connector configured with base_dir=/data counts files relative to wherever the process happens to run, and documents "ingested" that query() will never see — inconsistent semantics within the same plugin's two methods.
- **Evidence:** Constructor docstring (lines 35-37) says `base_dir: Root directory for file operations` and line 40 stores `self._base_dir = Path(base_dir).resolve()`, but ingest() builds paths without it: lines 56-64 `paths = [Path(p) for p in source]` / `p = Path(source)` — relative sources resolve against the process CWD. Only query() uses base_dir (line 89 `for fp in self._base_dir.glob(pattern)`); ingest results have no relationship to what query later searches.

### GuardrailsAIGuard ALLOW results omit the 'details' key required by the BaseGovernanceGuard return contract
- **Where:** `admina/plugins/builtin/guards/guardrailsai_guard.py:152` · **Category:** consistency · **Finder:** plugins
- **Impact:** Pipeline code or community tooling indexing result["details"] per the documented shape gets KeyError on the common ALLOW path; the synchronous validate() additionally blocks the proxy event loop for the duration of local ML inference on every inspected request/response.
- **Evidence:** base.py:212-214 contract: `Returns: A dict with {"action": "ALLOW"|"BLOCK"|"REDACT", "risk_level": str, "details": str}`. guardrailsai_guard.py:152 returns `{"action": "ALLOW", "risk_level": "LOW", "guard": "guardrailsai"}` and lines 157-162 the validated-ALLOW branch also has no "details" (only BLOCK at line 168 includes `"details": str(outcome.error)`). The guard also runs blocking ML validation `outcome = self._guard.validate(text)` (line 154) inside the async inspect_* methods awaited on the proxy hot path (proxy/main.py:1383).

### _extract_name's pii_engine → 'supported_languages' mapping is dead code, short-circuited two lines later
- **Where:** `admina/plugins/registry.py:348` · **Category:** dead-code · **Finder:** plugins
- **Impact:** Dead mapping entry confuses maintainers, and the mirrored CLI scaffold metadata generates pii-engine plugin templates treating supported_languages as the naming property — propagating the inconsistency to community plugin authors.
- **Evidence:** registry.py:340-350 builds `name_attrs = {... "pii_engine": "supported_languages", ...}` and line 352 `attr = name_attrs.get(type_key, "name")`, but lines 354-356 immediately override: `# For pii_engine, the identifier is not a name property — use class name\nif type_key == "pii_engine":\n    return cls.__name__.lower()` — the "supported_languages" attr value is never used (and would be a list, not a name). The same odd mapping is mirrored in cli/main.py:874 `"pii_engine": ("BasePIIEngine", "supported_languages", "pii")` and fed to plugin scaffolding as `name_property`.

### Entry-point fallbacks for Python <3.8 and 3.9 are unreachable under requires-python >=3.11
- **Where:** `admina/plugins/registry.py:227` · **Category:** dead-code · **Finder:** plugins
- **Impact:** Unreachable compatibility branches add noise and an untestable code path (the type: ignore'd dict fallback) for interpreter versions the package refuses to install on.
- **Evidence:** registry.py:221-229: `try:\n    from importlib.metadata import entry_points\nexcept ImportError:  # pragma: no cover (Python < 3.8)\n    return 0\ntry:\n    eps = entry_points(group=group)\nexcept TypeError:\n    # Python 3.9 entry_points() returns a dict\n    eps = entry_points().get(group, [])` — but pyproject.toml:25 declares `requires-python = ">=3.11"`, where importlib.metadata always exists and entry_points(group=...) is always supported.

### API key accepted via WebSocket query string ends up in logs and history
- **Where:** `admina/proxy/api/dashboard.py:228` · **Category:** security · **Finder:** proxy-auth
- **Impact:** Operators or tooling that connect the live feed with `?api_key=` leak the long-lived static API key into log sinks and browser history, where it survives far longer than the request and is commonly shipped to centralized logging.
- **Evidence:** `provided = (... or websocket.query_params.get("api_key") or ...)` (dashboard.py:226-231). The raw `ADMINA_API_KEY` passed as `/api/dashboard/live?api_key=<key>` is recorded verbatim in reverse-proxy/access logs, server request logs, and browser history, unlike a header or cookie. The docstring acknowledges browsers cannot set WS headers (dashboard.py:213-218) but offers this query-string fallback.

### INJECTION_DEEP_PATH_ENABLED is dead config; INJECTION_FAST_PATH_ENABLED gates the whole scan
- **Where:** `admina/proxy/config.py:121` · **Category:** dead-code · **Finder:** proxy-pipeline
- **Impact:** Setting INJECTION_DEEP_PATH_ENABLED=false has no effect — the heuristic deep path always runs. INJECTION_FAST_PATH_ENABLED=false disables ALL injection detection (both paths), not just the fast path, contradicting its name. Operators get the opposite of what these settings imply.
- **Evidence:** `INJECTION_DEEP_PATH_ENABLED: bool = True` (config.py:121) is never read anywhere (grep finds only this definition). The pipeline is wired with only the fast-path flag: `injection_enabled=settings.INJECTION_FAST_PATH_ENABLED` (main.py:1221), and that flag gates the ENTIRE injection block (governance.py:86 `if result.action != ... and injection_enabled`). Neither bridge accepts the flags: `_PythonFirewallBridge` builds `InjectionFirewall(...)` which has no fast/deep parameters (firewall.py:437-475), and `_RustFirewallBridge` calls `admina_core.RustFirewall()` with defaults (engine_bridge.py:111 […]

### MCPRequest / MCPResponse pydantic models are dead code
- **Where:** `admina/proxy/config.py:182` · **Category:** dead-code · **Finder:** proxy-pipeline
- **Impact:** Dead protocol models that suggest a validation path the proxy does not actually use. Future maintainers may assume incoming MCP bodies are validated against these schemas (they are not — `request.json()` is consumed as a bare dict).
- **Evidence:** `class MCPRequest(BaseModel)` (config.py:182-187) and `class MCPResponse(BaseModel)` (config.py:189-193) are defined but never imported or instantiated anywhere (grep for `MCPRequest` across admina/ and tests/ returns only the definition line). The proxy parses requests via `mcp_transport.parse_request(...)` (main.py:1184) and works on raw dicts; the only `MCPResponse`-named symbol in use is the unrelated SDK `GovernedMCPResponse`.

### MAX_REQUEST_TOKENS is enforced against character count, not tokens
- **Where:** `admina/proxy/main.py:1191` · **Category:** consistency · **Finder:** proxy-pipeline
- **Impact:** The limit is roughly 4x tighter than its name implies (≈100k characters ≈ 25k tokens at the default of 100000). Operators sizing the guard in tokens will set a value that rejects far smaller payloads than intended, or believe they have headroom they do not.
- **Evidence:** `if settings.MAX_REQUEST_TOKENS > 0 and len(content_str) > settings.MAX_REQUEST_TOKENS:` (main.py:1191), where `content_str` is the JSON-serialized request body (a character string, set in mcp.py:53 `content_str = json.dumps(body, default=str)`). The 413 error data reports `"max_tokens": settings.MAX_REQUEST_TOKENS` (main.py:1203) and the setting is named TOKENS (config.py:123).

### Upstream non-2xx responses are passed through to the client as HTTP 200
- **Where:** `admina/proxy/main.py:1371` · **Category:** bug · **Finder:** proxy-pipeline
- **Impact:** Clients and middleboxes that key off HTTP status (retries, circuit breakers, dashboards) see success even when the upstream errored. The JSON-RPC error body is preserved, so functional MCP clients still parse the error, but the HTTP-level signal is wrong, complicating monitoring and automated retry logic.
- **Evidence:** After forwarding, the proxy never checks the upstream status: it does `response_data = upstream_response.json()` (main.py:1371) and unconditionally returns `JSONResponse(content=response_data, headers=headers)` (main.py:1411), which defaults to status_code=200. There is no `raise_for_status()` anywhere in main.py (grep confirms none). A 4xx/5xx returned by the upstream MCP server is relayed to the client with an HTTP 200.

### ComplianceKit spins up a fresh event loop or thread per audit event
- **Where:** `admina/sdk/compliance_kit.py:359` · **Category:** consistency · **Finder:** sdk-core
- **Impact:** Audit emission cost and the foreign-loop subscriber hazard are baked into every compliance call; in async apps each ComplianceKit invocation briefly blocks the event loop and delivers its COMPLIANCE_CHECK event on a throwaway loop other than the one subscribers were registered on.
- **Evidence:** compliance_kit.py:351-359: `def _emit_sync(event): ... run_sync(bus.emit(event))` — called once per classify_risk/gap_analysis/generate_report. From sync code each emit pays a full `asyncio.run()` loop create/teardown; from async code each emit spawns a ThreadPoolExecutor thread plus a new loop (_compat.py:41-43) and blocks the caller's loop, with the cross-loop subscriber hazard described for run_sync. ComplianceKit is the only SDK primitive with no async API at all (all methods sync).

### GovernedMCPResponse.risk_level hardcoded to LOW on allowed calls, ignoring the firewall's assessed risk
- **Where:** `admina/sdk/governed_agent.py:326` · **Category:** consistency · **Finder:** sdk-core
- **Impact:** Consumers reading the documented `risk_level: Risk level of the request` field (line 42) get a constant "LOW" for every allowed call and miss the firewall's actual elevated-risk assessment unless they dig into the nested governance dict (which also still holds non-serialisable RiskLevel enums).
- **Evidence:** governed_agent.py:323-328 returns `GovernedMCPResponse(result=redacted_result, action=action, risk_level="LOW", governance=governance)` — risk_level is a literal. The firewall can legitimately return an elevated risk without blocking: deep_path yields `risk = RiskLevel.MEDIUM` for 0.3 <= score < 0.5 while `is_injection = score >= 0.5` is False (firewall.py:562-569), and that result is stored in `governance["firewall"]` (line 244). So the same response object reports risk_level="LOW" at the top level and MEDIUM inside governance.

### VALID_ZONES is dead code and residency zones are never validated
- **Where:** `admina/sdk/governed_data.py:100` · **Category:** dead-code · **Finder:** sdk-core
- **Impact:** The constant suggests zone validation that does not exist: a typo like residency_zone="EU" silently creates a self-consistent zone (allowed_zones={"EU"}) and all residency checks pass, so a misconfigured deployment never notices the canonical "eu" policies are not what it is enforcing.
- **Evidence:** governed_data.py:99-100: `# Allowed residency zones` / `VALID_ZONES = {"local", "eu", "us", "custom"}` — the set is never referenced anywhere else in the module and is not in `__all__` (line 32). The constructor accepts any string unvalidated (`residency_zone: str = "local"`, lines 155-176) and `_check_residency` only tests membership in the instance's own `allowed_zones` (lines 199-204).

### _classify_content's `text` parameter is documented but never used
- **Where:** `admina/sdk/governed_data.py:110` · **Category:** dead-code · **Finder:** sdk-core
- **Impact:** Dead parameter implying content-based classification that doesn't happen; misleads maintainers and callers about what drives the sensitivity rating.
- **Evidence:** governed_data.py:110-138: `def _classify_content(text: str, pii_result: dict) -> dict[str, Any]:` documents `text: The original text.` (line 114) but the body derives everything from `pii_result` only (`pii_count = pii_result.get("count", 0)`, `pii_types = {e["type"] for e in pii_result.get("entities", [])}`, lines 120-121); `text` is never read.

### Explicit empty allowed_zones (deny-all) is silently replaced by the permissive default
- **Where:** `admina/sdk/governed_data.py:176` · **Category:** bug · **Finder:** sdk-core
- **Impact:** A caller deliberately configuring zero allowed zones to lock down data access gets the opposite: access to the residency zone is silently allowed — a classic falsy-`or` default applied to a security-relevant parameter.
- **Evidence:** governed_data.py:176: `self.allowed_zones = allowed_zones or {residency_zone}` — an explicitly passed empty set is falsy, so `GovernedData(connector, allowed_zones=set())` (deny-all intent) becomes `allowed_zones={"local"}`, and `_check_residency("local")` (lines 199-204) then permits ingest/query in the default zone. The docstring only says it "Defaults to {residency_zone}" when omitted (lines 169-170), i.e. for None.

### GovernedModel docstring promises a default adapter and registry resolution that don't exist
- **Where:** `admina/sdk/governed_model.py:91` · **Category:** docs-drift · **Finder:** sdk-core
- **Impact:** Users reading the class docstring expect `GovernedModel("llama3")` to work out of the box ("None for default") and instead hit a RuntimeError at first ask(); the advertised PluginRegistry integration is left entirely to the caller.
- **Evidence:** governed_model.py:91: `adapter: A BaseModelAdapter instance, or None for default.` and lines 107-108: `adapter: Adapter instance. Can be resolved via :class:`PluginRegistry` or passed explicitly.` But ask() with adapter=None unconditionally raises `RuntimeError("No model adapter configured. Pass an adapter to GovernedModel() or resolve one via PluginRegistry.")` (lines 146-150); no code path in the class performs any default or registry resolution.

### Auto-generated session_id is never surfaced to the caller, breaking audit correlation
- **Where:** `admina/sdk/governed_model.py:152` · **Category:** consistency · **Finder:** sdk-core
- **Impact:** Callers who don't pre-supply a session_id (the default usage shown everywhere) cannot map a returned response/document back to its audit events — the correlation key exists only inside the event stream, weakening the traceability story the events are meant to provide.
- **Evidence:** governed_model.py:152: `session_id = kwargs.pop("session_id", None) or str(uuid.uuid4())` — the generated id is attached to the MODEL_CALL/MODEL_RESPONSE events (lines 161-168, 211-224) but appears nowhere in the returned GovernedResponse or its governance dict (lines 154-157, 227-231). Same pattern in GovernedAgent.call (governed_agent.py:224) and GovernedData.ingest/query (governed_data.py:236, 336).

### Latency measured with wall-clock time.time() instead of a monotonic clock
- **Where:** `admina/sdk/governed_model.py:153` · **Category:** bug · **Finder:** sdk-core
- **Impact:** Audit/forensic records and the governance dict can carry negative or skewed latency figures after a clock adjustment, and the codebase is internally inconsistent about how it measures duration.
- **Evidence:** governed_model.py:153 `start_us = time.time() * 1_000_000` and 203 `latency_us = time.time() * 1_000_000 - start_us`; same in governed_agent.py:225/299/352 and governed_data.py:237/296. time.time() is subject to NTP steps/DST adjustments, so latency_us can be negative or wildly wrong; the value is persisted into MODEL_RESPONSE/AGENT_RESPONSE audit event metadata (governed_model.py:219). The firewall in the same codebase correctly uses `time.perf_counter()` (firewall.py:488).

### A raising event-bus subscriber aborts the governed call after the model response was already obtained
- **Where:** `admina/sdk/governed_model.py:211` · **Category:** bug · **Finder:** sdk-core
- **Impact:** With audit=True (the default), one faulty operator-wired subscriber (OTEL exporter, webhook, dashboard) turns every successful, already-paid-for model call into an exception for the caller, and silently starves later subscribers of the event.
- **Evidence:** ask() awaits `bus.emit(...)` directly on the response path (governed_model.py:211-224) and EventBus.emit has no error isolation: `for callback in callbacks: result = callback(event); if asyncio.iscoroutine(result): await result` (event_bus.py:106-109) — the first subscriber that raises propagates out of emit, out of ask(), and skips all remaining subscribers. The adapter call at line 184 has by then already completed.

---

## Disposition — where each critical/high lands in the 0.10 plans

| Finding | Plan |
|---|---|
| forensic/filesystem.py:77 chain reset/overwrite (CRITICAL) | Plan 04 — D6 forensic (extends scope) |
| forensic/filesystem.py:99 verify_chain blind to tail truncation | Plan 04 — D6 forensic (extends scope) |
| governed_agent.py:224 per-call session_id no-op + memory leak | Plan 03 — D2 pipeline (already in spec) |
| governed_agent.py:121 deep-scan bypass (>5 depth, dict keys) | Plan 03 — D2 pipeline (added) |
| governance.py:126 observe-mode analytics never populate | Plan 03 — D2 pipeline (added) |
| governed_data.py:260 classifies locator, not content | Plan 03 — D2 pipeline (added) |
| proxy/main.py:621 fail-open default; dead 401 branch | Plan 05 — WS-auth/auth unification (added, HIGH PRIORITY) |
| apikey.py:137 signed cookie rejected by auth path | Plan 05 — WS-auth (already in spec) |
| dashboard.py:232 WS cookie vs raw key | Plan 05 — WS-auth (already in spec) |
| ollama.py:98 / openai.py:113 blocking sync in async | Plan 06 — retry (already in spec: asyncio.to_thread) |
| alerts/webhook.py:98 blocking urlopen in async | Plan 06 — retry (added alongside) |
| compliance_kit.py:239 zip truncation inflates compliance score | Plan 07 — D-docs/compliance honesty (added; NIS2 pads correctly — mirror it) |
| pii/spacy_regex.py:124 overlapping matches corrupt redaction | Plan 04 — PII/Presidio (added as pre-task) |

Rust-vs-Python parity findings (loop_breaker.rs, pii.rs, firewall homoglyph subset,
engine_bridge get_stats schema) stay on the tracked Rust-parity workstream — NOT 0.10,
except engine_bridge.py:124 get_stats normalization which Plan 02 (engines) absorbs.

---

## Addendum (2026-06-13) — Rust PII findings surfaced during Plan 02 review

Two findings about the `admina_core` (Rust) PII scanner, surfaced empirically while
wiring `admina/engines` (Plan 02 Task 5 review):

- **[HIGH → mitigated] Rust PII recall gap vs Python.** The Rust scanner does NOT
  redact EU national IDs (IT codice fiscale, ES DNI, DE Personalausweis) nor NER
  PERSON/ORG that the Python engine catches. Making the SDK/proxy default to Rust PII
  would silently under-redact. **Mitigation shipped (commit 2c68b27):** `admina/engines`
  now keeps the PII path on **Python under `ADMINA_ENGINE=auto`** (recall-safe default);
  Rust PII is opt-in via explicit `ADMINA_ENGINE=rust`. Firewall/loop keep Rust under auto.
  Pinned by `tests/test_engines.py::test_default_pii_redacts_eu_national_ids` and
  `::test_pii_recall_safe_default`. The underlying Rust recall gap remains a
  tracked `admina_core` parity item (not 0.10).

- **[MED] Rust IBAN misclassified as phone.** `RustPiiScanner.redact()` matches an IBAN
  with the phone pattern and emits `[PHONE_REDACTED]`, leaving a leading IBAN fragment
  (e.g. `IT60X0542811`) unredacted — wrong category label + partial leak. File against
  `admina_core`. Mirrors the Python IBAN/credit-card overlap defect already logged
  (pii.py overlapping-match finding). Not reachable on the recall-safe default path.
