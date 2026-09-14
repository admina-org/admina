# Admina — Component Card

This document is the transparency artifact for the **rule-based and
heuristic components** that ship inside Admina. Admina does not train or
distribute machine-learning models in v0.11.x: the governance pipeline is
built on regex pattern sets, TF-IDF cosine similarity, SHA-256 hash
chains, and keyword-based EU AI Act classifiers. This card documents the
intended use, scope, limitations, and known failure modes of each
component, and is updated alongside the codebase.

The structure follows the spirit of [Mitchell et al., *Model Cards for
Model Reporting*](https://arxiv.org/abs/1810.03993), adapted for
deterministic rule-based systems, and aligns with the transparency
expectations of EU AI Act Art. 13, NIST AI RMF *Map / Measure*
functions, and ISO/IEC 42001 clause 8 (Operations).

> **This is not a substitute for a model card on any external LLM** that
> Admina governs (Ollama, OpenAI, etc.). Those systems remain the
> responsibility of their providers. Admina is the *governance layer*,
> not the model.

---

## 1. Component overview

| Component | Type | Engine | Source |
|-----------|------|--------|--------|
| Injection Firewall | Pattern matcher (RegexSet) + heuristic scorer | Rust (`core-rust/src/firewall.rs`) + Python fallback | `admina/domains/agent_security/firewall.py` |
| PII Scanner | Regex + spaCy NER (optional), or Microsoft Presidio (opt-in) | Python default even when Rust is installed; Rust (`core-rust/src/pii.rs`) only under an explicit `ADMINA_ENGINE=rust` | `admina/domains/data_sovereignty/`, `admina/engines/presidio.py` |
| Loop Breaker | TF-IDF cosine similarity over a sliding window | Rust (`core-rust/src/loop_breaker.rs`) + Python fallback | `admina/domains/agent_security/loop_breaker.py` |
| Egress Policy | Destination allowlist (exact host / `*.suffix` / CIDR) matched against tool-call arguments | Python only — no Rust variant | `admina/domains/agent_security/egress.py` |
| Coordination Detector | Fan-in counter over distinct agents, escalating to keyed shingle-sketch echo confirmation | Python only — no Rust variant; requires Redis — no Redis means no detection at all | `admina/domains/agent_security/coordination.py`, `admina/domains/agent_security/fingerprint.py` |
| Forensic Hash Chain | SHA-256 chained log | Rust (`core-rust/src/forensic.rs`) + Python fallback | `admina/domains/compliance/forensic.py` |
| EU AI Act Classifier | Keyword-based risk classifier + Annex III mapping | Python (`admina/domains/compliance/eu_ai_act.py`) | — |
| NIS2 Self-Assessment | Deterministic checklist (10 areas × 4 controls = 40 checks) + gap analysis | Python (`admina/domains/compliance/nis2.py`) | — |
| GDPR RoPA Registry | Typed CRUD over Art. 30 records with optional JSON-on-disk persistence | Python (`admina/domains/compliance/gdpr.py`) | — |
| GDPR DPIA Template | Markdown scaffold for Art. 35 DPIA from operator-supplied facts | Python (`admina/domains/compliance/gdpr.py`) | — |
| Cross-Regulation Matrix | Hand-curated mapping of 12 operational controls across AI Act / NIS2 / GDPR | Python (`admina/domains/compliance/cross_regulation.py`) | — |

All Rust components are pure functions exposed via PyO3. Rust is faster,
but the two engines are not behaviorally equivalent: on an internal
14-attack evasion corpus the Python firewall blocks all 14 while the Rust
firewall blocks 7 (plain-text and single-encoding attacks only). The Rust
PII engine also lacks EU national-ID patterns, spaCy NER, and Luhn
validation. Python is the higher-recall default; Rust is opt-in for
latency-sensitive workloads where the narrower coverage is acceptable.

---

## 2. Intended use

Admina is intended for organizations building or operating AI
applications who need:

1. Defense-in-depth against prompt injection of agentic and chat
   workloads.
2. Automatic redaction of personally identifiable information (PII)
   before content reaches an external LLM endpoint.
3. Tamper-evident audit logging suitable as evidence under EU AI Act
   Art. 12 (record keeping) and Art. 15 (cybersecurity).
4. Self-assessment tooling for EU AI Act conformity gaps under
   Articles 9–15.

### Out-of-scope uses

Admina is **not**:

- A certified conformity assessment body under EU AI Act Art. 43. A
  passing score in `ComplianceKit.gap_analysis()` does not constitute
  legal compliance and cannot replace the assessment of a notified body
  for high-risk systems where one is required.
- A replacement for legal counsel. The EU AI Act classifier is a
  pre-screening aid; final classification of an AI system requires legal
  review.
- A guarantee against all prompt injection attacks. New attack classes
  emerge continuously; the firewall covers known patterns at the time
  of release.
- A jailbreak detector calibrated for any specific commercial LLM. The
  firewall is model-agnostic and does not have access to the upstream
  model's instruction hierarchy.
- A general-purpose content safety classifier (toxicity, hate speech,
  CSAM, etc.). For those, plug in `GuardrailsAI` via the optional
  extra and rely on its native model cards.

---

## 3. Injection Firewall

### What it does

Scans inbound text for prompt-injection attempts. Two layers: a fast
path of compiled regexes run against the raw text *and* against an
evasion-normalised copy (homoglyph / leetspeak / char-by-char /
base64 neutralised), and a deep path that scores five heuristic signals
(`0.0`–`1.0`). The fast path returns matched **categories**; the deep
path returns **signals** (e.g. `imperative_density=0.14`) and a score,
never a category.

### Categories emitted (v0.11.0)

The Python engine — the default, higher-recall engine — emits exactly
**9** distinct category labels. This is the authoritative set: it is
what appears in `detections_by_type`
(`admina/domains/agent_security/firewall.py:593-595`), what becomes the
`category` label of the Prometheus series
`admina_firewall_detections_total`
(`admina/proxy/main.py:777-785`), and the set of values valid in
`agent_security.firewall.disabled_categories`
(`admina.yaml.example:53-58`).

Each category covers several **pattern families**. The families are not
categories: a match in any family is reported under the category label
of its group.

| Category | Risk | Pattern families grouped under it | Source |
|----------|------|-----------------------------------|--------|
| `instruction_override` | critical / high | verb + qualifier + target override phrasing (`ignore` / `disregard` / `forget` / `override` / `bypass` / `circumvent` / `skip` / `sidestep` / `nullify` / `cancel` / `suspend` / `drop` / `remove` / `undo` × `instructions` / `prompts` / `rules` / `directions` / `directives` / `guidelines` / `guardrails` / `restrictions` / `policies` / `filters` / `safeguards` / `the above` / `everything`); imperative verb chains ("Ignore. Forget. Override.") | `firewall.py:196-210` |
| `role_hijack` | high | "you are now a…"; "act as a / DAN / AIM / STAN / DUDE"; "pretend to be"; "let's roleplay / imagine"; "from now on you will" | `firewall.py:211-224` |
| `prompt_extraction` | high / medium | reveal / show / print / repeat the system prompt or configuration (high); "what are your instructions / rules" (medium) | `firewall.py:225-241` |
| `jailbreak` | critical | mode toggles (`DAN` / `developer` / `admin` / `debug` / `maintenance` / `god` / `sudo` / `root` / `jailbreak` / `uncensored` / `unrestricted` **mode enabled / activated / on**); "DAN mode / DAN prompt"; "do anything now"; AIM | `firewall.py:242-256` |
| `delimiter_injection` | critical / high | ChatML / Llama / FIM control tokens (`<\|im_start\|>`, `<\|endoftext\|>`, `[INST]`, `<<SYS>>`); `<system>` / `<user>` / `<assistant>` tags; `### system:` headers | `firewall.py:257-266` |
| `data_exfiltration` | high | `curl` / `wget` / `nc` to a URL; send / post / upload / forward / leak … to an external URL or a known burner domain (webhook.site, requestbin, ngrok.io, pastebin, gist) | `firewall.py:267-285` |
| `tool_abuse` | critical / high | shell execution (`exec`, `subprocess`, `os.system`, `sh -c`); sensitive filesystem paths (`/etc/passwd`, `~/.ssh/`, `~/.aws/credentials`, `/proc/self/environ`); internal / admin / private API calls; destructive commands (`rm -rf`, `DROP TABLE`, `mkfs.`, `dd if=`) | `firewall.py:286-322` |
| `obfuscation` | high / medium | base64 encode/decode markers; hex-escape runs (`\xNN\xNN\xNN`); ROT13 / Caesar-cipher markers; hex-escape-as-instruction | `firewall.py:323-333` |
| `multilang_evasion` | critical | override phrasing in Italian, French, Spanish and German (verb-then-target and target-then-adjective word orders) | `firewall.py:334-397` |

Operators can add further categories without forking: every entry in
`agent_security.firewall.custom_patterns` carries its own `category`
label, which flows through to the same stats and Prometheus series
(`admina/engines/__init__.py:125-131`, `admina.yaml.example:59-71`).

### Rust engine labels differ from Python's

The optional Rust accelerator (`core-rust/src/firewall.rs:89-106`) has
its own, narrower pattern set with **15** label strings. Earlier
versions of this card listed those 15 as if they were the framework's
categories — they are not. They are only visible in the Rust engine's
`matched_patterns` field; the Rust bridge reports an empty
`detections_by_type` (`admina/engines/__init__.py:216-227`), so no Rust
label ever reaches the stats API, the Prometheus series, or
`disabled_categories` (a non-empty `disabled_categories` forces the
Python bridge — `admina/engines/__init__.py:333-341`).

| Rust label | Python equivalent |
|------------|-------------------|
| `instruction_override` | `instruction_override` |
| `role_hijacking` | `role_hijack` (short form) |
| `developer_mode`, `dan_mode` | `jailbreak` |
| `jailbreak` ("bypass safety filters") | `instruction_override` |
| `ignore_safety` ("disable safety checks") | partly `instruction_override`; "disable / turn off / deactivate … checks" is not in the Python regex set and is left to the deep path |
| `prompt_extraction` | `prompt_extraction` |
| `system_prompt_leak` ("what are your instructions") | `prompt_extraction` (medium-risk family) |
| `delimiter_injection` | `delimiter_injection` |
| `data_exfiltration` | `data_exfiltration` |
| `obfuscation` | `obfuscation` |
| `multilang_evasion` | `multilang_evasion` |
| `tool_abuse` ("execute this command") | `tool_abuse` — Python requires a concrete target (path, destructive command), so a bare "run this script" does not match |
| `new_instructions` ("new system instructions:") | no Python equivalent — Rust-only pattern |
| `roleplay_escape` ("you have no restrictions") | no Python equivalent — Rust-only pattern |

### Languages

Patterns are written for English with an explicit subset for
`multilang_evasion` covering French, Italian, Spanish, German. Coverage
in other languages is best-effort. We accept contributions for
additional locales.

### Known limitations

- **Adversarial robustness is bounded.** An attacker who knows the
  pattern list can construct evasions (homoglyphs, base64-wrapped
  payloads, multi-turn split, character-level obfuscation beyond the
  current `obfuscation` regex). Admina is one layer in defense in depth,
  not a complete defense.
- **False positives on legitimate technical content.** Tutorials about
  prompt injection, security research papers, and red-team logs will
  trigger the firewall. Use the heuristic score to set a tolerance, or
  whitelist known-safe contexts at the application layer.
- **No semantic understanding.** The firewall does not understand
  intent. "Please ignore my previous email" matches `instruction_override`
  even though no LLM context is being overridden.
- **No context-window awareness.** The firewall sees one input at a time
  and does not detect attacks that span multiple turns or are split
  across tool outputs.

### How to extend

New patterns are contributed via PR to the authoritative Python set in
`admina/domains/agent_security/firewall.py` (`INJECTION_PATTERNS`), and
optionally mirrored into the Rust accelerator at
`core-rust/src/firewall.rs`. Each new pattern must include:

- A test case in `tests/test_domains.py` showing the attack matches.
- A test case showing a benign string that should not match.
- If the pattern is mirrored into Rust, an entry in the parity corpus in
  `tests/test_firewall_parity.py` (`_SHARED_ATTACKS`); if it is not, add
  it to `_KNOWN_GAP` so the divergence stays measured.
- A description in this card. A new *category* label (rather than a new
  family under an existing one) must also be added to the "Builtin set"
  comment in `admina.yaml.example`, since that list is what operators
  read when setting `disabled_categories`.

---

## 4. PII Scanner

### What it does

Detects and redacts PII in text. Three modes:

- **Regex-only** (default, fast): email, phone, SSN, US credit card
  (Luhn-validated — Python engine only; Rust path does not run Luhn),
  IBAN, IPv4, Italian codice fiscale, Spanish DNI/NIE, and German
  Personalausweis (shipped but **disabled by default** — the format is
  too ambiguous to regex safely). Python engine default; Rust path
  opt-in via `ADMINA_ENGINE=rust`. Categories are individually
  toggleable from `admina.yaml`
  (`admina/domains/data_sovereignty/pii.py:39-106`).
- **Regex + spaCy NER** (`pip install admina-framework[nlp]`): adds named-entity
  detection for `PERSON`, `ORG`, `GPE`, `LOC`. Python only
  (`admina/domains/data_sovereignty/pii.py:58-75`).
- **Microsoft Presidio** (`pip install admina-framework[presidio]`,
  selected with `ADMINA_PII_ENGINE=presidio` or `pii_engine: presidio`
  in `admina.yaml`): a third, opt-in detection engine. Presidio does
  **detection only** — Admina keeps its own masking, so the output
  shape matches the default engine (`admina/engines/presidio.py`,
  `pyproject.toml:144`).

### Known limitations

- **English-trained NER model.** The shipped `en_core_web_sm` is a
  small English model. It under-detects names and organizations in
  Italian, French, German, Spanish, etc. For multilingual deployments,
  switch to the Presidio engine (`admina-framework[presidio]` +
  `ADMINA_PII_ENGINE=presidio`) and download the per-language spaCy
  models it needs. Note that on Admina's own corpus Presidio measures
  *lower* type-level recall than the default spaCy+regex engine on
  EU identifiers — see §9.
- **Regex precision varies by category.** Phone-number regex has high
  recall but low precision (matches version strings, IDs). Credit-card
  regex uses Luhn validation (Python engine) and is reliable. IBAN regex does not
  validate the country-specific checksum and may match invalid IBANs.
- **No image or document parsing.** Admina sees text only. PII embedded
  in images, PDFs, or audio passes through unchanged. Pre-process those
  upstream.
- **No re-identification protection.** Redacting a name does not
  prevent re-identification through quasi-identifiers (zip code + date
  of birth + gender, etc.). Differential privacy is out of scope.

---

## 5. Loop Breaker

### What it does

Detects when an agent is producing near-duplicate outputs in a sliding
window (default size 10), using TF-IDF cosine similarity with a
configurable threshold (default 0.85) and consecutive-match limit
(default 3).

### Known limitations

- **Threshold tuning is workload-dependent.** Question-answering agents
  on similar topics can legitimately produce similar responses; tool-use
  agents performing the same operation may legitimately repeat. The
  defaults are conservative and will need tuning for your domain.
- **No semantic understanding.** Two paraphrases with the same meaning
  but different vocabulary may not be flagged. Conversely, two unrelated
  responses sharing boilerplate may be flagged.

---

## 5b. Egress Policy

### What it does

Extracts destinations from tool-call arguments and evaluates them against
an operator-maintained allowlist, independently of the HTTP method: the
method is an assertion made by the resource being called, not a security
boundary. The allowlist (`domains.agent_security.egress.allow` in
`admina.yaml`) accepts exact hosts, `*.suffix` wildcards, and CIDR ranges.
A call naming a destination that is not on the allowlist is blocked under
`ADMINA_EGRESS_MODE=enforce` and recorded (not blocked) under `observe`; a
call with no network-facing argument is untouched. The call is also
classified as payload-bearing (`write_shaped`) or not. Two things read
that flag: this module's own quarantine check inside `evaluate()`
(`egress.py`; see limitations below), and the coordination detector's
fan-in trigger (`coordination.py`, §5c), which only counts a call toward
fan-in when it is both write-shaped and allowed. Otherwise the flag is
carried through to the forensic record for operators to build on. The
stage is wired into five governed surfaces — `/mcp`,
`/v1/chat/completions`, `/api/v1/validate`, `GovernedModel.ask()` and
`GovernedModel.stream()` — after PII redaction and before pluggable
governance guards, so a denied destination never reaches third-party
guard code.

### Coverage is not uniform across those five surfaces

The stage analyses whatever the surface passes as `params`, and only one
surface passes tool-call arguments:

| Surface | What `params` carries | What egress can see |
|---|---|---|
| `/mcp` | the MCP tool call's `name` and `arguments` | destinations as designed |
| `/v1/chat/completions` | the chat `messages` | only a URL appearing in the prompt text |
| `/api/v1/validate` | the submitted `content` string | only a URL appearing in that string |
| `GovernedModel.ask()` | the prompt | only a URL appearing in the prompt |
| `GovernedModel.stream()` | the prompt | only a URL appearing in the prompt |

On the four prompt-shaped surfaces the stage usually finds nothing,
because a prompt is not a tool call. That is not a defect of those
surfaces — they govern model calls, not tool calls — but it does mean
"runs on five surfaces" must not be read as "five surfaces are equally
protected". The destination control is a `/mcp` control in practice.

### `GovernedAgent.call()` has no egress control

`admina/sdk/governed_agent.py` is the agent-to-agent primitive. It carries
tool-call-shaped `params` — exactly the shape the egress stage was
designed for — and forwards them to an operator-supplied upstream callable
that need not be the Admina proxy. It nonetheless runs **no** egress
check: it reimplements the governance sequence inline instead of calling
`run_pipeline`, so it did not inherit the stage. An agent using
`GovernedAgent` reaches any destination it likes, in `enforce` mode
included. Wiring it is a separate change, not a configuration option.

### Known limitations

- **Admina sees the tool call arguments, not what the tool composes and
  actually dials.** A tool that assembles a URL from parts, or receives an
  IP where the allowlist holds a hostname, is not covered.
- **An agent with direct network access does not traverse Admina and is
  not governed by it.** This is a property of where Admina sits, not a gap
  to be closed at this layer.
- **The allowlist is host- and CIDR-scoped.** There are no path-level
  rules: a path is not a security boundary any more than a method is.
- **A scheme-less host is only a destination under a known argument name,
  and is otherwise invisible.** For a value with no `://`, the argument
  name is what declares a destination, and only these names count: `url`,
  `uri`, `host`, `hostname`, `endpoint`, `address`, `server`, `target`,
  `base_url`, `api_url`, `webhook`. A bare host passed under any other key
  — `callback_url`, `destination`, `forward_to`, or any tool-specific name
  — is not seen at all: the call is classified as not an egress attempt,
  so it passes under `enforce` **and leaves no record under `observe`**.
  There is nothing in the forensic log for an operator to notice, which
  makes this the quietest limitation on this page. A full URL (anything
  containing `://`) and an IP literal are still recognised under any key
  name, since neither is ambiguous.

  This is a deliberate departure from the design spec, which lists
  "scheme-less hosts" among the recognised destination forms without
  qualifying it by argument name. The gate exists because the hostname
  pattern also matches ordinary dotted tokens — `notes.txt`,
  `report.docx`, `users.accounts`, `os.path` — so accepting a bare dotted
  value anywhere would classify every local file, database and
  module-loading tool as an egress attempt and refuse it under
  default-deny. The trade is a false-negative on an unrecognised argument
  name against a false-positive on every non-network tool in the
  deployment. If a tool in your deployment names its destination something
  else, that destination is not governed; the list above is the contract.
- **Arguments nested deeper than the scan limit are refused under
  `enforce`.** The walk over the tool arguments stops at a fixed depth
  (`_MAX_SCAN_DEPTH`, 6, shared with the firewall and PII walks). A region
  the walk never reached could have held a destination, so the call is
  treated as having an undeterminable target and is denied — the same rule
  spec §5.2 applies to any field whose value cannot be resolved, and it
  outranks any destination resolved higher up, so an allowlisted host at
  the top of the arguments does not buy passage for one buried below the
  limit. The depth limit is therefore a denial trigger, not only a
  recursion guard. The refusal is explicit rather than silent: the decision
  reason reads *"unresolvable destination: arguments nested past the scan
  depth limit"* and `evidence.scan_truncated` is `true` in the forensic
  record, so a depth refusal is never mistaken for an allowlist refusal.
  Depth alone is not the trigger — a call that fits inside the limit is
  scanned in full, and a call with no network-facing argument still passes.
- **`observe` mode records without blocking.** A deployment that never
  promotes an allowlist gets observation, not protection.
- **Observation only reaches `suggest-allowlist` from two of the five
  surfaces.** `admina egress suggest-allowlist` reads forensic records, and
  only `/mcp` and `/v1/chat/completions` write one. `/api/v1/validate`,
  `GovernedModel.ask()` and `GovernedModel.stream()` write none, so
  destinations seen there return the verdict to the caller and are then
  gone. On top of that, `FORENSIC_BACKEND` defaults to `memory`, which
  keeps nothing across a restart: an observation window intended to produce
  an allowlist needs `FORENSIC_BACKEND=filesystem` (with
  `FORENSIC_BASE_DIR`) or `=s3` set before it starts.
- **A search API with a query string is classified payload-bearing.**
  Declare it under `read_only_tools` if that matters.
- **Only three narrow conditions make a call payload-bearing.** A truthy
  value under one of the seven payload keys (`body`, `data`, `payload`,
  `json`, `content`, `text`, `params`) counts regardless of its type — a
  boolean or an int under `body` counts just as a string would. A URL
  query string of at least 16 characters counts. And, under any other
  key, a plain string of at least 16 characters that is not itself a URL
  or hostname counts. Nothing else does: a short non-string scalar under
  an ordinary key never counts, `{"active": true}` and `{"status":
  "done"}` included. This does not affect the block decision — an
  unlisted destination is refused whatever the call's shape — but it
  means a call that falls outside those three conditions is invisible to
  both readers of `write_shaped`: it neither triggers the quarantine check
  above nor counts toward the coordination detector's fan-in trigger
  (§5c). A destination reached only by calls shaped this way accumulates
  no fan-in count at all.
- **Config reload is not immediate on any surface.** `GovernedModel`
  resolves the policy lazily on first use and caches it for the life of
  the instance. The proxy and the gateway resolve it once at startup and
  share that cached object across `/mcp`, `/api/v1/validate`, and
  `/v1/chat/completions` alike — `/api/v1/validate` reads the same
  startup-cached policy as the rest of the proxy, not a fresh one per
  request. An `admina.yaml` edit needs a new `GovernedModel` instance or a
  process restart to take effect anywhere.
- **An unreadable or malformed `admina.yaml` yields an empty allowlist**,
  which under `enforce` refuses every destination. This is deliberate —
  fail-closed, consistent with default-deny — and a warning is logged
  naming the parse error. If every destination is suddenly blocked, check
  the logs for this warning before assuming the allowlist itself is wrong.
- **The quarantine hook now has a live caller.** `EgressPolicy.set_quarantine()`
  is invoked every 5 seconds by `refresh_quarantine_once`, fed by the
  coordination detector below (§5c) through `admina/proxy/main.py`'s
  startup loop. The quarantine branch in `evaluate()` fires in any
  deployment that runs the MCP proxy with Redis configured; what feeds it,
  and what does not, is §5c's subject.

---

## 5c. Coordination Detector

### What it does

`admina/proxy/main.py` feeds the egress check and the call's *payload
fields* into `CoordinationDetector.observe()` for every MCP tool call that
reaches the egress stage — one not already short-circuited by an earlier
governance check (loop breaker, firewall) and with egress control enabled
(`"egress" in pipeline_result.checks`). The payload is
`egress.payload_fields()`: the string values the egress stage already
treats as payload-bearing, without the keys, the tool name or the JSON-RPC
envelope around them, and **each value kept separate**, at most two of them
(the longest), each cut to its last 2000 characters. Both halves of that
matter, and for one reason: the echo signal has to be computed over text
that varies with the message, and anything constant across a fleet's calls
manufactures similarity. Argument names, the tool name and the envelope are
constant, so they are excluded; a header block, a bearer token, a content
type and a trace id are constant too, so joining them into one text is
excluded as well — concatenated they form a run of shared words that no
single field contained. A call carrying no payload text is not
fingerprinted at all. Two phases run in order, each gated on the
destination not being in the operator's `coordination_declared` set:

1. **Fan-in trigger (always on).** `FanInCounter` counts distinct agent
   ids making write-shaped, egress-allowed calls to one destination across
   two tumbling `fanin.window_seconds` buckets (default 3600s), so the
   effective window is one to two times that value, as it is for the echo
   sketches below. Once a destination crosses `fanin.min_agents`
   (default 5, floor 2) distinct agents, the verdict escalates to
   `suspected` and is logged. Nothing is blocked yet.
2. **Echo confirmation (keyed).** Only once `ADMINA_EGRESS_FINGERPRINT_KEY`
   is set: each payload field is reduced on its own to a bounded set of
   keyed shingle hashes (`fingerprint.py`) and checked against the fields
   other agents already sent toward the same destination. A match needs
   both conditions and they are measured at different scopes: at least
   `MIN_SHARED_SHINGLES` (12) shared shingles **within one pair of
   fields** — one coherent run of text, never a union of separate fields —
   and a containment coefficient of at least 0.4 **over the whole payload**
   of each of the two calls, so a short constant field that every agent
   sends cannot match at 1.0 on its own. A field whose own sketch cannot
   reach the 12-shingle floor is not stored at all: it could never
   contribute to a match, and leaving it out keeps short constants — a
   bearer token, a content type — out of the echo store entirely. Shingles
   the *reading* agent has already sent toward the same destination in this
   window are discounted from its own side before matching, because text an
   agent repeats across its own calls is its boilerplate and not something
   it read from a peer; what the *stored* agent repeats is never discounted,
   since that would let an agent launder a message by sending it twice. A
   match against another agent's earlier output escalates the verdict to
   `confirmed` and adds the destination to the quarantine set.

A `confirmed` destination is refused for write-shaped calls fleet-wide
**under `ADMINA_EGRESS_MODE=enforce`**; under the default `observe` the
verdict is recorded and logged, the destination appears in `admina egress
quarantine list`, and the call proceeds — exactly as §5b describes for the
allowlist, and for the same reason: upgrading a deployment must not
silently start refusing calls. The quarantine holds until
`quarantine_ttl_seconds` (default 86400s) lapses without renewal, or an
operator runs `admina egress quarantine lift <destination>`. Reads are
never affected — the quarantine only ever gates `write_shaped` calls.

An armed quarantine writes its own record to the forensic chain, naming
the destination, the number of agents counted and the peer whose content
matched, and emits a `policy_violation` event on the governance bus.

Self-confirmation is blocked by three independent mechanisms, not one:
`FanInCounter` counts distinct `agent_id`s, so repeated calls from a single
agent never inflate the fan-in count on their own; `EchoStore.confirm`
separately discards any match against the same `agent_id` that produced
the sketch being matched against; and it discounts from the reading agent's
own side every shingle that agent has already sent toward the destination
in the window, so an agent's own repeated text cannot be evidence even
against a different agent's copy of it.

Replayed on every test run against a 7-trace labelled corpus
(`admina/redteam/corpora/coordination.jsonl`, exercised by
`tests/test_coordination_corpus.py`) covering confirmed coordination,
fan-in-only "suspected" traces, and declared/benign negative controls. This
is a small, hand-built corpus exercising the two-phase design's core
distinctions — it is not a comprehensive adversarial evaluation, and it
does not participate in the Python/Rust recall baseline in §9.

### Known limitations

- **It finds undeclared coordination, not malicious coordination.** A
  legitimate shared work queue and an emergent coordination channel
  produce the identical fan-in-plus-echo signature — many agents, one
  destination, overlapping content. `coordination_declared` is the only
  thing that tells them apart; anything meeting the same shape that is not
  listed there is flagged exactly as a genuine covert channel would be.
- **Without `ADMINA_EGRESS_FINGERPRINT_KEY` the detector never escalates
  past `suspected`.** With no key configured, echo confirmation does not
  run at all — it is disabled outright rather than falling back to
  unkeyed hashes, which would be dictionary-attackable and comparable
  across deployments. A key-less deployment gets a logged warning signal
  and nothing more; no destination is ever quarantined.
- **Without Redis there is no detection at all, and the verdict is
  `degraded`, not `none`** — the two must not be read as the same thing.
  `FanInCounter.record` returns 0 on any Redis failure, and `observe()`
  reports `degraded` for that case rather than silently reporting nothing
  found. The egress allowlist itself is unaffected by any of this: it is
  operator configuration evaluated in-process, with no Redis dependency.
- **Only the MCP proxy path feeds the detector.** `admina/proxy/main.py`
  is the only caller of `CoordinationDetector.observe()`. The
  OpenAI-compatible gateway (`/v1/chat/completions`), `POST
  /api/v1/validate`, and the SDK primitives (`GovernedModel`,
  `GovernedAgent`) never call it, so multi-agent coordination conducted
  through any of those surfaces is invisible to this control — the same
  asymmetry §5b documents for the egress stage itself, one layer up.
- **A quarantine is fleet-wide for writes, and only under `enforce`.**
  `QuarantineStore` keeps one shared destination-to-expiry hash; under
  `ADMINA_EGRESS_MODE=enforce` a single `confirmed` verdict costs *every*
  agent write access to that destination, not just the agents that
  triggered it, until the TTL lapses or an operator lifts it. Under the
  shipped default (`ADMINA_EGRESS_MODE` unset, which resolves to
  `observe`) the quarantine is recorded and visible to `admina egress
  quarantine list` and blocks nothing.
- **A shared footer can be most of a short message.** Confirmation needs
  12 shared shingles and a containment coefficient of 0.4, so two messages
  match when what they share is more than about 40% of the shorter one.
  Boilerplate long enough to clear the shingle floor does that on its own
  when the messages are short: two 30-word bodies with nothing in common
  but the same 25-word automated footer measure 21 shared shingles at 0.41
  and confirm. The same footer on 60-word bodies scores 0.26 and does not.
  A destination whose agents all append one signature is the shape to
  watch, and `coordination_declared` is the answer for it.
- **A whole argument that a fleet sends unchanged is the same limitation
  one level up.** Keeping payload fields separate stops short constants —
  a header block, a content type, a trace id — from pooling into a run long
  enough to clear the shingle floor, because no one of them reaches it. It
  does not help when a *single* constant field clears the floor by itself:
  a 250-word instruction template sent as its own argument beside a 30-word
  message measures 48 shared shingles at 0.623 containment and confirms.
  Telling that apart from an echo needs more than one call to look at, and
  the detector does exactly that much: from an agent's second call to the
  destination in the window onward, the constant is in that agent's own
  history and is discounted, and the same fleet measures `suspected`. The
  exposure is each agent's first call in a 2–4 hour window, and it narrows
  as messages get longer — the same 16-token constant beside 30-word
  messages scores 0.356 and does not confirm. `coordination_declared` is
  the answer for a destination whose tool carries one.
- **Detection is retrospective by construction.** The fan-in trigger needs
  `fanin_min_agents` distinct agents against one destination before it can
  conclude anything at all, so the calls that establish that count are
  themselves never flagged — a new channel always gets a bounded number of
  free calls, never zero, before a `suspected` verdict becomes possible.
- **Content sketches are bounded and keyed, never plaintext.** A sketch is
  a set of up to 512 keyed 64-bit HMAC values over 5-word shingles of one
  payload field a call carried toward a destination, taken from that
  field's last 2000 characters, with at most two fields per call;
  nothing in `fingerprint.py` stores or can reconstruct the source text.
  Outbound sketches live in a Redis set per destination, agent and bucket,
  the bucket sized at twice `fanin.window_seconds` (not an independently
  configurable value), and are matchable for roughly one to two times that
  size — with the shipped default (`window_seconds: 3600`) that is 2 to 4
  hours — after which they age out regardless of activity.
- **An agent's sketch storage is capped, and the cap is per agent.** Each
  agent holds up to 1024 values per destination per bucket; a call that
  does not fit that budget displaces the same agent's older sketches, so
  what an agent stores is always its most recent messages and no agent's
  traffic can displace another's. A call whose fields together exceed the
  whole budget is not stored at all, logged at WARNING, and takes no slot
  in the agent index.
- **The agent index is an attacker-reachable limit, not a capacity one.**
  `agent_id` is `X-Agent-Id`, a caller-supplied header the proxy does not
  authenticate, and at most 256 ids are indexed per destination per bucket.
  A flood of forged ids therefore fills a destination's index on purpose,
  and no cap on an unauthenticated identifier space can prevent that. What
  the cap does *not* do is lock a named agent out: an arriving agent
  evicts an indexed one rather than being refused, every write re-indexes
  its own writer, and the ids that stop writing are the ones that leave, so
  echo confirmation keeps working for agents that keep sending. What is
  lost while an index is full is certainty — some agent's sketches are no
  longer readable — so the detector reports that destination as `degraded`
  rather than `suspected` for calls that find no echo, and logs each
  eviction at WARNING. A real echo still confirms while the index is full.
- **Under `observe` the tracked keyspace is bounded only by the agents.**
  Fan-in and echo keys are named by destination, which comes from
  agent-supplied arguments. Under `enforce` an unlisted destination is
  refused upstream and nothing is recorded, so the allowlist bounds the
  keyspace; under `observe` every destination is "allowed", so an agent
  naming N hosts creates keys for N hosts, each held for 2-4 hours. Host
  length is bounded to 253 characters by the analyser's host pattern, so
  this is memory amplification rather than key injection. The per-destination
  ceiling is 256 agents x 1024 values x 2 buckets — roughly 28 MB of echo
  sketches for one destination, not the ~57 KB a single shared 1024-member
  bucket held before the storage budget became per agent.
- **The echo phase's coverage is exactly the egress stage's coverage.**
  Both halves read the payload with the same walk and the same notion of a
  payload-bearing value, including inside a subtree whose name declares a
  destination (`{"webhook": {"url": ..., "text": ...}}`), so a call the
  fan-in trigger counts is a call the echo phase can fingerprint. What
  neither reaches is not fingerprinted either: arguments nested past the
  six-level scan depth, and — from `fingerprint.py`'s ASCII-only word
  regex — text in non-Latin scripts.
- **A call the firewall or the loop breaker stops never reaches the
  detector.** `checks["egress"]` is only produced while the pipeline's
  action is still ALLOW, so a call blocked earlier is not counted. Under
  `observe`/`dry-run` that decision is downgraded back to ALLOW at stage 5
  and the call *is* forwarded upstream while staying invisible here —
  appending a known injection trigger to a payload removes a call from the
  fan-in count without preventing its delivery. The loop breaker collides
  with this feature's own subject: repetitive writes to one shared
  destination are what coordination looks like and what trips the
  breaker.

---

## 6. Forensic Hash Chain

### What it does

Maintains a SHA-256 chained log of governance events. Each entry's hash
incorporates the hash of the previous entry, so any tampering with a
historical record invalidates all subsequent hashes.

### Security properties

- **Tamper-evident**, not tamper-proof. An adversary with write access
  to the log can rebuild the chain from any point onward; what they
  cannot do is silently modify a single past entry.
- **Integrity scope is the chain itself.** The hash chain proves that
  the events recorded are internally consistent. It does not prove that
  the events recorded reflect what actually happened in the upstream
  LLM or tool — that requires the upstream system to participate in
  signing or attestation.
- **No external time anchoring by default.** Timestamps are local to
  the proxy. For non-repudiation against a third party, anchor the
  chain head to an external time-stamping authority (RFC 3161, OpenTSA,
  or a public blockchain) — outside the scope of v0.11.x.

---

## 7. EU AI Act Classifier

### What it does

Maps a free-text system description and a list of data types to one of
the four EU AI Act risk categories: `unacceptable`, `high`, `limited`,
`minimal` (Reg. 2024/1689 Art. 5–6 + Annex III).

### Method

Keyword-based scoring against three lists hard-coded in
`admina/domains/compliance/eu_ai_act.py`. No machine learning, no semantic
similarity. The lists were derived from the consolidated text of
Regulation 2024/1689 as of January 2026.

### Known limitations and disclaimers

- **This is a triage tool, not a legal determination.** Legal
  classification of an AI system requires reading the full system
  description against Annex III in the version in force at the time of
  placing on the market, and is fact-specific. A qualified lawyer or
  notified body is the only authoritative source.
- **Annex III is dynamic.** The Commission may amend Annex III by
  delegated act. The keyword lists in this release reflect the original
  Annex III only; updates ship in subsequent Admina releases.
- **The regulation has multiple application dates.** After the
  **Omnibus VII** agreement (Council and Parliament, 7 May 2026):
  Art. 5 prohibitions apply from 2 February 2025; GPAI obligations
  (Art. 50–55) from 2 August 2025; Art. 50 transparency for synthetic
  content and a new Art. 5 prohibition on non-consensual intimate
  imagery / synthetic CSAM both apply from **2 December 2026**; the
  bulk of high-risk obligations (Annex III — employment, education,
  biometrics, scoring) from **2 December 2027** (postponed from
  2 Aug 2026); Annex I high-risk (medical devices, toys, regulated
  products) from **2 August 2028** (postponed from 2 Aug 2027); and
  national AI regulatory sandboxes deadline from 2 August 2027.
  Admina exposes the full timeline via `EU_AI_ACT_DEADLINES` (dict)
  and `EU_AI_ACT_ENFORCEMENT_DEADLINE` (primary = Annex III high-risk).
  These constants **must not be read as the only deadline**.
- **No coverage of national implementing legislation.** Member states
  may enact additional obligations (e.g. on biometric identification by
  law enforcement). Admina does not model these.
- **No coverage of national implementing legislation** beyond EU. Member
  states may enact additional obligations (e.g. on biometric
  identification by law enforcement). Admina does not model these.
- **ISO/IEC 42001 and SOC 2** are not implemented in OSS.

---

## 7b. NIS2 Self-Assessment

### What it does

Enumerates the ten cybersecurity risk-management measure areas required
by Directive (EU) 2022/2555 (NIS2) Art. 21(2)(a)-(j) and lets the
operator declare which of a small number of standard controls is in
place per area. Returns a coverage score (0-100), a per-area
breakdown, and a typed list of missing controls.

40 controls total (10 areas × 4 controls), keyed to the Art. 21(2)
sub-paragraph that motivates each area.

### Known limitations

- **Triage tool, not a compliance attestation.** A high coverage score
  is necessary but not sufficient for NIS2 compliance: it tells you
  the technical/organisational measures are documented as in-place,
  not that they are *effective*. Internal audit and (where required)
  external audit / certification remain the operator's responsibility.
- **No incident reporting workflow.** NIS2 Art. 23 requires a 24-hour
  early warning, 72-hour notification, and 1-month report. The OSS
  module records the *posture* (incident response plan documented?
  yes/no), not the workflow itself. Real CSIRT routing is out of
  scope for this release.
- **No sector-specific controls.** NIS2 Annex I (essential entities)
  and Annex II (important entities) cover energy, transport, banking,
  healthcare, etc. Sector-specific control templates are not in OSS.
- **No mapping to national transposition acts.** Member states had to
  transpose by 2024-10-17. Admina's checklist tracks the Directive
  text; specific national obligations are not modelled.

---

## 7c. GDPR RoPA Registry & DPIA Template

### What it does

Two GDPR primitives:

- **Records of Processing Activities (Art. 30)**: typed CRUD over a
  flat list of `ProcessingActivity` records. JSON-on-disk persistence
  is opt-in (set `ADMINA_GDPR_ROPA_PATH` or pass `storage_path=`); the
  default is in-memory only so a fresh `pip install` never writes to
  disk unbidden.
- **DPIA template (Art. 35)**: renders a Markdown scaffold from
  operator-supplied facts (purpose, legal basis, data categories,
  identified risks, etc.). Sections that the operator did not provide
  are left as `_TBD_` placeholders. Includes the `DPIA_REQUIRED_CRITERIA`
  constant (the 9 WP29 triggers) so frontends can render a checkbox
  list.

### Known limitations

- **Single-controller, no multi-tenancy.** The registry is a flat list
  with no per-record ACL. Multi-tenant / multi-controller / role-based
  workflows are out of scope for this release.
- **The DPIA template is a scaffold, not a guided wizard.** It does NOT
  score risks, recommend mitigations, or determine whether
  consultation of the supervisory authority under Art. 36 is required.
  A real DPIA always involves the DPO (Art. 39) and may involve the
  supervisory authority — Admina cannot replace either.
- **No Data Subject Request workflow** (Art. 12-22), no consent
  records (Art. 6/7), no automated Transfer Impact Assessment under
  Schrems II. These are explicit gaps; address them with dedicated
  GRC tooling.
- **No automated retention enforcement.** Each `ProcessingActivity`
  records a retention period in free text; deleting source data when
  the period expires is the operator's job.

---

## 7d. Cross-Regulation Matrix

### What it does

Hand-curated mapping of 12 operational controls (risk assessment,
incident handling, encryption, access control + MFA, logging,
data minimisation, third-party risk, human oversight, transparency,
training, business continuity, documentation) to specific articles in
EU AI Act, NIS2, and GDPR. Each mapping carries the article reference
and a one-liner explaining the link.

### Known limitations

- **Base coverage only.** 12 controls is enough to drive a "implement
  once, report three times" play but is not exhaustive. ISO 27001,
  NIST AI RMF, ISO/IEC 42001, sector-specific frameworks and per-norm
  detailed mappings are out of scope for this release. Contributions
  are welcome (see CONTRIBUTING.md).
- **Constant data, no editor.** The matrix is a Python dict; operators
  who need a different shape can fork and override. There is no
  audit trail of who changed which mapping when.
- **Not a substitute for legal review.** A mapping says "this control
  is *relevant to* Art. X of regulation Y", not "implementing this
  control means you comply with Art. X". Compliance always depends
  on the operator's specific situation.

---

## 8. Data, training, and bias

Admina's components are **not trained on data**: they are deterministic
rules and statistics over the runtime input. There is therefore no
training dataset, no demographic distribution to disclose, and no
training-data bias in the classical sense.

However, **rule curation is itself a source of bias**:

- Pattern lists were authored by the maintainer's team and reflect the
  attack classes seen in English-language and EU-centric threat
  intelligence. Coverage of non-Latin-script languages is limited.
- The EU AI Act keyword list is biased toward European-style legal
  vocabulary. A system documented in non-EU regulatory language may be
  classified incorrectly.
- The PII regex set covers EU and US identifier formats. National
  identifiers from other jurisdictions (Aadhaar, CPF, RUT, etc.) are
  not covered out of the box.

We welcome contributions extending coverage. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## 9. Evaluation

### Performance benchmarks

Performance numbers in the README (`6.25 µs` median for the four-domain
pipeline) are reproduced via `scripts/benchmark.py` and
`docker-compose.benchmark.yml`. Hardware and methodology are documented
inside the benchmark script. These are **performance** metrics, not
**accuracy** metrics.

### Accuracy benchmarks

Admina ships `admina-redteam`, a reproducible detection-efficacy suite
(`admina/redteam/`, CLI `scripts/redteam.py`). It runs the injection firewall,
PII redactor and loop-breaker against original, hash-pinned, multilingual
(EN/IT/FR/ES/DE) corpora on **both** the Python and Rust engines and emits
precision/recall/FPR plus a per-class Python-vs-Rust matrix. A soft CI gate
(`tests/test_redteam_efficacy.py`) fails the build on any recall regression or
new false positive versus the committed baseline
(`admina/redteam/baselines/baseline.json`).

**Gate methodology.** Python detectors are **mandatory**: a detector the
baseline declares but that did not run (e.g. an optional extra went missing)
fails the gate rather than passing vacuously. The Rust engine is an **optional
accelerator** — its absence is skipped. The PII row reports **type-level
recall** — a micro-average over PII *types* (see `admina/redteam/metrics.py`),
**not** the sample-level recall used for injection/loop — and the baseline
**pins the PII measurement mode** (`nlp:<model>@<version>` vs regex-only),
because the Python redactor's recall and false positives depend on whether spaCy
NER is active. The gate compares only within the same pinned mode; if a mandatory
(Python) detector's pinned mode is not reproduced, the gate **fails** with an
actionable message (match the environment or regenerate the baseline) rather than
silently skipping — so a real regression measured in the wrong mode can never
pass. A python detector that ran but is absent from the baseline fails too.

**First measured baseline** (Admina's own corpus — **not** a third-party PINT
score; the corpus is small and EN/EU-focused, intended to grow). Injection/loop
are sample-level recall; PII is type-level recall measured in `nlp:en_core_web_sm`
mode (the mode pinned in the baseline):

| Detector  | Python recall | Rust recall | False positives (py · rust) |
|-----------|:---:|:---:|:---:|
| injection | 57% (sample-level) | 35% | 0/27 · 0/27 |
| pii       | 100% (type-level, nlp) | 66% (type-level) | 6/16 · 0/16 |
| loop      | 82% (sample-level) | 91% | 0/11 · 0/11 |

The optional Presidio PII engine is measured as a third row in the same
baseline (`admina/redteam/baselines/baseline.json`): **52%** type-level
recall with **9/16** false positives, pinned to mode
`presidio:2.2.363/en+it`. It is an alternative engine, not an
accelerator, so it is reported separately rather than in the
Python-vs-Rust matrix above.

Notable measured gaps (run `python scripts/redteam.py --format md` for the full
per-class matrix): the Rust firewall scores **0%** on base64 / homoglyph /
leetspeak / ROT13 / hyphenation evasions that the Python engine catches (no
`normalize_text()` pass — the fast path is the least thorough); the Rust PII
scanner scores **0%** on IBAN / codice-fiscale / DNI (regex-only, fewer patterns);
the Python loop-breaker misses counter-reset loops (last-5 window) that the Rust
full-window engine catches. The Python PII false positives are spaCy NER
mis-firing `PERSON`/`ORG` on non-English negative samples — which is also why
the PII baseline pins the NER mode. These measured gaps are consistent with §1:
the two engines are **not** behaviorally equivalent — Python is the
higher-recall default, Rust the narrower-coverage opt-in.

This replaces the previous "no accuracy benchmark suite" gap. Contributions
extending the corpora (more languages, larger adversarial sets, `garak` /
`PromptInject` adapters) remain welcome and prioritized.

---

## 10. Reporting issues

- **False positives / false negatives** in the firewall or PII scanner:
  open a GitHub issue with a minimal reproducer. Sensitive payloads
  (real PII, real prompts containing customer data) **must not** be
  attached — paraphrase or anonymize.
- **Bypass / vulnerability**: do *not* open a public issue. Follow
  [`SECURITY.md`](SECURITY.md).
- **EU AI Act misclassification**: open a GitHub issue with the system
  description and the expected classification, citing the article or
  Annex III point. Misclassifications that change `unacceptable`/`high`
  status are treated as security issues.

---

## 11. Versioning of this card

This card is versioned alongside the codebase. Material changes are
recorded in `CHANGELOG.md` under the relevant release. The current
version corresponds to **Admina 0.11.0**.

---

*Disclaimer.* Nothing in this document constitutes legal advice. Admina
is provided "AS IS" under the Apache License 2.0; see [`LICENSE`](LICENSE)
and [`NOTICE`](NOTICE).
