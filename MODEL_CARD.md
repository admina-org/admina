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
