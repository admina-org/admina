# Admina — Component Card

This document is the transparency artifact for the **rule-based and
heuristic components** that ship inside Admina. Admina does not train or
distribute machine-learning models in v0.9.x: the governance pipeline is
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
| PII Scanner | Regex + spaCy NER (optional) | Rust (`core-rust/src/pii.rs`) + Python fallback | `admina/domains/data_sovereignty/` |
| Loop Breaker | TF-IDF cosine similarity over a sliding window | Rust (`core-rust/src/loop_breaker.rs`) + Python fallback | `admina/domains/agent_security/loop_breaker.py` |
| Forensic Hash Chain | SHA-256 chained log | Rust (`core-rust/src/forensic.rs`) + Python fallback | `admina/domains/compliance/forensic.py` |
| EU AI Act Classifier | Keyword-based risk classifier + Annex III mapping | Python (`admina/domains/compliance/eu_ai_act.py`) | — |
| NIS2 Self-Assessment | Deterministic checklist (10 areas × 4 controls = 40 checks) + gap analysis | Python (`admina/domains/compliance/nis2.py`) | — |
| GDPR RoPA Registry | Typed CRUD over Art. 30 records with optional JSON-on-disk persistence | Python (`admina/domains/compliance/gdpr.py`) | — |
| GDPR DPIA Template | Markdown scaffold for Art. 35 DPIA from operator-supplied facts | Python (`admina/domains/compliance/gdpr.py`) | — |
| Cross-Regulation Matrix | Hand-curated mapping of 12 operational controls across AI Act / NIS2 / GDPR | Python (`admina/domains/compliance/cross_regulation.py`) | — |

All Rust components are pure functions exposed via PyO3. The Python
fallbacks are behaviorally equivalent for correctness; Rust is faster
but not more accurate. **Switching engine does not change governance
outcomes.**

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

Scans inbound text for 15 categories of prompt-injection attempts using
a single-pass `RegexSet`. Returns matched categories and a heuristic
score (`0.0`–`1.0`).

### Categories covered (v0.9.0)

`instruction_override`, `role_hijacking`, `developer_mode`, `dan_mode`,
`prompt_extraction`, `delimiter_injection`, `data_exfiltration`,
`system_prompt_leak`, `jailbreak`, `obfuscation`, `new_instructions`,
`ignore_safety`, `multilang_evasion`, `roleplay_escape`, `tool_abuse`.

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

New patterns are contributed via PR to
`core-rust/src/firewall.rs` (and the Python fallback at
`admina/domains/agent_security/firewall.py`). Each new pattern must include:

- A test case in `tests/test_proxy_security.py` showing the attack matches.
- A test case showing a benign string that should not match.
- A description in this card.

---

## 4. PII Scanner

### What it does

Detects and redacts PII in text. Two modes:

- **Regex-only** (default, fast): email, phone, SSN, US credit card
  (Luhn-validated), IBAN, IPv4. Rust path.
- **Regex + spaCy NER** (`pip install admina-framework[nlp]`): adds named-entity
  detection for `PERSON`, `ORG`, `GPE`. Python only.

### Known limitations

- **English-trained NER model.** The shipped `en_core_web_sm` is a
  small English model. It under-detects names and organizations in
  Italian, French, German, Spanish, etc. For multilingual deployments,
  install Microsoft Presidio via the
  [`guardrailsai`](README.md#guardrailsai) extra.
- **Regex precision varies by category.** Phone-number regex has high
  recall but low precision (matches version strings, IDs). Credit-card
  regex uses Luhn validation and is reliable. IBAN regex does not
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
  or a public blockchain) — outside the scope of v0.9.x.

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

Admina v0.9.0 does **not** ship an accuracy benchmark suite for the
firewall or PII scanner against a public adversarial dataset. This is a
known gap. Contributions adding evaluation against public datasets
(e.g. `garak`, `PromptInject`, AI red-team corpora) are welcome and
prioritized.

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
version corresponds to **Admina 0.9.0**.

---

*Disclaimer.* Nothing in this document constitutes legal advice. Admina
is provided "AS IS" under the Apache License 2.0; see [`LICENSE`](LICENSE)
and [`NOTICE`](NOTICE).
