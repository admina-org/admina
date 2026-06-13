# Admina 0.9.5 — Architecture & Functionality Review (Synthesis)

Repo: `/Users/stefano/Progetti/ADMINA/admina` · branch `release/0.10.0` · 6 architecture reviews + 18 verified claims

---

## 1. Overall Verdict

**The skeleton is sound; the circulatory system is fragmented.** Admina's foundational decisions are genuinely good and verified in code, not just docstrings: a dependency-free core kernel with an acyclic import graph (`admina/core/types.py`, `event_bus.py:31`), a pure side-effect-free governance pipeline (`proxy/governance.py:51-72`), a model-quality plugin contract file (`plugins/base.py`), a single composition root with injected state (`proxy/main.py:107-348`), and a consistently executed graceful-degradation philosophy. The detection engines themselves — firewall, PII, loop breaker, forensic hash chain — exist exactly once in `admina/domains` and are shared by every surface. Five of six area reviews land at "sound-with-issues"; nothing is rotten at the base.

**The defining architectural failure is orchestration divergence, not missing capability.** The same three engines are wired five different ways (GovernedModel, GovernedAgent, proxy `/mcp`, `/api/v1/validate`, LangChain/CrewAI callbacks), each with a different subset of governance stages, a different pipeline order, and a different relationship to configuration, the Rust accelerator, and the forensic trail. The result is that "same app, different entry point" silently yields different protection — and the flagship compliance promise (tamper-evident audit) is real only behind the proxy: SDK governance events evaporate into a subscriber-less bus (`event_bus.py:112`; only `proxy/main.py:174-191` subscribes). One review correctly rates this area "problematic"; it is the centerpiece finding (Section 3). The second systemic pattern is **parsed-but-never-executed surface**: 6 of 9 plugin interfaces are never resolved at runtime (`proxy/main.py:140-142`), most of `AdminaConfig`/admina.yaml is dead (including a concrete bug — `engine_bridge.py:55-63` reads `cfg.raw`, an attribute that never exists, so YAML firewall overrides can never load), and `admina init` scaffolds config keys nothing reads.

**The documentation is honest in places where most projects lie, and inaccurate in places that matter.** The README discloses the Rust firewall's 7/14 evasion gap (README.md:427-432) and the parity tests pin it; NIS2 self-describes as triage; the memory-backend warning is loud. But of 18 verified claims, 13 are "partial": the README's "pipeline identical in both modes" is false on four of six steps for GovernedModel; MODEL_CARD's "behaviorally equivalent engines" claim is contradicted by the repo's own parity suite; "Luhn-validated credit card" is false in both engines (`pii.py:81`, `pii.rs:37` — no checksum exists); LangChain/CrewAI "PII redaction" is detection-only; and three docs show three mutually inconsistent pipeline orders, none matching the code. No claim is vapor — every capability has real code — but the gap between advertised and wired governance is exactly the kind of gap a *governance* framework cannot afford.

---

## 2. Architecture Scorecard

| Area | Verdict | The one defining issue |
|---|---|---|
| Layering, boundaries, dependencies | sound-with-issues | Clean acyclic core←domains←surfaces graph, but engine selection (Rust + YAML overrides) lives in the *top* layer (`proxy/engine_bridge.py`), so SDK/integrations cannot reuse it without an upward import |
| Plugin architecture (9 ABCs + registry) | sound-with-issues | Excellent infrastructure the framework itself bypasses: 3/9 types registry-wired (`proxy/main.py:140-142`); the third-party loop is broken at every seam (dead `plugins:` yaml, scaffold emits sync methods for async ABCs, no entry-point section, wrong dependency name) |
| Governance pipeline coherence across surfaces | **problematic** | Five parallel orchestrations of the same engines; protection, ordering, audit, and engine choice all differ by entry point (Section 3) |
| Data & compliance (forensic, bus, config) | sound-with-issues | Forensic chain is well-designed but never verified in any wired path, not concurrency-safe (`forensic.py:205-236`, no lock), and the bus is not the audit spine — persistence is direct calls inside the MCP handler |
| Runtime & deployment | sound-with-issues | Pervasive per-process mutable state (loop windows, metrics, bus singleton, WS clients, compliance lists, forensic chain_head) collides head-on with the 0.12 multi-tenancy / 1.1 stateless roadmap |
| Public API surface & DX | sound-with-issues | Duplicated `BaseModelAdapter`/`BaseDataConnector` ABCs (`sdk/governed_model.py:35` vs `plugins/base.py:45`) make the documented quickstart a type error despite shipped `py.typed` |

---

## 3. The Governance-Coherence Matrix (centerpiece)

What each entry point **actually executes** (wired reality, with file:line provenance in the underlying reviews). ✓ = enforced, det = detection-only, — = absent.

| Governance stage | GovernedModel `.ask()` | GovernedAgent `.call()` | Proxy `POST /mcp` | Proxy `/api/v1/validate` (n8n, CheshireCat, OpenClaw) | LangChain / CrewAI callbacks |
|---|---|---|---|---|---|
| Injection firewall (request) | — | ✓ (runs **first**) | ✓ (runs after loop) | ✓ | det + raise (LangChain propagation unverified — no `BaseCallbackHandler`, no `raise_error`; CrewAI fires post-hoc) |
| Loop breaker | — | nominal — inert by default (fresh `uuid4` session per call, `governed_agent.py:224`) | ✓ (runs **first**) | ✓ | ✓ (CrewAI doc'd singletons share one session across all agents) |
| PII redaction — request | ✓ (prompt) | ✓ deep | ✓ deep (depth 5) | ✓ (`redacted_content` returned; caller must apply) | **det only** — prompt never mutated, unredacted text reaches the model |
| PII redaction — response | ✓ | ✓ deep dict | string-only `result` — **dead for spec-compliant MCP** (dict results pass through, `main.py:1373-1376`) | n/a | **det only** |
| Plugin governance guards (req + resp) | — | — | ✓ both sides | — | — |
| Observe / dry-run mode | — | — | ✓ | — (ignores `GOVERNANCE_MODE`) | — |
| Rate limiting / size guard | — | — | ✓ / ✓ | — | — |
| Forensic hash-chain record | — | — | ✓ (request leg only) | — (caller must voluntarily POST `/api/v1/audit`) | — |
| ClickHouse persistence | — | — | ✓ | — | — |
| Event bus emission | MODEL_* (no subscribers in SDK-only) | AGENT_* (idem) | GOVERNANCE_DECISION | **none** | framework-named domain events |
| OTEL spans + alert channels | — (subscribers listen only to GOVERNANCE_DECISION, `main.py:174,191`) | — | ✓ | — | — |
| Rust accelerator (when `[rust]` installed) | never | never | ✓ auto (and weaker at evasions: 7/14 vs 14/14) | ✓ (same bridge engines) | never |
| admina.yaml firewall overrides | — | — | Python engine only — and dead anyway (`cfg.raw` bug) | idem | — |
| Pipeline order | PII only | firewall→loop→PII | loop→firewall→PII→guards | loop→firewall→PII | firewall→loop→PII |
| Action vocabulary | ALLOW/REDACT | +BLOCK/CIRCUIT_BREAK | full set | **MODIFY** instead of REDACT; mixed risk_level casing | REDACT reported but not applied |

**Reading**: only `/mcp` delivers the documented pipeline, and even there response-side PII and bidirectional firewall/loop are not real. The surfaces third-party tools actually call (`/api/v1/validate`) and the surfaces developers start with (SDK) get strict subsets — silently. The fix is already designed: `run_pipeline` is pure and injectable; it just is not shared.

---

## 4. Claims Ledger

18 documented capabilities verified. **Works: 5 · Partial: 13 · Missing: 0.**

| # | Capability | Status | Note |
|---|---|---|---|
| 1 | GovernedModel + adapters + bidirectional PII | **works** | Exact as documented; caveat: "audit" = emit to subscriber-less bus in SDK-only mode (→ Debt D5) |
| 2 | GovernedData residency + classification + audit | partial | Residency is declarative label matching — default config can never block; audit sink absent SDK-only (D5) |
| 3 | GovernedAgent "full proxy pipeline in-process" | partial | Firewall/PII real; loop breaker inert by default session handling; no guards/mode/forensic/Rust — same root cause as D1/D2 |
| 4 | ComplianceKit EU AI Act classify + gap analysis + deadlines | **works** | Key-for-key match with Omnibus VII timeline; honest about keyword-based method |
| 5 | All 4 primitives async + sync | partial | 3 of 4; ComplianceKit is sync-only |
| 6 | MCP proxy fixed pipeline, bidirectional | partial | Pipeline real with 403/429 enforcement; but 3 docs show 3 wrong orderings, response PII dead for dict results, firewall/loop never see responses — "bidirectional" is false for the proxy |
| 7 | Firewall 15 categories + normalization + 14/14 vs 7/14 | partial | Numbers test-pinned and honest; but "15 categories/RegexSet" describes the opt-in Rust engine, default Python has 9 differently-named categories (`role_hijacking` vs `role_hijack` breaks `disabled_categories`) |
| 8 | Loop breaker TF-IDF, admina.yaml-configurable | partial | Mechanism + CIRCUIT_BREAK→429 real; "configurable per admina.yaml" not wired (env-only) — instance of D4; Rust variant is not TF-IDF |
| 9 | PII regex-only default + Luhn + EU IDs + spaCy extra | partial | Solid degradation design; **"Luhn-validated" is false in both engines**; Rust path silently drops EU IDs and NER |
| 10 | Forensic SHA-256 chain, 3 backends, minio→s3 shim | **works** | Full contract honored incl. Object Lock; caveats: no concurrency safety, verification never invoked in any wired path (D6) |
| 11 | REST `/api/v1/validate` + `/audit` | partial | Both real and tested; documented curl fails 401 (auth undocumented), MODIFY/casing inconsistencies, no guards/mode/forensic (D2) |
| 12 | Dashboard score + WS live feed + allSettled | partial | All 6 endpoints real; Docker SPA copy never got the allSettled fix; WS auth broken at HEAD in `admina dev` (cookie signing regression, dd90a13) |
| 13 | CLI init/dev/plugin/doctor | **works** | The strongest DX surface; adaptive next-steps and actionable doctor are wired reality |
| 14 | Plugin system: 9 interfaces, builtins for each, install/create | partial | ABCs/registry/CLI solid; "ships builtins for each" overstates — MCP transport isn't even a plugin class; 3/9 consumed (D3) |
| 15 | Rust engine: opt-in, auto-detect, 6.25 µs, "equivalent" | partial | Mechanism + honest README numbers; Rust hash chain is dead code outside benchmarks, SDK never accelerated (D1), **MODEL_CARD equivalence claim contradicted by repo's own parity tests** |
| 16 | LangChain/CrewAI in-process governance | partial | Public surface exists; PII "redaction" never sanitizes the flow; real-LangChain dispatch unverified anywhere in repo (D2) |
| 17 | Sidecars: OpenClaw fail-closed, CheshireCat fail-open, n8n nodes | partial | All artifacts exist; documented bootstrap broken end-to-end (entrypoint requires API key the setup never provides; 401 → silent permanent fail-open); OpenClaw SKILL.md teaches the wrong wire schema |
| 18 | NIS2 40-check + GDPR RoPA/DPIA + cross-reg matrix | **works** | Fully shipped, tested, REST-exposed — and conservatively *under*-documented (README never mentions NIS2) |

**Pattern**: nothing is fabricated; "partial" almost always means *the capability exists on one surface and the docs imply all surfaces* — i.e., the claims gap and the architecture gap are the same gap.

---

## 5. Structural Debts, Ranked by Roadmap Impact

**D1 — Engine acquisition split-brain** (root cause of claims 3, 7, 15 partials)
*What:* `proxy/engine_bridge.py` (Rust auto-detect + YAML overrides) is proxy-private; SDK (`governed_agent.py:55-73`) and integrations (`integrations/_engines.py:30-63`) construct pure-Python engines directly.
*Why it bites:* The 0.10 Presidio work targets `BasePIIEngine` — the spec itself notes implementing the ABC alone won't make Presidio run, because the live pipeline uses `PIIRedactor` via the bridge. Every 0.10 adapter multiplies the scatter.
*Pay:* **Before 0.10 lands.** Move the bridge below sdk/proxy/integrations (e.g. `admina/engines`), add explicit `ADMINA_ENGINE=auto|python|rust`, feed YAML overrides to both bridges.

**D2 — Five pipeline orchestrations, one canonical pipeline unused** (root cause of claims 6, 11, 16 partials)
*What:* `run_pipeline` is pure and injectable but only `/mcp` calls it; GovernedAgent, `/api/v1/validate`, and callbacks each hand-roll subsets with different ordering and vocabulary.
*Why it bites:* 0.11 SDK streaming needs a pipeline that exists exactly once to thread chunks through; retrofitting five orchestrations is a rewrite.
*Pay:* **0.10–0.11.** Promote `run_pipeline` to domains/core; delegate all surfaces; kill `MODIFY`, fix loop-vs-firewall ordering once.

**D3 — Plugin system: 3/9 wired, third-party loop broken** (root cause of claim 14 partial)
*What:* Registry never resolves forensic/PII/compliance/transport/adapter/connector types; scaffold emits sync methods for async ABCs (a scaffolded guard *silently never enforces* — TypeError swallowed at `governance.py:116-117`); name mangling (`ollamaadapter`) breaks the registry's own docstring example; `AdminaConfig.plugins` is never passed to `discover()`.
*Why it bites:* 0.10 ships Anthropic/Bedrock/Gemini adapters + Presidio *as plugins* onto this machinery. Shipping the adapter wave first cements the broken identity scheme as public API.
*Pay:* **Before the 0.10 adapter wave.** Fix `_extract_name`, add `__init__(config)` to the contract, wire `discover(extra_modules=)`, emit entry-points in the scaffold, add one build-install-list-execute integration test.

**D4 — Three config systems, mostly dead YAML** (root cause of claim 8 partial; concrete bugs: `cfg.raw`, OISG S2 false negative, `schema_version` vs `version` key)
*Why it bites:* 0.12 per-tenant configuration is impossible while config is split across env-Settings singleton, half-dead AdminaConfig, and a third CLI parser. Every release until then, `admina init` generates config that silently does nothing — a trust killer.
*Pay:* **0.10 for the bugs; 0.11–0.12 for unification** (AdminaConfig canonical, Settings derived, unknown-key warnings, wire-or-delete every field).

**D5 — Audit exists only behind the proxy; bus is not the audit spine** (root cause of claims 1, 2 caveats)
*What:* Forensic/ClickHouse are direct calls inside the MCP handler; OTEL/alerts subscribe only to GOVERNANCE_DECISION; six EventType members are dead; SDK events vanish.
*Why it bites:* The EU AI Act story rests on the forensic chain; an SDK GovernedAgent BLOCK leaving no tamper-evident record is a credibility hole *today*, and 0.11 observability inherits the dead taxonomy.
*Pay:* **0.11.** Move persistence behind bus subscribers, emit the specific EventTypes, give SDK-only mode a default sink.

**D6 — Per-process mutable state + single-writer forensic chain**
*What:* Loop windows, metrics, bus singleton, WS client set, compliance lists all in-process; `ForensicBlackBox.record()` does unlocked read-modify-write of `chain_head` — two writers fork the chain; on filesystem, duplicate sequence = silent overwrite. Verification is never run by any wired path.
*Why it bites:* This is the one component that **cannot** be made stateless by configuration — 0.12 per-tenant namespaces and 1.1 stateless scale both collide with it; deferring forces a rewrite under pressure.
*Pay:* **Lock + verify-endpoint now (cheap, 0.10); state-backend seam and multi-writer chain design before 0.12.**

**D7 — Observability wired to nothing end-to-end**
*What:* Collector traces export to `debug` only; `/metrics` scraped by nothing; Grafana charts otelcol self-metrics; exporter sets the global tracer provider; spans are detached roots.
*Why it bites:* 0.11 is literally "observability"; "request-level tracing correlation" starts from zero.
*Pay:* **0.11**, by definition.

**D8 — Duplicated artifacts that have already drifted** (dual SDK/plugins ABCs → claim quickstart type error; dual dashboard SPAs → Docker copy missing the allSettled fix; dual EU AI Act engines → keyword drift; dual HTTP/WS auth → live feed broken at HEAD)
*Why it bites:* The WS auth break is a 0.10 roadmap item ("WebSocket authentication") and a shipped regression; the dual ABCs poison every 0.10 adapter's type story.
*Pay:* **0.10.** Delete the SDK-local ABCs, single-source the SPA, one token verifier; consider moving the 9 ABCs to `core/ports.py` to fix the domains→plugins inversion.

**D9 — Forensic write awaited in the request critical path** (two sequential S3 PUTs per request, executor pool as throughput ceiling)
*Pay:* **0.11 performance work** — write-ahead queue with batched anchoring; bundle with the D6 chain redesign since both change the `ForensicBlackBox` contract.

---

## 6. What to Protect

These are verified-in-code design assets; future work must not erode them:

1. **The dependency-free core kernel and acyclic import graph** — no upward imports anywhere in `admina/core`; every deferred import has a documented reason. Moving the ABCs to core must preserve this purity.
2. **`run_pipeline` as pure logic** (`proxy/governance.py:51-72`) — engines/guards/mode injected, zero I/O. The fix for D2 is to *spread* this seam, never to let side effects leak into it.
3. **Graceful degradation with loud, actionable warnings** — Redis/ClickHouse/S3/OTEL/spaCy all optional, every downgrade logged with the operator fix; PIIRedactor's regex-only fallback; adapters' curated ImportErrors. The proxy is genuinely useful with zero infrastructure.
4. **The CLI DX investment** — adaptive `init` next-steps, single-process `admina dev`, `doctor` with uv-aware remediation. The only fully-"works" surface a new user touches first.
5. **Honest self-limiting documentation where it exists** — README's 7/14 Rust disclosure, NIS2's triage scoping, the forensic tamper-evident-not-tamper-proof note, the 0.10 spec naming its own defects. Extend this register to the README pipeline claims and MODEL_CARD; do not regress it.
6. **Test-pinned claims** — `test_firewall_parity.py` (expected-miss cases), `test_benchmark_14us.py` (README numbers as baselines), tamper-detection tests. The discipline of pinning marketing numbers in tests is rare; apply it to the plugin loop (D3's integration test).
7. **The composition-root pattern** (`ProxyState` built in lifespan, routers via factory closures) and the deployment hygiene (localhost-bound infra ports, non-root UID, commented healthchecks).
8. **The event bus as cross-layer spine** — the right abstraction; D5's fix is to make it carry *more* (persistence subscribers), not to bypass it further.
9. **`plugins/base.py` contract documentation quality** and registry failure isolation — keep the docstring standard when fixing identity/config-passing.
10. **The small, typed public surface** — 4 primitives + `__version__`, `py.typed`, uniform `*_sync` ergonomics via one `run_sync` bridge. Resist export sprawl while fixing the genuine gaps (re-export `BaseModelAdapter`, response types, `bus`/`EventType`).

---

**Bottom line:** Admina is a well-founded framework with one problematic axis — governance coherence across entry points — and a systemic habit of building excellent machinery (plugins, config, event taxonomy, observability stack) that its own runtime then bypasses. The 0.10 release is the cheapest moment to fix D1/D2/D3/D8; D6 is the one debt that, unpaid, forces a rewrite at 0.12/1.1.
