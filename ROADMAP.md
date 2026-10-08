# Roadmap

This document outlines the planned direction for Admina. It is intentionally
version-based rather than date-based: releases ship when the scope is ready,
not on a calendar. Scope may shift in response to user feedback, security
findings, or upstream changes in the governance landscape (EU AI Act
implementing acts, new frameworks, new attack classes).

The current release is **0.14.1**. Admina is pre-1.0: the public API may
still evolve before the 1.0 stability commitment, so a minor release may
carry a declared breaking change once its replacement is in place. Shipped
detail lives in [CHANGELOG.md](CHANGELOG.md).

---

## 0.9.x — Stabilisation

Patch releases only. No new features.

- Bug fixes driven by early-adopter reports
- Documentation hardening: guided tutorials, troubleshooting matrix,
  plugin development walkthrough
- Test-coverage expansion on edge cases surfaced after the public release
- Packaging fixes (wheel manifests, extras resolution, Docker image size)

---

## 0.10.0 — Adapter coverage and pipeline unification

Broader provider support and a single governance pipeline across every
surface.

- Five model adapters — Anthropic, Mistral, AWS Bedrock, Google Gemini,
  and a native vLLM adapter — each lazy-importing its provider SDK through
  a per-provider packaging extra.
- Configurable retry / backoff on the governed primitives
  (`GovernedModel`, `GovernedAgent`, `GovernedData`), opt-in via a
  `RetryPolicy` with no new runtime dependency.
- Uniform engine selection (`ADMINA_ENGINE=auto|python|rust`) across proxy,
  SDK, and integrations, with engines acquired through a single
  `admina.engines` package.
- One canonical governance pipeline (loop → firewall → PII → guards) shared
  by `POST /mcp`, `POST /api/v1/validate`, and the SDK primitives;
  `GovernedModel.ask()` runs full governance by default.
- Dashboard live-feed WebSocket authentication with session-cookie
  verification and an Origin allow-list.
- Security and forensic hardening: fail-closed default when no API key is
  configured, hash-chain state reconstruction from persisted records, and
  serialized forensic writes.

---

## 0.11.0 — Streaming governance and an OpenAI-compatible gateway

Governance on streamed responses and behind an OpenAI-compatible HTTP
surface, an additional PII engine, and the closure of deferred hardening
items.

- SDK streaming on `GovernedModel`: an async iterator that applies inline
  governance to each chunk through a windowed recomposition buffer, so a
  PII entity split across chunk boundaries is still redacted. Streaming
  metadata is shaped to map onto the OpenTelemetry GenAI conventions so
  0.12 can emit it unchanged.
- Microsoft Presidio as a selectable first-class PII engine
  (`ADMINA_PII_ENGINE=presidio`), analyzer-only so the redaction mask
  format is identical across engines. The default engine is unchanged
  (`spacy-regex`).
- An OpenAI-compatible HTTP gateway (`POST /v1/chat/completions`,
  `GET /v1/models`) as an additional governed surface, streaming and
  non-streaming, protected by the existing credential check.
- Breaking change: `/api/v1/validate` returns `action="REDACT"` in place
  of the former `"MODIFY"`, a clean rename with no compatibility shim.
  Permitted under the pre-1.0 posture: the public API may still evolve
  before the 1.0 stability commitment.
- Signed forensic state file: an optional HMAC over `_chain_state.json`
  (`ADMINA_FORENSIC_STATE_KEY`); an unsigned or tampered state falls back
  to reconstruction from the persisted records.
- Configurable guard fail mode (`ADMINA_GUARD_FAIL_MODE=open|closed`,
  default `open`): under `closed`, an exception inside a guard yields
  `action="BLOCK"`.
- Detection-efficacy red-team suite (already on `main`): measures
  firewall, PII, and loop-breaker recall against committed corpora with
  baseline pinning and a comparison gate that refuses to compare metrics
  across engine modes.

---

## 0.12.0 — Egress control and coordination detection

- Destination-based egress control on tool calls, evaluated independently of
  the HTTP method. It reads the tool-call arguments of `/mcp`; on the
  gateway, `POST /api/v1/validate` and `GovernedModel` it reads prompt
  text, which seldom holds a destination it recognises, and
  `GovernedAgent.call()` has none (see MODEL_CARD §5b). Default-deny under
  `ADMINA_EGRESS_MODE=enforce`, with an observe-first rollout and an
  `admina egress suggest-allowlist` command to build the allowlist from
  observed traffic. A cross-agent coordination detector, fed from the MCP
  proxy path only, escalates undeclared multi-agent fan-in on one
  destination to a fleet-wide write quarantine once keyed content confirms
  it — refused under `enforce`, recorded under `observe` like every other
  egress decision.

The observability items first planned for 0.12 are listed under
[Not yet scheduled](#not-yet-scheduled), except those shipped in 0.13.

---

## 0.13.0 — Embedded gateway and forensic integrity

The OpenAI-compatible gateway as the governed surface of an embedded
deployment, and a forensic store that can be verified record by record.

- Gateway: named upstream routes with keys, streams passed through
  unchanged while PII redaction is off, upstream errors and timeouts
  propagated, request limits, the whole chat completion body in the scan,
  the governance outcome on every response, request ids and W3C trace
  context.
- Deployment: secrets from files, `ADMINA_CONFIG`, `ADMINA_ENABLED_SURFACES`,
  the `proxy-minimal` extra, an offline mode, a schema check of
  `admina.yaml`, and signed release images with a `-slim` variant.
- Forensic store: atomic writes, a signature on each record, verification
  from a checkpoint and JSON Lines export.
- Firewall and PII: linear-time pattern matching, stable pattern ids,
  pattern packs, an Italian baseline, PII engines from other packages and
  an `[OMISSIS]` mask style.
- Observability: per-surface request metrics, event loop lag, and
  governance events without request text.
- Compliance and testing: an OISG score from external evidence and
  `admina redteam` on external corpora.

---

## 0.14.0 — Package name

- Admina is published on PyPI as `admina`; `admina-framework` is no longer
  released after a final 0.14.0 that stops the installation with the
  commands to switch. A declared breaking change for installs of
  `admina-framework`: the module, the `admina` command and the extras do
  not change. See
  [docs/guides/package-name.md](docs/guides/package-name.md).

---

## How to influence the roadmap

- Open a GitHub issue with the `roadmap` label
- Start a discussion in the repository's Discussions tab
- For security-sensitive proposals, follow the process in
  [SECURITY.md](SECURITY.md)

Proposals are evaluated on: fit with the governance mission, maintenance
cost, test-ability, and the project's pre-1.0 posture of preferring
deletion over additive complexity.
