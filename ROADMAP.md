# Roadmap

This document outlines the planned direction for Admina. It is intentionally
version-based rather than date-based: releases ship when the scope is ready,
not on a calendar. Scope may shift in response to user feedback, security
findings, or upstream changes in the governance landscape (EU AI Act
implementing acts, new frameworks, new attack classes).

The current release is **0.11.0**. Admina is pre-1.0: the public API may
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

## 0.12.0 — Multi-tenancy and RBAC

Operating Admina as a shared service.

- Organisation / workspace isolation in the proxy
- Per-tenant quotas (request rate, forensic retention, compliance
  templates enabled)
- Role-based access control on proxy endpoints (read / write / admin)
- OIDC authentication provider as a built-in plugin
- Per-tenant forensic namespace with independent hash chains

---

## 0.13.0 — Compliance template expansion

Beyond the EU AI Act.

- NIS2 template (incident response, supply-chain obligations)
- ISO / IEC 42001 template (AI management system controls)
- SOC 2 template (Trust Services Criteria mapping)
- Cross-framework gap analysis: surface obligations that satisfy
  multiple frameworks in a single control
- Report export in PDF and DOCX, signed with the forensic key

---

## 1.0.0 — API freeze and long-term support

The stability commitment. Shipped when the public surface has settled
through real-world use.

- Plugin ABI v1 frozen with contract tests; third-party plugin
  certification suite
- Official client SDKs: TypeScript, Go
- Deprecation policy formalised; 18-month LTS window for the 1.0 line
- Security advisory process documented; CVE assignment workflow
- Removal of the pre-0.3.0 compatibility shims in `proxy/`

---

## 1.1.0 — Horizontal scale

Running Admina as stateless, horizontally-scaled infrastructure.

- Stateless proxy mode backed by shared Redis / ClickHouse
- Hot-reload of governance configuration without restart
- Official Helm chart and Kubernetes operator
- Cross-region federation for the forensic store

---

## 2.0.0 — Only if required

Reserved for breaking changes that cannot be delivered under 1.x.
No breaking changes are planned. Candidate drivers:

- Plugin ABI v2 if adoption reveals design limitations that cannot be
  extended under v1
- Streaming-first pipeline rearchitecture if chunk-level governance
  becomes the dominant workload

---

## How to influence the roadmap

- Open a GitHub issue with the `roadmap` label
- Start a discussion in the repository's Discussions tab
- For security-sensitive proposals, follow the process in
  [SECURITY.md](SECURITY.md)

Proposals are evaluated on: fit with the governance mission, maintenance
cost, test-ability, and the project's pre-1.0 posture of preferring
deletion over additive complexity.
