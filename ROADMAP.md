# Roadmap

This document outlines the planned direction for Admina. It is intentionally
version-based rather than date-based: releases ship when the scope is ready,
not on a calendar. Scope may shift in response to user feedback, security
findings, or upstream changes in the governance landscape (EU AI Act
implementing acts, new frameworks, new attack classes).

The current release is **0.9.0**. Admina is pre-1.0: the public API is
feature-complete and production-ready, but the stability commitment is
deferred until community validation has confirmed the shape of the public
surface.

---

## 0.9.x — Stabilisation

Patch releases only. No new features.

- Bug fixes driven by early-adopter reports
- Documentation hardening: guided tutorials, troubleshooting matrix,
  plugin development walkthrough
- Test-coverage expansion on edge cases surfaced after the public release
- Packaging fixes (wheel manifests, extras resolution, Docker image size)

---

## 0.10.0 — Adapter coverage and SDK ergonomics

Broader model and engine support; SDK usability improvements.

- Model adapters: Anthropic, Mistral, AWS Bedrock, Google Gemini, native
  vLLM (beyond the current Ollama-based bridge)
- PII engine: Microsoft Presidio as a first-class alternative to spaCy +
  regex
- SDK: streaming-first API on `GovernedModel` (async iterator with
  inline governance on each chunk)
- SDK: configurable retry / backoff policies on all governed primitives
- Dashboard: WebSocket authentication with API-key scoping

---

## 0.11.0 — Observability and performance

Production observability beyond the current OTEL + Grafana baseline.

- Native Prometheus metrics endpoint with SLO panel
- Structured error taxonomy: stable error codes across proxy, SDK, and
  REST API
- Shared async pool for data connectors; decision cache for the
  injection firewall fast path
- Benchmark regression gate in CI (fail on >10% regression vs baseline)
- Request-level tracing correlation across SDK, proxy, and upstream LLM

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
