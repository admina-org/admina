# Compliance


## Forensic Black Box

::: domains.compliance.forensic


## EU AI Act

::: domains.compliance.eu_ai_act


## OISG Adequacy Score

Admina ships a self-assessment engine that scores a running instance against
the four [OISG](https://oisg.ai) pillars — **Open, Intelligent, Secure,
Governed** — with 5 criteria per pillar (0–100 total). Unlike the OISG
reference test at `oisg.ai/test` which is a manual checklist, Admina
computes the score automatically by inspecting the live runtime state
(firewall, PII redactor, forensic box, compliance engine, OTEL exporter,
governance guards, API key auth, Rust engine availability, etc.).

### Score levels

| Range | Level |
|-------|-------|
| 0–24  | Critical gaps |
| 25–49 | Partial coverage |
| 50–79 | Good coverage |
| 80–100 | OISG adequate |

### Endpoint

```
GET /api/dashboard/oisg
```

Returns total score, per-pillar breakdown, per-criterion satisfaction
(with reason), and pillar colours. Exposed in the dashboard under the
"Instance Configuration" section — separated from live runtime metrics
because it is a **static capability assessment**, not a live indicator.

### Distinction from Admina Score

- **Admina Score** (`/api/dashboard/score`) — weighted composite of live
  runtime metrics (residency enforcement, interactions audited, EU AI Act
  gap coverage, recent attacks, forensic chain validity).
- **OISG Score** (`/api/dashboard/oisg`) — static snapshot of *which OISG
  capabilities this deployment enables*, independent of traffic.

::: domains.compliance.oisg


## OpenTelemetry Export

::: domains.compliance.otel
