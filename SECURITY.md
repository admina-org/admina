# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.12.x  | Yes       |
| < 0.12  | No        |

During the pre-1.0 phase only the latest minor line receives security
fixes. Once 1.0 ships, an LTS window will be defined in
[ROADMAP.md](ROADMAP.md).

## Reporting a Vulnerability

Admina is a security-sensitive project — it sits in the critical path between AI agents
and the tools they use. We take vulnerability reports seriously and will respond promptly.

**Please do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

Email: **info@admina.org**

Include in your report:
- Description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept if possible)
- Affected version(s) and component(s)
- Any suggested mitigations

### What to expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix timeline** communicated within 10 business days
- **Credit** in the release notes (unless you prefer to remain anonymous)

We follow responsible disclosure: we ask that you give us reasonable time to release
a fix before making the vulnerability public.

## Scope

In scope:
- Prompt injection bypass (agent_security domain)
- PII leakage through redaction bypass (data_sovereignty domain)
- Hash chain tampering or forgery (compliance domain)
- Authentication bypass (`ADMINA_API_KEY` validation)
- Dependency vulnerabilities with known exploits

Out of scope:
- Issues requiring physical access to the server
- Social engineering
- Denial of service via resource exhaustion without a patch

## Security Design Notes

- **API key authentication**: Set `ADMINA_API_KEY` (generated with `openssl rand -hex 32`)
  to protect the API. `/health` and `/metrics` are public. The OpenAPI docs (`/docs`,
  `/redoc`, `/openapi.json`) are public unless `ADMINA_API_DOCS_ENABLED=false`. Without a
  key the proxy is fail-closed: protected requests are rejected with 401 unless
  `ALLOW_UNAUTHENTICATED=true` is set explicitly (local dev only).
- **Dashboard sessions**: The bundled dashboard page and its static assets are public and
  carry no credential. The browser signs in by presenting the API key to
  `POST /api/dashboard/session`, which sets a session cookie that is `HttpOnly`,
  `SameSite=Strict`, `Secure` over HTTPS (or with `DASHBOARD_COOKIE_SECURE=true`), scoped
  to `/api/`, signed with a key derived from `ADMINA_API_KEY` (rotating the key ends every
  session) and valid for `ADMINA_DASHBOARD_SESSION_TTL` seconds (default 3600). The
  session is accepted only for read-only requests to the dashboard API
  (`/api/dashboard/*`, `/api/stats`, the `/api/dashboard/live` feed, which is closed when
  the session expires); the MCP proxy, the OpenAI-compatible gateway and the integration
  and compliance APIs always require the API key. Signing out clears the cookie in the
  browser; to end every outstanding session at once, rotate `ADMINA_API_KEY`. Deployments
  that do not use the bundled dashboard should set `ADMINA_DASHBOARD_ENABLED=false`.
- **Secrets**: Never commit `.env` to version control. Use `.env.example` as a template.
- **Network isolation**: The Docker Compose setup isolates ClickHouse and Redis on an
  internal network — do not expose their ports to the internet.
- **Forensic S3 store**: use HTTPS endpoints (`FORENSIC_S3_ENDPOINT=https://…`) and
  enable Object Lock (`FORENSIC_S3_LOCK=true`) for tamper-evident WORM retention in production.
