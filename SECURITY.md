# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.9.x   | Yes       |
| < 0.9   | No        |

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
  to protect all endpoints. Without it, the proxy is unauthenticated (local dev only).
- **Secrets**: Never commit `.env` to version control. Use `.env.example` as a template.
- **Network isolation**: The Docker Compose setup isolates ClickHouse and Redis on an
  internal network — do not expose their ports to the internet.
- **MinIO**: Enable `MINIO_SECURE=true` and configure TLS in production deployments.
