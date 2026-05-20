# n8n-nodes-admina

n8n community nodes for [Admina](https://admina.org) AI governance.

Add EU AI Act compliance, PII redaction, injection detection, and immutable audit logging to your n8n workflows — in minutes.

## Nodes

| Node | Type | Purpose |
|------|------|---------|
| **Admina Govern** | Inline | Validates workflow data through the Admina proxy. Blocks injections, redacts PII, detects loops. |
| **Admina Audit** | Passive | Logs workflow events to the forensic black box. Adds EU AI Act risk classification. |
| **Admina Dashboard** | Trigger | Fires when Admina detects governance events (block, PII, loop) via WebSocket. |

## Prerequisites

- An Admina proxy running (Docker or standalone) — [install guide](https://admina.org/docs/quickstart)
- n8n instance (self-hosted or cloud)

## Installation

### In n8n (Community Nodes)

1. Go to **Settings > Community Nodes**
2. Enter `n8n-nodes-admina`
3. Click **Install**

### Manual

```bash
cd ~/.n8n
npm install n8n-nodes-admina
```

## Configuration

1. In n8n, go to **Credentials > New Credential > Admina API**
2. Enter your Admina proxy URL (default: `http://localhost:8080`)
3. Optionally add an API key

## Example Workflow

```
[HTTP Trigger] -> [Admina Govern (input)] -> [OpenAI Chat] -> [Admina Govern (output)] -> [Respond]
                         |                                            |
                   Admina Proxy :8080                           Admina Proxy :8080
                   (PII + firewall)                             (toxic + audit)
```

### Admina Govern (input check)

Place before your AI node to validate incoming data:

- **Check Mode**: `input` — validate before processing
- **On Block**: `stop` — halt the workflow if content is blocked
- **Domains**: firewall, PII redaction, loop breaker (all enabled by default)

### Admina Govern (output check)

Place after your AI node to validate generated content:

- **Check Mode**: `output` — validate before delivery
- **Log to Forensic**: `true` — record in the immutable audit trail

### Admina Audit

Place at key points to log events:

- **Risk Classification**: `high` / `limited` / `minimal` (EU AI Act)
- **Custom Metadata**: add workflow-specific key-value pairs

### Admina Dashboard (trigger)

Starts a workflow when a governance event occurs:

- **Event Filter**: `BLOCK`, `CRITICAL`, `PII_DETECTED`, `LOOP_DETECTED`, `COMPLIANCE_GAP`
- Connects via WebSocket to `ws://proxy:8080/api/dashboard/live`

## API Endpoints Used

| Endpoint | Node | Purpose |
|----------|------|---------|
| `POST /api/v1/validate` | Admina Govern | Validate content through governance pipeline |
| `POST /api/v1/audit` | Admina Audit, Admina Govern | Log events to forensic black box |
| `WS /api/dashboard/live` | Admina Dashboard | Live governance event stream |

## License

Apache-2.0 — same as Admina.
