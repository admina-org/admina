# Admina Governance Plugin for Cheshire Cat AI

Route all Cheshire Cat interactions through Admina for PII redaction, injection firewall, loop detection, and forensic audit logging.

## What it does

Three Cheshire Cat hooks govern the entire message pipeline:

| Hook | Purpose |
|------|---------|
| `agent_fast_reply` | Validates user messages **before** the agent processes them. Blocks injections, redacts PII. |
| `before_cat_sends_message` | Validates the Cat's reply **before** it reaches the user. Redacts PII leakage, audits the interaction. |
| `before_cat_recalls_memories` | Validates RAG queries **before** they hit the vector store. Prevents injection via retrieval. |

## Install

### 1. Start the Admina sidecar

```bash
cd integrations/cheshirecat/admina-plugin
./setup.sh
```

This starts the Admina governance proxy as a Docker container on port 18790.

### 2. Copy the plugin into Cheshire Cat

```bash
cp -r admina-plugin/ <your-cheshire-cat>/plugins/admina-plugin/
```

Or from the Cat admin panel: upload the plugin folder.

### 3. Set the environment variable

In your Cheshire Cat `.env` or `docker-compose.yml`:

```bash
ADMINA_PROXY_URL=http://host.docker.internal:18790
```

### 4. Activate

Enable the plugin from the Cheshire Cat admin panel.

## How it works

```
User Message
    |
    v
[agent_fast_reply]  ──> Admina /api/v1/validate
    |                        |
    |  BLOCK? ──> Return governance notice
    |  REDACT? ──> Replace PII in working memory
    |  ALLOW? ──> Continue
    |
    v
Cheshire Cat Agent (LLM + plugins + RAG)
    |
    |── [before_cat_recalls_memories] ──> Validate RAG query
    |
    v
[before_cat_sends_message] ──> Admina /api/v1/validate
    |                               |
    |  Redact PII from response     |
    |  Audit to forensic black box  |
    |
    v
User receives governed response
```

## Configuration

Edit `admina.yaml` to customize governance behavior:

- **Firewall sensitivity**: `agent_security.firewall.sensitivity`
- **PII entities**: `agent_security.pii_redaction.entities`
- **Loop detection**: `agent_security.loop_breaker.window_size`
- **EU AI Act risk category**: `compliance.eu_ai_act.risk_category`

## If Admina is unreachable

The plugin **fails open** with a warning log. Messages are processed normally but without governance. This ensures the Cat remains functional even if the sidecar is temporarily unavailable.

## Dashboard

View real-time governance events at: `http://localhost:18790/dashboard`

## Uninstall

```bash
./setup.sh --uninstall
```
