# Integration REST API

Provides a simpler REST interface for non-MCP callers that want to validate
actions or log audit records through the Admina governance pipeline without
speaking the full MCP protocol.

## Endpoints

- `POST /api/v1/validate` — validate an action payload (firewall, PII, loop breaker).
- `POST /api/v1/audit` — log an action result to the forensic black box.

## Quick Example

```python
import httpx

resp = httpx.post("http://localhost:8080/api/v1/validate", json={
    "content": "Summarize the Q3 report",
    "session_id": "my-session-1",
})
print(resp.json()["action"])      # "ALLOW"
print(resp.json()["checks"])      # per-domain check results
```

**See also:** [GovernedAgent](governed-agent.md) for in-process governance,
[Plugin Interfaces](plugins-base.md) for extending the pipeline.

## API Reference

::: proxy.api.integration
