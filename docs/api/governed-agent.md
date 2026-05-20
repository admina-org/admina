# GovernedAgent

`GovernedAgent` wraps an upstream callable with the full governance pipeline:
injection firewall, loop detection, PII redaction (bidirectional), and event
emission. Use it for programmatic agent-to-agent calls with governance built in.

## Quick Example

```python
from admina.sdk.governed_agent import GovernedAgent

async def my_upstream(method, params, **kwargs):
    return {"result": "upstream response"}

agent = GovernedAgent(upstream=my_upstream)
response = await agent.call(method="tools/call", params={"text": "hello"})
print(response.action)         # "ALLOW"
print(response.result)         # upstream response
print(response.governance)     # full governance details
```

**See also:** [GovernedModel](governed-model.md) for governed model inference,
[Data Sovereignty](domain-data-sovereignty.md) for PII redaction details.

## API Reference

::: sdk.governed_agent

**Exports:** `GovernedAgent`, `GovernedMCPResponse`
