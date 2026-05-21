# GovernedModel

`GovernedModel` wraps any LLM adapter with automatic PII redaction on prompts
and responses, governance event emission, and audit trail. It's the primary
entry point for governed model inference.

## Quick Example

```python
from admina.sdk.governed_model import GovernedModel

model = GovernedModel(
    model_name="llama3",
    adapter=my_adapter,
)
response = await model.ask("Summarize this document")
print(response.text)           # PII-redacted response
print(response.governance)     # governance decisions applied
```

**See also:** [GovernedAgent](governed-agent.md) for agent-to-agent calls,
[Plugin Interfaces](plugins-base.md) for building custom model adapters.

## API Reference

::: sdk.governed_model

**Exports:** `GovernedModel`, `GovernedResponse`, `BaseModelAdapter`
