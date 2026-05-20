# Plugin Interfaces

Admina defines 9 abstract base classes that cover every extensible capability:
model adapters, data connectors, governance guards, compliance templates,
transport adapters, forensic stores, auth providers, PII engines, and alert
channels. Community developers subclass these ABCs to add new functionality.

## Quick Example

```python
from admina.plugins.base import BaseGovernanceGuard

class ToxicityGuard(BaseGovernanceGuard):
    name = "toxicity"

    async def inspect_request(self, request):
        score = my_toxicity_model(request["content"])
        if score > 0.8:
            return {"action": "BLOCK", "risk_level": "HIGH", "reason": "toxic"}
        return {"action": "ALLOW", "risk_level": "LOW"}

    async def inspect_response(self, response):
        return {"action": "ALLOW", "risk_level": "LOW"}
```

Install a community plugin:

```bash
admina plugin install admina-guard-toxicity
```

**See also:** [Plugin Registry](plugins-registry.md) for discovery and lookup,
[GovernedModel](governed-model.md) for model adapters in action.

## API Reference

::: admina.plugins.base
