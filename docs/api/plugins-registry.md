# Plugin Registry

The registry scans three locations for plugins: `plugins/builtin/` (shipped with
Admina), `~/.admina/plugins/` (user-installed), and explicit module paths from
`admina.yaml`. Each discovered module is validated against the 9 base classes
and registered for runtime lookup.

## Quick Example

```python
from admina.plugins.registry import PluginRegistry

registry = PluginRegistry()
count = registry.discover()      # scan default locations
print(f"Found {count} plugins")

adapter = registry.get("model_adapter", "ollama")
```

**See also:** [Plugin Interfaces](plugins-base.md) for the 9 abstract base classes,
[GovernedModel](governed-model.md) for using model adapters.

## API Reference

::: admina.plugins.registry
