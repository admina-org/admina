# Builtin Plugins


## OllamaAdapter

::: plugins.builtin.adapters.ollama


## OpenAIAdapter

::: plugins.builtin.adapters.openai


## ChromaDBConnector

::: plugins.builtin.connectors.chromadb


## FilesystemConnector

::: plugins.builtin.connectors.filesystem


## MCP Transport

::: plugins.builtin.transports.mcp


## HTTP REST Transport

::: plugins.builtin.transports.http_rest


## spaCy + Regex PII

::: plugins.builtin.pii.spacy_regex


## API Key Auth

The provider reads `ADMINA_API_KEY` from the environment when it is created
without arguments, and the proxy loads it only when that variable is set. A
key given only through `ADMINA_API_KEY_FILE` or `.env` does not reach the
provider: the proxy's authentication middleware checks it instead, with the
same headers (`X-API-Key`, `Authorization: Bearer`).

::: plugins.builtin.auth.apikey


## Filesystem Forensic Store

::: plugins.builtin.forensic.filesystem


## EU AI Act Template

::: plugins.builtin.compliance.eu_ai_act


## GuardrailsAI Guard

::: plugins.builtin.guards.guardrailsai_guard


## Log Alert Channel

::: plugins.builtin.alerts.log


## Webhook Alert Channel

::: plugins.builtin.alerts.webhook
