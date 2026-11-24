# Coding agents

This guide puts the OpenAI-compatible gateway between a coding agent and its
model server, for agents that speak Chat Completions and run tools on the
user's machine:

```text
coding agent ──▶ reverse proxy ──▶ Admina gateway ──▶ model server
                 TLS, user keys     /v1
```

The gateway serves `POST /v1/chat/completions` and `GET /v1/models`. It does not
serve the Anthropic Messages API or the OpenAI Responses API, so an agent that
speaks only one of those cannot use it.

## Why the defaults do not fit

The messages of a coding session hold source code and shell commands, and the
history is sent again on every turn. With the default settings:

- the `tool_abuse` firewall category flags ordinary commands and scripts
  (`rm -rf build`, `cat /etc/hosts`). A flagged file stays in the history, so
  under `enforce` every later request of the session is blocked;
- the deep path of the firewall scores long files as suspicious;
- PII redaction reads code as text. It masks identifiers as names and
  organisations, and version numbers as IP addresses (`1.2.3.4`). The agent then
  receives masked files and sends masked edits, and with an NER model the
  redaction of a long history takes seconds on every turn.

## Configuration

```bash
ADMINA_GATEWAY_UPSTREAM=http://127.0.0.1:8000/v1
ADMINA_API_KEY_FILE=/run/secrets/admina_api_key
ADMINA_GATEWAY_TOOL_CALL_GATE=true
ADMINA_GOVERNANCE_MODE=observe       # enforce once the records look right
ADMINA_EGRESS_MODE=enforce           # still capped by the governance mode
PII_REDACTION_ENABLED=false
INJECTION_DEEP_PATH_ENABLED=false
ADMINA_GATEWAY_TIMEOUT_READ=600      # a queued request can wait for minutes
FORENSIC_BACKEND=filesystem
FORENSIC_BASE_DIR=/var/lib/admina/forensic
```

```yaml
# admina.yaml
schema_version: 1
domains:
  agent_security:
    firewall:
      disabled_categories: [tool_abuse]
    egress:
      enabled: true
      surfaces: [gateway_tool_calls]
      allow:
        - localhost
        - 127.0.0.1
        - github.com
        - "*.github.com"
        - "*.githubusercontent.com"
        - pypi.org
        - files.pythonhosted.org
        - registry.npmjs.org
```

`disabled_categories` applies to the Python firewall only: `ADMINA_ENGINE=auto`
then runs it, and `ADMINA_ENGINE=rust` stops the proxy.

The firewall still scans every message, tool results included, so instructions
hidden in a file or a web page the agent read are flagged. It is a heuristic, not
a guarantee, and other patterns can match source code too: a file flagged by a
pattern of another category blocks the session as above. `X-Admina-Categories`
and the `gateway_request` record name what matched, and
`agent_security.firewall.disabled_patterns` leaves out one pattern by its id
(`obfuscation.en.1`).

## Per-user records

The reverse proxy authenticates the user and passes on the identity. It must
replace the headers the client sent:

```nginx
proxy_set_header Authorization "Bearer <gateway key>";
proxy_set_header X-Agent-Id    $authenticated_user;
```

`X-Agent-Id` is recorded as `agent_id` in the forensic records. Keep the gateway
on a loopback or private address, so that it is reached only through the proxy.

## Rolling out

1. Start in `observe`, and read the `gateway_tool_call` records. A call the gate
   would block has `would_action: "BLOCK"` and names its check, reason and
   destinations.
2. Add the hosts your work needs to `allow`. `admina egress suggest-allowlist`
   lists the destinations of the records of a `filesystem` store, those of these
   records included: review them, since they include what the gate would block.
3. Set `ADMINA_GOVERNANCE_MODE=enforce`. A blocked call reaches the agent as a
   text notice, so the model can read why and try something else.

## Limits

- **Personal data.** With `PII_REDACTION_ENABLED=false`, personal data in prompts
  and code reaches the model server. Run the model on your own network if that
  matters. PII redaction has no setting to cover only some roles or to leave the
  arguments of tool calls alone.
- **Loops.** The loop breaker does not run on the gateway, only on `/mcp` and in
  the SDK. A runaway agent is limited by the rate limits of your proxy.
- **The gate reads arguments.** It does not see what a tool does when it runs. A
  program that builds its destination, or a script the agent wrote earlier, is
  not covered: see the [model card](https://github.com/admina-org/admina/blob/main/MODEL_CARD.md).
  The agent's own permission settings and a sandbox on the machine that runs the
  tools remain necessary.
- **Streaming.** The arguments of a call arrive together at the end of the
  response. An agent that shows them as they are generated shows them late.
