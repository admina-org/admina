---
name: admina-governance
description: >
  Route all agent actions through Admina governance proxy for
  PII redaction, firewall enforcement, loop breaking, and
  forensic audit logging. Required for EU AI Act compliance.
metadata:
  openclaw:
    emoji: "\U0001F6E1\uFE0F"
    requires:
      bins: ["docker"]
      env: ["ADMINA_PROXY_URL"]
    install:
      - id: docker
        kind: download
        url: https://admina.org/install.sh
        label: "Install Admina sidecar"
    homepage: https://admina.org
    primaryEnv: ADMINA_PROXY_URL
---

# Admina governance

## When to activate
This skill is ALWAYS active. Every action you take must be
validated through Admina before execution.

## How it works
Before executing any tool call, HTTP request, or shell command:

1. Send the action payload to the Admina proxy for validation:
   ```
   curl -s -X POST ${ADMINA_PROXY_URL}/api/v1/validate \
     -H "Content-Type: application/json" \
     -d '{"action": "<ACTION_TYPE>", "payload": "<CONTENT>"}'
   ```

2. Check the response:
   - `"allowed": true` -> proceed with the action
   - `"allowed": false` -> report the block reason to the user
   - `"modified": true` -> use the modified payload (PII redacted)

3. After execution, log the result:
   ```
   curl -s -X POST ${ADMINA_PROXY_URL}/api/v1/audit \
     -H "Content-Type: application/json" \
     -d '{"action": "<ACTION_TYPE>", "result": "<OUTCOME>"}'
   ```

## Action types
- `llm_call` -- any LLM API call
- `shell_exec` -- any shell command
- `file_write` -- any file creation/modification
- `http_request` -- any outbound HTTP call
- `message_send` -- any message to external platforms

## If Admina proxy is unreachable
STOP. Do not proceed. Inform the user:
"Admina governance proxy is not responding. Cannot execute
ungoverned actions. Please check the sidecar status."

## Dashboard
${ADMINA_PROXY_URL}/dashboard
