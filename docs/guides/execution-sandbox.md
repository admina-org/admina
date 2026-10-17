# Execution sandbox

The governance pipeline decides whether a tool call may proceed. It reads
the call's arguments, not what the tool does with them: a `python_exec`
tool that receives `{"code": "..."}` runs that code with the privileges,
filesystem and network of whatever process hosts the tool, and code that
assembles a URL from parts carries no destination the egress stage can
recognise.

The execution sandbox contains that execution. For the tools you declare,
Admina does not forward an allowed `tools/call` upstream: it runs the code
itself, in a fresh container per call, and removes the container
afterwards.

- Off by default (`domains.agent_security.sandbox.enabled: false`).
- Network: none. The container has loopback only.
- Never a fallback: a declared tool is executed in the sandbox or not at
  all.

What it does not guarantee is in
[MODEL_CARD.md §5d](https://github.com/admina-org/admina/blob/main/MODEL_CARD.md#5d-execution-sandbox); read it
before you rely on it.

---

## How a call is handled

On `POST /mcp`, for a `tools/call` whose `params.name` is a declared tool:

1. The governance pipeline runs as for any call (loop breaker, firewall,
   PII, egress, guards) and its forensic record is written.
2. A call that is blocked is answered as today and never executed. Under
   `ADMINA_GOVERNANCE_MODE=observe` or `dry-run` a call the pipeline would
   block is let through, and is therefore executed **in the sandbox**: the
   governance mode changes the verdict, never the isolation.
3. The tool's arguments, as the pipeline left them (PII redacted when PII
   redaction is on), are mapped to an execution by the tool's profile:
   `python` writes the code to `/work/main.py` and runs
   `python -I /work/main.py`; `shell` writes it to `/work/main.sh` and runs
   `sh /work/main.sh` (never `sh -c`).
4. The sandbox runs it and returns stdout, stderr, the exit code, and the
   files the code wrote under `/work/out/`.
5. A second forensic record, `<event_id>:sandbox`, is written, and a
   `sandbox_execution` event goes on the event bus.
6. The result, as an MCP `CallToolResult`, goes through the same response
   path as an upstream response: PII redaction, then the governance guards'
   response inspection.

The call is never forwarded upstream, even when an upstream server exposes
a tool of the same name.

The `CallToolResult`:

- `content[0]`: stdout as text; a second text block `[stderr]…` when stderr
  is not empty; a note when the time or memory limit stopped the code;
  one embedded `resource` per output file (`uri: sandbox:///work/out/…`,
  `text` for UTF-8 files, `blob` (base64) otherwise);
- `isError`: true when the code exited non-zero, timed out or ran out of
  memory;
- `structuredContent`: `exit_code`, `timed_out`, `oom_killed`,
  `stdout_truncated`, `stderr_truncated`, `files` (path and size),
  `files_truncated`, `duration_ms`.

### `tools/list`

Admina adds the declared tools to the upstream's `tools/list` result
(replacing upstream tools of the same name), with the `description` and
`input_schema` of their configuration, or a schema built from the tool's
arguments. When the upstream cannot be reached, `tools/list` returns the
declared tools alone. Every other method (`initialize` included) is still
forwarded upstream, so a client that needs only the sandboxed tools still
needs an MCP server behind Admina for the handshake.

### When the sandbox cannot run a call

| Situation | Response | Record |
|---|---|---|
| Arguments that do not fit the tool (no `code`, a file path outside `/work`, over a size limit) | HTTP 400, JSON-RPC `-32602`, `data.reason: sandbox_request_invalid` | `:sandbox`, `action: ERROR`, `error: invalid` |
| No free slot within `queue_timeout_seconds` | HTTP 503, JSON-RPC `-32603`, `data.reason: sandbox_unavailable` | `error: busy` |
| Engine unreachable, image missing, runtime not registered, container not created | HTTP 503, JSON-RPC `-32603`, `data.reason: sandbox_unavailable` | `error: unavailable` |

The error message of the runtime stays in the proxy's log; the client gets
the reason only. None of these falls back to forwarding or to running the
code elsewhere, whatever `ADMINA_GUARD_FAIL_MODE` or
`ADMINA_FORENSIC_FAIL_MODE` say. A timeout, a non-zero exit code and an
out-of-memory kill are results, not errors: the code ran, contained.

With `ADMINA_FORENSIC_FAIL_MODE=closed`, a `:sandbox` record that cannot be
written turns the response into a 503; the execution has already happened.

---

## Requirements

- A Docker or Podman engine the proxy process can reach, and its CLI
  (`docker` or `podman`) on the proxy's `PATH`. Admina drives the CLI; it
  adds no Python dependency.
- The image, present locally. The default is `python:3.12-slim` pinned by
  digest; nothing is pulled at request time:

  ```bash
  docker pull python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
  ```

  Another image must provide `sleep` and `tar` (and `python` or `sh` for
  the profiles). Pin it by digest (`name@sha256:…`); a tag only is logged
  as a warning at startup.
- For `runtime: runsc`: gVisor installed and registered with the engine
  (`/etc/docker/daemon.json`), Linux only. It is not available on Docker
  Desktop for macOS.

### The Docker socket is root on the host

Whoever can reach the engine's socket can start a privileged container
with the host's `/` mounted. Enabling the sandbox gives the proxy that
access, so a compromise of the proxy becomes a compromise of the host. A
socket proxy that filters API endpoints is not a fix: creating a container
alone allows arbitrary bind mounts.

Recommended:

- **rootless Docker** or **rootless Podman**: the engine and its socket
  belong to an unprivileged user, and so does everything a container can
  reach;
- or a dedicated host or VM for the proxy;
- never the socket of a root engine shared with other workloads.

The example `docker-compose.yml` does **not** mount the socket, and the
proxy image does not include the `docker` CLI: the sandbox is meant for a
proxy that runs where a rootless engine is available (on the host, or in an
image you derive with the CLI and `plugin_config.docker.host` pointing at a
rootless engine).

---

## Configuration

```yaml
domains:
  agent_security:
    sandbox:
      enabled: true
      provider: docker            # the execution_sandbox plugin
      runtime: runc               # runc: the engine's default runtime; runsc: gVisor
      max_concurrent: 4           # executions at once
      queue_timeout_seconds: 5    # wait for a free slot, then refuse
      defaults:                   # every tool, unless it sets its own
        image: "python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
        timeout_seconds: 30       # wall clock; the container is killed at the end
        memory_mb: 256            # memory = memory + swap
        cpus: 1.0
        pids: 128                 # processes and threads
        disk_mb: 64               # size of the /work tmpfs
        output_max_bytes: 65536   # kept of stdout, and of stderr
        files_max_bytes: 8388608  # input files, and output files
        network: none
      tools:
        python_exec:
          profile: python
          code_argument: code     # default
          files_argument: files   # optional: [{path, content}] or [{path, content_b64}]
          timeout_seconds: 10
          description: Run Python code without network access
          # input_schema: {...}   # JSON Schema for tools/list; default built from the arguments
        run_shell:
          profile: shell

plugin_config:
  docker:
    binary: docker                # docker | podman | a path to either
    host: ""                      # DOCKER_HOST (docker) or CONTAINER_HOST (podman); "" = CLI default
    orphan_age_seconds: 900
    cli_timeout_seconds: 60
```

Invalid values stop the proxy at startup with the key named, and so does
`network: egress`: network access through an allowlist is not supported
yet. An unknown provider and an unknown key of `plugin_config.docker` stop
it too. A provider that is not ready (engine unreachable, image missing,
`runsc` not registered) does not: the proxy starts, `/health` reports
`degraded`, and the sandboxed tools are refused until it is ready. The
other tools are not affected.

`runtime` is set in the sandbox section, not in `plugin_config.docker`.

### Inside the container

| Aspect | Value |
|---|---|
| User | `65534:65534`, whatever the image's `USER` |
| Root filesystem | read-only |
| Writable | tmpfs `/work` (`disk_mb`) and `/tmp` (16 MB), both `noexec,nosuid,nodev` |
| Privileges | `--cap-drop ALL`, `no-new-privileges`, the engine's default seccomp profile, never `--privileged` |
| Limits | `--memory` = `--memory-swap`, `--cpus`, `--pids-limit`, `nofile=256` |
| Network | `--network none` |
| Environment | none of the proxy's variables |
| Mounts | none from the host |
| Logs | `--log-driver none` |
| Labels | `admina.sandbox=1`, `admina.event_id`, `admina.created` |

Each call: `run` (PID 1 an idle `sleep infinity` behind `--init`), `exec tar
-x` of the input files onto the tmpfs, `exec` of the command, `exec tar -c`
of `out/`, `inspect` for the out-of-memory state, `rm -f`. The request has
no field for mounts, capabilities, privileges, the runtime or the user: they
come from this configuration only.

Containers with the `admina.sandbox=1` label older than
`orphan_age_seconds` (left behind by a crash) are removed at startup and
every 30 seconds; the ones still running are removed at shutdown.

---

## Observability

- **Forensic record** `<event_id>:sandbox`, `event_type: sandbox_execution`,
  `action: ALLOW` (it ran) or `ERROR`, with `checks.sandbox`:
  `provider`, `tool`, `runtime`, `image_digest`, `limits`, `network`
  (`mode`, `observed: false`, `attempts: []`), `input` (SHA-256 of the
  command, size and SHA-256 of stdin and of each input file), `exit_code`,
  `timed_out`, `oom_killed`, `duration_ms`, size and SHA-256 of stdout and
  stderr, `files_out` (path, size, SHA-256), `error`. Never the content of
  the code, of the files or of the output.
- **Bus event** `sandbox_execution` (domain `agent_security`) with the
  summary: the live feed and any subscriber see it.
- **Metrics**: `admina_sandbox_runs_total`,
  `admina_sandbox_errors_total{reason="invalid|busy|unavailable"}`,
  `admina_sandbox_timeouts_total`, `admina_sandbox_oom_total`,
  `admina_sandbox_duration_seconds` (histogram), `admina_sandbox_inflight`,
  `admina_sandbox_ready`.
- **`/health`**: `sandbox` is `null` when off; otherwise `provider`,
  `ready` (the last check, at startup and every 30 seconds), `runtime`,
  `detail`, `inflight` and `tools`. `status` is `degraded` while `ready` is
  false.

---

## SDK

`GovernedAgent` takes an upstream callable; `sandbox_upstream` builds one
that executes the declared tools:

```python
from admina.plugins.builtin.sandboxes.docker import DockerSandbox
from admina.sdk import GovernedAgent
from admina.sdk.sandbox import sandbox_upstream

agent = GovernedAgent(
    upstream=sandbox_upstream(
        DockerSandbox(),
        {"python_exec": {"profile": "python", "timeout_seconds": 10}},
        fallback=None,  # or the upstream of every other call
    )
)
response = await agent.call(
    "tools/call", {"name": "python_exec", "arguments": {"code": "print(6 * 7)"}}
)
print(response.result["content"][0]["text"])  # 42
```

A call that did not run raises `SandboxRequestInvalid` or
`SandboxUnavailable` (`admina.core.types`). The SDK emits the
`sandbox_execution` bus event and writes no forensic record, like the rest
of `GovernedAgent`.

---

## Other providers

`execution_sandbox` is a plugin type: `admina plugin create my-sandbox
--type execution_sandbox` scaffolds a provider implementing
`BaseExecutionSandbox` (`run()`, `capabilities`, optionally `health()`,
`reap()`, `aclose()`), and `provider: my-sandbox` selects it. A provider
must enforce the request's limits, give the environment nothing beyond
what the request names, report timeouts and out-of-memory kills as
results, raise `SandboxError` for failures of the environment, and list in
`capabilities` only what it enforces (the proxy refuses a provider without
`network_none` and `files`).

## Not in this release

- `network: egress` (outbound access through a proxy that applies the
  egress allowlist, with each connection attempt recorded);
- third-party MCP servers run in containers;
- persistent state between calls, warm container pools.
