# Copyright © 2025–2026 Stefano Noferi & Admina contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Admina — the execution sandbox in the proxy (``/mcp``).

:func:`build_sandbox_executor` builds the provider named by
``domains.agent_security.sandbox.provider`` at startup;
:class:`SandboxMetrics` is its part of ``/metrics``; the other helpers
shape what ``/mcp`` answers and records for a sandboxed tool call (see
``_mcp_sandbox_call`` in :mod:`admina.proxy.main`).
"""

from __future__ import annotations

import inspect
import logging
import threading
from typing import Any

from admina.core.config import SandboxConfig
from admina.core.types import EventType
from admina.domains.agent_security.sandbox import SandboxExecutor, SandboxOutcome
from admina.proxy.request_metrics import REQUEST_BUCKETS, _Histogram

__all__ = [
    "SandboxMetrics",
    "build_sandbox_executor",
    "bus_metadata",
    "health_field",
    "sandbox_error_response",
    "sandbox_forensic_record",
    "sandbox_tool_name",
    "with_sandbox_tools",
]

logger = logging.getLogger("admina.sandbox")

# JSON-RPC data.reason of a refused sandboxed call, per outcome error.
_REASONS = {
    "invalid": "sandbox_request_invalid",
    "busy": "sandbox_unavailable",
    "unavailable": "sandbox_unavailable",
}


def build_sandbox_executor(
    registry: Any, config: SandboxConfig | None, plugin_config: dict[str, Any] | None
) -> SandboxExecutor | None:
    """The executor of the sandboxed tools; None when the sandbox is off.

    The provider is the ``execution_sandbox`` plugin named by
    ``provider``, built with its ``plugin_config`` block and the
    ``runtime`` of the sandbox section.

    Raises:
        ValueError: invalid values in the sandbox section (``network:
            egress`` among them), an unknown provider, or a provider whose
            constructor refuses its configuration.
        SandboxUnavailable: the provider lacks a capability the tools need.
    """
    if config is None:
        return None
    if config.errors:
        raise ValueError("admina.yaml: " + "; ".join(config.errors))
    if not config.enabled:
        return None
    cls = registry.get("execution_sandbox", config.provider)
    if cls is None:
        known = ", ".join(sorted(registry.list("execution_sandbox"))) or "none"
        raise ValueError(
            f"admina.yaml: domains.agent_security.sandbox.provider {config.provider!r} is not "
            f"an installed execution_sandbox plugin (installed: {known})"
        )
    block = dict((plugin_config or {}).get(config.provider) or {})
    if block.get("runtime") not in (None, config.runtime):
        raise ValueError(
            f"admina.yaml: plugin_config.{config.provider}.runtime differs from "
            "domains.agent_security.sandbox.runtime; set it in the sandbox section only"
        )
    block["runtime"] = config.runtime
    if "config" in inspect.signature(cls.__init__).parameters:
        sandbox = cls(config=block)
    else:
        sandbox = cls()
    if not config.tools:
        logger.warning("Execution sandbox enabled with no tools: nothing is sandboxed")
    for name, tool in config.tools.items():
        if "@sha256:" not in tool.limits.image:
            logger.warning(
                "Sandboxed tool %r: image %r is not pinned by digest", name, tool.limits.image
            )
    return SandboxExecutor(
        sandbox,
        config.tools,
        max_concurrent=config.max_concurrent,
        queue_timeout_s=config.queue_timeout_seconds,
    )


def sandbox_tool_name(executor: SandboxExecutor | None, method: str, params: Any) -> str | None:
    """The sandboxed tool a ``tools/call`` names, else None. Such a call is
    executed by the sandbox and never forwarded upstream, even when an
    upstream exposes a tool of the same name."""
    if executor is None or method != "tools/call" or not isinstance(params, dict):
        return None
    name = params.get("name")
    return name if isinstance(name, str) and name in executor.tools else None


def with_sandbox_tools(response_data: Any, definitions: list[dict[str, Any]]) -> Any:
    """The upstream's ``tools/list`` *response_data* with the sandboxed tools
    added (replacing upstream tools of the same name). A response without a
    tool list (an error) is returned as it is."""
    if not definitions or not isinstance(response_data, dict):
        return response_data
    result = response_data.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return response_data
    names = {d["name"] for d in definitions}
    tools = [t for t in result["tools"] if not (isinstance(t, dict) and t.get("name") in names)]
    return {**response_data, "result": {**result, "tools": tools + definitions}}


def sandbox_error_response(body: Any, event_id: str, outcome: SandboxOutcome) -> tuple[int, dict]:
    """HTTP status and JSON-RPC error of a sandboxed call that did not run:
    400 (``-32602``) for invalid arguments, 503 (``-32603``) when the
    sandbox is unavailable or busy."""
    reason = _REASONS.get(outcome.error or "", "sandbox_unavailable")
    invalid = outcome.error == "invalid"
    return (
        400 if invalid else 503,
        {
            "jsonrpc": "2.0",
            "id": body.get("id") if isinstance(body, dict) else None,
            "error": {
                "code": -32602 if invalid else -32603,
                "message": (
                    f"Invalid arguments for sandboxed tool: {outcome.detail}"
                    if invalid
                    else "Sandboxed tool not executed: the execution sandbox is unavailable"
                ),
                "data": {"event_id": event_id, "reason": reason, "tool": outcome.tool},
            },
        },
    )


def sandbox_forensic_record(
    outcome: SandboxOutcome,
    *,
    event_id: str,
    agent_id: str,
    session_id: str,
    risk_level: Any,
) -> dict[str, Any]:
    """The second forensic record of a sandboxed call,
    ``<event_id>:sandbox``: what was executed and how it ended, as hashes
    and sizes (``checks.sandbox``)."""
    return {
        "event_id": f"{event_id}:sandbox",
        "event_type": EventType.SANDBOX_EXECUTION,
        "agent_id": agent_id,
        "session_id": session_id,
        "method": "tools/call",
        "action": "ALLOW" if outcome.ok else "ERROR",
        "risk_level": risk_level,
        "checks": {"sandbox": outcome.check},
    }


def bus_metadata(outcome: SandboxOutcome) -> dict[str, Any]:
    """The metadata of the ``sandbox_execution`` bus event: the summary of
    the forensic record, without the per-file entries."""
    check = outcome.check
    return {
        "provider": check.get("provider"),
        "tool": outcome.tool,
        "runtime": check.get("runtime"),
        "image_digest": check.get("image_digest"),
        "exit_code": check.get("exit_code"),
        "timed_out": check.get("timed_out"),
        "oom_killed": check.get("oom_killed"),
        "duration_ms": check.get("duration_ms"),
        "error": outcome.error,
    }


class SandboxMetrics:
    """The sandbox's part of ``/metrics``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.runs = 0
        self.timeouts = 0
        self.oom = 0
        self.errors = {"invalid": 0, "busy": 0, "unavailable": 0}
        self._duration = _Histogram(REQUEST_BUCKETS)

    def observe(self, outcome: SandboxOutcome) -> None:
        with self._lock:
            if outcome.error is not None:
                self.errors[outcome.error] = self.errors.get(outcome.error, 0) + 1
                return
            result = outcome.result
            if result is None:
                return
            self.runs += 1
            self.timeouts += int(result.timed_out)
            self.oom += int(result.oom_killed)
            self._duration.observe(result.duration_ms / 1000)

    def exposition(self, executor: SandboxExecutor) -> list[str]:
        """Prometheus text lines; *executor* gives the gauges."""
        ready = executor.health.get("ready")
        with self._lock:
            lines = [
                "# HELP admina_sandbox_runs_total Tool calls executed by the execution sandbox",
                "# TYPE admina_sandbox_runs_total counter",
                f"admina_sandbox_runs_total {self.runs}",
                "# HELP admina_sandbox_errors_total Sandboxed tool calls not executed, per reason",
                "# TYPE admina_sandbox_errors_total counter",
                *(
                    f'admina_sandbox_errors_total{{reason="{reason}"}} {count}'
                    for reason, count in sorted(self.errors.items())
                ),
                "# HELP admina_sandbox_timeouts_total Sandboxed executions stopped at their timeout",
                "# TYPE admina_sandbox_timeouts_total counter",
                f"admina_sandbox_timeouts_total {self.timeouts}",
                "# HELP admina_sandbox_oom_total Sandboxed executions that ran out of memory",
                "# TYPE admina_sandbox_oom_total counter",
                f"admina_sandbox_oom_total {self.oom}",
                "# HELP admina_sandbox_duration_seconds Duration of the sandboxed executions",
                "# TYPE admina_sandbox_duration_seconds histogram",
                *self._duration.lines(
                    "admina_sandbox_duration_seconds", f'provider="{executor.provider}"'
                ),
            ]
        lines += [
            "# HELP admina_sandbox_inflight Sandboxed executions running now",
            "# TYPE admina_sandbox_inflight gauge",
            f"admina_sandbox_inflight {executor.inflight}",
            "# HELP admina_sandbox_ready Whether the execution sandbox was ready at its last check",
            "# TYPE admina_sandbox_ready gauge",
            f"admina_sandbox_ready {1 if ready else 0}",
        ]
        return lines


def health_field(executor: SandboxExecutor | None) -> dict[str, Any] | None:
    """The ``sandbox`` field of ``/health``: None when the sandbox is off;
    else the provider's last health check (``ready``, ``detail``,
    ``runtime``) and the executions in flight."""
    if executor is None:
        return None
    health = executor.health
    return {
        "provider": executor.provider,
        "ready": health.get("ready"),
        "runtime": health.get("runtime"),
        "detail": health.get("detail", ""),
        "inflight": executor.inflight,
        "tools": sorted(executor.tools),
    }
