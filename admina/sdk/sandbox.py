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

"""Admina — execution sandbox for :class:`~admina.sdk.GovernedAgent`.

:func:`sandbox_upstream` builds the upstream callable of a
``GovernedAgent`` that executes the declared tools in an execution sandbox
(the same tool profiles as ``domains.agent_security.sandbox.tools``)::

    from admina.plugins.builtin.sandboxes.docker import DockerSandbox
    from admina.sdk import GovernedAgent
    from admina.sdk.sandbox import sandbox_upstream

    agent = GovernedAgent(
        upstream=sandbox_upstream(DockerSandbox(), {"python_exec": {"profile": "python"}})
    )
    response = await agent.call("tools/call", {"name": "python_exec",
                                               "arguments": {"code": "print(6 * 7)"}})

GovernedAgent runs its own checks (loop breaker, firewall, PII) before the
upstream is called; the sandbox then executes the call. A
``sandbox_execution`` event goes on the event bus; the SDK writes no
forensic record (the proxy's ``/mcp`` does).
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from admina.core.config import SandboxToolConfig, parse_sandbox_config
from admina.core.event_bus import EventType, GovernanceEvent, bus
from admina.core.types import SandboxRequestInvalid, SandboxUnavailable
from admina.domains.agent_security.sandbox import SandboxExecutor, call_tool_result

__all__ = ["sandbox_upstream"]

UpstreamCallable = Callable[..., Awaitable[dict]]


def _tools(
    tools: Mapping[str, SandboxToolConfig | Mapping[str, Any]],
) -> dict[str, SandboxToolConfig]:
    """*tools* as :class:`SandboxToolConfig`; mappings are read like
    admina.yaml's ``sandbox.tools`` entries.

    Raises:
        ValueError: an invalid entry (``network: egress`` among them).
    """
    ready = {name: tool for name, tool in tools.items() if isinstance(tool, SandboxToolConfig)}
    raw = {name: dict(tool) for name, tool in tools.items() if name not in ready}
    parsed = parse_sandbox_config({"tools": raw})
    if parsed.errors:
        raise ValueError("; ".join(parsed.errors))
    return {**parsed.tools, **ready}


def sandbox_upstream(
    sandbox: Any,
    tools: Mapping[str, SandboxToolConfig | Mapping[str, Any]],
    *,
    fallback: UpstreamCallable | None = None,
    max_concurrent: int = 4,
    queue_timeout_s: float = 5.0,
    audit: bool = True,
) -> UpstreamCallable:
    """An upstream callable ``(method, params, **kwargs)`` that executes
    the ``tools/call`` of *tools* in *sandbox*.

    Args:
        sandbox: An execution sandbox plugin (e.g. ``DockerSandbox()``).
        tools: The sandboxed tools, by name: ``SandboxToolConfig`` or
            mappings with the keys of ``sandbox.tools`` entries
            (``profile``, ``code_argument``, ``timeout_seconds``, …).
        fallback: Upstream of every other call; without one they raise
            ``ValueError``. A sandboxed tool never reaches it.
        max_concurrent: Executions at once in this process.
        queue_timeout_s: Wait for a free slot before a call is refused.
        audit: Emit a ``sandbox_execution`` event per call.

    Returns:
        The callable. A call that ran returns its MCP ``CallToolResult``;
        one that did not raises :class:`~admina.core.types.SandboxRequestInvalid`
        (its arguments) or :class:`~admina.core.types.SandboxUnavailable`.
        ``tools/list`` returns the fallback's tools (if any) with the
        sandboxed tools added.
    """
    executor = SandboxExecutor(
        sandbox,
        _tools(tools),
        max_concurrent=max_concurrent,
        queue_timeout_s=queue_timeout_s,
    )

    async def upstream(method: str, params: dict | None = None, **kwargs: Any) -> dict:
        params = params or {}
        name = params.get("name") if method == "tools/call" else None
        if isinstance(name, str) and name in executor.tools:
            outcome = await executor.run(
                name, params.get("arguments"), request_id=str(uuid.uuid4())
            )
            if audit:
                await bus.emit(
                    GovernanceEvent(
                        event_type=EventType.SANDBOX_EXECUTION,
                        session_id=kwargs.get("session_id"),
                        domain="agent-security",
                        action="ALLOW" if outcome.ok else "ERROR",
                        metadata={"sandbox": outcome.check},
                    )
                )
            if outcome.error == "invalid":
                raise SandboxRequestInvalid(outcome.detail)
            if not outcome.ok:
                raise SandboxUnavailable(f"sandboxed tool {name!r} not executed: {outcome.detail}")
            return call_tool_result(outcome.request, outcome.result)
        if method == "tools/list":
            listed = await fallback(method, params, **kwargs) if fallback else {"tools": []}
            definitions = executor.tool_definitions()
            names = {d["name"] for d in definitions}
            others = [t for t in listed.get("tools", []) if t.get("name") not in names]
            return {**listed, "tools": others + definitions}
        if fallback is None:
            raise ValueError(f"no upstream for {method!r} (only the sandboxed tools are served)")
        return await fallback(method, params, **kwargs)

    upstream.executor = executor  # type: ignore[attr-defined]
    return upstream
