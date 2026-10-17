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

"""Admina — execution sandbox: from a tool call to a sandboxed execution.

The parts shared by ``/mcp`` and the SDK (:mod:`admina.sdk.sandbox`):

- :func:`build_request` maps the arguments of a sandboxed tool
  (``domains.agent_security.sandbox.tools``) to a
  :class:`~admina.core.types.SandboxRequest` through its profile;
- :func:`check_request` refuses what no provider may execute (paths outside
  /work, sizes over the limits, malformed environment variables), before
  anything runs; providers call it too;
- :func:`call_tool_result` turns a result into an MCP ``CallToolResult``;
- :func:`sandbox_check` is the ``checks.sandbox`` of the forensic record:
  sizes and hashes, never the content;
- :class:`SandboxExecutor` runs a tool in the provider under a concurrency
  limit, and never runs anything outside it: every failure is an outcome
  with an error, not a fallback.

Nothing here decides whether a call is allowed: the governance pipeline
has already allowed it.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import mimetypes
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from admina.core.config import SandboxLimitsConfig, SandboxToolConfig
from admina.core.types import (
    SandboxError,
    SandboxFile,
    SandboxLimits,
    SandboxNetwork,
    SandboxRequest,
    SandboxRequestInvalid,
    SandboxResult,
    SandboxUnavailable,
)

__all__ = [
    "PROFILES",
    "SandboxExecutor",
    "SandboxOutcome",
    "build_request",
    "call_tool_result",
    "check_request",
    "limits_of",
    "safe_relative_path",
    "sandbox_check",
    "tool_definition",
]

logger = logging.getLogger("admina.sandbox")

#: Profile → (command, file the code is written to, under /work).
PROFILES: dict[str, tuple[tuple[str, ...], str]] = {
    "python": (("python", "-I", "/work/main.py"), "main.py"),
    "shell": (("sh", "/work/main.sh"), "main.sh"),
}

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_PATH = 255
_MAX_FILES = 256
_MAX_ENV = 64


def safe_relative_path(path: Any) -> str:
    """*path* as a normalised path relative to /work.

    Raises:
        SandboxRequestInvalid: not a string, empty, absolute, with ``..``,
            a NUL or a backslash, or longer than 255 characters.
    """
    if not isinstance(path, str) or not path:
        raise SandboxRequestInvalid("a file path must be a non-empty string")
    if "\x00" in path or "\\" in path:
        raise SandboxRequestInvalid(f"file path {path!r}: NUL and backslash are not allowed")
    if path.startswith("/"):
        raise SandboxRequestInvalid(f"file path {path!r} must be relative to /work")
    parts = [part for part in PurePosixPath(path).parts if part != "."]
    if not parts or ".." in parts:
        raise SandboxRequestInvalid(f"file path {path!r} must stay under /work")
    normalised = "/".join(parts)
    if len(normalised) > _MAX_PATH:
        raise SandboxRequestInvalid(f"file path longer than {_MAX_PATH} characters")
    return normalised


def check_request(request: SandboxRequest) -> None:
    """Refuse *request* if no provider may execute it.

    Raises:
        SandboxRequestInvalid: what is wrong with it.
    """
    command = request.command
    if not command or not all(isinstance(arg, str) and "\x00" not in arg for arg in command):
        raise SandboxRequestInvalid("the command must be a non-empty list of strings")
    image = request.image
    if image is not None and (
        not image or image.startswith("-") or any(c.isspace() for c in image)
    ):
        raise SandboxRequestInvalid("the image must be an image reference")
    if len(request.env) > _MAX_ENV:
        raise SandboxRequestInvalid(f"at most {_MAX_ENV} environment variables")
    for name, value in request.env.items():
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            raise SandboxRequestInvalid(f"environment variable name {name!r} is not valid")
        if not isinstance(value, str) or "\x00" in value:
            raise SandboxRequestInvalid(f"environment variable {name}: the value must be a string")
    limits = request.limits
    for key in ("timeout_s", "memory_mb", "cpus", "pids", "disk_mb"):
        if not getattr(limits, key) > 0:
            raise SandboxRequestInvalid(f"limit {key} must be greater than 0")
    if limits.output_max_bytes < 0 or limits.files_max_bytes < 0:
        raise SandboxRequestInvalid("the output limits must not be negative")
    if len(request.files) > _MAX_FILES:
        raise SandboxRequestInvalid(f"at most {_MAX_FILES} input files")
    seen: set[str] = set()
    total = 0
    for item in request.files:
        path = safe_relative_path(item.path)
        if path in seen:
            raise SandboxRequestInvalid(f"file {path!r} given twice")
        seen.add(path)
        total += len(item.content)
    if total > limits.files_max_bytes:
        raise SandboxRequestInvalid(
            f"input files of {total} bytes exceed the limit of {limits.files_max_bytes}"
        )
    if len(request.stdin) > limits.files_max_bytes:
        raise SandboxRequestInvalid("stdin exceeds the files limit")
    for directory in request.collect:
        safe_relative_path(directory)


def limits_of(config: SandboxLimitsConfig) -> SandboxLimits:
    """The :class:`SandboxLimits` of a tool's configured limits."""
    return SandboxLimits(
        timeout_s=config.timeout_seconds,
        memory_mb=config.memory_mb,
        cpus=config.cpus,
        pids=config.pids,
        disk_mb=config.disk_mb,
        output_max_bytes=config.output_max_bytes,
        files_max_bytes=config.files_max_bytes,
    )


def _input_files(tool: SandboxToolConfig, arguments: Mapping[str, Any]) -> list[SandboxFile]:
    """The extra input files of the call (``files_argument``)."""
    if not tool.files_argument:
        return []
    raw = arguments.get(tool.files_argument)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise SandboxRequestInvalid(f"argument {tool.files_argument!r} must be a list of files")
    files = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            raise SandboxRequestInvalid("each file must be an object with a path")
        path = safe_relative_path(entry.get("path"))
        if "content_b64" in entry:
            try:
                content = base64.b64decode(str(entry["content_b64"]), validate=True)
            except (binascii.Error, ValueError):
                raise SandboxRequestInvalid(f"file {path!r}: content_b64 is not base64") from None
        elif isinstance(entry.get("content"), str):
            content = entry["content"].encode("utf-8")
        else:
            raise SandboxRequestInvalid(f"file {path!r} needs content or content_b64")
        files.append(SandboxFile(path=path, content=content))
    return files


def build_request(
    tool: SandboxToolConfig, arguments: Any, *, request_id: str = ""
) -> SandboxRequest:
    """The execution of a call of *tool* with *arguments*: the code is
    written to the profile's file, the command is the profile's, the image
    and limits are the tool's. The environment is empty.

    Raises:
        SandboxRequestInvalid: the arguments do not fit the tool.
    """
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, Mapping):
        raise SandboxRequestInvalid("the tool arguments must be an object")
    code = arguments.get(tool.code_argument)
    if not isinstance(code, str):
        raise SandboxRequestInvalid(f"argument {tool.code_argument!r} must be a string")
    command, main_file = PROFILES[tool.profile]
    files = [SandboxFile(path=main_file, content=code.encode("utf-8"))]
    for extra in _input_files(tool, arguments):
        if extra.path == main_file:
            raise SandboxRequestInvalid(f"file {main_file!r} is the code of the call")
        files.append(extra)
    request = SandboxRequest(
        command=command,
        files=tuple(files),
        image=tool.limits.image,
        limits=limits_of(tool.limits),
        network=SandboxNetwork(tool.limits.network),
        request_id=request_id,
    )
    check_request(request)
    return request


def tool_definition(name: str, tool: SandboxToolConfig) -> dict[str, Any]:
    """The ``tools/list`` entry of *tool*: its ``input_schema`` from
    admina.yaml, else one built from its arguments."""
    schema = tool.input_schema
    if schema is None:
        language = "Python" if tool.profile == "python" else "POSIX shell"
        properties: dict[str, Any] = {
            tool.code_argument: {"type": "string", "description": f"{language} code to run"}
        }
        if tool.files_argument:
            properties[tool.files_argument] = {
                "type": "array",
                "description": "Input files, written under the working directory",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                        "content_b64": {"type": "string"},
                    },
                    "required": ["path"],
                },
            }
        schema = {"type": "object", "properties": properties, "required": [tool.code_argument]}
    description = tool.description or (
        f"Runs {'Python' if tool.profile == 'python' else 'shell'} code in an isolated "
        "sandbox without network access. Files written to out/ are returned."
    )
    return {"name": name, "description": description, "inputSchema": schema}


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def call_tool_result(request: SandboxRequest, result: SandboxResult) -> dict[str, Any]:
    """The MCP ``CallToolResult`` of *result*: stdout as text, stderr as a
    second text block, the output files as embedded resources, the exit
    status in ``structuredContent``. ``isError`` when the command exited
    non-zero, ran out of time or of memory."""
    content: list[dict[str, Any]] = [{"type": "text", "text": _text(result.stdout)}]
    if result.stderr:
        content.append({"type": "text", "text": "[stderr]\n" + _text(result.stderr)})
    if result.timed_out:
        content.append(
            {
                "type": "text",
                "text": f"[sandbox] stopped: time limit of {request.limits.timeout_s:g} s reached",
            }
        )
    if result.oom_killed:
        content.append(
            {
                "type": "text",
                "text": f"[sandbox] stopped: memory limit of {request.limits.memory_mb} MB reached",
            }
        )
    for item in result.files:
        resource: dict[str, Any] = {
            "uri": f"sandbox:///work/{item.path}",
            "mimeType": mimetypes.guess_type(item.path)[0] or "application/octet-stream",
        }
        try:
            resource["text"] = item.content.decode("utf-8")
        except UnicodeDecodeError:
            resource["blob"] = base64.b64encode(item.content).decode("ascii")
        content.append({"type": "resource", "resource": resource})
    return {
        "content": content,
        "isError": bool(result.exit_code != 0 or result.timed_out or result.oom_killed),
        "structuredContent": {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "oom_killed": result.oom_killed,
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "files": [{"path": f.path, "bytes": len(f.content)} for f in result.files],
            "files_truncated": result.files_truncated,
            "duration_ms": round(result.duration_ms, 1),
        },
    }


def _digest(data: bytes) -> dict[str, Any]:
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def sandbox_check(
    *,
    provider: str,
    tool: str,
    request: SandboxRequest | None,
    result: SandboxResult | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """``checks.sandbox`` of the forensic record of an execution: what was
    executed (hashes and sizes of the command and of the input files), with
    which limits, and how it ended. Never the content of the code, of the
    files or of the output. *error* names why nothing ran (``unavailable``,
    ``busy``, ``invalid``)."""
    check: dict[str, Any] = {"provider": provider, "tool": tool}
    if request is not None:
        limits = request.limits
        check["limits"] = {
            "timeout_s": limits.timeout_s,
            "memory_mb": limits.memory_mb,
            "cpus": limits.cpus,
            "pids": limits.pids,
            "disk_mb": limits.disk_mb,
        }
        check["input"] = {
            "command_sha256": hashlib.sha256("\x00".join(request.command).encode()).hexdigest(),
            "stdin": _digest(request.stdin),
            "files": [{"path": f.path, **_digest(f.content)} for f in request.files],
        }
        check["network"] = {"mode": request.network.value}
    if result is not None:
        summary = result.to_check()
        check["network"] = {**check.get("network", {}), **summary.pop("network")}
        check.update(summary)
    check["error"] = error
    return check


class _Slots:
    """A concurrency limit shared by every event loop of the process (the
    proxy's and those of the SDK): a counter behind a threading lock, waited
    on by polling, so no object bound to one event loop is kept."""

    _POLL_S = 0.01

    def __init__(self, size: int) -> None:
        self._size = size
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    def _try_acquire(self) -> bool:
        with self._lock:
            if self._used < self._size:
                self._used += 1
                return True
            return False

    async def acquire(self, timeout_s: float) -> bool:
        """Take a slot, waiting at most *timeout_s*; False if none freed."""
        deadline = time.monotonic() + timeout_s
        while not self._try_acquire():
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(self._POLL_S)
        return True

    def release(self) -> None:
        with self._lock:
            self._used = max(self._used - 1, 0)


@dataclass
class SandboxOutcome:
    """How a sandboxed tool call ended: a *result*, or an *error* (nothing
    was executed, or the environment failed) with a *detail* that can be
    shown to the caller."""

    tool: str
    request: SandboxRequest | None
    result: SandboxResult | None
    #: None, or ``invalid`` (the arguments), ``busy`` (no free slot within
    #: the queue timeout) or ``unavailable`` (the provider failed).
    error: str | None
    detail: str
    check: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None and self.result is not None


# Capabilities every request of a sandboxed tool needs.
_REQUIRED_CAPABILITIES = frozenset({"network_none", "files"})


class SandboxExecutor:
    """Runs the sandboxed tools of a configuration in one provider.

    Args:
        sandbox: The :class:`~admina.plugins.base.BaseExecutionSandbox`.
        tools: The sandboxed tools, by name.
        max_concurrent: Executions at once, across every event loop.
        queue_timeout_s: How long a call waits for a free slot before it is
            refused.

    Raises:
        SandboxUnavailable: the provider lacks a capability the tools need
            (no request would ever run as configured).
    """

    def __init__(
        self,
        sandbox: Any,
        tools: Mapping[str, SandboxToolConfig],
        *,
        max_concurrent: int = 4,
        queue_timeout_s: float = 5.0,
    ) -> None:
        missing = _REQUIRED_CAPABILITIES - frozenset(sandbox.capabilities)
        if missing:
            raise SandboxUnavailable(
                f"sandbox {sandbox.sandbox_name!r} lacks {', '.join(sorted(missing))}"
            )
        self.sandbox = sandbox
        self.tools = dict(tools)
        self.queue_timeout_s = queue_timeout_s
        self._slots = _Slots(max_concurrent)
        self.health: dict[str, Any] = {"ready": None, "detail": "not checked yet"}

    @property
    def provider(self) -> str:
        return str(self.sandbox.sandbox_name)

    @property
    def inflight(self) -> int:
        return self._slots.used

    def tool_definitions(self) -> list[dict[str, Any]]:
        """The ``tools/list`` entries of the sandboxed tools."""
        return [tool_definition(name, tool) for name, tool in self.tools.items()]

    def _outcome(
        self,
        tool: str,
        request: SandboxRequest | None,
        *,
        result: SandboxResult | None = None,
        error: str | None = None,
        detail: str = "",
    ) -> SandboxOutcome:
        return SandboxOutcome(
            tool=tool,
            request=request,
            result=result,
            error=error,
            detail=detail,
            check=sandbox_check(
                provider=self.provider, tool=tool, request=request, result=result, error=error
            ),
        )

    async def run(self, tool: str, arguments: Any, *, request_id: str = "") -> SandboxOutcome:
        """Execute a call of the sandboxed *tool* with *arguments*.

        Never raises for a failure of the call: an invalid argument, a full
        queue and a failing provider are outcomes with an error, and
        nothing is executed outside the sandbox in any of them.
        """
        try:
            request = build_request(self.tools[tool], arguments, request_id=request_id)
        except SandboxRequestInvalid as exc:
            return self._outcome(tool, None, error="invalid", detail=str(exc))
        if not await self._slots.acquire(self.queue_timeout_s):
            logger.warning("Sandbox busy: call %s of %r refused", request_id, tool)
            return self._outcome(
                tool, request, error="busy", detail="no sandbox slot free within the queue timeout"
            )
        try:
            result = await self.sandbox.run(request)
        except SandboxRequestInvalid as exc:
            return self._outcome(tool, request, error="invalid", detail=str(exc))
        except SandboxError as exc:
            # The message can quote the runtime's output: the logs only.
            logger.error("Sandbox %r failed for call %s: %s", self.provider, request_id, exc)
            return self._outcome(
                tool, request, error="unavailable", detail="the sandbox could not run the call"
            )
        except Exception as exc:  # noqa: BLE001 — provider outside its contract: refused, never run elsewhere
            logger.error(
                "Sandbox %r raised %s for call %s", self.provider, type(exc).__name__, request_id
            )
            return self._outcome(
                tool, request, error="unavailable", detail="the sandbox could not run the call"
            )
        finally:
            self._slots.release()
        return self._outcome(tool, request, result=result)

    async def check_health(self, timeout_s: float = 15.0) -> dict[str, Any]:
        """Ask the provider whether it is ready; the answer is kept in
        :attr:`health` (``/health`` reads it, without calling the provider)."""
        images = tuple(sorted({tool.limits.image for tool in self.tools.values()}))
        try:
            try:
                check = self.sandbox.health(images=images)
            except TypeError:  # a provider whose health() takes no images
                check = self.sandbox.health()
            status = dict(await asyncio.wait_for(check, timeout_s))
        except Exception as exc:  # noqa: BLE001 — a failing check is "not ready"
            status = {"ready": False, "detail": f"health check failed ({type(exc).__name__})"}
        status["ready"] = bool(status.get("ready"))
        self.health = status
        return status

    async def reap(self, timeout_s: float = 30.0) -> int:
        """Remove what crashed executions left behind; 0 when it fails or
        takes longer than *timeout_s* (retried at the next interval)."""
        try:
            return int(await asyncio.wait_for(self.sandbox.reap(), timeout_s))
        except Exception as exc:  # noqa: BLE001 — retried at the next interval
            logger.warning("Sandbox %r: reaping failed (%s)", self.provider, type(exc).__name__)
            return 0
