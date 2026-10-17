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

"""FakeSandbox: an in-process execution_sandbox for tests (no container,
nothing is executed). Not a test module itself; listing ``_sandbox`` under
``plugins:`` registers it as the provider ``fake``."""

from __future__ import annotations

from typing import Any

from admina.core.types import (
    SandboxFile,
    SandboxRequest,
    SandboxResult,
    SandboxUnavailable,
)
from admina.plugins.base import BaseExecutionSandbox


class FakeSandbox(BaseExecutionSandbox):
    """Records each request and answers with a fixed result.

    Config keys: ``stdout``, ``stderr`` (text), ``exit_code``,
    ``timed_out``, ``oom_killed``, ``files`` ({path: text}), ``fail``
    (raise SandboxUnavailable), ``ready`` (health), ``capabilities``.
    """

    name = "fake"
    sandbox_name = "fake"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = dict(config or {})
        self.requests: list[SandboxRequest] = []
        self.reaped = 0
        self.closed = False

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(self.config.get("capabilities", ("network_none", "files")))

    async def run(self, request: SandboxRequest) -> SandboxResult:
        self.requests.append(request)
        if self.config.get("fail"):
            raise SandboxUnavailable("engine down: /var/run/docker.sock refused")
        timed_out = bool(self.config.get("timed_out"))
        return SandboxResult(
            exit_code=None if timed_out else int(self.config.get("exit_code", 0)),
            stdout=str(self.config.get("stdout", "ok")).encode(),
            stderr=str(self.config.get("stderr", "")).encode(),
            stdout_truncated=False,
            stderr_truncated=False,
            files=tuple(
                SandboxFile(path=path, content=text.encode())
                for path, text in (self.config.get("files") or {}).items()
            ),
            files_truncated=False,
            network_attempts=(),
            network_observed=False,
            duration_ms=12.5,
            timed_out=timed_out,
            oom_killed=bool(self.config.get("oom_killed")),
            runtime="fake/none",
            image_digest="sha256:" + "0" * 64,
        )

    async def health(self) -> dict:
        ready = self.config.get("ready", True)
        return {"ready": ready, "detail": "" if ready else "fake not ready", "runtime": "fake/none"}

    async def reap(self) -> int:
        self.reaped += 1
        return 0

    async def aclose(self) -> None:
        self.closed = True
