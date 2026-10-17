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

"""Execution sandbox: types, plugin type, request building, executor.

No container runs here: the provider is the in-process FakeSandbox.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json

import pytest
from _sandbox import FakeSandbox

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
from admina.domains.agent_security.sandbox import (
    SandboxExecutor,
    build_request,
    call_tool_result,
    check_request,
    safe_relative_path,
    sandbox_check,
    tool_definition,
)
from admina.plugins.base import BaseExecutionSandbox
from admina.plugins.registry import PLUGIN_TYPES, PluginRegistry

PYTHON = SandboxToolConfig(profile="python", files_argument="files")
SECRET = "print('the secret 4242')"


def _result(**overrides) -> SandboxResult:
    values = {
        "exit_code": 0,
        "stdout": b"hello",
        "stderr": b"",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "files": (),
        "files_truncated": False,
        "network_attempts": (),
        "network_observed": False,
        "duration_ms": 10.0,
        "timed_out": False,
        "oom_killed": False,
        "runtime": "docker/runc",
        "image_digest": "sha256:abc",
    }
    values.update(overrides)
    return SandboxResult(**values)


# ── Types and plugin type ────────────────────────────────────


def test_error_hierarchy():
    assert issubclass(SandboxUnavailable, SandboxError)
    assert issubclass(SandboxRequestInvalid, SandboxError)
    assert issubclass(SandboxRequestInvalid, ValueError)


def test_request_defaults_are_safe():
    request = SandboxRequest(command=("true",))
    assert request.network is SandboxNetwork.NONE
    assert dict(request.env) == {}
    assert request.files == ()
    assert request.limits == SandboxLimits()


def test_request_has_no_field_for_mounts_privileges_or_runtime():
    fields = set(SandboxRequest.__dataclass_fields__)
    for forbidden in ("mounts", "volumes", "privileged", "cap_add", "runtime", "user", "devices"):
        assert forbidden not in fields


def test_to_check_holds_hashes_and_sizes_never_content():
    result = _result(
        stdout=b"PII: mario.rossi@example.com",
        stderr=b"traceback",
        files=(SandboxFile("out/r.txt", b"secret data"),),
    )
    check = result.to_check()
    dumped = json.dumps(check)
    assert "mario.rossi" not in dumped and "secret data" not in dumped and "traceback" not in dumped
    assert check["stdout"] == {
        "bytes": len(result.stdout),
        "sha256": hashlib.sha256(result.stdout).hexdigest(),
        "truncated": False,
    }
    assert check["files_out"] == [
        {"path": "out/r.txt", "bytes": 11, "sha256": hashlib.sha256(b"secret data").hexdigest()}
    ]
    assert check["network"] == {"observed": False, "attempts": []}


def test_plugin_type_is_registered():
    assert PLUGIN_TYPES["execution_sandbox"] is BaseExecutionSandbox
    assert inspect.isabstract(BaseExecutionSandbox)
    assert inspect.iscoroutinefunction(BaseExecutionSandbox.run)


def test_builtin_docker_sandbox_is_discovered():
    from admina.plugins.builtin.sandboxes.docker import DockerSandbox

    registry = PluginRegistry()
    registry.discover(entry_point_group="")
    cls = registry.get("execution_sandbox", "docker")
    assert cls is not None and cls.__name__ == DockerSandbox.__name__


def test_fake_sandbox_registers_from_a_module_path():
    registry = PluginRegistry()
    registry.discover(extra_modules=["_sandbox"], entry_point_group="")
    assert registry.get("execution_sandbox", "fake") is not None


def test_abc_defaults():
    sandbox = FakeSandbox()
    assert asyncio.run(BaseExecutionSandbox.health(sandbox)) == {"ready": True, "detail": ""}
    assert asyncio.run(BaseExecutionSandbox.reap(sandbox)) == 0


# ── Paths and request checks ─────────────────────────────────


@pytest.mark.parametrize(
    "path, expected",
    [("main.py", "main.py"), ("./a/b.txt", "a/b.txt"), ("a//b", "a/b"), ("out", "out")],
)
def test_safe_relative_path_accepts(path, expected):
    assert safe_relative_path(path) == expected


@pytest.mark.parametrize(
    "path",
    ["", "/etc/passwd", "../x", "a/../../x", "a/..", ".", "a\\b", "a\x00b", "x" * 300, None, 3],
)
def test_safe_relative_path_refuses(path):
    with pytest.raises(SandboxRequestInvalid):
        safe_relative_path(path)


@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"command": ()},
        {"command": ("python", "a\x00")},
        {"command": ("true",), "env": {"BAD-NAME": "x"}},
        {"command": ("true",), "env": {"OK": "a\x00b"}},
        {"command": ("true",), "image": "--privileged"},
        {"command": ("true",), "image": "img with space"},
        {"command": ("true",), "files": (SandboxFile("a", b"1"), SandboxFile("./a", b"2"))},
        {"command": ("true",), "files": (SandboxFile("../a", b"1"),)},
        {"command": ("true",), "collect": ("/etc",)},
        {"command": ("true",), "limits": SandboxLimits(timeout_s=0)},
        {"command": ("true",), "limits": SandboxLimits(pids=0)},
        {
            "command": ("true",),
            "files": (SandboxFile("a", b"x" * 11),),
            "limits": SandboxLimits(files_max_bytes=10),
        },
    ],
)
def test_check_request_refuses(request_kwargs):
    with pytest.raises(SandboxRequestInvalid):
        check_request(SandboxRequest(**request_kwargs))


def test_check_request_accepts_a_plain_request():
    check_request(
        SandboxRequest(
            command=("python", "-I", "/work/main.py"),
            files=(SandboxFile("main.py", b"print(1)"),),
            env={"LANG": "C.UTF-8"},
        )
    )


# ── Tool profiles ────────────────────────────────────────────


def test_python_profile():
    tool = SandboxToolConfig(
        profile="python",
        limits=SandboxLimitsConfig(image="img@sha256:" + "1" * 64, timeout_seconds=7, memory_mb=99),
    )
    request = build_request(tool, {"code": "print(1)"}, request_id="ev-1")
    assert request.command == ("python", "-I", "/work/main.py")
    assert request.files == (SandboxFile("main.py", b"print(1)"),)
    assert request.image == "img@sha256:" + "1" * 64
    assert request.limits.timeout_s == 7 and request.limits.memory_mb == 99
    assert request.network is SandboxNetwork.NONE
    assert dict(request.env) == {}
    assert request.request_id == "ev-1"


def test_shell_profile_never_uses_sh_c():
    request = build_request(SandboxToolConfig(profile="shell"), {"code": "echo hi"})
    assert request.command == ("sh", "/work/main.sh")
    assert "-c" not in request.command
    assert request.files[0] == SandboxFile("main.sh", b"echo hi")


def test_custom_code_argument():
    tool = SandboxToolConfig(code_argument="source")
    assert build_request(tool, {"source": "x=1"}).files[0].content == b"x=1"
    with pytest.raises(SandboxRequestInvalid, match="source"):
        build_request(tool, {"code": "x=1"})


def test_input_files_text_and_base64():
    request = build_request(
        PYTHON,
        {
            "code": "pass",
            "files": [
                {"path": "data/a.csv", "content": "a,b"},
                {"path": "img.bin", "content_b64": base64.b64encode(b"\x00\x01").decode()},
            ],
        },
    )
    assert request.files[1:] == (
        SandboxFile("data/a.csv", b"a,b"),
        SandboxFile("img.bin", b"\x00\x01"),
    )


@pytest.mark.parametrize(
    "arguments",
    [
        None,
        "code",
        {"code": 1},
        {"code": "x", "files": "nope"},
        {"code": "x", "files": [{"path": "../evil", "content": "x"}]},
        {"code": "x", "files": [{"path": "/etc/passwd", "content": "x"}]},
        {"code": "x", "files": [{"path": "main.py", "content": "x"}]},
        {"code": "x", "files": [{"path": "a", "content_b64": "%%%"}]},
        {"code": "x", "files": [{"path": "a"}]},
    ],
)
def test_invalid_arguments(arguments):
    with pytest.raises(SandboxRequestInvalid):
        build_request(PYTHON, arguments)


def test_files_ignored_without_files_argument():
    tool = SandboxToolConfig()
    request = build_request(tool, {"code": "x", "files": [{"path": "../evil", "content": "x"}]})
    assert [f.path for f in request.files] == ["main.py"]


def test_tool_definition_default_schema():
    definition = tool_definition("python_exec", PYTHON)
    assert definition["name"] == "python_exec"
    assert definition["inputSchema"]["required"] == ["code"]
    assert set(definition["inputSchema"]["properties"]) == {"code", "files"}
    assert "network" in definition["description"]


def test_tool_definition_from_config():
    schema = {"type": "object", "properties": {"code": {"type": "string"}}}
    tool = SandboxToolConfig(description="Run it", input_schema=schema)
    assert tool_definition("t", tool) == {
        "name": "t",
        "description": "Run it",
        "inputSchema": schema,
    }


# ── CallToolResult and checks.sandbox ────────────────────────


def test_call_tool_result_success():
    request = build_request(PYTHON, {"code": "print(1)"})
    result = _result(
        stdout=b"1\n",
        files=(SandboxFile("out/r.txt", b"res"), SandboxFile("out/p.png", b"\x89PNG\xff")),
    )
    payload = call_tool_result(request, result)
    assert payload["isError"] is False
    assert payload["content"][0] == {"type": "text", "text": "1\n"}
    text_file, binary_file = payload["content"][1]["resource"], payload["content"][2]["resource"]
    assert text_file == {
        "uri": "sandbox:///work/out/r.txt",
        "mimeType": "text/plain",
        "text": "res",
    }
    assert base64.b64decode(binary_file["blob"]) == b"\x89PNG\xff"
    assert payload["structuredContent"]["exit_code"] == 0
    assert payload["structuredContent"]["files"] == [
        {"path": "out/r.txt", "bytes": 3},
        {"path": "out/p.png", "bytes": 5},
    ]


@pytest.mark.parametrize(
    "overrides, marker",
    [
        ({"exit_code": 1, "stderr": b"Traceback"}, "[stderr]"),
        ({"exit_code": None, "timed_out": True}, "time limit"),
        ({"exit_code": 137, "oom_killed": True}, "memory limit"),
    ],
)
def test_call_tool_result_errors(overrides, marker):
    request = build_request(PYTHON, {"code": "x"})
    payload = call_tool_result(request, _result(**overrides))
    assert payload["isError"] is True
    assert any(marker in block.get("text", "") for block in payload["content"])


def test_sandbox_check_describes_input_by_hash():
    request = build_request(PYTHON, {"code": SECRET})
    check = sandbox_check(provider="docker", tool="python_exec", request=request, result=_result())
    dumped = json.dumps(check)
    assert "4242" not in dumped
    assert check["input"]["files"] == [
        {
            "path": "main.py",
            "bytes": len(SECRET),
            "sha256": hashlib.sha256(SECRET.encode()).hexdigest(),
        }
    ]
    assert check["network"] == {"mode": "none", "observed": False, "attempts": []}
    assert check["limits"]["timeout_s"] == 30.0
    assert check["error"] is None and check["exit_code"] == 0


# ── Executor ─────────────────────────────────────────────────


def _executor(sandbox=None, **kwargs) -> SandboxExecutor:
    return SandboxExecutor(sandbox or FakeSandbox(), {"python_exec": PYTHON}, **kwargs)


def test_executor_runs_the_tool():
    sandbox = FakeSandbox({"stdout": "42"})
    outcome = asyncio.run(
        _executor(sandbox).run("python_exec", {"code": "print(42)"}, request_id="e")
    )
    assert outcome.ok and outcome.result.stdout == b"42"
    assert sandbox.requests[0].files[0].content == b"print(42)"
    assert outcome.check["provider"] == "fake" and outcome.check["tool"] == "python_exec"


def test_executor_refuses_invalid_arguments_without_running():
    sandbox = FakeSandbox()
    outcome = asyncio.run(_executor(sandbox).run("python_exec", {"code": 1}))
    assert outcome.error == "invalid" and not outcome.ok
    assert sandbox.requests == []
    assert outcome.check["error"] == "invalid"


def test_executor_turns_provider_failures_into_errors():
    outcome = asyncio.run(_executor(FakeSandbox({"fail": True})).run("python_exec", {"code": "x"}))
    assert outcome.error == "unavailable"
    # The runtime's message stays in the logs.
    assert "docker.sock" not in outcome.detail


class _Broken(FakeSandbox):
    async def run(self, request):
        raise KeyError("outside the contract")


def test_executor_contains_exceptions_outside_the_contract():
    outcome = asyncio.run(_executor(_Broken()).run("python_exec", {"code": "x"}))
    assert outcome.error == "unavailable"


class _Slow(FakeSandbox):
    async def run(self, request):
        await asyncio.sleep(0.2)
        return await super().run(request)


def test_executor_concurrency_limit_and_queue_timeout():
    executor = _executor(_Slow(), max_concurrent=1, queue_timeout_s=0.05)

    async def go():
        return await asyncio.gather(
            executor.run("python_exec", {"code": "a"}),
            executor.run("python_exec", {"code": "b"}),
        )

    first, second = asyncio.run(go())
    assert {first.error, second.error} == {"busy", None}
    assert executor.inflight == 0


def test_executor_waits_for_a_free_slot():
    executor = _executor(_Slow(), max_concurrent=1, queue_timeout_s=2)

    async def go():
        return await asyncio.gather(
            executor.run("python_exec", {"code": "a"}),
            executor.run("python_exec", {"code": "b"}),
        )

    assert all(outcome.ok for outcome in asyncio.run(go()))


def test_executor_refuses_a_provider_without_the_needed_capabilities():
    with pytest.raises(SandboxUnavailable, match="files"):
        _executor(FakeSandbox({"capabilities": ["network_none"]}))


def test_executor_health_is_cached_and_failures_are_not_ready():
    executor = _executor(FakeSandbox({"ready": False}))
    assert executor.health["ready"] is None
    status = asyncio.run(executor.check_health())
    assert status["ready"] is False and executor.health is status

    class _Raising(FakeSandbox):
        async def health(self):
            raise OSError("boom")

        async def reap(self):
            raise OSError("boom")

    raising = _executor(_Raising())
    assert asyncio.run(raising.check_health())["ready"] is False
    assert asyncio.run(raising.reap()) == 0
