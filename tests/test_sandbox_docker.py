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

"""DockerSandbox against a real engine: containment regressions.

Marked ``docker``: they need a reachable Docker engine and the pinned
default image (``docker pull <SANDBOX_DEFAULT_IMAGE>``), and are skipped
otherwise. Run with ``pytest -m docker``.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import time

import pytest

from admina.core.config import SANDBOX_DEFAULT_IMAGE, SandboxLimitsConfig, SandboxToolConfig
from admina.core.types import SandboxFile, SandboxLimits, SandboxRequest
from admina.domains.agent_security.sandbox import SandboxExecutor, build_request
from admina.plugins.builtin.sandboxes.docker import SANDBOX_LABEL, DockerSandbox


def _engine_ready() -> str:
    """Why the tests cannot run, or "" when they can."""
    if shutil.which("docker") is None:
        return "docker CLI not installed"
    try:
        info = subprocess.run(["docker", "info"], capture_output=True, timeout=20)
        if info.returncode != 0:
            return "Docker engine not reachable"
        image = subprocess.run(
            ["docker", "image", "inspect", SANDBOX_DEFAULT_IMAGE], capture_output=True, timeout=20
        )
    except (OSError, subprocess.TimeoutExpired):
        return "Docker engine not reachable"
    if image.returncode != 0:
        return f"sandbox image not pulled: docker pull {SANDBOX_DEFAULT_IMAGE}"
    return ""


_SKIP = _engine_ready()
pytestmark = [pytest.mark.docker, pytest.mark.skipif(bool(_SKIP), reason=_SKIP or "ready")]


def _labelled() -> list[str]:
    out = subprocess.run(
        ["docker", "ps", "--all", "--quiet", "--filter", f"label={SANDBOX_LABEL}=1"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return out.split()


@pytest.fixture(scope="module", autouse=True)
def _no_leftovers():
    yield
    assert _labelled() == [], "sandbox containers left behind"


def _python(code: str, **limits) -> SandboxRequest:
    tool = SandboxToolConfig(profile="python", limits=SandboxLimitsConfig(**limits))
    return build_request(tool, {"code": code}, request_id="test")


def _run(request: SandboxRequest, sandbox: DockerSandbox | None = None):
    return asyncio.run((sandbox or DockerSandbox()).run(request))


def test_runs_python_and_returns_output_files():
    request = _python(
        "import os\n"
        "print(open('data/in.txt').read().upper())\n"
        "open('out/result.txt', 'w').write('done')\n"
    )
    request = SandboxRequest(
        **{**request.__dict__, "files": (*request.files, SandboxFile("data/in.txt", b"hello"))}
    )
    result = _run(request)
    assert result.exit_code == 0, result.stderr
    assert result.stdout == b"HELLO\n"
    assert result.files == (SandboxFile("out/result.txt", b"done"),)
    assert result.image_digest.startswith("sha256:")
    assert result.runtime == "docker/default"


def test_shell_profile():
    tool = SandboxToolConfig(profile="shell")
    result = _run(build_request(tool, {"code": "echo $((6 * 7))"}))
    assert result.stdout == b"42\n"


def test_unprivileged_user_and_no_capabilities():
    result = _run(
        _python(
            "import os\n"
            "print(os.getuid(), os.getgid())\n"
            "print([l.split()[1] for l in open('/proc/self/status') if l.startswith('CapEff')][0])\n"
        )
    )
    uid_gid, cap_eff = result.stdout.decode().split("\n")[:2]
    assert uid_gid == "65534 65534"
    assert int(cap_eff, 16) == 0


def test_root_filesystem_is_read_only():
    result = _run(_python("open('/etc/admina', 'w')"))
    assert result.exit_code != 0
    assert b"Read-only file system" in result.stderr or b"Permission denied" in result.stderr


def test_no_network():
    result = _run(
        _python(
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 53), timeout=3)\n"
            "    print('connected')\n"
            "except OSError as exc:\n"
            "    print('refused', exc.errno)\n"
            "print([n for n in socket.if_nameindex()])\n"
        )
    )
    assert b"refused" in result.stdout and b"connected" not in result.stdout
    assert b"eth0" not in result.stdout


def test_proxy_environment_does_not_reach_the_container(monkeypatch):
    monkeypatch.setenv("ADMINA_API_KEY", "proxy-secret-value")
    result = _run(_python("import os; print(sorted(os.environ))"))
    assert b"ADMINA_API_KEY" not in result.stdout
    assert b"proxy-secret-value" not in result.stdout


def test_timeout_kills_and_removes_the_container():
    started = time.monotonic()
    result = _run(_python("import time; time.sleep(30)", timeout_seconds=2))
    assert result.timed_out is True and result.exit_code is None
    assert time.monotonic() - started < 20
    assert _labelled() == []


def test_memory_limit():
    result = _run(_python("x = bytearray(512 * 1024 * 1024)", memory_mb=64))
    assert result.oom_killed is True
    assert result.exit_code != 0


def test_process_limit_contains_a_fork_bomb():
    code = (
        "import os, time\n"
        "n = 0\n"
        "try:\n"
        "    for _ in range(500):\n"
        "        if os.fork() == 0:\n"
        "            time.sleep(3); os._exit(0)\n"
        "        n += 1\n"
        "except OSError:\n"
        "    pass\n"
        "print(n)\n"
    )
    result = _run(_python(code, pids=32, timeout_seconds=20))
    assert result.exit_code == 0, result.stderr
    assert int(result.stdout) < 32


def test_output_is_truncated_at_the_limit():
    result = _run(_python("print('x' * 1_000_000)", output_max_bytes=1000))
    assert len(result.stdout) == 1000 and result.stdout_truncated is True


def test_work_directory_size_is_limited():
    code = "open('big', 'wb').write(b'0' * (20 * 1024 * 1024))"
    result = _run(_python(code, disk_mb=4))
    assert result.exit_code != 0
    assert b"No space left" in result.stderr


def test_stdin():
    request = SandboxRequest(
        command=("python", "-I", "-c", "import sys; print(sys.stdin.read()[::-1])"),
        stdin=b"abc",
        limits=SandboxLimits(),
    )
    assert _run(request).stdout == b"cba\n"


def test_concurrent_runs_through_the_executor():
    executor = SandboxExecutor(
        DockerSandbox(), {"py": SandboxToolConfig()}, max_concurrent=2, queue_timeout_s=60
    )

    async def go():
        return await asyncio.gather(
            *(executor.run("py", {"code": f"print({i})"}) for i in range(3))
        )

    outcomes = asyncio.run(go())
    assert sorted(o.result.stdout for o in outcomes) == [b"0\n", b"1\n", b"2\n"]


def test_health_and_reap_of_orphans():
    sandbox = DockerSandbox({"orphan_age_seconds": 60})
    assert asyncio.run(sandbox.health())["ready"] is True
    subprocess.run(
        [
            "docker",
            "run",
            "--detach",
            "--label",
            f"{SANDBOX_LABEL}=1",
            "--label",
            "admina.created=1",
            "--network",
            "none",
            "--entrypoint",
            "sleep",
            SANDBOX_DEFAULT_IMAGE,
            "infinity",
        ],
        capture_output=True,
        check=True,
    )
    assert asyncio.run(sandbox.reap()) == 1
    assert _labelled() == []


def test_runsc_not_registered_is_not_ready():
    info = subprocess.run(
        ["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True
    )
    if '"runsc"' in info.stdout:
        pytest.skip("runsc is registered on this engine")
    status = asyncio.run(DockerSandbox({"runtime": "runsc"}).health())
    assert status["ready"] is False and "runsc" in status["detail"]


def test_mcp_tool_call_end_to_end(monkeypatch, tmp_path):
    import httpx
    from _proxy_app import API_KEY, isolate, serve, with_key

    from admina.core.config import load_config
    from admina.proxy import main as proxy_main

    isolate(monkeypatch)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    path = tmp_path / "admina.yaml"
    path.write_text(
        "schema_version: 1\n"
        "domains:\n"
        "  agent_security:\n"
        "    sandbox:\n"
        "      enabled: true\n"
        "      tools:\n"
        "        python_exec: {timeout_seconds: 10}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(proxy_main, "_admina_config", load_config(path))
    forwarded: list = []

    def upstream(request: httpx.Request) -> httpx.Response:
        forwarded.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    call = with_key(
        {
            "method": "POST",
            "url": "/mcp",
            "json": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "python_exec", "arguments": {"code": "print(6 * 7)"}},
            },
        }
    )
    (response, health), _ = serve(
        [call, with_key({"method": "GET", "url": "/health"})], mcp=upstream
    )
    assert response.status_code == 200, response.text
    assert response.json()["result"]["content"][0]["text"] == "42\n"
    assert forwarded == []
    assert health.json()["sandbox"]["ready"] is True
    assert health.json()["sandbox"]["runtime"] == "docker/default"
