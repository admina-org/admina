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

"""DockerSandbox without an engine: the container spec flag by flag, the
archives, the settings, and the CLI sequence of a run against a stand-in
CLI (fixtures/fake_docker.py)."""

from __future__ import annotations

import asyncio
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

from admina.core.types import (
    SandboxError,
    SandboxFile,
    SandboxLimits,
    SandboxNetwork,
    SandboxRequest,
    SandboxRequestInvalid,
    SandboxUnavailable,
)
from admina.plugins.builtin.sandboxes.docker import (
    SANDBOX_LABEL,
    DockerSandbox,
    DockerSandboxSettings,
    build_container_spec,
    build_input_archive,
    read_output_archive,
)

FAKE = Path(__file__).parent / "fixtures" / "fake_docker.py"
REQUEST = SandboxRequest(
    command=("python", "-I", "/work/main.py"),
    files=(SandboxFile("main.py", b"print(1)"),),
    image="img@sha256:" + "a" * 64,
    limits=SandboxLimits(timeout_s=5, memory_mb=128, cpus=0.5, pids=64, disk_mb=32),
    request_id="ev-1\nx",
)


def _spec(request=REQUEST, **settings) -> list[str]:
    return build_container_spec(
        request, DockerSandboxSettings(**settings), name="admina-sbx-1", created=1000.0
    )


def _pairs(spec: list[str], flag: str) -> list[str]:
    return [spec[i + 1] for i, arg in enumerate(spec) if arg == flag]


# ── Container spec ───────────────────────────────────────────


def test_spec_isolation_flags():
    spec = _spec()
    assert spec[:2] == ["run", "--detach"]
    for flag in ("--init", "--read-only"):
        assert flag in spec
    assert _pairs(spec, "--user") == ["65534:65534"]
    assert _pairs(spec, "--cap-drop") == ["ALL"]
    assert _pairs(spec, "--security-opt") == ["no-new-privileges"]
    assert _pairs(spec, "--network") == ["none"]
    assert _pairs(spec, "--pull") == ["never"]
    assert _pairs(spec, "--log-driver") == ["none"]
    assert _pairs(spec, "--workdir") == ["/work"]


def test_spec_limits():
    spec = _spec()
    assert _pairs(spec, "--memory") == ["128m"]
    assert _pairs(spec, "--memory-swap") == ["128m"]
    assert _pairs(spec, "--cpus") == ["0.5"]
    assert _pairs(spec, "--pids-limit") == ["64"]
    assert _pairs(spec, "--ulimit") == ["nofile=256:256"]
    work, tmp = _pairs(spec, "--tmpfs")
    assert work == "/work:rw,noexec,nosuid,nodev,size=32m,mode=1777"
    assert tmp.startswith("/tmp:rw,noexec,nosuid,nodev,size=16m")


def test_spec_never_mounts_or_grants_anything():
    spec = _spec()
    for forbidden in (
        "-v",
        "--volume",
        "--mount",
        "--privileged",
        "--cap-add",
        "--device",
        "--pid",
        "--ipc",
        "--userns",
        "-p",
        "--publish",
        "--env-file",
    ):
        assert forbidden not in spec
    assert not any("seccomp=unconfined" in arg or "docker.sock" in arg for arg in spec)


def test_spec_labels_and_command():
    spec = _spec()
    assert _pairs(spec, "--label") == [
        f"{SANDBOX_LABEL}=1",
        "admina.event_id=ev-1_x",
        "admina.created=1000",
    ]
    assert _pairs(spec, "--name") == ["admina-sbx-1"]
    entry = spec.index("--entrypoint")
    assert spec[entry:] == ["--entrypoint", "sleep", REQUEST.image, "infinity"]


def test_spec_env_is_only_the_requests():
    request = SandboxRequest(command=("true",), env={"LANG": "C.UTF-8"})
    spec = _spec(request)
    assert _pairs(spec, "--env") == ["LANG=C.UTF-8"]
    assert _pairs(_spec(SandboxRequest(command=("true",))), "--env") == []


def test_spec_runtime():
    assert "--runtime" not in _spec()
    assert _pairs(_spec(runtime="runsc"), "--runtime") == ["runsc"]


def test_spec_default_image():
    spec = _spec(SandboxRequest(command=("true",)), image="local@sha256:1")
    assert spec[-2:] == ["local@sha256:1", "infinity"]


def test_spec_refuses_network_egress():
    with pytest.raises(SandboxRequestInvalid, match="network none"):
        _spec(SandboxRequest(command=("true",), network=SandboxNetwork.EGRESS))


# ── Archives ─────────────────────────────────────────────────


def test_input_archive_holds_the_files_and_the_collected_directories():
    data = build_input_archive(REQUEST)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = {m.name: m for m in archive.getmembers()}
        assert set(members) == {"out", "main.py"}
        assert members["out"].isdir()
        assert archive.extractfile("main.py").read() == b"print(1)"
        assert members["main.py"].mode == 0o644


def _tar(entries) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("out/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        archive.addfile(link)
    return buffer.getvalue()


def test_output_archive_skips_links_and_paths_outside_work():
    files, truncated = read_output_archive(
        _tar([("out/a.txt", b"a"), ("/abs", b"x"), ("../up", b"y")]), 100, complete=True
    )
    assert files == (SandboxFile("out/a.txt", b"a"),)
    assert truncated is False


def test_output_archive_limit():
    files, truncated = read_output_archive(
        _tar([("out/a", b"a" * 6), ("out/b", b"b" * 6)]), 10, complete=True
    )
    assert [f.path for f in files] == ["out/a"] and truncated is True


def test_output_archive_cut_or_garbage():
    data = _tar([("out/a", b"a" * 2000)])
    assert read_output_archive(data[:700], 10_000, complete=False)[1] is True
    assert read_output_archive(b"not a tar" * 100, 10_000, complete=True) == ((), True)


# ── Settings ─────────────────────────────────────────────────


def test_settings_defaults():
    settings = DockerSandboxSettings.from_config(None)
    assert settings.binary == "docker" and settings.runtime == "runc"
    assert "@sha256:" in settings.image
    assert settings.engine == "docker"
    assert DockerSandboxSettings(binary="/usr/bin/podman").engine == "podman"


@pytest.mark.parametrize(
    "config",
    [
        {"runtime": "kata"},
        {"binary": ""},
        {"orphan_age_seconds": 0},
        {"cli_timeout_seconds": "fast"},
        {"mounts": ["/:/host"]},
    ],
)
def test_settings_refused(config):
    with pytest.raises(ValueError):
        DockerSandboxSettings.from_config(config)


def test_capabilities():
    assert DockerSandbox().capabilities == frozenset({"network_none", "files"})
    runsc = DockerSandbox({"runtime": "runsc"})
    assert "runtime_runsc" in runsc.capabilities
    assert "network_egress" not in runsc.capabilities
    assert runsc.runtime_label == "docker/runsc"


# ── A run against the stand-in CLI ───────────────────────────


@pytest.fixture
def fake_cli(tmp_path, monkeypatch):
    """A ``docker`` that runs fixtures/fake_docker.py; returns a reader of
    the calls it received."""
    binary = tmp_path / "docker"
    binary.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n', encoding="utf-8")
    binary.chmod(0o755)
    log = tmp_path / "calls.jsonl"
    log.touch()
    monkeypatch.setenv("FAKE_DOCKER_LOG", str(log))
    monkeypatch.setenv("ADMINA_API_KEY", "must-not-reach-the-container")

    def calls() -> list[list[str]]:
        return [json.loads(line) for line in log.read_text().splitlines()]

    calls.binary = str(binary)
    return calls


def _sandbox(fake_cli, **config) -> DockerSandbox:
    return DockerSandbox({"binary": fake_cli.binary, **config})


def test_run_sequence(fake_cli):
    request = SandboxRequest(
        command=("python", "-I", "/work/main.py"),
        stdin=b"IN",
        files=(SandboxFile("main.py", b"print(1)"),),
        limits=SandboxLimits(output_max_bytes=10),
    )
    result = asyncio.run(_sandbox(fake_cli).run(request))
    names = [call[0] for call in fake_cli()]
    assert names == ["image", "run", "exec", "exec", "exec", "inspect", "rm"]
    calls = fake_cli()
    assert calls[2][:3] == ["exec", "-i", calls[1][calls[1].index("--name") + 1]]
    assert calls[3][-3:] == ["python", "-I", "/work/main.py"]
    assert result.exit_code == 3
    assert result.stdout == b"x" * 10 and result.stdout_truncated is True
    assert result.stderr == b"warning\n" and result.stderr_truncated is False
    assert result.files == (SandboxFile("out/r.txt", b"result"),)
    assert result.oom_killed is False and result.timed_out is False
    assert result.runtime == "docker/default"
    assert result.image_digest.startswith("sha256:")
    assert result.network_observed is False
    # Admina's environment is not passed to the container.
    assert not any("ADMINA_API_KEY" in arg for call in calls for arg in call)


def test_image_digest_from_the_reference(fake_cli):
    request = SandboxRequest(command=("true",), image="python@sha256:" + "b" * 64)
    result = asyncio.run(_sandbox(fake_cli).run(request))
    assert result.image_digest == "sha256:" + "b" * 64


def test_timeout_kills_the_container(fake_cli, monkeypatch):
    monkeypatch.setenv("FAKE_DOCKER_MODE", "slow")
    request = SandboxRequest(command=("sleep", "60"), limits=SandboxLimits(timeout_s=0.5))
    result = asyncio.run(_sandbox(fake_cli).run(request))
    assert result.timed_out is True and result.exit_code is None
    names = [call[0] for call in fake_cli()]
    assert "kill" in names and names[-1] == "rm"


def test_oom_is_reported(fake_cli, monkeypatch):
    monkeypatch.setenv("FAKE_DOCKER_MODE", "oom")
    result = asyncio.run(_sandbox(fake_cli).run(SandboxRequest(command=("true",))))
    assert result.oom_killed is True


def test_output_files_not_read_back_are_marked(fake_cli, monkeypatch):
    monkeypatch.setenv("FAKE_DOCKER_MODE", "nocollect")
    result = asyncio.run(_sandbox(fake_cli).run(SandboxRequest(command=("true",))))
    assert result.files == () and result.files_truncated is True


@pytest.mark.parametrize(
    "mode, error, removed",
    [
        ("noimage", SandboxUnavailable, False),
        ("norun", SandboxUnavailable, True),
        ("notar", SandboxError, True),
    ],
)
def test_infrastructure_failures_raise_and_clean_up(fake_cli, monkeypatch, mode, error, removed):
    monkeypatch.setenv("FAKE_DOCKER_MODE", mode)
    sandbox = _sandbox(fake_cli)
    with pytest.raises(error):
        asyncio.run(sandbox.run(SandboxRequest(command=("true",))))
    names = [call[0] for call in fake_cli()]
    assert ("rm" in names) is removed
    assert "exec" not in names or mode == "notar"
    assert sandbox._live == set()


def test_invalid_request_runs_nothing(fake_cli):
    with pytest.raises(SandboxRequestInvalid):
        asyncio.run(_sandbox(fake_cli).run(SandboxRequest(command=())))
    assert fake_cli() == []


def test_missing_binary_is_unavailable():
    sandbox = DockerSandbox({"binary": "/nonexistent/docker"})
    with pytest.raises(SandboxUnavailable):
        asyncio.run(sandbox.run(SandboxRequest(command=("true",))))
    assert asyncio.run(sandbox.health())["ready"] is False


def test_health_checks_the_images_it_is_given(fake_cli):
    status = asyncio.run(_sandbox(fake_cli).health(images=("registry/own:1", "registry/own:2")))
    assert status["ready"] is True
    inspected = [call[-1] for call in fake_cli() if call[:2] == ["image", "inspect"]]
    assert inspected == ["registry/own:1", "registry/own:2"]


def test_runtime_label_names_the_engine_default():
    assert DockerSandbox().runtime_label == "docker/default"
    assert DockerSandbox({"runtime": "runsc"}).runtime_label == "docker/runsc"


def test_health(fake_cli, monkeypatch):
    status = asyncio.run(_sandbox(fake_cli).health())
    assert status["ready"] is True and status["runtime"] == "docker/default"
    assert asyncio.run(_sandbox(fake_cli, runtime="runsc").health())["ready"] is False
    monkeypatch.setenv("FAKE_DOCKER_MODE", "noinfo")
    assert "not reachable" in asyncio.run(_sandbox(fake_cli).health())["detail"]
    monkeypatch.setenv("FAKE_DOCKER_MODE", "noimage")
    assert "not present locally" in asyncio.run(_sandbox(fake_cli).health())["detail"]


def test_reap_removes_old_and_unlabelled_containers_only(fake_cli):
    removed = asyncio.run(_sandbox(fake_cli).reap())
    assert removed == 2
    rm = [call for call in fake_cli() if call[0] == "rm"][0]
    assert rm[2:] == ["admina-sbx-old", "admina-sbx-bad"]
    ps = [call for call in fake_cli() if call[0] == "ps"][0]
    assert f"label={SANDBOX_LABEL}=1" in ps


def test_aclose_removes_live_containers(fake_cli):
    sandbox = _sandbox(fake_cli)
    sandbox._live.add("admina-sbx-left")
    asyncio.run(sandbox.aclose())
    assert ["rm", "--force", "admina-sbx-left"] in fake_cli()
    assert sandbox._live == set()
