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

"""Admina — Docker execution sandbox.

Runs each request in a fresh container through the ``docker`` CLI (or
``podman``: ``binary: podman``), with no new dependency. One request:

1. ``run``: a container whose PID 1 is an idle ``sleep infinity`` behind
   ``--init``, with a read-only root filesystem, a tmpfs at /work, no
   network, every capability dropped, ``no-new-privileges``, user
   65534:65534 and the cgroup limits of the request
   (:func:`build_container_spec`);
2. ``exec tar -x``: the input files, as a tar archive built in memory, onto
   the tmpfs (``docker cp`` cannot write to a tmpfs);
3. ``exec`` of the command, stdout and stderr read up to the limit; at the
   timeout the container is killed;
4. ``exec tar -c``: the files of the collected directories, up to the limit;
5. ``inspect``: whether the kernel killed a process for memory;
6. ``rm -f``, always.

The image must provide ``sleep`` and ``tar`` (``python:3.x-slim`` does) and
be present locally: nothing is pulled. Containers carry the label
``admina.sandbox=1``; :meth:`DockerSandbox.reap` removes those older than
``orphan_age_seconds`` (left behind by a crash).

Network: ``none`` only. Runtime: the engine's default (``runc``) or
``runsc`` (gVisor), which must be registered with the engine.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import tarfile
import threading
import time
import uuid
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from admina.core.config import SANDBOX_DEFAULT_IMAGE
from admina.core.types import (
    SandboxError,
    SandboxFile,
    SandboxNetwork,
    SandboxRequest,
    SandboxRequestInvalid,
    SandboxResult,
    SandboxUnavailable,
)
from admina.domains.agent_security.sandbox import check_request, safe_relative_path
from admina.plugins.base import BaseExecutionSandbox

logger = logging.getLogger("admina.plugins.sandboxes.docker")

#: The label of every sandbox container.
SANDBOX_LABEL = "admina.sandbox"
#: User and group the commands run as (nobody), whatever the image says.
SANDBOX_USER = "65534:65534"
_RUNTIMES = ("runc", "runsc")
_LABEL_VALUE = re.compile(r"[^A-Za-z0-9_.:-]")
# Read from the pipes in chunks of this size.
_CHUNK = 65_536
# Room for the tar headers of the collected files.
_TAR_OVERHEAD = 1 << 20
# Leading part of the output of a failed CLI call kept in an error message.
_ERROR_CHARS = 300


@dataclass(frozen=True)
class DockerSandboxSettings:
    """The ``plugin_config.docker`` block (``runtime`` comes from
    ``domains.agent_security.sandbox.runtime``)."""

    #: ``docker``, ``podman`` or the path of either.
    binary: str = "docker"
    #: The engine's address (``DOCKER_HOST`` for docker, ``CONTAINER_HOST``
    #: for podman); empty: the CLI's own default.
    host: str = ""
    #: ``runc``: the engine's default runtime; ``runsc``: gVisor.
    runtime: str = "runc"
    #: Image of a request that names none.
    image: str = SANDBOX_DEFAULT_IMAGE
    #: Sandbox containers older than this are orphans and are removed.
    orphan_age_seconds: float = 900.0
    #: Time budget of each CLI call other than the command itself.
    cli_timeout_seconds: float = 60.0

    @classmethod
    def from_config(cls, config: dict[str, Any] | None) -> DockerSandboxSettings:
        """The settings of a ``plugin_config`` block.

        Raises:
            ValueError: an unknown key or an invalid value.
        """
        config = dict(config or {})
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(config) - known)
        if unknown:
            raise ValueError(f"docker sandbox: unknown settings {', '.join(unknown)}")
        values = {key: value for key, value in config.items() if value is not None}
        settings = cls(**values)
        if settings.runtime not in _RUNTIMES:
            raise ValueError("docker sandbox: runtime must be one of: " + " | ".join(_RUNTIMES))
        if not settings.binary:
            raise ValueError("docker sandbox: binary must name the docker or podman CLI")
        for key in ("orphan_age_seconds", "cli_timeout_seconds"):
            value = getattr(settings, key)
            if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
                raise ValueError(f"docker sandbox: {key} must be a number greater than 0")
        return settings

    @property
    def engine(self) -> str:
        """``podman`` when the binary is podman, else ``docker``."""
        return "podman" if "podman" in Path(self.binary).name else "docker"


def _label(value: str) -> str:
    return _LABEL_VALUE.sub("_", value)[:128]


def build_container_spec(
    request: SandboxRequest,
    settings: DockerSandboxSettings,
    *,
    name: str,
    created: float,
) -> list[str]:
    """The arguments of ``docker run`` (after the binary) that create the
    container of *request*. Pure: everything the container is allowed comes
    from here, and nothing in it comes from the request other than its
    limits, its environment and its image.

    Raises:
        SandboxRequestInvalid: the request asks for a network other than
            ``none``.
    """
    if request.network is not SandboxNetwork.NONE:
        raise SandboxRequestInvalid("the docker sandbox supports only network none")
    limits = request.limits
    args = [
        "run",
        "--detach",
        "--name",
        name,
        "--pull",
        "never",
        "--label",
        f"{SANDBOX_LABEL}=1",
        "--label",
        f"admina.event_id={_label(request.request_id)}",
        "--label",
        f"admina.created={int(created)}",
    ]
    if settings.runtime != "runc":
        args += ["--runtime", settings.runtime]
    args += [
        "--init",
        "--read-only",
        "--user",
        SANDBOX_USER,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--network",
        "none",
        "--tmpfs",
        f"/work:rw,noexec,nosuid,nodev,size={limits.disk_mb}m,mode=1777",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",  # nosec B108 — a tmpfs in the container
        "--memory",
        f"{limits.memory_mb}m",
        "--memory-swap",
        f"{limits.memory_mb}m",
        "--cpus",
        f"{limits.cpus:g}",
        "--pids-limit",
        str(limits.pids),
        "--ulimit",
        "nofile=256:256",
        "--log-driver",
        "none",
        "--workdir",
        "/work",
    ]
    for key, value in request.env.items():
        args += ["--env", f"{key}={value}"]
    args += ["--entrypoint", "sleep", request.image or settings.image, "infinity"]
    return args


def build_input_archive(request: SandboxRequest) -> bytes:
    """The tar archive written to /work: the input files, and the
    collected directories (created empty so that collecting never fails on a
    missing one)."""
    buffer = io.BytesIO()
    now = int(time.time())
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for directory in request.collect:
            info = tarfile.TarInfo(safe_relative_path(directory))
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = now
            archive.addfile(info)
        for item in request.files:
            info = tarfile.TarInfo(safe_relative_path(item.path))
            info.size = len(item.content)
            info.mode = 0o644
            info.mtime = now
            archive.addfile(info, io.BytesIO(item.content))
    return buffer.getvalue()


def read_output_archive(
    data: bytes, limit: int, complete: bool
) -> tuple[tuple[SandboxFile, ...], bool]:
    """The regular files of the tar archive *data* (links, devices and
    paths outside /work are skipped), up to *limit* bytes in all; with
    whether some were left out. *complete* is False when *data* was cut."""
    files: list[SandboxFile] = []
    total = 0
    truncated = not complete
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                if not member.isfile():
                    continue
                try:
                    path = safe_relative_path(member.name)
                except SandboxRequestInvalid:
                    continue
                if total + member.size > limit:
                    truncated = True
                    break
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                content = handle.read()
                total += len(content)
                files.append(SandboxFile(path=path, content=content))
    except (tarfile.TarError, EOFError, OSError):
        truncated = True
    return tuple(files), truncated


async def _read_capped(stream: asyncio.StreamReader | None, cap: int) -> tuple[bytes, bool]:
    """Everything *stream* yields, kept up to *cap* bytes: the rest is read
    and discarded, so the writer never blocks."""
    if stream is None:
        return b"", False
    kept = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(_CHUNK)
        if not chunk:
            return bytes(kept), truncated
        room = cap - len(kept)
        if room > 0:
            kept += chunk[:room]
        if len(chunk) > room:
            truncated = True


class DockerSandbox(BaseExecutionSandbox):
    """Execution sandbox on a local Docker or Podman engine.

    Args:
        config: The ``plugin_config.docker`` block (see
            :class:`DockerSandboxSettings`).
    """

    name = "docker"
    sandbox_name = "docker"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.settings = DockerSandboxSettings.from_config(config)
        # Containers of this instance still running, removed by aclose().
        self._live: set[str] = set()
        self._live_lock = threading.Lock()
        # Image reference → digest, for the result.
        self._digests: dict[str, str] = {}
        self._digests_lock = threading.Lock()

    @property
    def capabilities(self) -> frozenset[str]:
        caps = {"network_none", "files"}
        if self.settings.runtime == "runsc":
            caps.add("runtime_runsc")
        return frozenset(caps)

    @property
    def runtime_label(self) -> str:
        """``<engine>/runsc`` for gVisor; ``<engine>/default`` for runc, which
        passes no ``--runtime`` and so runs the engine's default runtime."""
        runtime = "runsc" if self.settings.runtime == "runsc" else "default"
        return f"{self.settings.engine}/{runtime}"

    # ── CLI ────────────────────────────────────────────────────

    def _environment(self) -> dict[str, str]:
        """The environment of the CLI (never of the container)."""
        env = dict(os.environ)
        if self.settings.host:
            env["CONTAINER_HOST" if self.settings.engine == "podman" else "DOCKER_HOST"] = (
                self.settings.host
            )
        return env

    async def _spawn(self, args: list[str], *, stdin: bool = False) -> asyncio.subprocess.Process:
        try:
            return await asyncio.create_subprocess_exec(
                self.settings.binary,
                *args,
                stdin=asyncio.subprocess.PIPE if stdin else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._environment(),
            )
        except OSError as exc:
            raise SandboxUnavailable(
                f"{self.settings.binary}: cannot be started ({type(exc).__name__})"
            ) from None

    async def _cli(
        self, args: list[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> tuple[int, bytes, bytes]:
        """Run the CLI with *args*; its exit code, stdout and stderr.

        Raises:
            SandboxUnavailable: the CLI cannot be started or exceeds the
                time budget.
        """
        process = await self._spawn(args, stdin=stdin is not None)
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin), timeout or self.settings.cli_timeout_seconds
            )
        except TimeoutError:
            with suppress(ProcessLookupError):
                process.kill()
            await process.wait()
            raise SandboxUnavailable(f"{self.settings.binary} {args[0]}: timed out") from None
        return process.returncode or 0, stdout, stderr

    @staticmethod
    def _error_text(stderr: bytes) -> str:
        return stderr.decode("utf-8", errors="replace").strip()[:_ERROR_CHARS]

    # ── Image ──────────────────────────────────────────────────

    async def _image_digest(self, image: str) -> str:
        """The digest of the local *image*.

        Raises:
            SandboxUnavailable: the image is not present locally.
        """
        with self._digests_lock:
            cached = self._digests.get(image)
        if cached:
            return cached
        code, out, err = await self._cli(
            ["image", "inspect", "--format", "{{json .RepoDigests}}|{{.Id}}", image]
        )
        if code != 0:
            raise SandboxUnavailable(
                f"image {image!r} is not present locally (pull it first): {self._error_text(err)}"
            )
        digest = image.split("@", 1)[1] if "@" in image else ""
        if not digest:
            repo_digests, _, image_id = out.decode().strip().partition("|")
            with suppress(ValueError):
                found = json.loads(repo_digests) or []
                digest = found[0].split("@", 1)[1] if found and "@" in found[0] else ""
            digest = digest or image_id.strip()
        with self._digests_lock:
            self._digests[image] = digest
        return digest

    # ── Execution ──────────────────────────────────────────────

    async def run(self, request: SandboxRequest) -> SandboxResult:
        check_request(request)
        image = request.image or self.settings.image
        name = f"admina-sbx-{uuid.uuid4().hex[:16]}"
        spec = build_container_spec(request, self.settings, name=name, created=time.time())
        digest = await self._image_digest(image)

        code, _out, err = await self._cli(spec)
        with self._live_lock:
            self._live.add(name)
        try:
            if code != 0:
                raise SandboxUnavailable(f"container not created: {self._error_text(err)}")
            archive = build_input_archive(request)
            code, _out, err = await self._cli(
                ["exec", "-i", name, "tar", "-x", "-f", "-", "-C", "/work"], stdin=archive
            )
            if code != 0:
                raise SandboxError(f"input files not written: {self._error_text(err)}")
            return await self._execute(request, name, digest)
        finally:
            await self._remove(name)

    async def _execute(self, request: SandboxRequest, name: str, digest: str) -> SandboxResult:
        limits = request.limits
        args = ["exec", *(["-i"] if request.stdin else []), "--workdir", "/work", name]
        process = await self._spawn([*args, *request.command], stdin=bool(request.stdin))
        started = time.monotonic()

        async def feed() -> None:
            if process.stdin is None:
                return
            with suppress(ConnectionError, BrokenPipeError):
                process.stdin.write(request.stdin)
                await process.stdin.drain()
            process.stdin.close()

        feeder = asyncio.ensure_future(feed())
        out_task = asyncio.ensure_future(_read_capped(process.stdout, limits.output_max_bytes))
        err_task = asyncio.ensure_future(_read_capped(process.stderr, limits.output_max_bytes))
        timed_out = False
        try:
            await asyncio.wait_for(process.wait(), limits.timeout_s)
        except TimeoutError:
            timed_out = True
            # Killing the exec client would leave the command running in
            # the container: the container goes.
            await self._cli(["kill", name])
            with suppress(ProcessLookupError):
                process.kill()
            await process.wait()
        duration_ms = (time.monotonic() - started) * 1000
        with suppress(Exception):
            await feeder
        stdout, stdout_truncated = await out_task
        stderr, stderr_truncated = await err_task

        files: tuple[SandboxFile, ...] = ()
        files_truncated = False
        oom_killed = False
        if not timed_out:
            files, files_truncated = await self._collect(request, name)
            oom_killed = await self._oom_killed(name)
        return SandboxResult(
            exit_code=None if timed_out else process.returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            files=files,
            files_truncated=files_truncated,
            network_attempts=(),
            network_observed=False,
            duration_ms=duration_ms,
            timed_out=timed_out,
            oom_killed=oom_killed,
            runtime=self.runtime_label,
            image_digest=digest,
        )

    async def _collect(
        self, request: SandboxRequest, name: str
    ) -> tuple[tuple[SandboxFile, ...], bool]:
        """The files of the collected directories; ``(files, truncated)``.
        A failure to read them back (a process limit still exhausted by the
        command, for instance) returns no file, marked truncated."""
        if not request.collect:
            return (), False
        directories = [safe_relative_path(d) for d in request.collect]
        limit = request.limits.files_max_bytes
        process = await self._spawn(
            ["exec", name, "tar", "-c", "-f", "-", "-C", "/work", *directories]
        )
        try:
            data, cut = await asyncio.wait_for(
                _read_capped(process.stdout, limit + _TAR_OVERHEAD),
                self.settings.cli_timeout_seconds,
            )
            await asyncio.wait_for(process.wait(), self.settings.cli_timeout_seconds)
        except TimeoutError:
            with suppress(ProcessLookupError):
                process.kill()
            await process.wait()
            logger.warning("Sandbox %s: output files not read back (timed out)", name)
            return (), True
        if process.returncode != 0 and not cut:
            logger.warning(
                "Sandbox %s: output files not read back (tar exit %s)", name, process.returncode
            )
            return (), True
        return read_output_archive(data, limit, complete=not cut)

    async def _oom_killed(self, name: str) -> bool:
        try:
            code, out, _err = await self._cli(["inspect", "--format", "{{.State.OOMKilled}}", name])
        except SandboxError:
            return False
        return code == 0 and out.strip() == b"true"

    async def _remove(self, name: str) -> None:
        try:
            code, _out, err = await self._cli(["rm", "--force", name])
            if code != 0:
                logger.warning("Sandbox container %s not removed: %s", name, self._error_text(err))
                return
        except SandboxError as exc:
            logger.warning("Sandbox container %s not removed: %s", name, exc)
            return
        with self._live_lock:
            self._live.discard(name)

    # ── Lifecycle ──────────────────────────────────────────────

    async def health(self, images: Sequence[str] = ()) -> dict:
        images = tuple(images) or (self.settings.image,)
        base = {"runtime": self.runtime_label, "image": images[0]}
        # Docker lists its runtimes; Podman resolves --runtime when the
        # container is created, so for it only the engine is checked here.
        template = (
            "{{.Host.OCIRuntime.Name}}"
            if self.settings.engine == "podman"
            else "{{json .Runtimes}}"
        )
        try:
            code, out, err = await self._cli(["info", "--format", template])
        except SandboxError as exc:
            return {**base, "ready": False, "detail": str(exc)}
        if code != 0:
            return {
                **base,
                "ready": False,
                "detail": f"engine not reachable: {self._error_text(err)}",
            }
        if (
            self.settings.runtime == "runsc"
            and self.settings.engine == "docker"
            and b'"runsc"' not in out
        ):
            return {
                **base,
                "ready": False,
                "detail": "runtime runsc is not registered with the engine",
            }
        for image in images:
            try:
                await self._image_digest(image)
            except SandboxError as exc:
                return {**base, "ready": False, "detail": str(exc)}
        return {**base, "ready": True, "detail": ""}

    async def reap(self) -> int:
        """Remove the sandbox containers older than ``orphan_age_seconds``
        that this instance is not running."""
        code, out, _err = await self._cli(
            ["ps", "--all", "--quiet", "--filter", f"label={SANDBOX_LABEL}=1"]
        )
        ids = out.decode().split()
        if code != 0 or not ids:
            return 0
        code, out, _err = await self._cli(
            [
                "inspect",
                "--format",
                '{{.Name}} {{index .Config.Labels "admina.created"}}',
                *ids,
            ]
        )
        if code != 0:
            return 0
        cutoff = time.time() - self.settings.orphan_age_seconds
        with self._live_lock:
            live = set(self._live)
        orphans = []
        for line in out.decode().splitlines():
            container, _, created = line.strip().lstrip("/").partition(" ")
            if not container or container in live:
                continue
            try:
                stale = float(created) < cutoff
            except ValueError:
                stale = True
            if stale:
                orphans.append(container)
        if not orphans:
            return 0
        code, _out, err = await self._cli(["rm", "--force", *orphans])
        if code != 0:
            logger.warning("Orphan sandbox containers not removed: %s", self._error_text(err))
            return 0
        logger.info("Removed %d orphan sandbox container(s)", len(orphans))
        return len(orphans)

    async def aclose(self) -> None:
        with self._live_lock:
            names = sorted(self._live)
        for name in names:
            await self._remove(name)
