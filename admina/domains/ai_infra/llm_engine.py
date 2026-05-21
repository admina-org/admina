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

"""Admina — LLM engine module.

GPU auto-detection, Ollama/vLLM container configuration, model management,
and hot model switching without downtime.  All heavy operations (container
start, model pull) are expressed as *descriptions* — the actual Docker work
is done by the CLI ``admina dev`` command that renders the Jinja2
docker-compose template.

This module is pure Python with no runtime dependency on Docker or GPU
drivers — it only *inspects* the host and returns structured results that
other layers (CLI, SDK) consume.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("admina.ai_infra.llm_engine")


# ── GPU detection ────────────────────────────────────────────


class GPUVendor(str, Enum):
    """Supported GPU vendors."""

    NVIDIA = "nvidia"
    AMD = "amd"
    NONE = "none"


@dataclass(frozen=True)
class GPUInfo:
    """Detected GPU information."""

    vendor: GPUVendor
    device_count: int = 0
    devices: list[dict[str, Any]] = field(default_factory=list)
    driver_version: str = ""
    vram_total_mb: int = 0


def _run_cmd(cmd: list[str], *, timeout: int = 10) -> str | None:
    """Run a command and return stdout, or *None* on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _detect_nvidia() -> GPUInfo | None:
    """Probe NVIDIA GPUs via ``nvidia-smi``."""
    if shutil.which("nvidia-smi") is None:
        return None

    raw = _run_cmd(
        [
            "nvidia-smi",
            "--query-gpu=index,name,memory.total,driver_version",
            "--format=csv,noheader,nounits",
        ]
    )
    if raw is None:
        return None

    devices: list[dict[str, Any]] = []
    total_vram = 0
    driver = ""
    for line in raw.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue
        mem_mb = int(parts[2])
        devices.append(
            {
                "index": int(parts[0]),
                "name": parts[1],
                "vram_mb": mem_mb,
            }
        )
        total_vram += mem_mb
        driver = parts[3]

    if not devices:
        return None

    return GPUInfo(
        vendor=GPUVendor.NVIDIA,
        device_count=len(devices),
        devices=devices,
        driver_version=driver,
        vram_total_mb=total_vram,
    )


def _detect_amd() -> GPUInfo | None:
    """Probe AMD GPUs via ``rocm-smi``."""
    if shutil.which("rocm-smi") is None:
        return None

    raw = _run_cmd(["rocm-smi", "--showid", "--showmeminfo", "vram", "--csv"])
    if raw is None:
        return None

    # Simple heuristic: count non-header lines for device count.
    lines = [ln for ln in raw.splitlines() if ln and not ln.startswith("device")]
    if not lines:
        return None

    return GPUInfo(
        vendor=GPUVendor.AMD,
        device_count=len(lines),
        devices=[{"index": i} for i in range(len(lines))],
        driver_version="",
        vram_total_mb=0,
    )


def detect_gpu() -> GPUInfo:
    """Auto-detect available GPU hardware.

    Checks NVIDIA first (via ``nvidia-smi``), then AMD (via ``rocm-smi``).
    Returns :pyattr:`GPUVendor.NONE` when neither is found.
    """
    info = _detect_nvidia()
    if info is not None:
        logger.info(
            "Detected %d NVIDIA GPU(s), %d MB VRAM total",
            info.device_count,
            info.vram_total_mb,
        )
        return info

    info = _detect_amd()
    if info is not None:
        logger.info("Detected %d AMD GPU(s) via ROCm", info.device_count)
        return info

    logger.info("No GPU detected — LLM will run on CPU")
    return GPUInfo(vendor=GPUVendor.NONE)


# ── LLM backend configuration ───────────────────────────────


class LLMBackend(str, Enum):
    """Supported LLM serving backends."""

    OLLAMA = "ollama"
    VLLM = "vllm"


@dataclass
class OllamaConfig:
    """Container configuration for Ollama."""

    image: str = "ollama/ollama:latest"
    container_name: str = "admina-ollama"
    port: int = 11434
    model: str = "llama3.1:8b"
    gpu_vendor: GPUVendor = GPUVendor.NONE
    vram_limit_mb: int = 0
    environment: dict[str, str] = field(default_factory=dict)

    def to_compose_dict(self) -> dict[str, Any]:
        """Return a docker-compose service fragment."""
        svc: dict[str, Any] = {
            "image": self.image,
            "container_name": self.container_name,
            "ports": [f"{self.port}:11434"],
            "volumes": ["ollama-data:/root/.ollama"],
            "healthcheck": {
                "test": ["CMD", "curl", "-f", "http://localhost:11434/api/tags"],
                "interval": "15s",
                "timeout": "5s",
                "retries": 5,
            },
            "networks": ["admina"],
            "restart": "unless-stopped",
        }
        env = dict(self.environment)
        if self.vram_limit_mb > 0:
            env["OLLAMA_MAX_VRAM"] = str(self.vram_limit_mb)
        if env:
            svc["environment"] = [f"{k}={v}" for k, v in sorted(env.items())]

        if self.gpu_vendor == GPUVendor.NVIDIA:
            svc["deploy"] = {
                "resources": {
                    "reservations": {
                        "devices": [
                            {
                                "driver": "nvidia",
                                "count": "all",
                                "capabilities": [["gpu"]],
                            }
                        ],
                    },
                },
            }
        elif self.gpu_vendor == GPUVendor.AMD:
            svc["devices"] = ["/dev/kfd", "/dev/dri"]

        return svc


@dataclass
class VLLMConfig:
    """Container configuration for vLLM (multi-GPU)."""

    image: str = "vllm/vllm-openai:latest"
    container_name: str = "admina-vllm"
    port: int = 8000
    model: str = "meta-llama/Meta-Llama-3.1-8B"
    tensor_parallel_size: int = 1
    gpu_vendor: GPUVendor = GPUVendor.NONE

    def to_compose_dict(self) -> dict[str, Any]:
        """Return a docker-compose service fragment."""
        svc: dict[str, Any] = {
            "image": self.image,
            "container_name": self.container_name,
            "ports": [f"{self.port}:8000"],
            "command": [
                "--model",
                self.model,
                "--tensor-parallel-size",
                str(self.tensor_parallel_size),
            ],
            "healthcheck": {
                "test": ["CMD", "curl", "-f", "http://localhost:8000/health"],
                "interval": "15s",
                "timeout": "5s",
                "retries": 5,
            },
            "networks": ["admina"],
            "restart": "unless-stopped",
        }
        if self.gpu_vendor == GPUVendor.NVIDIA:
            svc["deploy"] = {
                "resources": {
                    "reservations": {
                        "devices": [
                            {
                                "driver": "nvidia",
                                "count": "all",
                                "capabilities": [["gpu"]],
                            }
                        ],
                    },
                },
            }
        return svc


# ── LLM Engine ───────────────────────────────────────────────


@dataclass
class ModelStatus:
    """Runtime status of a loaded model."""

    model: str
    backend: LLMBackend
    loaded: bool = False
    vram_used_mb: int = 0
    error: str = ""


@dataclass
class LLMEngine:
    """Manages LLM backend lifecycle and model switching.

    Inspects the host GPU, selects the appropriate backend (Ollama for
    single-GPU / CPU, vLLM for multi-GPU), and produces Docker Compose
    configuration fragments.
    """

    backend: LLMBackend = LLMBackend.OLLAMA
    model: str = "llama3.1:8b"
    gpu_info: GPUInfo = field(default_factory=lambda: GPUInfo(vendor=GPUVendor.NONE))
    vram_limit_mb: int = 0
    _current_model: str = ""

    # ── Factory ──────────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        *,
        backend: str = "ollama",
        model: str = "llama3.1:8b",
        gpu_autodetect: bool = True,
        vram_limit_mb: int = 0,
    ) -> LLMEngine:
        """Create an engine from admina.yaml values.

        Args:
            backend: ``"ollama"`` or ``"vllm"``.
            model: Default model to pull / serve.
            gpu_autodetect: Run GPU probe on the host.
            vram_limit_mb: Optional VRAM cap (0 = unlimited).
        """
        gpu = detect_gpu() if gpu_autodetect else GPUInfo(vendor=GPUVendor.NONE)
        resolved_backend = LLMBackend(backend)

        # Auto-select vLLM when multiple NVIDIA GPUs are present.
        if (
            resolved_backend == LLMBackend.OLLAMA
            and gpu.device_count > 1
            and gpu.vendor == GPUVendor.NVIDIA
        ):
            logger.info(
                "Multiple NVIDIA GPUs detected (%d) — recommending vLLM",
                gpu.device_count,
            )

        return cls(
            backend=resolved_backend,
            model=model,
            gpu_info=gpu,
            vram_limit_mb=vram_limit_mb,
        )

    # ── Compose generation ───────────────────────────────────

    def compose_service(self, project_name: str = "admina") -> dict[str, Any]:
        """Return the docker-compose service dict for the configured backend.

        Args:
            project_name: Used for container naming.
        """
        if self.backend == LLMBackend.VLLM:
            cfg = VLLMConfig(
                container_name=f"{project_name}-vllm",
                model=self.model,
                tensor_parallel_size=max(1, self.gpu_info.device_count),
                gpu_vendor=self.gpu_info.vendor,
            )
            return cfg.to_compose_dict()

        cfg = OllamaConfig(
            container_name=f"{project_name}-ollama",
            model=self.model,
            gpu_vendor=self.gpu_info.vendor,
            vram_limit_mb=self.vram_limit_mb,
        )
        return cfg.to_compose_dict()

    # ── Model management ─────────────────────────────────────

    async def pull_model(self, model: str | None = None) -> str:
        """Request model pull via Ollama CLI (non-blocking).

        Args:
            model: Model tag to pull.  Defaults to ``self.model``.

        Returns:
            Output from the pull command.
        """
        tag = model or self.model
        logger.info("Pulling model %s", tag)
        proc = await asyncio.create_subprocess_exec(
            "ollama",
            "pull",
            tag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            err = stderr.decode().strip()
            logger.error("Model pull failed: %s", err)
            return f"error: {err}"
        return stdout.decode().strip()

    def pull_model_sync(self, model: str | None = None) -> str:
        """Synchronous convenience wrapper for :meth:`pull_model`."""
        return asyncio.get_event_loop().run_until_complete(self.pull_model(model))

    async def switch_model(self, new_model: str) -> ModelStatus:
        """Hot-switch to a different model without container restart.

        For Ollama this works by pulling the new model (Ollama loads it on
        first request and unloads the previous one automatically).  For vLLM
        a container restart is required — this method returns a status
        indicating that.

        Args:
            new_model: The model tag to switch to.

        Returns:
            A :class:`ModelStatus` reflecting the new state.
        """
        old = self._current_model or self.model
        logger.info("Switching model %s → %s", old, new_model)

        if self.backend == LLMBackend.VLLM:
            return ModelStatus(
                model=new_model,
                backend=self.backend,
                loaded=False,
                error="vLLM requires container restart for model switch",
            )

        result = await self.pull_model(new_model)
        if result.startswith("error:"):
            return ModelStatus(
                model=new_model,
                backend=self.backend,
                loaded=False,
                error=result,
            )

        self._current_model = new_model
        self.model = new_model
        return ModelStatus(
            model=new_model,
            backend=self.backend,
            loaded=True,
        )

    async def switch_model_sync(self, new_model: str) -> ModelStatus:
        """Synchronous convenience wrapper for :meth:`switch_model`."""
        return await self.switch_model(new_model)

    # ── Status ───────────────────────────────────────────────

    def status(self) -> ModelStatus:
        """Return current engine status."""
        return ModelStatus(
            model=self._current_model or self.model,
            backend=self.backend,
            loaded=bool(self._current_model),
        )

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of the engine config."""
        return {
            "backend": self.backend.value,
            "model": self.model,
            "gpu": {
                "vendor": self.gpu_info.vendor.value,
                "device_count": self.gpu_info.device_count,
                "vram_total_mb": self.gpu_info.vram_total_mb,
                "driver_version": self.gpu_info.driver_version,
            },
            "vram_limit_mb": self.vram_limit_mb,
        }
