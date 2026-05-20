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

"""Tests for ``domains.ai_infra.llm_engine``."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from admina.domains.ai_infra.llm_engine import (
    GPUInfo,
    GPUVendor,
    LLMBackend,
    LLMEngine,
    OllamaConfig,
    VLLMConfig,
    _detect_amd,
    _detect_nvidia,
    detect_gpu,
)

# ── GPU detection ────────────────────────────────────────────


class TestDetectGPU:
    """Tests for GPU auto-detection functions."""

    def test_no_gpu_when_no_tools(self) -> None:
        """Returns NONE when neither nvidia-smi nor rocm-smi exist."""
        with patch("admina.domains.ai_infra.llm_engine.shutil.which", return_value=None):
            info = detect_gpu()
        assert info.vendor == GPUVendor.NONE
        assert info.device_count == 0

    def test_nvidia_detected(self) -> None:
        """Parses nvidia-smi CSV output correctly."""
        csv_output = "0, NVIDIA A100, 40960, 535.129.03"
        with (
            patch(
                "admina.domains.ai_infra.llm_engine.shutil.which",
                return_value="/usr/bin/nvidia-smi",
            ),
            patch("admina.domains.ai_infra.llm_engine._run_cmd", return_value=csv_output),
        ):
            info = _detect_nvidia()

        assert info is not None
        assert info.vendor == GPUVendor.NVIDIA
        assert info.device_count == 1
        assert info.vram_total_mb == 40960
        assert info.driver_version == "535.129.03"
        assert info.devices[0]["name"] == "NVIDIA A100"

    def test_nvidia_multi_gpu(self) -> None:
        """Parses multi-GPU nvidia-smi output."""
        csv_output = "0, NVIDIA A100, 40960, 535.129.03\n1, NVIDIA A100, 40960, 535.129.03"
        with (
            patch(
                "admina.domains.ai_infra.llm_engine.shutil.which",
                return_value="/usr/bin/nvidia-smi",
            ),
            patch("admina.domains.ai_infra.llm_engine._run_cmd", return_value=csv_output),
        ):
            info = _detect_nvidia()

        assert info is not None
        assert info.device_count == 2
        assert info.vram_total_mb == 81920

    def test_nvidia_smi_not_found(self) -> None:
        """Returns None when nvidia-smi binary missing."""
        with patch("admina.domains.ai_infra.llm_engine.shutil.which", return_value=None):
            assert _detect_nvidia() is None

    def test_nvidia_smi_fails(self) -> None:
        """Returns None when nvidia-smi returns no output."""
        with (
            patch(
                "admina.domains.ai_infra.llm_engine.shutil.which",
                return_value="/usr/bin/nvidia-smi",
            ),
            patch("admina.domains.ai_infra.llm_engine._run_cmd", return_value=None),
        ):
            assert _detect_nvidia() is None

    def test_amd_detected(self) -> None:
        """Detects AMD GPUs via rocm-smi."""
        csv_output = "device,0\ndevice,1"  # header-like + 2 data lines won't match
        # Actually: non-header lines are those not starting with "device"
        csv_output = "GPU[0]\nGPU[1]"
        with (
            patch(
                "admina.domains.ai_infra.llm_engine.shutil.which", return_value="/usr/bin/rocm-smi"
            ),
            patch("admina.domains.ai_infra.llm_engine._run_cmd", return_value=csv_output),
        ):
            info = _detect_amd()

        assert info is not None
        assert info.vendor == GPUVendor.AMD
        assert info.device_count == 2

    def test_amd_not_found(self) -> None:
        """Returns None when rocm-smi binary missing."""
        with patch("admina.domains.ai_infra.llm_engine.shutil.which", return_value=None):
            assert _detect_amd() is None

    def test_detect_gpu_prefers_nvidia(self) -> None:
        """When both NVIDIA and AMD are present, NVIDIA wins."""
        nvidia_info = GPUInfo(
            vendor=GPUVendor.NVIDIA,
            device_count=1,
            vram_total_mb=8192,
        )
        with (
            patch("admina.domains.ai_infra.llm_engine._detect_nvidia", return_value=nvidia_info),
            patch("admina.domains.ai_infra.llm_engine._detect_amd") as mock_amd,
        ):
            info = detect_gpu()
        assert info.vendor == GPUVendor.NVIDIA
        mock_amd.assert_not_called()

    def test_detect_gpu_falls_back_to_amd(self) -> None:
        """Falls back to AMD when NVIDIA not found."""
        amd_info = GPUInfo(vendor=GPUVendor.AMD, device_count=1)
        with (
            patch("admina.domains.ai_infra.llm_engine._detect_nvidia", return_value=None),
            patch("admina.domains.ai_infra.llm_engine._detect_amd", return_value=amd_info),
        ):
            info = detect_gpu()
        assert info.vendor == GPUVendor.AMD


# ── OllamaConfig ─────────────────────────────────────────────


class TestOllamaConfig:
    """Tests for Ollama docker-compose generation."""

    def test_cpu_compose(self) -> None:
        """CPU config has no deploy/devices keys."""
        cfg = OllamaConfig(gpu_vendor=GPUVendor.NONE)
        svc = cfg.to_compose_dict()
        assert "deploy" not in svc
        assert "devices" not in svc
        assert svc["image"] == "ollama/ollama:latest"
        assert svc["healthcheck"]["test"][0] == "CMD"

    def test_nvidia_compose(self) -> None:
        """NVIDIA config includes deploy.resources.reservations."""
        cfg = OllamaConfig(gpu_vendor=GPUVendor.NVIDIA)
        svc = cfg.to_compose_dict()
        assert "deploy" in svc
        devs = svc["deploy"]["resources"]["reservations"]["devices"]
        assert devs[0]["driver"] == "nvidia"

    def test_amd_compose(self) -> None:
        """AMD config includes device passthrough."""
        cfg = OllamaConfig(gpu_vendor=GPUVendor.AMD)
        svc = cfg.to_compose_dict()
        assert "/dev/kfd" in svc["devices"]
        assert "/dev/dri" in svc["devices"]

    def test_vram_limit(self) -> None:
        """VRAM limit is set in environment."""
        cfg = OllamaConfig(vram_limit_mb=4096)
        svc = cfg.to_compose_dict()
        assert "OLLAMA_MAX_VRAM=4096" in svc["environment"]

    def test_no_env_when_no_vram_limit(self) -> None:
        """No environment key when VRAM limit is 0."""
        cfg = OllamaConfig(vram_limit_mb=0)
        svc = cfg.to_compose_dict()
        assert "environment" not in svc


# ── VLLMConfig ────────────────────────────────────────────────


class TestVLLMConfig:
    """Tests for vLLM docker-compose generation."""

    def test_basic_compose(self) -> None:
        """Generates valid compose dict with command."""
        cfg = VLLMConfig(model="meta-llama/Meta-Llama-3.1-8B", tensor_parallel_size=2)
        svc = cfg.to_compose_dict()
        assert "--tensor-parallel-size" in svc["command"]
        assert "2" in svc["command"]

    def test_nvidia_compose(self) -> None:
        """NVIDIA deploy block present."""
        cfg = VLLMConfig(gpu_vendor=GPUVendor.NVIDIA)
        svc = cfg.to_compose_dict()
        assert "deploy" in svc


# ── LLMEngine ─────────────────────────────────────────────────


class TestLLMEngine:
    """Tests for the LLMEngine orchestrator."""

    def test_from_config_no_gpu(self) -> None:
        """Factory with gpu_autodetect=False returns NONE vendor."""
        engine = LLMEngine.from_config(
            backend="ollama",
            model="llama3.1:8b",
            gpu_autodetect=False,
        )
        assert engine.gpu_info.vendor == GPUVendor.NONE
        assert engine.backend == LLMBackend.OLLAMA

    def test_from_config_with_gpu(self) -> None:
        """Factory with mocked GPU detection."""
        gpu = GPUInfo(vendor=GPUVendor.NVIDIA, device_count=1, vram_total_mb=8192)
        with patch("admina.domains.ai_infra.llm_engine.detect_gpu", return_value=gpu):
            engine = LLMEngine.from_config(backend="ollama", model="llama3.1:8b")
        assert engine.gpu_info.vendor == GPUVendor.NVIDIA

    def test_compose_service_ollama(self) -> None:
        """Ollama compose output has correct container name."""
        engine = LLMEngine(backend=LLMBackend.OLLAMA, model="llama3.1:8b")
        svc = engine.compose_service(project_name="myapp")
        assert svc["container_name"] == "myapp-ollama"

    def test_compose_service_vllm(self) -> None:
        """vLLM compose output has correct container name."""
        gpu = GPUInfo(vendor=GPUVendor.NVIDIA, device_count=4, vram_total_mb=163840)
        engine = LLMEngine(
            backend=LLMBackend.VLLM,
            model="meta-llama/Meta-Llama-3.1-8B",
            gpu_info=gpu,
        )
        svc = engine.compose_service(project_name="myapp")
        assert svc["container_name"] == "myapp-vllm"
        assert "4" in svc["command"]  # tensor_parallel_size

    def test_status_initial(self) -> None:
        """Status reports model and not-loaded on fresh engine."""
        engine = LLMEngine(model="llama3.1:8b")
        st = engine.status()
        assert st.model == "llama3.1:8b"
        assert st.loaded is False

    def test_summary(self) -> None:
        """Summary returns JSON-serialisable dict."""
        engine = LLMEngine(model="llama3.1:8b")
        s = engine.summary()
        assert s["backend"] == "ollama"
        assert s["gpu"]["vendor"] == "none"

    def test_switch_model_ollama(self) -> None:
        """Hot-switch pulls model and updates state."""
        engine = LLMEngine(backend=LLMBackend.OLLAMA, model="llama3.1:8b")
        with patch.object(engine, "pull_model", new_callable=AsyncMock, return_value="success"):
            status = asyncio.run(engine.switch_model("mistral:7b"))
        assert status.loaded is True
        assert status.model == "mistral:7b"
        assert engine.model == "mistral:7b"

    def test_switch_model_vllm_requires_restart(self) -> None:
        """vLLM model switch returns error about restart."""
        engine = LLMEngine(backend=LLMBackend.VLLM, model="llama3.1:8b")
        status = asyncio.run(engine.switch_model("mistral:7b"))
        assert status.loaded is False
        assert "restart" in status.error.lower()

    def test_switch_model_pull_failure(self) -> None:
        """Switch reports error when pull fails."""
        engine = LLMEngine(backend=LLMBackend.OLLAMA, model="llama3.1:8b")
        with patch.object(
            engine,
            "pull_model",
            new_callable=AsyncMock,
            return_value="error: not found",
        ):
            status = asyncio.run(engine.switch_model("nonexistent:latest"))
        assert status.loaded is False
        assert "error" in status.error


# ── GPUInfo / enums ───────────────────────────────────────────


class TestEnums:
    """Tests for enum values and GPUInfo."""

    def test_gpu_vendor_values(self) -> None:
        assert GPUVendor.NVIDIA.value == "nvidia"
        assert GPUVendor.AMD.value == "amd"
        assert GPUVendor.NONE.value == "none"

    def test_llm_backend_values(self) -> None:
        assert LLMBackend.OLLAMA.value == "ollama"
        assert LLMBackend.VLLM.value == "vllm"

    def test_gpu_info_frozen(self) -> None:
        info = GPUInfo(vendor=GPUVendor.NONE)
        with pytest.raises(AttributeError):
            info.vendor = GPUVendor.NVIDIA  # type: ignore[misc]
