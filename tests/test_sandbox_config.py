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

"""Execution sandbox configuration: domains.agent_security.sandbox.

Off by default; values of the wrong type are schema errors; invalid values
(network egress among them) are listed in SandboxConfig.errors and stop the
proxy at startup (build_sandbox_executor).
"""

from __future__ import annotations

import textwrap

import pytest
from _sandbox import FakeSandbox

from admina.core.config import (
    SANDBOX_DEFAULT_IMAGE,
    ConfigSchemaError,
    SandboxConfig,
    check_config,
    load_config,
)
from admina.plugins.registry import PluginRegistry
from admina.proxy.sandbox_bridge import build_sandbox_executor


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ADMINA_CONFIG", raising=False)


def _load(tmp_path, sandbox_yaml: str):
    path = tmp_path / "admina.yaml"
    text = "schema_version: 1\ndomains:\n  agent_security:\n    sandbox:\n"
    text += textwrap.indent(textwrap.dedent(sandbox_yaml), "      ")
    path.write_text(text, encoding="utf-8")
    return path, load_config(path).agent_security.sandbox


def _registry() -> PluginRegistry:
    registry = PluginRegistry()
    registry.register(FakeSandbox)
    return registry


def test_off_by_default(tmp_path):
    path = tmp_path / "admina.yaml"
    path.write_text("schema_version: 1\n", encoding="utf-8")
    config = load_config(path).agent_security.sandbox
    assert config == SandboxConfig()
    assert config.enabled is False and config.tools == {} and config.errors == []
    assert config.defaults.network == "none"
    assert "@sha256:" in config.defaults.image and config.defaults.image == SANDBOX_DEFAULT_IMAGE


def test_full_section(tmp_path):
    path, config = _load(
        tmp_path,
        """        enabled: true
        provider: docker
        runtime: runsc
        max_concurrent: 2
        queue_timeout_seconds: 1.5
        defaults:
          image: "img@sha256:1111"
          timeout_seconds: 20
          memory_mb: 128
          network: none
        tools:
          python_exec:
            profile: python
            code_argument: code
            files_argument: files
            timeout_seconds: 10
            description: Run Python
            input_schema: {type: object}
          run_shell:
            profile: shell
            memory_mb: 64
        """,
    )
    assert check_config(path, strict=True).unknown == ()
    assert config.errors == []
    assert (config.enabled, config.runtime, config.max_concurrent) == (True, "runsc", 2)
    assert config.queue_timeout_seconds == 1.5
    python = config.tools["python_exec"]
    assert python.limits.timeout_seconds == 10 and python.limits.memory_mb == 128
    assert python.limits.image == "img@sha256:1111"
    assert python.files_argument == "files" and python.input_schema == {"type": "object"}
    shell = config.tools["run_shell"]
    assert shell.profile == "shell" and shell.limits.memory_mb == 64
    assert shell.limits.timeout_seconds == 20


def test_network_egress_is_refused_with_a_clear_error(tmp_path):
    _, config = _load(
        tmp_path,
        """        enabled: true
        tools:
          python_exec: {network: egress}
        """,
    )
    assert any("egress is not supported yet" in error for error in config.errors)
    with pytest.raises(ValueError, match="egress is not supported yet"):
        build_sandbox_executor(_registry(), config, {})


def test_network_egress_in_defaults_is_refused_even_when_disabled(tmp_path):
    _, config = _load(tmp_path, "enabled: false\ndefaults: {network: egress}\n")
    with pytest.raises(ValueError, match="egress is not supported yet"):
        build_sandbox_executor(_registry(), config, {})


@pytest.mark.parametrize(
    "body, message",
    [
        ("runtime: kata\n", "runtime must be one of"),
        ("max_concurrent: 0\n", "max_concurrent"),
        ("tools:\n  t: {profile: ruby}\n", "profile must be one of"),
        ("tools:\n  t: {memory_mb: 0}\n", "memory_mb"),
        ("tools:\n  t: {network: host}\n", "network must be none"),
        ("tools:\n  t: {code_argument: ''}\n", "code_argument"),
        ("tools:\n  t: {input_schema: [1]}\n", "input_schema"),
    ],
)
def test_invalid_values(tmp_path, body, message):
    _, config = _load(tmp_path, body)
    assert any(message in error for error in config.errors), config.errors


def test_wrong_types_are_schema_errors(tmp_path):
    with pytest.raises(ConfigSchemaError, match="sandbox.max_concurrent"):
        _load(tmp_path, "max_concurrent: many\n")


def test_unknown_keys_are_reported(tmp_path):
    path, _ = _load(tmp_path, "mcp_servers: {}\n")
    assert check_config(path).unknown == ("domains.agent_security.sandbox.mcp_servers",)


# ── Building the provider ────────────────────────────────────


def test_disabled_builds_nothing():
    assert build_sandbox_executor(_registry(), SandboxConfig(), {}) is None
    assert build_sandbox_executor(_registry(), None, {}) is None


def test_builds_the_named_provider_with_its_block_and_runtime(tmp_path):
    _, config = _load(tmp_path, "enabled: true\nprovider: fake\ntools:\n  py: {}\n")
    executor = build_sandbox_executor(_registry(), config, {"fake": {"stdout": "x"}})
    assert executor.provider == "fake"
    assert executor.sandbox.config == {"stdout": "x", "runtime": "runc"}
    assert set(executor.tools) == {"py"}


def test_unknown_provider_stops_startup(tmp_path):
    _, config = _load(tmp_path, "enabled: true\nprovider: firecracker\n")
    with pytest.raises(ValueError, match="firecracker"):
        build_sandbox_executor(_registry(), config, {})


def test_runtime_belongs_to_the_sandbox_section(tmp_path):
    _, config = _load(tmp_path, "enabled: true\nprovider: fake\nruntime: runsc\n")
    with pytest.raises(ValueError, match="runtime differs"):
        build_sandbox_executor(_registry(), config, {"fake": {"runtime": "runc"}})


def test_docker_settings_are_validated():
    from admina.plugins.builtin.sandboxes.docker import DockerSandbox

    registry = PluginRegistry()
    registry.register(DockerSandbox)
    config = SandboxConfig(enabled=True, provider="docker")
    executor = build_sandbox_executor(registry, config, {"docker": {"binary": "podman"}})
    assert executor.sandbox.settings.engine == "podman"
    with pytest.raises(ValueError, match="unknown settings"):
        build_sandbox_executor(registry, config, {"docker": {"privileged": True}})
