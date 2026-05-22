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

"""Tests for ``admina init`` CLI command."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from admina.cli.main import (
    AVAILABLE_DOMAINS,
    _resolve_domains,
    _scaffold_project,
    app,
)


@pytest.fixture()
def runner() -> CliRunner:
    """Isolated Click test runner."""
    return CliRunner()


@pytest.fixture()
def tmp_project(tmp_path: Path) -> Path:
    """Return a temporary directory for project scaffolding."""
    return tmp_path / "test-project"


# ── Domain resolution ─────────────────────────────────────


class TestResolveDomains:
    """Tests for ``_resolve_domains`` helper."""

    def test_full_stack_returns_all(self) -> None:
        result = _resolve_domains(full_stack=True, modules=None, interactive=False)
        assert set(result) == set(AVAILABLE_DOMAINS.keys())

    def test_modules_flag_maps_correctly(self) -> None:
        result = _resolve_domains(
            full_stack=False,
            modules="model,compliance",
            interactive=False,
        )
        assert "ai_infra" in result
        assert "compliance" in result
        assert len(result) == 2

    def test_modules_security(self) -> None:
        result = _resolve_domains(
            full_stack=False,
            modules="security",
            interactive=False,
        )
        assert result == ["agent_security"]

    def test_unknown_module_falls_back_to_all(self) -> None:
        result = _resolve_domains(
            full_stack=False,
            modules="nonexistent",
            interactive=False,
        )
        assert set(result) == set(AVAILABLE_DOMAINS.keys())

    def test_no_flags_non_interactive_defaults_all(self) -> None:
        result = _resolve_domains(
            full_stack=False,
            modules=None,
            interactive=False,
        )
        assert set(result) == set(AVAILABLE_DOMAINS.keys())


# ── Scaffolding ───────────────────────────────────────────


class TestScaffoldProject:
    """Tests for ``_scaffold_project`` file generation."""

    def test_creates_all_files(self, tmp_project: Path) -> None:
        tmp_project.mkdir(parents=True)
        created = _scaffold_project(
            tmp_project,
            list(AVAILABLE_DOMAINS.keys()),
            "test-project",
        )
        assert "admina.yaml" in created
        assert "docker-compose.yml" in created
        assert "main.py" in created
        assert ".env" in created
        for f in created:
            assert (tmp_project / f).exists()

    def test_admina_yaml_is_valid(self, tmp_project: Path) -> None:
        tmp_project.mkdir(parents=True)
        _scaffold_project(
            tmp_project,
            list(AVAILABLE_DOMAINS.keys()),
            "test-project",
        )
        data = yaml.safe_load((tmp_project / "admina.yaml").read_text())
        assert data["schema_version"] == 1
        assert data["domains"]["data_sovereignty"]["enabled"] is True
        assert data["domains"]["ai_infra"]["enabled"] is True
        assert data["domains"]["agent_security"]["enabled"] is True
        assert data["domains"]["compliance"]["enabled"] is True

    def test_admina_yaml_partial_domains(self, tmp_project: Path) -> None:
        tmp_project.mkdir(parents=True)
        _scaffold_project(tmp_project, ["compliance"], "test-project")
        data = yaml.safe_load((tmp_project / "admina.yaml").read_text())
        assert data["domains"]["compliance"]["enabled"] is True
        assert data["domains"]["ai_infra"]["enabled"] is False

    def test_docker_compose_is_valid_yaml(self, tmp_project: Path) -> None:
        tmp_project.mkdir(parents=True)
        _scaffold_project(
            tmp_project,
            list(AVAILABLE_DOMAINS.keys()),
            "test-project",
        )
        data = yaml.safe_load((tmp_project / "docker-compose.yml").read_text())
        assert "services" in data
        assert "proxy" in data["services"]
        assert "dashboard" in data["services"]
        assert "redis" in data["services"]

    def test_docker_compose_without_compliance(self, tmp_project: Path) -> None:
        tmp_project.mkdir(parents=True)
        _scaffold_project(tmp_project, ["agent_security"], "test-project")
        data = yaml.safe_load((tmp_project / "docker-compose.yml").read_text())
        assert "clickhouse" not in data["services"]
        assert "minio" not in data["services"]
        assert "proxy" in data["services"]

    def test_env_file_not_overwritten(self, tmp_project: Path) -> None:
        tmp_project.mkdir(parents=True)
        env_file = tmp_project / ".env"
        env_file.write_text("EXISTING=true\n")
        created = _scaffold_project(
            tmp_project,
            list(AVAILABLE_DOMAINS.keys()),
            "test-project",
        )
        assert ".env" not in created
        assert env_file.read_text() == "EXISTING=true\n"

    def test_main_py_contains_imports(self, tmp_project: Path) -> None:
        tmp_project.mkdir(parents=True)
        _scaffold_project(
            tmp_project,
            list(AVAILABLE_DOMAINS.keys()),
            "test-project",
        )
        content = (tmp_project / "main.py").read_text()
        assert "from admina import GovernedModel" in content


# ── CLI integration ───────────────────────────────────────


class TestInitCommand:
    """Integration tests for ``admina init`` via Click runner."""

    def test_init_full_stack(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init", "myproject", "--full-stack", "--no-pull"])
            assert result.exit_code == 0, result.output
            assert Path("myproject/admina.yaml").exists()
            assert Path("myproject/docker-compose.yml").exists()
            assert Path("myproject/main.py").exists()
            assert Path("myproject/.env").exists()

    def test_init_with_modules(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                app,
                ["init", "proj2", "--modules", "model,data", "--no-pull"],
            )
            assert result.exit_code == 0, result.output
            data = yaml.safe_load(Path("proj2/admina.yaml").read_text())
            assert data["domains"]["ai_infra"]["enabled"] is True
            assert data["domains"]["data_sovereignty"]["enabled"] is True
            assert data["domains"]["compliance"]["enabled"] is False

    def test_init_default_name(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init", "--full-stack", "--no-pull"])
            assert result.exit_code == 0, result.output
            assert Path("my-admina-project/admina.yaml").exists()

    def test_init_prints_next_steps(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["init", "proj3", "--full-stack", "--no-pull"])
            assert "Project ready!" in result.output
            assert "admina dev" in result.output

    def test_init_idempotent(self, runner: CliRunner, tmp_path: Path) -> None:
        """Running init twice should not fail."""
        with runner.isolated_filesystem(temp_dir=tmp_path):
            runner.invoke(app, ["init", "proj4", "--full-stack", "--no-pull"])
            result = runner.invoke(app, ["init", "proj4", "--full-stack", "--no-pull"])
            assert result.exit_code == 0, result.output

    def test_version_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "0.9.2" in result.output
