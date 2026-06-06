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
        from admina import __version__

        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        # Derive from __version__ so the assertion survives version bumps.
        assert __version__ in result.output


class TestFormatNextSteps:
    """Regression: `admina init` Next steps must adapt to installed extras."""

    def test_next_steps_when_proxy_installed_shows_admina_dev(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from admina.cli import main as cli_main

        monkeypatch.setattr(cli_main, "_proxy_extra_installed", lambda: True)
        out = cli_main._format_next_steps("foo")
        assert "admina dev" in out
        # No upgrade hint when [proxy] is already there.
        assert "pip install 'admina-framework[proxy]'" not in out

    def test_next_steps_when_proxy_missing_omits_admina_dev_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from admina.cli import main as cli_main

        monkeypatch.setattr(cli_main, "_proxy_extra_installed", lambda: False)
        out = cli_main._format_next_steps("foo")
        # No raw "admina dev<space>" command line that pretends to work.
        # The "admina dev" string may still appear in the explanatory text
        # ("To run admina dev, install ..."), but not as a runnable line.
        for line in out.splitlines():
            stripped = line.strip()
            if stripped == "admina dev" or stripped.startswith("admina dev "):
                # Only --stack is acceptable here, and only if docker is around.
                assert stripped.startswith("admina dev --stack"), line
        assert "pip install 'admina-framework[proxy]'" in out

    def test_next_steps_python_main_always_shown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from admina.cli import main as cli_main

        monkeypatch.setattr(cli_main, "_proxy_extra_installed", lambda: False)
        out = cli_main._format_next_steps("foo")
        assert "python main.py" in out


class TestDevRequiresProxyExtra:
    """Regression: `admina dev` local mode must not blow up cryptically when
    [proxy] is missing. It must print an actionable message and exit cleanly.
    """

    def test_require_proxy_extra_exits_with_actionable_message(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from admina.cli import main as cli_main

        monkeypatch.setattr(cli_main, "_proxy_extra_installed", lambda: False)
        with pytest.raises(SystemExit) as excinfo:
            cli_main._require_proxy_extra_for_local_dev()
        assert excinfo.value.code == 1
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert "[proxy]" in combined
        assert "pip install 'admina-framework[proxy]'" in combined
        assert "Traceback" not in combined

    def test_require_proxy_extra_noop_when_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from admina.cli import main as cli_main

        monkeypatch.setattr(cli_main, "_proxy_extra_installed", lambda: True)
        # Must not raise, must not print anything.
        cli_main._require_proxy_extra_for_local_dev()


class TestDoctorFlagsMissingProxy:
    """Regression: `admina doctor` must flag missing [proxy] as a real issue,
    not say 'All checks passed'."""

    def test_doctor_warns_when_proxy_missing(
        self,
        runner: CliRunner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        import builtins

        from admina.cli import main as cli_main

        real_import = builtins.__import__
        blocked = {"fastapi", "uvicorn", "httpx", "redis", "minio", "clickhouse_connect"}

        def fake_import(name: str, *args: object, **kwargs: object) -> object:
            top = name.split(".", 1)[0]
            if top in blocked:
                raise ImportError(f"blocked-by-test: {name}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        # Also override the helper used elsewhere in main.
        monkeypatch.setattr(cli_main, "_proxy_extra_installed", lambda: False)

        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["doctor"])
        assert "[proxy]" in result.output
        assert "All checks passed" not in result.output
        # Doctor should exit non-zero so CI / users notice
        assert result.exit_code != 0
