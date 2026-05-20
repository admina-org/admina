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

"""Tests for ``admina dev`` CLI command."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from admina.cli.main import (
    AVAILABLE_DOMAINS,
    _check_docker,
    _domains_from_yaml,
    _health_check,
    _load_admina_yaml,
    _maybe_regenerate_compose,
    _wait_for_services,
    app,
)


@pytest.fixture()
def runner() -> CliRunner:
    """Isolated Click test runner."""
    return CliRunner()


def _write_full_stack_yaml(directory: Path) -> Path:
    """Write a valid full-stack admina.yaml and return the path."""
    cfg = {
        "schema_version": 1,
        "domains": {
            "data_sovereignty": {"enabled": True},
            "ai_infra": {"enabled": True},
            "agent_security": {"enabled": True},
            "compliance": {"enabled": True},
        },
        "dashboard": {"enabled": True, "port": 3000},
    }
    yaml_path = directory / "admina.yaml"
    yaml_path.write_text(yaml.dump(cfg))
    return yaml_path


# ── _load_admina_yaml ─────────────────────────────────────


class TestLoadAdminaYaml:
    """Tests for YAML loading."""

    def test_loads_valid_yaml(self, tmp_path: Path) -> None:
        _write_full_stack_yaml(tmp_path)
        data = _load_admina_yaml(tmp_path)
        assert data["schema_version"] == 1
        assert "domains" in data

    def test_missing_yaml_exits(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit, match="1"):
            _load_admina_yaml(tmp_path)


# ── _domains_from_yaml ────────────────────────────────────


class TestDomainsFromYaml:
    """Tests for domain extraction from YAML data."""

    def test_all_enabled(self) -> None:
        data = {
            "domains": {
                "data_sovereignty": {"enabled": True},
                "ai_infra": {"enabled": True},
                "agent_security": {"enabled": True},
                "compliance": {"enabled": True},
            },
        }
        result = _domains_from_yaml(data)
        assert set(result) == set(AVAILABLE_DOMAINS.keys())

    def test_partial_enabled(self) -> None:
        data = {
            "domains": {
                "data_sovereignty": {"enabled": False},
                "ai_infra": {"enabled": False},
                "agent_security": {"enabled": True},
                "compliance": {"enabled": True},
            },
        }
        result = _domains_from_yaml(data)
        assert "agent_security" in result
        assert "compliance" in result
        assert "ai_infra" not in result

    def test_missing_domains_key_returns_empty(self) -> None:
        result = _domains_from_yaml({})
        assert result == []

    def test_invalid_domains_value_returns_all(self) -> None:
        result = _domains_from_yaml({"domains": "invalid"})
        assert set(result) == set(AVAILABLE_DOMAINS.keys())


# ── _maybe_regenerate_compose ─────────────────────────────


class TestMaybeRegenerateCompose:
    """Tests for config-change detection and compose regeneration."""

    def test_generates_on_first_run(self, tmp_path: Path) -> None:
        _write_full_stack_yaml(tmp_path)
        data = _load_admina_yaml(tmp_path)
        regenerated = _maybe_regenerate_compose(tmp_path, data)
        assert regenerated is True
        assert (tmp_path / "docker-compose.yml").exists()
        assert (tmp_path / ".admina_compose_hash").exists()

    def test_skips_when_unchanged(self, tmp_path: Path) -> None:
        _write_full_stack_yaml(tmp_path)
        data = _load_admina_yaml(tmp_path)
        _maybe_regenerate_compose(tmp_path, data)
        regenerated = _maybe_regenerate_compose(tmp_path, data)
        assert regenerated is False

    def test_regenerates_on_config_change(self, tmp_path: Path) -> None:
        _write_full_stack_yaml(tmp_path)
        data = _load_admina_yaml(tmp_path)
        _maybe_regenerate_compose(tmp_path, data)

        # Modify the YAML
        cfg = yaml.safe_load((tmp_path / "admina.yaml").read_text())
        cfg["domains"]["ai_infra"]["enabled"] = False
        (tmp_path / "admina.yaml").write_text(yaml.dump(cfg))
        data2 = _load_admina_yaml(tmp_path)

        regenerated = _maybe_regenerate_compose(tmp_path, data2)
        assert regenerated is True

    def test_generated_compose_is_valid_yaml(self, tmp_path: Path) -> None:
        _write_full_stack_yaml(tmp_path)
        data = _load_admina_yaml(tmp_path)
        _maybe_regenerate_compose(tmp_path, data)
        compose = yaml.safe_load((tmp_path / "docker-compose.yml").read_text())
        assert "services" in compose


# ── _check_docker ─────────────────────────────────────────


class TestCheckDocker:
    """Tests for Docker availability check."""

    @patch("admina.cli.main.shutil.which", return_value="/usr/bin/docker")
    def test_docker_available(self, _mock: MagicMock) -> None:
        assert _check_docker() is True

    @patch("admina.cli.main.shutil.which", return_value=None)
    def test_docker_missing(self, _mock: MagicMock) -> None:
        assert _check_docker() is False


# ── _health_check ─────────────────────────────────────────


class _OKHandler(BaseHTTPRequestHandler):
    """Simple handler that always returns 200."""

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *_args: object) -> None:
        pass  # suppress log noise


class TestHealthCheck:
    """Tests for HTTP health-check polling."""

    def test_healthy_service(self) -> None:
        server = HTTPServer(("127.0.0.1", 0), _OKHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()
        result = _health_check(
            f"http://127.0.0.1:{port}/health",
            timeout=5.0,
            interval=0.1,
        )
        assert result is True
        server.server_close()

    def test_unreachable_service_times_out(self) -> None:
        result = _health_check(
            "http://127.0.0.1:19999/health",
            timeout=0.3,
            interval=0.1,
        )
        assert result is False


# ── _wait_for_services ────────────────────────────────────


class TestWaitForServices:
    """Tests for multi-service health-check orchestration."""

    @patch("admina.cli.main._health_check", return_value=True)
    def test_all_healthy(self, _mock: MagicMock) -> None:
        services = [
            {
                "label": "Proxy",
                "url": "http://localhost:8080",
                "health": "http://localhost:8080/health",
            },
            {
                "label": "Dashboard",
                "url": "http://localhost:3000",
                "health": "http://localhost:3000/",
            },
        ]
        results = _wait_for_services(services, timeout=1.0)
        assert len(results) == 2
        assert all(r["healthy"] for r in results)

    @patch("admina.cli.main._health_check", side_effect=[True, False])
    def test_partial_healthy(self, _mock: MagicMock) -> None:
        services = [
            {
                "label": "Proxy",
                "url": "http://localhost:8080",
                "health": "http://localhost:8080/health",
            },
            {
                "label": "Dashboard",
                "url": "http://localhost:3000",
                "health": "http://localhost:3000/",
            },
        ]
        results = _wait_for_services(services, timeout=1.0)
        assert results[0]["healthy"] is True
        assert results[1]["healthy"] is False


# ── CLI integration ───────────────────────────────────────


class TestDevCommand:
    """Integration tests for ``admina dev`` via Click runner."""

    def test_dev_no_yaml_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["dev"])
            assert result.exit_code != 0
            assert "admina.yaml not found" in (result.output + (result.stderr or ""))

    @patch("admina.cli.main._check_docker", return_value=False)
    def test_dev_no_docker_fails(
        self,
        _mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            _write_full_stack_yaml(Path.cwd())
            # --stack requires Docker; default mode does not.
            result = runner.invoke(app, ["dev", "--stack"])
            assert result.exit_code != 0

    @patch("admina.cli.main.webbrowser.open")
    @patch(
        "admina.cli.main._wait_for_services",
        return_value=[
            {"label": "Dashboard", "url": "http://localhost:3000", "healthy": True},
        ],
    )
    @patch("admina.cli.main.subprocess.run")
    @patch("admina.cli.main._check_docker", return_value=True)
    def test_dev_happy_path(
        self,
        _docker_mock: MagicMock,
        subprocess_mock: MagicMock,
        _health_mock: MagicMock,
        browser_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        subprocess_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            _write_full_stack_yaml(Path.cwd())
            result = runner.invoke(app, ["dev", "--stack", "--detach"])
            assert result.exit_code == 0, result.output
            assert "admina.yaml loaded" in result.output
            browser_mock.assert_called_once_with("http://localhost:3000")

    @patch("admina.cli.main.webbrowser.open")
    @patch(
        "admina.cli.main._wait_for_services",
        return_value=[
            {"label": "Dashboard", "url": "http://localhost:3000", "healthy": True},
        ],
    )
    @patch("admina.cli.main.subprocess.run")
    @patch("admina.cli.main._check_docker", return_value=True)
    def test_dev_no_browser_flag(
        self,
        _docker_mock: MagicMock,
        subprocess_mock: MagicMock,
        _health_mock: MagicMock,
        browser_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        subprocess_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            _write_full_stack_yaml(Path.cwd())
            result = runner.invoke(app, ["dev", "--stack", "--detach", "--no-browser"])
            assert result.exit_code == 0, result.output
            browser_mock.assert_not_called()

    @patch("admina.cli.main.webbrowser.open")
    @patch(
        "admina.cli.main._wait_for_services",
        return_value=[
            {"label": "Dashboard", "url": "http://localhost:3000", "healthy": True},
        ],
    )
    @patch("admina.cli.main.subprocess.run")
    @patch("admina.cli.main._check_docker", return_value=True)
    def test_dev_no_build_flag(
        self,
        _docker_mock: MagicMock,
        subprocess_mock: MagicMock,
        _health_mock: MagicMock,
        _browser_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        subprocess_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            _write_full_stack_yaml(Path.cwd())
            result = runner.invoke(
                app, ["dev", "--stack", "--detach", "--no-build", "--no-browser"]
            )
            assert result.exit_code == 0, result.output
            # Verify --build was NOT passed to docker compose
            call_args = subprocess_mock.call_args_list[0][0][0]
            assert "--build" not in call_args

    @patch("admina.cli.main.subprocess.run")
    @patch("admina.cli.main._check_docker", return_value=True)
    def test_dev_docker_compose_failure(
        self,
        _docker_mock: MagicMock,
        subprocess_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        subprocess_mock.return_value = MagicMock(
            returncode=1,
            stderr="image not found",
            stdout="",
        )
        with runner.isolated_filesystem(temp_dir=tmp_path):
            _write_full_stack_yaml(Path.cwd())
            result = runner.invoke(app, ["dev", "--stack", "--detach"])
            assert result.exit_code != 0

    @patch("admina.cli.main.webbrowser.open")
    @patch(
        "admina.cli.main._wait_for_services",
        return_value=[
            {"label": "Dashboard", "url": "http://localhost:3000", "healthy": True},
        ],
    )
    @patch("admina.cli.main.subprocess.run")
    @patch("admina.cli.main._check_docker", return_value=True)
    def test_dev_prints_summary(
        self,
        _docker_mock: MagicMock,
        subprocess_mock: MagicMock,
        _health_mock: MagicMock,
        _browser_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        subprocess_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            _write_full_stack_yaml(Path.cwd())
            result = runner.invoke(app, ["dev", "--stack", "--detach", "--no-browser"])
            assert result.exit_code == 0, result.output
            assert "development stack is running" in result.output
            assert "docker compose logs -f" in result.output
            assert "docker compose down" in result.output

    @patch("admina.cli.main.webbrowser.open")
    @patch(
        "admina.cli.main._wait_for_services",
        return_value=[
            {"label": "Dashboard", "url": "http://localhost:3000", "healthy": True},
        ],
    )
    @patch("admina.cli.main.subprocess.run")
    @patch("admina.cli.main._check_docker", return_value=True)
    def test_dev_regenerates_compose_on_change(
        self,
        _docker_mock: MagicMock,
        subprocess_mock: MagicMock,
        _health_mock: MagicMock,
        _browser_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        subprocess_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            _write_full_stack_yaml(Path.cwd())
            # First run
            result1 = runner.invoke(app, ["dev", "--stack", "--detach", "--no-browser"])
            assert result1.exit_code == 0
            assert "regenerated" in result1.output

            # Second run without changes
            result2 = runner.invoke(app, ["dev", "--stack", "--detach", "--no-browser"])
            assert result2.exit_code == 0
            assert "up to date" in result2.output
