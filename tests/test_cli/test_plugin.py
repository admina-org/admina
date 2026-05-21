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

"""Tests for ``admina plugin`` CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from admina.cli.main import (
    PLUGIN_TYPE_CHOICES,
    _scaffold_plugin,
    app,
)


@pytest.fixture()
def runner() -> CliRunner:
    """Isolated Click test runner."""
    return CliRunner()


# ── _scaffold_plugin ──────────────────────────────────────


class TestScaffoldPlugin:
    """Tests for plugin boilerplate generation."""

    def test_creates_all_files(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "my-plugin"
        created = _scaffold_plugin("my-plugin", "model_adapter", output_dir)
        assert "my_plugin.py" in created
        assert "tests/test_my_plugin.py" in created
        assert "pyproject.toml" in created
        assert "README.md" in created
        for f in created:
            assert (output_dir / f).exists()

    def test_plugin_module_has_base_import(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "test-adapter"
        _scaffold_plugin("test-adapter", "model_adapter", output_dir)
        content = (output_dir / "test_adapter.py").read_text()
        assert "from admina.plugins.base import BaseModelAdapter" in content
        assert "class TestAdapter(BaseModelAdapter):" in content

    def test_plugin_test_has_import(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "test-adapter"
        _scaffold_plugin("test-adapter", "model_adapter", output_dir)
        content = (output_dir / "tests" / "test_test_adapter.py").read_text()
        assert "from test_adapter import TestAdapter" in content

    def test_pyproject_has_name(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "my-plugin"
        _scaffold_plugin("my-plugin", "model_adapter", output_dir)
        content = (output_dir / "pyproject.toml").read_text()
        assert 'name = "my-plugin"' in content

    @pytest.mark.parametrize("plugin_type", PLUGIN_TYPE_CHOICES)
    def test_all_types_scaffold(self, tmp_path: Path, plugin_type: str) -> None:
        output_dir = tmp_path / f"test-{plugin_type}"
        created = _scaffold_plugin(f"test-{plugin_type}", plugin_type, output_dir)
        assert len(created) == 4
        # Plugin module should exist and be non-empty
        py_file = output_dir / f"test_{plugin_type}.py"
        assert py_file.exists()
        assert len(py_file.read_text()) > 100

    def test_compliance_template_has_framework_name(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "gdpr-checker"
        _scaffold_plugin("gdpr-checker", "compliance_template", output_dir)
        content = (output_dir / "gdpr_checker.py").read_text()
        assert "framework_name" in content
        assert "BaseComplianceTemplate" in content

    def test_forensic_store_has_store_name(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "s3-store"
        _scaffold_plugin("s3-store", "forensic_store", output_dir)
        content = (output_dir / "s3_store.py").read_text()
        assert "store_name" in content
        assert "BaseForensicStore" in content

    def test_class_name_conversion(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "my-custom-adapter"
        _scaffold_plugin("my-custom-adapter", "model_adapter", output_dir)
        content = (output_dir / "my_custom_adapter.py").read_text()
        assert "class MyCustomAdapter" in content


# ── admina plugin install ─────────────────────────────────


class TestPluginInstall:
    """Tests for ``admina plugin install``."""

    @patch("admina.cli.main._pip_install")
    def test_install_success(
        self,
        pip_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        pip_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["plugin", "install", "admina-adapter-bedrock"])
            assert result.exit_code == 0, result.output
            assert "Installed admina-adapter-bedrock" in result.output

    @patch("admina.cli.main._pip_install")
    def test_install_failure(
        self,
        pip_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        pip_mock.return_value = MagicMock(
            returncode=1,
            stderr="Package not found",
            stdout="",
        )
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["plugin", "install", "nonexistent-pkg"])
            assert result.exit_code != 0

    @patch("admina.cli.main._pip_install")
    def test_install_updates_admina_yaml(
        self,
        pip_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        pip_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            # Create admina.yaml
            yaml_path = Path("admina.yaml")
            yaml_path.write_text(yaml.dump({"version": "2.0", "plugins": []}))

            result = runner.invoke(app, ["plugin", "install", "admina-adapter-bedrock"])
            assert result.exit_code == 0, result.output
            assert "Added admina_adapter_bedrock to admina.yaml" in result.output

            # Verify YAML was updated
            data = yaml.safe_load(yaml_path.read_text())
            assert "admina_adapter_bedrock" in data["plugins"]

    @patch("admina.cli.main._pip_install")
    def test_install_no_duplicate_in_yaml(
        self,
        pip_mock: MagicMock,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        pip_mock.return_value = MagicMock(returncode=0, stderr="", stdout="")
        with runner.isolated_filesystem(temp_dir=tmp_path):
            yaml_path = Path("admina.yaml")
            yaml_path.write_text(
                yaml.dump(
                    {
                        "version": "2.0",
                        "plugins": ["admina_adapter_bedrock"],
                    }
                )
            )

            result = runner.invoke(app, ["plugin", "install", "admina-adapter-bedrock"])
            assert result.exit_code == 0
            data = yaml.safe_load(yaml_path.read_text())
            assert data["plugins"].count("admina_adapter_bedrock") == 1


# ── admina plugin list ────────────────────────────────────


class TestPluginList:
    """Tests for ``admina plugin list``."""

    @patch("admina.cli.main._discover_and_list_plugins")
    def test_list_with_plugins(
        self,
        discover_mock: MagicMock,
        runner: CliRunner,
    ) -> None:
        class FakeAdapter:
            __module__ = "admina.plugins.builtin.adapters.ollama"

        discover_mock.return_value = {
            "model_adapter": {"ollama": FakeAdapter},
            "data_connector": {},
            "governance_guard": {},
            "compliance_template": {},
            "transport_adapter": {},
            "forensic_store": {},
            "auth_provider": {},
            "pii_engine": {},
            "alert_channel": {},
        }
        result = runner.invoke(app, ["plugin", "list"])
        assert result.exit_code == 0, result.output
        assert "ollama" in result.output
        assert "Model Adapter" in result.output
        assert "Total: 1 plugin(s)" in result.output

    @patch("admina.cli.main._discover_and_list_plugins")
    def test_list_empty(
        self,
        discover_mock: MagicMock,
        runner: CliRunner,
    ) -> None:
        discover_mock.return_value = {k: {} for k in PLUGIN_TYPE_CHOICES}
        result = runner.invoke(app, ["plugin", "list"])
        assert result.exit_code == 0
        assert "No plugins found" in result.output

    @patch("admina.cli.main._discover_and_list_plugins")
    def test_list_multiple_types(
        self,
        discover_mock: MagicMock,
        runner: CliRunner,
    ) -> None:
        class FakeAdapter:
            __module__ = "fake.adapters.ollama"

        class FakeAlert:
            __module__ = "fake.alerts.log"

        discover_mock.return_value = {
            "model_adapter": {"ollama": FakeAdapter},
            "data_connector": {},
            "governance_guard": {},
            "compliance_template": {},
            "transport_adapter": {},
            "forensic_store": {},
            "auth_provider": {},
            "pii_engine": {},
            "alert_channel": {"log": FakeAlert},
        }
        result = runner.invoke(app, ["plugin", "list"])
        assert result.exit_code == 0
        assert "Total: 2 plugin(s)" in result.output


# ── admina plugin create ──────────────────────────────────


class TestPluginCreate:
    """Tests for ``admina plugin create``."""

    def test_create_default_type(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["plugin", "create", "my-adapter"])
            assert result.exit_code == 0, result.output
            assert Path("my-adapter/my_adapter.py").exists()
            assert Path("my-adapter/pyproject.toml").exists()
            assert Path("my-adapter/tests/test_my_adapter.py").exists()
            assert Path("my-adapter/README.md").exists()

    def test_create_with_type(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                app,
                ["plugin", "create", "my-store", "--type", "forensic_store"],
            )
            assert result.exit_code == 0, result.output
            content = Path("my-store/my_store.py").read_text()
            assert "BaseForensicStore" in content
            assert "store_name" in content

    def test_create_existing_nonempty_dir_fails(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            Path("existing-plugin").mkdir()
            (Path("existing-plugin") / "file.txt").write_text("content")
            result = runner.invoke(app, ["plugin", "create", "existing-plugin"])
            assert result.exit_code != 0

    def test_create_prints_next_steps(self, runner: CliRunner, tmp_path: Path) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(app, ["plugin", "create", "my-plugin"])
            assert result.exit_code == 0
            assert "Next steps:" in result.output
            assert "admina plugin list" in result.output

    @pytest.mark.parametrize("plugin_type", PLUGIN_TYPE_CHOICES)
    def test_create_all_types(
        self,
        runner: CliRunner,
        tmp_path: Path,
        plugin_type: str,
    ) -> None:
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                app,
                [
                    "plugin",
                    "create",
                    f"test-{plugin_type.replace('_', '-')}",
                    "--type",
                    plugin_type,
                ],
            )
            assert result.exit_code == 0, result.output
