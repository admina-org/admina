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

"""Tests for the forensic hash-chain check in ``admina doctor``."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from admina.cli.main import app


@pytest.fixture()
def runner() -> CliRunner:
    """Isolated Click test runner."""
    return CliRunner()


class TestDoctorForensicCheck:
    """Forensic chain section of ``admina doctor``."""

    def test_filesystem_valid_chain_prints_ok(self, tmp_path: Path, runner: CliRunner) -> None:
        """With a valid filesystem chain, doctor prints a passing forensic line."""
        from admina.domains.compliance.forensic import ForensicBlackBox

        forensic_dir = tmp_path / "forensic"
        fbox = ForensicBlackBox(filesystem_dir=str(forensic_dir))
        fbox.record({"event": "e1", "session_id": "s1"})
        fbox.record({"event": "e2", "session_id": "s1"})

        result = runner.invoke(
            app,
            ["doctor"],
            env={
                "FORENSIC_BACKEND": "filesystem",
                "FORENSIC_BASE_DIR": str(forensic_dir),
                # Suppress env-var warnings that would add issues and exit 1
                "ADMINA_API_KEY": "test-key-for-doctor",
            },
            catch_exceptions=False,
        )
        assert "Forensic chain" in result.output
        assert "[OK]" in result.output or "valid" in result.output

    def test_memory_backend_prints_neutral_line(self, runner: CliRunner) -> None:
        """With memory backend (default), doctor prints a neutral dash line."""
        result = runner.invoke(
            app,
            ["doctor"],
            env={
                "FORENSIC_BACKEND": "memory",
                "ADMINA_API_KEY": "test-key-for-doctor",
            },
            catch_exceptions=False,
        )
        assert "Forensic chain" in result.output
        assert "memory" in result.output or "--" in result.output

    def test_unset_backend_prints_neutral_line(self, runner: CliRunner) -> None:
        """With no FORENSIC_BACKEND env var, doctor prints the neutral dash line."""
        result = runner.invoke(
            app,
            ["doctor"],
            env={
                "ADMINA_API_KEY": "test-key-for-doctor",
            },
            catch_exceptions=False,
        )
        assert "Forensic chain" in result.output
        # Should show the not-configured neutral line (-- or 'memory')
        output = result.output
        assert "memory" in output or "--" in output

    def test_filesystem_tampered_chain_prints_fail(self, tmp_path: Path, runner: CliRunner) -> None:
        """With a tampered filesystem chain, doctor prints a failing forensic line."""
        from admina.domains.compliance.forensic import ForensicBlackBox

        forensic_dir = tmp_path / "forensic"
        fbox = ForensicBlackBox(filesystem_dir=str(forensic_dir))
        fbox.record({"event": "e1", "session_id": "s1"})
        fbox.record({"event": "e2", "session_id": "s1"})

        # Tamper: delete one record file
        record_files = [p for p in forensic_dir.rglob("*.json") if p.name != "_chain_state.json"]
        assert record_files, "Expected at least one record file"
        record_files[0].unlink()

        result = runner.invoke(
            app,
            ["doctor"],
            env={
                "FORENSIC_BACKEND": "filesystem",
                "FORENSIC_BASE_DIR": str(forensic_dir),
                "ADMINA_API_KEY": "test-key-for-doctor",
            },
            catch_exceptions=False,
        )
        assert "Forensic chain" in result.output
        assert "[FAIL]" in result.output or "FAILED" in result.output
