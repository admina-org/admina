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

"""Tests for the Heimdall banner of the ``admina`` CLI."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from admina import __version__
from admina.cli import main as cli_main
from admina.cli.main import app


@pytest.fixture()
def runner() -> CliRunner:
    """Isolated Click test runner."""
    return CliRunner()


def test_no_arguments_prints_banner_and_help(runner: CliRunner, monkeypatch) -> None:
    monkeypatch.delenv("ADMINA_NO_BANNER", raising=False)
    result = runner.invoke(app, [], prog_name="admina", env={"NO_COLOR": "1"})
    assert result.exit_code == 0
    lines = result.output.splitlines()
    assert lines[0] == f" (O,O)  Admina {__version__}"
    assert lines[1] == " /)_)   governed AI development framework"
    assert "Usage: admina" in result.output


def test_no_banner_env_keeps_help_only(runner: CliRunner) -> None:
    result = runner.invoke(app, [], prog_name="admina", env={"ADMINA_NO_BANNER": "1"})
    assert result.exit_code == 0
    assert "(O,O)" not in result.output
    assert result.output.startswith("Usage: admina")


def test_help_and_version_have_no_banner(runner: CliRunner) -> None:
    assert "(O,O)" not in runner.invoke(app, ["--help"]).output
    assert runner.invoke(app, ["--version"]).output.startswith("admina, version")


def test_no_color_disables_styling(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b[" not in cli_main._banner()


@pytest.mark.parametrize(
    ("args", "tty", "env", "expected"),
    [
        (["doctor"], True, {}, True),
        (["doctor"], False, {}, False),
        (["doctor"], True, {"ADMINA_NO_BANNER": "1"}, False),
        (["doctor", "--help"], True, {}, False),
        (["forensic", "verify", "--json"], True, {}, False),
    ],
)
def test_compact_banner_conditions(monkeypatch, args, tty, env, expected) -> None:
    monkeypatch.delenv("ADMINA_NO_BANNER", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cli_main.sys.stderr, "isatty", lambda: tty)
    assert cli_main._compact_banner_enabled(args) is expected
