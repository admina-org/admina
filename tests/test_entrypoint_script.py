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

"""The container entrypoint (admina/proxy/docker-entrypoint.sh).

It accepts ADMINA_API_KEY or ADMINA_API_KEY_FILE, prints no character
sequence of the key, stops with the setup instructions when neither is set,
and runs the command it is given.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "admina" / "proxy" / "docker-entrypoint.sh"

# Letters and digits the banner never puts next to each other.
CANARY = "QzX7wK9jQ2xZ8kW3jX5qZ4vJ6"

pytestmark = pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX sh")


def _run(*command: str, **env: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sh", str(SCRIPT), *command],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env},
        capture_output=True,
        text=True,
        timeout=30,
    )


def _fragments(secret: str, shortest: int = 4) -> set[str]:
    return {secret[i:j] for i in range(len(secret)) for j in range(i + shortest, len(secret) + 1)}


def _leaked(output: str) -> set[str]:
    return {f for f in _fragments(CANARY) if f in output}


def test_key_from_the_environment_is_not_printed():
    proc = _run("true", ADMINA_API_KEY=CANARY)
    assert proc.returncode == 0, proc.stderr
    assert _leaked(proc.stdout + proc.stderr) == set()
    assert re.search(r"API key: +set$", proc.stdout, re.MULTILINE)


def test_key_from_a_file_is_not_printed(tmp_path):
    key_file = tmp_path / "admina_api_key"
    key_file.write_text(CANARY + "\n")
    proc = _run("true", ADMINA_API_KEY_FILE=str(key_file))
    assert proc.returncode == 0, proc.stderr
    assert _leaked(proc.stdout + proc.stderr) == set()
    assert re.search(r"API key: +set \(from ADMINA_API_KEY_FILE\)$", proc.stdout, re.MULTILINE)


def test_short_key_is_not_printed():
    proc = _run("true", ADMINA_API_KEY=CANARY[:6])
    assert proc.returncode == 0
    assert CANARY[:4] not in proc.stdout + proc.stderr


def test_without_a_key_it_stops_with_the_setup_instructions():
    proc = _run("true")
    assert proc.returncode == 1
    assert "ADMINA_API_KEY is not set" in proc.stdout
    assert "ADMINA_API_KEY_FILE" in proc.stdout
    assert "bootstrap-secrets.sh" in proc.stdout


def test_empty_values_count_as_unset():
    proc = _run("true", ADMINA_API_KEY="", ADMINA_API_KEY_FILE="")
    assert proc.returncode == 1


def test_the_command_is_run():
    proc = _run("sh", "-c", "echo command-ran; exit 7", ADMINA_API_KEY=CANARY)
    assert proc.returncode == 7
    assert proc.stdout.rstrip().endswith("command-ran")
