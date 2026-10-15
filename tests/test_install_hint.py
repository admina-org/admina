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


"""Install hints name uv first and pip as the alternative, and
``admina plugin install`` installs with uv when it is on PATH."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from admina.core.install_hint import install_hint


def test_hint_names_uv_then_pip():
    assert install_hint("chromadb") == "uv pip install chromadb (or pip install chromadb)"


def test_hint_quotes_extras_and_keeps_upgrade():
    assert install_hint("admina[proxy]", upgrade=True) == (
        "uv pip install 'admina[proxy]' --upgrade (or pip install 'admina[proxy]' --upgrade)"
    )


def test_plugin_install_uses_uv_when_available():
    from admina.cli import main

    with (
        patch("admina.cli.main.shutil.which", return_value="/usr/bin/uv"),
        patch("admina.cli.main.subprocess.run") as run,
    ):
        run.return_value = MagicMock(returncode=0)
        main._install_package("admina-adapter-x")
    assert run.call_args.args[0] == [
        "/usr/bin/uv",
        "pip",
        "install",
        "--python",
        sys.executable,
        "admina-adapter-x",
    ]


def test_plugin_install_falls_back_to_pip():
    from admina.cli import main

    with (
        patch("admina.cli.main.shutil.which", return_value=None),
        patch("admina.cli.main.subprocess.run") as run,
    ):
        run.return_value = MagicMock(returncode=0)
        main._install_package("admina-adapter-x")
    assert run.call_args.args[0] == [sys.executable, "-m", "pip", "install", "admina-adapter-x"]
