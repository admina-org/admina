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

"""The ``admina`` alias package (``packaging/admina``) mirrors admina-framework.

``pip install admina[X]`` installs ``admina-framework[X]`` at the same
version, for every extra X of admina-framework, and the alias ships no
module of its own (``import admina`` comes from admina-framework only).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _project(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


ROOT = _project(REPO / "pyproject.toml")
ALIAS = _project(REPO / "packaging" / "admina" / "pyproject.toml")


def test_the_alias_installs_admina_framework_at_its_version():
    version = ROOT["project"]["version"]
    assert ALIAS["project"]["name"] == "admina"
    assert ALIAS["project"]["version"] == version
    assert ALIAS["project"]["dependencies"] == [f"admina-framework=={version}"]


def test_every_extra_of_admina_framework_has_an_alias_extra():
    version = ROOT["project"]["version"]
    expected = {
        extra: [f"admina-framework[{extra}]=={version}"]
        for extra in ROOT["project"]["optional-dependencies"]
    }
    assert ALIAS["project"]["optional-dependencies"] == expected


def test_the_alias_ships_no_module():
    assert ALIAS["tool"]["setuptools"]["packages"] == []
    assert ALIAS["project"]["requires-python"] == ROOT["project"]["requires-python"]
