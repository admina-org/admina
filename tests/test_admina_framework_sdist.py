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

"""The last admina-framework release (``scripts/build-admina-framework-sdist.py``).

A source distribution named after the version of ``pyproject.toml`` whose
``setup.py`` stops the installation with the commands to switch to
``admina``.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tarfile
import tomllib
from email.parser import Parser
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _build(out_dir: Path) -> Path:
    spec = importlib.util.spec_from_file_location(
        "build_admina_framework_sdist", REPO / "scripts" / "build-admina-framework-sdist.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build(out_dir)


def test_the_archive_is_named_and_laid_out_as_an_sdist(tmp_path):
    archive = _build(tmp_path)
    top = f"admina_framework-{VERSION}"
    assert archive.name == f"{top}.tar.gz"
    with tarfile.open(archive) as tar:
        names = sorted(tar.getnames())
    assert names == sorted(
        f"{top}/{name}" for name in ("PKG-INFO", "pyproject.toml", "setup.py", "README.md")
    )


def test_the_metadata_names_admina_framework_at_the_project_version(tmp_path):
    archive = _build(tmp_path)
    with tarfile.open(archive) as tar:
        raw = tar.extractfile(f"admina_framework-{VERSION}/PKG-INFO").read().decode()
    meta = Parser().parsestr(raw)
    assert meta["Name"] == "admina-framework"
    assert meta["Version"] == VERSION
    assert meta["Description-Content-Type"] == "text/markdown"
    assert "pip install admina" in meta.get_payload()


def test_setup_py_stops_with_the_commands_to_switch(tmp_path):
    archive = _build(tmp_path)
    with tarfile.open(archive) as tar:
        tar.extractall(tmp_path, filter="data")
    result = subprocess.run(
        [sys.executable, "setup.py", "egg_info"],
        cwd=tmp_path / f"admina_framework-{VERSION}",
        capture_output=True,
        text=True,
        check=False,
        # Only PATH: no coverage variables, so the subprocess writes no data
        # file outside the configuration of the repository.
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert result.returncode != 0
    assert "admina-framework is now published as admina" in result.stderr
    assert "pip uninstall -y admina admina-framework && pip install admina" in result.stderr
