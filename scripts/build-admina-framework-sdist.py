#!/usr/bin/env python3

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

"""Build the last admina-framework release: a source distribution that
stops its installation with the commands to switch to ``admina``.

Usage (from the repository root)::

    python scripts/build-admina-framework-sdist.py dist-framework/

The version is the one of ``pyproject.toml``. The archive holds
``PKG-INFO`` (with ``packaging/admina-framework/README.md`` as the
description), a ``pyproject.toml`` that names the setuptools backend, and
``packaging/admina-framework/setup.py``, which raises ``SystemExit`` with the
message: pip and uv run it before they change the installed packages.
"""

from __future__ import annotations

import io
import sys
import tarfile
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_PYPROJECT = """[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"
"""


def pkg_info(version: str, description: str) -> str:
    """The core metadata of the release."""
    return (
        "Metadata-Version: 2.4\n"
        "Name: admina-framework\n"
        f"Version: {version}\n"
        "Summary: Admina is published as admina: this release cannot be installed\n"
        "Project-URL: Homepage, https://pypi.org/project/admina/\n"
        "Project-URL: Repository, https://github.com/admina-org/admina\n"
        "License-Expression: Apache-2.0\n"
        "Requires-Python: >=3.11\n"
        "Description-Content-Type: text/markdown\n"
        "\n"
        f"{description}"
    )


def build(out_dir: Path, repo: Path = REPO) -> Path:
    """Write ``admina_framework-<version>.tar.gz`` into *out_dir*."""
    version = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "version"
    ]
    sources = repo / "packaging" / "admina-framework"
    top = f"admina_framework-{version}"
    files = {
        "PKG-INFO": pkg_info(version, (sources / "README.md").read_text(encoding="utf-8")),
        "pyproject.toml": _PYPROJECT,
        "setup.py": (sources / "setup.py").read_text(encoding="utf-8"),
        "README.md": (sources / "README.md").read_text(encoding="utf-8"),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{top}.tar.gz"
    with tarfile.open(target, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, text in files.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return target


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: build-admina-framework-sdist.py OUT_DIR")
    print(build(Path(sys.argv[1])))
