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

"""Assert all admina artefact versions are aligned.

Run from the repository root.  Exits non-zero (and prints a table) when
any of the tracked manifests disagrees with the canonical version in
``pyproject.toml``.

Tracked points of truth:
    1. pyproject.toml                 →  admina-framework  (canonical)
    2. admina/__init__.py             →  runtime __version__
    3. core-rust/pyproject.toml       →  admina-core       (PyPI)
    4. core-rust/Cargo.toml           →  admina_core crate
    5. core-rust/Cargo.lock           →  resolved admina_core entry
    6. uv.lock                        →  resolved admina-framework entry
    7. core-rust/uv.lock              →  resolved admina-core entry

Docker images and dashboard HTML derive their version dynamically from
pyproject.toml at build time, so they need no separate check here.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _toml_version(path: Path, *, table: str = "project") -> str:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if table == "project":
        return data["project"]["version"]
    if table == "package":
        return data["package"]["version"]
    raise ValueError(f"unknown table {table!r}")


def _python_dunder_version(path: Path) -> str:
    m = re.search(r'__version__\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8"))
    if not m:
        raise RuntimeError(f"__version__ not found in {path}")
    return m.group(1)


def _cargo_lock_admina_core(path: Path) -> str:
    """Pull the `version = "..."` line that follows `name = "admina_core"`."""
    text = path.read_text(encoding="utf-8")
    m = re.search(r'name = "admina_core"\s*\nversion = "([^"]+)"', text)
    if not m:
        raise RuntimeError("admina_core entry not found in Cargo.lock")
    return m.group(1)


def _uv_lock_package(path: Path, pkg: str) -> str:
    """Pull the version of a specific package out of an uv.lock TOML."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for entry in data.get("package", []):
        if entry.get("name") == pkg:
            return entry["version"]
    raise RuntimeError(f"{pkg!r} entry not found in {path}")


def main() -> int:
    versions: dict[str, str] = {
        "pyproject.toml": _toml_version(REPO / "pyproject.toml"),
        "admina/__init__.py": _python_dunder_version(REPO / "admina" / "__init__.py"),
        "uv.lock": _uv_lock_package(REPO / "uv.lock", "admina-framework"),
        "core-rust/pyproject.toml": _toml_version(REPO / "core-rust" / "pyproject.toml"),
        "core-rust/Cargo.toml": _toml_version(REPO / "core-rust" / "Cargo.toml", table="package"),
        "core-rust/Cargo.lock": _cargo_lock_admina_core(REPO / "core-rust" / "Cargo.lock"),
        "core-rust/uv.lock": _uv_lock_package(REPO / "core-rust" / "uv.lock", "admina-core"),
    }

    canonical = versions["pyproject.toml"]
    width = max(len(p) for p in versions)
    print(f"Canonical (pyproject.toml): {canonical}\n")
    print(f"{'File':<{width}}  Version    Status")
    print(f"{'-' * width}  {'-' * 9}  {'-' * 6}")
    drift = []
    for path, ver in versions.items():
        ok = ver == canonical
        status = "OK" if ok else "DRIFT"
        print(f"{path:<{width}}  {ver:<9}  {status}")
        if not ok:
            drift.append(path)

    if drift:
        print(
            f"\nERROR: {len(drift)} file(s) drift from canonical {canonical}: {', '.join(drift)}",
            file=sys.stderr,
        )
        return 1
    print("\nAll versions aligned.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
