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
"""Load JSONL corpora and verify their SHA-256 integrity before use."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

CORPORA_DIR = Path(__file__).parent / "corpora"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_hashes(corpora_dir: Path = CORPORA_DIR) -> None:
    """Raise ValueError if any file listed in SHA256SUMS does not match its hash."""
    sums_path = corpora_dir / "SHA256SUMS"
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, name = line.split(maxsplit=1)
        actual = sha256_file(corpora_dir / name.strip())
        if actual != digest:
            raise ValueError(f"corpus hash mismatch for {name.strip()}")


def load_corpus(name: str, corpora_dir: Path = CORPORA_DIR, verify: bool = True) -> list[dict]:
    """Load one corpus (e.g. "injection") as a list of row dicts, verifying hashes first."""
    if verify:
        verify_hashes(corpora_dir)
    path = corpora_dir / f"{name}.jsonl"
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows
