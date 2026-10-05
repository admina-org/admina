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
"""Load JSONL corpora and verify their SHA-256 integrity before use.

The packaged corpora are in :data:`CORPORA_DIR`. An external directory
(:func:`load_external_corpora`) holds more corpora in the same format: one
``<name>.jsonl`` per corpus, rows as those of the packaged corpus of the
detector they are for, and a ``SHA256SUMS`` that lists every corpus.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import NamedTuple

CORPORA_DIR = Path(__file__).parent / "corpora"

#: Keys of every row, by detector (the format of the packaged corpora).
ROW_KEYS = {
    "injection": ("id", "text", "label", "lang", "tag"),
    "pii": ("id", "text", "expected_types", "lang", "tag"),
    "loop": ("id", "messages", "label", "lang", "tag"),
}

#: Labels of the rows of the binary detectors.
LABELS = {"injection": ("attack", "benign"), "loop": ("loop", "not_loop")}


class ExternalCorpus(NamedTuple):
    """A corpus of an external directory: the detector it is for, and its rows."""

    detector: str
    rows: list[dict]


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


def _listed(corpora_dir: Path) -> set[str]:
    """The file names that ``SHA256SUMS`` of *corpora_dir* lists.

    Raises:
        ValueError: a line is not ``<sha256>  <file name>``.
    """
    sums = (corpora_dir / "SHA256SUMS").read_text(encoding="utf-8")
    names = set()
    for number, line in enumerate(sums.splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(f"SHA256SUMS of {corpora_dir}, line {number}: not '<sha256>  <file>'")
        names.add(parts[1].strip())
    return names


def detector_for(name: str, rows: list[dict]) -> str:
    """The detector of corpus *name*, from the format of its rows.

    Rows with ``messages`` are for the loop detector, rows with
    ``expected_types`` for the PII detector, other rows for the injection
    detector; every row must then have the keys of :data:`ROW_KEYS`, and a
    label of :data:`LABELS`.

    Raises:
        ValueError: *rows* is empty, or a row does not match the format.
    """
    if not rows:
        raise ValueError(f"corpus {name} is empty")
    first = rows[0]
    if "messages" in first:
        detector = "loop"
    elif "expected_types" in first:
        detector = "pii"
    else:
        detector = "injection"
    for number, row in enumerate(rows, start=1):
        where = f"corpus {name} ({detector}), row {number}"
        if not isinstance(row, dict):
            raise ValueError(f"{where}: not an object")
        missing = [key for key in ROW_KEYS[detector] if key not in row]
        if missing:
            raise ValueError(f"{where}: missing {', '.join(missing)}")
        if detector in LABELS and row["label"] not in LABELS[detector]:
            raise ValueError(
                f"{where}: label {row['label']!r} is not one of {', '.join(LABELS[detector])}"
            )
        if detector == "loop" and not isinstance(row["messages"], list):
            raise ValueError(f"{where}: messages must be a list")
        if detector == "pii" and not isinstance(row["expected_types"], list):
            raise ValueError(f"{where}: expected_types must be a list")
        strings = ("lang", "tag") if detector == "loop" else ("text", "lang", "tag")
        for key in strings:
            if not isinstance(row[key], str):
                raise ValueError(f"{where}: {key} must be a string")
    return detector


def load_external_corpora(corpora_dir: str | Path) -> dict[str, ExternalCorpus]:
    """Every corpus of an external directory, by name (the stem of its
    ``*.jsonl`` file), in name order, with the detector its rows are for
    (:func:`detector_for`).

    ``SHA256SUMS`` must list every ``*.jsonl`` file of the directory; the
    hashes are verified first, as for the packaged corpora.

    Raises:
        ValueError: the directory or its ``SHA256SUMS`` is missing, has no
            corpus, a corpus is not listed, a hash does not match, or a
            row is not valid JSON or does not match the format.
        OSError: a file cannot be read.
    """
    corpora_dir = Path(corpora_dir)
    if not corpora_dir.is_dir():
        raise ValueError(f"corpora directory {corpora_dir} is not a directory")
    if not (corpora_dir / "SHA256SUMS").is_file():
        raise ValueError(f"corpora directory {corpora_dir} has no SHA256SUMS")
    names = sorted(path.stem for path in corpora_dir.glob("*.jsonl"))
    if not names:
        raise ValueError(f"corpora directory {corpora_dir} has no *.jsonl corpus")
    listed = _listed(corpora_dir)
    unlisted = [f"{name}.jsonl" for name in names if f"{name}.jsonl" not in listed]
    if unlisted:
        raise ValueError(f"SHA256SUMS of {corpora_dir} does not list {', '.join(unlisted)}")
    verify_hashes(corpora_dir)
    loaded = {}
    for name in names:
        rows = load_corpus(name, corpora_dir, verify=False)
        loaded[name] = ExternalCorpus(detector_for(name, rows), rows)
    return loaded
