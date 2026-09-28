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

"""Hashing and verification of forensic records (format ``admina-forensic/1``).

A record is a JSON object with ``sequence_number`` (from 1),
``timestamp_utc``, ``timestamp_unix_ms``, ``previous_hash`` (``GENESIS`` for
the first record, else the ``record_hash`` of the record before) and
``event``, plus ``record_hash``: the SHA-256, as 64 lowercase hex characters,
of :func:`canonical_record` — the record without
:data:`HASH_EXCLUDED_FIELDS`, as ``json.dumps(..., sort_keys=True,
default=str)`` with the default separators, encoded as UTF-8.

:func:`verify_entries` checks records one at a time, in sequence order, and
reports the first failure as a reason code and the sequence number of the
record concerned:

- ``hash_mismatch``: the record's bytes are not a JSON object, or its
  ``record_hash`` is not the hash of its content;
- ``link_broken``: its ``previous_hash`` is not the ``record_hash`` of the
  record before it (``GENESIS`` for record 1, the checkpoint's hash for the
  first record after a checkpoint);
- ``missing_record``: a record that must exist cannot be found;
- ``state_mismatch``: the records do not reach the chain state's count, or
  the record at that count is not the state's head;
- ``checkpoint_mismatch``: the record at the checkpoint's sequence number
  has another ``record_hash``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

__all__ = [
    "CHECKPOINT_MISMATCH",
    "GENESIS",
    "HASH_EXCLUDED_FIELDS",
    "HASH_MISMATCH",
    "LINK_BROKEN",
    "MISSING_RECORD",
    "STATE_MISMATCH",
    "ChainReport",
    "canonical_record",
    "compute_record_hash",
    "verify_entries",
]

#: ``previous_hash`` of the first record of a chain.
GENESIS = "GENESIS"

#: Fields left out of the hashed form of a record.
HASH_EXCLUDED_FIELDS: tuple[str, ...] = ("record_hash",)

# Reason codes of a failed verification.
HASH_MISMATCH = "hash_mismatch"
LINK_BROKEN = "link_broken"
MISSING_RECORD = "missing_record"
STATE_MISMATCH = "state_mismatch"
CHECKPOINT_MISMATCH = "checkpoint_mismatch"

_HEX64 = re.compile(r"[0-9a-f]{64}")

#: A record to verify: its sequence number and a callable returning its bytes.
RecordEntry = tuple[int, Callable[[], bytes]]


def canonical_record(record: dict[str, Any]) -> str:
    """The hashed form of *record*: ``json.dumps`` of the record without
    :data:`HASH_EXCLUDED_FIELDS`, keys sorted, default separators,
    ``default=str``."""
    hashed = {k: v for k, v in record.items() if k not in HASH_EXCLUDED_FIELDS}
    return json.dumps(hashed, sort_keys=True, default=str)


def compute_record_hash(record: dict[str, Any]) -> str:
    """``record_hash`` of *record*: SHA-256 of :func:`canonical_record`
    (UTF-8), 64 lowercase hex characters."""
    return hashlib.sha256(canonical_record(record).encode("utf-8")).hexdigest()


@dataclass
class ChainReport:
    """Outcome of a verification.

    ``records``: the records checked (the checkpoint's own record is not
    counted); ``reason`` and ``sequence_number``: the first failure;
    ``checkpoint``: ``(sequence_number, record_hash)`` of the last record
    checked (or the checkpoint given, when none follows it), to resume from
    — None when the verification failed or found no record.
    """

    valid: bool = True
    records: int = 0
    reason: str | None = None
    sequence_number: int | None = None
    checkpoint: tuple[int, str] | None = None

    def fail(self, reason: str, sequence_number: int | None) -> ChainReport:
        self.valid = False
        self.reason = reason
        self.sequence_number = sequence_number
        self.checkpoint = None
        return self

    def as_dict(self) -> dict[str, Any]:
        checkpoint = None
        if self.checkpoint is not None:
            checkpoint = {
                "sequence_number": self.checkpoint[0],
                "record_hash": self.checkpoint[1],
            }
        return {
            "valid": self.valid,
            "records": self.records,
            "reason": self.reason,
            "sequence_number": self.sequence_number,
            "checkpoint": checkpoint,
        }


def _load(load: Callable[[], bytes]) -> dict[str, Any] | None:
    """The record returned by *load*, or None when it is not a JSON object.
    Raises FileNotFoundError when it is gone."""
    data = load()
    try:
        record = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    return record if isinstance(record, dict) else None


def _hash_ok(record: dict[str, Any]) -> bool:
    stored = record.get("record_hash")
    return (
        isinstance(stored, str)
        and _HEX64.fullmatch(stored) is not None
        and compute_record_hash(record) == stored
    )


def verify_entries(
    entries: Iterable[RecordEntry],
    *,
    from_seq: int = 1,
    checkpoint: tuple[int, str] | None = None,
    state: tuple[int, str] | None = None,
) -> ChainReport:
    """Verify the records of *entries*, in order, one at a time.

    *entries* yields ``(sequence_number, load)`` in sequence order, from
    *from_seq* on — from the checkpoint's own record when *checkpoint*
    ``(sequence_number, record_hash)`` is given, then only the records
    after it are checked, the first against the checkpoint's hash. Without
    a checkpoint, record 1 links to ``GENESIS`` and the first record of a
    range that starts later is not linked to anything.

    *state* ``(record_count, chain_head)``: the chain state. The records
    must reach its count, and the record at that count must be its head,
    whenever that record is in the range checked. Records after it are
    checked like any other.
    """
    report = ChainReport()
    iterator = iter(entries)
    at_count: str | None = None
    count, head = state if state is not None else (0, "")
    if checkpoint is not None:
        lower = checkpoint[0]
        previous: str | None = checkpoint[1]
        first = next(iterator, None)
        if first is None or first[0] != lower:
            return report.fail(MISSING_RECORD, lower)
        try:
            record = _load(first[1])
        except FileNotFoundError:
            return report.fail(MISSING_RECORD, lower)
        if record is None or record.get("record_hash") != checkpoint[1]:
            return report.fail(CHECKPOINT_MISMATCH, lower)
        report.checkpoint = checkpoint
        if lower == count:
            at_count = checkpoint[1]
    else:
        lower = from_seq
        previous = GENESIS if from_seq == 1 else None

    for seq, load in iterator:
        try:
            record = _load(load)
        except FileNotFoundError:
            return report.fail(MISSING_RECORD, seq)
        if record is None or not _hash_ok(record):
            return report.fail(HASH_MISMATCH, seq)
        if previous is not None and record.get("previous_hash") != previous:
            return report.fail(LINK_BROKEN, seq)
        previous = record["record_hash"]
        report.records += 1
        report.checkpoint = (seq, previous)
        if seq == count:
            at_count = previous

    if count > 0 and count >= lower:
        last = report.checkpoint[0] if report.checkpoint is not None else lower - 1
        if last < count or at_count != head:
            return report.fail(STATE_MISMATCH, count)
    return report
