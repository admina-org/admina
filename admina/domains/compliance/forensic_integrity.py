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
``event``, plus:

- ``record_hash``: the SHA-256, as 64 lowercase hex characters, of
  :func:`canonical_record` — the record without :data:`HASH_EXCLUDED_FIELDS`
  (``record_hash``, ``record_sig``, ``record_sig_alg``), as
  ``json.dumps(..., sort_keys=True, default=str)`` with the default
  separators, encoded as UTF-8;
- ``record_sig``: the HMAC-SHA256, as 64 lowercase hex characters, of the
  ASCII characters of ``record_hash``, under the record signing key
  (:func:`record_signing_key`: HMAC-SHA256 of
  ``b"admina-forensic/1 record signature"`` under the chain-state key,
  ``ADMINA_FORENSIC_STATE_KEY``), with ``record_sig_alg: "hmac-sha256"``;
  a record written without a key has ``record_sig_alg: "none"`` and no
  ``record_sig``.

:func:`verify_entries` checks records one at a time, in sequence order, and
reports the first failure as a reason code and the sequence number of the
record concerned:

- ``hash_mismatch``: the record's bytes are not a JSON object, or its
  ``record_hash`` is not the hash of its content;
- ``link_broken``: its ``previous_hash`` is not the ``record_hash`` of the
  record before it (``GENESIS`` for record 1, the checkpoint's hash for the
  first record after a checkpoint);
- ``missing_record``: there is no record with the next sequence number:
  before the first one found (sequence numbers start at 1), between two
  records, or before the chain state's count;
- ``sequence_gap``: a record's ``sequence_number`` is not the one of its
  file (or key), or a sequence number comes twice or out of order;
- ``state_mismatch``: the record at the chain state's count is not the
  state's head;
- ``checkpoint_mismatch``: the record at the checkpoint's sequence number
  has another ``record_hash``;
- ``signature_invalid``: its ``record_sig`` is not the signature of its
  ``record_hash`` under the key (or ``record_sig_alg`` is unknown);
- ``unsigned``: it has no signature, and the key requires one (from the
  chain state's ``signed_from`` on).

Without the key, signatures are not checked: records with one are counted
as ``signed``, those without as ``unsigned``, and ``signatures_verified`` is
false.

Reasons given by the stores for the chain state (see
:mod:`admina.domains.compliance.forensic`): ``state_missing`` (records but
no chain state), ``state_invalid`` (a chain state that cannot be read, or
whose HMAC does not verify with the key) and ``store_unavailable`` (a
backend that could not be opened).
"""

from __future__ import annotations

import hashlib
import hmac
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
    "RECORD_SIG_ALG",
    "RECORD_SIG_LABEL",
    "RECORD_UNSIGNED",
    "SEQUENCE_GAP",
    "SIGNATURE_INVALID",
    "STATE_INVALID",
    "STATE_MISSING",
    "STORE_UNAVAILABLE",
    "UNSIGNED",
    "ChainReport",
    "canonical_record",
    "compute_record_hash",
    "record_signing_key",
    "sign_record_hash",
    "verify_entries",
]

#: ``previous_hash`` of the first record of a chain.
GENESIS = "GENESIS"

#: Fields left out of the hashed form of a record.
HASH_EXCLUDED_FIELDS: tuple[str, ...] = ("record_hash", "record_sig", "record_sig_alg")

#: ``record_sig_alg`` of a signed record, and of a record written without a key.
RECORD_SIG_ALG = "hmac-sha256"
RECORD_UNSIGNED = "none"

# Reason codes of a failed verification.
HASH_MISMATCH = "hash_mismatch"
LINK_BROKEN = "link_broken"
MISSING_RECORD = "missing_record"
SEQUENCE_GAP = "sequence_gap"
STATE_MISSING = "state_missing"
STATE_INVALID = "state_invalid"
STATE_MISMATCH = "state_mismatch"
CHECKPOINT_MISMATCH = "checkpoint_mismatch"
STORE_UNAVAILABLE = "store_unavailable"
SIGNATURE_INVALID = "signature_invalid"
UNSIGNED = "unsigned"

_HEX64 = re.compile(r"[0-9a-f]{64}")

#: A record to verify: its sequence number and a callable returning its bytes.
RecordEntry = tuple[int, Callable[[], bytes]]


#: Label of the derivation of the record signing key from the state key.
RECORD_SIG_LABEL = b"admina-forensic/1 record signature"


def record_signing_key(state_key: str) -> bytes:
    """The key of the record signatures: HMAC-SHA256 of
    :data:`RECORD_SIG_LABEL` under *state_key* (UTF-8)."""
    return hmac.new(state_key.encode("utf-8"), RECORD_SIG_LABEL, hashlib.sha256).digest()


def sign_record_hash(signing_key: bytes, record_hash: str) -> str:
    """``record_sig``: HMAC-SHA256 of *record_hash* (its ASCII hex
    characters) under *signing_key*, 64 lowercase hex characters."""
    return hmac.new(signing_key, record_hash.encode("ascii"), hashlib.sha256).hexdigest()


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
    — None when the verification failed or found no record. ``signed`` and
    ``unsigned``: the records checked with and without a signature;
    ``signatures_verified``: whether the signatures were checked (a key was
    given).
    """

    valid: bool = True
    records: int = 0
    reason: str | None = None
    sequence_number: int | None = None
    checkpoint: tuple[int, str] | None = None
    signed: int = 0
    unsigned: int = 0
    signatures_verified: bool = False

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
            "signed": self.signed,
            "unsigned": self.unsigned,
            "signatures_verified": self.signatures_verified,
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


def _signature_error(
    record: dict[str, Any], seq: int, signing_key: bytes | None, signed_from: int | None
) -> str | None:
    """The reason code of *record*'s signature, or None when it is fine."""
    sig = record.get("record_sig")
    alg = record.get("record_sig_alg")
    if sig is None and alg in (None, RECORD_UNSIGNED):
        required = signing_key is not None and signed_from is not None and seq >= signed_from
        return UNSIGNED if required else None
    if alg != RECORD_SIG_ALG or not isinstance(sig, str):
        return SIGNATURE_INVALID
    if signing_key is not None and not hmac.compare_digest(
        sig, sign_record_hash(signing_key, record["record_hash"])
    ):
        return SIGNATURE_INVALID
    return None


def verify_entries(
    entries: Iterable[RecordEntry],
    *,
    from_seq: int = 1,
    checkpoint: tuple[int, str] | None = None,
    state: tuple[int, str] | None = None,
    signing_key: bytes | None = None,
    signed_from: int | None = None,
) -> ChainReport:
    """Verify the records of *entries*, in order, one at a time.

    *entries* yields ``(sequence_number, load)`` in sequence order, from
    *from_seq* on — from the checkpoint's own record when *checkpoint*
    ``(sequence_number, record_hash)`` is given, then only the records
    after it are checked, the first against the checkpoint's hash. Without
    a checkpoint, record 1 links to ``GENESIS`` and the first record of a
    range that starts later is not linked to anything. The sequence
    numbers must follow one another from the first one expected.

    *state* ``(record_count, chain_head)``: the chain state. The records
    must reach its count, and the record at that count must be its head,
    whenever that record is in the range checked. Records after it are
    checked like any other.

    *signing_key* (:func:`record_signing_key`): check the signatures; the
    records from *signed_from* on must have one.
    """
    report = ChainReport(signatures_verified=signing_key is not None)
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
    expected = lower + 1 if checkpoint is not None else lower

    for seq, load in iterator:
        if seq > expected:
            return report.fail(MISSING_RECORD, expected)
        if seq < expected:
            return report.fail(SEQUENCE_GAP, seq)
        try:
            record = _load(load)
        except FileNotFoundError:
            return report.fail(MISSING_RECORD, seq)
        if record is None or not _hash_ok(record):
            return report.fail(HASH_MISMATCH, seq)
        if record.get("sequence_number") != seq:
            return report.fail(SEQUENCE_GAP, seq)
        if previous is not None and record.get("previous_hash") != previous:
            return report.fail(LINK_BROKEN, seq)
        error = _signature_error(record, seq, signing_key, signed_from)
        if error is not None:
            return report.fail(error, seq)
        if record.get("record_sig") is None:
            report.unsigned += 1
        else:
            report.signed += 1
        previous = record["record_hash"]
        report.records += 1
        report.checkpoint = (seq, previous)
        expected += 1
        if seq == count:
            at_count = previous

    if count > 0 and count >= lower:
        if expected <= count:
            return report.fail(MISSING_RECORD, expected)
        if at_count != head:
            return report.fail(STATE_MISMATCH, count)
    return report
