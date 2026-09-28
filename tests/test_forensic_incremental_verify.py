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

"""Forensic chain verification reads the records one at a time, in sequence
order, and can resume from a checkpoint ``(sequence_number, record_hash)``
returned by an earlier verification, checking only the records after it.
"""

from __future__ import annotations

import asyncio
import time
import tracemalloc

import pytest
from _forensic_chain import flip_byte, record_file, write_chain

from admina.domains.compliance.forensic import ForensicBlackBox


def _box(tmp_path, count: int) -> ForensicBlackBox:
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"))
    for i in range(count):
        box.record({"event_id": f"e{i}", "note": f"note-{i}"})
    return box


def _verify(box: ForensicBlackBox, **kwargs) -> dict:
    return asyncio.run(box.verify_chain(**kwargs))


def test_a_full_verification_returns_a_checkpoint(tmp_path):
    box = _box(tmp_path, 5)
    result = _verify(box)
    assert result["valid"] is True
    assert result["records"] == 5
    assert result["reason"] is None
    assert result["sequence_number"] is None
    assert result["checkpoint"] == {"sequence_number": 5, "record_hash": box.chain_head}
    assert result["last_hash"] == box.chain_head


def test_resuming_from_a_checkpoint_checks_only_the_records_after_it(tmp_path):
    box = _box(tmp_path, 3)
    checkpoint = _verify(box)["checkpoint"]
    for i in range(3, 6):
        box.record({"event_id": f"e{i}", "note": f"note-{i}"})
    # A change before the checkpoint is not read again...
    flip_byte(record_file(tmp_path / "forensic", 2), b"note-1")

    result = _verify(box, checkpoint=(checkpoint["sequence_number"], checkpoint["record_hash"]))
    assert result["valid"] is True
    assert result["records"] == 3
    assert result["checkpoint"] == {"sequence_number": 6, "record_hash": box.chain_head}
    # ...while a full verification finds it.
    full = _verify(box)
    assert (full["valid"], full["reason"], full["sequence_number"]) == (False, "hash_mismatch", 2)


def test_a_change_after_the_checkpoint_is_found(tmp_path):
    box = _box(tmp_path, 3)
    checkpoint = _verify(box)["checkpoint"]
    for i in range(3, 6):
        box.record({"event_id": f"e{i}", "note": f"note-{i}"})
    flip_byte(record_file(tmp_path / "forensic", 5), b"note-4")

    result = _verify(box, checkpoint=(checkpoint["sequence_number"], checkpoint["record_hash"]))
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "hash_mismatch",
        5,
    )


def test_a_checkpoint_that_does_not_match_the_stored_record(tmp_path):
    box = _box(tmp_path, 4)
    result = _verify(box, checkpoint=(2, "0" * 64))
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "checkpoint_mismatch",
        2,
    )


def test_a_checkpoint_at_the_head_with_nothing_after_it(tmp_path):
    box = _box(tmp_path, 4)
    result = _verify(box, checkpoint=(4, box.chain_head))
    assert result["valid"] is True
    assert result["records"] == 0
    assert result["checkpoint"] == {"sequence_number": 4, "record_hash": box.chain_head}


def test_from_seq_verifies_from_that_record_on(tmp_path):
    box = _box(tmp_path, 5)
    flip_byte(record_file(tmp_path / "forensic", 1), b"note-0")
    result = _verify(box, from_seq=3)
    assert result["valid"] is True
    assert result["records"] == 3


def test_a_record_that_does_not_link_to_the_one_before(tmp_path):
    base = tmp_path / "forensic"
    write_chain(base, 6, per_dir=2)
    # Record 4 swapped for record 4 of another chain: its own hash is right.
    other = tmp_path / "other"
    write_chain(other, 6, per_dir=2, padding=10)
    record_file(base, 4).write_bytes(record_file(other, 4).read_bytes())

    result = _verify(ForensicBlackBox(filesystem_dir=str(base)))
    assert (result["valid"], result["reason"], result["sequence_number"]) == (
        False,
        "link_broken",
        4,
    )


def test_records_are_read_in_sequence_order_across_directories(tmp_path):
    base = tmp_path / "forensic"
    head = write_chain(base, 250, per_dir=7)
    box = ForensicBlackBox(filesystem_dir=str(base))
    assert box.record_count == 250
    result = _verify(box)
    assert result["valid"] is True
    assert result["records"] == 250
    assert result["checkpoint"]["record_hash"] == head


def _peak_while_verifying(base) -> tuple[dict, int, float]:
    box = ForensicBlackBox(filesystem_dir=str(base))
    tracemalloc.start()
    try:
        started = time.perf_counter()
        result = _verify(box)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak, elapsed


def test_verification_of_50k_records_stays_in_bounded_memory(tmp_path):
    base = tmp_path / "forensic"
    write_chain(base, 50_000)
    result, peak, _ = _peak_while_verifying(base)
    assert result["valid"] is True
    assert result["records"] == 50_000
    assert peak < 16 * 1024 * 1024, f"peak {peak / 1e6:.1f} MB"


@pytest.mark.benchmark
def test_verification_of_200k_records(tmp_path):
    base = tmp_path / "forensic"
    write_chain(base, 200_000)
    result, peak, elapsed = _peak_while_verifying(base)
    assert result["valid"] is True
    assert result["records"] == 200_000
    assert peak < 16 * 1024 * 1024, f"peak {peak / 1e6:.1f} MB"
    print(f"\n200k records: {elapsed:.1f} s, peak {peak / 1e6:.1f} MB (tracemalloc)")
