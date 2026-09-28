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

"""What happens when a forensic record cannot be written.

The store's fail mode: ``open`` (the default) logs the failure and goes on
without the record; ``closed`` raises :class:`ForensicWriteError`. Either
way the chain does not advance past a record that was not written.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os

import pytest
from _forensic_chain import record_files

from admina.domains.compliance.forensic import ForensicBlackBox, ForensicWriteError

root_only = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root writes to any directory"
)


def _no_space(monkeypatch) -> None:
    """Every fsync fails as on a full disk."""

    def fsync(fd: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "fsync", fsync)


# ── Store ─────────────────────────────────────────────────────


def test_fail_mode_defaults_to_open(tmp_path):
    assert ForensicBlackBox(filesystem_dir=str(tmp_path)).fail_mode == "open"


def test_an_unknown_fail_mode_is_an_error(tmp_path):
    with pytest.raises(ValueError, match="fail_mode"):
        ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="sometimes")


def test_open_mode_logs_a_full_disk_and_goes_on(tmp_path, monkeypatch, caplog):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path))
    box.record({"event_id": "e1"})
    _no_space(monkeypatch)

    with caplog.at_level(logging.ERROR, logger="admina.forensic_blackbox"):
        result = box.record({"event_id": "e2"})

    assert result == {
        "sequence_number": None,
        "record_hash": None,
        "previous_hash": None,
        "stored": False,
    }
    assert box.record_count == 1
    assert box.accepting_records() is False
    assert any("ENOSPC" in r.getMessage() or "No space" in r.getMessage() for r in caplog.records)


def test_closed_mode_raises_on_a_full_disk(tmp_path, monkeypatch):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="closed")
    box.record({"event_id": "e1"})
    _no_space(monkeypatch)

    with pytest.raises(ForensicWriteError) as excinfo:
        box.record({"event_id": "e2"})
    assert isinstance(excinfo.value.__cause__, OSError)
    assert box.record_count == 1
    assert len(record_files(tmp_path)) == 1


def test_a_write_that_works_again_is_accepted_again(tmp_path, monkeypatch):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path), fail_mode="closed")
    with monkeypatch.context() as m:
        _no_space(m)
        with pytest.raises(ForensicWriteError):
            box.record({"event_id": "e1"})
    assert box.accepting_records() is False
    assert box.record({"event_id": "e2"})["sequence_number"] == 1
    assert box.accepting_records() is True
    assert asyncio.run(box.verify_chain())["valid"] is True


@root_only
def test_a_read_only_directory(tmp_path):
    directory = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(directory), fail_mode="closed")
    directory.chmod(0o500)
    try:
        with pytest.raises(ForensicWriteError):
            box.record({"event_id": "e1"})
        assert box.writable() is False
    finally:
        directory.chmod(0o700)


def test_the_memory_store_never_fails(tmp_path):
    box = ForensicBlackBox(fail_mode="closed")
    result = box.record({"event_id": "e1"})
    assert result["sequence_number"] == 1
    assert result["stored"] is False
    assert box.accepting_records() is True
