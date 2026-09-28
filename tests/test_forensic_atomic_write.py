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

"""The filesystem forensic store writes each file atomically and durably.

A record, ``_chain_state.json`` and ``_chain_state.json.sig`` are each written
to a temporary file in their own directory, fsynced, renamed into place, and
the directory is fsynced after the rename. A new directory is fsynced in its
parent. A write interrupted before the rename leaves no record behind and
does not advance the chain; a temporary file left by a process that stopped
mid-write is ignored.
"""

from __future__ import annotations

import asyncio
import errno
import os
import stat
from pathlib import Path

import pytest
from _forensic_chain import STATE, STATE_SIG, record_files

from admina.domains.compliance.forensic import ForensicBlackBox, ForensicWriteError


class _Calls:
    """Records os.fsync (inode, is a directory) and os.replace calls."""

    def __init__(self, monkeypatch) -> None:
        self.calls: list[tuple] = []
        real_fsync, real_replace = os.fsync, os.replace

        def fsync(fd: int) -> None:
            info = os.fstat(fd)
            self.calls.append(("fsync", info.st_ino, stat.S_ISDIR(info.st_mode)))
            real_fsync(fd)

        def replace(src, dst, *args, **kwargs) -> None:
            real_replace(src, dst, *args, **kwargs)
            self.calls.append(("replace", Path(src), Path(dst)))

        monkeypatch.setattr(os, "fsync", fsync)
        monkeypatch.setattr(os, "replace", replace)

    def replaced_at(self, target: Path) -> int:
        (index,) = [i for i, c in enumerate(self.calls) if c[0] == "replace" and c[2] == target]
        return index

    def assert_atomic(self, target: Path) -> int:
        """*target* was written to a temporary file in its directory, fsynced,
        renamed, then its directory fsynced. Returns the index of the rename."""
        at = self.replaced_at(target)
        src = self.calls[at][1]
        assert src.parent == target.parent
        assert src.name.startswith(".") and src.name.endswith(".tmp")
        assert not src.exists()
        inode = os.stat(target).st_ino  # a rename keeps the inode
        before = self.calls[:at]
        assert ("fsync", inode, False) in before
        directory = os.stat(target.parent).st_ino
        assert ("fsync", directory, True) in self.calls[at + 1 :]
        return at


def test_record_and_state_files_are_written_through_fsync_and_rename(tmp_path, monkeypatch):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base), state_signing_key="state-key")
    calls = _Calls(monkeypatch)

    box.record({"event_id": "e1", "action": "ALLOW"})

    (record,) = record_files(base)
    at_record = calls.assert_atomic(record)
    at_state = calls.assert_atomic(base / STATE)
    at_sig = calls.assert_atomic(base / STATE_SIG)
    # The record is in place before the state that counts it.
    assert at_record < at_state < at_sig


def test_a_new_directory_is_fsynced_in_its_parent(tmp_path, monkeypatch):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base))
    calls = _Calls(monkeypatch)

    box.record({"event_id": "e1"})

    (record,) = record_files(base)
    synced = {c[1] for c in calls.calls if c[0] == "fsync" and c[2]}
    # The hour, day, month and year directories were created by this write:
    # each one's parent directory was fsynced.
    for directory in (record.parent, *list(record.parent.parents)[:3]):
        assert os.stat(directory.parent).st_ino in synced


def test_files_keep_the_default_permissions(tmp_path):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base))
    box.record({"event_id": "e1"})
    mask = os.umask(0)
    os.umask(mask)
    for path in (*record_files(base), base / STATE):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o666 & ~mask


def _interrupt_rename_of(monkeypatch, name: str) -> None:
    real = os.replace

    def replace(src, dst, *args, **kwargs):
        if Path(dst).name == name:
            raise OSError(errno.EIO, "Input/output error")
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", replace)


def test_an_interrupted_record_write_leaves_no_record(tmp_path, monkeypatch, caplog):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base))
    first = box.record({"event_id": "e1"})

    with monkeypatch.context() as m:
        _interrupt_rename_of(m, "00000002.json")
        result = box.record({"event_id": "e2"})

    assert result["stored"] is False
    assert result["record_hash"] is None
    assert [p.name for p in record_files(base)] == ["00000001.json"]
    assert not list(base.rglob("*.tmp"))
    # The chain did not move: the next record takes the same number.
    assert (box.record_count, box.chain_head) == (1, first["record_hash"])
    assert any("not written" in r.getMessage() for r in caplog.records if r.levelname == "ERROR")
    again = box.record({"event_id": "e3"})
    assert again["sequence_number"] == 2
    assert again["previous_hash"] == first["record_hash"]
    assert asyncio.run(box.verify_chain())["valid"] is True


def test_an_interrupted_write_raises_in_closed_mode(tmp_path, monkeypatch):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base), fail_mode="closed")
    box.record({"event_id": "e1"})
    _interrupt_rename_of(monkeypatch, "00000002.json")

    with pytest.raises(ForensicWriteError):
        box.record({"event_id": "e2"})
    assert box.record_count == 1
    assert [p.name for p in record_files(base)] == ["00000001.json"]


def test_a_temporary_file_left_mid_write_is_ignored(tmp_path):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base))
    box.record({"event_id": "e1"})
    box.record({"event_id": "e2"})
    last = record_files(base)[-1]
    # What a process stopped between the write and the rename leaves.
    (last.parent / ".00000003.json.5f2a9c1d.tmp").write_bytes(b'{"sequence_number": 3, "ev')

    assert asyncio.run(box.verify_chain())["valid"] is True
    restarted = ForensicBlackBox(filesystem_dir=str(base))
    assert restarted.record_count == 2
    assert restarted.record({"event_id": "e3"})["sequence_number"] == 3
    assert asyncio.run(restarted.verify_chain())["valid"] is True


def test_the_state_file_is_never_partial(tmp_path, monkeypatch):
    base = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(base))
    box.record({"event_id": "e1"})
    before = (base / STATE).read_bytes()

    with monkeypatch.context() as m:
        _interrupt_rename_of(m, STATE)
        box.record({"event_id": "e2"})

    # The record is in place; the previous state is intact, not truncated.
    assert len(record_files(base)) == 2
    assert (base / STATE).read_bytes() == before
    assert not list(base.rglob("*.tmp"))
