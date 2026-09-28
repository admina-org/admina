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

"""Layout and files of the forensic store (format ``admina-forensic/1``).

Each record is one JSON object, on one line, at
``YYYY/MM/DD/HH/NNNNNNNN.json``: the UTC hour of the write and the sequence
number, zero-padded to eight digits. A record never goes into an hour
directory earlier than the one of the record before it, even when the clock
steps back, so directory order is sequence order. The chain state is
``_chain_state.json`` (and its HMAC, ``_chain_state.json.sig``) at the top.
The same keys name the objects of the S3 backend.

On the filesystem every file is written atomically and durably
(:func:`atomic_write`): a temporary file in the same directory, fsynced,
renamed into place, then the directory fsynced. Temporary files start with
``.`` and end with ``.tmp``, so one left by an interrupted write is never
read as a record.
"""

from __future__ import annotations

import errno
import os
import re
import secrets
from collections.abc import Iterable, Iterator
from contextlib import suppress
from datetime import datetime
from pathlib import Path

__all__ = [
    "FORMAT",
    "STATE_KEY",
    "STATE_SIG_KEY",
    "atomic_write",
    "ensure_directory",
    "fsync_directory",
    "iter_record_files",
    "ordered_record_keys",
    "record_key",
    "record_seq",
]

#: Format of the store.
FORMAT = "admina-forensic/1"
#: Key of the chain state.
STATE_KEY = "_chain_state.json"
#: Key of the HMAC-SHA256 of the chain state.
STATE_SIG_KEY = "_chain_state.json.sig"

_RECORD_NAME = re.compile(r"([0-9]{8,})\.json")
# Year, month, day and hour directories.
_DIR_NAMES = (
    re.compile(r"[0-9]{4}"),
    re.compile(r"[0-9]{2}"),
    re.compile(r"[0-9]{2}"),
    re.compile(r"[0-9]{2}"),
)


def record_key(seq: int, when: datetime, floor: str | None = None) -> str:
    """Key of record *seq* written at *when* (UTC): ``YYYY/MM/DD/HH/NNNNNNNN.json``,
    in the hour directory *floor* (the directory of the record before) when
    that one is later."""
    directory = f"{when.year:04d}/{when.month:02d}/{when.day:02d}/{when.hour:02d}"
    if floor is not None and floor > directory:
        directory = floor
    return f"{directory}/{seq:08d}.json"


def record_seq(key: str) -> int | None:
    """The sequence number of a record key or file name, or None when *key*
    does not name a record."""
    match = _RECORD_NAME.fullmatch(key.rsplit("/", 1)[-1])
    return int(match.group(1)) if match else None


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def fsync_directory(directory: Path) -> None:
    """Flush *directory*'s entries to disk. A file system that cannot fsync a
    directory (``EINVAL``) is left as it is."""
    fd = os.open(directory, os.O_RDONLY)
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
    finally:
        os.close(fd)


def ensure_directory(directory: Path) -> None:
    """Create *directory* and its missing parents, each one fsynced in its
    parent once created."""
    missing: list[Path] = []
    current = directory
    while not current.is_dir():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for path in reversed(missing):
        with suppress(FileExistsError):
            path.mkdir()
        fsync_directory(path.parent)


def atomic_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically and durably.

    The bytes go to a temporary file in the same directory (created with the
    permissions a new file gets), which is fsynced and renamed to *path*;
    then the directory is fsynced. On any failure before the rename the
    temporary file is removed and *path* is untouched.
    """
    directory = path.parent
    temporary = directory / f".{path.name}.{secrets.token_hex(8)}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except BaseException:
        with suppress(OSError):
            os.unlink(temporary)
        raise
    fsync_directory(directory)


def _sorted_dirs(parent: Path, pattern: re.Pattern[str]) -> list[Path]:
    try:
        entries = list(os.scandir(parent))
    except FileNotFoundError:
        return []
    return sorted(
        (Path(e.path) for e in entries if pattern.fullmatch(e.name) and e.is_dir()),
        key=lambda p: p.name,
    )


def _hour_dirs(base: Path) -> Iterator[Path]:
    """The hour directories under *base*, oldest first."""
    for year in _sorted_dirs(base, _DIR_NAMES[0]):
        for month in _sorted_dirs(year, _DIR_NAMES[1]):
            for day in _sorted_dirs(month, _DIR_NAMES[2]):
                yield from _sorted_dirs(day, _DIR_NAMES[3])


def iter_record_files(base: Path, from_seq: int = 1) -> Iterator[tuple[int, Path]]:
    """``(sequence number, path)`` of each record file under *base* with a
    sequence number of at least *from_seq*, in directory order and, within a
    directory, by sequence number. One directory is listed at a time."""
    for directory in _hour_dirs(base):
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        found = []
        for entry in entries:
            seq = record_seq(entry.name)
            if seq is not None and seq >= from_seq:
                found.append((seq, Path(entry.path)))
        found.sort(key=lambda item: item[0])
        yield from found


def ordered_record_keys(keys: Iterable[str], from_seq: int = 1) -> Iterator[tuple[int, str]]:
    """``(sequence number, key)`` of the record keys in *keys* (in the
    lexicographic order an S3 listing returns them) with a sequence number
    of at least *from_seq*: each directory's keys sorted by sequence number.
    Other keys are skipped. One directory is held at a time."""
    group: list[tuple[int, str]] = []
    directory: str | None = None
    for key in keys:
        seq = record_seq(key)
        if seq is None or key.count("/") != 4:
            continue
        prefix = key.rsplit("/", 1)[0]
        if prefix != directory:
            group.sort(key=lambda item: item[0])
            yield from group
            group, directory = [], prefix
        if seq >= from_seq:
            group.append((seq, key))
    group.sort(key=lambda item: item[0])
    yield from group
