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

"""``admina forensic``: export and verify the chain of a filesystem store.

Both commands only read the store directory (``--dir``, default
``$FORENSIC_BASE_DIR``); they can run while the proxy writes to it.

- ``admina forensic export --from-seq N --format jsonl [--out FILE|-]``: the
  records from sequence number N on, in sequence order, one per line: the
  bytes of each record file as they are, then ``\\n``. Nothing is added,
  removed or re-encoded, so each line hashes as the file does.
- ``admina forensic verify [--from-seq N | --checkpoint SEQ:HASH]``: the
  result of the verification as JSON (see
  :mod:`admina.domains.compliance.forensic_integrity`); exit status 0 when
  the chain is valid, 1 when it is not.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

import click

from admina.domains.compliance.forensic import verify_directory
from admina.domains.compliance.forensic_files import iter_record_files

__all__ = ["forensic"]

_CHECKPOINT = re.compile(r"([0-9]+):([0-9a-f]{64})")

_DIR_HELP = "Directory of the filesystem forensic store. Defaults to $FORENSIC_BASE_DIR."


@click.group()
def forensic() -> None:
    """Export and verify the forensic chain of a filesystem store."""


def _store_dir(directory: str | None) -> Path:
    value = directory or os.environ.get("FORENSIC_BASE_DIR", "")
    if not value:
        raise click.UsageError("no forensic directory: pass --dir or set FORENSIC_BASE_DIR")
    path = Path(value)
    if not path.is_dir():
        raise click.ClickException(f"{value} is not a directory")
    return path


def _lines(base: Path, from_seq: int) -> Iterator[bytes]:
    """Each record from *from_seq* on, as it is stored, plus ``\\n``."""
    for seq, path in iter_record_files(base, from_seq):
        data = path.read_bytes()
        if b"\n" in data or b"\r" in data:
            raise click.ClickException(f"record {seq} ({path}) is not a single line")
        yield data + b"\n"


def _write(base: Path, from_seq: int, stream: BinaryIO) -> None:
    for line in _lines(base, from_seq):
        stream.write(line)


@forensic.command("export")
@click.option(
    "--from-seq",
    type=click.IntRange(min=1),
    default=1,
    show_default=True,
    help="First sequence number exported.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["jsonl"]),
    default="jsonl",
    show_default=True,
    help="Output format: one record per line.",
)
@click.option("--dir", "directory", default=None, help=_DIR_HELP)
@click.option(
    "--out",
    default="-",
    show_default=True,
    help="File to write (replaced once complete), or - for standard output.",
)
def export(from_seq: int, fmt: str, directory: str | None, out: str) -> None:
    """Write the records from --from-seq on, in sequence order, one per line."""
    base = _store_dir(directory)
    if out == "-":
        stream = click.get_binary_stream("stdout")
        _write(base, from_seq, stream)
        stream.flush()
        return
    target = Path(out)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            _write(base, from_seq, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _checkpoint(value: str | None) -> tuple[int, str] | None:
    if value is None:
        return None
    match = _CHECKPOINT.fullmatch(value.strip())
    if match is None or int(match.group(1)) < 1:
        raise click.BadParameter(
            "expected SEQ:HASH, a sequence number of at least 1 and 64 lowercase hex characters",
            param_hint="--checkpoint",
        )
    return int(match.group(1)), match.group(2)


@forensic.command("verify")
@click.option("--dir", "directory", default=None, help=_DIR_HELP)
@click.option(
    "--from-seq",
    type=click.IntRange(min=1),
    default=None,
    help="Verify from this sequence number on.",
)
@click.option(
    "--checkpoint",
    default=None,
    metavar="SEQ:HASH",
    help="Verify only the records after this one (from an earlier result).",
)
def verify(directory: str | None, from_seq: int | None, checkpoint: str | None) -> None:
    """Verify the chain without writing to the store; print the result as JSON.

    Exit status 0 when the chain is valid, 1 when it is not.
    """
    parsed = _checkpoint(checkpoint)
    if parsed is not None and from_seq is not None:
        raise click.UsageError("--from-seq and --checkpoint cannot be used together")
    base = _store_dir(directory)
    result = verify_directory(base, from_seq=from_seq, checkpoint=parsed)
    click.echo(json.dumps(result, indent=2))
    sys.exit(0 if result["valid"] else 1)
