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

"""Helpers for the forensic chain tests — not a test module itself.

:func:`write_chain` writes a chain of records straight into a store
directory, in the layout and with the hashes the filesystem store uses, much
faster than :meth:`ForensicBlackBox.record` (no fsync): for the tests that
need tens of thousands of records. :class:`MemoryBucket` is an S3 bucket
in memory; :class:`S3Error` and :func:`no_such_key` are errors of the S3
API as boto3 raises them.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from admina.domains.compliance.forensic_integrity import GENESIS, compute_record_hash

STATE = "_chain_state.json"
STATE_SIG = "_chain_state.json.sig"


def record_files(base: Path) -> list[Path]:
    """The record files of the store at *base*, by sequence number."""
    files = [p for p in base.rglob("*.json") if not p.name.startswith("_chain_state")]
    return sorted(files, key=lambda p: int(p.stem))


def record_file(base: Path, seq: int) -> Path:
    """The file of record *seq*."""
    (path,) = [p for p in record_files(base) if int(p.stem) == seq]
    return path


def load(path: Path) -> dict:
    return json.loads(path.read_bytes())


def write_chain(base: Path, count: int, *, per_dir: int = 1000, padding: int = 700) -> str:
    """Write records 1..*count* and a chain state; return the head hash.

    Records are spread over hour directories, *per_dir* per directory; each
    event carries *padding* characters so a record is about 1 KB.
    """
    previous = GENESIS
    for seq in range(1, count + 1):
        index = (seq - 1) // per_dir
        directory = base / "2026" / "01" / f"{1 + index // 24:02d}" / f"{index % 24:02d}"
        if (seq - 1) % per_dir == 0:
            directory.mkdir(parents=True, exist_ok=True)
        record = {
            "sequence_number": seq,
            "timestamp_utc": "2026-01-01T00:00:00+00:00",
            "timestamp_unix_ms": 1767225600000 + seq,
            "previous_hash": previous,
            "event": {
                "event_id": f"{seq:032x}",
                "event_type": "gateway_request",
                "action": "ALLOW",
                "risk_level": "LOW",
                "notes": "x" * padding,
            },
        }
        record["record_hash"] = compute_record_hash(record)
        (directory / f"{seq:08d}.json").write_bytes(
            json.dumps(record, sort_keys=True, default=str).encode("utf-8")
        )
        previous = record["record_hash"]
    state = {"chain_head": previous, "record_count": count}
    (base / STATE).write_bytes(json.dumps(state).encode("utf-8"))
    return previous


def rewrite(path: Path, record: dict) -> None:
    """Write *record* to *path* the way the store serialises records."""
    path.write_bytes(json.dumps(record, sort_keys=True, default=str).encode("utf-8"))


def flip_byte(path: Path, marker: bytes) -> None:
    """Change one byte of *path*: the first byte of *marker* in it (+1)."""
    data = bytearray(path.read_bytes())
    at = data.index(marker)
    data[at] = data[at] + 1
    path.write_bytes(bytes(data))


class S3Error(Exception):
    """An S3 API error as boto3 raises it (botocore's ``ClientError``): the
    error code in ``response["Error"]["Code"]`` and the HTTP status in
    ``response["ResponseMetadata"]["HTTPStatusCode"]``."""

    def __init__(self, code: str, status: int) -> None:
        super().__init__(f"An error occurred ({code}) when calling the S3 API")
        self.response = {
            "Error": {"Code": code, "Message": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


def no_such_key() -> S3Error:
    """What S3 answers to a read of an object that does not exist."""
    return S3Error("NoSuchKey", 404)


class MemoryBucket:
    """The S3 calls of the forensic store, in memory, answered as S3 does (a
    missing object is ``NoSuchKey``). :meth:`fail` makes reads fail."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.puts = 0
        self.reads: list[str] = []
        self._failures: dict[str, list] = {}

    def list_buckets(self):
        return {"Buckets": []}

    def head_bucket(self, **_kw):
        return {}

    def put_object(self, **kw):
        self.puts += 1
        self.objects[kw["Key"]] = kw["Body"]
        return {}

    def get_object(self, **kw):
        key = kw["Key"]
        self.reads.append(key)
        for suffix, failure in self._failures.items():
            if key.endswith(suffix) and failure[0] > 0:
                failure[0] -= 1
                raise failure[1]
        if key not in self.objects:
            raise no_such_key()
        return {"Body": io.BytesIO(self.objects[key])}

    def list_objects_v2(self, **kw):
        after = kw.get("StartAfter", "")
        keys = [k for k in sorted(self.objects) if k > after]
        return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False}

    def fail(self, suffix: str, times: int, error: Exception | None = None) -> None:
        """The next *times* reads of the keys ending with *suffix* raise
        *error* (by default ``SlowDown``, 503)."""
        self._failures[suffix] = [times, error if error is not None else S3Error("SlowDown", 503)]

    def record(self, seq: int) -> dict:
        """The stored record *seq*."""
        (key,) = [k for k in self.objects if k.endswith(f"/{seq:08d}.json")]
        return json.loads(self.objects[key])


def sign_state(base: Path, key: str) -> None:
    """Write the HMAC-SHA256 sidecar of the chain state with *key*."""
    import hashlib
    import hmac

    payload = (base / STATE).read_bytes()
    digest = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    (base / STATE_SIG).write_text(digest, encoding="utf-8")
