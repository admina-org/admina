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

"""How the S3 forensic store reads its chain state and records.

A read is retried with the store's backoff (``s3_max_retries``,
``s3_base_delay_s``), except when S3 answers that the object does not exist
(error code ``NoSuchKey``, ``NotFound`` or ``404``): only that answer makes
an object missing, and it is not retried. Any other error that outlasts the
retries is a read error, as an unreadable file is for the filesystem store:
a chain state that cannot be read is not used (it is rebuilt only from
records that verify with the key), and a record that cannot be read at
startup keeps the store from opening (``OSError``). :func:`verify_bucket`
reports a missing chain state only when S3 answers that it does not exist.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time

import pytest
from _forensic_chain import STATE, STATE_SIG, MemoryBucket, S3Error

from admina.domains.compliance.forensic import ForensicBlackBox, verify_bucket


@pytest.fixture(autouse=True)
def _no_key_in_environment(monkeypatch):
    for name in ("ADMINA_FORENSIC_STATE_KEY", "ADMINA_FORENSIC_STATE_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def key() -> str:
    return "canary-" + secrets.token_hex(16)


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    """The backoff delays of the store, recorded instead of slept."""
    delays: list[float] = []
    monkeypatch.setattr(time, "sleep", delays.append)
    return delays


def _store(bucket: MemoryBucket, key: str | None = None, **kwargs) -> ForensicBlackBox:
    return ForensicBlackBox(boto3_client=bucket, bucket="b", state_signing_key=key, **kwargs)


def _chain(bucket: MemoryBucket, key: str | None = None, count: int = 3) -> ForensicBlackBox:
    box = _store(bucket, key)
    for i in range(count):
        box.record({"event_id": f"e{i}", "action": "ALLOW"})
    return box


# ── Transient errors ──────────────────────────────────────────


@pytest.mark.parametrize("suffix", [STATE, STATE_SIG, "/00000003.json"])
def test_a_read_that_fails_once_at_startup_is_retried(key, sleeps, suffix):
    bucket = MemoryBucket()
    first = _chain(bucket, key)
    puts = bucket.puts
    bucket.fail(suffix, 1)

    box = _store(bucket, key)

    assert box.chain_status == "ok"
    assert box.chain_error is None
    assert (box.record_count, box.chain_head) == (3, first.chain_head)
    assert bucket.puts == puts  # nothing rebuilt, nothing recorded
    assert len(sleeps) == 1
    assert asyncio.run(box.verify_chain())["valid"] is True


def test_a_keyless_chain_state_read_that_fails_once_is_retried(sleeps):
    bucket = MemoryBucket()
    _chain(bucket)
    bucket.fail(STATE, 1)

    box = _store(bucket)

    assert box.chain_status == "ok"
    assert box.record({"event_id": "e3"})["sequence_number"] == 4
    assert asyncio.run(box.verify_chain())["valid"] is True


def test_closed_mode_records_after_a_record_read_that_failed_once(key, sleeps):
    bucket = MemoryBucket()
    _chain(bucket, key)
    bucket.fail("/00000003.json", 1)

    box = _store(bucket, key, fail_mode="closed")

    assert box.accepting_records() is True
    assert box.record({"event_id": "e3"})["sequence_number"] == 4


# ── Missing objects ───────────────────────────────────────────


def test_a_missing_object_is_read_once(key, sleeps):
    bucket = MemoryBucket()

    box = _store(bucket, key)

    assert (box.chain_status, box.record_count) == ("ok", 0)
    assert bucket.reads.count(STATE) == 1
    assert sleeps == []


def test_a_chain_state_that_does_not_exist_is_rebuilt_from_verified_records(key, sleeps):
    bucket = MemoryBucket()
    _chain(bucket, key)
    del bucket.objects[STATE]

    box = _store(bucket, key)

    assert (box.chain_status, box.record_count) == ("rebuilt", 4)
    assert bucket.record(4)["event"]["cause"] == "state_missing"
    assert sleeps == []


@pytest.mark.parametrize("code", ["NoSuchKey", "NotFound", "404"])
def test_a_botocore_not_found_error_is_a_missing_object(key, sleeps, code):
    exceptions = pytest.importorskip("botocore.exceptions")

    class Bucket(MemoryBucket):
        def get_object(self, **kw):
            if kw["Key"] not in self.objects:
                raise exceptions.ClientError(
                    {
                        "Error": {"Code": code, "Message": "Not Found"},
                        "ResponseMetadata": {"HTTPStatusCode": 404},
                    },
                    "GetObject",
                )
            return super().get_object(**kw)

    bucket = Bucket()
    box = _store(bucket, key)

    assert (box.chain_status, box.record_count, sleeps) == ("ok", 0, [])
    assert box.record({"event_id": "e0"})["sequence_number"] == 1


# ── Errors that outlast the retries ───────────────────────────


def test_a_chain_state_that_cannot_be_read_is_not_taken_for_a_missing_one(key, sleeps, caplog):
    bucket = MemoryBucket()
    _chain(bucket, key)
    bucket.fail(STATE, 10)

    with caplog.at_level(logging.ERROR, logger="admina.forensic_blackbox"):
        box = _store(bucket, key, s3_max_retries=2)

    # As an unreadable chain-state file: not used, and rebuilt only because
    # every record verifies with the key.
    assert (box.chain_status, box.record_count) == ("rebuilt", 4)
    assert bucket.record(4)["event"]["cause"] == "state_invalid"
    assert len(sleeps) == 2
    assert any("SlowDown" in r.getMessage() for r in caplog.records)


def test_a_keyless_chain_state_that_cannot_be_read_is_not_taken_for_a_missing_one(sleeps):
    bucket = MemoryBucket()
    _chain(bucket)
    bucket.fail(STATE, 10)

    box = _store(bucket, s3_max_retries=1)

    assert box.chain_status == "invalid"
    assert box.chain_error == {"reason": "state_invalid", "sequence_number": None}


@pytest.mark.parametrize(
    "error",
    [
        S3Error("SlowDown", 503),
        S3Error("AccessDenied", 403),
        S3Error("NoSuchBucket", 404),
        ConnectionResetError("connection reset"),
    ],
    ids=["slow-down", "access-denied", "no-such-bucket", "connection-reset"],
)
def test_a_record_that_cannot_be_read_keeps_the_store_from_opening(key, sleeps, error):
    bucket = MemoryBucket()
    _chain(bucket, key)
    bucket.fail("/00000003.json", 10, error)

    with pytest.raises(OSError, match="00000003"):
        _store(bucket, key, s3_max_retries=1)
    assert len(sleeps) == 1


def test_a_botocore_server_error_is_not_a_missing_object(key, sleeps):
    exceptions = pytest.importorskip("botocore.exceptions")
    bucket = MemoryBucket()
    _chain(bucket, key)
    error = exceptions.ClientError(
        {
            "Error": {"Code": "InternalError", "Message": "We encountered an internal error."},
            "ResponseMetadata": {"HTTPStatusCode": 500},
        },
        "GetObject",
    )
    bucket.fail("/00000003.json", 10, error)

    with pytest.raises(OSError, match="InternalError"):
        _store(bucket, key, s3_max_retries=1)


# ── verify_bucket ─────────────────────────────────────────────


def test_verify_bucket_reports_a_chain_state_that_does_not_exist(key):
    bucket = MemoryBucket()
    _chain(bucket, key)
    del bucket.objects[STATE]

    result = verify_bucket(bucket, "b", state_key=key)

    assert (result["valid"], result["reason"]) == (False, "state_missing")


def test_verify_bucket_does_not_take_a_read_error_for_a_missing_chain_state(key):
    bucket = MemoryBucket()
    _chain(bucket, key)
    bucket.fail(STATE, 1)
    puts = bucket.puts

    with pytest.raises(S3Error):
        verify_bucket(bucket, "b", state_key=key)
    assert bucket.puts == puts
    assert verify_bucket(bucket, "b", state_key=key)["valid"] is True
