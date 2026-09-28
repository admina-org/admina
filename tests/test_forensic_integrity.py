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

"""What the forensic chain accepts as valid, and what it does at startup.

Sequence numbers start at 1 and are contiguous; every record is checked for
its hash, its signature and its link, and the records must reach the signed
chain state. At startup a store whose chain state is missing or does not
verify rebuilds it only from records that all verify with the key (from
record 1: signatures, sequence, links), logs it and records a
``chain_state_rebuilt`` event; otherwise the chain is marked invalid, no
record is written, and verification never reports it as valid.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets

import pytest
from _forensic_chain import (
    STATE,
    STATE_SIG,
    flip_byte,
    load,
    record_file,
    record_files,
    rewrite,
    write_chain,
)

from admina.domains.compliance.forensic import (
    ForensicBlackBox,
    ForensicWriteError,
    verify_directory,
)
from admina.domains.compliance.forensic_integrity import GENESIS, compute_record_hash


def _key() -> str:
    return "canary-" + secrets.token_hex(16)


@pytest.fixture
def key(monkeypatch) -> str:
    """A chain-state key, given to each store explicitly."""
    for name in ("ADMINA_FORENSIC_STATE_KEY", "ADMINA_FORENSIC_STATE_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    return _key()


def _store(base, key, **kwargs) -> ForensicBlackBox:
    return ForensicBlackBox(filesystem_dir=str(base), state_signing_key=key, **kwargs)


def _chain(tmp_path, key, count: int = 6) -> tuple:
    base = tmp_path / "forensic"
    box = _store(base, key)
    for i in range(count):
        box.record({"event_id": f"e{i}", "action": "ALLOW", "note": f"note-{i}"})
    return base, box


def _verify(box: ForensicBlackBox) -> dict:
    return asyncio.run(box.verify_chain())


def _failure(result: dict) -> tuple:
    return result["valid"], result["reason"], result["sequence_number"]


def _rechain(base, start: int, change) -> None:
    """Apply *change* to record *start*, then recompute record_hash and
    previous_hash of it and every record after it (signatures unchanged,
    as whoever does this has no key)."""
    previous = load(record_file(base, start - 1))["record_hash"] if start > 1 else GENESIS
    for path in record_files(base)[start - 1 :]:
        record = load(path)
        if record["sequence_number"] == start:
            change(record)
        record["previous_hash"] = previous
        record["record_hash"] = compute_record_hash(record)
        rewrite(path, record)
        previous = record["record_hash"]


def _event_types(base) -> list[str]:
    return [load(p)["event"].get("event_type") for p in record_files(base)]


# ── Records ───────────────────────────────────────────────────


def test_a_changed_byte_is_found_with_its_sequence_number(tmp_path, key):
    base, box = _chain(tmp_path, key)
    flip_byte(record_file(base, 4), b"note-3")
    for result in (_verify(box), verify_directory(base, state_key=key)):
        assert result["valid"] is False
        assert result["reason"] in ("hash_mismatch", "signature_invalid")
        assert result["sequence_number"] == 4


def test_a_deleted_record_is_found(tmp_path, key):
    base, box = _chain(tmp_path, key)
    record_file(base, 3).unlink()
    for result in (_verify(box), verify_directory(base, state_key=key)):
        assert _failure(result) == (False, "missing_record", 3)


def test_renumbering_to_hide_a_gap_is_found(tmp_path, key):
    base, box = _chain(tmp_path, key)
    record_file(base, 3).unlink()
    for path in record_files(base)[2:]:
        seq = int(path.stem)
        path.rename(path.with_name(f"{seq - 1:08d}.json"))
    for result in (_verify(box), verify_directory(base, state_key=key)):
        assert _failure(result) == (False, "sequence_gap", 3)


def test_a_duplicate_sequence_number_is_found(tmp_path, key):
    base, box = _chain(tmp_path, key)
    copy = record_file(base, 2).read_bytes()
    other = base / "2099" / "01" / "01" / "00"
    other.mkdir(parents=True)
    (other / "00000002.json").write_bytes(copy)
    assert _failure(_verify(box)) == (False, "sequence_gap", 2)


def test_a_truncated_tail_is_found_against_the_state(tmp_path, key):
    base, box = _chain(tmp_path, key)
    record_file(base, 6).unlink()
    record_file(base, 5).unlink()
    for result in (_verify(box), verify_directory(base, state_key=key)):
        assert _failure(result) == (False, "missing_record", 5)


def test_a_truncated_head_is_found(tmp_path, key):
    base, box = _chain(tmp_path, key)
    record_file(base, 1).unlink()
    record_file(base, 2).unlink()
    for result in (_verify(box), verify_directory(base, state_key=key)):
        assert _failure(result) == (False, "missing_record", 1)


def test_a_rewritten_and_rechained_record_is_found(tmp_path, key):
    base, box = _chain(tmp_path, key)
    _rechain(base, 3, lambda r: r["event"].update(action="BLOCK"))
    for result in (_verify(box), verify_directory(base, state_key=key)):
        assert _failure(result) == (False, "signature_invalid", 3)


# ── Chain state ───────────────────────────────────────────────


def test_a_rewritten_chain_with_its_state_removed_is_never_valid(tmp_path, key, caplog):
    base, _ = _chain(tmp_path, key)
    _rechain(base, 3, lambda r: r["event"].update(action="BLOCK"))
    (base / STATE).unlink()
    (base / STATE_SIG).unlink()
    before = sorted(p.name for p in record_files(base))

    with caplog.at_level(logging.CRITICAL):
        box = _store(base, key)

    assert box.chain_status == "invalid"
    assert _failure(_verify(box)) == (False, "signature_invalid", 3)
    assert verify_directory(base, state_key=key)["valid"] is False
    assert any(r.levelno == logging.CRITICAL for r in caplog.records)
    # Nothing is adopted or written.
    assert box.record({"event_id": "later"})["stored"] is False
    assert sorted(p.name for p in record_files(base)) == before
    assert not (base / STATE).exists()


def test_without_a_key_a_missing_state_is_not_rebuilt(tmp_path, monkeypatch):
    for name in ("ADMINA_FORENSIC_STATE_KEY", "ADMINA_FORENSIC_STATE_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    base, _ = _chain(tmp_path, None)
    _rechain(base, 3, lambda r: r["event"].update(action="BLOCK"))
    (base / STATE).unlink()

    box = _store(base, None)

    assert box.chain_status == "invalid"
    assert _failure(_verify(box)) == (False, "state_missing", None)
    assert _failure(verify_directory(base)) == (False, "state_missing", None)


def test_a_state_written_without_the_key_is_rejected(tmp_path, key, caplog):
    base, _ = _chain(tmp_path, key)
    fourth = load(record_file(base, 4))
    # A state that stops at record 4, with a signature made with another key.
    (base / STATE).write_bytes(
        json.dumps({"chain_head": fourth["record_hash"], "record_count": 4}).encode()
    )
    (base / STATE_SIG).write_text("0" * 64)
    assert _failure(verify_directory(base, state_key=key)) == (False, "state_invalid", None)

    with caplog.at_level(logging.CRITICAL):
        box = _store(base, key)

    # Not adopted: the chain goes on after all six verified records.
    assert box.chain_status == "rebuilt"
    assert box.record_count == 7
    assert _event_types(base)[-1] == "chain_state_rebuilt"
    assert _verify(box)["valid"] is True


def test_a_lost_state_with_intact_signed_records_is_rebuilt(tmp_path, key, caplog):
    base, first = _chain(tmp_path, key)
    head = first.chain_head
    (base / STATE).unlink()
    (base / STATE_SIG).unlink()

    with caplog.at_level(logging.CRITICAL):
        box = _store(base, key)

    assert box.chain_status == "rebuilt"
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any("chain state rebuilt from verified records" in m for m in messages)
    rebuilt = load(record_file(base, 7))
    assert rebuilt["previous_hash"] == head
    assert rebuilt["event"]["event_type"] == "chain_state_rebuilt"
    assert rebuilt["event"]["cause"] == "state_missing"
    assert rebuilt["event"]["records_verified"] == 6
    assert rebuilt["record_sig_alg"] == "hmac-sha256"
    assert box.record({"event_id": "next"})["sequence_number"] == 8
    assert _verify(box)["valid"] is True
    assert verify_directory(base, state_key=key)["valid"] is True
    # The next start finds a valid signed state: no second rebuild.
    assert _store(base, key).chain_status == "ok"


def test_records_without_signatures_are_not_a_base_for_a_rebuild(tmp_path, key):
    base = tmp_path / "forensic"
    write_chain(base, 4)
    (base / STATE).unlink()
    box = _store(base, key)
    assert box.chain_status == "invalid"
    assert _failure(_verify(box)) == (False, "unsigned", 1)


def test_a_missing_head_record_at_startup_marks_the_chain_invalid(tmp_path, key):
    base, _ = _chain(tmp_path, key)
    record_file(base, 6).unlink()
    box = _store(base, key)
    assert box.chain_status == "invalid"
    assert box.record_count == 6  # from the signed state, not adopted from the records
    assert _failure(_verify(box)) == (False, "missing_record", 6)


def test_a_changed_head_record_at_startup_marks_the_chain_invalid(tmp_path, key):
    base, _ = _chain(tmp_path, key)
    flip_byte(record_file(base, 6), b"note-5")
    assert _store(base, key).chain_status == "invalid"


def test_an_invalid_chain_refuses_records_in_closed_mode(tmp_path, key):
    base, _ = _chain(tmp_path, key)
    record_file(base, 6).unlink()
    box = _store(base, key, fail_mode="closed")
    assert box.accepting_records() is False
    with pytest.raises(ForensicWriteError):
        box.record({"event_id": "e"})
    assert len(record_files(base)) == 5


def test_the_chain_status_of_a_valid_store(tmp_path, key):
    base, box = _chain(tmp_path, key)
    assert box.chain_status == "ok"
    assert _store(base, key).chain_status == "ok"
    assert ForensicBlackBox().chain_status is None


# ── Proxy ─────────────────────────────────────────────────────


def test_health_reports_the_chain(tmp_path, key, monkeypatch):
    pytest.importorskip("fastapi")
    from test_health_fields import _health

    base, box = _chain(tmp_path, key)
    assert _health(monkeypatch, box)["forensic_chain"] == "ok"
    record_file(base, 6).unlink()
    body = _health(monkeypatch, _store(base, key))
    assert body["forensic_chain"] == "invalid"
    assert body["status"] == "degraded"
    assert _health(monkeypatch, ForensicBlackBox())["forensic_chain"] is None


def test_the_gateway_refuses_requests_on_an_invalid_chain_in_closed_mode(tmp_path, key):
    pytest.importorskip("fastapi")
    from _gateway_stream import MockUpstream, chat_body, settings, through

    base, _ = _chain(tmp_path, key)
    record_file(base, 6).unlink()
    upstream = MockUpstream([b"{}"], content_type="application/json")
    response = through(
        upstream,
        chat_body(stream=False),
        settings(),
        state={"forensic_box": _store(base, key, fail_mode="closed")},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "forensic_unavailable"
    assert upstream.requests == []


class _Bucket:
    """The S3 calls of a forensic store, in memory; counts the writes."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.puts = 0

    def head_bucket(self, **_kw):
        return {}

    def put_object(self, **kw):
        self.puts += 1
        self.objects[kw["Key"]] = kw["Body"]
        return {}

    def get_object(self, **kw):
        import io

        return {"Body": io.BytesIO(self.objects[kw["Key"]])}

    def list_objects_v2(self, **kw):
        after = kw.get("StartAfter", "")
        return {"Contents": [{"Key": k} for k in sorted(self.objects) if k > after]}


def test_a_bucket_is_verified_without_writing_to_it(key):
    from admina.domains.compliance.forensic import verify_bucket

    bucket = _Bucket()
    box = ForensicBlackBox(boto3_client=bucket, bucket="b", state_signing_key=key)
    for i in range(5):
        box.record({"event_id": f"e{i}"})
    writes = bucket.puts
    assert verify_bucket(bucket, "b", state_key=key)["valid"] is True
    del bucket.objects[STATE]
    assert _failure(verify_bucket(bucket, "b", state_key=key)) == (False, "state_missing", None)
    assert bucket.puts == writes


def test_an_s3_chain_state_is_rebuilt_and_checked_like_a_directory(key):
    bucket = _Bucket()
    box = ForensicBlackBox(boto3_client=bucket, bucket="b", state_signing_key=key)
    for i in range(3):
        box.record({"event_id": f"e{i}"})
    del bucket.objects[STATE]
    rebuilt = ForensicBlackBox(boto3_client=bucket, bucket="b", state_signing_key=key)
    assert rebuilt.chain_status == "rebuilt"
    assert rebuilt.record_count == 4
    assert _verify(rebuilt)["valid"] is True
    # The last record of the state is removed: invalid at the next start.
    (last,) = [k for k in bucket.objects if k.endswith("/00000004.json")]
    del bucket.objects[last]
    assert ForensicBlackBox(
        boto3_client=bucket, bucket="b", state_signing_key=key
    ).chain_status == ("invalid")
