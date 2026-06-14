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

"""Tests for the ForensicBlackBox used by the proxy in production.

`admina/domains/compliance/forensic.py::ForensicBlackBox` is the class the
proxy instantiates (admina/proxy/main.py lifespan) for its tamper-evident
audit trail. These tests exercise its critical path directly against the
filesystem backend (the default when no S3/MinIO is configured):

  * record() builds a linked SHA-256 hash chain (previous_hash == prior head).
  * verify_records() accepts an untampered chain reconstructed from stored JSON.
  * verify_records() rejects a tampered event payload (hash mismatch) and a
    broken link (previous_hash mismatch).
  * chain state (head + count) survives a restart via the persisted state file.
  * S3 Object Lock (WORM) parameters reach put_object as COMPLIANCE retention.
  * the BaseForensicStore plugin contract (append / verify_chain(last_n) /
    store_name) works and reads records back from the backend.

verify_records() recomputes each record's hash over the FULL record (timestamps
+ event), so the records are read back from disk exactly as _store_to_s3 wrote
them — this exercises the real serialize -> verify round-trip, not a hand-built
stand-in.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from admina.domains.compliance.forensic import ForensicBlackBox
from admina.plugins.base import BaseForensicStore

# Object key layout written by _store_to_s3: YYYY/MM/DD/HH/<seq:08d>.json
# plus the mutable _chain_state.json at the root.
_STATE_FILE = "_chain_state.json"


def _stored_records(base: Path) -> list[dict]:
    """Read every persisted forensic record (excluding chain state), ordered
    by sequence_number — the input shape verify_records() expects."""
    records = []
    for p in base.rglob("*.json"):
        if p.name == _STATE_FILE:
            continue
        records.append(json.loads(p.read_text(encoding="utf-8")))
    records.sort(key=lambda r: r["sequence_number"])
    return records


class TestForensicRecord:
    def test_record_returns_chain_metadata(self, tmp_path):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path / "f"))
        r = box.record({"action": "BLOCK", "reason": "injection"})
        assert r["sequence_number"] == 1
        assert r["previous_hash"] == "GENESIS"
        assert len(r["record_hash"]) == 64  # sha256 hex
        assert r["stored"] is True

    def test_record_links_previous_hash(self, tmp_path):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path / "f"))
        r1 = box.record({"i": 1})
        r2 = box.record({"i": 2})
        assert r2["sequence_number"] == 2
        # Each record chains to the prior record's hash.
        assert r2["previous_hash"] == r1["record_hash"]
        assert box.chain_head == r2["record_hash"]

    def test_record_persists_to_disk(self, tmp_path):
        base = tmp_path / "f"
        box = ForensicBlackBox(filesystem_dir=str(base))
        box.record({"i": 1})
        box.record({"i": 2})
        stored = _stored_records(base)
        assert [r["sequence_number"] for r in stored] == [1, 2]
        assert stored[0]["event"] == {"i": 1}


class TestVerifyChain:
    def test_empty_chain_is_valid(self, tmp_path):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path / "f"))
        assert box.verify_records([]) == {"valid": True, "checked": 0}

    def test_untampered_chain_verifies(self, tmp_path):
        base = tmp_path / "f"
        box = ForensicBlackBox(filesystem_dir=str(base))
        for i in range(3):
            box.record({"i": i})
        result = box.verify_records(_stored_records(base))
        assert result == {"valid": True, "checked": 3}

    def test_tampered_event_is_detected(self, tmp_path):
        base = tmp_path / "f"
        box = ForensicBlackBox(filesystem_dir=str(base))
        box.record({"amount": 100})
        box.record({"amount": 200})

        records = _stored_records(base)
        # Mutate a stored event payload, leaving record_hash untouched.
        records[0]["event"]["amount"] = 999

        result = box.verify_records(records)
        assert result["valid"] is False
        assert "Hash mismatch" in result["error"]
        assert result["checked"] == 0

    def test_broken_link_is_detected(self, tmp_path):
        base = tmp_path / "f"
        box = ForensicBlackBox(filesystem_dir=str(base))
        box.record({"i": 1})
        box.record({"i": 2})

        records = _stored_records(base)
        # Re-point the second record's previous_hash and re-seal its own hash
        # so the per-record hash check passes but the chain link is broken.
        records[1]["previous_hash"] = "0" * 64
        resealed = {k: v for k, v in records[1].items() if k != "record_hash"}
        records[1]["record_hash"] = box._compute_hash(
            json.dumps(resealed, sort_keys=True, default=str)
        )

        result = box.verify_records(records)
        assert result["valid"] is False
        assert "Chain broken" in result["error"]
        assert result["checked"] == 1


class TestChainStatePersistence:
    def test_state_restored_across_restart(self, tmp_path):
        base = str(tmp_path / "f")
        box1 = ForensicBlackBox(filesystem_dir=base)
        box1.record({"i": 1})
        head_after_first = box1.chain_head

        # A fresh instance pointed at the same dir must resume the chain.
        box2 = ForensicBlackBox(filesystem_dir=base)
        assert box2.record_count == 1
        assert box2.chain_head == head_after_first

        r2 = box2.record({"i": 2})
        assert r2["sequence_number"] == 2
        assert r2["previous_hash"] == head_after_first

    def test_full_chain_valid_across_restart(self, tmp_path):
        base = tmp_path / "f"
        box1 = ForensicBlackBox(filesystem_dir=str(base))
        box1.record({"i": 1})
        box2 = ForensicBlackBox(filesystem_dir=str(base))
        box2.record({"i": 2})

        result = box2.verify_records(_stored_records(base))
        assert result == {"valid": True, "checked": 2}


class TestS3ObjectLock:
    """The boto3 backend WORM path: Object Lock parameters must reach
    put_object so records are written under COMPLIANCE retention."""

    class _FakeS3:
        def __init__(self):
            self.puts: list[dict] = []

        def head_bucket(self, **kwargs):
            return {}

        def get_object(self, **kwargs):
            raise RuntimeError("no existing state")  # forces a fresh chain

        def list_objects_v2(self, **kwargs):
            # No records exist yet → reconstruction finds nothing → stays GENESIS/0.
            return {"Contents": [], "IsTruncated": False}

        def put_object(self, **kwargs):
            self.puts.append(kwargs)
            return {}

    def test_object_lock_sets_compliance_retention(self):
        from datetime import datetime

        s3 = self._FakeS3()
        box = ForensicBlackBox(
            boto3_client=s3,
            bucket="audit",
            s3_object_lock=True,
            s3_lock_days=30,
        )
        box.record({"action": "BLOCK"})

        record_puts = [p for p in s3.puts if p["Key"] != _STATE_FILE]
        assert record_puts, "no forensic record written to S3"
        put = record_puts[0]
        assert put["ObjectLockMode"] == "COMPLIANCE"
        assert isinstance(put["ObjectLockRetainUntilDate"], datetime)

    def test_no_object_lock_when_disabled(self):
        s3 = self._FakeS3()
        box = ForensicBlackBox(boto3_client=s3, bucket="audit", s3_object_lock=False)
        box.record({"action": "ALLOW"})

        record_puts = [p for p in s3.puts if p["Key"] != _STATE_FILE]
        assert record_puts
        assert "ObjectLockMode" not in record_puts[0]


class TestBaseForensicStoreContract:
    """ForensicBlackBox satisfies the BaseForensicStore plugin interface, so it
    can be selected through the plugin registry like any other backend."""

    def test_is_a_forensic_store(self, tmp_path):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path / "f"))
        assert isinstance(box, BaseForensicStore)
        assert box.store_name == "blackbox"

    def test_append_returns_record_hash(self, tmp_path):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path / "f"))
        h = asyncio.run(box.append({"action": "BLOCK"}))
        assert isinstance(h, str) and len(h) == 64
        assert box.chain_head == h

    def test_verify_chain_reads_back_and_validates(self, tmp_path):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path / "f"))
        asyncio.run(box.append({"i": 1}))
        asyncio.run(box.append({"i": 2}))
        result = asyncio.run(box.verify_chain())
        assert result["valid"] is True
        assert result["records"] == 2
        assert result["last_hash"] == box.chain_head

    def test_verify_chain_detects_tampering_via_readback(self, tmp_path):
        base = tmp_path / "f"
        box = ForensicBlackBox(filesystem_dir=str(base))
        asyncio.run(box.append({"amount": 100}))
        asyncio.run(box.append({"amount": 200}))

        # Tamper with a persisted record file on disk.
        rec_file = next(p for p in base.rglob("*.json") if p.name != _STATE_FILE)
        data = json.loads(rec_file.read_text())
        data["event"]["amount"] = 999
        rec_file.write_text(json.dumps(data))

        result = asyncio.run(box.verify_chain())
        assert result["valid"] is False

    def test_verify_chain_last_n(self, tmp_path):
        box = ForensicBlackBox(filesystem_dir=str(tmp_path / "f"))
        for i in range(5):
            asyncio.run(box.append({"i": i}))
        result = asyncio.run(box.verify_chain(last_n=2))
        assert result["valid"] is True
        assert result["records"] == 2

    def test_in_memory_verify_chain_is_trivially_valid(self):
        # No backend → nothing persisted to read back → empty chain is valid.
        box = ForensicBlackBox()
        asyncio.run(box.append({"i": 1}))
        result = asyncio.run(box.verify_chain())
        assert result["valid"] is True
        assert result["records"] == 0


class TestS3ChainStateReconstruction:
    """When the S3 chain-state key is missing the chain must be reconstructed
    from the immutable record objects — not silently restarted from GENESIS."""

    class _FullFakeS3:
        """In-memory S3 fake that stores all objects in a dict keyed by Key.

        Supports the methods called by ForensicBlackBox:
          head_bucket, put_object, get_object, list_objects_v2.
        """

        def __init__(self):
            self._store: dict[str, bytes] = {}

        def head_bucket(self, **kwargs):
            return {}

        def put_object(self, **kwargs):
            self._store[kwargs["Key"]] = kwargs["Body"]
            return {}

        def get_object(self, **kwargs):
            key = kwargs["Key"]
            if key not in self._store:
                raise KeyError(f"no object: {key}")
            import io

            return {"Body": io.BytesIO(self._store[key])}

        def list_objects_v2(self, **kwargs):
            keys = list(self._store.keys())
            return {
                "Contents": [{"Key": k} for k in keys],
                "IsTruncated": False,
            }

    def test_s3_reconstructs_chain_from_existing_records(self):

        s3 = self._FullFakeS3()
        box = ForensicBlackBox(boto3_client=s3, bucket="b")

        box.record({"i": 1})
        box.record({"i": 2})
        box.record({"i": 3})

        head_before = box.chain_head
        count_before = box.record_count  # 3

        # Simulate lost state key — the record objects remain intact.
        del s3._store[_STATE_FILE]

        # A fresh instance must reconstruct from the 3 S3 record objects.
        box2 = ForensicBlackBox(boto3_client=s3, bucket="b")
        assert box2.record_count == count_before  # reconstructed, not 0
        assert box2.chain_head == head_before  # reconstructed, not GENESIS


class TestChainStateReconstruction:
    """When the mutable state file is missing or corrupt, the chain must be
    reconstructed from the immutable records on disk — not silently restarted
    from GENESIS (which would fork the audit trail)."""

    def test_forensic_reconstructs_chain_after_state_file_lost(self, tmp_path):
        fb = ForensicBlackBox(filesystem_dir=str(tmp_path))
        fb.record({"event": "a"})
        fb.record({"event": "b"})
        head_before = fb.chain_head
        count_before = fb.record_count  # 2

        (tmp_path / "_chain_state.json").unlink()  # lose the state file

        fb2 = ForensicBlackBox(filesystem_dir=str(tmp_path))
        assert fb2.record_count == count_before  # reconstructed, not 0
        assert fb2.chain_head == head_before  # reconstructed, not GENESIS

        r = fb2.record({"event": "c"})
        assert r["sequence_number"] == 3  # chain CONTINUES
        assert r["previous_hash"] == head_before

    def test_forensic_reconstructs_on_corrupt_state(self, tmp_path):
        fb = ForensicBlackBox(filesystem_dir=str(tmp_path))
        fb.record({"event": "a"})
        head, count = fb.chain_head, fb.record_count
        (tmp_path / "_chain_state.json").write_text("{ corrupt json")  # tamper/corruption
        fb2 = ForensicBlackBox(filesystem_dir=str(tmp_path))
        assert fb2.record_count == count and fb2.chain_head == head

    def test_forensic_empty_store_starts_at_genesis(self, tmp_path):
        fb = ForensicBlackBox(filesystem_dir=str(tmp_path))
        assert fb.record_count == 0 and fb.chain_head == "GENESIS"


def test_verify_chain_detects_tail_truncation(tmp_path):
    import asyncio

    from admina.domains.compliance.forensic import ForensicBlackBox

    fb = ForensicBlackBox(filesystem_dir=str(tmp_path))
    for i in range(5):
        fb.record({"event": f"e{i}"})
    assert asyncio.run(fb.verify_chain())["valid"] is True

    # delete the last record file (tail truncation) WITHOUT updating state
    record_files = sorted(p for p in tmp_path.rglob("*.json") if p.name != "_chain_state.json")
    record_files[-1].unlink()

    res = asyncio.run(fb.verify_chain())
    assert res["valid"] is False  # truncation must be detected


def test_verify_chain_in_memory_still_valid():
    import asyncio

    from admina.domains.compliance.forensic import ForensicBlackBox

    fb = ForensicBlackBox()  # in-memory, no durable backend
    fb.record({"event": "x"})
    fb.record({"event": "y"})
    # in-memory has no durable records to read back — verify must still pass
    assert asyncio.run(fb.verify_chain())["valid"] is True


def test_verify_chain_intact_is_valid(tmp_path):
    import asyncio

    from admina.domains.compliance.forensic import ForensicBlackBox

    fb = ForensicBlackBox(filesystem_dir=str(tmp_path))
    for i in range(3):
        fb.record({"event": f"e{i}"})
    res = asyncio.run(fb.verify_chain())
    assert res["valid"] is True and res["records"] == 3


def test_forensic_concurrent_records_do_not_fork(tmp_path):
    import asyncio
    import threading

    from admina.domains.compliance.forensic import ForensicBlackBox

    fb = ForensicBlackBox(filesystem_dir=str(tmp_path))

    def _w(i):
        fb.record({"event": f"e{i}"})

    threads = [threading.Thread(target=_w, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert fb.record_count == 20
    res = asyncio.run(fb.verify_chain())
    assert res["valid"] is True
    assert res["records"] == 20  # 20 distinct sequence numbers, no fork/dup
