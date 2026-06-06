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
