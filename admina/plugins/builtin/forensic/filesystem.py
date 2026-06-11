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

"""Admina — Filesystem forensic store plugin.

A zero-dependency fallback forensic store that writes JSON records to
the local filesystem.  Suitable for development, testing, and
single-node deployments where S3/MinIO is not available.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path

from admina.plugins.base import BaseForensicStore

logger = logging.getLogger("admina.plugins.forensic.filesystem")


class FilesystemForensicStore(BaseForensicStore):
    """Forensic store backed by local JSON files.

    Args:
        base_dir: Directory to store forensic records.
    """

    name = "filesystem"

    def __init__(self, base_dir: str = ".admina/forensic") -> None:
        self._base_dir = Path(base_dir).resolve()
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._chain_head: str = "GENESIS"
        self._record_count: int = 0
        self._restore_chain_state()

    # ── BaseForensicStore interface ─────────────────────────────

    async def append(self, record: dict) -> str:
        """Write a governance record to a local JSON file.

        Args:
            record: The governance event dict.

        Returns:
            The SHA-256 hash of the stored record.
        """
        self._record_count += 1

        forensic_record = {
            "sequence_number": self._record_count,
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "timestamp_unix_ms": int(time.time() * 1000),
            "previous_hash": self._chain_head,
            "event": record,
        }

        record_json = json.dumps(forensic_record, sort_keys=True, default=str)
        record_hash = hashlib.sha256(record_json.encode("utf-8")).hexdigest()
        forensic_record["record_hash"] = record_hash
        self._chain_head = record_hash

        # Write record file
        record_file = self._base_dir / f"{self._record_count:08d}.json"
        record_file.write_text(
            json.dumps(forensic_record, indent=2, default=str),
            encoding="utf-8",
        )

        self._persist_chain_state()
        return record_hash

    async def verify_chain(self, last_n: int = 0) -> dict:
        """Verify hash-chain integrity by re-reading stored records.

        Args:
            last_n: If > 0, verify only the last *n* records.

        Returns:
            ``{"valid": bool, "records": int, "last_hash": str}``.
        """
        files = sorted(self._base_dir.glob("[0-9]*.json"))
        if last_n > 0:
            files = files[-last_n:]

        prev_hash: str | None = None
        for fp in files:
            try:
                rec = json.loads(fp.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {"valid": False, "records": 0, "last_hash": ""}

            if prev_hash is not None and rec.get("previous_hash") != prev_hash:
                return {
                    "valid": False,
                    "records": self._record_count,
                    "last_hash": self._chain_head,
                }

            # Recompute hash to verify integrity
            stored_hash = rec.pop("record_hash", "")
            recomputed = hashlib.sha256(
                json.dumps(rec, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            if recomputed != stored_hash:
                return {
                    "valid": False,
                    "records": self._record_count,
                    "last_hash": self._chain_head,
                }
            prev_hash = stored_hash

        return {
            "valid": True,
            "records": self._record_count,
            "last_hash": self._chain_head,
        }

    @property
    def store_name(self) -> str:
        """Store name."""
        return "filesystem"

    # ── Internal helpers ────────────────────────────────────────

    def _restore_chain_state(self) -> None:
        """Restore chain state from the state file on startup."""
        state_file = self._base_dir / "_chain_state.json"
        if state_file.exists():
            try:
                state = json.loads(state_file.read_text(encoding="utf-8"))
                self._chain_head = state.get("chain_head", "GENESIS")
                self._record_count = state.get("record_count", 0)
            except (OSError, json.JSONDecodeError):
                pass

    def _persist_chain_state(self) -> None:
        """Persist chain state to a JSON file."""
        state_file = self._base_dir / "_chain_state.json"
        state_file.write_text(
            json.dumps(
                {
                    "chain_head": self._chain_head,
                    "record_count": self._record_count,
                    "updated_at": datetime.now(UTC).isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
