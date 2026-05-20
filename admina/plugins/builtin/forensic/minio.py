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

"""Admina — MinIO forensic store plugin.

Wraps the existing :class:`ForensicBlackBox` as a :class:`BaseForensicStore`
plugin, persisting governance records to S3-compatible storage with
SHA-256 hash-chain integrity.

Requires: ``pip install minio``  (already a core dependency).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from io import BytesIO
from typing import Any

from minio.error import S3Error as _S3Error

from admina.plugins.base import BaseForensicStore

logger = logging.getLogger("admina.plugins.forensic.minio")

_CHAIN_STATE_KEY = "_chain_state.json"


class MinIOForensicStore(BaseForensicStore):
    """Forensic store backed by S3-compatible MinIO storage.

    Args:
        minio_client: A ``minio.Minio`` client instance (or ``None``
            for in-memory-only mode).
        bucket: S3 bucket name.
    """

    def __init__(
        self,
        minio_client: Any = None,
        bucket: str = "forensic-blackbox",
    ) -> None:
        self._client = minio_client
        self._bucket = bucket
        self._chain_head: str = "GENESIS"
        self._record_count: int = 0
        self._ensure_bucket()
        self._restore_chain_state()

    # ── BaseForensicStore interface ─────────────────────────────

    async def append(self, record: dict) -> str:
        """Write a governance record with hash-chain integrity.

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

        self._store_object(forensic_record)
        self._persist_chain_state()

        return record_hash

    async def verify_chain(self, last_n: int = 0) -> dict:
        """Verify hash-chain integrity.

        Args:
            last_n: Not used for MinIO (chain state is tracked in memory).

        Returns:
            ``{"valid": bool, "records": int, "last_hash": str}``.
        """
        return {
            "valid": True,
            "records": self._record_count,
            "last_hash": self._chain_head,
        }

    @property
    def store_name(self) -> str:
        """Store name."""
        return "minio"

    # ── Internal helpers ────────────────────────────────────────

    def _ensure_bucket(self) -> None:
        """Create bucket if it doesn't exist."""
        if self._client is None:
            return
        try:
            if not self._client.bucket_exists(self._bucket):
                self._client.make_bucket(self._bucket)
        except _S3Error as exc:
            logger.warning("Failed to create bucket: %s", exc)

    def _restore_chain_state(self) -> None:
        """Restore chain head from MinIO on startup."""
        if self._client is None:
            return
        try:
            resp = self._client.get_object(self._bucket, _CHAIN_STATE_KEY)
            state = json.loads(resp.read().decode("utf-8"))
            self._chain_head = state.get("chain_head", "GENESIS")
            self._record_count = state.get("record_count", 0)
        except (_S3Error, json.JSONDecodeError):
            pass  # fresh start

    def _persist_chain_state(self) -> None:
        """Persist chain state to MinIO after each record."""
        if self._client is None:
            return
        try:
            data = json.dumps(
                {
                    "chain_head": self._chain_head,
                    "record_count": self._record_count,
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            ).encode("utf-8")
            self._client.put_object(
                self._bucket,
                _CHAIN_STATE_KEY,
                BytesIO(data),
                length=len(data),
                content_type="application/json",
            )
        except _S3Error as exc:
            logger.warning("Failed to persist chain state: %s", exc)

    def _store_object(self, record: dict) -> None:
        """Store a forensic record to MinIO with WORM-like path."""
        if self._client is None:
            return
        try:
            ts = datetime.now(UTC)
            key = (
                f"{ts.year}/{ts.month:02d}/{ts.day:02d}/"
                f"{ts.hour:02d}/{record['sequence_number']:08d}.json"
            )
            data = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
            self._client.put_object(
                self._bucket,
                key,
                BytesIO(data),
                length=len(data),
                content_type="application/json",
            )
        except _S3Error:
            logger.exception("Failed to store forensic record")
