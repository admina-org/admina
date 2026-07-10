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

import asyncio
import hashlib
import hmac
import json
import logging
import os
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

    def __init__(
        self, base_dir: str = ".admina/forensic", state_signing_key: str | None = None
    ) -> None:
        self._base_dir = Path(base_dir).resolve()
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._chain_head: str = "GENESIS"
        self._record_count: int = 0
        self._state_signing_key = state_signing_key or os.environ.get("ADMINA_FORENSIC_STATE_KEY")
        self._lock = asyncio.Lock()
        self._restore_chain_state()

    # ── BaseForensicStore interface ─────────────────────────────

    async def append(self, record: dict) -> str:
        """Write a governance record to a local JSON file.

        Concurrent calls are serialized by ``_lock`` so that
        ``_record_count`` increments and ``_chain_head`` updates are
        atomic with respect to each other and filesystem I/O.

        Args:
            record: The governance event dict.

        Returns:
            The SHA-256 hash of the stored record.
        """
        async with self._lock:
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

            # Write record file — refuse to overwrite an existing file to
            # preserve chain integrity (a pre-existing file means the
            # sequence counter was silently reset or corrupted).
            record_file = self._base_dir / f"{self._record_count:08d}.json"
            if record_file.exists():
                raise RuntimeError(
                    f"forensic record {record_file.name} already exists — "
                    f"refusing to overwrite (chain integrity)"
                )
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

        # Anchor a full verify against the persisted head + count so a
        # truncated tail is detected (the remaining records still link).
        if last_n == 0:
            file_count = len(sorted(self._base_dir.glob("[0-9]*.json")))
            if file_count != self._record_count:
                return {
                    "valid": False,
                    "records": self._record_count,
                    "last_hash": self._chain_head,
                }
            # prev_hash after the loop is the last record's stored hash
            if prev_hash is not None and prev_hash != self._chain_head:
                return {
                    "valid": False,
                    "records": self._record_count,
                    "last_hash": self._chain_head,
                }

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

    def _reconstruct_from_records(self) -> bool:
        """Rebuild _chain_head/_record_count from stored record files.

        Used when the state file is missing or corrupt, so the chain is
        never silently restarted from GENESIS while records still exist.
        """
        files = sorted(self._base_dir.glob("[0-9]*.json"))
        if not files:
            return False
        try:
            last = json.loads(files[-1].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        self._record_count = last.get("sequence_number", len(files))
        self._chain_head = last.get("record_hash", "GENESIS")
        logger.error(
            "Forensic chain state reconstructed from %d record file(s) "
            "(state file missing or corrupt): seq=%d",
            len(files),
            self._record_count,
        )
        return True

    def _sign_state_payload(self, payload: bytes) -> str | None:
        """HMAC-SHA256 hex digest of *payload*, or None when no signing key
        is configured (``ADMINA_FORENSIC_STATE_KEY`` unset)."""
        if not self._state_signing_key:
            return None
        return hmac.new(
            self._state_signing_key.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()

    def _state_sig_is_valid(self, payload: bytes, signature: str | None) -> bool:
        """True iff a signing key is set and *signature* matches *payload*."""
        expected = self._sign_state_payload(payload)
        if expected is None or not signature:
            return False
        return hmac.compare_digest(signature, expected)

    def _restore_chain_state(self) -> None:
        """Restore chain state from the state file on startup.

        When the state file is missing, corrupt, or (with a signing key set)
        carries a missing/invalid HMAC signature, falls back to reconstructing
        state from the stored record files so the chain is never silently
        restarted from GENESIS while records still exist.
        """
        state_file = self._base_dir / "_chain_state.json"
        if not state_file.exists():
            self._reconstruct_from_records()
            return
        try:
            payload = state_file.read_bytes()
        except OSError:
            logger.error(
                "Cannot read forensic chain state at %s — reconstructing from records",
                state_file,
            )
            self._reconstruct_from_records()
            return
        if self._state_signing_key:
            sig_file = self._base_dir / "_chain_state.json.sig"
            signature = sig_file.read_text(encoding="utf-8").strip() if sig_file.exists() else None
            if not self._state_sig_is_valid(payload, signature):
                logger.critical(
                    "Forensic chain state signature INVALID or MISSING at %s "
                    "— possible tampering; reconstructing from records",
                    state_file,
                )
                self._reconstruct_from_records()
                return
        try:
            state = json.loads(payload)
            self._chain_head = state.get("chain_head", "GENESIS")
            self._record_count = state.get("record_count", 0)
        except json.JSONDecodeError:
            logger.error(
                "Corrupt forensic chain state at %s — reconstructing from records",
                state_file,
            )
            self._reconstruct_from_records()

    def _persist_chain_state(self) -> None:
        """Persist chain state to a JSON file, with an optional HMAC sidecar."""
        state_file = self._base_dir / "_chain_state.json"
        payload = json.dumps(
            {
                "chain_head": self._chain_head,
                "record_count": self._record_count,
                "updated_at": datetime.now(UTC).isoformat(),
            },
            indent=2,
        ).encode("utf-8")
        state_file.write_bytes(payload)
        sig = self._sign_state_payload(payload)
        if sig is not None:
            (self._base_dir / "_chain_state.json.sig").write_text(sig, encoding="utf-8")
