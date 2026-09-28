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

"""
Admina — Forensic Black Box — Compliance domain
Hash-chain integrity, immutable audit trail.

Records and the chain state are stored as described in
:mod:`admina.domains.compliance.forensic_files` and hashed and verified as
described in :mod:`admina.domains.compliance.forensic_integrity`.

A record that cannot be written is never counted: the chain goes on from
the last record written. What else happens depends on the store's
``fail_mode``: ``open`` (the default) logs the failure and returns
``stored: False`` without a hash; ``closed`` raises
:class:`ForensicWriteError`.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import tempfile
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from admina.core.secretfile import secret_from_env
from admina.domains.compliance.forensic_files import (
    FORMAT,
    STATE_KEY,
    STATE_SIG_KEY,
    atomic_write,
    ensure_directory,
    iter_record_files,
    ordered_record_keys,
    record_key,
    record_seq,
)
from admina.domains.compliance.forensic_integrity import (
    GENESIS,
    RECORD_SIG_ALG,
    RECORD_UNSIGNED,
    STORE_UNAVAILABLE,
    RecordEntry,
    compute_record_hash,
    record_signing_key,
    sign_record_hash,
    verify_entries,
)
from admina.plugins.base import BaseForensicStore

logger = logging.getLogger("admina.forensic_blackbox")

# Key used to persist the chain state in the object store.
_CHAIN_STATE_KEY = STATE_KEY
# Sidecar holding the HMAC-SHA256 signature of the chain-state payload.
_CHAIN_STATE_SIG_KEY = STATE_SIG_KEY

#: What a store does when a record cannot be written (see the module docstring).
FAIL_MODES = ("open", "closed")


class ForensicWriteError(Exception):
    """A forensic record, or the chain state after it, was not written
    (``fail_mode="closed"``)."""


class ForensicBlackBox(BaseForensicStore):
    """
    Immutable audit log with hash-chain integrity.

    Two storage backends are supported, in this priority order:

    1. ``boto3_client`` — generic S3-compatible (AWS S3, Cloudflare R2,
       SeaweedFS, Garage, Ceph RGW, Backblaze B2, and MinIO servers via
       their S3 API). Supports WORM Object Lock. The recommended backend
       for on-premise / air-gapped deployments.
    2. ``filesystem_dir`` — local JSON files with the same hash-chain
       semantics, each written atomically and fsynced. Zero external
       dependencies. Default for OSS / single host / development
       deployments.

    If neither is configured the class still works as an in-memory ledger
    (events are hashed and chained, but lost on restart).
    """

    def __init__(
        self,
        bucket: str = "forensic-blackbox",
        boto3_client=None,
        filesystem_dir: str | None = None,
        # S3 Object Lock (WORM) — only honoured by the boto3 backend
        s3_object_lock: bool = False,
        s3_lock_days: int = 365 * 7,
        s3_auto_create_locked_bucket: bool = False,
        # Retry policy for transient S3 errors
        s3_max_retries: int = 5,
        s3_base_delay_s: float = 0.2,
        # Optional HMAC key for the chain-state file (else ADMINA_FORENSIC_STATE_KEY,
        # or the file named by ADMINA_FORENSIC_STATE_KEY_FILE)
        state_signing_key: str | None = None,
        # "open" (default) or "closed": see the module docstring.
        fail_mode: str = "open",
    ):
        if fail_mode not in FAIL_MODES:
            raise ValueError(f"fail_mode must be one of {FAIL_MODES} (got {fail_mode!r})")
        self.fail_mode = fail_mode
        self.boto3_client = boto3_client
        self.bucket = bucket
        self.filesystem_dir = (
            Path(filesystem_dir).resolve() if filesystem_dir and boto3_client is None else None
        )
        self.s3_object_lock = bool(s3_object_lock)
        self.s3_lock_days = int(s3_lock_days)
        self.s3_auto_create_locked_bucket = bool(s3_auto_create_locked_bucket)
        self.s3_max_retries = max(0, int(s3_max_retries))
        self.s3_base_delay_s = max(0.0, float(s3_base_delay_s))
        self.chain_head: str = GENESIS
        self.record_count: int = 0
        self._write_lock = threading.Lock()
        # Key of the last record written (its directory is the lowest the
        # next record may go to).
        self._head_key: str | None = None
        # Result of the last record write (None before the first one).
        self._last_write_ok: bool | None = None
        self._state_signing_key = state_signing_key or secret_from_env("ADMINA_FORENSIC_STATE_KEY")
        # Key of the record signatures, derived from the state key.
        self._signing_key = (
            record_signing_key(self._state_signing_key) if self._state_signing_key else None
        )
        # First sequence number that must carry a signature (None: no key).
        self._signed_from: int | None = 1 if self._signing_key is not None else None
        if self.filesystem_dir is not None:
            ensure_directory(self.filesystem_dir)
        self._ensure_bucket()
        self._restore_chain_state()

    @property
    def _durable(self) -> bool:
        return self.boto3_client is not None or self.filesystem_dir is not None

    # ── Retry / backoff helper for transient S3 failures ────────
    def _s3_call(self, fn, *args, **kwargs):
        """Run *fn(*args, **kwargs)* with exponential backoff retries.

        Used only by the boto3 backend; the filesystem path keeps its
        original behaviour.
        """
        import time as _time

        attempt = 0
        while True:
            try:
                return fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                attempt += 1
                if attempt > self.s3_max_retries:
                    raise
                delay = self.s3_base_delay_s * (2 ** (attempt - 1))
                logger.warning(
                    "S3 op %s failed (attempt %d/%d): %s — retrying in %.2fs",
                    getattr(fn, "__name__", "?"),
                    attempt,
                    self.s3_max_retries,
                    exc,
                    delay,
                )
                _time.sleep(delay)

    def _ensure_bucket(self):
        """Create bucket if it doesn't exist (S3 backends only).

        For the boto3 backend, optionally create with ObjectLockEnabled
        when s3_auto_create_locked_bucket is True — this MUST happen at
        bucket creation, it cannot be enabled retroactively.
        """
        if self.boto3_client is not None:
            try:
                self._s3_call(self.boto3_client.head_bucket, Bucket=self.bucket)
            except Exception:  # noqa: BLE001 — bucket missing
                kwargs = {"Bucket": self.bucket}
                if self.s3_object_lock and self.s3_auto_create_locked_bucket:
                    kwargs["ObjectLockEnabledForBucket"] = True
                try:
                    self._s3_call(self.boto3_client.create_bucket, **kwargs)
                    logger.info(
                        "Created forensic bucket (S3): %s%s",
                        self.bucket,
                        " (Object Lock enabled)"
                        if kwargs.get("ObjectLockEnabledForBucket")
                        else "",
                    )
                except Exception:  # noqa: BLE001
                    logger.exception("Failed to create S3 forensic bucket %s", self.bucket)
            return
        if self.filesystem_dir is not None:
            return  # created in __init__
        logger.warning("No forensic backend configured — events kept in memory only")

    # ── Backend I/O ─────────────────────────────────────────────

    def _write_object(self, key: str, data: bytes, *, content_type: str, lock: bool) -> None:
        """Store *data* at *key*: an atomic, fsynced file, or an S3 object
        (under Object Lock when *lock* and the store locks records)."""
        if self.boto3_client is not None:
            put_kwargs: dict = {
                "Bucket": self.bucket,
                "Key": key,
                "Body": data,
                "ContentType": content_type,
            }
            if lock and self.s3_object_lock:
                from datetime import timedelta

                retain_until = datetime.now(UTC) + timedelta(days=self.s3_lock_days)
                put_kwargs["ObjectLockMode"] = "COMPLIANCE"
                put_kwargs["ObjectLockRetainUntilDate"] = retain_until
            self._s3_call(self.boto3_client.put_object, **put_kwargs)
            return
        assert self.filesystem_dir is not None
        path = self.filesystem_dir / key
        ensure_directory(path.parent)
        atomic_write(path, data)

    def _read_object(self, key: str) -> bytes | None:
        """The bytes at *key*, or None when there is no such file or object.
        A filesystem read error other than a missing file raises OSError."""
        if self.boto3_client is not None:
            try:
                obj = self.boto3_client.get_object(Bucket=self.bucket, Key=key)
                return obj["Body"].read()
            except Exception:  # noqa: BLE001 — NoSuchKey or similar
                return None
        assert self.filesystem_dir is not None
        try:
            return (self.filesystem_dir / key).read_bytes()
        except FileNotFoundError:
            return None

    def _s3_get(self, key: str) -> bytes:
        obj = self._s3_call(self.boto3_client.get_object, Bucket=self.bucket, Key=key)
        return obj["Body"].read()

    def _s3_keys(self) -> Iterator[str]:
        """Every key of the bucket, in the order S3 lists them, a page at a time."""
        token: str | None = None
        while True:
            kwargs: dict = {"Bucket": self.bucket}
            if token:
                kwargs["ContinuationToken"] = token
            resp = self._s3_call(self.boto3_client.list_objects_v2, **kwargs)
            for item in resp.get("Contents", []) or []:
                yield item["Key"]
            if not resp.get("IsTruncated"):
                return
            token = resp.get("NextContinuationToken")

    def _record_entries(self, from_seq: int = 1) -> Iterator[RecordEntry]:
        """``(sequence number, load)`` of each stored record from *from_seq*
        on, in sequence order; ``load()`` returns the record's bytes."""
        if self.boto3_client is not None:
            for seq, key in ordered_record_keys(self._s3_keys(), from_seq):
                yield seq, partial(self._s3_get, key)
        elif self.filesystem_dir is not None:
            for seq, path in iter_record_files(self.filesystem_dir, from_seq):
                yield seq, path.read_bytes

    def _last_record(self) -> tuple[str, bytes] | None:
        """Key and bytes of the stored record with the highest sequence
        number, or None when there is none. Reads one record."""
        last: tuple[int, str] | None = None
        if self.boto3_client is not None:
            for seq, key in ordered_record_keys(self._s3_keys()):
                if last is None or seq > last[0]:
                    last = (seq, key)
            return None if last is None else (last[1], self._s3_get(last[1]))
        if self.filesystem_dir is None:
            return None
        for seq, path in iter_record_files(self.filesystem_dir):
            if last is None or seq > last[0]:
                last = (seq, path.relative_to(self.filesystem_dir).as_posix())
        if last is None:
            return None
        return last[1], (self.filesystem_dir / last[1]).read_bytes()

    # ── Chain state ─────────────────────────────────────────────

    def _reconstruct_chain_state_from_records(self) -> bool:
        """Rebuild chain_head/record_count from the stored records.

        Returns True if records were found. Used when the mutable state file
        is missing or corrupt, so the chain is never silently restarted from
        GENESIS while records still exist. Only the last record is read.
        """
        found = self._last_record()
        if found is None:
            return False
        key, data = found
        last = json.loads(data)
        self.record_count = last.get("sequence_number", record_seq(key) or 0)
        self.chain_head = last.get("record_hash", GENESIS)
        self._head_key = key
        if self._signing_key is not None:
            self._signed_from = self.record_count + 1
        logger.warning(
            "Forensic chain state reconstructed from the stored records "
            "(state file missing or corrupt): seq=%d, head=%s...",
            self.record_count,
            self.chain_head[:16],
        )
        return True

    def _read_state_sig(self) -> str | None:
        """The HMAC sidecar of the chain state, or None."""
        try:
            data = self._read_object(_CHAIN_STATE_SIG_KEY)
        except OSError:
            return None
        return data.decode("utf-8", errors="replace").strip() if data is not None else None

    def _apply_state(self, state: dict[str, Any]) -> None:
        self.chain_head = state.get("chain_head", GENESIS)
        self.record_count = state.get("record_count", 0)
        head_key = state.get("head_key")
        self._head_key = head_key if isinstance(head_key, str) and record_seq(head_key) else None
        if self._signing_key is not None:
            signed_from = state.get("signed_from")
            # A state written before records were signed: the records from
            # the next one on are.
            self._signed_from = (
                signed_from if isinstance(signed_from, int) else self.record_count + 1
            )

    def _restore_chain_state(self):
        """Restore chain_head and record_count from the configured backend."""
        if not self._durable:
            return
        where = "S3" if self.boto3_client is not None else "filesystem"
        try:
            payload = self._read_object(_CHAIN_STATE_KEY)
        except OSError:
            logger.error(
                "Cannot read forensic chain state (%s) — reconstructing from records", where
            )
            self._reconstruct_chain_state_from_records()
            return
        if payload is None:
            logger.info("No existing forensic chain state (%s), starting fresh", where)
            self._reconstruct_chain_state_from_records()
            return
        if self._state_signing_key and not self._state_sig_is_valid(
            payload, self._read_state_sig()
        ):
            logger.critical(
                "Forensic chain state signature INVALID or MISSING (%s) "
                "— possible tampering; reconstructing from records",
                where,
            )
            self._reconstruct_chain_state_from_records()
            return
        try:
            state = json.loads(payload)
            if not isinstance(state, dict):
                raise ValueError("not an object")
        except (ValueError, UnicodeDecodeError):
            logger.error("Corrupt forensic chain state (%s) — reconstructing from records", where)
            self._reconstruct_chain_state_from_records()
            return
        self._apply_state(state)
        logger.info(
            "Restored forensic chain state (%s): seq=%d, head=%s...",
            where,
            self.record_count,
            self.chain_head[:16],
        )

    def _persist_chain_state(self) -> None:
        """Persist chain_head and record_count (and the HMAC sidecar when a
        signing key is set). A failure is logged, and raised as
        :class:`ForensicWriteError` in closed mode."""
        payload = json.dumps(
            {
                "chain_head": self.chain_head,
                "record_count": self.record_count,
                "updated_at": datetime.now(UTC).isoformat(),
                "format": FORMAT,
                "head_key": self._head_key,
                "signed_from": self._signed_from,
            }
        ).encode("utf-8")
        sig = self._sign_state_payload(payload)
        try:
            # The chain state is rewritten after every record, so it is
            # never locked; the records are.
            self._write_object(
                _CHAIN_STATE_KEY, payload, content_type="application/json", lock=False
            )
            if sig is not None:
                self._write_object(
                    _CHAIN_STATE_SIG_KEY, sig.encode("utf-8"), content_type="text/plain", lock=False
                )
        except Exception as exc:  # noqa: BLE001 — any backend failure
            self._last_write_ok = False
            logger.error(
                "Forensic chain state not written after record %d: %s", self.record_count, exc
            )
            if self.fail_mode == "closed":
                raise ForensicWriteError(
                    f"forensic chain state not written after record {self.record_count}"
                ) from exc

    def _compute_hash(self, data: str) -> str:
        """SHA-256 hash for chain integrity."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _sign_state_payload(self, payload: bytes) -> str | None:
        """HMAC-SHA256 hex digest of *payload*, or None when no signing key
        is configured (``ADMINA_FORENSIC_STATE_KEY`` unset)."""
        if not self._state_signing_key:
            return None
        return hmac.new(
            self._state_signing_key.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()

    def _state_sig_is_valid(self, payload: bytes, signature: str | None) -> bool:
        """True iff a signing key is set and *signature* matches *payload*
        (constant-time)."""
        expected = self._sign_state_payload(payload)
        if expected is None or not signature:
            return False
        return hmac.compare_digest(signature, expected)

    # ── Writing ─────────────────────────────────────────────────

    def record(self, event: dict) -> dict:
        """
        Record an event to the forensic black box.
        Adds hash-chain integrity and eIDAS-style timestamp.
        Returns the forensic record with integrity metadata.

        Concurrent calls are serialized by ``_write_lock`` so that
        ``record_count`` increments and ``chain_head`` updates are
        atomic with respect to each other and the backend I/O.
        Holding the lock through I/O is intentional: correctness of the
        tamper-evident chain takes precedence over throughput.

        A record that cannot be written leaves the chain where it was; in
        closed mode :class:`ForensicWriteError` is raised, in open mode the
        result has ``stored: False`` and no sequence number or hash.
        """
        with self._write_lock:
            now = datetime.now(UTC)
            seq = self.record_count + 1
            previous = self.chain_head
            forensic_record = {
                "sequence_number": seq,
                "timestamp_utc": now.isoformat(),
                "timestamp_unix_ms": int(time.time() * 1000),
                "previous_hash": previous,
                "event": event,
            }
            record_hash = compute_record_hash(forensic_record)
            forensic_record["record_hash"] = record_hash
            if self._signing_key is not None:
                forensic_record["record_sig"] = sign_record_hash(self._signing_key, record_hash)
                forensic_record["record_sig_alg"] = RECORD_SIG_ALG
            else:
                forensic_record["record_sig_alg"] = RECORD_UNSIGNED

            if not self._durable:
                self.record_count, self.chain_head = seq, record_hash
                return {
                    "sequence_number": seq,
                    "record_hash": record_hash,
                    "previous_hash": previous,
                    "stored": False,
                }

            head_dir = self._head_key.rsplit("/", 1)[0] if self._head_key else None
            key = record_key(seq, now, head_dir)
            data = json.dumps(forensic_record, sort_keys=True, default=str).encode("utf-8")
            try:
                self._write_object(key, data, content_type="application/json", lock=True)
            except Exception as exc:  # noqa: BLE001 — any backend failure
                return self._not_written(seq, exc)
            self.record_count, self.chain_head, self._head_key = seq, record_hash, key
            self._last_write_ok = True
            logger.debug("Stored forensic record: %s", key)
            self._persist_chain_state()
            return {
                "sequence_number": seq,
                "record_hash": record_hash,
                "previous_hash": previous,
                "stored": True,
            }

    def _not_written(self, seq: int, exc: Exception) -> dict:
        """Handle a record that could not be written, as the fail mode says."""
        self._last_write_ok = False
        logger.error("Forensic record %d not written: %s", seq, exc)
        if self.fail_mode == "closed":
            raise ForensicWriteError(f"forensic record {seq} not written") from exc
        return {
            "sequence_number": None,
            "record_hash": None,
            "previous_hash": None,
            "stored": False,
        }

    def accepting_records(self) -> bool:
        """False after a record or chain-state write failed, until one
        succeeds again."""
        return self._last_write_ok is not False

    def writable(self) -> bool | None:
        """Whether the backend accepts writes.

        - filesystem: a probe file is created in the directory, written,
          fsynced and removed; ``False`` when any of it fails;
        - S3: the result of the last record write, ``None`` before the first;
        - in-memory: ``None`` (nothing is persisted).
        """
        if self.boto3_client is not None:
            return self._last_write_ok
        if self.filesystem_dir is None:
            return None
        return _probe_directory(self.filesystem_dir)

    # ── Verification ────────────────────────────────────────────

    def verify_records(self, records: list[dict]) -> dict:
        """
        Verify the integrity of an explicit list of forensic records.

        Recomputes each record's SHA-256 over its content (see
        :func:`~admina.domains.compliance.forensic_integrity.canonical_record`)
        and checks that each record's ``previous_hash`` links to the prior
        record's hash.

        Args:
            records: Forensic records ordered by sequence_number, as written
                by ``record()`` / read back from the backend.

        Returns:
            ``{"valid": bool, "checked": int, "error": str (if invalid)}``.
        """
        if not records:
            return {"valid": True, "checked": 0}

        for i, record in enumerate(records):
            if compute_record_hash(record) != record.get("record_hash"):
                return {
                    "valid": False,
                    "error": f"Hash mismatch at sequence {record.get('sequence_number')}",
                    "checked": i,
                }

            if i > 0:
                expected_prev = records[i - 1].get("record_hash")
                actual_prev = record.get("previous_hash")
                if expected_prev != actual_prev:
                    return {
                        "valid": False,
                        "error": f"Chain broken at sequence {record.get('sequence_number')}",
                        "checked": i,
                    }

        return {"valid": True, "checked": len(records)}

    def verify(
        self,
        last_n: int = 0,
        *,
        from_seq: int | None = None,
        checkpoint: tuple[int, str] | None = None,
    ) -> dict:
        """Verify the stored chain, reading one record at a time.

        Args:
            last_n: If > 0, verify only the last *n* records.
            from_seq: Verify from this sequence number on (its record's
                ``previous_hash`` is not checked).
            checkpoint: ``(sequence_number, record_hash)`` of a record an
                earlier verification ended on: only the records after it are
                verified, the first one linked to it.

        Returns:
            ``valid``, ``records`` (checked), ``last_hash`` (the chain
            head), ``reason`` and ``sequence_number`` (the first failure,
            see :mod:`~admina.domains.compliance.forensic_integrity`),
            ``checkpoint`` (``{"sequence_number", "record_hash"}`` to resume
            from, None when invalid), ``signed``, ``unsigned`` and
            ``signatures_verified`` (signatures are checked with the key
            the store signs with). The in-memory store has no stored chain:
            valid, 0 records.
        """
        if checkpoint is not None and from_seq is not None:
            raise ValueError("pass from_seq or checkpoint, not both")
        if checkpoint is not None:
            seq, digest = checkpoint
            if not isinstance(seq, int) or seq < 1 or not isinstance(digest, str):
                raise ValueError("checkpoint must be (sequence_number >= 1, record_hash)")
        if from_seq is not None and from_seq < 1:
            raise ValueError("from_seq must be at least 1")
        with self._write_lock:
            count, head, signed_from = self.record_count, self.chain_head, self._signed_from
        result: dict[str, Any] = {
            "valid": True,
            "records": 0,
            "reason": None,
            "sequence_number": None,
            "checkpoint": None,
            "signed": 0,
            "unsigned": 0,
            "signatures_verified": self._signing_key is not None,
        }
        if self._durable:
            if checkpoint is not None:
                start = checkpoint[0]
            elif from_seq is not None:
                start = from_seq
            elif last_n > 0:
                start = max(1, count - last_n + 1)
            else:
                start = 1
            report = verify_entries(
                self._record_entries(start),
                from_seq=start,
                checkpoint=checkpoint,
                state=(count, head),
                signing_key=self._signing_key,
                signed_from=signed_from,
            )
            result = report.as_dict()
        return {**result, "last_hash": head}

    # ── BaseForensicStore interface ─────────────────────────────
    # ForensicBlackBox is the proxy's production forensic store. It satisfies
    # the BaseForensicStore plugin contract so it can be selected through the
    # plugin registry like any other backend, while keeping its richer
    # synchronous record()/verify_records() API for direct SDK use.

    @property
    def store_name(self) -> str:
        return "blackbox"

    async def append(self, record: dict) -> str:
        """Write a governance record (BaseForensicStore contract).

        Delegates to the synchronous :meth:`record` and returns the
        record's SHA-256 hash, as the plugin contract requires.
        """
        result = self.record(record)
        return result["record_hash"]

    async def verify_chain(
        self,
        last_n: int = 0,
        *,
        from_seq: int | None = None,
        checkpoint: tuple[int, str] | None = None,
    ) -> dict:
        """Verify the persisted hash chain (BaseForensicStore contract):
        :meth:`verify`, on a worker thread.

        Returns at least ``{"valid": bool, "records": int, "last_hash": str}``
        per the plugin contract.
        """
        return await asyncio.to_thread(
            self.verify, last_n, from_seq=from_seq, checkpoint=checkpoint
        )

    def get_stats(self) -> dict:
        return {
            "record_count": self.record_count,
            "chain_head": self.chain_head[:16] + "...",
            "storage_available": self._durable,
        }


class UnavailableForensicStore(ForensicBlackBox):
    """The store of a configured backend that could not be opened.

    It records nothing, not even in memory: every :meth:`record` fails as
    the fail mode says (logged, or :class:`ForensicWriteError`), it is never
    writable and its chain never verifies (``store_unavailable``).
    """

    def __init__(self, backend: str, reason: str, *, fail_mode: str = "open"):
        self.backend = backend
        self.reason = reason
        super().__init__(fail_mode=fail_mode)

    def _ensure_bucket(self):
        """Nothing to create: the backend could not be opened."""

    def record(self, event: dict) -> dict:
        with self._write_lock:
            cause = RuntimeError(f"forensic backend {self.backend} cannot be used: {self.reason}")
            return self._not_written(self.record_count + 1, cause)

    def accepting_records(self) -> bool:
        return False

    def writable(self) -> bool:
        return False

    def verify(
        self,
        last_n: int = 0,
        *,
        from_seq: int | None = None,
        checkpoint: tuple[int, str] | None = None,
    ) -> dict:
        return {
            "valid": False,
            "records": 0,
            "reason": STORE_UNAVAILABLE,
            "sequence_number": None,
            "checkpoint": None,
            "last_hash": self.chain_head,
        }


def _state_of(payload: bytes | None) -> dict[str, Any] | None:
    """The chain-state payload as an object with an integer
    ``record_count`` and a string ``chain_head``, or None."""
    if payload is None:
        return None
    try:
        state = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(state, dict):
        return None
    if not isinstance(state.get("record_count", 0), int):
        return None
    if not isinstance(state.get("chain_head", GENESIS), str):
        return None
    return state


def verify_directory(
    base_dir: str | Path,
    *,
    state_key: str | None = None,
    from_seq: int | None = None,
    checkpoint: tuple[int, str] | None = None,
) -> dict:
    """Verify the chain stored in the filesystem store directory *base_dir*,
    reading one record at a time and writing nothing.

    As :meth:`ForensicBlackBox.verify`, against the chain state stored in
    the directory; with *state_key* (the chain-state key) the record
    signatures are checked. ``last_hash`` is the state's head (or, without a
    state, the hash of the last record checked).
    """
    if checkpoint is not None and from_seq is not None:
        raise ValueError("pass from_seq or checkpoint, not both")
    base = Path(base_dir)
    try:
        payload = (base / _CHAIN_STATE_KEY).read_bytes()
    except FileNotFoundError:
        payload = None
    state = _state_of(payload)
    signing_key = record_signing_key(state_key) if state_key else None
    signed_from = state.get("signed_from") if state is not None else None
    start = checkpoint[0] if checkpoint is not None else (from_seq or 1)
    report = verify_entries(
        ((seq, path.read_bytes) for seq, path in iter_record_files(base, start)),
        from_seq=start,
        checkpoint=checkpoint,
        state=None
        if state is None
        else (state.get("record_count", 0), state.get("chain_head", GENESIS)),
        signing_key=signing_key,
        signed_from=signed_from if isinstance(signed_from, int) else None,
    )
    result = report.as_dict()
    if state is not None:
        last_hash = state.get("chain_head", GENESIS)
    else:
        last_hash = report.checkpoint[1] if report.checkpoint is not None else GENESIS
    return {**result, "last_hash": last_hash}


def _probe_directory(directory: Path) -> bool:
    """Create, write, fsync and remove a probe file in *directory*."""
    try:
        fd, name = tempfile.mkstemp(prefix=".write-probe-", suffix=".tmp", dir=directory)
    except OSError:
        return False
    ok = True
    try:
        os.write(fd, b"probe")
        os.fsync(fd)
    except OSError:
        ok = False
    finally:
        os.close(fd)
    try:
        os.unlink(name)
    except OSError:
        ok = False
    return ok
