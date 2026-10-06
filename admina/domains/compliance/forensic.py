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

At startup a durable store checks its chain state (``chain_status``):
``ok`` when the saved state verifies and matches the stored records,
``rebuilt`` when a missing or unverifiable state was rebuilt from records
that all verify with the key (logged, and recorded as a
``chain_state_rebuilt`` event; the status stays ``rebuilt`` across restarts
until :meth:`ForensicBlackBox.acknowledge_rebuild`), ``invalid`` otherwise — then no record is
written until the forensic directory is restored or moved aside. A store
whose chain was written with a key (its chain state names the first signed
record, or has a signature beside it), opened without one, raises
:class:`ForensicKeyError` in ``closed`` mode; in ``open`` mode it logs a
warning and writes unsigned records.
:func:`verify_directory` and :func:`verify_bucket` verify a stored chain
without writing to it.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import itertools
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from admina.core.secretfile import SecretFileError, secret_from_env
from admina.core.types import EventType
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
    MISSING_RECORD,
    RECORD_SIG_ALG,
    RECORD_UNSIGNED,
    STATE_INVALID,
    STATE_MISMATCH,
    STATE_MISSING,
    STORE_UNAVAILABLE,
    RecordEntry,
    compute_record_hash,
    hex_digest_matches,
    record_signing_key,
    sign_record_hash,
    stored_hex_digest,
    verify_entries,
)
from admina.plugins.base import BaseForensicStore

logger = logging.getLogger("admina.forensic_blackbox")

# Key used to persist the chain state in the object store.
_CHAIN_STATE_KEY = STATE_KEY
# Sidecar holding the HMAC-SHA256 signature of the chain-state payload.
_CHAIN_STATE_SIG_KEY = STATE_SIG_KEY
# Records kept in memory for recent_records(), newest last.
RECENT_RECORDS_MAX = 1000

#: What a store does when a record cannot be written (see the module docstring).
FAIL_MODES = ("open", "closed")

#: ``chain_status`` of a durable store: the chain state was restored as
#: saved, rebuilt from verified records at startup, or the chain is invalid.
CHAIN_OK = "ok"
CHAIN_REBUILT = "rebuilt"
CHAIN_INVALID = "invalid"


class ForensicWriteError(Exception):
    """A forensic record, or the chain state after it, was not written
    (``fail_mode="closed"``)."""


class ForensicKeyError(RuntimeError):
    """A durable store whose chain was written with a key was opened without
    one (``fail_mode="closed"``): its records would be written unsigned."""


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
        # The last records written by this process, for readers that need
        # recent activity without reading the backend back (the dashboard
        # feed when no analytics store is configured).
        self._recent: deque[dict] = deque(maxlen=RECENT_RECORDS_MAX)
        # Key of the last record written (its directory is the lowest the
        # next record may go to).
        self._head_key: str | None = None
        # Result of the last record write (None before the first one).
        self._last_write_ok: bool | None = None
        if state_signing_key is None:
            _refuse_key_file_inside(self.filesystem_dir)
        self._state_signing_key = state_signing_key or secret_from_env("ADMINA_FORENSIC_STATE_KEY")
        # Key of the record signatures, derived from the state key.
        self._signing_key = (
            record_signing_key(self._state_signing_key) if self._state_signing_key else None
        )
        # First sequence number that must carry a signature (None: no key).
        self._signed_from: int | None = 1 if self._signing_key is not None else None
        # CHAIN_OK, CHAIN_REBUILT or CHAIN_INVALID (None: nothing is stored);
        # for an invalid chain, chain_error holds reason and sequence_number.
        self.chain_status: str | None = None
        self.chain_error: dict[str, Any] | None = None
        # The rebuild not yet acknowledged ({"cause", "record_count", "at"}),
        # kept in the chain state so that "rebuilt" survives a restart.
        self._rebuilt: dict[str, Any] | None = None
        if self.filesystem_dir is not None:
            ensure_directory(self.filesystem_dir)
        self._ensure_bucket()
        self._restore_chain_state()

    @property
    def _durable(self) -> bool:
        return self.boto3_client is not None or self.filesystem_dir is not None

    # ── Retry / backoff helper for transient S3 failures ────────
    def _s3_call(
        self,
        fn,
        *args,
        final: Callable[[Exception], bool] | None = None,
        **kwargs,
    ):
        """Run *fn(*args, **kwargs)* with exponential backoff retries; an
        error for which *final(error)* is true is raised at once.

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
                if attempt > self.s3_max_retries or (final is not None and final(exc)):
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

        Any other read error raises OSError: for S3, an error other than
        "no such key" (:func:`_s3_missing`) that is still there after the
        retries."""
        if self.boto3_client is not None:
            try:
                return self._s3_get(key, final=_s3_missing)
            except Exception as exc:  # noqa: BLE001 — any client or connection error
                if _s3_missing(exc):
                    return None
                raise OSError(
                    f"S3 object {key} cannot be read ({type(exc).__name__}: {exc})"
                ) from exc
        assert self.filesystem_dir is not None
        try:
            return (self.filesystem_dir / key).read_bytes()
        except FileNotFoundError:
            return None

    def _s3_get(self, key: str, *, final: Callable[[Exception], bool] | None = None) -> bytes:
        """The bytes of the S3 object *key*, read with the retries of
        :meth:`_s3_call` (the object's body included)."""

        def get_object() -> bytes:
            return self.boto3_client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

        return self._s3_call(get_object, final=final)

    def _s3_keys(self, start_after: str | None = None) -> Iterator[str]:
        """The keys of the bucket (after *start_after* when given), in the
        order S3 lists them, a page at a time."""
        token: str | None = None
        while True:
            kwargs: dict = {"Bucket": self.bucket}
            if token:
                kwargs["ContinuationToken"] = token
            elif start_after:
                kwargs["StartAfter"] = start_after
            resp = self._s3_call(self.boto3_client.list_objects_v2, **kwargs)
            for item in resp.get("Contents", []) or []:
                if start_after is None or item["Key"] > start_after:
                    yield item["Key"]
            if not resp.get("IsTruncated"):
                return
            token = resp.get("NextContinuationToken")

    def _record_items(
        self, from_seq: int = 1, after_key: str | None = None
    ) -> Iterator[tuple[int, str, Any]]:
        """``(sequence number, key, load)`` of each stored record from
        *from_seq* on, in sequence order; ``load()`` returns the record's
        bytes. With *after_key*, only the records stored from its directory
        on are listed."""
        if self.boto3_client is not None:
            keys = self._s3_keys(after_key)
            for seq, key in ordered_record_keys(keys, from_seq):
                yield seq, key, partial(self._s3_get, key)
        elif self.filesystem_dir is not None:
            start_dir = after_key.rsplit("/", 1)[0] if after_key else None
            for seq, path in iter_record_files(self.filesystem_dir, from_seq, start_dir):
                key = path.relative_to(self.filesystem_dir).as_posix()
                yield seq, key, path.read_bytes

    def _record_entries(self, from_seq: int = 1) -> Iterator[RecordEntry]:
        """``(sequence number, load)`` of each stored record from *from_seq*
        on, in sequence order; ``load()`` returns the record's bytes."""
        for seq, _key, load in self._record_items(from_seq):
            yield seq, load

    # ── Chain state ─────────────────────────────────────────────
    #
    # At startup the chain state is read and, with a key, its HMAC checked.
    #
    # - A valid state is used as it is; the record at its count must be its
    #   head, and any record after it (written just before the process
    #   stopped) must verify and link to it, and is then counted.
    # - A missing state, when there are records, or one that does not verify
    #   is rebuilt only from records that all verify with the key, from
    #   record 1 on (sequence, hashes, links, signatures); the rebuild is
    #   logged (CRITICAL) and recorded as a ``chain_state_rebuilt`` event.
    # - In any other case the chain is invalid: CRITICAL log, chain_status
    #   "invalid", no record is written and verification is never valid,
    #   until an operator restores the forensic directory or moves it aside.

    def _read_state_sig(self) -> str | None:
        """The HMAC in the sidecar of the chain state (:func:`stored_hex_digest`),
        or None when it is missing, cannot be read or holds anything else."""
        try:
            data = self._read_object(_CHAIN_STATE_SIG_KEY)
        except OSError as exc:
            logger.error("Cannot read the forensic chain-state signature: %s", exc)
            return None
        return stored_hex_digest(data) if data is not None else None

    def _was_keyed(self, payload: bytes) -> bool:
        """Whether the chain was written with a key: its chain state names
        the first signed record, or has a signature beside it. A write
        without the key rewrites the state but leaves the signature in
        place, so the store stays marked after unsigned records."""
        state = _state_of(payload)
        if state is not None and isinstance(state.get("signed_from"), int):
            return True
        try:
            return self._read_object(_CHAIN_STATE_SIG_KEY) is not None
        except OSError as exc:
            logger.error("Cannot read the forensic chain-state signature: %s", exc)
            return False

    def _apply_state(self, state: dict[str, Any]) -> None:
        self.chain_head = state.get("chain_head", GENESIS)
        self.record_count = state.get("record_count", 0)
        head_key = state.get("head_key")
        self._head_key = head_key if isinstance(head_key, str) and record_seq(head_key) else None
        rebuilt = state.get("rebuilt")
        self._rebuilt = rebuilt if isinstance(rebuilt, dict) else None
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
        self.chain_status = CHAIN_OK
        where = "S3" if self.boto3_client is not None else "filesystem"
        try:
            payload = self._read_object(_CHAIN_STATE_KEY)
        except OSError as exc:
            logger.error("Cannot read the forensic chain state (%s): %s", where, exc)
            self._rebuild(STATE_INVALID)
            return
        if payload is None:
            if next(self._record_items(), None) is None:
                logger.info("No forensic chain state or record (%s): new chain", where)
                return
            logger.critical("Forensic chain state missing (%s) while records exist", where)
            self._rebuild(STATE_MISSING)
            return
        if not self._state_signing_key and self._was_keyed(payload):
            message = (
                f"The forensic chain ({where}) was written with ADMINA_FORENSIC_STATE_KEY, "
                "which is not set: its next records would be written unsigned, and a "
                "verification with the key reports them as unsigned. Set "
                "ADMINA_FORENSIC_STATE_KEY (or ADMINA_FORENSIC_STATE_KEY_FILE) to the key "
                "of the store, or move the store aside to start a new chain"
            )
            if self.fail_mode == "closed":
                raise ForensicKeyError(message)
            logger.warning("%s.", message)
        if self._state_signing_key and not self._state_sig_is_valid(
            payload, self._read_state_sig()
        ):
            logger.critical(
                "Forensic chain state signature invalid or missing (%s): not used", where
            )
            self._rebuild(STATE_INVALID)
            return
        state = _state_of(payload)
        if state is None:
            logger.critical("Forensic chain state unreadable (%s): not used", where)
            self._rebuild(STATE_INVALID)
            return
        self._apply_state(state)
        logger.info(
            "Restored forensic chain state (%s): seq=%d, head=%s...",
            where,
            self.record_count,
            self.chain_head[:16],
        )
        self._check_tail()
        if self.chain_status == CHAIN_OK and self._rebuilt is not None:
            self.chain_status = CHAIN_REBUILT
            logger.warning(
                "Forensic chain state was rebuilt (%s, at record %s) and the rebuild has not "
                "been acknowledged: run `admina forensic acknowledge-rebuild` once the chain "
                "is checked",
                self._rebuilt.get("cause"),
                self._rebuilt.get("record_count"),
            )

    def _alarm(self, reason: str, sequence_number: int | None, detail: str) -> None:
        """Mark the chain invalid: nothing is recorded until an operator acts."""
        self.chain_status = CHAIN_INVALID
        self.chain_error = {"reason": reason, "sequence_number": sequence_number}
        logger.critical(
            "Forensic chain INVALID (%s at record %s): %s. No forensic record is written "
            "until the store is restored or moved aside and the process restarted "
            "(check it with `admina forensic verify` or `admina doctor`).",
            reason,
            sequence_number,
            detail,
        )

    def _rebuild(self, cause: str) -> None:
        """Rebuild the chain state from the stored records, only when they
        all verify with the key; else mark the chain invalid."""
        if self._signing_key is None:
            self._alarm(cause, None, "without a key the records cannot be verified")
            return
        last_key: list[str] = []

        def entries() -> Iterator[RecordEntry]:
            for seq, key, load in self._record_items():
                last_key[:] = [key]
                yield seq, load

        report = verify_entries(entries(), signing_key=self._signing_key, signed_from=1)
        if not report.valid:
            self._alarm(report.reason or cause, report.sequence_number, "a record does not verify")
            return
        if report.checkpoint is None:
            self._alarm(cause, None, "there is no record to rebuild it from")
            return
        self.record_count, self.chain_head = report.checkpoint
        self._head_key = last_key[0]
        self._signed_from = 1
        self.chain_status = CHAIN_REBUILT
        self._rebuilt = {
            "cause": cause,
            "record_count": self.record_count,
            "at": datetime.now(UTC).isoformat(),
        }
        logger.critical(
            "Forensic chain state rebuilt from verified records (%s): %d records, head %s...",
            cause,
            self.record_count,
            self.chain_head[:16],
        )
        self.record(
            {
                "event_id": uuid.uuid4().hex,
                "event_type": EventType.CHAIN_STATE_REBUILT,
                "cause": cause,
                "records_verified": self.record_count,
                "head_hash": self.chain_head,
            }
        )

    def _check_tail(self) -> None:
        """Check the chain restored from a valid state against the stored
        records: its last record, and the records after it."""
        count, head = self.record_count, self.chain_head
        head_record: list[RecordEntry] = []
        if count > 0:
            key = self._head_key or next(
                (k for seq, k, _ in self._record_items(count) if seq == count), None
            )
            data = self._read_object(key) if key is not None else None
            if data is None:
                self._alarm(
                    MISSING_RECORD, count, "the last record of the chain state cannot be read"
                )
                return
            head_record = [(count, lambda: data)]
            report = verify_entries(
                head_record,
                from_seq=count,
                signing_key=self._signing_key,
                signed_from=self._signed_from,
            )
            if not report.valid or report.checkpoint != (count, head):
                reason = report.reason if not report.valid else STATE_MISMATCH
                self._alarm(reason, count, "the last record of the chain state does not match it")
                return
            self._head_key = key
        last_key: list[str] = []

        def after() -> Iterator[RecordEntry]:
            for seq, key, load in self._record_items(count + 1, self._head_key):
                last_key[:] = [key]
                yield seq, load

        report = verify_entries(
            itertools.chain(head_record, after()),
            from_seq=count + 1,
            checkpoint=(count, head) if count > 0 else None,
            signing_key=self._signing_key,
            signed_from=self._signed_from,
        )
        if not report.valid:
            self._alarm(
                report.reason or STATE_MISMATCH,
                report.sequence_number,
                "a record after the last one of the chain state does not verify",
            )
            return
        if report.records:
            self.record_count, self.chain_head = report.checkpoint
            self._head_key = last_key[0]
            logger.warning(
                "Forensic chain state advanced to record %d: %d verified record(s) "
                "written after the last saved state",
                self.record_count,
                report.records,
            )
            self._persist_chain_state()

    def _persist_chain_state(self) -> None:
        """Persist chain_head and record_count (and the HMAC sidecar when a
        signing key is set). A failure is logged, and raised as
        :class:`ForensicWriteError` in closed mode."""
        state: dict[str, Any] = {
            "chain_head": self.chain_head,
            "record_count": self.record_count,
            "updated_at": datetime.now(UTC).isoformat(),
            "format": FORMAT,
            "head_key": self._head_key,
            "signed_from": self._signed_from,
        }
        if self._rebuilt is not None:
            state["rebuilt"] = self._rebuilt
        payload = json.dumps(state).encode("utf-8")
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
        (:func:`hex_digest_matches`)."""
        expected = self._sign_state_payload(payload)
        if expected is None or not signature:
            return False
        return hex_digest_matches(signature, expected)

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
            if self.chain_status == CHAIN_INVALID:
                error = self.chain_error or {}
                cause = RuntimeError(
                    f"the forensic chain is invalid ({error.get('reason')} at record "
                    f"{error.get('sequence_number')})"
                )
                return self._not_written(seq, cause)
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
                self._recent.append(forensic_record)
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
            self._recent.append(forensic_record)
            return {
                "sequence_number": seq,
                "record_hash": record_hash,
                "previous_hash": previous,
                "stored": True,
            }

    def recent_records(self, limit: int = RECENT_RECORDS_MAX) -> list[dict]:
        """Return up to *limit* records written by this process, newest first.

        Only the last ``RECENT_RECORDS_MAX`` written records are kept, in
        memory, with every backend; a record that could not be written is not
        among them, and records written before the process started are not
        read back. Use :meth:`verify_chain` for the persisted chain.
        """
        if limit <= 0:
            return []
        with self._write_lock:
            records = list(self._recent)
        return records[::-1][:limit]

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
        """False while the chain is invalid, and after a record or
        chain-state write failed, until one succeeds again."""
        return self.chain_status != CHAIN_INVALID and self._last_write_ok is not False

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
        if self.chain_status == CHAIN_INVALID and result["valid"]:
            # The records read verify, but the chain was found invalid at
            # startup (e.g. no chain state and no key to rebuild it with).
            error = self.chain_error or {}
            result.update(
                valid=False,
                reason=error.get("reason"),
                sequence_number=error.get("sequence_number"),
                checkpoint=None,
            )
        return {**result, "last_hash": head}

    def acknowledge_rebuild(self) -> dict[str, Any]:
        """Clear the ``rebuilt`` status of a chain whose state was rebuilt,
        once the whole stored chain verifies.

        Returns ``{"acknowledged": True, "records": <checked>, "last_hash":
        ...}``, or ``{"acknowledged": False, "reason": ...}``: ``not_rebuilt``
        when the chain status is not ``rebuilt``, else the reason the chain
        does not verify (see :meth:`verify`) and the status stays.
        """
        if self.chain_status != CHAIN_REBUILT:
            return {"acknowledged": False, "reason": "not_rebuilt"}
        result = self.verify()
        if not result["valid"]:
            return {
                "acknowledged": False,
                "reason": result["reason"],
                "sequence_number": result["sequence_number"],
            }
        with self._write_lock:
            self._rebuilt = None
            self.chain_status = CHAIN_OK
            self._persist_chain_state()
        logger.warning(
            "Forensic chain rebuild acknowledged: %d records verified, head %s...",
            result["records"],
            result["last_hash"][:16],
        )
        return {
            "acknowledged": True,
            "records": result["records"],
            "last_hash": result["last_hash"],
        }

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


def _refuse_key_file_inside(directory: Path | None) -> None:
    """Raise when ``ADMINA_FORENSIC_STATE_KEY_FILE`` is inside *directory*,
    the forensic directory: the key must be kept outside the store."""
    key_file = os.environ.get("ADMINA_FORENSIC_STATE_KEY_FILE", "")
    if not key_file or directory is None:
        return
    resolved = Path(key_file).resolve()
    if resolved == directory or directory in resolved.parents:
        raise SecretFileError(
            "ADMINA_FORENSIC_STATE_KEY_FILE: keep the key file outside the forensic directory"
        )


#: S3 error codes meaning that the object read does not exist.
_S3_MISSING_CODES = frozenset({"NoSuchKey", "NotFound", "404"})


def _s3_missing(exc: BaseException) -> bool:
    """True when *exc* is the answer of S3 that the object read does not
    exist: a boto3 ``ClientError`` whose error code is ``NoSuchKey`` (or
    ``NotFound`` or ``404``, the codes of a response without a body). Any
    other error (throttling, access denied, a missing bucket, a connection
    error) is not."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error")
    return isinstance(error, dict) and str(error.get("Code", "")) in _S3_MISSING_CODES


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


def verify_stored_chain(
    read: Callable[[str], bytes | None],
    entries: Callable[[int], Iterable[RecordEntry]],
    *,
    state_key: str | None = None,
    from_seq: int | None = None,
    checkpoint: tuple[int, str] | None = None,
) -> dict:
    """Verify a stored chain without writing to it.

    *read(key)* returns the bytes of the chain state (``_chain_state.json``)
    or its HMAC (``_chain_state.json.sig``), or None when missing;
    *entries(from_seq)* yields ``(sequence number, load)`` of the stored
    records from *from_seq* on, in sequence order.

    As :meth:`ForensicBlackBox.verify`, against the stored chain state. With
    *state_key* (the chain-state key) the state's HMAC and the record
    signatures are checked. When the records verify but the state does not,
    the result is invalid: ``state_missing`` (records and no state) or
    ``state_invalid`` (a state that cannot be read, or whose HMAC does not
    verify); the records are then checked from record 1 on as signed.
    ``last_hash`` is the state's head (or, without a usable state, the hash
    of the last record checked).
    """
    if checkpoint is not None and from_seq is not None:
        raise ValueError("pass from_seq or checkpoint, not both")
    payload = read(_CHAIN_STATE_KEY)
    signing_key = record_signing_key(state_key) if state_key else None
    problem: str | None = None
    state: dict[str, Any] | None = None
    if payload is None:
        problem = STATE_MISSING if next(iter(entries(1)), None) is not None else None
    else:
        sig = read(_CHAIN_STATE_SIG_KEY)
        expected = (
            hmac.new(state_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            if state_key
            else None
        )
        signature = stored_hex_digest(sig) if sig is not None else None
        if expected is not None and not hex_digest_matches(signature, expected):
            problem = STATE_INVALID
        else:
            state = _state_of(payload)
            problem = STATE_INVALID if state is None else None
    if state is not None:
        signed_from = state.get("signed_from")
        signed_from = signed_from if isinstance(signed_from, int) else None
        chain_state = (state.get("record_count", 0), state.get("chain_head", GENESIS))
    else:
        # No state to rely on: every record must be signed.
        signed_from, chain_state = 1, None
    start = checkpoint[0] if checkpoint is not None else (from_seq or 1)
    report = verify_entries(
        entries(start),
        from_seq=start,
        checkpoint=checkpoint,
        state=chain_state,
        signing_key=signing_key,
        signed_from=signed_from,
    )
    if report.valid and problem is not None:
        report.fail(problem, None)
    if chain_state is not None:
        last_hash = chain_state[1]
    else:
        last_hash = report.checkpoint[1] if report.checkpoint is not None else GENESIS
    return {**report.as_dict(), "last_hash": last_hash}


def verify_directory(
    base_dir: str | Path,
    *,
    state_key: str | None = None,
    from_seq: int | None = None,
    checkpoint: tuple[int, str] | None = None,
) -> dict:
    """Verify the chain stored in the filesystem store directory *base_dir*,
    reading one record at a time and writing nothing (see
    :func:`verify_stored_chain`)."""
    base = Path(base_dir)

    def read(key: str) -> bytes | None:
        try:
            return (base / key).read_bytes()
        except FileNotFoundError:
            return None

    def entries(start: int) -> Iterator[RecordEntry]:
        for seq, path in iter_record_files(base, start):
            yield seq, path.read_bytes

    return verify_stored_chain(
        read, entries, state_key=state_key, from_seq=from_seq, checkpoint=checkpoint
    )


def verify_bucket(
    client: Any,
    bucket: str,
    *,
    state_key: str | None = None,
    from_seq: int | None = None,
    checkpoint: tuple[int, str] | None = None,
) -> dict:
    """Verify the chain stored in the S3 *bucket* through the boto3
    *client*, reading one record at a time and writing nothing (see
    :func:`verify_stored_chain`). The chain state is missing only when S3
    answers that it does not exist; any other read error is raised."""

    def get(key: str) -> bytes:
        return client.get_object(Bucket=bucket, Key=key)["Body"].read()

    def read(key: str) -> bytes | None:
        try:
            return get(key)
        except Exception as exc:  # noqa: BLE001 — any client or connection error
            if _s3_missing(exc):
                return None
            raise

    def keys() -> Iterator[str]:
        token: str | None = None
        while True:
            kwargs: dict = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            resp = client.list_objects_v2(**kwargs)
            for item in resp.get("Contents", []) or []:
                yield item["Key"]
            if not resp.get("IsTruncated"):
                return
            token = resp.get("NextContinuationToken")

    def entries(start: int) -> Iterator[RecordEntry]:
        for seq, key in ordered_record_keys(keys(), start):
            yield seq, partial(get, key)

    return verify_stored_chain(
        read, entries, state_key=state_key, from_seq=from_seq, checkpoint=checkpoint
    )


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
