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
"""

import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

# minio is in the [proxy] extra. Make it optional so the forensic module
# is importable on a pure-SDK install (filesystem backend works without it).
try:
    from minio.error import S3Error as _S3Error  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover

    class _S3Error(Exception):  # type: ignore[no-redef]
        pass


logger = logging.getLogger("admina.forensic_blackbox")

# Key used to persist the chain state in MinIO.
_CHAIN_STATE_KEY = "_chain_state.json"


class ForensicBlackBox:
    """
    Immutable audit log with hash-chain integrity.

    Three storage backends are supported, in this priority order:

    1. ``boto3_client`` — generic S3-compatible (AWS S3, Cloudflare R2,
       SeaweedFS, Garage, Ceph RGW, Backblaze B2, …). The recommended
       backend for new air-gapped or on-premise deployments since the
       MinIO Python SDK has been archived.
    2. ``minio_client`` — legacy MinIO SDK. Kept for backward
       compatibility; deprecated, will be removed in a future release.
    3. ``filesystem_dir`` — local JSON files with the same hash-chain
       semantics. Zero external dependencies. Default for OSS / single
       host / development deployments.

    If none of the three is configured the class still works as an
    in-memory ledger (events are hashed and chained, but lost on
    restart).
    """

    def __init__(
        self,
        minio_client=None,
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
    ):
        self.minio_client = minio_client
        self.boto3_client = boto3_client
        self.bucket = bucket
        self.filesystem_dir = Path(filesystem_dir).resolve() if filesystem_dir else None
        self.s3_object_lock = bool(s3_object_lock)
        self.s3_lock_days = int(s3_lock_days)
        self.s3_auto_create_locked_bucket = bool(s3_auto_create_locked_bucket)
        self.s3_max_retries = max(0, int(s3_max_retries))
        self.s3_base_delay_s = max(0.0, float(s3_base_delay_s))
        self.chain_head: str = "GENESIS"
        self.record_count: int = 0
        if self.filesystem_dir is not None:
            self.filesystem_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_bucket()
        self._restore_chain_state()

    # ── Retry / backoff helper for transient S3 failures ────────
    def _s3_call(self, fn, *args, **kwargs):
        """Run *fn(*args, **kwargs)* with exponential backoff retries.

        Used only by the boto3 backend; the legacy MinIO and filesystem
        paths keep their original behaviour.
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
        if self.minio_client is not None:
            try:
                if not self.minio_client.bucket_exists(self.bucket):
                    self.minio_client.make_bucket(self.bucket)
                    logger.info("Created forensic bucket (MinIO): %s", self.bucket)
            except _S3Error:
                logger.exception("Failed to create forensic bucket %s", self.bucket)
            return
        if self.filesystem_dir is not None:
            return  # mkdir already done in __init__
        logger.warning("No forensic backend configured — events kept in memory only")

    def _restore_chain_state(self):
        """Restore chain_head and record_count from the configured backend."""
        if self.boto3_client is not None:
            try:
                obj = self.boto3_client.get_object(Bucket=self.bucket, Key=_CHAIN_STATE_KEY)
                state = json.loads(obj["Body"].read().decode("utf-8"))
                self.chain_head = state.get("chain_head", "GENESIS")
                self.record_count = state.get("record_count", 0)
                logger.info(
                    "Restored forensic chain state (S3): seq=%d, head=%s...",
                    self.record_count,
                    self.chain_head[:16],
                )
            except Exception:  # noqa: BLE001 — NoSuchKey or similar
                logger.info("No existing forensic chain state in S3, starting fresh")
            return
        if self.minio_client is not None:
            try:
                response = self.minio_client.get_object(self.bucket, _CHAIN_STATE_KEY)
                state = json.loads(response.read().decode("utf-8"))
                self.chain_head = state.get("chain_head", "GENESIS")
                self.record_count = state.get("record_count", 0)
                logger.info(
                    "Restored forensic chain state (MinIO): seq=%d, head=%s...",
                    self.record_count,
                    self.chain_head[:16],
                )
            except (_S3Error, json.JSONDecodeError):
                logger.info("No existing forensic chain state found, starting fresh")
            return
        if self.filesystem_dir is not None:
            state_path = self.filesystem_dir / _CHAIN_STATE_KEY
            if state_path.exists():
                try:
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    self.chain_head = state.get("chain_head", "GENESIS")
                    self.record_count = state.get("record_count", 0)
                    logger.info(
                        "Restored forensic chain state (filesystem): seq=%d, head=%s...",
                        self.record_count,
                        self.chain_head[:16],
                    )
                except (OSError, json.JSONDecodeError):
                    logger.warning("Corrupt chain state at %s — starting fresh", state_path)

    def _persist_chain_state(self):
        """Persist chain_head and record_count to the configured backend."""
        payload = json.dumps(
            {
                "chain_head": self.chain_head,
                "record_count": self.record_count,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        ).encode("utf-8")
        if self.boto3_client is not None:
            try:
                # Chain-state is mutable by design (overwritten every
                # write) so we deliberately do NOT lock it. Locking the
                # individual records (in _store_to_s3) is what makes the
                # chain tamper-evident.
                self._s3_call(
                    self.boto3_client.put_object,
                    Bucket=self.bucket,
                    Key=_CHAIN_STATE_KEY,
                    Body=payload,
                    ContentType="application/json",
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to persist chain state (S3): %s", e)
            return
        if self.minio_client is not None:
            try:
                self.minio_client.put_object(
                    self.bucket,
                    _CHAIN_STATE_KEY,
                    BytesIO(payload),
                    length=len(payload),
                    content_type="application/json",
                )
            except _S3Error as e:
                logger.warning("Failed to persist chain state (MinIO): %s", e)
            return
        if self.filesystem_dir is not None:
            try:
                (self.filesystem_dir / _CHAIN_STATE_KEY).write_bytes(payload)
            except OSError as e:
                logger.warning("Failed to persist chain state (filesystem): %s", e)

    def _compute_hash(self, data: str) -> str:
        """SHA-256 hash for chain integrity."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def record(self, event: dict) -> dict:
        """
        Record an event to the forensic black box.
        Adds hash-chain integrity and eIDAS-style timestamp.
        Returns the forensic record with integrity metadata.
        """
        self.record_count += 1

        forensic_record = {
            "sequence_number": self.record_count,
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "timestamp_unix_ms": int(time.time() * 1000),
            "previous_hash": self.chain_head,
            "event": event,
        }

        record_json = json.dumps(forensic_record, sort_keys=True, default=str)
        record_hash = self._compute_hash(record_json)
        forensic_record["record_hash"] = record_hash

        self.chain_head = record_hash

        # Store the record and persist the updated chain state
        self._store_to_s3(forensic_record)
        self._persist_chain_state()

        return {
            "sequence_number": self.record_count,
            "record_hash": record_hash,
            "previous_hash": forensic_record["previous_hash"],
            "stored": (
                self.minio_client is not None
                or self.boto3_client is not None
                or self.filesystem_dir is not None
            ),
        }

    def _store_to_s3(self, record: dict):
        """Persist a forensic record using the configured backend."""
        ts = datetime.now(UTC)
        key = (
            f"{ts.year}/{ts.month:02d}/{ts.day:02d}/"
            f"{ts.hour:02d}/{record['sequence_number']:08d}.json"
        )
        data = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
        if self.boto3_client is not None:
            put_kwargs: dict = {
                "Bucket": self.bucket,
                "Key": key,
                "Body": data,
                "ContentType": "application/json",
            }
            if self.s3_object_lock:
                from datetime import timedelta

                retain_until = datetime.now(UTC) + timedelta(days=self.s3_lock_days)
                put_kwargs["ObjectLockMode"] = "COMPLIANCE"
                put_kwargs["ObjectLockRetainUntilDate"] = retain_until
            try:
                self._s3_call(self.boto3_client.put_object, **put_kwargs)
                logger.debug(
                    "Stored forensic record (S3%s): %s",
                    " + lock" if self.s3_object_lock else "",
                    key,
                )
            except Exception:  # noqa: BLE001
                logger.exception("Failed to store forensic record %s", key)
            return
        if self.minio_client is not None:
            try:
                self.minio_client.put_object(
                    self.bucket,
                    key,
                    BytesIO(data),
                    length=len(data),
                    content_type="application/json",
                )
                logger.debug("Stored forensic record (MinIO): %s", key)
            except _S3Error:
                logger.exception("Failed to store forensic record %s", key)
            return
        if self.filesystem_dir is not None:
            path = self.filesystem_dir / key
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                logger.debug("Stored forensic record (filesystem): %s", path)
            except OSError:
                logger.exception("Failed to write forensic record %s", path)
            return
        # No backend → in-memory only, nothing to do

    def verify_chain(self, records: list[dict]) -> dict:
        """
        Verify the integrity of a chain of forensic records.
        Returns verification result.
        """
        if not records:
            return {"valid": True, "checked": 0}

        for i, record in enumerate(records):
            event_copy = {k: v for k, v in record.items() if k != "record_hash"}
            recomputed = self._compute_hash(json.dumps(event_copy, sort_keys=True, default=str))
            if recomputed != record.get("record_hash"):
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

    def get_stats(self) -> dict:
        return {
            "record_count": self.record_count,
            "chain_head": self.chain_head[:16] + "...",
            "storage_available": self.minio_client is not None,
        }
