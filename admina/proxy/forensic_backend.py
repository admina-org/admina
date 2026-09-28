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

"""The proxy's forensic store, built at startup.

Backend and directory: ``FORENSIC_BACKEND`` and ``FORENSIC_BASE_DIR`` when
they are set (in the environment or ``.env``, not empty), else
``domains.compliance.forensic.backend`` (or its older name ``storage``) and
``base_dir`` of admina.yaml, else ``memory``. A value set in both places with
different values is logged at startup; the environment's is used.

A ``filesystem`` or ``s3`` backend that cannot be opened (no directory, a
directory that cannot be created or written, boto3 missing, S3 not
reachable) is never replaced by the in-memory store. With
``ADMINA_FORENSIC_FAIL_MODE=closed`` the proxy does not start
(:class:`ForensicBackendError`); with ``open`` an error is logged and the
proxy starts with an
:class:`~admina.domains.compliance.forensic.UnavailableForensicStore`, which
records nothing and reports itself not writable. A directory that exists but
cannot be written is kept in ``open`` mode (its writes fail and are logged
until it can be written).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from admina.domains.compliance.forensic import ForensicBlackBox, UnavailableForensicStore

__all__ = [
    "FORENSIC_BACKENDS",
    "ForensicBackendChoice",
    "ForensicBackendError",
    "build_forensic_store",
    "forensic_backend_choice",
]

logger = logging.getLogger("admina.proxy")

#: The forensic backends.
FORENSIC_BACKENDS = ("memory", "filesystem", "s3")

_YAML_BACKEND = "domains.compliance.forensic.backend"
_YAML_BASE_DIR = "domains.compliance.forensic.base_dir"


class ForensicBackendError(RuntimeError):
    """The configured forensic backend cannot be used and
    ``ADMINA_FORENSIC_FAIL_MODE=closed``: the proxy does not start."""


@dataclass(frozen=True)
class ForensicBackendChoice:
    """The forensic backend and directory the proxy uses."""

    backend: str
    base_dir: str


def _yaml_backend(value: str) -> str:
    if not value:
        return ""
    if value == "minio":
        # As FORENSIC_BACKEND=minio: MinIO servers speak the S3 API.
        logger.warning("%s: 'minio' is the s3 backend — using 's3'", _YAML_BACKEND)
        return "s3"
    if value not in FORENSIC_BACKENDS:
        raise ValueError(
            f"{_YAML_BACKEND} must be one of: {' | '.join(FORENSIC_BACKENDS)} (got {value!r})"
        )
    return value


def _pick(settings: Any, name: str, yaml_name: str, yaml_value: str, default: str) -> str:
    """The environment's value of *name* when set, else *yaml_value*, else
    *default*; a conflict between the two is logged."""
    value = getattr(settings, name)
    if value and name in getattr(settings, "model_fields_set", ()):
        if yaml_value and yaml_value != value:
            logger.warning(
                "%s=%r (environment) overrides %s=%r (admina.yaml)",
                name,
                value,
                yaml_name,
                yaml_value,
            )
        return value
    return yaml_value or default


def forensic_backend_choice(settings: Any, config: Any) -> ForensicBackendChoice:
    """The backend and directory from *settings* (the proxy settings) and
    *config* (the loaded admina.yaml, or None); see the module docstring.

    Raises:
        ValueError: admina.yaml names an unknown backend.
    """
    forensic = getattr(getattr(config, "compliance", None), "forensic", None)
    yaml_backend = _yaml_backend(getattr(forensic, "backend", "") or "")
    yaml_dir = getattr(forensic, "base_dir", "") or ""
    return ForensicBackendChoice(
        backend=_pick(settings, "FORENSIC_BACKEND", _YAML_BACKEND, yaml_backend, "memory"),
        base_dir=_pick(settings, "FORENSIC_BASE_DIR", _YAML_BASE_DIR, yaml_dir, ""),
    )


def _unavailable(backend: str, reason: str, fail_mode: str) -> UnavailableForensicStore:
    if fail_mode == "closed":
        raise ForensicBackendError(f"{reason} (ADMINA_FORENSIC_FAIL_MODE=closed)")
    logger.error(
        "Forensic backend %s cannot be used: %s — no forensic record is written until "
        "this is fixed (ADMINA_FORENSIC_FAIL_MODE=open)",
        backend,
        reason,
    )
    return UnavailableForensicStore(backend, reason, fail_mode=fail_mode)


def _filesystem_store(base_dir: str, fail_mode: str) -> ForensicBlackBox:
    if not base_dir:
        return _unavailable(
            "filesystem",
            f"FORENSIC_BACKEND=filesystem needs FORENSIC_BASE_DIR (or {_YAML_BASE_DIR})",
            fail_mode,
        )
    try:
        box = ForensicBlackBox(filesystem_dir=base_dir, fail_mode=fail_mode)
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        return _unavailable(
            "filesystem", f"the forensic directory {base_dir} cannot be used ({reason})", fail_mode
        )
    if box.writable() is False:
        message = f"the forensic directory {base_dir} is not writable"
        if fail_mode == "closed":
            raise ForensicBackendError(f"{message} (ADMINA_FORENSIC_FAIL_MODE=closed)")
        logger.error("%s — its records are not written until it is", message)
    logger.info("Forensic backend: filesystem at %s", base_dir)
    return box


def _s3_store(settings: Any, fail_mode: str) -> ForensicBlackBox:
    try:
        import boto3
    except ImportError:
        return _unavailable("s3", "FORENSIC_BACKEND=s3 needs boto3 (pip install boto3)", fail_mode)
    kwargs: dict[str, Any] = {"service_name": "s3", "region_name": settings.FORENSIC_S3_REGION}
    if settings.FORENSIC_S3_ENDPOINT:
        kwargs["endpoint_url"] = settings.FORENSIC_S3_ENDPOINT
    if settings.FORENSIC_S3_ACCESS_KEY:
        kwargs["aws_access_key_id"] = settings.FORENSIC_S3_ACCESS_KEY
        kwargs["aws_secret_access_key"] = settings.FORENSIC_S3_SECRET_KEY
    try:
        client = boto3.client(**kwargs)
        client.list_buckets()
    except Exception as exc:  # noqa: BLE001 — any client or connection error
        return _unavailable("s3", f"S3 not reachable ({type(exc).__name__}: {exc})", fail_mode)
    logger.info(
        "S3 forensic backend connected (endpoint=%s)",
        settings.FORENSIC_S3_ENDPOINT or "default AWS",
    )
    box = ForensicBlackBox(
        boto3_client=client,
        bucket=settings.FORENSIC_S3_BUCKET,
        s3_object_lock=settings.FORENSIC_S3_LOCK,
        s3_lock_days=settings.FORENSIC_S3_LOCK_DAYS,
        s3_auto_create_locked_bucket=settings.FORENSIC_S3_LOCK_AUTO_BUCKET,
        s3_max_retries=settings.FORENSIC_S3_MAX_RETRIES,
        s3_base_delay_s=settings.FORENSIC_S3_BASE_DELAY_S,
        fail_mode=fail_mode,
    )
    if settings.FORENSIC_S3_LOCK:
        logger.info(
            "Forensic Object Lock ENABLED: every record locked for %d days "
            "in COMPLIANCE mode (WORM)",
            settings.FORENSIC_S3_LOCK_DAYS,
        )
    return box


def build_forensic_store(settings: Any, config: Any) -> ForensicBlackBox:
    """The proxy's forensic store (see the module docstring).

    Raises:
        ForensicBackendError: the backend cannot be used, in closed mode.
        ValueError: admina.yaml names an unknown backend.
    """
    choice = forensic_backend_choice(settings, config)
    fail_mode = settings.ADMINA_FORENSIC_FAIL_MODE
    if choice.backend == "s3":
        return _s3_store(settings, fail_mode)
    if choice.backend == "filesystem":
        return _filesystem_store(choice.base_dir, fail_mode)
    # Default: in-memory only. Loud warning so the operator knows the proxy
    # is running with no audit persistence.
    logger.warning(
        "Forensic backend: IN-MEMORY ONLY — events will be LOST on restart. "
        "Set FORENSIC_BACKEND=filesystem (with FORENSIC_BASE_DIR) or =s3 "
        "for persistence."
    )
    return ForensicBlackBox(fail_mode=fail_mode)
