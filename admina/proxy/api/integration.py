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

"""External integration REST endpoints.

Provides a simpler REST interface for non-MCP callers:
  POST /api/v1/validate  — validate an action payload
  POST /api/v1/audit     — log an action result to forensic black box

The records of ``/api/v1/audit`` are stamped by the proxy: ``source`` is
always ``api_v1_audit`` (a ``source`` sent by the caller is kept as
``client_source``) and ``submitted_by`` is the credential the request was
admitted with: ``api_key``, ``append_key`` (``ADMINA_AUDIT_APPEND_KEY``),
``user:<id>`` for an auth provider's user, or ``unauthenticated``. An
``event_type`` of the records the proxy writes itself
(:data:`PROXY_RECORD_TYPES`, compared without case and surrounding white
space) is refused with ``400``.

Each ``/api/v1/validate`` request that reaches the governance pipeline is
passed to the ``on_decision`` callable of
:func:`create_integration_endpoints` as an
:class:`admina.proxy.decisions.Decision` of the ``integration`` surface
(``ERROR`` when the pipeline raised), with its duration: the proxy counts it
on ``/metrics`` and emits its ``governance.decision`` event (see
``admina.proxy.main.record_decision``). The decision reports ``session_id``
and ``agent_id`` of the body when they are strings or integers, without
CR/LF and cut to 128 characters; its ``request_sha256`` is the SHA-256 of
``content`` (of its JSON form when it is not a string).
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from admina.core.exception_log import log_frames
from admina.core.types import EventType
from admina.domains.compliance.forensic import ForensicWriteError
from admina.proxy.decisions import Decision, text_sha256

logger = logging.getLogger("admina.api.integration")

# Longest session_id / agent_id reported, as for the X-Session-Id header.
_REPORTED_ID_MAX = 128


def _reported_id(value: Any) -> str | None:
    """*value* as a decision reports it (see the module docstring), or None."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    return re.sub(r"[\r\n]", "", str(value))[:_REPORTED_ID_MAX]


def _content_sha256(content: Any) -> str:
    """SHA-256 of *content*, or of its JSON form when it is not a string."""
    if isinstance(content, str):
        return text_sha256(content)
    return text_sha256(json.dumps(content, default=str))


# Sentinel default settings object used when no get_settings callable is
# provided (e.g. in integration tests that don't need mode awareness).
class _DefaultSettings:
    GOVERNANCE_MODE: str = "enforce"


def _scrub_check_errors(checks: dict[str, Any]) -> dict[str, Any]:
    """Replace the ``error`` of each check with a generic reason for external
    callers.

    A guard that breaks its contract records the class of its exception
    under ``checks["guard_<name>"]["error"]``; the forensic record keeps it,
    the REST API returns ``"Guard error"``. The check name and its ``ERROR``
    action still tell a caller which guard failed.
    """
    scrubbed: dict[str, Any] = {}
    for name, entry in checks.items():
        if isinstance(entry, dict) and "error" in entry:
            scrubbed[name] = {**entry, "error": "Guard error"}
        else:
            scrubbed[name] = entry
    return scrubbed


# The checkpoint of GET /api/v1/forensic/verify: SEQ:HASH.
_CHECKPOINT = re.compile(r"([0-9]+):([0-9a-f]{64})")

#: ``source`` of every record written through ``POST /api/v1/audit``.
AUDIT_SOURCE = "api_v1_audit"

#: The ``event_type`` of the forensic records the proxy writes itself;
#: ``POST /api/v1/audit`` refuses them (``400``).
PROXY_RECORD_TYPES = frozenset(
    t.value
    for t in (
        EventType.MCP_REQUEST,
        EventType.MCP_RESPONSE,
        EventType.GATEWAY_REQUEST,
        EventType.GATEWAY_RESPONSE,
        EventType.GATEWAY_RESPONSE_SCAN,
        EventType.POLICY_VIOLATION,
        EventType.CHAIN_STATE_REBUILT,
    )
)


def _proxy_record_type(event_type: Any) -> bool:
    return isinstance(event_type, str) and event_type.strip().lower() in PROXY_RECORD_TYPES


def _submitter(request: Request) -> str:
    """The credential *request* was admitted with (see the module docstring)."""
    credential = getattr(request.state, "credential", None)
    if isinstance(credential, str) and credential:
        return credential
    user = getattr(request.state, "user", None)
    if isinstance(user, dict) and user.get("user_id"):
        return f"user:{user['user_id']}"
    return "unauthenticated"


def _require_forensic_records(fbox: Any) -> None:
    """503 while a closed-mode forensic store does not accept records (its
    last write failed, or its backend could not be opened)."""
    if fbox is None or getattr(fbox, "fail_mode", "open") != "closed":
        return
    accepting = getattr(fbox, "accepting_records", None)
    if accepting is not None and not accepting():
        raise HTTPException(
            status_code=503,
            detail="Forensic records cannot be written (ADMINA_FORENSIC_FAIL_MODE=closed)",
        )


def create_integration_endpoints(
    *,
    get_firewall: Any,
    get_pii_scanner: Any,
    get_loop_breaker: Any,
    get_forensic_box: Any,
    get_settings: Any = lambda: _DefaultSettings(),
    get_egress_policy: Any = lambda: None,
    on_decision: Callable[..., None] | None = None,
) -> APIRouter:
    """Create a new APIRouter with integration endpoints.

    A fresh router is created on each call for test isolation.

    Args:
        get_firewall: Callable returning the firewall checker.
        get_pii_scanner: Callable returning the PII redactor.
        get_loop_breaker: Callable returning the loop breaker.
        get_forensic_box: Callable returning ForensicBlackBox | None.
        get_settings: Callable returning the settings object (optional).
        get_egress_policy: Callable returning the EgressPolicy, or None when
            egress control is disabled (optional; defaults to ``None``).
        on_decision: ``on_decision(decision, *, duration_s)``, called with
            the decision of each ``/api/v1/validate`` request (see the
            module docstring); optional.

    Returns:
        The configured APIRouter.
    """
    router = APIRouter(prefix="/api/v1", tags=["integration"])

    def decided(decision: Decision, started: float) -> None:
        if on_decision is not None:
            on_decision(decision, duration_s=time.perf_counter() - started)

    @router.post("/validate")
    async def validate_action(body: dict) -> dict[str, Any]:
        """Validate an action payload through the governance pipeline.

        Expects JSON body with at least ``content`` (str).  Optional:
        ``session_id``, ``method``.

        Returns ``action`` (ALLOW / BLOCK / REDACT), ``risk_level``,
        and per-domain ``checks``. With a closed-mode forensic store that
        does not accept records (its last write failed), 503. When the
        pipeline raises, 500 ``{"detail": "Internal Server Error"}``, and the
        exception is logged by its class (:mod:`admina.core.exception_log`).
        """
        from admina.domains.agent_security.egress import egress_policy_for, resolve_egress_mode
        from admina.domains.governance import run_pipeline

        started = time.perf_counter()
        content = body.get("content", "")
        if not content:
            raise HTTPException(status_code=400, detail="'content' field is required")
        _require_forensic_records(get_forensic_box())

        session_id = body.get("session_id", "rest-" + uuid.uuid4().hex[:8])
        agent_id = body.get("agent_id", "rest-api")
        request_id = body.get("request_id", uuid.uuid4().hex)

        settings = get_settings()
        mode = getattr(settings, "GOVERNANCE_MODE", "enforce")

        event_id = uuid.uuid4().hex
        pipeline_body = {"params": {"content": content}}
        try:
            result = await run_pipeline(
                body=pipeline_body,
                content_str=content,
                session_id=session_id,
                agent_id=agent_id,
                request_id=request_id,
                params={"content": content},
                firewall=get_firewall(),
                pii_redactor=get_pii_scanner(),
                loop_breaker=get_loop_breaker(),
                governance_guards=[],
                injection_enabled=True,
                pii_enabled=True,
                mode=mode,
                egress_policy=egress_policy_for(get_egress_policy(), "integration"),
                egress_mode=resolve_egress_mode(mode),
            )
        except Exception as exc:  # noqa: BLE001 — answered 500, logged by its class
            decided(Decision.failed("integration", event_id), started)
            logger.error("Validate governance pipeline failed: %s", type(exc).__name__)
            log_frames(logger, "Validate governance pipeline", exc)
            raise HTTPException(status_code=500, detail="Internal Server Error") from None
        decided(
            Decision.of(
                "integration",
                event_id,
                result,
                request_sha256=_content_sha256(content),
                session_id=_reported_id(session_id),
                agent_id=_reported_id(agent_id),
                method="validate",
            ),
            started,
        )

        gov = result.gov_response  # action/risk_level are already UPPERCASE
        pii_count = result.checks.get("pii_redaction", {}).get("count", 0)

        # External REST contract: REDACT signals content was redacted on an
        # otherwise-ALLOW request.  This vocab is consumed by n8n / CheshireCat
        # / OpenClaw and mirrors the internal GovernanceAction.REDACT value.
        if gov.action == "ALLOW" and pii_count > 0:
            action = "REDACT"
        elif gov.action == "CIRCUIT_BREAK":
            # external REST vocab: a loop is reported as BLOCK (consumers
            # never received CIRCUIT_BREAK from this endpoint historically)
            action = "BLOCK"
        else:
            action = gov.action

        redacted_content = (
            result.redacted_body.get("params", {}).get("content", content)
            if result.redacted_body is not None
            else content
        )

        return {
            "action": action,
            "risk_level": gov.risk_level,
            "checks": _scrub_check_errors(result.checks),
            "redacted_content": redacted_content if action == "REDACT" else None,
            "latency_ms": round(result.latency_ms, 2),
        }

    @router.post("/audit")
    async def audit_action(body: dict, request: Request) -> dict[str, Any]:
        """Log an action result to the forensic black box.

        Expects JSON body with ``event`` (dict) containing the
        action details to record. ``source`` and ``submitted_by`` are set
        by the proxy, and an ``event_type`` of the proxy's own records is
        refused with 400 (see the module docstring).

        Returns forensic record metadata (sequence number, hash);
        ``recorded: false`` when the record could not be written, or 503
        with a closed-mode forensic store.
        """
        event_data = body.get("event")
        if not event_data or not isinstance(event_data, dict):
            raise HTTPException(
                status_code=400,
                detail="'event' field is required and must be a dict",
            )
        if _proxy_record_type(event_data.get("event_type")):
            raise HTTPException(
                status_code=400,
                detail="'event_type' names a record type the proxy writes itself",
            )

        fbox = get_forensic_box()
        if fbox is None:
            return {
                "recorded": False,
                "error": "Forensic black box not available (no storage backend configured)",
            }

        event_data = dict(event_data)
        event_data.setdefault("event_id", str(uuid.uuid4()))
        event_data.setdefault("timestamp", datetime.now(UTC).isoformat())
        client_source = event_data.pop("source", None)
        if client_source is not None and client_source != AUDIT_SOURCE:
            event_data["client_source"] = client_source
        event_data["source"] = AUDIT_SOURCE
        event_data["submitted_by"] = _submitter(request)

        try:
            record = fbox.record(event_data)
        except ForensicWriteError:
            raise HTTPException(
                status_code=503, detail="The forensic record could not be written"
            ) from None
        if record.get("record_hash") is None:
            return {"recorded": False, "error": "The forensic record could not be written"}
        return {
            "recorded": True,
            "sequence_number": record["sequence_number"],
            "record_hash": record["record_hash"],
            "previous_hash": record["previous_hash"],
        }

    @router.get(
        "/forensic/verify", tags=["integration"], summary="Forensic hash-chain integrity check"
    )
    async def forensic_verify(
        from_seq: int | None = Query(default=None, ge=1),
        checkpoint: str | None = Query(default=None, description="SEQ:HASH"),
    ) -> dict[str, Any]:
        """Verify the forensic hash-chain integrity.

        Reads the persisted records back from the configured backend, one
        at a time, and checks them (see
        :mod:`admina.domains.compliance.forensic_integrity`). An invalid
        chain is a successful *report* (HTTP 200 with ``"valid": false``) —
        it is not a server error. Only an unexpected exception produces a
        500 response.

        ``from_seq``: verify from that sequence number on; ``checkpoint``
        (``SEQ:HASH``, the ``checkpoint`` of an earlier result): verify only
        the records after it. Not both (400).

        Returns a dict with at least:
            ``valid`` (bool), ``records`` (int), ``last_hash`` (str),
            ``backend`` (str — the store_name of the forensic box).
        """
        resume: tuple[int, str] | None = None
        if checkpoint is not None:
            match = _CHECKPOINT.fullmatch(checkpoint.strip())
            if match is None or int(match.group(1)) < 1:
                raise HTTPException(
                    status_code=400,
                    detail="checkpoint must be SEQ:HASH (SEQ >= 1, 64 lowercase hex characters)",
                )
            resume = (int(match.group(1)), match.group(2))
        if resume is not None and from_seq is not None:
            raise HTTPException(status_code=400, detail="pass from_seq or checkpoint, not both")

        fbox = get_forensic_box()
        if fbox is None:
            return {
                "valid": None,
                "records": 0,
                "last_hash": "",
                "backend": "not_configured",
                "detail": "Forensic black box not available (no storage backend configured)",
            }

        options: dict[str, Any] = {}
        if from_seq is not None:
            options["from_seq"] = from_seq
        if resume is not None:
            options["checkpoint"] = resume
        result = await fbox.verify_chain(**options)
        if getattr(fbox, "boto3_client", None) is not None:
            backend = "s3"
        elif getattr(fbox, "filesystem_dir", None) is not None:
            backend = "filesystem"
        else:
            backend = "memory"
        return {**result, "backend": backend}

    return router
