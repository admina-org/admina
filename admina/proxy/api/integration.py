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
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException

logger = logging.getLogger("admina.api.integration")

# Sentinel default settings object used when no get_settings callable is
# provided (e.g. in integration tests that don't need mode awareness).
class _DefaultSettings:
    GOVERNANCE_MODE: str = "enforce"


def create_integration_endpoints(
    *,
    get_firewall: Any,
    get_pii_scanner: Any,
    get_loop_breaker: Any,
    get_forensic_box: Any,
    get_settings: Any = lambda: _DefaultSettings(),
) -> APIRouter:
    """Create a new APIRouter with integration endpoints.

    A fresh router is created on each call for test isolation.

    Args:
        get_firewall: Callable returning the firewall checker.
        get_pii_scanner: Callable returning the PII redactor.
        get_loop_breaker: Callable returning the loop breaker.
        get_forensic_box: Callable returning ForensicBlackBox | None.
        get_settings: Callable returning the settings object (optional).

    Returns:
        The configured APIRouter.
    """
    router = APIRouter(prefix="/api/v1", tags=["integration"])

    @router.post("/validate")
    async def validate_action(body: dict) -> dict[str, Any]:
        """Validate an action payload through the governance pipeline.

        Expects JSON body with at least ``content`` (str).  Optional:
        ``session_id``, ``method``.

        Returns ``action`` (ALLOW / BLOCK / MODIFY), ``risk_level``,
        and per-domain ``checks``.
        """
        from admina.domains.governance import run_pipeline

        content = body.get("content", "")
        if not content:
            raise HTTPException(status_code=400, detail="'content' field is required")

        session_id = body.get("session_id", "rest-" + uuid.uuid4().hex[:8])
        agent_id = body.get("agent_id", "rest-api")
        request_id = body.get("request_id", uuid.uuid4().hex)

        settings = get_settings()
        mode = getattr(settings, "GOVERNANCE_MODE", "enforce")

        pipeline_body = {"params": {"content": content}}
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
        )

        gov = result.gov_response  # action/risk_level are already UPPERCASE
        pii_count = result.checks.get("pii_redaction", {}).get("count", 0)

        # External REST contract: MODIFY signals content was redacted on an
        # otherwise-ALLOW request.  This vocab is consumed by n8n / CheshireCat
        # / OpenClaw — do not rename to REDACT.
        if gov.action == "ALLOW" and pii_count > 0:
            action = "MODIFY"
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
            "checks": result.checks,
            "redacted_content": redacted_content if action == "MODIFY" else None,
            "latency_ms": round(result.latency_ms, 2),
        }

    @router.post("/audit")
    async def audit_action(body: dict) -> dict[str, Any]:
        """Log an action result to the forensic black box.

        Expects JSON body with ``event`` (dict) containing the
        action details to record.

        Returns forensic record metadata (sequence number, hash).
        """
        event_data = body.get("event")
        if not event_data or not isinstance(event_data, dict):
            raise HTTPException(
                status_code=400,
                detail="'event' field is required and must be a dict",
            )

        fbox = get_forensic_box()
        if fbox is None:
            return {
                "recorded": False,
                "error": "Forensic black box not available (no storage backend configured)",
            }

        event_data.setdefault("event_id", str(uuid.uuid4()))
        event_data.setdefault("timestamp", datetime.now(UTC).isoformat())
        event_data.setdefault("source", "api_v1_audit")

        record = fbox.record(event_data)
        return {
            "recorded": True,
            "sequence_number": record["sequence_number"],
            "record_hash": record["record_hash"],
            "previous_hash": record["previous_hash"],
        }

    return router
