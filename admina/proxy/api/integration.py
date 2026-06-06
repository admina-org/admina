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


def create_integration_endpoints(
    *,
    get_firewall: Any,
    get_pii_scanner: Any,
    get_loop_breaker: Any,
    get_forensic_box: Any,
) -> APIRouter:
    """Create a new APIRouter with integration endpoints.

    A fresh router is created on each call for test isolation.

    Args:
        get_firewall: Callable returning the firewall checker.
        get_pii_scanner: Callable returning the PII redactor.
        get_loop_breaker: Callable returning the loop breaker.
        get_forensic_box: Callable returning ForensicBlackBox | None.

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
        content = body.get("content", "")
        if not content:
            raise HTTPException(status_code=400, detail="'content' field is required")

        session_id = body.get("session_id", "rest-" + uuid.uuid4().hex[:8])

        start = time.perf_counter()
        action = "ALLOW"
        risk_level = "LOW"
        checks: dict[str, Any] = {}

        # Loop breaker
        lb = get_loop_breaker()
        lb_result = lb.check(session_id, content)
        checks["loop_breaker"] = lb_result
        if lb_result.get("is_loop"):
            action = "BLOCK"
            risk_level = "HIGH"

        # Firewall
        if action == "ALLOW":
            fw = get_firewall()
            fw_result = fw.check(content)
            checks["firewall"] = fw_result
            if fw_result.get("is_injection"):
                action = "BLOCK"
                risk_level = fw_result.get("risk_level", "HIGH")

        # PII redaction
        redacted_content = content
        pii = get_pii_scanner()
        pii_result = pii.redact(content)
        checks["pii_redaction"] = {
            "count": pii_result["count"],
            "entities": pii_result["entities"],
        }
        if pii_result["count"] > 0:
            redacted_content = pii_result["redacted_text"]
            if action == "ALLOW":
                action = "MODIFY"

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        return {
            "action": action,
            "risk_level": risk_level,
            "checks": checks,
            "redacted_content": redacted_content if action == "MODIFY" else None,
            "latency_ms": latency_ms,
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
