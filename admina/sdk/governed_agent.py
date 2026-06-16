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

"""Admina — GovernedAgent SDK primitive.

Exposes the existing proxy governance pipeline (firewall, loop breaker,
PII redaction) as a Python object for programmatic agent-to-agent calls.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from admina.core.event_bus import EventType, GovernanceEvent, bus
from admina.domains.governance import _deep_redact, _extract_text_fields
from admina.sdk._compat import run_sync
from admina.sdk.retry import RetryPolicy, run_with_retry

__all__ = ["GovernedAgent", "GovernedMCPResponse"]


@dataclass
class GovernedMCPResponse:
    """Response from GovernedAgent.call().

    Attributes:
        result: The upstream response payload.
        action: Governance action taken (ALLOW, BLOCK, REDACT, CIRCUIT_BREAK).
        risk_level: Risk level of the request.
        governance: Full governance details (domain results, latency).
    """

    result: Any = None
    action: str = "ALLOW"
    risk_level: str = "LOW"
    governance: dict[str, Any] = field(default_factory=dict)


UpstreamCallable = Callable[..., Awaitable[dict]]


def _load_firewall() -> Any:
    """Engine from admina.engines (honors ADMINA_ENGINE and YAML firewall overrides)."""
    from admina.engines import get_firewall

    return get_firewall()


def _load_loop_breaker() -> Any:
    """Engine from admina.engines (honors ADMINA_ENGINE)."""
    from admina.engines import get_loop_breaker

    return get_loop_breaker()


def _load_pii_redactor() -> Any:
    """Engine from admina.engines (honors ADMINA_ENGINE and pii_engine)."""
    from admina.engines import get_pii_engine

    return get_pii_engine()


def _redact_value(obj: Any, pii_redactor: Any) -> tuple[Any, int]:
    """Collision-safe deep redaction returning (redacted, pii_count)."""
    acc: dict[str, Any] = {"redacted_text": "", "entities": [], "count": 0}
    redacted = _deep_redact(obj, acc, pii_redactor)
    return redacted, acc["count"]


class GovernedAgent:
    """SDK primitive for governed agent-to-agent calls.

    Wraps an upstream callable with the full governance pipeline:
    firewall check, loop detection, PII redaction (bidirectional),
    and event emission.

    Args:
        upstream: An async callable that performs the actual upstream call,
            accepting (method, params, **kwargs) and returning a dict.
        audit: Whether to emit governance events.
        pii_redaction: Whether to run PII redaction.
        firewall_enabled: Whether to run the injection firewall.
        loop_detection: Whether to run loop detection.
    """

    def __init__(
        self,
        upstream: UpstreamCallable,
        audit: bool = True,
        pii_redaction: bool = True,
        firewall_enabled: bool = True,
        loop_detection: bool = True,
        retry: RetryPolicy | None = None,
    ) -> None:
        """Initialize GovernedAgent.

        Args:
            upstream: Async callable for upstream calls.
            audit: If True, emit events to the event bus.
            pii_redaction: If True, redact PII bidirectionally.
            firewall_enabled: If True, run injection firewall.
            loop_detection: If True, run loop breaker.
            retry: Optional RetryPolicy for transient upstream errors. Default
                None (single attempt, unchanged behaviour). Retry is opt-in
                because the upstream callable may be non-idempotent (e.g. a
                tool call that triggers a payment or a git push).
        """
        self._upstream = upstream
        self._audit = audit
        self._pii_redaction = pii_redaction
        self._firewall_enabled = firewall_enabled
        self._loop_detection = loop_detection
        self._retry = retry
        self._session_id = str(uuid.uuid4())
        self._firewall: Any = None
        self._loop_breaker: Any = None
        self._pii_redactor: Any = None

    def _get_firewall(self) -> Any:
        """Return the firewall, creating it lazily."""
        if self._firewall is None:
            self._firewall = _load_firewall()
        return self._firewall

    def _get_loop_breaker(self) -> Any:
        """Return the loop breaker, creating it lazily."""
        if self._loop_breaker is None:
            self._loop_breaker = _load_loop_breaker()
        return self._loop_breaker

    def _get_pii_redactor(self) -> Any:
        """Return the PII redactor, creating it lazily."""
        if self._pii_redactor is None:
            self._pii_redactor = _load_pii_redactor()
        return self._pii_redactor

    async def call(
        self,
        method: str,
        params: dict,
        **kwargs: Any,
    ) -> GovernedMCPResponse:
        """Make a governed upstream call.

        Runs the governance pipeline on the request, forwards to
        upstream if allowed, then inspects the response bidirectionally.

        Args:
            method: The RPC method name.
            params: The call parameters.
            **kwargs: Additional arguments (session_id, etc.).

        Returns:
            GovernedMCPResponse with result, action, and governance info.
        """
        session_id = kwargs.pop("session_id", None) or self._session_id
        start_us = time.time() * 1_000_000
        governance: dict[str, Any] = {}

        # 1. Emit AGENT_REQUEST event
        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.AGENT_REQUEST,
                    session_id=session_id,
                    domain="agent-security",
                    metadata={"method": method},
                )
            )

        text_to_scan = " ".join(_extract_text_fields(params))

        # 2. Loop detection
        if self._loop_detection and text_to_scan:
            loop_result = self._get_loop_breaker().check(
                session_id,
                text_to_scan,
            )
            governance["loop_breaker"] = loop_result
            if loop_result.get("is_loop"):
                return await self._blocked_response(
                    session_id,
                    start_us,
                    "CIRCUIT_BREAK",
                    "HIGH",
                    "loop_breaker",
                    governance,
                )

        # 3. Firewall check
        if self._firewall_enabled and text_to_scan:
            fw_result = self._get_firewall().check(text_to_scan)
            governance["firewall"] = fw_result
            if fw_result.get("is_injection"):
                return await self._blocked_response(
                    session_id,
                    start_us,
                    "BLOCK",
                    fw_result.get("risk_level", "HIGH"),
                    "firewall",
                    governance,
                )

        # 4. PII redaction on request (inbound)
        redacted_params = params
        if self._pii_redaction:
            redacted_params, pii_count = _redact_value(params, self._get_pii_redactor())
            governance["pii_request"] = {
                "redacted": pii_count > 0,
                "count": pii_count,
            }

        # 5. Forward to upstream
        upstream_result = await run_with_retry(
            lambda: self._upstream(method, redacted_params, **kwargs),
            self._retry,
        )

        # 6. PII redaction on response (outbound)
        redacted_result = upstream_result
        if self._pii_redaction:
            redacted_result, pii_count = _redact_value(upstream_result, self._get_pii_redactor())
            governance["pii_response"] = {
                "redacted": pii_count > 0,
                "count": pii_count,
            }

        latency_us = time.time() * 1_000_000 - start_us
        governance["latency_us"] = latency_us

        action = "ALLOW"
        pii_req = governance.get("pii_request", {}).get("count", 0)
        pii_resp = governance.get("pii_response", {}).get("count", 0)
        if pii_req > 0 or pii_resp > 0:
            action = "REDACT"

        # 7. Emit AGENT_RESPONSE event
        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.AGENT_RESPONSE,
                    session_id=session_id,
                    domain="agent-security",
                    action=action,
                    metadata={
                        "method": method,
                        "latency_us": latency_us,
                    },
                )
            )

        return GovernedMCPResponse(
            result=redacted_result,
            action=action,
            risk_level="LOW",
            governance=governance,
        )

    async def _blocked_response(
        self,
        session_id: str,
        start_us: float,
        action: str,
        risk_level: Any,
        domain: str,
        governance: dict[str, Any],
    ) -> GovernedMCPResponse:
        """Build a blocked response and emit the event.

        Args:
            session_id: Session identifier.
            start_us: Start time in microseconds.
            action: The governance action (BLOCK, CIRCUIT_BREAK).
            risk_level: The risk level.
            domain: Which domain blocked the request.
            governance: Governance dict to include.

        Returns:
            GovernedMCPResponse with the block decision.
        """
        latency_us = time.time() * 1_000_000 - start_us
        governance["latency_us"] = latency_us

        risk_str = str(risk_level)
        if hasattr(risk_level, "value"):
            risk_str = str(risk_level.value).upper()
        else:
            risk_str = risk_str.upper()

        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.AGENT_RESPONSE,
                    session_id=session_id,
                    domain="agent-security",
                    action=action,
                    risk_level=risk_str,
                    metadata={"domain": domain},
                )
            )

        return GovernedMCPResponse(
            result=None,
            action=action,
            risk_level=risk_str,
            governance=governance,
        )

    def call_sync(self, method: str, params: dict, **kwargs: Any) -> GovernedMCPResponse:
        """Synchronous convenience wrapper around call().

        Args:
            method: The RPC method name.
            params: The call parameters.
            **kwargs: Forwarded to call().

        Returns:
            GovernedMCPResponse.
        """
        return run_sync(self.call(method, params, **kwargs))
