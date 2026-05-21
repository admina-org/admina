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
from admina.sdk._compat import run_sync

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
    """Lazily load the InjectionFirewall."""
    from admina.domains.agent_security.firewall import InjectionFirewall

    return InjectionFirewall()


def _load_loop_breaker() -> Any:
    """Lazily load the LoopBreaker."""
    from admina.domains.agent_security.loop_breaker import LoopBreaker

    return LoopBreaker()


def _load_pii_redactor() -> Any:
    """Lazily load the PII redactor."""
    from admina.domains.data_sovereignty.pii import PIIRedactor

    return PIIRedactor()


def _extract_text(params: dict) -> str:
    """Extract scannable text from params dict.

    Args:
        params: The call params.

    Returns:
        Concatenated string values for scanning.
    """
    texts: list[str] = []
    _collect_strings(params, texts, depth=0)
    return " ".join(texts) if texts else ""


def _collect_strings(obj: Any, acc: list[str], depth: int) -> None:
    """Recursively collect string values from nested structures.

    Args:
        obj: Value to inspect.
        acc: Accumulator list.
        depth: Recursion depth (capped at 5).
    """
    if depth > 5:
        return
    if isinstance(obj, str):
        acc.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, acc, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, acc, depth + 1)


def _redact_dict(obj: Any, pii_redactor: Any, depth: int = 0) -> tuple[Any, int]:
    """Recursively redact PII in nested structures.

    Args:
        obj: Value to redact.
        pii_redactor: Object with .redact(text) method.
        depth: Recursion depth (capped at 5).

    Returns:
        Tuple of (redacted value, total PII count).
    """
    if depth > 5:
        return obj, 0
    if isinstance(obj, str):
        r = pii_redactor.redact(obj)
        return r["redacted_text"], r["count"]
    if isinstance(obj, dict):
        total = 0
        out = {}
        for k, v in obj.items():
            rv, c = _redact_dict(v, pii_redactor, depth + 1)
            out[k] = rv
            total += c
        return out, total
    if isinstance(obj, list):
        total = 0
        out_list = []
        for item in obj:
            rv, c = _redact_dict(item, pii_redactor, depth + 1)
            out_list.append(rv)
            total += c
        return out_list, total
    return obj, 0


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
    ) -> None:
        """Initialize GovernedAgent.

        Args:
            upstream: Async callable for upstream calls.
            audit: If True, emit events to the event bus.
            pii_redaction: If True, redact PII bidirectionally.
            firewall_enabled: If True, run injection firewall.
            loop_detection: If True, run loop breaker.
        """
        self._upstream = upstream
        self._audit = audit
        self._pii_redaction = pii_redaction
        self._firewall_enabled = firewall_enabled
        self._loop_detection = loop_detection
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
        session_id = kwargs.pop("session_id", None) or str(uuid.uuid4())
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

        text_to_scan = _extract_text(params)

        # 2. Firewall check
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

        # 3. Loop detection
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

        # 4. PII redaction on request (inbound)
        redacted_params = params
        if self._pii_redaction:
            redacted_params, pii_count = _redact_dict(
                params,
                self._get_pii_redactor(),
            )
            governance["pii_request"] = {
                "redacted": pii_count > 0,
                "count": pii_count,
            }

        # 5. Forward to upstream
        upstream_result = await self._upstream(method, redacted_params, **kwargs)

        # 6. PII redaction on response (outbound)
        redacted_result = upstream_result
        if self._pii_redaction and isinstance(upstream_result, dict):
            redacted_result, pii_count = _redact_dict(
                upstream_result,
                self._get_pii_redactor(),
            )
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
