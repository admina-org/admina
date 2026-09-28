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

"""The governance decision of a request, as an event of the event bus.

Each governed request of the ``gateway``, ``mcp`` and ``integration``
(``/api/v1/validate``) surfaces has one :class:`Decision`, which
``admina.proxy.main.record_decision`` counts on ``/metrics``, emits on the
event bus and stores in ClickHouse when it is configured (the forensic
records are written by each surface).

The live feed of the dashboard, the OpenTelemetry exporter and the alert
channels read the events. An event carries names, counts and hashes, never
the text of the request (:meth:`Decision.event`): its ``metadata`` is

- ``surface``: the surface that governed the request;
- ``event_id``: the ``event_id`` of the request's forensic record (a new
  id for ``/api/v1/validate``, which writes none);
- ``domain``: the part of the pipeline that decided (``firewall``, ``pii``,
  ``loop_breaker``, a guard's name, ``pipeline``, or ``none``); for a gateway
  completion answered with the block message after the upstream answered,
  ``response_firewall`` (flagged by the response scan) or ``response_pii``
  (its PII redaction did not finish);
- ``latency_us``: the time the governance pipeline took, in microseconds;
- ``categories``: the names of the firewall categories that matched;
- ``pii_count``: the number of PII entities masked in the request;
- ``request_sha256``: the SHA-256 (64 lowercase hex characters) of the
  request the surface governs, or ``None``: for the gateway, of the RFC 8785
  form of the ``messages`` forwarded upstream (the ``request_sha256`` of the
  forensic record); for ``/mcp``, of the JSON-RPC request as the proxy
  serialises it (``json.dumps(body, default=str)``); for
  ``/api/v1/validate``, of ``content`` (:func:`text_sha256`; of its JSON
  form when it is not a string);
- ``would_action``: only in ``observe`` and ``dry-run`` mode, the action
  that ``enforce`` mode would take.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from admina.core.event_bus import GovernanceEvent
from admina.core.types import EventType
from admina.domains.governance import (
    GovernanceResult,
    build_governance_details,
    safe_serialize,
)
from admina.proxy.gateway_outcome import firewall_categories

__all__ = ["Decision", "pii_count", "text_sha256"]


def text_sha256(text: str) -> str:
    """SHA-256 (64 lowercase hex characters) of the UTF-8 encoding of
    *text*; an unpaired surrogate is encoded as its code unit."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def pii_count(result: GovernanceResult) -> int:
    """The number of PII entities the pipeline *result* masked."""
    check = result.checks.get("pii_redaction")
    count = check.get("count", 0) if isinstance(check, dict) else 0
    return count if isinstance(count, int) else 0


@dataclass(frozen=True)
class Decision:
    """The governance decision of one request of a surface."""

    surface: str
    event_id: str
    #: Upper case: ALLOW, BLOCK or CIRCUIT_BREAK; ERROR when the request
    #: failed in the proxy before its governance decision.
    action: str
    #: Upper case: LOW, MEDIUM, HIGH or CRITICAL.
    risk_level: str
    #: The part of the pipeline that decided.
    domain: str
    #: The time the governance pipeline took, in milliseconds (None without
    #: a decision).
    latency_ms: float | None = None
    categories: tuple[str, ...] = ()
    pii_count: int = 0
    request_sha256: str | None = None
    would_action: str | None = None
    session_id: str | None = None
    # For the ClickHouse row only, never on the event bus:
    agent_id: str | None = None
    method: str = ""
    tool_name: str = ""
    #: The checks of the pipeline (``build_governance_details``).
    details: dict[str, Any] = field(default_factory=dict)
    response_sha256: str | None = None

    @classmethod
    def of(
        cls,
        surface: str,
        event_id: str,
        result: GovernanceResult,
        *,
        request_sha256: str | None = None,
        session_id: str | None = None,
        agent_id: str | None = None,
        method: str = "",
        tool_name: str = "",
    ) -> Decision:
        """The decision of the pipeline *result*."""
        gov = result.gov_response
        would = result.would_action
        return cls(
            surface=surface,
            event_id=event_id,
            action=gov.action,
            risk_level=gov.risk_level,
            domain=gov.domain,
            latency_ms=result.latency_ms,
            categories=firewall_categories(result.checks.get("firewall")),
            pii_count=pii_count(result),
            request_sha256=request_sha256,
            would_action=None if would is None else str(safe_serialize(would)).upper(),
            session_id=session_id,
            agent_id=agent_id,
            method=method,
            tool_name=tool_name,
            details=build_governance_details(result),
        )

    @classmethod
    def failed(cls, surface: str, event_id: str) -> Decision:
        """The decision of a request of *surface* that failed in the proxy
        before the pipeline decided: ``ERROR``, only counted."""
        return cls(
            surface=surface, event_id=event_id, action="ERROR", risk_level="LOW", domain="none"
        )

    @property
    def decided(self) -> bool:
        """False for a request that failed before its governance decision:
        it is counted, but has no event and no ClickHouse row."""
        return self.action != "ERROR"

    @property
    def metric_action(self) -> str:
        """The ``action`` label of ``admina_requests_total``: the action,
        or ``REDACT`` for a request allowed with PII masked."""
        return "REDACT" if self.action == "ALLOW" and self.pii_count > 0 else self.action

    def metadata(self) -> dict[str, Any]:
        """The metadata of the decision's event (see the module docstring)."""
        metadata: dict[str, Any] = {
            "surface": self.surface,
            "event_id": self.event_id,
            "domain": self.domain,
            "latency_us": None if self.latency_ms is None else round(self.latency_ms * 1000, 1),
            "categories": list(self.categories),
            "pii_count": self.pii_count,
            "request_sha256": self.request_sha256,
        }
        if self.would_action is not None:
            metadata["would_action"] = self.would_action
        return metadata

    def event(self) -> GovernanceEvent:
        """The ``governance.decision`` event of the decision."""
        return GovernanceEvent(
            event_type=EventType.GOVERNANCE_DECISION,
            session_id=self.session_id,
            action=self.action,
            risk_level=self.risk_level,
            domain="proxy",
            metadata=self.metadata(),
        )
