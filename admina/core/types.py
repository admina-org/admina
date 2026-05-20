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

"""Admina — Protocol-agnostic governance types.

These dataclasses decouple the governance engine from any wire format.
Transport adapters (MCP, A2A, AG-UI, REST) convert to/from these types.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

__all__ = [
    "RiskLevel",
    "GovernanceAction",
    "EventType",
    "GovernanceRequest",
    "GovernanceResponse",
]


class RiskLevel(str, Enum):
    """Risk severity levels used across all governance domains.

    Using ``str`` mixin so values serialise directly to JSON strings.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GovernanceAction(str, Enum):
    """Actions the governance engine can take on a request."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    ESCALATE = "escalate"
    CIRCUIT_BREAK = "circuit_break"


class EventType(str, Enum):
    """Unified event types used across proxy and SDK."""

    # Proxy / MCP events
    MCP_REQUEST = "mcp_request"
    MCP_RESPONSE = "mcp_response"
    INJECTION_DETECTED = "injection_detected"
    PII_REDACTED = "pii_redacted"
    LOOP_DETECTED = "loop_detected"
    POLICY_VIOLATION = "policy_violation"
    CIRCUIT_BREAK = "circuit_break"

    # SDK / framework events
    MODEL_CALL = "model.call"
    MODEL_RESPONSE = "model.response"
    DATA_ACCESS = "data.access"
    DATA_CLASSIFY = "data.classify"
    DATA_REDACT = "data.redact"
    AGENT_REQUEST = "agent.request"
    AGENT_RESPONSE = "agent.response"
    GOVERNANCE_DECISION = "governance.decision"
    COMPLIANCE_CHECK = "compliance.check"


@dataclass
class GovernanceRequest:
    """A protocol-agnostic inbound request to the governance engine.

    Transport adapters normalize protocol-specific messages into this
    dataclass before the governance pipeline processes them.
    """

    content: str
    method: str = ""
    direction: Literal["inbound", "outbound"] = "inbound"
    session_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    protocol: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: Any = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_us: float = field(default_factory=lambda: time.time() * 1_000_000)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (excluding ``raw``)."""
        return {
            "request_id": self.request_id,
            "content": self.content,
            "method": self.method,
            "direction": self.direction,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "protocol": self.protocol,
            "metadata": self.metadata,
            "timestamp_us": self.timestamp_us,
        }


@dataclass
class GovernanceResponse:
    """The governance engine's decision for a single request.

    Returned by the governance pipeline and converted back to wire format
    by the transport adapter.
    """

    content: str
    action: Literal["ALLOW", "BLOCK", "REDACT", "CIRCUIT_BREAK"] = "ALLOW"
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "LOW"
    domain: str = ""
    latency_us: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "request_id": self.request_id,
            "content": self.content,
            "action": self.action,
            "risk_level": self.risk_level,
            "domain": self.domain,
            "latency_us": self.latency_us,
            "metadata": self.metadata,
        }
