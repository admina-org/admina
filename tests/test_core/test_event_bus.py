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

"""Tests for core.event_bus module."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from admina.core.event_bus import EventBus, EventType, GovernanceEvent, bus


class TestEventType:
    """Tests for the EventType enum."""

    def test_all_event_types_exist(self) -> None:
        """All expected event types are defined."""
        expected = {
            # Proxy / MCP events
            "MCP_REQUEST",
            "MCP_RESPONSE",
            "INJECTION_DETECTED",
            "PII_REDACTED",
            "LOOP_DETECTED",
            "POLICY_VIOLATION",
            "CIRCUIT_BREAK",
            # SDK / framework events
            "MODEL_CALL",
            "MODEL_RESPONSE",
            "DATA_ACCESS",
            "DATA_CLASSIFY",
            "DATA_REDACT",
            "AGENT_REQUEST",
            "AGENT_RESPONSE",
            "GOVERNANCE_DECISION",
            "COMPLIANCE_CHECK",
        }
        assert {e.name for e in EventType} == expected

    def test_event_type_values(self) -> None:
        """Event type values use dot notation."""
        assert EventType.MODEL_CALL.value == "model.call"
        assert EventType.DATA_REDACT.value == "data.redact"
        assert EventType.COMPLIANCE_CHECK.value == "compliance.check"


class TestGovernanceEvent:
    """Tests for the GovernanceEvent dataclass."""

    def test_minimal_event(self) -> None:
        """Event can be created with only event_type."""
        event = GovernanceEvent(event_type=EventType.MODEL_CALL)
        assert event.event_type == EventType.MODEL_CALL
        assert isinstance(event.timestamp, datetime)
        assert event.session_id is None
        assert event.metadata == {}

    def test_full_event(self) -> None:
        """Event can be created with all fields."""
        event = GovernanceEvent(
            event_type=EventType.GOVERNANCE_DECISION,
            session_id="sess-123",
            user_id="user-456",
            domain="data-sovereignty",
            action="BLOCK",
            risk_level="high",
            metadata={"reason": "PII detected"},
        )
        assert event.action == "BLOCK"
        assert event.domain == "data-sovereignty"
        assert event.metadata["reason"] == "PII detected"

    def test_default_timestamp(self) -> None:
        """Timestamp defaults to approximately now."""
        before = datetime.now(UTC)
        event = GovernanceEvent(event_type=EventType.DATA_ACCESS)
        after = datetime.now(UTC)
        assert before <= event.timestamp <= after

    def test_metadata_isolation(self) -> None:
        """Each event gets its own metadata dict."""
        e1 = GovernanceEvent(event_type=EventType.MODEL_CALL)
        e2 = GovernanceEvent(event_type=EventType.MODEL_CALL)
        e1.metadata["key"] = "value"
        assert "key" not in e2.metadata


class TestEventBus:
    """Tests for the EventBus class."""

    def test_subscribe_and_emit(self) -> None:
        """Sync subscriber receives emitted events."""
        eb = EventBus()
        received: list[GovernanceEvent] = []
        eb.subscribe(EventType.MODEL_CALL, received.append)

        event = GovernanceEvent(event_type=EventType.MODEL_CALL)
        asyncio.run(eb.emit(event))

        assert len(received) == 1
        assert received[0] is event

    def test_subscribe_filters_by_type(self) -> None:
        """Subscriber only receives events of subscribed type."""
        eb = EventBus()
        received: list[GovernanceEvent] = []
        eb.subscribe(EventType.MODEL_CALL, received.append)

        asyncio.run(eb.emit(GovernanceEvent(event_type=EventType.DATA_ACCESS)))
        assert len(received) == 0

        asyncio.run(eb.emit(GovernanceEvent(event_type=EventType.MODEL_CALL)))
        assert len(received) == 1

    def test_subscribe_all(self) -> None:
        """Wildcard subscriber receives all event types."""
        eb = EventBus()
        received: list[GovernanceEvent] = []
        eb.subscribe_all(received.append)

        async def emit_all() -> None:
            await eb.emit(GovernanceEvent(event_type=EventType.MODEL_CALL))
            await eb.emit(GovernanceEvent(event_type=EventType.DATA_ACCESS))
            await eb.emit(GovernanceEvent(event_type=EventType.COMPLIANCE_CHECK))

        asyncio.run(emit_all())
        assert len(received) == 3

    def test_multiple_subscribers_same_type(self) -> None:
        """Multiple subscribers on the same type all receive the event."""
        eb = EventBus()
        received_a: list[GovernanceEvent] = []
        received_b: list[GovernanceEvent] = []
        eb.subscribe(EventType.AGENT_REQUEST, received_a.append)
        eb.subscribe(EventType.AGENT_REQUEST, received_b.append)

        asyncio.run(eb.emit(GovernanceEvent(event_type=EventType.AGENT_REQUEST)))

        assert len(received_a) == 1
        assert len(received_b) == 1

    def test_async_callback(self) -> None:
        """Async callbacks are awaited correctly."""
        eb = EventBus()
        received: list[GovernanceEvent] = []

        async def async_handler(event: GovernanceEvent) -> None:
            await asyncio.sleep(0)
            received.append(event)

        eb.subscribe(EventType.DATA_REDACT, async_handler)
        asyncio.run(eb.emit(GovernanceEvent(event_type=EventType.DATA_REDACT)))

        assert len(received) == 1

    def test_wildcard_and_typed_both_fire(self) -> None:
        """Both typed and wildcard subscribers fire for the same event."""
        eb = EventBus()
        typed: list[GovernanceEvent] = []
        wildcard: list[GovernanceEvent] = []

        eb.subscribe(EventType.MODEL_RESPONSE, typed.append)
        eb.subscribe_all(wildcard.append)

        event = GovernanceEvent(event_type=EventType.MODEL_RESPONSE)
        asyncio.run(eb.emit(event))

        assert len(typed) == 1
        assert len(wildcard) == 1
        assert typed[0] is wildcard[0] is event

    def test_emit_with_no_subscribers(self) -> None:
        """Emitting with no subscribers does not raise."""
        eb = EventBus()
        asyncio.run(eb.emit(GovernanceEvent(event_type=EventType.GOVERNANCE_DECISION)))


class TestModuleSingleton:
    """Tests for the module-level bus singleton."""

    def test_singleton_is_event_bus(self) -> None:
        """Module-level bus is an EventBus instance."""
        assert isinstance(bus, EventBus)

    def test_singleton_works(self) -> None:
        """Module-level bus can subscribe and emit."""
        received: list[GovernanceEvent] = []
        bus.subscribe(EventType.COMPLIANCE_CHECK, received.append)

        asyncio.run(bus.emit(GovernanceEvent(event_type=EventType.COMPLIANCE_CHECK)))
        assert len(received) >= 1
