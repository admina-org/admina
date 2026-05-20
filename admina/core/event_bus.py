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

"""Async event bus for governance events.

Provides a pub/sub mechanism for governance events across the framework.
Subscribers are wired at proxy startup and include:
- OTEL exporter (governance decision spans)
- Alert channels (BLOCK/CIRCUIT_BREAK notifications)
- Dashboard WebSocket (live event feed to connected clients)
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from admina.core.types import EventType

__all__ = ["EventBus", "EventType", "GovernanceEvent", "bus"]


@dataclass
class GovernanceEvent:
    """A single governance event emitted by the framework.

    Attributes:
        event_type: The type of governance event.
        timestamp: When the event occurred.
        session_id: Optional session identifier.
        user_id: Optional user identifier.
        domain: Optional domain name (e.g. data-sovereignty, ai-infra).
        action: Optional action taken (ALLOW, BLOCK, REDACT, CIRCUIT_BREAK).
        risk_level: Optional risk level assessment.
        metadata: Additional event-specific data.
    """

    event_type: EventType
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    session_id: str | None = None
    user_id: str | None = None
    domain: str | None = None
    action: str | None = None
    risk_level: str | None = None
    metadata: dict = field(default_factory=dict)


class EventBus:
    """Async pub/sub event bus for governance events.

    Supports per-type subscriptions and wildcard subscribers that
    receive all events.
    """

    def __init__(self) -> None:
        """Initialize the event bus with empty subscriber lists."""
        self._subscribers: dict[EventType, list[Callable]] = {}
        self._wildcard_subscribers: list[Callable] = []

    def subscribe(self, event_type: EventType, callback: Callable) -> None:
        """Subscribe to a specific event type.

        Args:
            event_type: The event type to listen for.
            callback: Callable invoked with the GovernanceEvent.
                Can be sync or async.
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)

    def subscribe_all(self, callback: Callable) -> None:
        """Subscribe to all event types.

        Args:
            callback: Callable invoked with every GovernanceEvent.
                Can be sync or async.
        """
        self._wildcard_subscribers.append(callback)

    async def emit(self, event: GovernanceEvent) -> None:
        """Emit an event to all matching subscribers.

        Calls per-type subscribers first, then wildcard subscribers.
        Both sync and async callbacks are supported.

        Args:
            event: The governance event to emit.
        """
        callbacks = list(self._subscribers.get(event.event_type, []))
        callbacks.extend(self._wildcard_subscribers)

        for callback in callbacks:
            result = callback(event)
            if asyncio.iscoroutine(result):
                await result


bus = EventBus()
