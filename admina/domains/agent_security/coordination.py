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

"""
Admina — Coordination detector — Agent Security domain

Finds agents coordinating through a destination the operator never declared.

A legitimate shared work queue and an emergent coordination channel have the
same behavioural signature — many agents, one destination, writes, content
passing between them — because they are the same behaviour. What separates them
is authorisation, so this module looks for *undeclared* coordination and takes
its declared set from configuration.

Nothing here blocks. A confirmed verdict is written to a quarantine set that
EgressPolicy consumes, so the decision stays on the inline path that already
owns it.
"""

from __future__ import annotations

import logging
from typing import Any

__all__ = ["FanInCounter"]

logger = logging.getLogger("admina.coordination")


class FanInCounter:
    """Distinct agents making payload-bearing calls to one destination.

    State is two tumbling buckets rather than a sorted set: summing the current
    and previous bucket approximates a sliding window at two reads, and the
    per-key TTL does the eviction for free.
    """

    def __init__(self, redis: Any, window_seconds: int, cap: int = 256) -> None:
        self._redis = redis
        self._window = max(1, window_seconds)
        self._cap = cap

    def _key(self, destination: str, bucket: int) -> str:
        return f"admina:egress:fanin:{destination}:{bucket}"

    def _buckets(self, now: float) -> tuple[int, int]:
        current = int(now // self._window)
        return current, current - 1

    async def record(self, destination: str, agent_id: str, now: float) -> int:
        """Record one agent against a destination; return distinct agents in window.

        Returns 0 when Redis is unavailable. The caller treats that as "cannot
        conclude" and reports a degraded status — it must never be read as
        "no coordination".
        """
        if self._redis is None:
            return 0
        current, previous = self._buckets(now)
        try:
            key = self._key(destination, current)
            await self._redis.sadd(key, agent_id)
            await self._redis.expire(key, self._window * 2)
            seen: set[str] = set()
            for bucket in (current, previous):
                seen |= set(await self._redis.smembers(self._key(destination, bucket)))
            return min(len(seen), self._cap)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("Fan-in counter unavailable, cannot correlate: %s", exc)
            return 0

    async def agents(self, destination: str, now: float) -> set[str]:
        """Agent ids seen against a destination across both buckets."""
        if self._redis is None:
            return set()
        current, previous = self._buckets(now)
        found: set[str] = set()
        try:
            for bucket in (current, previous):
                found |= set(await self._redis.smembers(self._key(destination, bucket)))
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("Fan-in counter unavailable, cannot list agents: %s", exc)
            return set()
        return found
