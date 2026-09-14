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

import hashlib
import logging
from typing import Any

from admina.domains.agent_security.fingerprint import matches

__all__ = ["EchoStore", "FanInCounter"]

logger = logging.getLogger("admina.coordination")


class EchoStore:
    """Outbound content sketches, matched against later inbound content.

    Entries are ``<agent_id>:<timestamp>:<msgid>:<value>`` members in buckets
    per destination and time window. The agent and msgid (content-derived hash)
    are what let the two rules that give the verdict meaning be enforced at
    read time: a match against the same agent is discarded, and the outbound
    sketch must predate the inbound content.

    Each distinct message is matched individually against the inbound sketch.
    This prevents false positives where unrelated messages are pooled to meet
    the MIN_SHARED_SHINGLES floor that guarantees containment of one coherent
    text.

    ttl_seconds is a bucket window. Content is matchable for roughly one to
    two times that duration and is hard-bounded regardless of activity (unlike
    older time-based expiry that reset on each write).
    """

    def __init__(self, redis: Any, ttl_seconds: int, threshold: float = 0.4) -> None:
        self._redis = redis
        self._window = max(1, ttl_seconds)
        self._threshold = threshold
        self._cap = 1024  # Members per bucket before clamping.

    @staticmethod
    def _msgid(sketch_values: frozenset[int]) -> str:
        """Derive a short content-based message id from the sketch."""
        sorted_values = sorted(sketch_values)
        h = hashlib.sha256(str(sorted_values).encode()).digest()
        return h.hex()[:8]

    def _buckets(self, now: float) -> tuple[int, int]:
        current = int(now // self._window)
        return current, current - 1

    def _key(self, destination: str, bucket: int) -> str:
        return f"admina:egress:echo:{destination}:{bucket}"

    async def record_outbound(
        self, destination: str, agent_id: str, sketch_values: frozenset[int], now: float
    ) -> None:
        """Store one agent's outbound sketch. No-op without Redis or a sketch.

        Concurrent writers can cause overage slightly beyond the cap; this is
        acceptable against unbounded growth.
        """
        if self._redis is None or not sketch_values:
            return
        current, _ = self._buckets(now)
        key = self._key(destination, current)
        msgid = self._msgid(sketch_values)
        try:
            current_count = await self._redis.scard(key)
            # Only write as many values as fit in the cap.
            available = self._cap - current_count
            if available > 0:
                values_to_write = min(available, len(sketch_values))
                values_iter = iter(sketch_values)
                members = [
                    f"{agent_id}:{now}:{msgid}:{v}"
                    for _ in range(values_to_write)
                    if (v := next(values_iter, None)) is not None
                ]
                if members:
                    await self._redis.sadd(key, *members)
            await self._redis.expire(key, self._window * 2)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Echo store unavailable, not recording outbound: %s", exc)

    async def confirm(
        self, destination: str, agent_id: str, inbound: frozenset[int], now: float
    ) -> str | None:
        """Return the other agent's id when inbound content echoes its output."""
        if self._redis is None or not inbound:
            return None
        current, previous = self._buckets(now)
        try:
            members_combined: set[str] = set()
            for bucket in (current, previous):
                members_combined |= set(await self._redis.smembers(self._key(destination, bucket)))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Echo store unavailable, cannot confirm: %s", exc)
            return None

        # Group by (agent_id, msgid) to keep distinct messages separate.
        # Each distinct message is matched individually.
        by_message: dict[tuple[str, str], set[int]] = {}
        for member in members_combined:
            member_str = str(member)
            # Parse from the right to handle agent IDs containing colons.
            # agent_id:timestamp:msgid:value -> rsplit gives us four parts.
            parts = member_str.rsplit(":", 3)
            if len(parts) != 4:
                continue
            other, stamp, msgid, value = parts
            if other == agent_id:
                continue
            try:
                timestamp = float(stamp)
                if timestamp > now:
                    continue
                by_message.setdefault((other, msgid), set()).add(int(value))
            except ValueError:
                continue

        for (other, _), values in by_message.items():
            if matches(inbound, frozenset(values), self._threshold):
                return other
        return None


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

        The cap bounds memory growth: once the current bucket reaches cap distinct
        agents, further writes are skipped. Concurrent writers can cause the set to
        exceed cap slightly under a race; this bound is acceptable against unbounded
        growth. Precision beyond cap is lost to the clamped return anyway.
        """
        if self._redis is None:
            return 0
        current, previous = self._buckets(now)
        try:
            key = self._key(destination, current)
            current_count = await self._redis.scard(key)
            if current_count < self._cap:
                await self._redis.sadd(key, agent_id)
            await self._redis.expire(key, self._window * 2)
            seen: set[str] = set()
            for bucket in (current, previous):
                seen |= set(await self._redis.smembers(self._key(destination, bucket)))
            return min(len(seen), self._cap)
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
            logger.warning("Fan-in counter unavailable, cannot list agents: %s", exc)
            return set()
        return found
