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
from dataclasses import dataclass
from typing import Any

from admina.domains.agent_security.fingerprint import SKETCH_SIZE, matches, sketch

__all__ = [
    "CoordinationDetector",
    "CoordinationVerdict",
    "EchoStore",
    "FanInCounter",
    "QuarantineStore",
    "refresh_quarantine_once",
]

logger = logging.getLogger("admina.coordination")


class EchoStore:
    """Outbound content sketches, matched against later inbound content.

    Entries are ``<agent_id>:<timestamp>:<msgid>:<value>`` members in one set
    per destination, *agent* and time window. The agent and msgid
    (content-derived hash) are what let the two rules that give the verdict
    meaning be enforced at read time: a match against the same agent is
    discarded, and the outbound sketch must predate the inbound content.

    Each distinct message is matched individually against the inbound sketch.
    This prevents false positives where unrelated messages are pooled to meet
    the MIN_SHARED_SHINGLES floor that guarantees containment of one coherent
    text.

    The storage budget is per agent, not per destination. A single set per
    destination is a resource every agent writing there shares, so whichever
    rule bounds it — refusing writes at a cap, or evicting — lets one agent's
    traffic decide whether *other* agents' messages are available to a later
    confirm(). Since a quarantine can only be armed by a confirmed echo, that
    is an evasion channel: fill the destination's budget, then coordinate
    through it unobserved. Per-agent keys make the only traffic that can
    displace an agent's sketches its own.

    Reading them back needs the agents' ids, so each bucket also carries an
    index set of the agents that wrote to it, capped at *agent_cap*; confirm()
    reads the two indexes and unions the keys they name in one round trip.
    Being an index of *this* store's buckets rather than the fan-in counter's
    (whose window is half as long) keeps the matchable period where the
    docstring below says it is.

    ttl_seconds is a bucket window. Content is matchable for roughly one to
    two times that duration and is hard-bounded regardless of activity (unlike
    older time-based expiry that reset on each write).
    """

    def __init__(
        self,
        redis: Any,
        ttl_seconds: int,
        threshold: float = 0.4,
        cap: int = 2 * SKETCH_SIZE,
        agent_cap: int = 256,
    ) -> None:
        self._redis = redis
        self._window = max(1, ttl_seconds)
        self._threshold = threshold
        # Values per agent per bucket. Two maximal sketches: large enough that
        # one sketch always fits after the eviction in record_outbound, so the
        # message an agent just sent is always the one that is kept.
        self._cap = cap
        # Agents indexed per destination per bucket. Bounds both the fan-out
        # of confirm()'s union and the total memory a destination can hold,
        # which is agent_cap x cap values.
        self._agent_cap = agent_cap

    @staticmethod
    def _msgid(sketch_values: frozenset[int]) -> str:
        """Derive a short content-based message id from the sketch."""
        sorted_values = sorted(sketch_values)
        h = hashlib.sha256(str(sorted_values).encode()).digest()
        return h.hex()[:8]

    def _buckets(self, now: float) -> tuple[int, int]:
        current = int(now // self._window)
        return current, current - 1

    def _key(self, destination: str, agent_id: str, bucket: int) -> str:
        return f"admina:egress:echo:{destination}:{agent_id}:{bucket}"

    def _index_key(self, destination: str, bucket: int) -> str:
        # Cannot collide with a _key(): that one ends in an integer bucket.
        return f"admina:egress:echo:{destination}:{bucket}:agents"

    async def _register(self, index_key: str, agent_id: str) -> bool:
        """Index the agent against the bucket. False when the index is full."""
        if await self._redis.scard(index_key) >= self._agent_cap and not (
            await self._redis.sismember(index_key, agent_id)
        ):
            return False
        await self._redis.sadd(index_key, agent_id)
        await self._redis.expire(index_key, self._window * 2)
        return True

    async def record_outbound(
        self, destination: str, agent_id: str, sketch_values: frozenset[int], now: float
    ) -> None:
        """Store one agent's outbound sketch. No-op without Redis or a sketch.

        Writes all values of the sketch or none. Partial writes are dropped to
        avoid creating unsearchable fragments (too few shingles to ever match).

        When the agent's own budget cannot hold the sketch, its older sketches
        for this bucket are dropped and the current message is written whole.
        Keeping the older ones instead would leave the agent's most recent
        message — the one another agent is about to echo — unmatchable, and
        would do so on traffic the agent controls. Concurrent writers can
        exceed the cap slightly; this is acceptable against unbounded growth.

        Anything that does lose a message is logged at WARNING: the echo phase
        is the only path to a quarantine, so a sketch that is not stored is
        confirmation that cannot happen.
        """
        if self._redis is None or not sketch_values:
            return
        current, _ = self._buckets(now)
        key = self._key(destination, agent_id, current)
        index_key = self._index_key(destination, current)
        msgid = self._msgid(sketch_values)
        try:
            if not await self._register(index_key, agent_id):
                logger.warning(
                    "Echo store index for %r holds %d agents; %r's content is not recorded "
                    "for this window and cannot confirm an echo",
                    destination,
                    self._agent_cap,
                    agent_id,
                )
                return
            if len(sketch_values) > self._cap:
                logger.warning(
                    "Sketch of %d values exceeds the %d-value echo budget per agent; %r's "
                    "content toward %r is not recorded and cannot confirm an echo",
                    len(sketch_values),
                    self._cap,
                    agent_id,
                    destination,
                )
                return
            stored = await self._redis.scard(key)
            if self._cap - stored < len(sketch_values):
                await self._redis.delete(key)
                logger.info(
                    "Echo budget of %d values for %r on %r is full; dropping its older "
                    "sketches to record the message it just sent",
                    self._cap,
                    agent_id,
                    destination,
                )
            members = [f"{agent_id}:{now}:{msgid}:{v}" for v in sketch_values]
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
            keys: list[str] = []
            for bucket in (current, previous):
                indexed = await self._redis.smembers(self._index_key(destination, bucket))
                keys.extend(self._key(destination, str(other), bucket) for other in indexed)
            members_combined: set[str] = (
                {str(m) for m in await self._redis.sunion(*keys)} if keys else set()
            )
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


class QuarantineStore:
    """Destinations that may not receive payload-bearing calls.

    One Redis hash of destination to expiry timestamp. Expiry is evaluated on
    read rather than delegated to a key TTL because every entry lives in the
    same hash, and because the refresh task needs to see the whole set at once.
    """

    KEY = "admina:egress:quarantine"

    def __init__(self, redis: Any, ttl_seconds: int) -> None:
        self._redis = redis
        self._ttl = max(1, ttl_seconds)

    async def add(self, destination: str, now: float) -> None:
        if self._redis is None:
            return
        try:
            await self._redis.hset(self.KEY, destination, now + self._ttl)
            logger.warning(
                "Destination %r quarantined for writes until %.0f (undeclared coordination)",
                destination,
                now + self._ttl,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot record quarantine for %r: %s", destination, exc)

    async def renew(self, destination: str, now: float) -> None:
        """Extend an existing quarantine. Never creates one."""
        if self._redis is None:
            return
        try:
            existing = await self._redis.hgetall(self.KEY)
            if destination in existing:
                try:
                    expiry = float(existing[destination])
                    if expiry > now:
                        await self._redis.hset(self.KEY, destination, now + self._ttl)
                except (TypeError, ValueError):
                    pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot renew quarantine for %r: %s", destination, exc)

    async def lift(self, destination: str) -> bool:
        if self._redis is None:
            return False
        try:
            return bool(await self._redis.hdel(self.KEY, destination))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot lift quarantine for %r: %s", destination, exc)
            return False

    async def current(self, now: float) -> frozenset[str]:
        """Destinations still quarantined. Empty when Redis is unavailable.

        Purges expired entries encountered during read. The refresh task calls
        this every ~5s on every replica; purging is idempotent so concurrent
        purges converge. This bounds hash growth and removes the resurrection
        surface at its source rather than only at renew()'s check.

        Race: a renew() and purge() can collide on the same expiry instant, with
        purge deleting what renew just extended. This is acceptable — the window
        is one Redis round-trip, it requires both operations at an instant when
        the quarantine's TTL has just reached zero, and new evidence re-flags.
        """
        try:
            return await self._read_live(now)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot read quarantine set: %s", exc)
            return frozenset()

    async def current_raising(self, now: float) -> frozenset[str]:
        """Destinations still quarantined. Raises on Redis failure.

        Same as :meth:`current` but propagates exceptions instead of failing
        open. CLI commands use this to distinguish unavailability (operator
        needs to know) from absence (nothing to report).
        """
        return await self._read_live(now)

    async def lift_raising(self, destination: str) -> bool:
        """Clear one destination's quarantine. Raises on Redis failure.

        Same as :meth:`lift` but propagates exceptions instead of failing open.
        CLI commands use this to distinguish unavailability from absence.
        """
        if self._redis is None:
            return False
        return bool(await self._redis.hdel(self.KEY, destination))

    async def _read_live(self, now: float) -> frozenset[str]:
        """Read the hash and purge expired entries. Raises on a Redis failure.

        Returns an empty set with no client configured — that is a
        supported deployment (see admina/proxy/main.py's "Redis disabled"
        log line), not a failure, and must not be reported as one.

        Factored out of :meth:`current` so :func:`refresh_quarantine_once` can
        tell "nothing is quarantined" apart from "the store could not be
        read" — the distinction :meth:`current`'s fail-open contract erases
        for its own callers (a plain empty result either way), and which
        would otherwise be the wrong default for a caller that must not
        silently clear the policy's block list on a transient outage.
        """
        if self._redis is None:
            return frozenset()
        entries = await self._redis.hgetall(self.KEY)
        live: set[str] = set()
        for destination, expiry in entries.items():
            try:
                if float(expiry) > now:
                    live.add(str(destination))
                else:
                    try:
                        await self._redis.hdel(self.KEY, destination)
                    except Exception:  # noqa: BLE001
                        pass
            except (TypeError, ValueError):
                continue
        return frozenset(live)


async def refresh_quarantine_once(policy: Any, store: QuarantineStore, now: float) -> None:
    """Hand the current quarantine set to the policy. Never raises.

    On failure the policy keeps the set it already has: a block list is the
    conservative thing to retain when the store cannot be read. This is why
    it reads through :meth:`QuarantineStore._read_live` rather than
    :meth:`QuarantineStore.current`: ``current()`` fails open to an empty set
    for callers that treat "unavailable" the same as "nothing is quarantined"
    (a defensible default there), but a refresh loop must not confuse the
    two — doing so would clear every quarantine on a transient Redis outage.
    """
    try:
        quarantined = await store._read_live(now)  # noqa: SLF001
        policy.set_quarantine(quarantined)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Quarantine refresh failed, keeping the last known set: %s", exc)


@dataclass
class CoordinationVerdict:
    """What one observation concluded about a destination."""

    status: str = "none"
    destination: str = ""
    agents: int = 0
    peer: str | None = None


# Severity order for picking one verdict when a call names several
# destinations (e.g. one tool call producing several URLs). A real detection
# or a store outage must never be masked by a milder or merely-informational
# result on another destination processed in the same call.
_VERDICT_SEVERITY = {"none": 0, "declared": 1, "suspected": 2, "degraded": 3, "confirmed": 4}


class CoordinationDetector:
    """Finds undeclared coordination and arms the quarantine set.

    A legitimate shared work queue and an emergent coordination channel look
    identical from here — many agents, one destination, writes, content
    passing between them. That is why this class judges *declaration*, not
    intent: the ``declared`` set is the only thing that turns the same
    fan-in-plus-echo signature from "suspected"/"confirmed" into "declared".

    Never blocks. A confirmed verdict writes to the quarantine store, which
    EgressPolicy reads on the inline path.
    """

    def __init__(
        self,
        fanin: FanInCounter,
        echo: EchoStore,
        quarantine: QuarantineStore,
        declared: frozenset[str],
        min_agents: int,
        fingerprint_key: bytes | None,
    ) -> None:
        self._fanin = fanin
        self._echo = echo
        self._quarantine = quarantine
        self._declared = declared
        self._min_agents = max(2, min_agents)
        self._key = fingerprint_key

    async def observe(
        self, agent_id: str, egress_check: dict, content_tail: str, now: float
    ) -> CoordinationVerdict:
        """Record one governed call and report what it implies.

        A call can name several destinations at once (one tool call can
        produce several URLs). Every destination's side effects — renewal,
        fan-in, echo, quarantine — run unconditionally: none is skipped
        because an earlier destination in the same call already confirmed,
        and none silently overwrites a stronger verdict already found on an
        earlier destination. The verdict returned is the most severe one
        seen across all of this call's destinations, not the last one
        processed.
        """
        destinations = [d for d in (egress_check.get("destinations") or []) if isinstance(d, str)]
        if not destinations:
            return CoordinationVerdict()

        best = CoordinationVerdict()
        for destination in destinations:
            # An attempt renews an existing quarantine even when the policy
            # refused it, and even when another destination in this same
            # call already confirmed: either one suppresses the successes
            # that would otherwise be the renewal signal.
            await self._quarantine.renew(destination, now)

            if destination in self._declared:
                best = self._stronger(best, CoordinationVerdict("declared", destination))
                continue
            if not egress_check.get("write_shaped") or not egress_check.get("allowed"):
                continue

            count = await self._fanin.record(destination, agent_id, now)
            if count == 0:
                best = self._stronger(best, CoordinationVerdict("degraded", destination))
                continue

            outbound = sketch(content_tail, self._key) if self._key else frozenset()
            peer = None
            if self._key and count >= self._min_agents:
                peer = await self._echo.confirm(destination, agent_id, outbound, now)
            await self._echo.record_outbound(destination, agent_id, outbound, now)

            if count < self._min_agents:
                continue
            if peer is not None:
                await self._quarantine.add(destination, now)
                best = self._stronger(
                    best, CoordinationVerdict("confirmed", destination, count, peer)
                )
                continue
            best = self._stronger(best, CoordinationVerdict("suspected", destination, count))
        return best

    @staticmethod
    def _stronger(
        current: CoordinationVerdict, candidate: CoordinationVerdict
    ) -> CoordinationVerdict:
        """Whichever of the two verdicts ranks higher in severity; ties keep `current`."""
        if _VERDICT_SEVERITY[candidate.status] > _VERDICT_SEVERITY[current.status]:
            return candidate
        return current
