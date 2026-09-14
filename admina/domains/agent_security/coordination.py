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

import asyncio
import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from admina.domains.agent_security.fingerprint import (
    MIN_SHARED_SHINGLES,
    SKETCH_SIZE,
    matches,
    sketch,
)

__all__ = [
    "CoordinationDetector",
    "CoordinationVerdict",
    "EchoStore",
    "FanInCounter",
    "QuarantineStore",
    "refresh_quarantine_once",
]

logger = logging.getLogger("admina.coordination")


# Echo keys unioned and parsed in one go before confirm() yields the event
# loop. confirm() runs on the proxy's own loop (main.py schedules _observe()
# with asyncio.create_task), so the quantity that matters is not the total
# work but the longest stretch of it that no other request can interrupt:
# at the store's ceiling of agent_cap x cap values a single pass would hold
# the loop for hundreds of milliseconds. Sixteen keys of a full budget is a
# few milliseconds per batch, and a batch never splits a call's members
# because every member of a call lives in one key.
_CONFIRM_KEY_BATCH = 16


class EchoStore:
    """Outbound content sketches, matched against later inbound content.

    Entries are ``<agent_id>:<timestamp>:<callid>-<field>:<value>`` members in
    one set per destination, *agent* and time window. The agent and callid
    (content-derived hash) are what let the two rules that give the verdict
    meaning be enforced at read time: a match against the same agent is
    discarded, and the outbound sketch must predate the inbound content.

    Each distinct message is matched individually against the inbound
    content, and within a message each *field* of the payload is kept
    separate. Both are the same rule: the shingle floor that guarantees a
    match is one coherent run of text is trivially met by pooling texts that
    were never together — two unrelated messages, or a header block, a
    content type and a bearer token that every agent in a fleet sends.

    The storage budget is per agent, not per destination. A single set per
    destination is a resource every agent writing there shares, so whichever
    rule bounds it — refusing writes at a cap, or evicting — lets one agent's
    traffic decide whether *other* agents' messages are available to a later
    confirm(). Since a quarantine can only be armed by a confirmed echo, that
    is an evasion channel: fill the destination's budget, then coordinate
    through it unobserved. Per-agent keys make the only traffic that can
    displace an agent's sketches its own.

    Reading them back needs the agents' ids, so each bucket also carries an
    index set of the agents that wrote to it, holding *agent_cap* ids; confirm()
    reads the two indexes and unions the keys they name in bounded batches.
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
        # one call always fits after the eviction in record_outbound, so the
        # message an agent just sent is always the one that is kept.
        self._cap = cap
        # Agents indexed per destination per bucket. Bounds both the fan-out
        # of confirm()'s union and the total memory a destination can hold,
        # which is agent_cap x cap values.
        self._agent_cap = agent_cap

    @staticmethod
    def _callid(sketches: Sequence[frozenset[int]]) -> str:
        """Derive a short content-based call id from the call's field sketches."""
        combined = sorted(v for values in sketches for v in values)
        h = hashlib.sha256(str(combined).encode()).digest()
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
        """Index the agent against the bucket. True when the index was full.

        ``agent_id`` is whatever the caller put in the ``X-Agent-Id`` header,
        so the index is fillable on purpose. Making room for the arriving
        agent rather than refusing it means forged ids cannot lock a named
        agent out of the echo phase for the life of the bucket: every write
        re-registers its writer, so an agent that keeps sending is re-indexed
        on its next call and the ids that stop sending are the ones that
        leave. What a full index does cost is certainty — some agent's
        sketches are no longer readable — which is why the caller reports the
        destination as `degraded` rather than as "no echo found" while it
        lasts.
        """
        saturated = await self._redis.scard(index_key) >= self._agent_cap
        if saturated and not await self._redis.sismember(index_key, agent_id):
            await self._redis.spop(index_key)
            logger.warning(
                "Echo store index for %r is full at %d agents; evicting one to record %r. "
                "Agent ids come from a caller-supplied header, so a flood of forged ids "
                "reaches this state deliberately",
                index_key,
                self._agent_cap,
                agent_id,
            )
        await self._redis.sadd(index_key, agent_id)
        await self._redis.expire(index_key, self._window * 2)
        return saturated

    async def record_outbound(
        self,
        destination: str,
        agent_id: str,
        sketches: Sequence[frozenset[int]],
        now: float,
    ) -> bool:
        """Store one call's per-field sketches. No-op without Redis or a sketch.

        Returns whether a later negative result from :meth:`confirm` can be
        read as "no echo". False means something the echo phase needed is
        missing — the store is unreachable, this call's content was too large
        to record, or the destination's agent index is full and some agent's
        sketches are therefore unreadable — and the caller reports `degraded`
        instead of `suspected`. True with no sketches to store is not a
        degradation: a call carrying no matchable text is the ordinary case.

        Writes all values of the call or none. Partial writes are dropped to
        avoid creating unsearchable fragments (too few shingles to ever match).

        When the agent's own budget cannot hold the call, its older sketches
        for this bucket are dropped and the current message is written whole.
        Keeping the older ones instead would leave the agent's most recent
        message — the one another agent is about to echo — unmatchable, and
        would do so on traffic the agent controls. Concurrent writers can
        exceed the cap slightly; this is acceptable against unbounded growth.

        Anything that does lose a message is logged at WARNING: the echo phase
        is the only path to a quarantine, so a sketch that is not stored is
        confirmation that cannot happen.
        """
        if self._redis is None:
            return False
        if not sketches:
            return True
        total = sum(len(values) for values in sketches)
        if total > self._cap:
            # Checked before the agent is indexed: a call that will store
            # nothing must not take a slot in a bounded index either.
            logger.warning(
                "Call of %d sketch values exceeds the %d-value echo budget per agent; %r's "
                "content toward %r is not recorded and cannot confirm an echo",
                total,
                self._cap,
                agent_id,
                destination,
            )
            return False
        current, _ = self._buckets(now)
        key = self._key(destination, agent_id, current)
        index_key = self._index_key(destination, current)
        callid = self._callid(sketches)
        try:
            saturated = await self._register(index_key, agent_id)
            stored = await self._redis.scard(key)
            if self._cap - stored < total:
                await self._redis.delete(key)
                logger.info(
                    "Echo budget of %d values for %r on %r is full; dropping its older "
                    "sketches to record the message it just sent",
                    self._cap,
                    agent_id,
                    destination,
                )
            members = [
                f"{agent_id}:{now}:{callid}-{index}:{value}"
                for index, values in enumerate(sketches)
                for value in values
            ]
            await self._redis.sadd(key, *members)
            await self._redis.expire(key, self._window * 2)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Echo store unavailable, not recording outbound: %s", exc)
            return False
        return not saturated

    @staticmethod
    def _parse(members: Any, agent_id: str, now: float) -> dict[tuple[str, str, str], set[int]]:
        """Group raw members into ``(agent, callid, field) -> sketch values``.

        Members written by *agent_id* itself are dropped: an agent echoing
        itself is not coordination, and the caller handles its own history
        separately.
        """
        grouped: dict[tuple[str, str, str], set[int]] = {}
        for member in members:
            # Parse from the right to handle agent IDs containing colons.
            # agent_id:timestamp:callid-field:value -> rsplit gives four parts.
            parts = str(member).rsplit(":", 3)
            if len(parts) != 4:
                continue
            other, stamp, message, value = parts
            if other == agent_id:
                continue
            callid, _, fieldno = message.rpartition("-")
            try:
                if float(stamp) > now:
                    continue
                grouped.setdefault((other, callid, fieldno), set()).add(int(value))
            except ValueError:
                continue
        return grouped

    async def _own_shingles(self, keys: Sequence[str]) -> frozenset[int]:
        """Every shingle this agent has already sent to this destination.

        Text an agent repeats across its own calls is, by construction, not
        evidence that it read another agent's message: it is that agent's own
        boilerplate — a template, a signature, the header block its runtime
        attaches. Discounting it is the only part of this design that can tell
        a fleet-wide constant from a message, because telling them apart needs
        more than one call to look at.

        Only the *reader's* own history is discounted, never the stored peer's.
        Discounting a peer's repeats would let an agent launder a coordination
        message by sending it twice, which is the evasion this whole store is
        bounded to prevent.
        """
        values: set[int] = set()
        for member in await self._redis.sunion(*keys):
            parts = str(member).rsplit(":", 3)
            if len(parts) != 4:
                continue
            try:
                values.add(int(parts[3]))
            except ValueError:
                continue
        return frozenset(values)

    async def confirm(
        self,
        destination: str,
        agent_id: str,
        inbound: Sequence[frozenset[int]],
        now: float,
    ) -> str | None:
        """Return the other agent's id when inbound content echoes its output."""
        if self._redis is None or not inbound:
            return None
        current, previous = self._buckets(now)
        own_keys = [self._key(destination, agent_id, bucket) for bucket in (current, previous)]
        try:
            peer_keys: list[str] = []
            for bucket in (current, previous):
                indexed = await self._redis.smembers(self._index_key(destination, bucket))
                peer_keys.extend(
                    self._key(destination, str(other), bucket)
                    for other in indexed
                    if str(other) != agent_id
                )
            own = await self._own_shingles(own_keys)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Echo store unavailable, cannot confirm: %s", exc)
            return None

        probe = [field - own for field in inbound]
        probe = [field for field in probe if len(field) >= MIN_SHARED_SHINGLES]
        if not probe:
            return None

        for start in range(0, len(peer_keys), _CONFIRM_KEY_BATCH):
            batch = peer_keys[start : start + _CONFIRM_KEY_BATCH]
            try:
                members = await self._redis.sunion(*batch)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Echo store unavailable, cannot confirm: %s", exc)
                return None
            calls: dict[tuple[str, str], list[frozenset[int]]] = {}
            for (other, callid, _), values in self._parse(members, agent_id, now).items():
                calls.setdefault((other, callid), []).append(frozenset(values))
            for (other, _), fields in calls.items():
                if matches(probe, fields, self._threshold):
                    return other
            # Hand the loop back between batches: this coroutine runs on the
            # proxy's own event loop and the parsing above is synchronous.
            await asyncio.sleep(0)
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


def _live_expiry(raw: Any, now: float) -> bool:
    """Whether a stored expiry field exists and is still in the future."""
    if raw is None:
        return False
    try:
        return float(raw) > now
    except (TypeError, ValueError):
        return False


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
        """Quarantine a destination, or extend one already in force.

        Logs at WARNING only when the quarantine begins. Under ``observe``
        the policy keeps letting the calls through, so the detector keeps
        confirming and every confirmation lands here; repeating the line
        would report one event once per call.
        """
        if self._redis is None:
            return
        try:
            existing = await self._redis.hget(self.KEY, destination)
            await self._redis.hset(self.KEY, destination, now + self._ttl)
            if not _live_expiry(existing, now):
                logger.warning(
                    "Destination %r quarantined for writes until %.0f (undeclared coordination)",
                    destination,
                    now + self._ttl,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot record quarantine for %r: %s", destination, exc)

    async def renew(self, destination: str, now: float) -> None:
        """Extend an existing quarantine. Never creates one.

        Reads the one field it needs: this runs for every destination of
        every governed call, whether or not anything is quarantined, so
        reading the whole hash here scales with the size of the quarantine
        set for a lookup that is constant.
        """
        if self._redis is None:
            return
        try:
            expiry = await self._redis.hget(self.KEY, destination)
            if _live_expiry(expiry, now):
                await self._redis.hset(self.KEY, destination, now + self._ttl)
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
        self,
        agent_id: str,
        egress_check: dict,
        payload: str | Sequence[str],
        now: float,
    ) -> CoordinationVerdict:
        """Record one governed call and report what it implies.

        *payload* is the call's payload-bearing fields, as
        ``egress.payload_fields()`` returns them; a single string is read as
        one field. Each field is fingerprinted on its own and stays separate
        for the whole of its life in the echo store, because the shingle
        floor that makes a match mean "one coherent run of shared text" is
        met by any fleet-wide constant once a call's strings are joined.

        A call can name several destinations at once (one tool call can
        produce several URLs). Every destination's side effects — renewal,
        fan-in, echo, quarantine — run unconditionally: none is skipped
        because an earlier destination in the same call already confirmed,
        and none silently overwrites a stronger verdict already found on an
        earlier destination. The verdict returned is the most severe one
        seen across all of this call's destinations, not the last one
        processed.
        """
        texts = [payload] if isinstance(payload, str) else list(payload)
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

            # A field whose sketch cannot reach the shingle floor on its own
            # can never contribute to a match, so dropping it loses nothing
            # and keeps short constants — a bearer token, a content type —
            # out of the store entirely.
            outbound = (
                [
                    values
                    for values in (sketch(text, self._key) for text in texts)
                    if len(values) >= MIN_SHARED_SHINGLES
                ]
                if self._key
                else []
            )
            peer = None
            if self._key and count >= self._min_agents:
                peer = await self._echo.confirm(destination, agent_id, outbound, now)
            conclusive = await self._echo.record_outbound(destination, agent_id, outbound, now)

            if count < self._min_agents:
                continue
            if peer is not None:
                await self._quarantine.add(destination, now)
                best = self._stronger(
                    best, CoordinationVerdict("confirmed", destination, count, peer)
                )
                continue
            if not conclusive:
                # The echo phase could not see everything it needed to, so a
                # negative result is not the same as no echo: say so instead
                # of reporting `suspected`, which claims the content was
                # looked at.
                best = self._stronger(best, CoordinationVerdict("degraded", destination, count))
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
