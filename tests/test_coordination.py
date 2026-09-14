import logging

import pytest
from _fakes import FakeRedis, FakeRedisError, FakeRedisHash

from admina.domains.agent_security.coordination import (
    CoordinationDetector,
    EchoStore,
    FanInCounter,
    QuarantineStore,
)
from admina.domains.agent_security.fingerprint import sketch

_KEY = b"k"
_MSG = "task 42 completed, results are on ZZZ_Results_42, whoever takes 43 starts at column two in the spreadsheet"

# Additional test messages with sufficient length (>= 16 words for >= 12 shingles)
_MSG_A = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa"
_MSG_B = "quebec romeo sierra tango uniform victor whiskey xray yankee zulu alpha bravo charlie delta echo foxtrot"


def _filler(tag: str, words: int = 20) -> str:
    """A message of *words* unique words: 16 shingles, disjoint from any other tag."""
    return " ".join(f"{tag}{i}" for i in range(words))


def _values_of(agent_id: str, redis) -> set[int]:
    """Every sketch value stored for *agent_id*, wherever the store put it."""
    return {
        int(str(m).rsplit(":", 3)[3])
        for members in redis.sets.values()
        for m in members
        if str(m).startswith(f"{agent_id}:")
    }


@pytest.mark.anyio
class TestFanInCounter:
    async def test_counts_distinct_agents(self):
        c = FanInCounter(FakeRedis(), window_seconds=3600)
        for agent in ("a1", "a2", "a3"):
            n = await c.record("wiki.corp", agent, now=1000.0)
        assert n == 3

    async def test_the_same_agent_twice_counts_once(self):
        c = FanInCounter(FakeRedis(), window_seconds=3600)
        await c.record("wiki.corp", "a1", now=1000.0)
        assert await c.record("wiki.corp", "a1", now=1000.0) == 1

    async def test_destinations_are_counted_separately(self):
        c = FanInCounter(FakeRedis(), window_seconds=3600)
        await c.record("wiki.corp", "a1", now=1000.0)
        assert await c.record("other.corp", "a2", now=1000.0) == 1

    async def test_the_previous_bucket_is_included(self):
        """Without this a coordination straddling a bucket edge is missed."""
        c = FanInCounter(FakeRedis(), window_seconds=100)
        await c.record("wiki.corp", "a1", now=1000.0)
        assert await c.record("wiki.corp", "a2", now=1150.0) == 2

    async def test_an_old_bucket_is_not_included(self):
        c = FanInCounter(FakeRedis(), window_seconds=100)
        await c.record("wiki.corp", "a1", now=1000.0)
        assert await c.record("wiki.corp", "a2", now=5000.0) == 1

    async def test_a_ttl_is_always_set(self):
        """An unbounded key set would grow forever."""
        r = FakeRedis()
        c = FanInCounter(r, window_seconds=100)
        await c.record("wiki.corp", "a1", now=1000.0)
        assert all(ttl == 200 for ttl in r.ttls.values())

    async def test_redis_failure_degrades_to_zero_not_an_exception(self):
        r = FakeRedis()
        r.fail = True
        c = FanInCounter(r, window_seconds=3600)
        assert await c.record("wiki.corp", "a1", now=1000.0) == 0

    async def test_no_redis_at_all_degrades_to_zero(self):
        c = FanInCounter(None, window_seconds=3600)
        assert await c.record("wiki.corp", "a1", now=1000.0) == 0

    async def test_agents_returns_the_union_of_both_buckets(self):
        c = FanInCounter(FakeRedis(), window_seconds=100)
        await c.record("wiki.corp", "a1", now=1000.0)
        await c.record("wiki.corp", "a2", now=1150.0)
        assert await c.agents("wiki.corp", now=1150.0) == {"a1", "a2"}

    async def test_an_agent_in_both_buckets_counts_once(self):
        """scard summed over buckets would double-count; the union must not."""
        c = FanInCounter(FakeRedis(), window_seconds=100)
        await c.record("wiki.corp", "a1", now=1000.0)
        assert await c.record("wiki.corp", "a1", now=1150.0) == 1

    async def test_cap_stops_growth(self):
        """Once cap is reached, the underlying set stops growing."""
        r = FakeRedis()
        c = FanInCounter(r, window_seconds=100, cap=3)
        for i in range(5):
            await c.record("wiki.corp", f"a{i}", now=1000.0)
        key = "admina:egress:fanin:wiki.corp:10"
        assert len(r.sets[key]) == 3


@pytest.mark.anyio
class TestEchoStore:
    async def test_content_from_another_agent_confirms(self):
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1100.0) == "a1"

    async def test_an_agent_does_not_echo_itself(self):
        """Matching your own earlier output proves nothing."""
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        assert await s.confirm("wiki.corp", "a1", sketch(_MSG, _KEY), now=1100.0) is None

    async def test_causality_is_required(self):
        """An 'echo' that predates the write is a coincidence, not a channel."""
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=900.0) is None

    async def test_unrelated_content_does_not_confirm(self):
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        other = sketch("the quarterly revenue report shows a decline in the north", _KEY)
        assert await s.confirm("wiki.corp", "a2", other, now=1100.0) is None

    async def test_a_different_destination_does_not_confirm(self):
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        assert await s.confirm("other.corp", "a2", sketch(_MSG, _KEY), now=1100.0) is None

    async def test_an_empty_sketch_never_confirms(self):
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        assert await s.confirm("wiki.corp", "a2", frozenset(), now=1100.0) is None

    async def test_redis_failure_degrades_to_none(self):
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        r.fail = True
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1100.0) is None

    async def test_no_plaintext_is_stored(self):
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        assert "ZZZ_Results_42" not in str(r.sets)

    async def test_agent_id_with_colons_is_correctly_parsed(self):
        """Agent IDs can contain colons; parsing from the right handles them."""
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        agent_with_colons = "team:alpha:1"
        await s.record_outbound("wiki.corp", agent_with_colons, sketch(_MSG, _KEY), now=1000.0)
        # Different agent should match
        assert (
            await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1100.0) == agent_with_colons
        )
        # Same agent (with colons) should not match
        assert (
            await s.confirm("wiki.corp", agent_with_colons, sketch(_MSG, _KEY), now=1100.0) is None
        )

    async def test_pooling_does_not_defeat_min_shared_shingles(self):
        """Messages are matched individually, not pooled.

        Two messages from one agent, neither matching the inbound alone,
        recorded with the same timestamp, should not confirm. Inbound is
        constructed from the two messages so that both individually fall below
        the 12-shingle floor while their union exceeds it. This ensures the
        floor is enforced per message, not pooled, regardless of clock reuse.
        """
        from admina.domains.agent_security.fingerprint import MIN_SHARED_SHINGLES

        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        # Two messages of 16+ words each, neither matching inbound alone.
        msg_a = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar"
        msg_b = (
            "papa quebec romeo sierra tango uniform victor whiskey xray yankee"
            " zulu alpha bravo charlie delta"
        )
        # Inbound is concatenation of both, so both messages contribute shingles.
        inbound_text = msg_a + " " + msg_b
        sketch_a = sketch(msg_a, _KEY)
        sketch_b = sketch(msg_b, _KEY)
        inbound = sketch(inbound_text, _KEY)
        # Verify and report intersection sizes.
        shared_a = inbound & sketch_a
        shared_b = inbound & sketch_b
        shared_ab = inbound & (sketch_a | sketch_b)
        print(
            f"\nPooling test data: "
            f"a∩inbound={len(shared_a)} (need 0<x<12), "
            f"b∩inbound={len(shared_b)} (need 0<x<12), "
            f"(a∪b)∩inbound={len(shared_ab)} (need ≥12)"
        )
        assert 0 < len(shared_a) < MIN_SHARED_SHINGLES, "a should partially match"
        assert 0 < len(shared_b) < MIN_SHARED_SHINGLES, "b should partially match"
        assert len(shared_ab) >= MIN_SHARED_SHINGLES, "union should exceed floor"
        # Record both from a1 WITH THE SAME TIMESTAMP (tests clock reuse).
        shared_time = 1000.0
        await s.record_outbound("wiki.corp", "a1", sketch_a, now=shared_time)
        await s.record_outbound("wiki.corp", "a1", sketch_b, now=shared_time)
        # Confirm with inbound should return None (messages matched individually).
        # Without msgid grouping, pooling would give ≥12 shingles; with it, each
        # message fails individually.
        assert await s.confirm("wiki.corp", "a2", inbound, now=1100.0) is None

    async def test_a_sketch_is_stored_whole_or_not_at_all(self):
        """A fragment of a sketch is a fragment nothing can ever match.

        Fewer than MIN_SHARED_SHINGLES values can never reach the floor, so a
        clamped partial write does not save a message, it stores one that
        cannot be found while consuming the budget of one that could.
        """
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200, cap=40)
        first, second, third = (sketch(_filler(t), _KEY) for t in ("alpha", "bravo", "delta"))
        assert len(first) == len(second) == len(third) == 16, "16 values each"
        await s.record_outbound("wiki.corp", "a1", first, now=1000.0)
        await s.record_outbound("wiki.corp", "a1", second, now=1000.0)
        # 32 of 40 values used: the third sketch does not fit in what is left.
        await s.record_outbound("wiki.corp", "a1", third, now=1000.0)

        stored = _values_of("a1", r)
        assert third <= stored, "the sketch just recorded must be stored whole"
        assert len(stored) == len(third), "its own older sketches are what make room"

    async def test_an_agents_member_count_does_not_grow_unbounded(self):
        """Per-agent budgets bound memory; they do not remove the bound."""
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=100, cap=64)
        for i in range(200):
            await s.record_outbound("wiki.corp", "a1", sketch(_filler(f"m{i}"), _KEY), now=1050.0)
        assert len(_values_of("a1", r)) <= 64 + 16, "cap, plus at most one sketch of overage"

    async def test_a_flood_before_an_echo_does_not_stop_it_being_recorded(self):
        """The evasion a shared budget opens: fill it, then coordinate.

        One agent writes far past the whole budget, then two other agents
        exchange a message. Anything shared per destination lets the flood
        decide whether their echo is recorded at all.
        """
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200, cap=40)
        for i in range(50):
            await s.record_outbound(
                "wiki.corp", "flooder", sketch(_filler(f"j{i}"), _KEY), now=1000.0 + i
            )
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1060.0)
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1070.0) == "a1"

    async def test_a_flood_after_an_echo_does_not_erase_it(self):
        """The same evasion from the other side.

        Whether a full budget refuses the newest write or makes room for it,
        a shared one lets an agent remove what another agent stored — here by
        flooding after the message it wants to hide has been recorded.
        """
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200, cap=40)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        for i in range(50):
            await s.record_outbound(
                "wiki.corp", "flooder", sketch(_filler(f"j{i}"), _KEY), now=1010.0 + i
            )
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1070.0) == "a1"

    async def test_a_full_budget_keeps_the_message_just_sent(self):
        """Refusing the newest write instead would be the same hole, self-inflicted:
        an agent could bury the message it is about to have echoed."""
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200, cap=20)
        old = sketch(_filler("older"), _KEY)
        await s.record_outbound("wiki.corp", "a1", old, now=1000.0)
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1001.0)
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1002.0) == "a1"
        assert await s.confirm("wiki.corp", "a2", old, now=1002.0) is None, "older one made room"

    async def test_a_sketch_larger_than_the_budget_is_reported_not_dropped_quietly(self, caplog):
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200, cap=8)
        with caplog.at_level(logging.WARNING, logger="admina.coordination"):
            await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        key = f"admina:egress:echo:wiki.corp:a1:{int(1000.0 // 7200)}"
        assert key not in r.sets
        assert any("cannot confirm an echo" in rec.getMessage() for rec in caplog.records)

    async def test_the_agent_index_is_capped_and_the_refusal_is_reported(self, caplog):
        """Bounds confirm()'s fan-out. An agent left out of it is invisible to
        the echo phase, which is a loss of detection and is logged as one."""
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=7200, agent_cap=3)
        with caplog.at_level(logging.WARNING, logger="admina.coordination"):
            for i in range(5):
                await s.record_outbound("wiki.corp", f"a{i}", sketch(_MSG, _KEY), now=1000.0)
        assert len(r.sets[f"admina:egress:echo:wiki.corp:{int(1000.0 // 7200)}:agents"]) == 3
        assert any("is not recorded" in rec.getMessage() for rec in caplog.records)

    async def test_the_previous_bucket_is_included(self):
        """Without this, a message straddling a bucket edge is missed."""
        s = EchoStore(FakeRedis(), ttl_seconds=100)
        # bucket 10: times 1000-1099; bucket 11: times 1100-1199
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        # Confirm at time 1150 (bucket 11) should still see a1's write at 1000 (bucket 10).
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1150.0) == "a1"

    async def test_an_old_bucket_is_not_included(self):
        """Content expires after the window elapses.

        A message written in an old bucket is not found when confirming after
        enough time has passed that the bucket has aged out of the two-bucket
        sliding window.
        """
        s = EchoStore(FakeRedis(), ttl_seconds=100)
        # bucket 10: times 1000-1099; confirm at 1250 checks buckets 12 and 11.
        await s.record_outbound("wiki.corp", "a1", sketch(_MSG, _KEY), now=1000.0)
        # Confirm at time 1250 (bucket 12): looks at buckets 12 and 11.
        # Bucket 10 (time 1000) is too old, not checked.
        assert await s.confirm("wiki.corp", "a2", sketch(_MSG, _KEY), now=1250.0) is None

    async def test_high_overlap_without_min_shingles_does_not_confirm(self):
        """High ratio but few shared shingles should not confirm.

        Verifies that matches() enforces both the shingle floor and the ratio.
        A prefix of a longer message has high overlap (fewer shingles all match)
        but below MIN_SHARED_SHINGLES. This is the exact scenario Ruling 2
        exists to catch. Test passes with matches() and fails with bare overlap.
        """
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        # Use a prefix of _MSG. This will share some shingles at containment 1.0
        # (all prefix shingles appear in the full message) but the count will
        # be much less than 12.
        prefix_msg = "task 42 completed results are on ZZZ_Results_42 whoever"
        outbound = sketch(prefix_msg, _KEY)
        inbound = sketch(_MSG, _KEY)
        # Verify outbound has shingles but < 12.
        from admina.domains.agent_security.fingerprint import MIN_SHARED_SHINGLES

        assert 0 < len(outbound) < MIN_SHARED_SHINGLES, (
            f"Need a smaller sketch; got {len(outbound)}"
        )
        # Record the prefix sketch.
        await s.record_outbound("wiki.corp", "a1", outbound, now=1000.0)
        # Confirm should return None because matches enforces both floor and ratio.
        result = await s.confirm("wiki.corp", "a2", inbound, now=1100.0)
        assert result is None, f"Expected None (matches enforces floor), got {result}"


@pytest.mark.anyio
class TestQuarantineStore:
    async def test_an_added_destination_is_current(self):
        q = QuarantineStore(FakeRedisHash(), ttl_seconds=86400)
        await q.add("wiki.corp", now=1000.0)
        assert await q.current(now=1000.0) == frozenset({"wiki.corp"})

    async def test_it_expires_after_the_ttl(self):
        q = QuarantineStore(FakeRedisHash(), ttl_seconds=100)
        await q.add("wiki.corp", now=1000.0)
        assert await q.current(now=1200.0) == frozenset()

    async def test_renewal_extends_it(self):
        """Attempts renew — a quarantine suppresses the successes."""
        q = QuarantineStore(FakeRedisHash(), ttl_seconds=100)
        await q.add("wiki.corp", now=1000.0)
        await q.renew("wiki.corp", now=1090.0)
        assert await q.current(now=1150.0) == frozenset({"wiki.corp"})

    async def test_renewing_an_absent_destination_does_not_create_it(self):
        q = QuarantineStore(FakeRedisHash(), ttl_seconds=100)
        await q.renew("wiki.corp", now=1000.0)
        assert await q.current(now=1000.0) == frozenset()

    async def test_renewal_reads_one_field_not_the_whole_hash(self):
        """renew() runs for every destination of every governed call, whether
        or not anything is quarantined; reading the whole hash there scales
        the cost with the size of the quarantine set."""

        class _CountingRedis(FakeRedisHash):
            def __init__(self):
                super().__init__()
                self.hgetall_calls = 0

            async def hgetall(self, key):
                self.hgetall_calls += 1
                return await super().hgetall(key)

        r = _CountingRedis()
        q = QuarantineStore(r, ttl_seconds=100)
        await q.add("wiki.corp", now=1000.0)
        r.hgetall_calls = 0
        await q.renew("wiki.corp", now=1090.0)
        await q.renew("never.quarantined", now=1090.0)
        assert r.hgetall_calls == 0
        assert await q.current(now=1150.0) == frozenset({"wiki.corp"}), "still renewed"

    async def test_the_warning_reports_the_quarantine_not_every_confirmation(self, caplog):
        """Under `observe` the calls keep going through, so the detector keeps
        confirming and every confirmation lands in add(). One quarantine is
        one event."""
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=100)
        with caplog.at_level(logging.WARNING, logger="admina.coordination"):
            for stamp in (1000.0, 1010.0, 1020.0):
                await q.add("wiki.corp", now=stamp)
        armed = [rec for rec in caplog.records if "quarantined for writes" in rec.getMessage()]
        assert len(armed) == 1, [rec.getMessage() for rec in armed]
        assert await q.current(now=1115.0) == frozenset({"wiki.corp"}), "later ones still extend"

    async def test_a_destination_quarantined_again_after_it_lapsed_is_reported_again(self, caplog):
        """Reporting on transition must not silence a second quarantine."""
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=100)
        with caplog.at_level(logging.WARNING, logger="admina.coordination"):
            await q.add("wiki.corp", now=1000.0)
            assert await q.current(now=1200.0) == frozenset(), "the first one lapsed"
            await q.add("wiki.corp", now=1300.0)
        armed = [rec for rec in caplog.records if "quarantined for writes" in rec.getMessage()]
        assert len(armed) == 2, [rec.getMessage() for rec in armed]

    async def test_lift_removes_it(self):
        q = QuarantineStore(FakeRedisHash(), ttl_seconds=86400)
        await q.add("wiki.corp", now=1000.0)
        assert await q.lift("wiki.corp") is True
        assert await q.current(now=1000.0) == frozenset()

    async def test_lifting_an_absent_destination_reports_false(self):
        q = QuarantineStore(FakeRedisHash(), ttl_seconds=86400)
        assert await q.lift("wiki.corp") is False

    async def test_redis_failure_yields_an_empty_set_not_an_exception(self):
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=86400)
        await q.add("wiki.corp", now=1000.0)
        r.fail = True
        assert await q.current(now=1000.0) == frozenset()

    async def test_no_redis_at_all_yields_an_empty_set(self):
        q = QuarantineStore(None, ttl_seconds=86400)
        await q.add("wiki.corp", now=1000.0)
        assert await q.current(now=1000.0) == frozenset()

    async def test_renewing_an_expired_quarantine_does_not_resurrect_it(self):
        """Expired entries must not be extended; renewal checks liveness.

        Renews without intermediate current() to ensure the expiry check in
        renew() is reached. Verifies both that the entry is not resurrected
        and that the stored expiry is unchanged.
        """
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=100)
        await q.add("wiki.corp", now=1000.0)  # expires at 1100
        stored_before = dict(r.hashes.get("admina:egress:quarantine", {}))
        await q.renew("wiki.corp", now=5000.0)  # should not extend
        stored_after = dict(r.hashes.get("admina:egress:quarantine", {}))
        # Expiry unchanged: renew rejected it as expired
        assert stored_before == stored_after
        # Not resurrected on later read
        assert await q.current(now=5050.0) == frozenset()

    async def test_expired_entries_are_purged_from_store(self):
        """Entries judged expired by current() are deleted from the hash."""
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=100)
        await q.add("wiki.corp", now=1000.0)  # expires at 1100
        await q.add("other.corp", now=1000.0)  # expires at 1100
        # Call current at 1200 to expire both
        assert await q.current(now=1200.0) == frozenset()
        # Verify entries are actually gone from store, not just absent from return value
        assert len(r.hashes["admina:egress:quarantine"]) == 0


_ECHOED = (
    "task 42 completed, results are on ZZZ_Results_42, whoever takes 43"
    " starts at column two in the shared spreadsheet"
)


def _check(dest="wiki.corp", write_shaped=True, allowed=True, status="resolved"):
    return {
        "status": status,
        "destinations": [dest] if dest else [],
        "write_shaped": write_shaped,
        "allowed": allowed,
    }


def _detector(redis, *, declared=frozenset(), min_agents=3, key=b"k"):
    return CoordinationDetector(
        fanin=FanInCounter(redis, window_seconds=3600),
        echo=EchoStore(redis, ttl_seconds=7200),
        quarantine=QuarantineStore(redis, ttl_seconds=86400),
        declared=declared,
        min_agents=min_agents,
        fingerprint_key=key,
    )


@pytest.mark.anyio
class TestCoordinationDetector:
    async def test_below_the_threshold_reports_none(self):
        d = _detector(FakeRedisHash())
        v = await d.observe("a1", _check(), _ECHOED, now=1000.0)
        assert v.status == "none"

    async def test_the_configured_threshold_is_floored_at_two_agents(self):
        """One agent is not coordination with anyone.

        `min_agents: 1` in admina.yaml would otherwise report every single
        write-shaped call to an undeclared destination as `suspected`, and
        the word would stop meaning "more than one agent is writing here".
        """
        for configured in (1, 0, -3):
            d = _detector(FakeRedisHash(), min_agents=configured)
            v = await d.observe("a1", _check(), _ECHOED, now=1000.0)
            assert v.status == "none", f"min_agents={configured} flagged a lone agent"
            v = await d.observe("a2", _check(), "unrelated text for a2 alone", now=1010.0)
            assert v.status == "suspected", f"min_agents={configured} must still fire at two"

    async def test_reaching_the_threshold_without_an_echo_is_suspected(self):
        d = _detector(FakeRedisHash())
        for agent in ("a1", "a2", "a3"):
            v = await d.observe(agent, _check(), f"unrelated text for {agent} alone", now=1000.0)
        assert v.status == "suspected"

    async def test_an_echo_from_another_agent_confirms_and_quarantines(self):
        r = FakeRedisHash()
        d = _detector(r)
        await d.observe("a1", _check(), _ECHOED, now=1000.0)
        await d.observe("a2", _check(), "something else entirely here", now=1010.0)
        v = await d.observe("a3", _check(), _ECHOED, now=1020.0)
        assert v.status == "confirmed"
        assert v.peer == "a1"
        assert "wiki.corp" in await QuarantineStore(r, 86400).current(now=1020.0)

    async def test_one_agents_flood_does_not_disable_confirmation_for_the_fleet(self):
        """Echo confirmation is the only path to a quarantine.

        An agent that could exhaust the store for a destination would not be
        blinding itself, it would be blinding the confirmation phase for
        every other agent writing there — flood first, then coordinate.
        """
        r = FakeRedisHash()
        echo = EchoStore(r, ttl_seconds=7200, cap=40)
        d = CoordinationDetector(
            fanin=FanInCounter(r, window_seconds=3600),
            echo=echo,
            quarantine=QuarantineStore(r, ttl_seconds=86400),
            declared=frozenset(),
            min_agents=2,
            fingerprint_key=b"k",
        )
        for i in range(60):
            await d.observe("flooder", _check(), _filler(f"j{i}"), now=1000.0 + i)
        await d.observe("a1", _check(), _ECHOED, now=1100.0)
        v = await d.observe("a2", _check(), _ECHOED, now=1110.0)
        assert v.status == "confirmed"
        assert v.peer == "a1"
        assert "wiki.corp" in await QuarantineStore(r, 86400).current(now=1110.0)

    async def test_a_declared_destination_is_never_flagged(self):
        """Designed and emergent coordination look identical; only this separates them."""
        d = _detector(FakeRedisHash(), declared=frozenset({"queue.internal"}))
        for agent in ("a1", "a2", "a3", "a4"):
            v = await d.observe(agent, _check(dest="queue.internal"), _ECHOED, now=1000.0)
        assert v.status == "declared"

    async def test_reads_are_not_counted(self):
        d = _detector(FakeRedisHash())
        for agent in ("a1", "a2", "a3", "a4"):
            v = await d.observe(agent, _check(write_shaped=False), _ECHOED, now=1000.0)
        assert v.status == "none"

    async def test_blocked_calls_are_not_counted_as_coordination(self):
        d = _detector(FakeRedisHash())
        for agent in ("a1", "a2", "a3", "a4"):
            v = await d.observe(agent, _check(allowed=False), _ECHOED, now=1000.0)
        assert v.status == "none"

    async def test_a_call_with_no_destination_is_ignored(self):
        d = _detector(FakeRedisHash())
        v = await d.observe("a1", _check(status="no_egress", dest=""), _ECHOED, now=1000.0)
        assert v.status == "none"

    async def test_without_a_key_it_never_escalates_past_suspected(self):
        """An unkeyed fallback would be dictionary-attackable, so echo is off."""
        d = _detector(FakeRedisHash(), key=None)
        for agent in ("a1", "a2", "a3"):
            v = await d.observe(agent, _check(), _ECHOED, now=1000.0)
        assert v.status == "suspected"

    async def test_redis_down_reports_degraded_not_none(self):
        r = FakeRedisHash()
        r.fail = True
        d = _detector(r)
        v = await d.observe("a1", _check(), _ECHOED, now=1000.0)
        assert v.status == "degraded"

    async def test_an_attempt_renews_an_existing_quarantine(self):
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=100)
        await q.add("wiki.corp", now=1000.0)
        d = CoordinationDetector(
            fanin=FanInCounter(r, window_seconds=3600),
            echo=EchoStore(r, ttl_seconds=7200),
            quarantine=q,
            declared=frozenset(),
            min_agents=3,
            fingerprint_key=b"k",
        )
        await d.observe("a9", _check(allowed=False), _ECHOED, now=1090.0)
        assert "wiki.corp" in await q.current(now=1150.0)

    async def test_a_declared_destination_still_renews_an_existing_quarantine(self):
        """Declaring a destination exempts it from being flagged, not from renewal.

        Renewal must run unconditionally, before the declared check, so an
        existing quarantine entry is never dropped merely because its
        destination sits in the declared set. Checked strictly *after* the
        original expiry (1100), since a check at or before that timestamp
        cannot distinguish "renewed" from "simply hasn't expired yet".
        """
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=100)
        await q.add("queue.internal", now=1000.0)  # expires at 1100 unless renewed
        d = CoordinationDetector(
            fanin=FanInCounter(r, window_seconds=3600),
            echo=EchoStore(r, ttl_seconds=7200),
            quarantine=q,
            declared=frozenset({"queue.internal"}),
            min_agents=3,
            fingerprint_key=b"k",
        )
        v = await d.observe("a1", _check(dest="queue.internal"), _ECHOED, now=1050.0)
        assert v.status == "declared"
        assert "queue.internal" in await q.current(now=1110.0)

    async def test_a_confirmed_destination_does_not_starve_another_of_renewal(self):
        """A destination processed after one that confirms must still be renewed.

        Reproduces the multi-destination bug directly: the early ``return`` on
        ``confirmed`` used to skip every destination named after the one that
        confirmed, including its ``quarantine.renew()``. Checked strictly
        *after* the pre-existing quarantine's original expiry (1100), since a
        check at or before that timestamp cannot distinguish "renewed" from
        "simply hasn't expired yet".
        """
        r = FakeRedisHash()
        q = QuarantineStore(r, ttl_seconds=100)
        await q.add("second.dest", now=1000.0)  # expires at 1100 unless renewed
        d = CoordinationDetector(
            fanin=FanInCounter(r, window_seconds=3600),
            echo=EchoStore(r, ttl_seconds=7200),
            quarantine=q,
            declared=frozenset(),
            min_agents=3,
            fingerprint_key=b"k",
        )
        single = _check(dest="first.dest")
        await d.observe("a1", single, _ECHOED, now=1000.0)
        await d.observe("a2", single, "something else entirely here", now=1010.0)
        both = {
            "status": "resolved",
            "destinations": ["first.dest", "second.dest"],
            "write_shaped": True,
            "allowed": True,
        }
        v = await d.observe("a3", both, _ECHOED, now=1020.0)
        assert v.status == "confirmed"
        assert v.destination == "first.dest"
        assert "second.dest" in await q.current(now=1110.0)

    async def test_a_suspected_destination_is_not_masked_by_a_declared_one(self):
        """A later declared destination must not silently overwrite an earlier verdict."""
        d = _detector(FakeRedisHash(), declared=frozenset({"declared.dest"}))
        check = {
            "status": "resolved",
            "destinations": ["suspected.dest", "declared.dest"],
            "write_shaped": True,
            "allowed": True,
        }
        for agent in ("a1", "a2", "a3"):
            v = await d.observe(agent, check, f"unrelated text for {agent} alone", now=1000.0)
        assert v.status == "suspected"
        assert v.destination == "suspected.dest"

    async def test_a_degraded_destination_is_not_masked_by_a_healthy_one(self):
        """A healthy destination that turns suspected must not mask a store outage.

        ``healthy.dest`` must actually reach "suspected" within the same call
        for this to reproduce anything: a healthy destination that stays
        below the fan-in threshold never touches the verdict either way, so
        it could not distinguish the old overwrite bug from the fix.
        """

        class _PartialFailRedis(FakeRedisHash):
            """Fails fan-in operations for one destination only.

            Simulates a Redis shard outage that affects a single destination
            while the rest of the store stays healthy, so the two
            destinations can be told apart in one observe() call.
            """

            def __init__(self, broken_destination):
                super().__init__()
                self._broken = broken_destination

            async def scard(self, key):
                if self._broken in key:
                    raise FakeRedisError("redis down for this destination")
                return await super().scard(key)

            async def sadd(self, key, *values):
                if self._broken in key:
                    raise FakeRedisError("redis down for this destination")
                return await super().sadd(key, *values)

        r = _PartialFailRedis("broken.dest")
        d = _detector(r)
        check = {
            "status": "resolved",
            "destinations": ["broken.dest", "healthy.dest"],
            "write_shaped": True,
            "allowed": True,
        }
        for agent in ("a1", "a2", "a3"):
            v = await d.observe(agent, check, f"unrelated text for {agent} alone", now=1000.0)
        assert v.status == "degraded"
        assert v.destination == "broken.dest"
