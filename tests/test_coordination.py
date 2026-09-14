import pytest
from _fakes import FakeRedis, FakeRedisHash

from admina.domains.agent_security.coordination import EchoStore, FanInCounter, QuarantineStore
from admina.domains.agent_security.fingerprint import sketch

_KEY = b"k"
_MSG = "task 42 completed, results are on ZZZ_Results_42, whoever takes 43 starts at column two in the spreadsheet"

# Additional test messages with sufficient length (>= 16 words for >= 12 shingles)
_MSG_A = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa"
_MSG_B = "quebec romeo sierra tango uniform victor whiskey xray yankee zulu alpha bravo charlie delta echo foxtrot"


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

    async def test_member_count_does_not_grow_unbounded(self):
        """Stored member count stops growing at cap per bucket."""
        r = FakeRedis()
        s = EchoStore(r, ttl_seconds=100)
        # Write from one agent (sketch of our message has 13 values)
        base_sketch = sketch(_MSG, _KEY)
        await s.record_outbound("wiki.corp", "a1", base_sketch, now=1000.0)
        # Get the current bucket key
        current_bucket = int(1000.0 // 100)
        key = f"admina:egress:echo:wiki.corp:{current_bucket}"
        # Write many more messages; bucket should cap at 1024
        for i in range(200):
            await s.record_outbound("wiki.corp", f"a{i}", base_sketch, now=1050.0)
        count = len(r.sets.get(key, set()))
        # Count should be capped (around 1024, may exceed slightly under race).
        # Without the cap, we'd have 201 writes * 13 values = 2613 members.
        # With the cap, we have <= 1037 (1024 + 13 for overage).
        assert count <= 1037
        assert count < 2000  # Much less than unbounded growth

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
