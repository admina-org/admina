import pytest
from _fakes import FakeRedis

from admina.domains.agent_security.coordination import EchoStore, FanInCounter
from admina.domains.agent_security.fingerprint import sketch

_KEY = b"k"
_MSG = "task 42 completed, results are on ZZZ_Results_42, whoever takes 43 starts at column two in the spreadsheet"


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
        should not confirm even though pooling them would exceed
        MIN_SHARED_SHINGLES. This ensures Ruling 2's 12-shingle floor
        applies per message, not across fragments.
        """
        from admina.domains.agent_security.fingerprint import MIN_SHARED_SHINGLES

        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        # Create two small sketches (each with few shingles)
        msg1 = "alpha bravo charlie"
        msg2 = "delta echo foxtrot"
        inbound = sketch(_MSG, _KEY)  # Our long test message
        sketch1 = sketch(msg1, _KEY)
        sketch2 = sketch(msg2, _KEY)
        # Verify sketches are small
        assert len(sketch1) < MIN_SHARED_SHINGLES
        assert len(sketch2) < MIN_SHARED_SHINGLES
        # Record both from a1 (they won't match individually)
        await s.record_outbound("wiki.corp", "a1", sketch1, now=1000.0)
        await s.record_outbound("wiki.corp", "a1", sketch2, now=1010.0)
        # Confirm with inbound should return None (messages matched individually)
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

    async def test_high_overlap_without_min_shingles_does_not_confirm(self):
        """High ratio but few shared shingles should not confirm.

        Verifies that matches() enforces both the shingle floor and the ratio.
        A case where overlap >= 0.4 but shared < MIN_SHARED_SHINGLES should be
        rejected. This is the exact scenario Ruling 2 exists to catch.
        """
        s = EchoStore(FakeRedis(), ttl_seconds=7200)
        # Create a small sketch with few shingles. If it happens to overlap
        # with the inbound, the ratio could be high, but the absolute count
        # will be below MIN_SHARED_SHINGLES, so matches() rejects it.
        small_msg = "results on"
        outbound = sketch(small_msg, _KEY)  # Will be < 5 shingles
        inbound = sketch(_MSG, _KEY)  # Will be 13 shingles
        # Record the small sketch
        await s.record_outbound("wiki.corp", "a1", outbound, now=1000.0)
        # Confirm should return None because matches enforces both floor and ratio
        assert await s.confirm("wiki.corp", "a2", inbound, now=1100.0) is None
