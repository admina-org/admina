import asyncio
import logging
from unittest.mock import AsyncMock

import pytest
from _fakes import FakeRedisHash

pytest.importorskip("fastapi")

import httpx

from admina.domains.agent_security.coordination import (
    CoordinationDetector,
    CoordinationVerdict,
    EchoStore,
    FanInCounter,
    QuarantineStore,
)
from admina.domains.agent_security.egress import EgressPolicy, analyze


@pytest.mark.anyio
class TestQuarantineReachesThePolicy:
    async def test_a_confirmed_verdict_makes_the_policy_refuse_writes(self):
        """The loop the whole design rests on: detector writes, policy blocks."""
        r = FakeRedisHash()
        quarantine = QuarantineStore(r, ttl_seconds=86400)
        detector = CoordinationDetector(
            fanin=FanInCounter(r, window_seconds=3600),
            echo=EchoStore(r, ttl_seconds=7200),
            quarantine=quarantine,
            declared=frozenset(),
            min_agents=2,
            fingerprint_key=b"k",
        )
        # 18 words -> 14 shingles, clearing fingerprint.MIN_SHARED_SHINGLES (12);
        # a shorter paraphrase of this sentence stays below the floor and the
        # echo never confirms (see test_coordination.py's `_ECHOED`).
        msg = (
            "task 42 completed, results are on ZZZ_Results_42, whoever takes 43"
            " starts at column two in the shared spreadsheet"
        )
        check = {
            "status": "resolved",
            "destinations": ["wiki.corp"],
            "write_shaped": True,
            "allowed": True,
        }
        await detector.observe("a1", check, msg, now=1000.0)
        verdict = await detector.observe("a2", check, msg, now=1010.0)
        assert verdict.status == "confirmed"

        policy = EgressPolicy(allow=["wiki.corp"])
        write = analyze({"url": "https://wiki.corp/w?action=edit&text=a long enough payload"})
        read = analyze({"url": "https://wiki.corp/page"})
        assert policy.evaluate(write, "enforce").allowed is True, "not armed yet"

        policy.set_quarantine(await quarantine.current(now=1010.0))
        assert policy.evaluate(write, "enforce").allowed is False, "writes refused"
        assert policy.evaluate(read, "enforce").allowed is True, "reads survive"


@pytest.mark.anyio
class TestProxyWiring:
    async def test_state_carries_the_detector(self):
        from admina.proxy.state import ProxyState

        state = ProxyState()
        assert hasattr(state, "coordination")
        assert hasattr(state, "quarantine_refresh")

    async def test_the_refresh_hands_the_set_to_the_policy(self):
        from admina.domains.agent_security.coordination import refresh_quarantine_once

        r = FakeRedisHash()
        store = QuarantineStore(r, ttl_seconds=86400)
        await store.add("wiki.corp", now=1000.0)
        policy = EgressPolicy(allow=["wiki.corp"])
        await refresh_quarantine_once(policy, store, now=1000.0)
        write = analyze({"url": "https://wiki.corp/w?action=edit&text=a long enough payload"})
        assert policy.evaluate(write, "enforce").allowed is False

    async def test_the_refresh_keeps_the_last_set_when_the_store_fails(self):
        """A block list is the conservative thing to retain on failure."""
        from admina.domains.agent_security.coordination import refresh_quarantine_once

        r = FakeRedisHash()
        store = QuarantineStore(r, ttl_seconds=86400)
        await store.add("wiki.corp", now=1000.0)
        policy = EgressPolicy(allow=["wiki.corp"])
        await refresh_quarantine_once(policy, store, now=1000.0)
        r.fail = True
        await refresh_quarantine_once(policy, store, now=1001.0)
        write = analyze({"url": "https://wiki.corp/w?action=edit&text=a long enough payload"})
        assert policy.evaluate(write, "enforce").allowed is False

    async def test_the_refresh_is_silent_with_no_redis_configured(self, caplog):
        """No Redis configured is a supported deployment, not a failure.

        Regression test: an earlier version of QuarantineStore._read_live
        omitted the `self._redis is None` guard current() and every sibling
        method has, so this raised AttributeError every cycle and logged a
        "refresh failed" warning forever — for a deployment where nothing
        had actually failed and there was never a set to keep.
        """
        from admina.domains.agent_security.coordination import refresh_quarantine_once

        store = QuarantineStore(None, ttl_seconds=86400)
        policy = EgressPolicy(allow=["wiki.corp"])
        with caplog.at_level(logging.WARNING, logger="admina.coordination"):
            await refresh_quarantine_once(policy, store, now=1000.0)
        assert caplog.records == [], "no Redis client is not a refresh failure"


class _RecordingCoordination:
    """Stands in for CoordinationDetector; records every observe() call."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def observe(self, agent_id, egress_check, content_tail, now):
        self.calls.append(
            {
                "agent_id": agent_id,
                "destinations": list(egress_check.get("destinations") or []),
                "content_tail": content_tail,
                "now": now,
            }
        )
        return CoordinationVerdict()


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low", "patterns": []}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


def _wiki_body(tool: str, message: str, extra: dict | None = None) -> dict:
    """One JSON-RPC tool call whose only free content is *message*."""
    arguments = {"url": "https://wiki.corp/rest/api/content/44182/child/page"}
    arguments.update(extra or {})
    arguments["content"] = message
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


def _drive_governed_calls(monkeypatch, coordination, calls):
    """POST each of *calls* through the real /mcp handler against one state.

    *calls* is a sequence of ``(agent_id, body)``. Returns
    ``(responses, pipeline_results)``, one entry per call; each
    ``pipeline_result`` is the GovernanceResult mcp_proxy built, captured via
    a spy on ``run_pipeline``. The fire-and-forget ``_observe()`` task each
    call spawns is drained before the next one starts, so a detector passed
    here sees the calls in order.
    """
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", False)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    monkeypatch.setattr(proxy_main.settings, "UPSTREAM_MCP_URL", "http://fake-upstream")
    monkeypatch.setattr(proxy_main.settings, "GOVERNANCE_MODE", "enforce")

    captured: list = []
    original_run_pipeline = proxy_main.run_pipeline

    async def _spy_run_pipeline(*args, **kwargs):
        result = await original_run_pipeline(*args, **kwargs)
        captured.append(result)
        return result

    monkeypatch.setattr(proxy_main, "run_pipeline", _spy_run_pipeline)

    mock_http = AsyncMock()
    mock_http.post = AsyncMock(
        return_value=httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    )

    state = ProxyState(
        firewall=_FakeFirewall(),
        pii_redactor=None,
        loop_breaker=_FakeLoopBreaker(),
        egress_policy=EgressPolicy(allow=["wiki.corp"]),
        coordination=coordination,
        router=MultiUpstreamRouter(default_upstream="http://fake-upstream"),
        http_client=mock_http,
        redis=None,
        clickhouse=None,
        forensic_box=None,
        governance_guards=[],
        alert_channels=[],
        auth_providers=[],
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)

    async def go():
        responses = []
        transport = httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            for agent_id, body in calls:
                responses.append(
                    await client.post("/mcp", json=body, headers={"X-Agent-Id": agent_id})
                )
                # _observe() is fire-and-forget (_spawn); drain it before the
                # next call so the detector sees this one first.
                pending = [t for t in proxy_main._background_tasks if not t.done()]
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
        return responses

    responses = asyncio.run(go())
    return responses, captured


def _drive_governed_call(monkeypatch, coordination):
    """One write-shaped call through the real /mcp handler.

    3000 chars of payload guarantee the content tail is well past the
    2000-char cap it must be clipped to.
    """
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "wiki_edit",
            "arguments": {"url": "https://wiki.corp/w", "text": "x" * 3000},
        },
    }
    responses, results = _drive_governed_calls(monkeypatch, coordination, [("agent-7", body)])
    return responses[0], results[0]


class TestCallSiteIsPinned:
    """Drives a real request through mcp_proxy to pin the call site itself.

    Every test above exercises CoordinationDetector, QuarantineStore or
    refresh_quarantine_once directly — none of them go through main.py's
    ``/mcp`` handler. Without a test that does, the ``_observe()`` block in
    ``mcp_proxy`` (or its 2000-char tail cap) could be deleted or widened
    and the whole suite would stay green — exactly the "eight of eight
    call-site mutations survived" failure mode this test defends against.
    Set ``state.coordination = None`` (its own default) and this is the
    test that fails.
    """

    def test_a_governed_call_reaches_the_detector_with_a_capped_tail(self, monkeypatch):
        fake_coordination = _RecordingCoordination()
        resp, _pipeline_result = _drive_governed_call(monkeypatch, fake_coordination)
        assert resp.status_code == 200

        assert len(fake_coordination.calls) == 1, "state.coordination.observe() was never called"
        call = fake_coordination.calls[0]
        assert call["agent_id"] == "agent-7"
        assert "wiki.corp" in call["destinations"]
        assert len(call["content_tail"]) == 2000, "the tail must be capped at 2000 chars"

    def test_the_tail_is_the_payload_and_not_the_request_envelope(self, monkeypatch):
        """What is fingerprinted is the message, not the call that carried it.

        ``content_str`` — what the pipeline scans — is json.dumps() of the
        whole JSON-RPC body, so a tail taken from it carries the method, the
        tool name and every argument name, all identical across every caller
        of that tool.
        """
        fake_coordination = _RecordingCoordination()
        _resp, _result = _drive_governed_call(monkeypatch, fake_coordination)
        tail = fake_coordination.calls[0]["content_tail"]
        assert tail == "x" * 2000, "the tail must be the payload value itself"
        for envelope_token in ("jsonrpc", "tools/call", "wiki_edit", "arguments", "wiki.corp"):
            assert envelope_token not in tail


class _SpyDetector(CoordinationDetector):
    """The real detector, keeping every verdict it returned."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.verdicts: list[CoordinationVerdict] = []

    async def observe(self, *args, **kwargs):
        verdict = await super().observe(*args, **kwargs)
        self.verdicts.append(verdict)
        return verdict


# Five unrelated messages: no two share a five-word run.
_DIFFERENT_MESSAGES = [
    "The migration of the billing ledger finished at noon and reconciliation found three orphaned"
    " invoices in the eu-west shard, reissued under the new numbering scheme.",
    "Quarterly headcount planning is blocked until finance publishes the revised opex envelope, so"
    " the hiring panel for the platform team moves to the second week of next month.",
    "A customer reported that exported CSV files open with mojibake in Excel on Windows; the root"
    " cause is a missing byte order mark and the exporter now writes UTF-8 with it.",
    "Load testing on the new search cluster peaked at eleven thousand queries per second before"
    " latency degraded, roughly double what the previous deployment sustained under the same load.",
    "Design review for the onboarding flow concluded that the progress indicator confuses users who"
    " skip optional steps, so the wizard will show completed sections instead of a percentage.",
]

# A verbose but ordinary tool envelope: seven arguments, all constant per tool.
_VERBOSE_ARGS = {
    "space_key": "ENGINEERING",
    "parent_page_id": "44182031",
    "title": "Daily operations log",
    "content_format": "storage",
    "notify_watchers": False,
    "minor_edit": True,
}


def _real_detector(redis, min_agents):
    return _SpyDetector(
        fanin=FanInCounter(redis, window_seconds=3600),
        echo=EchoStore(redis, ttl_seconds=7200),
        quarantine=QuarantineStore(redis, ttl_seconds=86400),
        declared=frozenset(),
        min_agents=min_agents,
        fingerprint_key=b"deployment-secret",
    )


class TestOrdinaryTrafficThroughOneToolIsNotAnEcho:
    """Five agents, one verbose tool, five different messages.

    This is what a shared wiki looks like on an ordinary afternoon. The
    fan-in trigger is supposed to notice it (`suspected`, which blocks
    nothing); the echo phase is supposed to find no echo, because there is
    none. Fingerprinting the serialised request instead of the payload turns
    the fixed part of the envelope — method, tool name, argument names, the
    constant argument values — into the shared shingles the confirmation
    rests on, and every pair of agents matches.
    """

    def test_five_agents_posting_different_messages_are_not_confirmed(self, monkeypatch):
        detector = _real_detector(FakeRedisHash(), min_agents=5)
        calls = [
            (f"agent-{i}", _wiki_body("confluence_page_append_content", msg, _VERBOSE_ARGS))
            for i, msg in enumerate(_DIFFERENT_MESSAGES)
        ]
        responses, _results = _drive_governed_calls(monkeypatch, detector, calls)

        assert [r.status_code for r in responses] == [200] * 5
        statuses = [v.status for v in detector.verdicts]
        assert "confirmed" not in statuses, f"ordinary traffic was confirmed: {statuses}"
        assert statuses[-1] == "suspected", (
            f"the fan-in trigger must still fire on five agents, got {statuses}"
        )

    def test_a_genuine_echo_through_the_same_tool_still_confirms(self, monkeypatch):
        """The fix narrows what is fingerprinted, not whether it detects."""
        detector = _real_detector(FakeRedisHash(), min_agents=5)
        echoed = list(_DIFFERENT_MESSAGES)
        echoed[4] = _DIFFERENT_MESSAGES[0]  # agent-4 repeats what agent-0 wrote
        calls = [
            (f"agent-{i}", _wiki_body("confluence_page_append_content", msg, _VERBOSE_ARGS))
            for i, msg in enumerate(echoed)
        ]
        _responses, _results = _drive_governed_calls(monkeypatch, detector, calls)

        final = detector.verdicts[-1]
        assert final.status == "confirmed", [v.status for v in detector.verdicts]
        assert final.peer == "agent-0"
        assert final.destination == "wiki.corp"


class TestCoordinationChecksShape:
    """``checks["coordination"]`` is a brief-mandated "Produces" item.

    It is written by a fire-and-forget background task, after the HTTP
    response has already gone out, so nothing else in the request path
    reads it — a renamed key or a dropped field would pass the rest of the
    suite silently.
    """

    def test_the_verdict_is_recorded_with_the_documented_shape(self, monkeypatch):
        fake_coordination = _RecordingCoordination()
        _resp, pipeline_result = _drive_governed_call(monkeypatch, fake_coordination)

        checks = pipeline_result.checks["coordination"]
        assert set(checks) == {"status", "destination", "agents"}
        assert isinstance(checks["status"], str)
        assert isinstance(checks["destination"], str)
        assert isinstance(checks["agents"], int)
