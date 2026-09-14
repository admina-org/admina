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

    async def test_the_configured_fan_in_threshold_reaches_both_places_it_is_used(self):
        """`fanin.min_agents` is read twice, and neither read was pinned.

        It sets the fan-in trigger *and*, through `common_sender_floor()`,
        the number of distinct senders that make a shingle a destination's
        ambient content. Replacing either with a literal left the whole
        suite green, because every test that exercises the detector builds
        one of its own: a deployment's `fanin.min_agents` could be
        disconnected from the detector entirely and nothing would notice.

        The floor is asserted against `common_sender_floor(7)` and not
        against `EchoStore`'s constructor default, so dropping the argument
        fails here too.
        """
        from admina.core.config import EgressConfig
        from admina.domains.agent_security.coordination import common_sender_floor
        from admina.proxy.main import build_coordination_detector

        cfg = EgressConfig(
            coordination_declared=["queue.internal"],
            fanin_window_seconds=900,
            fanin_min_agents=7,
        )
        r = FakeRedisHash()
        detector = build_coordination_detector(r, cfg, QuarantineStore(r, 60))

        check = {
            "status": "resolved",
            "destinations": ["wiki.corp"],
            "write_shaped": True,
            "allowed": True,
        }
        statuses = [
            (
                await detector.observe(f"agent-{i}", check, f"message {i} from agent", 1000.0 + i)
            ).status
            for i in range(7)
        ]
        assert statuses == ["none"] * 6 + ["suspected"], statuses
        assert detector._echo._common_min == common_sender_floor(7) == 6
        assert detector._fanin._window == 900
        assert detector._echo._window == 1800, "the echo bucket is twice the fan-in window"
        assert detector._declared == frozenset({"queue.internal"})

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

    def __init__(self, verdict: CoordinationVerdict | None = None) -> None:
        self.calls: list[dict] = []
        self._verdict = verdict or CoordinationVerdict()

    async def observe(self, agent_id, egress_check, payload, now):
        self.calls.append(
            {
                "agent_id": agent_id,
                "destinations": list(egress_check.get("destinations") or []),
                "payload": list(payload),
                "now": now,
            }
        )
        return self._verdict


class _FakeForensicBox:
    """Stands in for ForensicBlackBox; keeps the events it was handed."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    def record(self, event: dict) -> dict:
        self.records.append(event)
        return {"sequence_number": len(self.records), "record_hash": "h", "stored": False}


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


def _drive_governed_calls(monkeypatch, coordination, calls, forensic_box=None, allow=None):
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
        egress_policy=EgressPolicy(allow=allow or ["wiki.corp"]),
        coordination=coordination,
        router=MultiUpstreamRouter(default_upstream="http://fake-upstream"),
        http_client=mock_http,
        redis=None,
        clickhouse=None,
        forensic_box=forensic_box,
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


def _drive_governed_call(monkeypatch, coordination, forensic_box=None):
    """One write-shaped call through the real /mcp handler.

    3000 chars of payload guarantee the payload field is well past the
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
    responses, results = _drive_governed_calls(
        monkeypatch, coordination, [("agent-7", body)], forensic_box=forensic_box
    )
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
        assert [len(f) for f in call["payload"]] == [2000], "each field capped at 2000 chars"

    def test_the_tail_is_the_payload_and_not_the_request_envelope(self, monkeypatch):
        """What is fingerprinted is the message, not the call that carried it.

        ``content_str`` — what the pipeline scans — is json.dumps() of the
        whole JSON-RPC body, so a tail taken from it carries the method, the
        tool name and every argument name, all identical across every caller
        of that tool.
        """
        fake_coordination = _RecordingCoordination()
        _resp, _result = _drive_governed_call(monkeypatch, fake_coordination)
        payload = fake_coordination.calls[0]["payload"]
        assert payload == ["x" * 2000], "the field must be the payload value itself"
        for envelope_token in ("jsonrpc", "tools/call", "wiki_edit", "arguments", "wiki.corp"):
            assert envelope_token not in "".join(payload)


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


# A shared service-account key: constant across the fleet, and long enough
# that its word tokens form shingles. Nothing stops it being extracted; what
# stops it being stored is that six shingles cannot reach the floor a match
# needs, so it can never be evidence of anything.
_SERVICE_CREDENTIAL = "Bearer sk-corp-shared-service-account-2026-eu-west-1"


# Five ordinary tool shapes. Every one of them carries values that are
# identical on every call a fleet makes through it — a header block, a bearer
# token, a content type, a space key — beside the one value that is the
# message.
def _http_request(msg):
    return {
        "name": "http_request",
        "arguments": {
            "url": "https://hooks.corp/v1/dispatch",
            "method": "POST",
            "headers": {
                "user-agent": "AdminaAgentRuntime/2.4 (+https://example.invalid/agents)",
                "authorization": _SERVICE_CREDENTIAL,
                "content-type": "application/json; charset=utf-8",
                "x-trace-context": "runtime-dispatch-pool-worker-eu-west-1",
            },
            "body": msg,
        },
    }


def _wiki_append(msg):
    return {
        "name": "confluence_page_append_content",
        "arguments": {
            "url": "https://wiki.corp/rest/api/content/44182/child/page",
            "space_key": "ENGINEERING",
            "parent_page_id": "44182031",
            "title": "Daily operations log",
            "content_format": "storage",
            "representation": "storage editor2 macro rendering enabled",
            "content": msg,
        },
    }


def _slack_post(msg):
    return {
        "name": "slack_post_message",
        "arguments": {
            "url": "https://slack.corp/api/chat.postMessage",
            "channel": "C08ANALYTICSOPS",
            "username": "admina-dispatch-bot",
            "icon_emoji": ":robot_face: dispatch runtime",
            "unfurl_links": False,
            "text": msg,
        },
    }


def _github_comment(msg):
    return {
        "name": "github_issue_comment",
        "arguments": {
            "endpoint": "https://api.github.corp/repos/platform/core/issues/412/comments",
            "accept": "application/vnd.github.v3+json",
            "user_agent": "octokit-rest.js/20.0.2 admina-agent-runtime worker",
            "authorization": "token ghp_0123456789abcdefghijklmnopqrstuvwx",
            "body": msg,
        },
    }


def _nested_webhook(msg):
    return {
        "name": "webhook_dispatch",
        "arguments": {
            "webhook": {
                "url": "https://hooks.corp/services/T0/B0/XXXX",
                "text": msg,
                "link_names": True,
            },
            "retry_policy": {"max_attempts": 3, "backoff": "exponential with jitter enabled"},
            "content_type": "application/json; charset=utf-8",
        },
    }


# One argument the fleet sends unchanged, long enough to clear the shingle
# floor on its own and to outweigh the bodies beside it: an instruction
# preamble a tool carries as its own argument. This is the shape in which a
# constant is indistinguishable from a quotation within a single call.
_INSTRUCTION_PREAMBLE = (
    "You are an operations assistant acting on behalf of the platform engineering "
    "organisation. Before writing anything to the shared wiki confirm that the page you are "
    "appending to is the correct daily operations log for the current rotation, that the "
    "summary does not contain customer identifiers of any kind, and that every figure you "
    "quote was taken from the reporting warehouse rather than from a cached dashboard. Write "
    "in the past tense, keep each entry to a single paragraph, and never include credentials, "
    "internal hostnames or ticket links in the body of the entry. If the rotation has closed "
    "for the day, append to the next rotation instead and note the delay at the start of the "
    "entry."
)


def _preamble_tool(msg):
    return {
        "name": "wiki_append",
        "arguments": {
            "url": "https://wiki.corp/rest/api/content/44182/child/page",
            "space_key": "ENGINEERING",
            "instructions": _INSTRUCTION_PREAMBLE,
            "content": msg,
        },
    }


def _credentialed_call(msg):
    """Two payload values and nothing else: the token and the message."""
    return {
        "name": "http_post",
        "arguments": {
            "url": "https://hooks.corp/v1/dispatch",
            "authorization": _SERVICE_CREDENTIAL,
            "body": msg,
        },
    }


_TOOL_SHAPES = {
    "http_request": (_http_request, "hooks.corp"),
    "wiki_append": (_wiki_append, "wiki.corp"),
    "slack_post": (_slack_post, "slack.corp"),
    "github_comment": (_github_comment, "api.github.corp"),
    "nested_webhook": (_nested_webhook, "hooks.corp"),
}

# Driven only by the credential test, so the five-shape matrix keeps naming
# the five shapes the review asked for.
_TOOL_SHAPES_EXTRA = {"credentialed": (_credentialed_call, "hooks.corp")}

# A genuine echo: agent-4 quotes agent-0's message inside its own text.
_QUOTED = (
    "Picking this up from the earlier note, quoting it verbatim so the thread has it: "
    + _DIFFERENT_MESSAGES[0]
    + " I will take the follow-up on the eu-west shard."
)


def _jsonrpc(params):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}


def _run_shape(monkeypatch, shape, messages):
    build, host = {**_TOOL_SHAPES, **_TOOL_SHAPES_EXTRA}[shape]
    redis = FakeRedisHash()
    detector = _real_detector(redis, min_agents=5)
    calls = [(f"agent-{i}", _jsonrpc(build(msg))) for i, msg in enumerate(messages)]
    responses, _results = _drive_governed_calls(monkeypatch, detector, calls, allow=[host])
    assert [r.status_code for r in responses] == [200] * len(messages)
    return detector, host, redis


class TestOrdinaryTrafficThroughOneToolIsNotAnEcho:
    """Five agents, one tool, five different messages, five tool shapes.

    This is what a shared destination looks like on an ordinary afternoon.
    The fan-in trigger is supposed to notice it (`suspected`, which blocks
    nothing); the echo phase is supposed to find no echo, because there is
    none. Anything constant across the fleet's calls manufactures the
    similarity the echo phase reads as coordination: first the serialised
    envelope, then — once that was stripped — the argument *values*, a
    header block and a bearer token and a content type, joined into a run of
    shared text that no single field contained. Both directions are pinned
    here, for every shape, because a fix that stops confirming is not a fix.
    """

    @pytest.mark.parametrize("shape", sorted(_TOOL_SHAPES))
    def test_five_agents_posting_different_messages_are_not_confirmed(self, shape, monkeypatch):
        detector, _host, _redis = _run_shape(monkeypatch, shape, _DIFFERENT_MESSAGES)
        statuses = [v.status for v in detector.verdicts]
        assert "confirmed" not in statuses, f"{shape}: ordinary traffic was confirmed: {statuses}"
        assert statuses[-1] == "suspected", (
            f"{shape}: the fan-in trigger must still fire on five agents, got {statuses}"
        )

    @pytest.mark.parametrize("shape", sorted(_TOOL_SHAPES))
    def test_a_genuine_echo_through_the_same_tool_still_confirms(self, shape, monkeypatch):
        """The fix narrows what is fingerprinted, not whether it detects."""
        echoed = _DIFFERENT_MESSAGES[:4] + [_QUOTED]
        detector, host, _redis = _run_shape(monkeypatch, shape, echoed)
        final = detector.verdicts[-1]
        assert final.status == "confirmed", f"{shape}: {[v.status for v in detector.verdicts]}"
        assert final.peer == "agent-0"
        assert final.destination == host

    def test_a_short_status_line_fleet_is_not_confirmed(self, monkeypatch):
        """The length band the constant-value false positive lived in.

        Messages too short to clear the shingle floor on their own leave the
        fleet's constant argument values as the only long run of shared text
        in the call, which is what made twenty of twenty ordered pairs match.
        """
        shorts = [
            "the quarterly revenue figures for the northern region have been finalised today",
            "deployment of the search indexer is paused until the storage quota increases",
            "three invoices in the eu-west shard were reissued under the new scheme",
            "the onboarding wizard now shows completed sections instead of a percentage bar",
            "load testing peaked at eleven thousand queries per second before latency rose",
        ]
        detector, _host, _redis = _run_shape(monkeypatch, "http_request", shorts)
        statuses = [v.status for v in detector.verdicts]
        assert "confirmed" not in statuses, statuses

    @pytest.mark.parametrize(
        ("label", "agent_ids"),
        [
            ("rotating", [f"session-{i}-{i * 7919}" for i in range(8)]),
            ("stable", [f"agent-{i % 5}" for i in range(8)]),
        ],
    )
    def test_a_constant_preamble_is_not_an_echo_however_ids_are_minted(
        self, label, agent_ids, monkeypatch
    ):
        """One tool argument the whole fleet sends unchanged, eight calls.

        `X-Agent-Id` is caller-supplied and unauthenticated, and a runtime
        that mints one per session is an ordinary deployment, not an attack.
        Every call is then a first call, so a rule that discounts what the
        *reader* has sent before has nothing to work with and the constant
        confirms on call after call, each one arming a fleet-wide write
        quarantine. Both ways of minting the header are pinned here: fixing
        the rotating case by blinding the stable one would not be a fix.
        """
        redis = FakeRedisHash()
        detector = _real_detector(redis, min_agents=5)
        bodies = [
            "billing ledger migration finished at noon with three orphaned invoices reissued",
            "quarterly headcount planning is blocked until finance publishes the opex envelope",
            "exported csv files opened with mojibake in excel until the exporter wrote a bom",
            "load testing on the search cluster peaked at eleven thousand queries per second",
            "design review concluded the progress indicator confuses users who skip steps",
            "the storage quota increase for the indexer landed and the pause has been lifted",
            "the nightly reconciliation job now writes its summary to the warehouse instead",
            "two shards were rebalanced after the retention change and the lag has cleared",
        ]
        calls = [
            (agent, _jsonrpc(_preamble_tool(body)))
            for agent, body in zip(agent_ids, bodies, strict=True)
        ]
        responses, _ = _drive_governed_calls(monkeypatch, detector, calls, allow=["wiki.corp"])
        assert [r.status_code for r in responses] == [200] * len(calls)
        statuses = [v.status for v in detector.verdicts]
        assert "confirmed" not in statuses, f"{label} ids: a fleet constant confirmed: {statuses}"
        assert statuses[-1] == "suspected", (
            f"{label} ids: the fan-in trigger must still fire, got {statuses}"
        )

    def test_a_credential_value_is_never_fingerprinted(self, monkeypatch):
        """A security control should not be drawing bearer tokens into its
        echo store, keyed HMAC or not. Nothing below the shingle floor can
        contribute to a match, so nothing below it is stored — and the
        credential is extracted here, not filtered out by the field cap:
        the call carries exactly two payload values and this is one of them.
        """
        from admina.domains.agent_security.fingerprint import sketch

        _detector, _host, redis = _run_shape(monkeypatch, "credentialed", _DIFFERENT_MESSAGES)
        stored = {
            int(str(m).rsplit(":", 3)[3])
            for members in redis.sets.values()
            for m in members
            if str(m).rsplit(":", 3)[-1].isdigit()
        }
        credential = sketch(_SERVICE_CREDENTIAL, b"deployment-secret")
        assert stored, "the fleet's messages are stored"
        assert credential, "the credential does form shingles; the floor is what excludes it"
        assert not (stored & credential), "a credential value reached the echo store"


class TestAnArmedQuarantineLeavesAnAuditRecord:
    """A confirmed verdict costs every agent write access to a destination.

    It is reached on a fire-and-forget task, after the request's own
    forensic record and ClickHouse event have been built and after the
    response has gone out, so nothing that serialises `pipeline_result`
    can carry it: writing it there was a store no consumer reads.
    """

    def test_a_confirmed_verdict_is_recorded_with_the_peer_that_matched(self, monkeypatch):
        box = _FakeForensicBox()
        coordination = _RecordingCoordination(
            CoordinationVerdict(
                status="confirmed", destination="wiki.corp", agents=5, peer="agent-3"
            )
        )
        _resp, _result = _drive_governed_call(monkeypatch, coordination, forensic_box=box)

        coordination_records = [r for r in box.records if "coordination" in (r.get("checks") or {})]
        assert len(coordination_records) == 1, "an armed quarantine left no forensic record"
        record = coordination_records[0]
        assert record["checks"]["coordination"] == {
            "status": "confirmed",
            "destination": "wiki.corp",
            "agents": 5,
            "peer": "agent-3",
        }
        assert record["agent_id"] == "agent-7"
        assert record["action"] == "QUARANTINE"

    def test_a_verdict_that_arms_nothing_adds_no_record(self, monkeypatch):
        """Under a Redis outage every call reports `degraded`; one forensic
        entry per call would bury the chain."""
        box = _FakeForensicBox()
        coordination = _RecordingCoordination(
            CoordinationVerdict(status="degraded", destination="wiki.corp")
        )
        _resp, _result = _drive_governed_call(monkeypatch, coordination, forensic_box=box)
        assert [r for r in box.records if "coordination" in (r.get("checks") or {})] == []

    def test_the_peer_is_named_in_the_warning(self, monkeypatch, caplog):
        coordination = _RecordingCoordination(
            CoordinationVerdict(
                status="confirmed", destination="wiki.corp", agents=5, peer="agent-3"
            )
        )
        with caplog.at_level(logging.WARNING, logger="admina.proxy"):
            _drive_governed_call(monkeypatch, coordination)
        assert any("peer agent-3" in rec.getMessage() for rec in caplog.records), [
            rec.getMessage() for rec in caplog.records
        ]
