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

"""The gateway runs the governance pipeline in a bounded pool of worker
threads, with a per-request time budget.

- A slow firewall does not hold up the event loop: ``/health`` answers
  promptly while eight governed requests are being scanned.
- At most ``ADMINA_GATEWAY_PIPELINE_WORKERS`` requests are governed at once.
- A request whose governance decision takes longer than
  ``ADMINA_GATEWAY_PIPELINE_TIMEOUT`` is blocked and recorded; the upstream
  is never called.
- A request whose pipeline raises is blocked and recorded, in every
  governance mode. ``ADMINA_GUARD_FAIL_MODE`` still decides what a guard
  contract error does, which the pipeline handles itself.
- PII redaction of completions, streamed or not, runs in the worker threads
  too, within the time budget: a completion whose redaction does not finish
  is never sent as it is.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import httpx
import pytest

pytest.importorskip("fastapi")

from _gateway_stream import (
    EMAIL,
    FakeFirewall,
    FakePII,
    MockUpstream,
    post_through,
    settings,
    through,
)

SLOW = "slow marker"
_COMPLETION = {
    "id": "c1",
    "object": "chat.completion",
    "model": "example-model",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
}


def _upstream() -> MockUpstream:
    return MockUpstream([json.dumps(_COMPLETION).encode()], content_type="application/json")


def _body(content: str = SLOW, *, stream: bool = False) -> dict:
    return {
        "model": "example-model",
        "messages": [{"role": "user", "content": content}],
        "stream": stream,
    }


class SlowFirewall(FakeFirewall):
    """Takes *delay* seconds on text containing :data:`SLOW` and records
    how many checks ran at once."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.active = 0
        self.peak = 0
        self.threads: set[str] = set()
        self._lock = threading.Lock()

    def check(self, text: str) -> dict:
        if SLOW in text:
            with self._lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.threads.add(threading.current_thread().name)
            try:
                time.sleep(self.delay)
            finally:
                with self._lock:
                    self.active -= 1
        return super().check(text)


class RaisingFirewall(FakeFirewall):
    def check(self, text: str) -> dict:
        raise RuntimeError("firewall failure")


class _Recorder:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> dict:
        # Completion records: see tests/test_forensic_gateway_records.py.
        if event["event_type"] != "gateway_response":
            self.events.append(event)
        return {"record_hash": "0" * 64}


def _blocked(resp: httpx.Response) -> bool:
    return resp.json()["choices"][0]["finish_reason"] == "content_filter"


# ── The event loop stays free ─────────────────────────────────

# How long the slow job (a firewall check, a redaction) sleeps in the thread
# that runs it, and the largest event loop stall the tests accept. Run on the
# event loop, or awaited there without yielding, the job stalls the loop for
# at least its whole duration: a stall shorter than the job means the loop
# was free. The bound is the job itself, so the test fails for a blocked
# loop whatever the load, and passes with the loop free unless the scheduler
# holds it for a whole second (stalls of up to 0.51 s were seen on loaded
# macOS runners with the loop free).
SLOW_JOB = 1.0
MAX_STALL = SLOW_JOB


async def _largest_gap(stop: asyncio.Event) -> float:
    """Largest time between two wake-ups of a task that sleeps 5 ms at a
    time, until *stop* is set: how long the event loop was held up."""
    largest = 0.0
    last = time.perf_counter()
    while not stop.is_set():
        await asyncio.sleep(0.005)
        now = time.perf_counter()
        largest = max(largest, now - last)
        last = now
    return largest


def test_slow_firewall_does_not_block_the_event_loop(monkeypatch):
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.pipeline_executor import PipelineExecutor
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", False)
    firewall = SlowFirewall(delay=SLOW_JOB)
    # One thread per request, whatever the number of CPUs of the host.
    executor = PipelineExecutor(workers=8)

    async def scenario() -> tuple[float, list[float], list[httpx.Response]]:
        async with _upstream().client() as client:
            state = ProxyState(
                firewall=firewall,
                router=MultiUpstreamRouter(default_upstream="http://upstream"),
                gateway_http_client=client,
                auth_providers=[],
                pipeline_executor=executor,
            )
            monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
            transport = httpx.ASGITransport(app=proxy_main.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                stop = asyncio.Event()
                gap = asyncio.create_task(_largest_gap(stop))
                posts = [
                    asyncio.create_task(c.post("/v1/chat/completions", json=_body()))
                    for _ in range(8)
                ]
                latencies = []
                for _ in range(5):
                    await asyncio.sleep(0.03)
                    started = time.perf_counter()
                    health = await c.get("/health")
                    latencies.append(time.perf_counter() - started)
                    assert health.status_code == 200
                responses = await asyncio.gather(*posts)
                stop.set()
                return await gap, latencies, responses

    try:
        largest_gap, latencies, responses = asyncio.run(scenario())
    finally:
        executor.shutdown()
    assert [r.status_code for r in responses] == [200] * 8
    assert largest_gap < MAX_STALL, largest_gap
    assert max(latencies) < MAX_STALL, latencies
    assert threading.main_thread().name not in firewall.threads
    assert firewall.peak == 8  # scanned side by side


# ── Concurrency bound ─────────────────────────────────────────


def test_concurrency_is_bounded_by_the_workers():
    from admina.proxy.pipeline_executor import PipelineExecutor

    firewall = SlowFirewall(delay=0.1)
    executor = PipelineExecutor(workers=2)

    async def scenario() -> list[httpx.Response]:
        from _gateway_stream import gateway_app

        async with _upstream().client() as client:
            app = gateway_app(client, state={"firewall": firewall, "pipeline_executor": executor})
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                return await asyncio.gather(
                    *(c.post("/v1/chat/completions", json=_body()) for _ in range(6))
                )

    try:
        responses = asyncio.run(scenario())
    finally:
        executor.shutdown()
    assert [r.status_code for r in responses] == [200] * 6
    assert firewall.peak == 2


# ── Time budget ───────────────────────────────────────────────


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_budget_exceeded_blocks_and_is_recorded(stream, mode):
    upstream = _upstream()
    recorder = _Recorder()
    started = time.perf_counter()
    resp = through(
        upstream,
        _body(stream=stream),
        settings(ADMINA_GATEWAY_PIPELINE_TIMEOUT=0.1, ADMINA_GOVERNANCE_MODE=mode),
        state={"firewall": SlowFirewall(delay=0.6), "forensic_box": recorder},
    )
    elapsed = time.perf_counter() - started

    assert elapsed < 0.5
    assert upstream.requests == []
    assert resp.status_code == 200
    if stream:
        assert '"finish_reason":"content_filter"' in resp.text
        assert resp.text.endswith("data: [DONE]\n\n")
    else:
        assert _blocked(resp)
    (event,) = recorder.events
    assert event["action"] == "BLOCK"
    assert event["risk_level"] == "HIGH"
    assert event["checks"]["pipeline"] == {
        "action": "BLOCK",
        "reason": "time_budget_exceeded",
        "budget_ms": 100,
    }


def test_within_the_budget_the_request_is_forwarded():
    upstream = _upstream()
    resp = through(
        upstream,
        _body(),
        settings(ADMINA_GATEWAY_PIPELINE_TIMEOUT=2.0),
        state={"firewall": SlowFirewall(delay=0.05)},
    )
    assert not _blocked(resp)
    assert len(upstream.requests) == 1


def test_no_budget_by_default():
    from admina.proxy.config import Settings

    assert Settings().ADMINA_GATEWAY_PIPELINE_TIMEOUT == 0
    assert Settings().ADMINA_GATEWAY_PIPELINE_WORKERS == 0


# ── A pipeline that raises blocks the request ────────────────


class RaisingPII(FakePII):
    def redact(self, text: str) -> dict:
        raise KeyError("redaction failure")


class _Guard:
    def __init__(self, name: str, exc: Exception) -> None:
        self.name = name
        self._exc = exc

    async def inspect_request(self, payload: dict) -> dict:
        raise self._exc

    async def inspect_response(self, payload: dict) -> dict:
        return {"action": "ALLOW", "risk_level": "LOW"}


def _assert_blocked(resp: httpx.Response, stream: bool) -> None:
    assert resp.status_code == 200
    if stream:
        assert '"finish_reason":"content_filter"' in resp.text
        assert resp.text.endswith("data: [DONE]\n\n")
    else:
        assert _blocked(resp)


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("fail_mode", ["open", "closed"])
@pytest.mark.parametrize("mode", ["enforce", "observe", "dry-run"])
def test_pipeline_error_blocks_and_is_recorded(stream, fail_mode, mode):
    upstream = _upstream()
    recorder = _Recorder()
    resp = through(
        upstream,
        _body("hello", stream=stream),
        settings(ADMINA_GUARD_FAIL_MODE=fail_mode, ADMINA_GOVERNANCE_MODE=mode),
        state={"firewall": RaisingFirewall(), "forensic_box": recorder},
    )
    _assert_blocked(resp, stream)
    assert upstream.requests == []
    (event,) = recorder.events
    assert event["action"] == "BLOCK"
    assert event["risk_level"] == "HIGH"
    assert event["checks"]["pipeline"] == {"action": "ERROR", "error": "RuntimeError"}


def test_redaction_error_blocks_the_request():
    upstream = _upstream()
    recorder = _Recorder()
    resp = through(
        upstream,
        _body("hello"),
        settings(PII_REDACTION_ENABLED=True, ADMINA_GUARD_FAIL_MODE="open"),
        state={"pii_redactor": RaisingPII(), "forensic_box": recorder},
    )
    assert _blocked(resp)
    assert upstream.requests == []
    (event,) = recorder.events
    assert event["checks"]["pipeline"] == {"action": "ERROR", "error": "KeyError"}


def test_guard_error_outside_the_contract_blocks_the_request():
    upstream = _upstream()
    guard = _Guard("lookup", LookupError("guard failure"))
    resp = through(
        upstream,
        _body("hello"),
        settings(ADMINA_GUARD_FAIL_MODE="open"),
        state={"governance_guards": [guard]},
    )
    assert _blocked(resp)
    assert upstream.requests == []


def test_guard_contract_error_follows_the_guard_fail_mode():
    upstream = _upstream()
    recorder = _Recorder()
    guard = _Guard("contract", RuntimeError("guard failure"))
    resp = through(
        upstream,
        _body("hello"),
        settings(ADMINA_GUARD_FAIL_MODE="open"),
        state={"governance_guards": [guard], "forensic_box": recorder},
    )
    assert not _blocked(resp)
    assert len(upstream.requests) == 1
    (event,) = recorder.events
    assert event["action"] == "ALLOW"
    assert "pipeline" not in event["checks"]
    assert event["checks"]["guard_contract"]["action"] == "ERROR"


def test_a_stopped_executor_blocks_the_request():
    from admina.proxy.pipeline_executor import PipelineExecutor

    executor = PipelineExecutor(workers=1)
    executor.shutdown()
    upstream = _upstream()
    recorder = _Recorder()
    resp = through(
        upstream,
        _body("hello"),
        state={"pipeline_executor": executor, "forensic_box": recorder},
    )
    assert _blocked(resp)
    assert upstream.requests == []
    (event,) = recorder.events
    assert event["checks"]["pipeline"] == {"action": "ERROR", "error": "RuntimeError"}


# ── Guards run in the worker threads ──────────────────────────


class _ThreadGuard:
    name = "thread-probe"

    def __init__(self) -> None:
        self.on_main_thread: bool | None = None

    async def inspect_request(self, payload: dict) -> dict:
        await asyncio.sleep(0)
        self.on_main_thread = threading.current_thread() is threading.main_thread()
        return {"action": "ALLOW", "risk_level": "LOW"}

    async def inspect_response(self, payload: dict) -> dict:
        return {"action": "ALLOW", "risk_level": "LOW"}


def test_guards_run_off_the_event_loop_thread():
    guard = _ThreadGuard()
    resp = through(_upstream(), _body("hello"), state={"governance_guards": [guard]})
    assert not _blocked(resp)
    assert guard.on_main_thread is False


class _ConcurrencyGuard:
    """Records the thread and event loop of each call, and how many calls
    overlap."""

    name = "concurrency-probe"

    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()

    async def inspect_request(self, payload: dict) -> dict:
        with self._lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.calls.append((threading.current_thread().name, id(asyncio.get_running_loop())))
        try:
            await asyncio.sleep(0.1)
        finally:
            with self._lock:
                self.active -= 1
        return {"action": "ALLOW", "risk_level": "LOW"}

    async def inspect_response(self, payload: dict) -> dict:
        return {"action": "ALLOW", "risk_level": "LOW"}


def test_one_guard_is_called_from_several_threads_each_on_its_own_loop():
    from _gateway_stream import gateway_app

    from admina.proxy.pipeline_executor import PipelineExecutor

    guard = _ConcurrencyGuard()
    executor = PipelineExecutor(workers=4)

    async def scenario() -> tuple[int, list[httpx.Response]]:
        async with _upstream().client() as client:
            app = gateway_app(
                client, state={"governance_guards": [guard], "pipeline_executor": executor}
            )
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                responses = await asyncio.gather(
                    *(c.post("/v1/chat/completions", json=_body("hello")) for _ in range(4))
                )
                return id(asyncio.get_running_loop()), responses

    try:
        main_loop, responses = asyncio.run(scenario())
    finally:
        executor.shutdown()
    assert not any(_blocked(r) for r in responses)
    assert guard.peak == 4  # the same guard, four calls at once
    assert len({thread for thread, _ in guard.calls}) == 4
    loops = {loop for _, loop in guard.calls}
    assert len(loops) == 4
    assert main_loop not in loops


# ── Completion redaction runs in the worker threads ──────────

ANSWER = "answer marker"


class _AnswerPII(FakePII):
    """Redacts :data:`EMAIL`; records the threads it ran on. On text with
    :data:`ANSWER` it sleeps *delay* seconds, or raises when *fail*."""

    def __init__(self, delay: float = 0.0, fail: bool = False) -> None:
        self.delay = delay
        self.fail = fail
        self.threads: set[str] = set()
        self._lock = threading.Lock()

    def redact(self, text: str) -> dict:
        with self._lock:
            self.threads.add(threading.current_thread().name)
        if ANSWER in text:
            if self.fail:
                raise KeyError("redaction failure")
            time.sleep(self.delay)
        return super().redact(text)


def _answer_completion() -> MockUpstream:
    completion = {
        **_COMPLETION,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": f"{ANSWER}: write to {EMAIL}"},
                "finish_reason": "stop",
            }
        ],
    }
    return MockUpstream([json.dumps(completion).encode()], content_type="application/json")


def _answer_stream() -> MockUpstream:
    def event(content: str, finish: str | None = None) -> bytes:
        chunk = {
            "id": "c1",
            "object": "chat.completion.chunk",
            "model": "example-model",
            "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": finish}],
        }
        return f"data: {json.dumps(chunk)}\n\n".encode()

    return MockUpstream(
        [
            b": keep-alive\n\n",
            event("The first part. " * 10),  # longer than the redaction window
            event(f"{ANSWER}: write to {EMAIL} "),
            event("today.", "stop"),
            b"data: [DONE]\n\n",
        ]
    )


def _redacting(**over):
    return settings(PII_REDACTION_ENABLED=True, **over)


def _run_with_gap(coro_factory):
    """The result of the coroutine and the largest event loop stall while
    it ran."""

    async def scenario():
        stop = asyncio.Event()
        gap = asyncio.create_task(_largest_gap(stop))
        await asyncio.sleep(0.01)
        try:
            return await coro_factory(), gap
        finally:
            stop.set()

    async def main():
        result, gap = await scenario()
        return result, await gap

    return asyncio.run(main())


@pytest.mark.parametrize("stream", [False, True])
def test_completion_redaction_runs_off_the_event_loop(stream):
    pii = _AnswerPII(delay=SLOW_JOB)
    upstream = _answer_stream() if stream else _answer_completion()
    resp, largest_gap = _run_with_gap(
        lambda: post_through(
            upstream,
            _body("hello", stream=stream),
            _redacting(),
            stream_mode="governed",
            state={"pii_redactor": pii},
        )
    )
    assert resp.status_code == 200
    assert EMAIL not in resp.text
    assert "[EMAIL]" in resp.text
    assert threading.main_thread().name not in pii.threads
    assert all(name.startswith("admina-pipeline") for name in pii.threads)
    assert largest_gap < MAX_STALL, largest_gap


def test_completion_redaction_over_the_budget_is_not_returned():
    upstream = _answer_completion()
    resp = through(
        upstream,
        _body("hello"),
        _redacting(ADMINA_GATEWAY_PIPELINE_TIMEOUT=0.1),
        state={"pii_redactor": _AnswerPII(delay=0.6)},
    )
    assert len(upstream.requests) == 1
    assert _blocked(resp)
    assert ANSWER not in resp.text
    assert EMAIL not in resp.text


def test_completion_redaction_error_is_not_returned():
    upstream = _answer_completion()
    resp = through(
        upstream, _body("hello"), _redacting(), state={"pii_redactor": _AnswerPII(fail=True)}
    )
    assert _blocked(resp)
    assert EMAIL not in resp.text


@pytest.mark.parametrize(
    ("over", "pii"),
    [
        ({"ADMINA_GATEWAY_PIPELINE_TIMEOUT": 0.1}, _AnswerPII(delay=0.6)),
        ({}, _AnswerPII(fail=True)),
    ],
    ids=["over-the-budget", "error"],
)
def test_stream_redaction_failure_ends_the_stream(over, pii):
    resp = through(
        _answer_stream(),
        _body("hello", stream=True),
        _redacting(**over),
        stream_mode="governed",
        state={"pii_redactor": pii},
    )
    assert resp.status_code == 200
    events = [e for e in resp.text.split("\n\n") if e]
    assert "The first part." in resp.text
    assert EMAIL not in resp.text
    assert ANSWER not in resp.text
    assert "today." not in resp.text
    assert "data: [DONE]" not in events
    last = json.loads(events[-1].removeprefix("data: "))
    assert last["error"]["code"] == "response_redaction_failed"


# ── PipelineExecutor ──────────────────────────────────────────


def test_executor_returns_results_and_raises_errors():
    from admina.proxy.pipeline_executor import PipelineExecutor

    executor = PipelineExecutor(workers=1)

    async def scenario():
        assert await executor.run(lambda: 41 + 1) == 42
        with pytest.raises(KeyError):
            await executor.run(lambda: {}["missing"])

        async def coro():
            await asyncio.sleep(0)
            return threading.current_thread().name

        name = await executor.run_coroutine(coro)
        assert name.startswith("admina-pipeline")

    try:
        asyncio.run(scenario())
    finally:
        executor.shutdown()


def test_executor_reuses_one_event_loop_per_thread():
    from admina.proxy.pipeline_executor import PipelineExecutor

    executor = PipelineExecutor(workers=1)

    async def running_loop():
        return asyncio.get_running_loop()

    async def scenario():
        first = await executor.run_coroutine(running_loop)
        second = await executor.run_coroutine(running_loop)
        assert first is second
        assert first is not asyncio.get_running_loop()
        return first

    try:
        loop = asyncio.run(scenario())
    finally:
        executor.shutdown()
    assert loop.is_closed()


def test_executor_timeout_cancels_a_queued_job():
    from admina.proxy.pipeline_executor import PipelineExecutor, PipelineTimeout

    executor = PipelineExecutor(workers=1)
    ran = threading.Event()

    async def scenario():
        busy = asyncio.ensure_future(executor.run(lambda: time.sleep(0.3)))
        await asyncio.sleep(0.02)
        with pytest.raises(PipelineTimeout):
            await executor.run(ran.set, timeout=0.05)
        await busy
        await asyncio.sleep(0.05)

    try:
        asyncio.run(scenario())
    finally:
        executor.shutdown()
    assert not ran.is_set()


def test_executor_starts_its_threads_up_front():
    from admina.proxy.pipeline_executor import PipelineExecutor

    executor = PipelineExecutor(workers=3)
    try:
        threads = executor._pool._threads
        assert len(threads) == 3
        assert all(thread.is_alive() for thread in threads)
        assert len(executor._loops) == 3  # one event loop per thread, ready
    finally:
        executor.shutdown()


def test_executor_default_size_is_the_cpu_count():
    from admina.proxy.pipeline_executor import PipelineExecutor, default_workers

    executor = PipelineExecutor()
    try:
        assert executor.workers == default_workers() >= 1
    finally:
        executor.shutdown()


def test_startup_builds_the_executor_and_shutdown_stops_it(monkeypatch):
    from _gateway_stream import run_lifespan

    from admina.core.config import AdminaConfig
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_PIPELINE_WORKERS", 3)
    state = run_lifespan(monkeypatch, AdminaConfig())
    assert state.pipeline_executor.workers == 3

    async def after_shutdown():
        await state.pipeline_executor.run(lambda: None)

    with pytest.raises(RuntimeError):
        asyncio.run(after_shutdown())
