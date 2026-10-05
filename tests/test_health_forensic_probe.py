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

"""``forensic_writable`` of ``GET /health``: the forensic store's write check
runs on a thread of its own, at most once per interval, and a check that
does not finish within the timeout reports ``false``. Concurrent calls share
one check; a stalled check holds neither the event loop nor the default
executor, which the gateway uses for its forensic records."""

from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

pytest.importorskip("fastapi")

from _proxy_app import API_KEY, CHAT, isolate, upstream, with_key

from admina.proxy.forensic_probe import (
    PROBE_INTERVAL_S,
    PROBE_THREAD_NAME,
    PROBE_TIMEOUT_S,
    ForensicWriteProbe,
)


class _Store:
    """A forensic store whose write check counts its calls and can stall."""

    def __init__(self, result: object = True, *, stall: bool = False) -> None:
        self.result = result
        self.calls = 0
        self.threads: list[str] = []
        self.release = threading.Event()
        self.done = threading.Event()
        if not stall:
            self.release.set()
        self._lock = threading.Lock()

    def writable(self) -> bool | None:
        with self._lock:
            self.calls += 1
            self.threads.append(threading.current_thread().name)
        try:
            # Bounded, so a failing test cannot leave a thread behind for long.
            self.release.wait(10)
            if isinstance(self.result, BaseException):
                raise self.result
            return self.result  # type: ignore[return-value]
        finally:
            self.done.set()


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _check(probe: ForensicWriteProbe, store: object) -> bool | None:
    return asyncio.run(probe.check(store))


# ── Defaults ──────────────────────────────────────────────────


def test_defaults():
    probe = ForensicWriteProbe()
    assert probe.interval == PROBE_INTERVAL_S == 10.0
    # Well inside the 2-3 s timeout of a container healthcheck.
    assert probe.timeout == PROBE_TIMEOUT_S == 1.0


def test_proxy_state_has_a_probe_of_its_own():
    from admina.proxy.state import ProxyState

    first, second = ProxyState(), ProxyState()
    assert isinstance(first.forensic_probe, ForensicWriteProbe)
    assert first.forensic_probe is not second.forensic_probe


# ── No store ──────────────────────────────────────────────────


def test_no_store_is_null():
    assert _check(ForensicWriteProbe(), None) is None


def test_a_store_without_a_write_check_is_null():
    assert _check(ForensicWriteProbe(), object()) is None


# ── One check per interval ────────────────────────────────────


def test_the_result_is_reused_within_the_interval():
    clock = _Clock()
    probe = ForensicWriteProbe(interval=10.0, clock=clock)
    store = _Store(True)
    assert _check(probe, store) is True
    clock.now += 9.9
    store.result = False
    assert _check(probe, store) is True
    assert store.calls == 1
    clock.now += 0.2
    assert _check(probe, store) is False
    assert store.calls == 2
    # A failed check is reused as well.
    clock.now += 5.0
    assert _check(probe, store) is False
    assert store.calls == 2


def test_concurrent_calls_share_one_check():
    probe = ForensicWriteProbe()
    store = _Store(True, stall=True)

    async def scenario() -> list[bool | None]:
        calls = [asyncio.create_task(probe.check(store)) for _ in range(50)]
        await asyncio.sleep(0.05)
        store.release.set()
        return await asyncio.gather(*calls)

    assert asyncio.run(scenario()) == [True] * 50
    assert store.calls == 1


def test_a_new_store_is_checked_at_once():
    probe = ForensicWriteProbe(interval=3600.0)
    first, second = _Store(True), _Store(False)
    assert _check(probe, first) is True
    assert _check(probe, second) is False
    assert (first.calls, second.calls) == (1, 1)


def test_the_check_runs_on_a_thread_of_its_own():
    store = _Store(True)
    assert _check(ForensicWriteProbe(), store) is True
    assert store.threads == [PROBE_THREAD_NAME]


def test_an_error_in_the_check_reports_false():
    store = _Store(RuntimeError("store failure"))
    assert _check(ForensicWriteProbe(), store) is False


# ── Timeout ───────────────────────────────────────────────────


def test_a_stalled_check_reports_false_within_the_timeout():
    probe = ForensicWriteProbe(timeout=0.3)
    store = _Store(True, stall=True)
    try:
        started = time.monotonic()
        assert _check(probe, store) is False
        first = time.monotonic() - started
        assert 0.25 <= first < 3.0, first

        # The check is still running: no second check, and no second wait.
        started = time.monotonic()
        assert _check(probe, store) is False
        second = time.monotonic() - started
        assert second < 0.3, second
        assert store.calls == 1
    finally:
        store.release.set()

    # When it does finish, its result is kept for the interval.
    assert store.done.wait(5)
    deadline = time.monotonic() + 5
    while _check(probe, store) is not True:
        assert time.monotonic() < deadline, "the late result was not kept"
        time.sleep(0.01)
    assert store.calls == 1


def test_a_stalled_check_leaves_the_default_executor_free():
    probe = ForensicWriteProbe(timeout=0.2)
    store = _Store(True, stall=True)

    async def scenario() -> tuple[bool | None, int]:
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))
        result = await probe.check(store)
        other = await asyncio.wait_for(loop.run_in_executor(None, lambda: 42), 5)
        return result, other

    try:
        assert asyncio.run(scenario()) == (False, 42)
    finally:
        store.release.set()


# ── Through the proxy ─────────────────────────────────────────


def _state(store: object, probe: ForensicWriteProbe):
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    return ProxyState(
        router=MultiUpstreamRouter(default_upstream="http://mcp.test"),
        forensic_box=store,
        forensic_probe=probe,
    )


async def _health_calls(app, count: int) -> list[httpx.Response]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await asyncio.gather(*(client.get("/health") for _ in range(count)))


def test_concurrent_health_calls_run_one_check(monkeypatch):
    from admina.proxy import main as proxy_main

    store = _Store(True)
    state = _state(store, ForensicWriteProbe())
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)

    responses = asyncio.run(_health_calls(proxy_main.app, 20))
    responses += asyncio.run(_health_calls(proxy_main.app, 5))
    assert [r.status_code for r in responses] == [200] * 25
    assert {r.json()["forensic_writable"] for r in responses} == {True}
    assert store.calls == 1


def test_health_answers_in_time_when_the_check_stalls(monkeypatch):
    from admina.proxy import main as proxy_main

    store = _Store(True, stall=True)
    state = _state(store, ForensicWriteProbe(timeout=0.3))
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)

    async def scenario() -> list[httpx.Response]:
        return await asyncio.wait_for(_health_calls(proxy_main.app, 20), 5)

    try:
        started = time.monotonic()
        responses = asyncio.run(scenario())
        elapsed = time.monotonic() - started
    finally:
        store.release.set()
    assert [r.status_code for r in responses] == [200] * 20
    assert {r.json()["forensic_writable"] for r in responses} == {False}
    # A store that does not answer in time is reported as not writable.
    assert {r.json()["status"] for r in responses} == {"degraded"}
    assert elapsed < 3.0, elapsed
    assert store.calls == 1


def test_a_stalled_check_does_not_hold_up_gateway_requests(monkeypatch, tmp_path):
    """The gateway writes its forensic record on the default executor; a
    stalled write check must not take that executor's only worker."""
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    isolate(monkeypatch, forensic_backend="filesystem", forensic_dir=str(tmp_path / "forensic"))
    store = _Store(True, stall=True)

    async def scenario() -> tuple[list[httpx.Response], httpx.Response, int]:
        async with proxy_main.lifespan(proxy_main.app):
            state = proxy_main.app.state.proxy
            await state.gateway_http_client.aclose()
            state.gateway_http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
            state.forensic_probe = ForensicWriteProbe(timeout=0.3)
            monkeypatch.setattr(state.forensic_box, "writable", store.writable)
            asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
            records = state.forensic_box.record_count
            transport = httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                health = [asyncio.create_task(client.get("/health")) for _ in range(3)]
                await asyncio.sleep(0.05)
                chat = await asyncio.wait_for(client.request(**with_key(CHAT)), 5)
                health_responses = await asyncio.wait_for(asyncio.gather(*health), 5)
            return health_responses, chat, state.forensic_box.record_count - records

    try:
        health, chat, written = asyncio.run(scenario())
    finally:
        store.release.set()
    assert chat.status_code == 200
    assert written >= 1
    assert [r.json()["forensic_writable"] for r in health] == [False] * 3
    assert store.calls == 1
