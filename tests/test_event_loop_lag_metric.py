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

"""admina_event_loop_lag_seconds: how late the event loop runs a callback.

A background task sleeps a fixed interval and records by how much each
wake-up overshoots it, as a Prometheus histogram on ``/metrics``.
"""

from __future__ import annotations

import asyncio
import re
import time

import httpx
import pytest

pytest.importorskip("fastapi")

NAME = "admina_event_loop_lag_seconds"


def _proxy_state():
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    return ProxyState(router=MultiUpstreamRouter(default_upstream="http://upstream"))


async def _metrics(monkeypatch, state) -> str:
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    transport = httpx.ASGITransport(app=proxy_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")
    assert resp.status_code == 200
    return resp.text


def _samples(body: str) -> dict[str, float]:
    samples = {}
    for line in body.splitlines():
        if line.startswith(NAME):
            key, value = line.rsplit(" ", 1)
            samples[key] = float(value)
    return samples


def test_metric_is_on_metrics(monkeypatch):
    body = asyncio.run(_metrics(monkeypatch, _proxy_state()))
    lines = body.splitlines()
    assert f"# TYPE {NAME} histogram" in lines
    assert sum(1 for line in lines if line.startswith(f"# HELP {NAME} ")) == 1
    samples = _samples(body)
    assert samples[f'{NAME}_bucket{{le="+Inf"}}'] == 0
    assert samples[f"{NAME}_count"] == 0
    assert samples[f"{NAME}_sum"] == 0


def test_metric_grows_when_the_loop_is_blocked(monkeypatch):
    state = _proxy_state()
    state.loop_lag.interval = 0.01

    async def scenario() -> str:
        state.loop_lag.start()
        await asyncio.sleep(0.05)
        time.sleep(0.2)  # hold the event loop
        await asyncio.sleep(0.05)
        body = await _metrics(monkeypatch, state)
        await state.loop_lag.stop()
        return body

    samples = _samples(asyncio.run(scenario()))
    count = samples[f"{NAME}_count"]
    assert count >= 3
    assert samples[f'{NAME}_bucket{{le="+Inf"}}'] == count
    assert samples[f'{NAME}_bucket{{le="0.1"}}'] <= count - 1  # the blocked wake-up
    assert samples[f"{NAME}_sum"] >= 0.15


def test_histogram_buckets_are_cumulative():
    from admina.proxy.loop_lag import EventLoopLagMonitor

    monitor = EventLoopLagMonitor(buckets=(0.001, 0.01, 0.1))
    for lag in (0.0005, 0.002, 0.003, 0.05, 2.0, -0.001):
        monitor.observe(lag)
    lines = monitor.exposition()
    assert lines[0].startswith(f"# HELP {NAME} ")
    assert lines[1] == f"# TYPE {NAME} histogram"
    assert lines[2:] == [
        f'{NAME}_bucket{{le="0.001"}} 2',
        f'{NAME}_bucket{{le="0.01"}} 4',
        f'{NAME}_bucket{{le="0.1"}} 5',
        f'{NAME}_bucket{{le="+Inf"}} 6',
        f"{NAME}_sum 2.0555",
        f"{NAME}_count 6",
    ]


def test_samples_are_taken_at_the_interval():
    from admina.proxy.loop_lag import EventLoopLagMonitor

    monitor = EventLoopLagMonitor(interval=0.01)

    async def scenario() -> None:
        monitor.start()
        await asyncio.sleep(0.12)
        await monitor.stop()

    asyncio.run(scenario())
    assert 5 <= monitor.count <= 12
    assert monitor.sum < 0.1  # an idle loop


def test_startup_starts_the_sampler_and_shutdown_stops_it(monkeypatch):
    from _gateway_stream import run_lifespan

    from admina.core.config import AdminaConfig

    state = run_lifespan(monkeypatch, AdminaConfig())
    assert state.loop_lag.running is False  # stopped on shutdown
    assert state.loop_lag.started is True


def test_help_names_the_sampling_interval():
    from admina.proxy.loop_lag import DEFAULT_INTERVAL, EventLoopLagMonitor

    help_line = EventLoopLagMonitor().exposition()[0]
    assert re.search(rf"every {DEFAULT_INTERVAL:g} s", help_line)
