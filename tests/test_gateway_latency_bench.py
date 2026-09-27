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

"""Time to the first streamed chunk through the gateway, against a direct call.

Local benchmark (``-m benchmark``; absolute thresholds, not for shared CI
runners). A mock upstream waits 5 ms before each chunk. The gateway runs in
passthrough mode with the installed firewall engine and an in-memory
forensic log; PII redaction is off. For concurrency 1 and 8 the requests
alternate between a direct call and a call through the gateway, and the
p95 time to the first chunk through the gateway may exceed the direct p95
by at most 5 ms.
"""

from __future__ import annotations

import asyncio
import statistics
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from _gateway_stream import (
    UPSTREAM,
    FakePII,
    MockUpstream,
    asgi_post,
    chat_body,
    fixture,
    settings,
)
from fastapi import FastAPI

from admina.proxy.api.gateway import create_gateway_endpoints

pytestmark = pytest.mark.benchmark

_CHUNK_DELAY_S = 0.005
_ROUNDS = 60
_ADDED_P95_MAX_MS = 5.0


def _p95(samples: list[float]) -> float:
    return statistics.quantiles(samples, n=20, method="inclusive")[-1]


def _gateway(client) -> FastAPI:
    from admina.domains.compliance.forensic import ForensicBlackBox
    from admina.engines import get_firewall, get_loop_breaker

    state = SimpleNamespace(
        firewall=get_firewall(),
        pii_redactor=FakePII(),  # redaction is off
        loop_breaker=get_loop_breaker(),
        egress_policy=None,
        governance_guards=[],
        forensic_box=ForensicBlackBox(),
        gateway_http_client=client,
        gateway_stream_mode="passthrough",
    )
    cfg = settings()
    app = FastAPI()
    app.include_router(create_gateway_endpoints(get_state=lambda: state, get_settings=lambda: cfg))
    return app


async def _direct_first_chunk_ms(client, body: dict) -> float:
    started = time.perf_counter()
    first: list[float] = []
    async with client.stream("POST", f"{UPSTREAM}/chat/completions", json=body) as resp:
        async for chunk in resp.aiter_bytes():
            if chunk and not first:
                first.append((time.perf_counter() - started) * 1000)
    return first[0]


async def _gateway_first_chunk_ms(app, body: dict) -> float:
    started = time.perf_counter()
    first: list[float] = []

    async def on_message(message: dict) -> None:
        if message["type"] == "http.response.body" and message.get("body") and not first:
            first.append((time.perf_counter() - started) * 1000)

    await asgi_post(app, body, on_message, asyncio.Event())
    return first[0]


async def _measure(concurrency: int) -> tuple[list[float], list[float]]:
    upstream = MockUpstream(
        fixture("plain_content")["chunks"], before_headers=_CHUNK_DELAY_S, delay=_CHUNK_DELAY_S
    )
    body = chat_body("plain_content")
    direct: list[float] = []
    through: list[float] = []
    async with upstream.client() as client:
        app = _gateway(client)
        await _gateway_first_chunk_ms(app, body)  # warm-up
        for _ in range(_ROUNDS):
            direct += await asyncio.gather(
                *(_direct_first_chunk_ms(client, body) for _ in range(concurrency))
            )
            through += await asyncio.gather(
                *(_gateway_first_chunk_ms(app, body) for _ in range(concurrency))
            )
    return direct, through


@pytest.mark.parametrize("concurrency", [1, 8])
def test_first_chunk_added_by_the_gateway_p95_within_5ms(concurrency):
    direct, through = asyncio.run(_measure(concurrency))

    added = _p95(through) - _p95(direct)
    print(
        f"\nc={concurrency}: first chunk p95 direct {_p95(direct):.2f} ms, "
        f"gateway {_p95(through):.2f} ms, added {added:.2f} ms "
        f"(p50 {statistics.median(direct):.2f} / {statistics.median(through):.2f} ms, "
        f"{len(through)} requests each)"
    )
    assert added <= _ADDED_P95_MAX_MS
