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
passthrough mode with an in-memory forensic log; PII redaction is off. For
concurrency 1 and 8 the requests alternate between a direct call and a call
through the gateway, and the p95 time to the first chunk through the
gateway may exceed the direct p95 by at most 5 ms:

- with a short prompt and the installed firewall engine;
- on a RAG-shaped prompt (12 ``<source>`` blocks, about 44,000 characters,
  1000 streamed tokens) with ``X-Admina-Scan-Policy`` declaring the blocks
  and the system message already scanned, for the Python engine and, when
  ``admina-core`` is installed, the Rust engine (``scripts/bench_gateway.py``).
  With the Python engine at concurrency 8 the limit is 6 ms (see
  ``_RAG_ADDED_P95_MAX_MS``).

With 8 clients streaming RAG answers through the gateway, the event loop lag
p95 stays within 5 ms as well.
"""

from __future__ import annotations

import asyncio
import importlib.util
import statistics
import sys
import time
from pathlib import Path
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


# ── RAG-shaped trace with a scan policy ───────────────────────


def _bench_module():
    path = Path(__file__).resolve().parent.parent / "scripts" / "bench_gateway.py"
    spec = importlib.util.spec_from_file_location("bench_gateway", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up there
    spec.loader.exec_module(module)
    return module


bench = _bench_module()
_ENGINES = ["python"] + (["rust"] if importlib.util.find_spec("admina_core") else [])
_RAG_ROUNDS = 60
_RAG_TOKENS = 1000
_LAG_SECONDS = 6.0
_LAG_P95_MAX_MS = 5.0
# Added p95 limits that differ from _ADDED_P95_MAX_MS, by (engine,
# concurrency). The request record holds request_sha256, the SHA-256 of the
# RFC 8785 form of the messages, and is written before the request is
# forwarded. On the 44,000-character prompt the canonical form takes about
# 0.05 ms (ASCII text) to 0.1 ms (other text) of CPU per request, holding
# the GIL like the firewall scan: eight concurrent requests queue for it,
# which adds 0.5 to 1 ms to the p95. With the Python engine's longer scan
# that crosses 5 ms; the Rust engine keeps the 5 ms limit.
_RAG_ADDED_P95_MAX_MS = {("python", 8): 6.0}


@pytest.mark.parametrize("engine", _ENGINES)
@pytest.mark.parametrize("concurrency", [1, 8])
def test_rag_first_chunk_added_with_scan_policy_p95_within_5ms(engine, concurrency):
    result = asyncio.run(
        bench.measure_first_chunk(
            engine, concurrency, _RAG_ROUNDS, _RAG_TOKENS, _CHUNK_DELAY_S, full_scan=False
        )
    )
    stats = result.summary()
    limit = _RAG_ADDED_P95_MAX_MS.get((engine, concurrency), _ADDED_P95_MAX_MS)
    print(f"\nengine={engine} c={concurrency} (limit {limit} ms): {stats}")
    assert result.added_p95("prescan") <= limit


@pytest.mark.parametrize("engine", _ENGINES)
def test_rag_event_loop_lag_p95_at_c8_within_5ms(engine):
    lag = asyncio.run(bench.measure_loop_lag(engine, _LAG_SECONDS, _RAG_TOKENS, _CHUNK_DELAY_S))
    stats = lag.summary()
    print(f"\nengine={engine} event loop lag c=8: {stats}")
    assert lag.requests >= bench.LAG_CONCURRENCY
    assert bench.p95(lag.samples) <= _LAG_P95_MAX_MS
