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

"""Latency the gateway adds on a retrieval-augmented (RAG) trace.

Runs in one process, without network or Docker:

- a mock OpenAI-compatible upstream that answers a streamed chat completion
  with ``--tokens`` chunks, waiting ``--chunk-ms`` before the first chunk and
  between chunks;
- the gateway router in passthrough mode, PII redaction off, an in-memory
  forensic log and the firewall engine under test (``python`` or ``rust``);
- a RAG-shaped prompt: a system message and a user message with 12
  ``<source>`` blocks of generated prose (about 44,000 characters, 11k
  tokens) followed by the question.

Two measurements per engine:

1. Time to the first streamed chunk, direct to the upstream and through the
   gateway, alternated round by round (``--rounds`` rounds of 1 and 8
   concurrent requests; a request stops reading after its first chunk). The
   gateway is measured with ``X-Admina-Scan-Policy`` (the system message
   and the ``<source>`` blocks declared as already scanned) and without it
   (full scan). Reported: p50 and p95, and the p95 the gateway adds.
2. Event loop lag with 8 concurrent clients, each one streaming complete
   answers through the gateway for ``--lag-seconds``, with the scan policy
   and without it: the lag sampled every 10 ms, as
   ``admina_event_loop_lag_seconds`` does every 100 ms.

Usage::

    .venv/bin/python scripts/bench_gateway.py
    .venv/bin/python scripts/bench_gateway.py --engines python --rounds 60 --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import sys
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

UPSTREAM = "http://upstream.bench/v1"
PRESCAN_TAG = "source"
CONCURRENCY = (1, 8)
LAG_CONCURRENCY = 8

# ── RAG-shaped prompt ─────────────────────────────────────────

_OPENINGS = (
    "In the morning",
    "Over the years",
    "During the summer",
    "Along the northern edge",
    "Near the old centre",
    "After the spring rains",
    "On most weekends",
    "Beyond the second bridge",
)
_ADJECTIVES = (
    "quiet",
    "narrow",
    "green",
    "busy",
    "wide",
    "bright",
    "small",
    "stone",
    "wooden",
    "sunlit",
)
_NOUNS = (
    "river",
    "garden",
    "market",
    "bridge",
    "harbour",
    "library",
    "orchard",
    "meadow",
    "workshop",
    "village",
    "station",
    "forest",
    "valley",
    "museum",
    "bakery",
    "coastline",
    "courtyard",
    "vineyard",
)
_VERBS = (
    "follows",
    "joins",
    "surrounds",
    "overlooks",
    "crosses",
    "borders",
    "shelters",
    "welcomes",
    "reflects",
    "faces",
)


def _sentence(rng: random.Random) -> str:
    return (
        f"{rng.choice(_OPENINGS)}, the {rng.choice(_ADJECTIVES)} {rng.choice(_NOUNS)} "
        f"{rng.choice(_VERBS)} the {rng.choice(_ADJECTIVES)} {rng.choice(_NOUNS)}."
    )


def rag_messages(blocks: int = 12, chars: int = 44_000, seed: int = 7) -> list[dict[str, str]]:
    """A system message and a user message with *blocks* ``<source>``
    blocks of generated prose (about *chars* characters in all) and a
    question."""
    rng = random.Random(seed)
    per_block = chars // blocks
    parts = []
    for number in range(1, blocks + 1):
        text: list[str] = []
        while sum(len(s) + 1 for s in text) < per_block:
            text.append(_sentence(rng))
        parts.append(f'<source id="{number}" title="Notes {number}">\n{" ".join(text)}\n</source>')
    question = "Which of the notes describe the market near the river, and how do they differ?"
    return [
        {
            "role": "system",
            "content": "Answer from the notes below and cite each note you use by its id.",
        },
        {"role": "user", "content": "\n\n".join(parts) + "\n\n" + question},
    ]


# ── Mock upstream ─────────────────────────────────────────────


def _sse_chunks(tokens: int) -> list[bytes]:
    base = {"id": "chatcmpl-bench", "object": "chat.completion.chunk", "model": "bench-model"}
    chunks = []
    for position in range(tokens):
        delta = {"role": "assistant", "content": ""} if position == 0 else {"content": " word"}
        event = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}
        chunks.append(f"data: {json.dumps(event, separators=(',', ':'))}\n\n".encode())
    finish = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
    chunks.append(f"data: {json.dumps(finish, separators=(',', ':'))}\n\n".encode())
    chunks.append(b"data: [DONE]\n\n")
    return chunks


def mock_upstream(tokens: int, chunk_s: float) -> httpx.AsyncClient:
    """An upstream client that streams *tokens* chunks, *chunk_s* before
    the first one and between chunks."""
    chunks = _sse_chunks(tokens)

    async def body():
        for position, chunk in enumerate(chunks):
            if position:
                await asyncio.sleep(chunk_s)
            yield chunk

    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(chunk_s)
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body())

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ── Gateway ───────────────────────────────────────────────────


@dataclass
class Gateway:
    app: Any
    scan_policy: str
    executor: Any
    #: Scan policy outcomes counted by the gateway ("prescan_<status>").
    prescan: Counter = field(default_factory=Counter)

    def check_scan_policy(self) -> None:
        """Raise unless every scan policy sent so far was applied."""
        if not self.prescan["prescan_accepted"] or len(self.prescan) != 1:
            raise RuntimeError(f"the scan policy was not applied: {dict(self.prescan)}")

    def close(self) -> None:
        self.executor.shutdown()


def firewall_for(engine: str) -> Any:
    """The firewall bridge of *engine*, without admina.yaml overrides."""
    from admina import engines

    if engine == "rust":
        if not engines._rust_available:
            raise RuntimeError("the rust engine needs admina-core")
        return engines._RustFirewallBridge()
    return engines._PythonFirewallBridge(engines._FirewallSettings())


def build_gateway(engine: str, client: httpx.AsyncClient) -> Gateway:
    """The gateway router with the *engine* firewall and *client* upstream;
    ``<source>`` blocks may be declared as already scanned."""
    from fastapi import FastAPI

    from admina.core.config import AdminaConfig, GatewayConfig
    from admina.domains.compliance.forensic import ForensicBlackBox
    from admina.proxy.api.gateway import create_gateway_endpoints
    from admina.proxy.config import Settings
    from admina.proxy.gateway_scan import build_gateway_scan_config
    from admina.proxy.pipeline_executor import PipelineExecutor

    firewall = firewall_for(engine)
    config = AdminaConfig(gateway=GatewayConfig(prescan_tags=[PRESCAN_TAG]))
    scan = build_gateway_scan_config(firewall, config)
    executor = PipelineExecutor()
    prescan: Counter = Counter()
    state = SimpleNamespace(
        firewall=firewall,
        pii_redactor=None,
        loop_breaker=None,
        egress_policy=None,
        governance_guards=[],
        forensic_box=ForensicBlackBox(),
        gateway_http_client=client,
        gateway_stream_mode="passthrough",
        gateway_scan=scan,
        pipeline_executor=executor,
        inc_metric=lambda key, value=1: prescan.update({key: value}),
    )
    settings = Settings(
        ADMINA_GATEWAY_UPSTREAM=UPSTREAM,
        PII_REDACTION_ENABLED=False,
        ADMINA_GATEWAY_SCAN_POLICY_ENABLED=True,
    )
    app = FastAPI()
    app.include_router(
        create_gateway_endpoints(get_state=lambda: state, get_settings=lambda: settings)
    )
    policy = f"v1; roles=user,tool; prescanned={PRESCAN_TAG}; ruleset={scan.ruleset_sha256}"
    return Gateway(app=app, scan_policy=policy, executor=executor, prescan=prescan)


async def asgi_stream(
    app: Any,
    body: dict,
    headers: dict[str, str],
    *,
    first_only: bool,
) -> float:
    """POST *body* to the gateway over raw ASGI; the milliseconds to the
    first body chunk. With *first_only* the client disconnects after it."""
    raw = json.dumps(body).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/chat/completions",
        "raw_path": b"/v1/chat/completions",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"bench"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(raw)).encode()),
            *((k.lower().encode(), v.encode()) for k, v in headers.items()),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("bench", 80),
    }
    disconnect = asyncio.Event()
    sent = False
    first: list[float] = []
    started = time.perf_counter()

    async def receive() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": raw, "more_body": False}
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        if message["type"] != "http.response.body":
            return
        if message.get("body") and not first:
            first.append((time.perf_counter() - started) * 1000)
            if first_only:
                disconnect.set()
        if not message.get("more_body", False):
            disconnect.set()

    await app(scope, receive, send)
    return first[0]


async def direct_first_chunk_ms(client: httpx.AsyncClient, body: dict) -> float:
    started = time.perf_counter()
    async with client.stream("POST", f"{UPSTREAM}/chat/completions", json=body) as resp:
        async for chunk in resp.aiter_raw():
            if chunk:
                return (time.perf_counter() - started) * 1000
    raise RuntimeError("empty upstream stream")


# ── Measurements ──────────────────────────────────────────────


def p95(samples: list[float]) -> float:
    return statistics.quantiles(samples, n=20, method="inclusive")[-1]


@dataclass
class FirstChunk:
    """Time to the first chunk, in ms, per path, at one concurrency."""

    concurrency: int
    samples: dict[str, list[float]] = field(default_factory=dict)

    def added_p95(self, path: str) -> float:
        return p95(self.samples[path]) - p95(self.samples["direct"])

    def summary(self) -> dict[str, Any]:
        return {
            path: {
                "p50_ms": round(statistics.median(values), 2),
                "p95_ms": round(p95(values), 2),
                "added_p95_ms": round(self.added_p95(path), 2) if path != "direct" else 0.0,
                "requests": len(values),
            }
            for path, values in self.samples.items()
        }


async def measure_first_chunk(
    engine: str,
    concurrency: int,
    rounds: int,
    tokens: int,
    chunk_s: float,
    *,
    full_scan: bool = True,
) -> FirstChunk:
    """Alternate direct and gateway rounds of *concurrency* requests; the
    gateway without the scan policy too when *full_scan*."""
    body = {"model": "bench-model", "messages": rag_messages(), "stream": True}
    result = FirstChunk(concurrency, {"direct": [], "prescan": []})
    async with mock_upstream(tokens, chunk_s) as client:
        gateway = build_gateway(engine, client)
        paths: dict[str, Callable[[], Awaitable[float]]] = {
            "direct": lambda: direct_first_chunk_ms(client, body),
            "prescan": lambda: asgi_stream(
                gateway.app,
                body,
                {"X-Admina-Scan-Policy": gateway.scan_policy},
                first_only=True,
            ),
        }
        if full_scan:
            result.samples["full_scan"] = []
            paths["full_scan"] = lambda: asgi_stream(gateway.app, body, {}, first_only=True)
        try:
            await paths["prescan"]()  # warm-up
            gateway.check_scan_policy()
            for path, measure in paths.items():
                if path != "prescan":
                    await measure()
            for _ in range(rounds):
                for path, measure in paths.items():
                    result.samples[path] += await asyncio.gather(
                        *(measure() for _ in range(concurrency))
                    )
        finally:
            gateway.close()
    return result


@dataclass
class LoopLag:
    """Event loop lag samples, in ms, with streams in flight."""

    samples: list[float]
    requests: int

    def summary(self) -> dict[str, Any]:
        return {
            "p50_ms": round(statistics.median(self.samples), 3),
            "p95_ms": round(p95(self.samples), 3),
            "max_ms": round(max(self.samples), 3),
            "samples": len(self.samples),
            "requests": self.requests,
        }


async def measure_loop_lag(
    engine: str, seconds: float, tokens: int, chunk_s: float, *, prescan: bool = True
) -> LoopLag:
    """Lag with :data:`LAG_CONCURRENCY` clients streaming complete answers
    through the gateway for *seconds*, with the scan policy when *prescan*."""
    from admina.proxy.loop_lag import EventLoopLagMonitor

    samples: list[float] = []

    class _Recording(EventLoopLagMonitor):
        def observe(self, lag: float) -> None:
            super().observe(lag)
            samples.append(max(lag, 0.0) * 1000)

    body = {"model": "bench-model", "messages": rag_messages(), "stream": True}
    completed = 0
    async with mock_upstream(tokens, chunk_s) as client:
        gateway = build_gateway(engine, client)
        headers = {"X-Admina-Scan-Policy": gateway.scan_policy} if prescan else {}
        deadline = time.perf_counter() + seconds

        async def user(offset: float) -> None:
            nonlocal completed
            await asyncio.sleep(offset)
            while time.perf_counter() < deadline:
                await asyncio.wait_for(
                    asgi_stream(gateway.app, body, headers, first_only=False),
                    timeout=tokens * chunk_s * 4 + 10,
                )
                completed += 1

        monitor = _Recording(interval=0.01)
        monitor.start()
        try:
            # Staggered starts, so that new requests arrive while others stream.
            await asyncio.gather(
                *(user(i * tokens * chunk_s / LAG_CONCURRENCY) for i in range(LAG_CONCURRENCY))
            )
        finally:
            await monitor.stop()
            gateway.close()
    if prescan:
        gateway.check_scan_policy()
    return LoopLag(samples=samples, requests=completed)


def run(engines: list[str], rounds: int, tokens: int, chunk_ms: float, lag_seconds: float) -> dict:
    chunk_s = chunk_ms / 1000
    report: dict[str, Any] = {
        "prompt_chars": sum(len(m["content"]) for m in rag_messages()),
        "tokens": tokens,
        "chunk_ms": chunk_ms,
        "rounds": rounds,
        "engines": {},
    }
    for engine in engines:
        first = {
            f"c={c}": asyncio.run(measure_first_chunk(engine, c, rounds, tokens, chunk_s)).summary()
            for c in CONCURRENCY
        }
        lag = {
            path: asyncio.run(
                measure_loop_lag(engine, lag_seconds, tokens, chunk_s, prescan=path == "prescan")
            ).summary()
            for path in ("prescan", "full_scan")
        }
        report["engines"][engine] = {
            "first_chunk": first,
            f"event_loop_lag_c={LAG_CONCURRENCY}": lag,
        }
    return report


def _print(report: dict) -> None:
    print(
        f"RAG prompt {report['prompt_chars']} characters, {report['tokens']} tokens, "
        f"{report['chunk_ms']} ms per chunk, {report['rounds']} rounds"
    )
    for engine, data in report["engines"].items():
        print(f"\nengine={engine}")
        for concurrency, paths in data["first_chunk"].items():
            for path, stats in paths.items():
                print(
                    f"  first chunk {concurrency:<4} {path:<9} p50 {stats['p50_ms']:8.2f} ms"
                    f"  p95 {stats['p95_ms']:8.2f} ms  added p95 {stats['added_p95_ms']:8.2f} ms"
                )
        for path, lag in data[f"event_loop_lag_c={LAG_CONCURRENCY}"].items():
            print(
                f"  event loop lag c={LAG_CONCURRENCY} {path:<9} p50 {lag['p50_ms']:.3f} ms  "
                f"p95 {lag['p95_ms']:.3f} ms  max {lag['max_ms']:.3f} ms  "
                f"({lag['samples']} samples, {lag['requests']} requests)"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--engines", default="python,rust", help="comma-separated")
    parser.add_argument("--rounds", type=int, default=40)
    parser.add_argument("--tokens", type=int, default=1000)
    parser.add_argument("--chunk-ms", type=float, default=5.0)
    parser.add_argument("--lag-seconds", type=float, default=10.0)
    parser.add_argument("--json", type=Path, help="also write the report here")
    args = parser.parse_args()
    engines = [e.strip() for e in args.engines.split(",") if e.strip()]
    report = run(engines, args.rounds, args.tokens, args.chunk_ms, args.lag_seconds)
    _print(report)
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
