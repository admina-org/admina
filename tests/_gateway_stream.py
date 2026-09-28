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

"""Helpers for the gateway streaming tests — not a test module itself.

- :class:`MockUpstream`: an OpenAI-compatible upstream behind
  ``httpx.MockTransport``. It serves a body in pieces, optionally with
  delays or a failure, and records what the gateway asked and how far the
  body got.
- The SSE fixtures of ``tests/fixtures/sse``: each file holds the exact
  bytes of one upstream stream as a list of chunks, and the request
  options that produce such a stream.
- A gateway app with fake engines, and a raw ASGI driver that sees each
  response message as it leaves the application.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
from fastapi import FastAPI

from admina.proxy.api.gateway import create_gateway_endpoints

UPSTREAM = "http://upstream.test/v1"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sse"
FIXTURES = sorted(path.stem for path in FIXTURE_DIR.glob("*.json"))
EMAIL = "jane.doe@example.com"


def fixture(name: str) -> dict:
    """A fixture with its chunks as bytes."""
    data = json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))
    data["chunks"] = [chunk.encode("utf-8") for chunk in data["chunks"]]
    return data


def fixture_bytes(name: str) -> bytes:
    return b"".join(fixture(name)["chunks"])


def split_every(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def chat_body(name: str | None = None, *, stream: bool = True, content: str = "hello") -> dict:
    """A chat completion request, with the request options of fixture *name*."""
    body = {"model": "example-model", "messages": [{"role": "user", "content": content}]}
    if name is not None:
        body.update(fixture(name)["request"])
    body["stream"] = stream
    return body


ErrorFactory = Callable[[httpx.Request], Exception]


class MockUpstream:
    """Answers every request with the same status, headers and body pieces.

    Args:
        pieces: The body, in the pieces it is sent in.
        status: HTTP status of the response.
        content_type: Its Content-Type (None = no header).
        headers: Other response headers.
        delay: Seconds before each piece after the first.
        before_headers: Seconds before the response starts.
        error: Raised instead of answering (called with the request).
        error_after: Raised after the last piece (called with the request).
    """

    def __init__(
        self,
        pieces: list[bytes] | tuple = (),
        *,
        status: int = 200,
        content_type: str | None = "text/event-stream",
        headers: dict[str, str] | None = None,
        delay: float = 0.0,
        before_headers: float = 0.0,
        error: ErrorFactory | None = None,
        error_after: ErrorFactory | None = None,
    ):
        self.pieces = [p if isinstance(p, bytes) else p.encode("utf-8") for p in pieces]
        self.status = status
        self.content_type = content_type
        self.headers = headers or {}
        self.delay = delay
        self.before_headers = before_headers
        self.error = error
        self.error_after = error_after
        self.requests: list[httpx.Request] = []
        self.produced = 0
        self.closed = False
        self.stopped_by: str | None = None

    async def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.before_headers:
            await asyncio.sleep(self.before_headers)
        if self.error is not None:
            raise self.error(request)
        headers = {"content-type": self.content_type} if self.content_type else {}
        headers.update(self.headers)
        return httpx.Response(self.status, headers=headers, content=self._body(request))

    async def _body(self, request: httpx.Request):
        try:
            for i, piece in enumerate(self.pieces):
                if i and self.delay:
                    await asyncio.sleep(self.delay)
                self.produced += 1
                yield piece
            if self.error_after is not None:
                raise self.error_after(request)
        except BaseException as exc:
            self.stopped_by = type(exc).__name__
            raise
        finally:
            self.closed = True

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


# ── Fake engines ──────────────────────────────────────────────


class FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": "INJECT" in text, "risk_level": "high", "patterns": []}

    def get_stats(self) -> dict:
        return {}


class FakePII:
    """Redacts :data:`EMAIL` to ``[EMAIL]``."""

    def redact(self, text: str) -> dict:
        n = text.count(EMAIL)
        return {"redacted_text": text.replace(EMAIL, "[EMAIL]"), "entities": [], "count": n}

    def get_stats(self) -> dict:
        return {}


class FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}

    def get_stats(self) -> dict:
        return {}


# ── Gateway app ───────────────────────────────────────────────


def settings(**over: Any):
    """Real proxy settings pointing at :data:`UPSTREAM`, PII redaction off."""
    from admina.proxy.config import Settings

    base: dict[str, Any] = {"ADMINA_GATEWAY_UPSTREAM": UPSTREAM, "PII_REDACTION_ENABLED": False}
    base.update(over)
    return Settings(**base)


def gateway_app(
    client: Any,
    cfg: Any = None,
    *,
    stream_mode: str = "passthrough",
    state: dict[str, Any] | None = None,
) -> FastAPI:
    """The gateway router alone, with fake engines and *client* upstream.

    *state* replaces or adds attributes of the proxy state.
    """
    cfg = cfg if cfg is not None else settings()
    proxy_state = SimpleNamespace(
        firewall=FakeFirewall(),
        pii_redactor=FakePII(),
        loop_breaker=FakeLoopBreaker(),
        egress_policy=None,
        governance_guards=[],
        forensic_box=None,
        gateway_http_client=client,
        gateway_stream_mode=stream_mode,
    )
    for name, value in (state or {}).items():
        setattr(proxy_state, name, value)
    app = FastAPI()
    app.include_router(
        create_gateway_endpoints(get_state=lambda: proxy_state, get_settings=lambda: cfg)
    )
    return app


async def post_direct(upstream: MockUpstream, body: dict, path: str = "/chat/completions"):
    """The same request sent straight to the upstream."""
    async with upstream.client() as client:
        return await client.post(f"{UPSTREAM}{path}", json=body)


async def post_through(
    upstream: MockUpstream,
    body: dict,
    cfg: Any = None,
    *,
    stream_mode: str = "passthrough",
    method: str = "POST",
    path: str = "/v1/chat/completions",
    state: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    """The request sent through the gateway router to *upstream*: *body* as
    JSON, or the raw JSON text *content* when given."""
    async with upstream.client() as client:
        app = gateway_app(client, cfg, stream_mode=stream_mode, state=state)
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            if method == "GET":
                return await c.get(path, headers=headers)
            if content is not None:
                raw_headers = {"content-type": "application/json", **(headers or {})}
                return await c.post(path, content=content, headers=raw_headers)
            return await c.post(path, json=body, headers=headers)


def through(upstream: MockUpstream, body: dict, cfg: Any = None, **kw: Any) -> httpx.Response:
    return asyncio.run(post_through(upstream, body, cfg, **kw))


def direct(upstream: MockUpstream, body: dict, **kw: Any) -> httpx.Response:
    return asyncio.run(post_direct(upstream, body, **kw))


async def asgi_post(
    app: Any,
    body: dict,
    on_message: Callable[[dict], Awaitable[None]],
    disconnect: asyncio.Event,
    path: str = "/v1/chat/completions",
) -> None:
    """POST *body* to *app* over raw ASGI.

    Every message the application sends goes to *on_message* as it is sent.
    After the request body, ``receive`` waits for *disconnect* and then
    reports that the client went away.
    """
    raw = json.dumps(body).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"test"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(raw)).encode()),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("test", 80),
    }
    body_sent = False

    async def receive() -> dict:
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": raw, "more_body": False}
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        await on_message(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            disconnect.set()

    await app(scope, receive, send)


def run_lifespan(monkeypatch: Any, config: Any) -> Any:
    """Run the proxy lifespan with *config* as admina.yaml; return its state.

    No Redis, ClickHouse, forensic files or OTEL export, and the lifespan's
    event-bus subscriptions go to a bus of their own.
    """
    from admina.core.event_bus import EventBus
    from admina.proxy import main as proxy_main

    class _NoOTEL:
        enabled = False

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    monkeypatch.setattr(proxy_main.settings, "REDIS_URL", "")
    monkeypatch.setattr(proxy_main.settings, "CLICKHOUSE_HOST", "")
    monkeypatch.setattr(proxy_main.settings, "FORENSIC_BACKEND", "memory")
    monkeypatch.setattr(proxy_main, "OTELGovernanceExporter", _NoOTEL)
    monkeypatch.setattr(proxy_main, "governance_bus", EventBus())
    monkeypatch.setattr(proxy_main, "_admina_config", config)
    app = FastAPI()

    async def go() -> Any:
        async with proxy_main.lifespan(app):
            return app.state.proxy

    return asyncio.run(go())
