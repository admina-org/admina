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

"""Run the real proxy app (``admina.proxy.main.app``) with its lifespan.

:func:`isolate` keeps the lifespan off Redis, ClickHouse and OTEL and gives
it an event bus of its own; :func:`serve` starts the lifespan, points the
gateway at an in-process fake upstream and sends requests through the ASGI
app, middleware included.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from typing import Any

import httpx

API_KEY = "proxy-test-key-" + "0" * 16

CHAT = {
    "method": "POST",
    "url": "/v1/chat/completions",
    "json": {"model": "m1", "messages": [{"role": "user", "content": "hello"}]},
}


def subprocess_env(*drop_prefixes: str, **extra: str) -> dict[str, str]:
    """The environment for a child interpreter: ``os.environ`` without the
    variables starting with *drop_prefixes*, plus *extra*.

    pytest-cov's subprocess hook (``COV_CORE_*``) is left out as well: a
    child running in another directory would not find the coverage
    configuration and would write data the parent cannot combine.
    """
    drop = ("COV_CORE_", *drop_prefixes)
    env = {name: value for name, value in os.environ.items() if not name.startswith(drop)}
    env.update(extra)
    return env


def with_key(request: dict, key: str = API_KEY) -> dict:
    """*request* with ``Authorization: Bearer <key>``."""
    return {**request, "headers": {**request.get("headers", {}), "Authorization": f"Bearer {key}"}}


class NoOTEL:
    """Stands in for the OTEL exporter: nothing is exported from tests."""

    enabled = False

    def __init__(self, **_kw: Any) -> None:
        pass


def isolate(monkeypatch, *, forensic_backend: str = "memory", forensic_dir: str = "") -> None:
    """No Redis, ClickHouse or OTEL export; the lifespan's event-bus
    subscriptions go to a bus of their own; ``app.state.proxy`` is restored
    after the test."""
    from admina.core.event_bus import EventBus
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "REDIS_URL", "")
    monkeypatch.setattr(proxy_main.settings, "CLICKHOUSE_HOST", "")
    monkeypatch.setattr(proxy_main.settings, "FORENSIC_BACKEND", forensic_backend)
    monkeypatch.setattr(proxy_main.settings, "FORENSIC_BASE_DIR", forensic_dir)
    monkeypatch.setattr(proxy_main, "OTELGovernanceExporter", NoOTEL)
    monkeypatch.setattr(proxy_main, "governance_bus", EventBus())
    monkeypatch.setattr(proxy_main.app.state, "proxy", None, raising=False)


def upstream(request: httpx.Request) -> httpx.Response:
    """A fake OpenAI-compatible upstream: one model, one fixed completion."""
    if request.url.path.endswith("/models"):
        return httpx.Response(200, json={"object": "list", "data": [{"id": "m1"}]})
    return httpx.Response(
        200,
        json={
            "id": "c1",
            "object": "chat.completion",
            "model": "m1",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hi"},
                    "finish_reason": "stop",
                }
            ],
        },
    )


def serve(
    requests: list[dict],
    *,
    inspect: Callable[[Any], Any] | None = None,
) -> tuple[list[httpx.Response], Any]:
    """Start the proxy lifespan, send *requests* (kwargs of
    ``httpx.AsyncClient.request``) and return the responses with the value
    of ``inspect(state)`` taken while the proxy is still running."""
    from admina.proxy import main as proxy_main

    async def go() -> tuple[list[httpx.Response], Any]:
        async with proxy_main.lifespan(proxy_main.app):
            state = proxy_main.app.state.proxy
            await state.gateway_http_client.aclose()
            state.gateway_http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
            transport = httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                responses = [await client.request(**kw) for kw in requests]
            return responses, (inspect(state) if inspect else state)

    return asyncio.run(go())
