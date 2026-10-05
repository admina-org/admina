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

"""ADMINA_METRICS_REQUIRE_AUTH and ADMINA_API_DOCS_REQUIRE_AUTH.

Both default to false: /metrics and the OpenAPI docs are public, as before.
When set, the route needs the API key like every other route; /health stays
public.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

pytest.importorskip("fastapi")

from _proxy_app import API_KEY

DOCS = ["/docs", "/redoc", "/openapi.json"]


def _get(monkeypatch, paths: list[str], headers: dict | None = None, providers=()) -> list[int]:
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    state = ProxyState(
        router=MultiUpstreamRouter(default_upstream="http://mcp.test"),
        auth_providers=list(providers),
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_DOCS_ENABLED", True)

    async def go() -> list[int]:
        transport = httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return [(await client.get(p, headers=headers or {})).status_code for p in paths]

    return asyncio.run(go())


def _require(monkeypatch, *, metrics: bool, docs: bool) -> None:
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_METRICS_REQUIRE_AUTH", metrics)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_DOCS_REQUIRE_AUTH", docs)


def test_defaults_keep_metrics_and_docs_public(monkeypatch):
    from admina.proxy.config import Settings

    settings = Settings(_env_file=None)
    assert settings.ADMINA_METRICS_REQUIRE_AUTH is False
    assert settings.ADMINA_API_DOCS_REQUIRE_AUTH is False
    _require(monkeypatch, metrics=False, docs=False)
    assert _get(monkeypatch, ["/metrics", *DOCS, "/health"]) == [200] * 5


def test_metrics_needs_the_key(monkeypatch):
    _require(monkeypatch, metrics=True, docs=False)
    assert _get(monkeypatch, ["/metrics", *DOCS, "/health"]) == [401, 200, 200, 200, 200]
    assert _get(monkeypatch, ["/metrics"], {"Authorization": f"Bearer {API_KEY}"}) == [200]
    assert _get(monkeypatch, ["/metrics"], {"X-API-Key": API_KEY}) == [200]
    assert _get(monkeypatch, ["/metrics"], {"X-API-Key": "wrong-" + API_KEY}) == [401]


def test_docs_need_the_key(monkeypatch):
    _require(monkeypatch, metrics=False, docs=True)
    assert _get(monkeypatch, [*DOCS, "/metrics", "/health"]) == [401, 401, 401, 200, 200]
    assert _get(monkeypatch, DOCS, {"X-API-Key": API_KEY}) == [200, 200, 200]


def test_docs_need_the_key_with_the_api_key_provider_loaded(monkeypatch):
    """The built-in provider exempts the docs paths on its own; the setting
    is not bypassed by it."""
    from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

    provider = APIKeyAuthProvider(api_key=API_KEY)
    _require(monkeypatch, metrics=True, docs=True)
    assert _get(monkeypatch, [*DOCS, "/metrics"], providers=[provider]) == [401] * 4
    assert _get(monkeypatch, [*DOCS, "/metrics"], {"X-API-Key": API_KEY}, [provider]) == [200] * 4


def test_disabled_docs_stay_404(monkeypatch):
    from admina.proxy import main as proxy_main

    _require(monkeypatch, metrics=True, docs=True)
    statuses = _get(monkeypatch, [])  # sets the key and state
    assert statuses == []
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_DOCS_ENABLED", False)

    async def go() -> list[int]:
        transport = httpx.ASGITransport(app=proxy_main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return [(await client.get(p)).status_code for p in DOCS]

    assert asyncio.run(go()) == [404, 404, 404]
