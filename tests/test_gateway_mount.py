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

"""Gateway is mounted on the real proxy app and gated by the global auth
middleware (verify_credential)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

pytest.importorskip("fastapi")


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low", "patterns": []}

    def get_stats(self) -> dict:
        return {}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoop:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}

    def get_stats(self) -> dict:
        return {}


class _FakeHTTP:
    async def post(self, url, **kw):
        return httpx.Response(
            200,
            content=json.dumps(
                {
                    "id": "c1",
                    "object": "chat.completion",
                    "model": "llama3",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "hi"},
                            "finish_reason": "stop",
                        }
                    ],
                }
            ).encode(),
            headers={"content-type": "application/json"},
        )


def _inject(monkeypatch, *, api_key: str, allow_unauth: bool):
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", api_key)
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", allow_unauth)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_UPSTREAM", "http://upstream/v1")

    state = ProxyState(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoop(),
        router=MultiUpstreamRouter(default_upstream="http://upstream"),
        http_client=_FakeHTTP(),
        redis=None,
        clickhouse=None,
        forensic_box=None,
        governance_guards=[],
        alert_channels=[],
        auth_providers=[],
    )
    proxy_main.app.state.proxy = state
    return proxy_main.app


def _post(app, headers=None):
    body = {"model": "llama3", "messages": [{"role": "user", "content": "hi"}]}

    async def go():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.post("/v1/chat/completions", json=body, headers=headers or {})

    return asyncio.run(go())


def test_gateway_requires_auth_when_key_set(monkeypatch):
    app = _inject(monkeypatch, api_key="secret-key-1234567890", allow_unauth=False)
    resp = _post(app)  # no credential
    assert resp.status_code == 401


def test_gateway_allows_with_bearer_key(monkeypatch):
    app = _inject(monkeypatch, api_key="secret-key-1234567890", allow_unauth=False)
    resp = _post(app, headers={"Authorization": "Bearer secret-key-1234567890"})
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == "hi"


class _FakeClickHouse:
    """Records the rows inserted into governance_events."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list, list]] = []

    def insert(self, table, rows, column_names):
        self.inserts.append((table, rows, column_names))


async def _drain_background() -> None:
    """Wait for the fire-and-forget tasks of the gateway and the proxy."""
    from admina.proxy import main as proxy_main
    from admina.proxy.api import gateway

    while gateway._background_tasks or proxy_main._background_tasks:
        pending = list(gateway._background_tasks) + list(proxy_main._background_tasks)
        await asyncio.gather(*pending, return_exceptions=True)


def test_gateway_requests_reach_api_stats(monkeypatch):
    app = _inject(monkeypatch, api_key="secret-key-1234567890", allow_unauth=False)
    headers = {"Authorization": "Bearer secret-key-1234567890"}
    assert _post(app, headers=headers).status_code == 200
    assert _post(app, headers=headers).status_code == 200

    async def stats():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.get("/api/stats", headers=headers)

    proxy = asyncio.run(stats()).json()["proxy"]
    assert proxy["requests_total"] == 2
    assert proxy["requests_allowed"] == 2
    assert proxy["requests_blocked"] == 0


def test_gateway_request_is_stored_in_clickhouse(monkeypatch):
    app = _inject(monkeypatch, api_key="secret-key-1234567890", allow_unauth=False)
    ch = _FakeClickHouse()
    app.state.proxy.clickhouse = ch
    body = {"model": "llama3", "messages": [{"role": "user", "content": "hi"}]}

    async def go():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(
                "/v1/chat/completions",
                json=body,
                headers={"Authorization": "Bearer secret-key-1234567890"},
            )
        await _drain_background()
        return resp

    assert asyncio.run(go()).status_code == 200

    assert len(ch.inserts) == 1
    table, rows, columns = ch.inserts[0]
    assert table.endswith(".governance_events")
    row = dict(zip(columns, rows[0], strict=True))
    assert row["event_type"] == "gateway_request"
    assert row["method"] == "chat.completions"
    assert row["action"] == "allow"
