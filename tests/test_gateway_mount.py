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


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoop:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


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
