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

"""End-to-end tests for the OpenAI-compatible gateway router.

The router is exercised in isolation via a fresh FastAPI app with an
injected fake ProxyState and settings — no real infra required.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI

from admina.proxy.api.gateway import create_gateway_endpoints

# ── Fakes ─────────────────────────────────────────────────────


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": "INJECT" in text, "risk_level": "high", "patterns": []}


class _FakePII:
    """Redacts 'a@b.com' → '[EMAIL]' deterministically."""

    def redact(self, text: str) -> dict:
        n = text.count("a@b.com")
        return {"redacted_text": text.replace("a@b.com", "[EMAIL]"), "entities": [], "count": n}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


def _json_response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


class _FakeHTTP:
    """Records the last post/get and returns a preset httpx.Response."""

    def __init__(self, response: httpx.Response | None = None):
        self._response = response
        self.last_post = None
        self.last_get = None

    async def get(self, url, **kw):
        self.last_get = (url, kw)
        return self._response

    async def post(self, url, **kw):
        self.last_post = (url, kw)
        return self._response


def _settings(**over):
    base = dict(
        ADMINA_GATEWAY_UPSTREAM="http://upstream/v1",
        ADMINA_GATEWAY_BLOCK_MESSAGE="blocked by policy",
        ADMINA_GATEWAY_MODELS_ALLOWLIST="",
        INJECTION_FAST_PATH_ENABLED=True,
        PII_REDACTION_ENABLED=True,
        GOVERNANCE_MODE="enforce",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _app(state, settings):
    app = FastAPI()
    app.include_router(
        create_gateway_endpoints(get_state=lambda: state, get_settings=lambda: settings)
    )
    return app


def _client(app):
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _state(http, **over):
    base = dict(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoopBreaker(),
        governance_guards=[],
        forensic_box=None,
        http_client=http,
    )
    base.update(over)
    return SimpleNamespace(**base)


# ── GET /v1/models ────────────────────────────────────────────


def test_models_passthrough():
    http = _FakeHTTP(_json_response({"object": "list", "data": [{"id": "llama3"}, {"id": "phi3"}]}))
    app = _app(_state(http), _settings())

    async def go():
        async with _client(app) as c:
            return await c.get("/v1/models")

    resp = asyncio.run(go())
    assert resp.status_code == 200
    assert http.last_get[0] == "http://upstream/v1/models"
    assert {m["id"] for m in resp.json()["data"]} == {"llama3", "phi3"}


def test_models_allowlist_filters():
    http = _FakeHTTP(_json_response({"object": "list", "data": [{"id": "llama3"}, {"id": "phi3"}]}))
    app = _app(_state(http), _settings(ADMINA_GATEWAY_MODELS_ALLOWLIST="llama3"))

    async def go():
        async with _client(app) as c:
            return await c.get("/v1/models")

    resp = asyncio.run(go())
    assert [m["id"] for m in resp.json()["data"]] == ["llama3"]
