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

"""Gateway-side tests for the configurable guard fail mode (B3).

``chat_completions`` (admina/proxy/api/gateway.py) calls the canonical
``run_pipeline`` directly, so it must forward ``guard_fail_mode`` from
settings just like ``mcp_proxy`` does — otherwise ``ADMINA_GUARD_FAIL_MODE=
closed`` silently fails to protect this surface. Fixtures mirror
tests/test_gateway_endpoints.py (fresh FastAPI app, fake ProxyState/settings,
no real infra).
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
        return {"is_injection": False, "risk_level": "low", "patterns": []}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


class _RaisingGuard:
    name = "gateway-raiser"

    async def inspect_request(self, payload):
        raise RuntimeError("gateway guard boom")

    async def inspect_response(self, payload):
        return {"action": "ALLOW", "risk_level": "LOW"}


def _json_response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


class _FakeHTTP:
    """Records whether upstream was ever called and returns a preset response."""

    def __init__(self, response: httpx.Response | None = None):
        self._response = response
        self.last_post = None

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
        GUARD_FAIL_MODE="open",
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
        governance_guards=[_RaisingGuard()],
        forensic_box=None,
        http_client=http,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _post_chat_completions(app):
    body = {"model": "llama3", "messages": [{"role": "user", "content": "hello"}]}

    async def go():
        async with _client(app) as c:
            return await c.post("/v1/chat/completions", json=body)

    return asyncio.run(go())


class TestGatewayGuardFailMode:
    def test_open_mode_swallows_guard_error_and_forwards(self):
        upstream_resp = _json_response(
            {
                "id": "cmpl-1",
                "object": "chat.completion",
                "model": "llama3",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop",
                    }
                ],
            }
        )
        http = _FakeHTTP(upstream_resp)
        app = _app(_state(http), _settings(GUARD_FAIL_MODE="open"))

        resp = _post_chat_completions(app)
        assert resp.status_code == 200
        assert resp.json()["choices"][0]["message"]["content"] == "ok"
        assert http.last_post is not None  # request reached upstream

    def test_closed_mode_blocks_synthetic_content_filter(self):
        # Upstream must never be reached in closed mode.
        http = _FakeHTTP(_json_response({"should": "not be used"}))
        app = _app(_state(http), _settings(GUARD_FAIL_MODE="closed"))

        resp = _post_chat_completions(app)
        assert resp.status_code == 200  # synthetic completion, not an HTTP error
        j = resp.json()
        assert j["choices"][0]["finish_reason"] == "content_filter"
        assert j["choices"][0]["message"]["content"] == "blocked by policy"
        assert http.last_post is None  # upstream never called
