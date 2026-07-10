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

"""Proxy-side tests for the configurable guard fail mode (B3)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

pytest.importorskip("fastapi")


class TestGuardFailModeConfig:
    def test_default_is_open(self):
        from admina.proxy.config import Settings

        s = Settings(_env_file=None)
        assert s.GUARD_FAIL_MODE == "open"

    def test_reads_canonical_env_var(self, monkeypatch):
        monkeypatch.setenv("ADMINA_GUARD_FAIL_MODE", "CLOSED")
        from admina.proxy.config import Settings

        s = Settings(_env_file=None)
        assert s.GUARD_FAIL_MODE == "closed"

    def test_invalid_value_rejected(self, monkeypatch):
        from pydantic import ValidationError

        from admina.proxy.config import Settings

        monkeypatch.setenv("ADMINA_GUARD_FAIL_MODE", "sometimes")
        with pytest.raises(ValidationError):
            Settings(_env_file=None)


# ── e2e stubs (mirrors tests/test_proxy_mcp_response_pii.py) ──


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low"}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


class _RaisingRequestGuard:
    name = "req-raiser"

    async def inspect_request(self, payload):
        raise RuntimeError("request guard boom")

    async def inspect_response(self, payload):
        return {"action": "ALLOW", "risk_level": "LOW"}


class _RaisingResponseGuard:
    name = "resp-raiser"

    async def inspect_request(self, payload):
        return {"action": "ALLOW", "risk_level": "LOW"}

    async def inspect_response(self, payload):
        raise RuntimeError("response guard boom")


class _FakeForensicBox:
    def __init__(self):
        self.records = []

    def record(self, event: dict) -> dict:
        self.records.append(event)
        return {"record_hash": "ab" * 16, "sequence_number": len(self.records)}


def _upstream_response(payload: dict) -> httpx.Response:
    return httpx.Response(
        status_code=200,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


def _inject_state(monkeypatch, *, guards, fail_mode, forensic_box=None):
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", True)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    monkeypatch.setattr(proxy_main.settings, "UPSTREAM_MCP_URL", "http://fake-upstream")
    monkeypatch.setattr(proxy_main.settings, "GUARD_FAIL_MODE", fail_mode)

    mock_http = AsyncMock()
    mock_http.post = AsyncMock(
        return_value=_upstream_response({"jsonrpc": "2.0", "id": 1, "result": {"text": "ok"}})
    )

    state = ProxyState(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoopBreaker(),
        router=MultiUpstreamRouter(default_upstream="http://fake-upstream"),
        http_client=mock_http,
        redis=None,
        clickhouse=None,
        forensic_box=forensic_box,
        governance_guards=guards,
        alert_channels=[],
        auth_providers=[],
    )
    proxy_main.app.state.proxy = state


def _post_mcp():
    from admina.proxy.main import app

    mcp_body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get_contact", "arguments": {}},
    }

    async def go():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/mcp", json=mcp_body)

    return asyncio.run(go())


class TestRequestSideFailMode:
    def test_open_mode_request_guard_error_allows(self, monkeypatch):
        _inject_state(monkeypatch, guards=[_RaisingRequestGuard()], fail_mode="open")
        resp = _post_mcp()
        assert resp.status_code == 200

    def test_closed_mode_request_guard_error_blocks(self, monkeypatch):
        _inject_state(monkeypatch, guards=[_RaisingRequestGuard()], fail_mode="closed")
        resp = _post_mcp()
        assert resp.status_code == 403
