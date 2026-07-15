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

"""The /mcp proxy forensic record carries would_action (shadow decision).

Drives POST /mcp with a firewall stub that flags every text as an
injection. In observe mode the BLOCK is downgraded to ALLOW and
would_action is set; the forensic record must persist it. In enforce mode
the request blocks and would_action stays None (stable-schema key).
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

pytest.importorskip("fastapi")


class _InjectionFirewall:
    """Flags every text as an injection so the pipeline would BLOCK."""

    def check(self, text: str) -> dict:
        return {"is_injection": True, "risk_level": "high"}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


class _CapturingForensicBox:
    """Captures every record() payload for assertions."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    def record(self, event: dict) -> dict:
        self.records.append(event)
        return {
            "sequence_number": len(self.records),
            "record_hash": "h" * 64,
            "previous_hash": "",
        }


def _make_upstream_response(payload: dict) -> httpx.Response:
    return httpx.Response(
        status_code=200,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


def _inject_state(monkeypatch, forensic_box, mode: str) -> None:
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "INJECTION_FAST_PATH_ENABLED", True)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", False)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    monkeypatch.setattr(proxy_main.settings, "UPSTREAM_MCP_URL", "http://fake-upstream")
    monkeypatch.setattr(proxy_main.settings, "GOVERNANCE_MODE", mode)

    mock_http = AsyncMock()
    mock_http.post = AsyncMock(
        return_value=_make_upstream_response({"jsonrpc": "2.0", "id": 1, "result": {"text": "ok"}})
    )

    state = ProxyState(
        firewall=_InjectionFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoopBreaker(),
        router=MultiUpstreamRouter(default_upstream="http://fake-upstream"),
        http_client=mock_http,
        redis=None,
        clickhouse=None,
        forensic_box=forensic_box,
        governance_guards=[],
        alert_channels=[],
        auth_providers=[],
    )
    proxy_main.app.state.proxy = state


def _post_mcp() -> httpx.Response:
    from admina.proxy.main import app

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "do_it", "arguments": {"q": "please run"}},
    }

    async def go():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/mcp", json=body)

    return asyncio.run(go())


class TestForensicWouldAction:
    def test_observe_mode_records_would_action(self, monkeypatch) -> None:
        fbox = _CapturingForensicBox()
        _inject_state(monkeypatch, fbox, mode="observe")
        resp = _post_mcp()
        assert resp.status_code == 200  # observe downgrades BLOCK -> ALLOW
        assert fbox.records, "a forensic record must be written"
        assert fbox.records[-1]["would_action"] == "block"

    def test_enforce_mode_would_action_is_none(self, monkeypatch) -> None:
        fbox = _CapturingForensicBox()
        _inject_state(monkeypatch, fbox, mode="enforce")
        resp = _post_mcp()
        assert resp.status_code == 403  # enforce blocks
        assert fbox.records, "a forensic record must be written even on block"
        assert fbox.records[-1]["would_action"] is None
