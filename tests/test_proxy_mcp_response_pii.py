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

"""End-to-end test: /mcp response PII redaction.

Drives an HTTP POST to the proxy's /mcp endpoint with a mocked upstream that
returns a dict-shaped tool result containing PII (email address).  Asserts the
response body has the email redacted before it reaches the caller.

The proxy app is imported as-is; lifespan is skipped and ProxyState is injected
directly into app.state so no real infra (Redis, ClickHouse, httpx upstream) is
required.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

pytest.importorskip("fastapi")


# ── Minimal stubs ─────────────────────────────────────────────


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low"}


class _FakePII:
    """Redacts 'a@b.com' → '[EMAIL]' so the test has a deterministic signal."""

    def redact(self, text: str) -> dict:
        redacted = text.replace("a@b.com", "[EMAIL]")
        count = text.count("a@b.com")
        return {"redacted_text": redacted, "entities": [], "count": count}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


# ── Helpers ───────────────────────────────────────────────────


def _make_upstream_response(payload: dict) -> httpx.Response:
    """Build a synthetic httpx.Response carrying *payload* as JSON."""
    return httpx.Response(
        status_code=200,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


def _inject_state(monkeypatch) -> None:
    """Patch proxy settings and inject a minimal ProxyState."""
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    # Allow unauthenticated requests so auth middleware passes.
    # Clear API key so the key-check branch is skipped; set ALLOW_UNAUTHENTICATED.
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", True)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)  # disable rate limit
    monkeypatch.setattr(proxy_main.settings, "UPSTREAM_MCP_URL", "http://fake-upstream")

    # Build a ProxyState with a mocked http_client; everything else None-safe
    mock_http = AsyncMock()
    mock_http.post = AsyncMock(
        return_value=_make_upstream_response(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"text": "contact a@b.com for details"},
            }
        )
    )

    state = ProxyState(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoopBreaker(),
        router=MultiUpstreamRouter(default_upstream="http://fake-upstream"),
        http_client=mock_http,
        redis=None,
        clickhouse=None,
        forensic_box=None,
        governance_guards=[],
        alert_channels=[],
        auth_providers=[],
    )
    proxy_main.app.state.proxy = state


# ── Test ─────────────────────────────────────────────────────


class TestMcpResponsePiiRedaction:
    """The /mcp endpoint redacts PII from upstream dict results before responding."""

    def test_email_in_result_dict_is_redacted(self, monkeypatch):
        """End-to-end: upstream returns dict result with email; response has it redacted."""
        _inject_state(monkeypatch)

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

        resp = asyncio.run(go())

        assert resp.status_code == 200
        body = resp.json()
        result_text = json.dumps(body.get("result", body))
        assert "a@b.com" not in result_text, (
            f"PII email must be redacted in /mcp response, got: {body}"
        )
        assert "[EMAIL]" in result_text, f"Expected [EMAIL] placeholder in response, got: {body}"
