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

"""``POST /api/v1/audit``: who wrote a record is set by the proxy.

The record's ``source`` is always ``api_v1_audit`` (a ``source`` sent by the
caller is kept as ``client_source``) and ``submitted_by`` names the
credential the request was admitted with. ``ADMINA_AUDIT_APPEND_KEY`` (or
``_FILE``) is a key accepted by this route only; unset, the route needs the
API key, as every other route.
"""

from __future__ import annotations

import asyncio
import secrets

import httpx
import pytest

pytest.importorskip("fastapi")

from _forensic_chain import load, record_files

from admina.domains.compliance.forensic import ForensicBlackBox

API_KEY = "api-" + secrets.token_hex(16)
APPEND_KEY = "append-" + secrets.token_hex(16)


@pytest.fixture
def proxy(monkeypatch, tmp_path):
    """The real app with a filesystem store; returns (store directory, send)."""
    from _gateway_stream import FakeLoopBreaker, FakePII

    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    class _Clean:
        def check(self, text: str) -> dict:
            return {"is_injection": False, "risk_level": "low"}

    base = tmp_path / "forensic"
    state = ProxyState(
        firewall=_Clean(),
        pii_redactor=FakePII(),
        loop_breaker=FakeLoopBreaker(),
        router=MultiUpstreamRouter(default_upstream="http://mcp.test"),
        forensic_box=ForensicBlackBox(filesystem_dir=str(base)),
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", False)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_AUDIT_APPEND_KEY", APPEND_KEY)

    def send(method: str, url: str, key: str | None = None, **kwargs) -> httpx.Response:
        headers = {"X-API-Key": key} if key else {}

        async def go() -> httpx.Response:
            transport = httpx.ASGITransport(app=proxy_main.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                return await c.request(method, url, headers=headers, **kwargs)

        return asyncio.run(go())

    return base, send


def _audit(send, key, event: dict) -> httpx.Response:
    return send("POST", "/api/v1/audit", key, json={"event": event})


def _last_event(base) -> dict:
    return load(record_files(base)[-1])["event"]


def test_a_source_sent_by_the_caller_is_not_the_record_source(proxy):
    base, send = proxy
    response = _audit(send, API_KEY, {"action": "tool_call", "source": "proxy"})
    assert response.status_code == 200
    assert response.json()["recorded"] is True
    event = _last_event(base)
    assert event["source"] == "api_v1_audit"
    assert event["client_source"] == "proxy"
    assert event["submitted_by"] == "api_key"


def test_the_submitter_cannot_be_set_by_the_caller(proxy):
    base, send = proxy
    _audit(send, APPEND_KEY, {"action": "x", "submitted_by": "api_key"})
    assert _last_event(base)["submitted_by"] == "append_key"


def test_without_a_source_nothing_else_is_added(proxy):
    base, send = proxy
    _audit(send, API_KEY, {"action": "tool_call"})
    event = _last_event(base)
    assert event["source"] == "api_v1_audit"
    assert "client_source" not in event


def test_the_append_key_is_accepted_by_the_audit_route(proxy):
    base, send = proxy
    response = _audit(send, APPEND_KEY, {"action": "tool_call"})
    assert response.status_code == 200
    assert _last_event(base)["submitted_by"] == "append_key"


@pytest.mark.parametrize(
    ("method", "url", "body"),
    [
        ("POST", "/api/v1/validate", {"content": "hello"}),
        ("GET", "/api/v1/forensic/verify", None),
        ("GET", "/api/v1/audit", None),
        ("POST", "/v1/chat/completions", {"model": "m", "messages": []}),
        ("POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ("GET", "/api/stats", None),
    ],
)
def test_the_append_key_is_refused_everywhere_else(proxy, method, url, body):
    _, send = proxy
    kwargs = {"json": body} if body is not None else {}
    assert send(method, url, APPEND_KEY, **kwargs).status_code == 401


def test_the_api_key_still_writes_audit_records(proxy):
    _, send = proxy
    assert _audit(send, API_KEY, {"action": "x"}).status_code == 200


def test_other_keys_are_refused(proxy):
    _, send = proxy
    assert _audit(send, "wrong-" + secrets.token_hex(16), {"action": "x"}).status_code == 401
    assert _audit(send, None, {"action": "x"}).status_code == 401


def test_without_the_setting_the_route_needs_the_api_key(proxy, monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_AUDIT_APPEND_KEY", "")
    _, send = proxy
    assert _audit(send, APPEND_KEY, {"action": "x"}).status_code == 401
    assert _audit(send, None, {"action": "x"}).status_code == 401
    assert _audit(send, API_KEY, {"action": "x"}).status_code == 200


def test_the_append_key_works_without_an_api_key(proxy, monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    _, send = proxy
    assert _audit(send, APPEND_KEY, {"action": "x"}).status_code == 200
    assert send("POST", "/api/v1/validate", APPEND_KEY, json={"content": "x"}).status_code == 401


def test_unauthenticated_local_use_is_recorded_as_such(proxy, monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ADMINA_AUDIT_APPEND_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    base, send = proxy
    assert _audit(send, None, {"action": "x"}).status_code == 200
    assert _last_event(base)["submitted_by"] == "unauthenticated"


def test_the_append_key_can_come_from_a_file(tmp_path, monkeypatch):
    from admina.proxy.config import Settings

    path = tmp_path / "append_key"
    path.write_text(APPEND_KEY + "\n")
    monkeypatch.setenv("ADMINA_AUDIT_APPEND_KEY_FILE", str(path))
    monkeypatch.delenv("ADMINA_AUDIT_APPEND_KEY", raising=False)
    assert Settings(_env_file=None).ADMINA_AUDIT_APPEND_KEY == APPEND_KEY
