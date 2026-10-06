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

"""Request size limits.

``ADMINA_MAX_REQUEST_BYTES`` caps the request body on every route: a body
over the cap gets 413 before it is parsed, whether its length is declared
(``Content-Length``) or not (chunked). ``ADMINA_GATEWAY_MAX_PROMPT_CHARS``
caps the message text of the gateway's chat completions, in characters (no
limit by default); ``MAX_REQUEST_TOKENS`` applies to ``/mcp`` only.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

pytest.importorskip("fastapi")

from starlette.requests import Request

_COMPLETION = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "example-model",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
}

_GATEWAY_BODY = {"model": "example-model", "messages": [{"role": "user", "content": "hello"}]}
_MCP_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "echo", "arguments": {"text": "hello"}},
}
_VALIDATE_BODY = {"content": "hello"}

_OPENAI_TOO_LARGE = {
    "error": {
        "message": "Request body exceeds the size limit.",
        "type": "invalid_request_error",
        "param": None,
        "code": "request_too_large",
    }
}
_DETAIL_TOO_LARGE = {"detail": "Request body too large"}

ROUTES = [
    pytest.param("/v1/chat/completions", _GATEWAY_BODY, _OPENAI_TOO_LARGE, id="gateway"),
    pytest.param("/mcp", _MCP_BODY, _DETAIL_TOO_LARGE, id="mcp"),
    pytest.param("/api/v1/validate", _VALIDATE_BODY, _DETAIL_TOO_LARGE, id="validate"),
]


class _Firewall:
    def __init__(self):
        self.checked = 0

    def check(self, text: str) -> dict:
        self.checked += 1
        return {"is_injection": False, "risk_level": "low", "patterns": []}

    def get_stats(self) -> dict:
        return {}


class _PII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _Loop:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}

    def get_stats(self) -> dict:
        return {}


class _Forensic:
    def __init__(self):
        self.records: list[dict] = []

    def record(self, event: dict) -> dict:
        self.records.append(event)
        return {"sequence_number": len(self.records), "record_hash": "h", "previous_hash": "p"}


class _Upstream:
    """Upstream client of the gateway and of /mcp: records every call."""

    def __init__(self):
        self.calls: list[str] = []

    async def post(self, url, **kw):
        self.calls.append(url)
        if url.endswith("/chat/completions"):
            return httpx.Response(200, json=_COMPLETION)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"text": "ok"}})


class _Proxy:
    """The real proxy app with fake engines, one upstream fake and parser spies."""

    def __init__(
        self,
        monkeypatch,
        *,
        max_bytes: int,
        max_tokens: int = 100000,
        max_prompt_chars: int = 0,
        api_key="",
    ):
        from admina.proxy import main as proxy_main
        from admina.proxy.multi_upstream import MultiUpstreamRouter
        from admina.proxy.state import ProxyState

        settings = proxy_main.settings
        monkeypatch.setattr(settings, "ADMINA_API_KEY", api_key)
        monkeypatch.setattr(settings, "ALLOW_UNAUTHENTICATED", not api_key)
        monkeypatch.setattr(settings, "RATE_LIMIT_MAX_REQUESTS", 0)
        monkeypatch.setattr(settings, "PII_REDACTION_ENABLED", False)
        monkeypatch.setattr(settings, "GOVERNANCE_MODE", "enforce")
        monkeypatch.setattr(settings, "UPSTREAM_MCP_URL", "http://mcp.upstream.test")
        monkeypatch.setattr(settings, "ADMINA_GATEWAY_UPSTREAM", "http://upstream.test/v1")
        monkeypatch.setattr(settings, "ADMINA_MAX_REQUEST_BYTES", max_bytes)
        monkeypatch.setattr(settings, "MAX_REQUEST_TOKENS", max_tokens)
        monkeypatch.setattr(settings, "ADMINA_GATEWAY_MAX_PROMPT_CHARS", max_prompt_chars)

        self.upstream = _Upstream()
        self.firewall = _Firewall()
        self.forensic = _Forensic()
        state = ProxyState(
            firewall=self.firewall,
            pii_redactor=_PII(),
            loop_breaker=_Loop(),
            router=MultiUpstreamRouter(default_upstream="http://mcp.upstream.test"),
            http_client=self.upstream,
            gateway_http_client=self.upstream,
            forensic_box=self.forensic,
            governance_guards=[],
            alert_channels=[],
            auth_providers=[],
        )
        monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
        self.app = proxy_main.app

        # Paths whose body reached the JSON parser (Request.json reads the
        # body, then parses it).
        self.parsed: list[str] = []

        async def json_spy(request: Request):
            body = await request.body()
            self.parsed.append(request.url.path)
            return json.loads(body)

        monkeypatch.setattr(Request, "json", json_spy)

    def post(self, path: str, raw: bytes, *, chunked: bool = False, headers=None):
        async def pieces():
            yield raw[: len(raw) // 2]
            yield raw[len(raw) // 2 :]

        async def go() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app, raise_app_exceptions=False)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.post(
                    path,
                    content=pieces() if chunked else raw,
                    headers={"content-type": "application/json", **(headers or {})},
                )

        return asyncio.run(go())


def _raw(body: dict) -> bytes:
    return json.dumps(body).encode()


# ── Byte cap on every route ───────────────────────────────────


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
@pytest.mark.parametrize(("path", "body", "error"), ROUTES)
def test_body_over_the_cap_gets_413_before_parsing(monkeypatch, path, body, error, chunked):
    raw = _raw(body)
    proxy = _Proxy(monkeypatch, max_bytes=len(raw) - 1)

    resp = proxy.post(path, raw, chunked=chunked)

    assert resp.status_code == 413
    assert resp.json() == error
    assert proxy.parsed == []
    assert proxy.upstream.calls == []
    assert proxy.firewall.checked == 0


@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
@pytest.mark.parametrize(("path", "body", "error"), ROUTES)
def test_body_exactly_at_the_cap_is_accepted(monkeypatch, path, body, error, chunked):
    raw = _raw(body)
    proxy = _Proxy(monkeypatch, max_bytes=len(raw))

    resp = proxy.post(path, raw, chunked=chunked)

    assert resp.status_code == 200
    assert proxy.parsed == [path]


def test_zero_cap_means_no_limit(monkeypatch):
    raw = _raw({"model": "example-model", "messages": [{"role": "user", "content": "x" * 5000}]})
    proxy = _Proxy(monkeypatch, max_bytes=0)

    assert proxy.post("/v1/chat/completions", raw).status_code == 200


def test_cap_is_checked_before_authentication(monkeypatch):
    raw = _raw(_GATEWAY_BODY)
    proxy = _Proxy(monkeypatch, max_bytes=len(raw), api_key="canary-admina-key-0123456789")

    assert proxy.post("/v1/chat/completions", raw + b" ").status_code == 413
    assert proxy.post("/v1/chat/completions", raw).status_code == 401


def test_requests_without_a_body_are_unaffected(monkeypatch):
    proxy = _Proxy(monkeypatch, max_bytes=1)

    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=proxy.app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/health")

    assert asyncio.run(go()).status_code == 200


def test_cap_setting_defaults_to_ten_mebibytes():
    from admina.proxy.config import Settings

    assert Settings().ADMINA_MAX_REQUEST_BYTES == 10 * 1024 * 1024


def test_negative_cap_is_rejected():
    from pydantic import ValidationError

    from admina.proxy.config import Settings

    with pytest.raises(ValidationError):
        Settings(ADMINA_MAX_REQUEST_BYTES=-1)


# ── Message length limit on the gateway ───────────────────────


def _chat(*contents: str) -> bytes:
    return _raw(
        {"model": "example-model", "messages": [{"role": "user", "content": c} for c in contents]}
    )


def test_gateway_rejects_message_text_over_its_limit(monkeypatch):
    proxy = _Proxy(monkeypatch, max_bytes=0, max_prompt_chars=10)

    resp = proxy.post("/v1/chat/completions", _chat("x" * 11))

    assert resp.status_code == 413
    assert resp.json() == {
        "error": {
            "message": "The message text exceeds the length limit.",
            "type": "invalid_request_error",
            "param": None,
            "code": "prompt_too_long",
        }
    }
    assert proxy.upstream.calls == []
    assert proxy.firewall.checked == 0
    assert proxy.forensic.records == []


def test_gateway_counts_the_text_of_every_message(monkeypatch):
    proxy = _Proxy(monkeypatch, max_bytes=0, max_prompt_chars=10)

    # "12345" + "\n" + "12345" = 11 characters.
    assert proxy.post("/v1/chat/completions", _chat("12345", "12345")).status_code == 413


def test_gateway_accepts_message_text_at_its_limit(monkeypatch):
    proxy = _Proxy(monkeypatch, max_bytes=0, max_prompt_chars=10)

    resp = proxy.post("/v1/chat/completions", _chat("x" * 10))

    assert resp.status_code == 200
    assert proxy.upstream.calls == ["http://upstream.test/v1/chat/completions"]


def test_gateway_message_text_is_not_limited_by_max_request_tokens(monkeypatch):
    proxy = _Proxy(monkeypatch, max_bytes=0, max_tokens=10, max_prompt_chars=0)

    assert proxy.post("/v1/chat/completions", _chat("x" * 200_000)).status_code == 200


def test_max_request_tokens_still_applies_to_mcp(monkeypatch):
    proxy = _Proxy(monkeypatch, max_bytes=0, max_tokens=10)
    body = {**_MCP_BODY, "params": {"name": "echo", "arguments": {"text": "x" * 50}}}

    resp = proxy.post("/mcp", _raw(body))

    assert resp.status_code == 413
    assert proxy.upstream.calls == []


def test_the_mcp_token_limit_error_carries_the_event_id(monkeypatch):
    """Like the other JSON-RPC errors of /mcp, in ``error.data.event_id``."""
    proxy = _Proxy(monkeypatch, max_bytes=0, max_tokens=10)
    body = {**_MCP_BODY, "params": {"name": "echo", "arguments": {"text": "x" * 50}}}

    error = proxy.post("/mcp", _raw(body)).json()["error"]

    assert error["code"] == -32000
    assert error["message"] == "Request too large"
    assert isinstance(error["data"]["event_id"], str) and error["data"]["event_id"]
    assert error["data"]["max_tokens"] == 10
    assert error["data"]["content_length"] > 10


def test_gateway_message_length_limit_defaults_to_no_limit():
    from admina.proxy.config import Settings

    assert Settings().ADMINA_GATEWAY_MAX_PROMPT_CHARS == 0


def test_negative_gateway_message_length_limit_is_rejected():
    from pydantic import ValidationError

    from admina.proxy.config import Settings

    with pytest.raises(ValidationError):
        Settings(ADMINA_GATEWAY_MAX_PROMPT_CHARS=-1)
