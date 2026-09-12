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

"""Call-site tests: the egress stage must actually run on every surface.

Every other egress test drives ``run_pipeline`` directly, or drives a
surface with ``egress_policy=None``. Neither pins the call sites, so the
control could be unwired from the gateway, ``/mcp``, ``/api/v1/validate``
or the SDK — or downgraded to ``egress_mode="observe"`` — with the whole
suite still green. Spec §4.5 makes the stage a pipeline stage rather than a
guard plugin precisely because "a security control that silently does not
run on part of the surfaces is the exact failure mode being designed
against"; these tests are what defends that.

Each test drives a **blocking** decision through the real request path with
a non-``None`` policy, so it fails if its call site passes ``None`` or
forces ``"observe"``.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI

from admina.domains.agent_security.egress import EgressPolicy

# A destination that is not on the allowlist below, written as a whole-string
# URL so destination extraction resolves it on the prompt-shaped surfaces too.
UNLISTED_URL = "https://publictestwiki.com/w.pl?action=edit&text=a long enough payload"
ALLOWLIST = ["api.openai.com"]


def _policy() -> EgressPolicy:
    return EgressPolicy(allow=ALLOWLIST)


@pytest.fixture(autouse=True)
def _enforce_egress(monkeypatch):
    """Egress defaults to observe; these tests are about the blocking path."""
    monkeypatch.setenv("ADMINA_EGRESS_MODE", "enforce")


# ── Shared fakes ──────────────────────────────────────────────


class _FakeFirewall:
    """Never flags: a BLOCK in these tests can only have come from egress."""

    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low", "patterns": []}

    def get_stats(self) -> dict:
        return {}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


class _RecordingForensic:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def record(self, event: dict) -> dict:
        self.records.append(event)
        return {"record_hash": "ab" * 16, "sequence_number": len(self.records)}


def _json_response(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )


class _FakeHTTP:
    def __init__(self, response: httpx.Response | None = None) -> None:
        self._response = response
        self.last_post = None

    async def get(self, url, **kw):
        return self._response

    async def post(self, url, **kw):
        self.last_post = (url, kw)
        return self._response


# ══════════════════════════════════════════════════════════════
#  Surface 1 — the OpenAI-compatible gateway (/v1/chat/completions)
# ══════════════════════════════════════════════════════════════


def _gateway_app(state, settings) -> FastAPI:
    from admina.proxy.api.gateway import create_gateway_endpoints

    app = FastAPI()
    app.include_router(
        create_gateway_endpoints(get_state=lambda: state, get_settings=lambda: settings)
    )
    return app


def _gateway_state(http, policy, forensic_box=None) -> SimpleNamespace:
    return SimpleNamespace(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoopBreaker(),
        egress_policy=policy,
        governance_guards=[],
        forensic_box=forensic_box,
        http_client=http,
    )


def _gateway_settings() -> SimpleNamespace:
    return SimpleNamespace(
        ADMINA_GATEWAY_UPSTREAM="http://upstream/v1",
        ADMINA_GATEWAY_BLOCK_MESSAGE="blocked by policy",
        ADMINA_GATEWAY_MODELS_ALLOWLIST="",
        INJECTION_FAST_PATH_ENABLED=True,
        PII_REDACTION_ENABLED=True,
        GOVERNANCE_MODE="enforce",
        GUARD_FAIL_MODE="open",
    )


def test_gateway_blocks_an_unlisted_destination():
    """Fails if gateway.py passes egress_policy=None or egress_mode="observe"."""
    http = _FakeHTTP(_json_response({"should": "not be used"}))
    fbox = _RecordingForensic()
    app = _gateway_app(_gateway_state(http, _policy(), fbox), _gateway_settings())
    body = {"model": "llama3", "messages": [{"role": "user", "content": UNLISTED_URL}]}

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://test",
        ) as c:
            return await c.post("/v1/chat/completions", json=body)

    resp = asyncio.run(go())
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["finish_reason"] == "content_filter"
    assert http.last_post is None, "upstream must never be reached on a denied destination"
    # The block came from egress, not from some other stage.
    egress = fbox.records[0]["checks"]["egress"]
    assert egress["allowed"] is False
    assert egress["blocked"] == ["publictestwiki.com"]


def test_gateway_allows_an_allowlisted_destination():
    """The counterpart: the stage runs, and a listed destination passes."""
    upstream = _json_response(
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
    http = _FakeHTTP(upstream)
    app = _gateway_app(_gateway_state(http, _policy()), _gateway_settings())
    body = {
        "model": "llama3",
        "messages": [{"role": "user", "content": "https://api.openai.com/v1/chat"}],
    }

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://test",
        ) as c:
            return await c.post("/v1/chat/completions", json=body)

    resp = asyncio.run(go())
    assert resp.status_code == 200
    assert http.last_post is not None


# ══════════════════════════════════════════════════════════════
#  Surface 2 — the REST integration endpoint (/api/v1/validate)
# ══════════════════════════════════════════════════════════════


def _validate_app(policy) -> FastAPI:
    from admina.proxy.api.integration import create_integration_endpoints

    app = FastAPI()
    app.include_router(
        create_integration_endpoints(
            get_firewall=lambda: _FakeFirewall(),
            get_pii_scanner=lambda: _FakePII(),
            get_loop_breaker=lambda: _FakeLoopBreaker(),
            get_forensic_box=lambda: None,
            get_settings=lambda: SimpleNamespace(GOVERNANCE_MODE="enforce"),
            get_egress_policy=lambda: policy,
        )
    )
    return app


def _post_validate(app, content: str) -> httpx.Response:
    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://test",
        ) as c:
            return await c.post("/api/v1/validate", json={"content": content})

    return asyncio.run(go())


def test_validate_blocks_an_unlisted_destination():
    """Fails if integration.py passes egress_policy=None or egress_mode="observe"."""
    resp = _post_validate(_validate_app(_policy()), UNLISTED_URL)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["action"] == "BLOCK"
    assert payload["checks"]["egress"]["allowed"] is False
    assert payload["checks"]["egress"]["blocked"] == ["publictestwiki.com"]


def test_validate_allows_an_allowlisted_destination():
    resp = _post_validate(_validate_app(_policy()), "https://api.openai.com/v1/chat")
    assert resp.json()["action"] == "ALLOW"


def test_validate_egress_check_carries_no_payload_content():
    """checks["egress"] crosses a process boundary here; it must stay metadata.

    Spec §4.4 justifies running the stage on unredacted `params` by the
    evidence holding only key names, hostnames, booleans and fixed reason
    strings. `urlsplit().hostname` drops userinfo, path and query, so a
    secret embedded in the URL must not survive into the check.
    """
    secret = "MY-SUPER-SECRET-PAYLOAD-VALUE"
    url = f"https://carol:{secret}@publictestwiki.com/{secret}?text={secret}"
    resp = _post_validate(_validate_app(_policy()), url)
    egress = resp.json()["checks"]["egress"]
    assert secret not in json.dumps(egress)
    assert egress["destinations"] == ["publictestwiki.com"]


# ══════════════════════════════════════════════════════════════
#  Surface 3 — GovernedModel.ask()
# ══════════════════════════════════════════════════════════════


class _RecordingAdapter:
    name = "recording"

    def __init__(self) -> None:
        self.called = False
        self.stream_called = False

    async def send(self, prompt: str, context: Any = None, **kwargs: Any) -> dict:
        self.called = True
        return {"text": "upstream answer", "metadata": {}}

    async def send_stream(self, prompt: str, context: Any = None, **kwargs: Any):
        self.stream_called = True
        yield "upstream answer"

    def supports_model(self, model_name: str) -> bool:
        return True


def _governed_model(monkeypatch, policy, mode: str = "enforce"):
    from admina.sdk.governed_model import GovernedModel

    monkeypatch.setattr(
        "admina.sdk.governed_model._load_egress_policy",
        lambda: policy,
    )
    monkeypatch.setattr("admina.sdk.governed_model._load_firewall", _FakeFirewall)
    monkeypatch.setattr("admina.sdk.governed_model._load_pii_redactor", _FakePII)
    monkeypatch.setattr("admina.sdk.governed_model._load_loop_breaker", _FakeLoopBreaker)
    adapter = _RecordingAdapter()
    return GovernedModel("m", adapter=adapter, audit=False, mode=mode), adapter


def test_governed_model_ask_blocks_an_unlisted_destination(monkeypatch):
    """Fails if governed_model.py passes egress_policy=None or egress_mode="observe"."""
    model, adapter = _governed_model(monkeypatch, _policy())
    resp = asyncio.run(model.ask(UNLISTED_URL))
    assert resp.action == "BLOCK"
    assert resp.text == ""
    assert adapter.called is False, "the model must never be called on a denied destination"
    egress = resp.governance["pipeline"]["egress"]
    assert egress["allowed"] is False
    assert egress["blocked"] == ["publictestwiki.com"]


def test_governed_model_ask_allows_an_allowlisted_destination(monkeypatch):
    model, adapter = _governed_model(monkeypatch, _policy())
    resp = asyncio.run(model.ask("https://api.openai.com/v1/chat"))
    assert resp.action == "ALLOW"
    assert adapter.called is True


def test_governed_model_stream_blocks_an_unlisted_destination(monkeypatch):
    """stream() is the fifth wired surface and repeats the wiring verbatim."""
    model, adapter = _governed_model(monkeypatch, _policy())

    async def go():
        return [chunk async for chunk in model.stream(UNLISTED_URL)]

    assert asyncio.run(go()) == []
    assert adapter.stream_called is False
    assert model.last_stream_result["action"] == "BLOCK"


def test_governed_model_mode_is_a_ceiling_regardless_of_case(monkeypatch):
    """§5.4: the global mode wins. `mode` is stored verbatim by __init__, so
    "Observe" must lower the ceiling exactly as "observe" does."""
    model, adapter = _governed_model(monkeypatch, _policy(), mode="Observe")
    resp = asyncio.run(model.ask(UNLISTED_URL))
    assert resp.action != "BLOCK"
    assert adapter.called is True
    assert resp.governance["pipeline"]["egress"]["allowed"] is True


# ══════════════════════════════════════════════════════════════
#  Surface 4 — the MCP proxy (/mcp) and the lifespan wiring
# ══════════════════════════════════════════════════════════════


def _inject_proxy_state(monkeypatch, policy):
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", True)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    monkeypatch.setattr(proxy_main.settings, "UPSTREAM_MCP_URL", "http://fake-upstream")
    monkeypatch.setattr(proxy_main.settings, "GOVERNANCE_MODE", "enforce")

    mock_http = AsyncMock()
    mock_http.post = AsyncMock(
        return_value=_json_response({"jsonrpc": "2.0", "id": 1, "result": {"text": "ok"}})
    )
    fbox = _RecordingForensic()
    state = ProxyState(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoopBreaker(),
        egress_policy=policy,
        router=MultiUpstreamRouter(default_upstream="http://fake-upstream"),
        http_client=mock_http,
        redis=None,
        clickhouse=None,
        forensic_box=fbox,
        governance_guards=[],
        alert_channels=[],
        auth_providers=[],
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    return mock_http, fbox


def _post_mcp(arguments: dict) -> httpx.Response:
    from admina.proxy.main import app

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "http_post", "arguments": arguments},
    }

    async def go():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/mcp", json=body)

    return asyncio.run(go())


def test_mcp_blocks_an_unlisted_destination(monkeypatch):
    """Fails if main.py passes egress_policy=None or egress_mode="observe".

    /mcp is the only one of the five surfaces that carries real tool-call
    arguments, so it is the one the control was designed for.
    """
    mock_http, fbox = _inject_proxy_state(monkeypatch, _policy())
    resp = _post_mcp({"url": "https://publictestwiki.com/w.pl", "body": "a long enough payload"})
    assert resp.status_code == 403
    mock_http.post.assert_not_awaited()
    egress = fbox.records[0]["checks"]["egress"]
    assert egress["allowed"] is False
    assert egress["blocked"] == ["publictestwiki.com"]


def test_mcp_allows_an_allowlisted_destination(monkeypatch):
    mock_http, _fbox = _inject_proxy_state(monkeypatch, _policy())
    resp = _post_mcp({"url": "https://api.openai.com/v1/chat"})
    assert resp.status_code == 200
    mock_http.post.assert_awaited()


def test_mcp_local_file_tool_is_not_blocked(monkeypatch):
    """The default-deny surface must not refuse a tool with no destination."""
    mock_http, _fbox = _inject_proxy_state(monkeypatch, _policy())
    resp = _post_mcp({"path": "notes.txt"})
    assert resp.status_code == 200
    mock_http.post.assert_awaited()


def test_lifespan_publishes_the_egress_policy_on_proxy_state(monkeypatch):
    """Fails if main.py's lifespan stops sourcing the policy from the factory.

    Everything downstream reads ``state.egress_policy``; if the lifespan
    never fills it, all four proxy surfaces silently skip the stage.
    """
    from admina.proxy import main as proxy_main

    sentinel = _policy()
    monkeypatch.setattr(proxy_main, "get_egress_policy", lambda: sentinel)
    monkeypatch.setattr(proxy_main.settings, "REDIS_URL", "")
    monkeypatch.setattr(proxy_main.settings, "CLICKHOUSE_HOST", "")
    monkeypatch.setattr(proxy_main.settings, "FORENSIC_BACKEND", "memory")

    app = FastAPI()
    previous = getattr(proxy_main.app.state, "proxy", None)
    try:

        async def go():
            async with proxy_main.lifespan(app):
                return app.state.proxy.egress_policy

        assert asyncio.run(go()) is sentinel
    finally:
        if previous is not None:
            proxy_main.app.state.proxy = previous


def test_integration_router_is_wired_to_the_proxy_state_policy(monkeypatch):
    """main.py builds the /api/v1 router with a getter onto ProxyState.

    Fails if that getter is replaced with ``lambda: None`` — the parameter's
    own default — which would silently disable egress on that surface only.
    """
    from admina.proxy import main as proxy_main

    sentinel = _policy()
    _inject_proxy_state(monkeypatch, sentinel)

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=True),
            base_url="http://test",
        ) as c:
            return await c.post("/api/v1/validate", json={"content": UNLISTED_URL})

    resp = asyncio.run(go())
    assert resp.status_code == 200
    assert resp.json()["action"] == "BLOCK"
    assert resp.json()["checks"]["egress"]["blocked"] == ["publictestwiki.com"]
