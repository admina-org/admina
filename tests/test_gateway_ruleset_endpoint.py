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

"""The gateway reports its active firewall ruleset.

``GET /v1/admina/ruleset`` (API key required) and the ``X-Admina-Ruleset``
header on every ``POST /v1/chat/completions`` response carry
``ruleset_sha256()`` of the configuration and engine the proxy started with.
"""

from __future__ import annotations

import asyncio
import json
import re
import textwrap

import httpx
import pytest

pytest.importorskip("fastapi")

from _gateway_stream import (
    MockUpstream,
    chat_body,
    fixture,
    run_lifespan,
    settings,
    through,
)

import admina
from admina.core.config import AdminaConfig, load_config
from admina.domains.agent_security.ruleset import ruleset_sha256
from admina.proxy.gateway_scan import GatewayScanConfig, build_gateway_scan_config
from admina.proxy.gateway_upstreams import GatewayUpstreamError, build_gateway_upstreams

_HEX64 = re.compile(r"[0-9a-f]{64}")
_ACTIVE = "1" * 64
_EXTRA = "2" * 64
_SCAN = GatewayScanConfig(
    ruleset_sha256=_ACTIVE,
    engine="python",
    admina_core_version=None,
    prescan_rulesets=(_EXTRA,),
    prescan_tags=frozenset({"source"}),
)
_COMPLETION = {
    "id": "c1",
    "object": "chat.completion",
    "model": "example-model",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}
    ],
}


def _json_upstream(status: int = 200) -> MockUpstream:
    return MockUpstream(
        [json.dumps(_COMPLETION).encode()], status=status, content_type="application/json"
    )


def _connect_error(request: httpx.Request) -> Exception:
    return httpx.ConnectError("refused", request=request)


# ── X-Admina-Ruleset on every chat completion response ───────

_CASES = {
    "allowed": (_json_upstream(), chat_body(stream=False), {}, {}, 200),
    "allowed-stream": (
        MockUpstream(fixture("plain_content")["chunks"]),
        chat_body("plain_content"),
        {},
        {},
        200,
    ),
    "blocked": (_json_upstream(), chat_body(stream=False, content="INJECT now"), {}, {}, 200),
    "blocked-stream": (_json_upstream(), chat_body(content="INJECT now"), {}, {}, 200),
    "upstream-error": (_json_upstream(status=500), chat_body(stream=False), {}, {}, 500),
    "upstream-unreachable": (
        MockUpstream(error=_connect_error),
        chat_body(stream=False),
        {},
        {},
        502,
    ),
    "unknown-route": (
        _json_upstream(),
        chat_body(stream=False),
        {},
        {"X-Admina-Upstream": "nope"},
        400,
    ),
    "prompt-too-long": (
        _json_upstream(),
        chat_body(stream=False, content="x" * 50),
        {"ADMINA_GATEWAY_MAX_PROMPT_CHARS": 10},
        {},
        413,
    ),
}


@pytest.mark.parametrize("case", list(_CASES))
def test_ruleset_header_on_every_response(case):
    upstream, body, over, headers, status = _CASES[case]
    resp = through(upstream, body, settings(**over), state={"gateway_scan": _SCAN}, headers=headers)
    assert resp.status_code == status
    assert resp.headers["X-Admina-Ruleset"] == _ACTIVE


def test_ruleset_header_on_invalid_json():
    from _gateway_stream import gateway_app

    async def go() -> httpx.Response:
        async with _json_upstream().client() as client:
            app = gateway_app(client, state={"gateway_scan": _SCAN})
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                return await c.post(
                    "/v1/chat/completions",
                    content=b"{not json",
                    headers={"content-type": "application/json"},
                )

    resp = asyncio.run(go())
    assert resp.status_code == 400
    assert resp.json() == {"detail": "Invalid JSON body"}
    assert resp.headers["X-Admina-Ruleset"] == _ACTIVE


def test_header_without_startup_state_is_the_default_ruleset():
    resp = through(_json_upstream(), chat_body(stream=False))
    assert resp.headers["X-Admina-Ruleset"] == ruleset_sha256(AdminaConfig(), engine="python")


# ── GET /v1/admina/ruleset ────────────────────────────────────


def test_endpoint_fields():
    resp = through(
        _json_upstream(), {}, method="GET", path="/v1/admina/ruleset", state={"gateway_scan": _SCAN}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ruleset_sha256"] == _ACTIVE
    assert data["engine"] == "python"
    assert data["admina_core_version"] is None
    assert data["admina_version"] == admina.__version__
    assert data["accepted_prescan_rulesets"] == [_ACTIVE, _EXTRA]
    assert data["prescan_tags"] == ["source"]


def test_endpoint_matches_the_header():
    endpoint = through(_json_upstream(), {}, method="GET", path="/v1/admina/ruleset")
    header = through(_json_upstream(), chat_body(stream=False)).headers["X-Admina-Ruleset"]
    assert endpoint.json()["ruleset_sha256"] == header
    assert _HEX64.fullmatch(header)


def _proxy_app(monkeypatch):
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "canary-key-0123456789")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", False)
    state = ProxyState(
        router=MultiUpstreamRouter(default_upstream="http://upstream"),
        auth_providers=[],
        gateway_scan=_SCAN,
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    return proxy_main.app


def _get(app, headers: dict[str, str] | None = None) -> httpx.Response:
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.get("/v1/admina/ruleset", headers=headers or {})

    return asyncio.run(go())


def test_endpoint_requires_the_api_key(monkeypatch):
    app = _proxy_app(monkeypatch)
    assert _get(app).status_code == 401
    resp = _get(app, {"Authorization": "Bearer canary-key-0123456789"})
    assert resp.status_code == 200
    assert resp.json()["ruleset_sha256"] == _ACTIVE


# ── Resolved at startup ───────────────────────────────────────

_YAML = textwrap.dedent(
    """\
    domains:
      agent_security:
        firewall:
          custom_patterns:
            - regex: "\\\\bexample\\\\s+marker\\\\b"
              category: example_custom
              risk_level: high
    gateway:
      prescan_tags: [source, document]
      prescan_rulesets: ["{extra}"]
    """
)


def test_startup_hashes_the_loaded_configuration(monkeypatch, tmp_path):
    (tmp_path / "admina.yaml").write_text(_YAML.format(extra=_EXTRA.upper()), encoding="utf-8")
    monkeypatch.chdir(tmp_path)  # the firewall reads admina.yaml from the working directory
    config = load_config(tmp_path / "admina.yaml")

    state = run_lifespan(monkeypatch, config)

    scan = state.gateway_scan
    assert scan.engine == "python"  # custom_patterns run on the Python engine
    assert scan.ruleset_sha256 == ruleset_sha256(config, engine="python")
    assert scan.accepted_rulesets == (scan.ruleset_sha256, _EXTRA)
    assert scan.prescan_tags == frozenset({"source", "document"})


def test_startup_uses_the_rust_engine_when_active(monkeypatch, tmp_path):
    pytest.importorskip("admina_core")
    monkeypatch.chdir(tmp_path)  # no admina.yaml
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    state = run_lifespan(monkeypatch, AdminaConfig())
    assert state.gateway_scan.engine == "rust"
    assert state.gateway_scan.ruleset_sha256 == ruleset_sha256(AdminaConfig(), engine="rust")


def test_build_from_a_firewall_without_engine_name():
    class _Firewall:
        def check(self, text: str) -> dict:
            return {"is_injection": False}

    scan = build_gateway_scan_config(_Firewall(), AdminaConfig())
    assert scan.engine == "python"
    assert scan.ruleset_sha256 == ruleset_sha256(AdminaConfig(), engine="python")
    assert scan.accepted_rulesets == (scan.ruleset_sha256,)
    assert scan.prescan_tags == frozenset()


# ── admina.yaml gateway.prescan_* ─────────────────────────────


@pytest.mark.parametrize(
    "section",
    [
        "prescan_rulesets: [abc]",
        "prescan_rulesets: [123]",
        "prescan_rulesets: abc",
        "prescan_tags: ['<source>']",
        "prescan_tags: [1]",
        "prescan_tags: source",
    ],
)
def test_invalid_prescan_settings_stop_the_proxy(tmp_path, section):
    path = tmp_path / "admina.yaml"
    path.write_text(f"gateway:\n  {section}\n", encoding="utf-8")
    config = load_config(path)
    assert config.gateway.errors
    with pytest.raises(GatewayUpstreamError):
        build_gateway_upstreams(settings(), config.gateway)


def test_prescan_settings_default_to_none(tmp_path):
    path = tmp_path / "admina.yaml"
    path.write_text("gateway: {}\n", encoding="utf-8")
    gateway = load_config(path).gateway
    assert gateway.prescan_tags == []
    assert gateway.prescan_rulesets == []
    assert gateway.errors == []
