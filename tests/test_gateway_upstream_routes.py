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

"""Named upstream routes of the OpenAI-compatible gateway.

Routes come from ``ADMINA_GATEWAY_UPSTREAMS`` or ``gateway.upstreams`` in
``admina.yaml``; a request picks one with ``X-Admina-Upstream``. The
upstream is an ``httpx.MockTransport`` that records every request.
"""

from __future__ import annotations

import asyncio
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI

from admina.core.config import load_config
from admina.proxy.api.gateway import create_gateway_endpoints
from admina.proxy.config import Settings
from admina.proxy.gateway_upstreams import (
    GatewayUpstreamError,
    GatewayUpstreams,
    build_gateway_upstreams,
)

MAIN_URL = "http://main.upstream.test/v1"
UTIL_URL = "http://util.upstream.test/v1"
TWO_ROUTES = f"main={MAIN_URL},util={UTIL_URL}"


@pytest.fixture(autouse=True)
def _no_gateway_env(monkeypatch):
    """Gateway settings come only from what each test sets."""
    import os

    for name in list(os.environ):
        if name.startswith("ADMINA_GATEWAY_"):
            monkeypatch.delenv(name)


# ── Fakes ─────────────────────────────────────────────────────


class _RecordingFirewall:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def check(self, text: str) -> dict:
        self.calls.append(text)
        return {"is_injection": False, "risk_level": "low", "patterns": []}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


class _RecordingForensic:
    def __init__(self) -> None:
        self.records: list[dict] = []

    def record(self, event: dict) -> dict:
        self.records.append(event)
        return {"sequence_number": len(self.records), "record_hash": "h", "previous_hash": "p"}


_COMPLETION = {
    "id": "cmpl-1",
    "object": "chat.completion",
    "model": "m1",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
}
_SSE = (
    'data: {"id":"c1","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":null}]}\n\n'
    'data: {"id":"c1","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
    "data: [DONE]\n\n"
)


class _Upstream:
    """Records every request the gateway sends upstream."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"object": "list", "data": [{"id": "m1"}]})
        if json.loads(request.content).get("stream"):
            return httpx.Response(
                200, content=_SSE.encode(), headers={"content-type": "text/event-stream"}
            )
        return httpx.Response(200, json=_COMPLETION)


def _call(
    upstreams: GatewayUpstreams | None,
    *,
    method: str = "POST",
    path: str = "/v1/chat/completions",
    headers: dict | None = None,
    body: dict | None = None,
    firewall: _RecordingFirewall | None = None,
    forensic_box: _RecordingForensic | None = None,
    settings: Settings | None = None,
) -> tuple[httpx.Response, list[httpx.Request]]:
    upstream = _Upstream()
    cfg = settings or Settings()
    if method == "POST" and body is None:
        body = {"model": "m1", "messages": [{"role": "user", "content": "hello"}]}

    async def go() -> httpx.Response:
        async with httpx.AsyncClient(transport=httpx.MockTransport(upstream.handler)) as http:
            state = SimpleNamespace(
                firewall=firewall or _RecordingFirewall(),
                pii_redactor=_FakePII(),
                loop_breaker=_FakeLoopBreaker(),
                egress_policy=None,
                governance_guards=[],
                forensic_box=forensic_box,
                gateway_http_client=http,
                gateway_upstreams=upstreams,
            )
            app = FastAPI()
            app.include_router(
                create_gateway_endpoints(get_state=lambda: state, get_settings=lambda: cfg)
            )
            transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
                return await c.request(method, path, headers=headers or {}, json=body)

    resp = asyncio.run(go())
    return resp, upstream.requests


def _yaml_config(tmp_path, text: str):
    path = tmp_path / "admina.yaml"
    path.write_text(textwrap.dedent(text))
    return load_config(path)


_TWO_ROUTES_YAML = f"""\
    gateway:
      upstreams:
        main: {{ url: "{MAIN_URL}" }}
        util: {{ url: "{UTIL_URL}" }}
      default_upstream: main
    """


# ── Default route only (ADMINA_GATEWAY_UPSTREAM) ──────────────


def test_single_upstream_is_the_default_route(monkeypatch):
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAM", "http://upstream.test/v1")
    upstreams = build_gateway_upstreams(Settings(), None, environ={})

    assert upstreams.names() == ["default"]
    assert upstreams.default == "default"
    resp, sent = _call(upstreams)
    assert resp.status_code == 200
    assert [str(r.url) for r in sent] == ["http://upstream.test/v1/chat/completions"]
    assert "authorization" not in sent[0].headers


def test_single_upstream_default_value_is_unchanged():
    upstreams = build_gateway_upstreams(Settings(), None, environ={})
    assert upstreams.select("").url == "http://localhost:11434/v1"


def test_router_without_resolved_routes_uses_the_single_upstream():
    """A router mounted outside the proxy lifespan keeps the single upstream."""
    resp, sent = _call(None, settings=Settings(ADMINA_GATEWAY_UPSTREAM="http://upstream.test/v1"))
    assert resp.status_code == 200
    assert str(sent[0].url) == "http://upstream.test/v1/chat/completions"
    assert "authorization" not in sent[0].headers


def test_single_upstream_accepts_its_own_name_in_the_header():
    upstreams = build_gateway_upstreams(
        Settings(ADMINA_GATEWAY_UPSTREAM="http://upstream.test/v1"), None, environ={}
    )
    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "default"})
    assert resp.status_code == 200
    assert str(sent[0].url) == "http://upstream.test/v1/chat/completions"


# ── Routes from ADMINA_GATEWAY_UPSTREAMS ──────────────────────


def test_env_routes_select_by_header(monkeypatch):
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAMS", TWO_ROUTES)
    upstreams = build_gateway_upstreams(Settings(), None, environ={})
    assert upstreams.names() == ["main", "util"]

    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "util"})
    assert resp.status_code == 200
    assert str(sent[0].url) == f"{UTIL_URL}/chat/completions"

    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "main"})
    assert str(sent[0].url) == f"{MAIN_URL}/chat/completions"


def test_env_routes_without_header_use_the_first_route(monkeypatch):
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAMS", TWO_ROUTES)
    upstreams = build_gateway_upstreams(Settings(), None, environ={})
    assert upstreams.default == "main"

    resp, sent = _call(upstreams)
    assert resp.status_code == 200
    assert str(sent[0].url) == f"{MAIN_URL}/chat/completions"


def test_env_routes_without_header_use_default_upstream(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAMS", TWO_ROUTES)
    config = _yaml_config(tmp_path, "gateway:\n  default_upstream: util\n")
    upstreams = build_gateway_upstreams(Settings(), config.gateway, environ={})
    assert upstreams.default == "util"

    resp, sent = _call(upstreams)
    assert str(sent[0].url) == f"{UTIL_URL}/chat/completions"


def test_env_routes_stream_to_the_selected_route(monkeypatch):
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAMS", TWO_ROUTES)
    upstreams = build_gateway_upstreams(Settings(), None, environ={})
    body = {"model": "m1", "stream": True, "messages": [{"role": "user", "content": "hi"}]}

    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "util"}, body=body)
    assert resp.status_code == 200
    assert resp.text.rstrip().endswith("data: [DONE]")
    assert str(sent[0].url) == f"{UTIL_URL}/chat/completions"


def test_header_value_is_trimmed():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "  util "})
    assert resp.status_code == 200
    assert str(sent[0].url) == f"{UTIL_URL}/chat/completions"


def test_empty_header_uses_the_default_route():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": ""})
    assert resp.status_code == 200
    assert str(sent[0].url) == f"{MAIN_URL}/chat/completions"


def test_env_routes_accept_trailing_slash_and_empty_items():
    upstreams = build_gateway_upstreams(
        Settings(ADMINA_GATEWAY_UPSTREAMS=f" main = {MAIN_URL}/ , , util={UTIL_URL},"), None, {}
    )
    assert upstreams.names() == ["main", "util"]
    assert upstreams.select("main").url == MAIN_URL


@pytest.mark.parametrize(
    "value, message",
    [
        ("main", "entry 1 is not name=url"),
        ("main=http://a.test/v1,util", "entry 2 is not name=url"),
        ("=http://a.test/v1", "route name"),
        ("Main=http://a.test/v1", "route name"),
        ("ma-in=http://a.test/v1", "route name"),
        ("main=", "route 'main'"),
        ("main=ftp://a.test/v1", "route 'main'"),
        ("main=a.test/v1", "route 'main'"),
        ("main=http://a.test/v1,main=http://b.test/v1", "route 'main' is defined twice"),
    ],
)
def test_malformed_env_routes_are_rejected(value, message):
    with pytest.raises(GatewayUpstreamError, match=message):
        build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=value), None, {})


def test_route_names_up_to_64_characters_are_accepted():
    name = "r" * 64
    upstreams = build_gateway_upstreams(
        Settings(ADMINA_GATEWAY_UPSTREAMS=f"{name}=http://a.test/v1"), None, {}
    )
    assert upstreams.names() == [name]
    with pytest.raises(GatewayUpstreamError, match="route name"):
        build_gateway_upstreams(
            Settings(ADMINA_GATEWAY_UPSTREAMS=f"{name}r=http://a.test/v1"), None, {}
        )


# ── Routes from admina.yaml (gateway.upstreams) ───────────────


def test_yaml_routes_select_by_header(tmp_path):
    config = _yaml_config(tmp_path, _TWO_ROUTES_YAML)
    upstreams = build_gateway_upstreams(Settings(), config.gateway, environ={})
    assert upstreams.names() == ["main", "util"]
    assert upstreams.default == "main"

    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "util"})
    assert resp.status_code == 200
    assert str(sent[0].url) == f"{UTIL_URL}/chat/completions"

    resp, sent = _call(upstreams)
    assert str(sent[0].url) == f"{MAIN_URL}/chat/completions"


def test_yaml_default_upstream_selects_the_default_route(tmp_path):
    config = _yaml_config(
        tmp_path, _TWO_ROUTES_YAML.replace("default_upstream: main", "default_upstream: util")
    )
    upstreams = build_gateway_upstreams(Settings(), config.gateway, environ={})

    resp, sent = _call(upstreams)
    assert str(sent[0].url) == f"{UTIL_URL}/chat/completions"


def test_yaml_routes_parse_into_the_config(tmp_path):
    config = _yaml_config(
        tmp_path,
        f"""\
        gateway:
          upstreams:
            main: {{ url: "{MAIN_URL}", api_key_file: /run/secrets/upstream_api_key }}
          default_upstream: main
        """,
    )
    assert config.gateway.default_upstream == "main"
    assert config.gateway.upstreams["main"].url == MAIN_URL
    assert config.gateway.upstreams["main"].api_key_file == "/run/secrets/upstream_api_key"
    assert config.gateway.errors == []


def test_config_without_gateway_section_has_no_routes(tmp_path):
    config = _yaml_config(tmp_path, "schema_version: 1\n")
    assert config.gateway.upstreams == {}
    assert config.gateway.default_upstream == ""
    upstreams = build_gateway_upstreams(Settings(), config.gateway, environ={})
    assert upstreams.names() == ["default"]


def test_example_config_keeps_the_single_upstream(tmp_path):
    """admina.yaml.example works as shipped; its commented routes parse."""
    example = (Path(__file__).resolve().parent.parent / "admina.yaml.example").read_text()
    config = _yaml_config(tmp_path, example)
    assert build_gateway_upstreams(Settings(), config.gateway, environ={}).names() == ["default"]

    uncommented = example
    for commented, active in (
        ("  upstreams: {}\n  # upstreams:\n", "  upstreams:\n"),
        ("  #   main:", "    main:"),
        ("  #   util:", "    util:"),
        ("  # default_upstream:", "  default_upstream:"),
    ):
        assert commented in uncommented
        uncommented = uncommented.replace(commented, active)
    gateway = _yaml_config(tmp_path, uncommented).gateway
    assert gateway.errors == []
    assert list(gateway.upstreams) == ["main", "util"]
    assert gateway.upstreams["util"].url == "http://util.upstream.test/v1"
    assert gateway.upstreams["util"].api_key_file == "/run/secrets/upstream_api_key"
    assert gateway.default_upstream == "main"


def test_env_routes_override_yaml_routes(monkeypatch, tmp_path):
    config = _yaml_config(tmp_path, _TWO_ROUTES_YAML)
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAMS", "main=http://other.upstream.test/v1")
    upstreams = build_gateway_upstreams(Settings(), config.gateway, environ={})
    assert upstreams.names() == ["main"]

    resp, sent = _call(upstreams)
    assert str(sent[0].url) == "http://other.upstream.test/v1/chat/completions"

    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "util"})
    assert resp.status_code == 400
    assert sent == []


@pytest.mark.parametrize(
    "text, message",
    [
        ("gateway: [main]\n", "gateway must be a mapping"),
        ("gateway:\n  upstreams: [main]\n", "gateway.upstreams must be a mapping"),
        ("gateway:\n  upstreams:\n    main: http://a.test/v1\n", "gateway.upstreams.main"),
        ("gateway:\n  upstreams:\n    main: {api_key_file: /k}\n", "gateway.upstreams.main.url"),
        (
            "gateway:\n  upstreams:\n    main: {url: 'http://a.test/v1', api_key_file: 3}\n",
            "gateway.upstreams.main.api_key_file",
        ),
        ("gateway:\n  default_upstream: [main]\n", "gateway.default_upstream"),
        ("gateway:\n  upstreams:\n    Main: {url: 'http://a.test/v1'}\n", "route name"),
        ("gateway:\n  upstreams:\n    main: {url: 'a.test/v1'}\n", "route 'main'"),
    ],
)
def test_malformed_yaml_routes_are_rejected(tmp_path, text, message):
    config = _yaml_config(tmp_path, text)  # loading never fails: other readers are unaffected
    with pytest.raises(GatewayUpstreamError, match=message):
        build_gateway_upstreams(Settings(), config.gateway, environ={})


# ── default_upstream must name a route ────────────────────────


def test_default_upstream_naming_a_missing_route_is_an_error(tmp_path):
    config = _yaml_config(
        tmp_path, _TWO_ROUTES_YAML.replace("default_upstream: main", "default_upstream: other")
    )
    with pytest.raises(GatewayUpstreamError, match="default_upstream"):
        build_gateway_upstreams(Settings(), config.gateway, environ={})


def test_default_upstream_must_name_an_env_route(monkeypatch, tmp_path):
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAMS", "main=http://a.test/v1")
    config = _yaml_config(tmp_path, "gateway:\n  default_upstream: util\n")
    with pytest.raises(GatewayUpstreamError, match="default_upstream"):
        build_gateway_upstreams(Settings(), config.gateway, environ={})


def test_default_upstream_without_named_routes_is_an_error(tmp_path):
    config = _yaml_config(tmp_path, "gateway:\n  default_upstream: main\n")
    with pytest.raises(GatewayUpstreamError, match="default_upstream"):
        build_gateway_upstreams(Settings(), config.gateway, environ={})


class _NoOTEL:
    """Stands in for the OTEL exporter: nothing is exported from tests."""

    enabled = False

    def __init__(self, **_kw) -> None:
        pass


def _isolate_lifespan(monkeypatch) -> None:
    """No Redis, ClickHouse, forensic files or OTEL export; the lifespan's
    event-bus subscriptions go to a bus of their own."""
    from admina.core.event_bus import EventBus
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "REDIS_URL", "")
    monkeypatch.setattr(proxy_main.settings, "CLICKHOUSE_HOST", "")
    monkeypatch.setattr(proxy_main.settings, "FORENSIC_BACKEND", "memory")
    monkeypatch.setattr(proxy_main, "OTELGovernanceExporter", _NoOTEL)
    monkeypatch.setattr(proxy_main, "governance_bus", EventBus())


def _lifespan(monkeypatch, config=None):
    """Run the proxy lifespan; return the ProxyState it publishes."""
    from admina.proxy import main as proxy_main

    _isolate_lifespan(monkeypatch)
    monkeypatch.setattr(proxy_main, "_admina_config", config)
    app = FastAPI()

    async def go():
        async with proxy_main.lifespan(app):
            return app.state.proxy

    return asyncio.run(go())


def test_proxy_does_not_start_when_default_upstream_names_no_route(monkeypatch, tmp_path):
    config = _yaml_config(
        tmp_path, _TWO_ROUTES_YAML.replace("default_upstream: main", "default_upstream: other")
    )
    with pytest.raises(GatewayUpstreamError, match="default_upstream"):
        _lifespan(monkeypatch, config)


def test_proxy_resolves_routes_at_startup(monkeypatch, tmp_path):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_UPSTREAMS", "")
    state = _lifespan(monkeypatch, _yaml_config(tmp_path, _TWO_ROUTES_YAML))
    assert state.gateway_upstreams.names() == ["main", "util"]
    assert state.gateway_upstreams.default == "main"


# ── Unknown route → 400 ───────────────────────────────────────


def _assert_openai_invalid_request(resp: httpx.Response) -> None:
    assert resp.status_code == 400
    error = resp.json()["error"]
    assert error["type"] == "invalid_request_error"
    assert error["code"] == "unknown_upstream"
    assert "X-Admina-Upstream" in error["message"]


@pytest.mark.parametrize("stream", [False, True])
def test_unknown_route_is_rejected_before_governance(stream):
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    firewall = _RecordingFirewall()
    fbox = _RecordingForensic()
    body = {"model": "m1", "stream": stream, "messages": [{"role": "user", "content": "hi"}]}

    resp, sent = _call(
        upstreams,
        headers={"X-Admina-Upstream": "other"},
        body=body,
        firewall=firewall,
        forensic_box=fbox,
    )

    _assert_openai_invalid_request(resp)
    assert sent == []  # upstream never called
    assert firewall.calls == []  # no governance scan
    assert fbox.records == []  # no forensic record


def test_unknown_route_is_rejected_in_single_upstream_mode():
    upstreams = build_gateway_upstreams(Settings(), None, environ={})
    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "main"})
    _assert_openai_invalid_request(resp)
    assert sent == []


def test_overlong_header_value_is_an_unknown_route():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "main" + " " * 200 + "x"})
    _assert_openai_invalid_request(resp)
    assert sent == []


def test_route_names_are_case_sensitive():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    resp, sent = _call(upstreams, headers={"X-Admina-Upstream": "MAIN"})
    _assert_openai_invalid_request(resp)
    assert sent == []


def test_select_strips_cr_lf_and_bounds_the_value():
    from admina.proxy.api.gateway import _requested_route

    assert _requested_route("ut\r\nil") == "util"
    assert _requested_route(" main ") == "main"
    assert len(_requested_route("x" * 500)) == 128


# ── GET /v1/models honours the route ──────────────────────────


def test_models_uses_the_selected_route():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})

    resp, sent = _call(
        upstreams, method="GET", path="/v1/models", headers={"X-Admina-Upstream": "util"}
    )
    assert resp.status_code == 200
    assert [str(r.url) for r in sent] == [f"{UTIL_URL}/models"]

    resp, sent = _call(upstreams, method="GET", path="/v1/models")
    assert [str(r.url) for r in sent] == [f"{MAIN_URL}/models"]


def test_models_allowlist_still_applies_on_a_route():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    resp, _sent = _call(
        upstreams,
        method="GET",
        path="/v1/models",
        headers={"X-Admina-Upstream": "util"},
        settings=Settings(ADMINA_GATEWAY_MODELS_ALLOWLIST="other"),
    )
    assert resp.json()["data"] == []


def test_models_rejects_an_unknown_route():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    resp, sent = _call(
        upstreams, method="GET", path="/v1/models", headers={"X-Admina-Upstream": "other"}
    )
    _assert_openai_invalid_request(resp)
    assert sent == []


# ── Forensic record carries the route name ────────────────────


def test_forensic_record_names_the_route():
    upstreams = build_gateway_upstreams(Settings(ADMINA_GATEWAY_UPSTREAMS=TWO_ROUTES), None, {})
    fbox = _RecordingForensic()

    _call(upstreams, headers={"X-Admina-Upstream": "util"}, forensic_box=fbox)
    _call(upstreams, forensic_box=fbox)

    assert [r["upstream"] for r in fbox.records] == ["util", "main"]
    assert UTIL_URL not in json.dumps(fbox.records, default=str)
