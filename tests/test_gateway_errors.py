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

"""Upstream errors, timeouts and failures seen through the gateway.

- An upstream error response (4xx/5xx) reaches the client with its status,
  body and content type, streaming or not.
- A timeout before the response starts gets 504, any other transport
  failure 502, both with an OpenAI-style error body.
- A failure during a stream ends it with one ``data: {"error": ...}`` event
  and no ``data: [DONE]``.
- Timeouts and connection pool limits come from the settings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path

import httpx
import pytest

pytest.importorskip("fastapi")

from _gateway_stream import MockUpstream, chat_body, fixture, run_lifespan, settings, through

_TIMEOUT_BODY = {
    "error": {
        "message": "The upstream did not respond in time.",
        "type": "upstream_error",
        "param": None,
        "code": "upstream_timeout",
    }
}
_FAILED_BODY = {
    "error": {
        "message": "The upstream connection failed.",
        "type": "upstream_error",
        "param": None,
        "code": "upstream_error",
    }
}
_INVALID_BODY = {
    "error": {
        "message": "The upstream response could not be read.",
        "type": "upstream_error",
        "param": None,
        "code": "upstream_invalid_response",
    }
}


def _event(body: dict) -> bytes:
    return b"data: " + json.dumps(body, separators=(",", ":")).encode() + b"\n\n"


# ── Upstream error responses ──────────────────────────────────

ERRORS = [
    pytest.param(
        400,
        "application/json",
        b'{"error":{"message":"This model\'s maximum context length is 4096 tokens.",'
        b'"type":"BadRequestError","param":null,"code":400}}',
        id="400-json",
    ),
    pytest.param(
        404,
        "application/json",
        b'{"object":"error","message":"The model `other-model` does not exist.",'
        b'"type":"NotFoundError","param":null,"code":404}',
        id="404-json",
    ),
    pytest.param(
        429,
        "application/json",
        b'{"error": {"message": "Rate limit reached.", "type": "rate_limit_error"}}',
        id="429-json",
    ),
    pytest.param(500, "text/plain; charset=utf-8", b"Internal Server Error", id="500-text"),
    pytest.param(
        502, "text/html", b"<html><body><h1>502 Bad Gateway</h1></body></html>\n", id="502-html"
    ),
    pytest.param(503, None, b"upstream overloaded", id="503-no-content-type"),
]


@pytest.mark.parametrize("redaction", [False, True], ids=["redaction-off", "redaction-on"])
@pytest.mark.parametrize("stream", [False, True], ids=["json", "stream"])
@pytest.mark.parametrize(("status", "content_type", "raw"), ERRORS)
def test_upstream_error_reaches_the_client_unchanged(status, content_type, raw, stream, redaction):
    upstream = MockUpstream([raw], status=status, content_type=content_type)

    resp = through(upstream, chat_body(stream=stream), settings(PII_REDACTION_ENABLED=redaction))

    assert resp.status_code == status
    assert resp.content == raw
    assert resp.headers.get("content-type") == content_type


@pytest.mark.parametrize(("status", "content_type", "raw"), ERRORS)
def test_models_upstream_error_reaches_the_client_unchanged(status, content_type, raw):
    upstream = MockUpstream([raw], status=status, content_type=content_type)

    resp = through(upstream, {}, method="GET", path="/v1/models")

    assert resp.status_code == status
    assert resp.content == raw


def test_models_allowlist_filters_a_json_list():
    raw = b'{"object":"list","data":[{"id":"example-model"},{"id":"other-model"}]}'
    upstream = MockUpstream([raw], content_type="application/json")

    cfg = settings(ADMINA_GATEWAY_MODELS_ALLOWLIST="example-model")
    resp = through(upstream, {}, cfg, method="GET", path="/v1/models")

    assert resp.status_code == 200
    assert [m["id"] for m in resp.json()["data"]] == ["example-model"]


def test_models_allowlist_with_an_unreadable_list_is_502():
    upstream = MockUpstream([b"<html>not json</html>"], content_type="text/html")

    cfg = settings(ADMINA_GATEWAY_MODELS_ALLOWLIST="example-model")
    resp = through(upstream, {}, cfg, method="GET", path="/v1/models")

    assert resp.status_code == 502
    assert resp.json() == _INVALID_BODY


@pytest.mark.parametrize("raw", [b"<html>not json</html>", b"[1, 2]"], ids=["html", "json-array"])
def test_redaction_on_with_an_unreadable_completion_is_502(raw):
    upstream = MockUpstream([raw], content_type="application/json")

    resp = through(upstream, chat_body(stream=False), settings(PII_REDACTION_ENABLED=True))

    assert resp.status_code == 502
    assert resp.json() == _INVALID_BODY


# ── Failures before the response starts ───────────────────────

TIMEOUTS = [httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.WriteTimeout]
TRANSPORT_ERRORS = [httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError]
SECRET = "secret-host.internal:8443"


def _raise(exc_type):
    return lambda request: exc_type(f"failure talking to {SECRET}", request=request)


@pytest.mark.parametrize("stream", [False, True], ids=["json", "stream"])
@pytest.mark.parametrize("exc_type", TIMEOUTS, ids=lambda e: e.__name__)
def test_timeout_before_the_response_is_504(exc_type, stream):
    upstream = MockUpstream(error=_raise(exc_type))

    resp = through(upstream, chat_body(stream=stream))

    assert resp.status_code == 504
    assert resp.json() == _TIMEOUT_BODY
    assert SECRET not in resp.text


@pytest.mark.parametrize("stream", [False, True], ids=["json", "stream"])
@pytest.mark.parametrize("exc_type", TRANSPORT_ERRORS, ids=lambda e: e.__name__)
def test_transport_error_before_the_response_is_502(exc_type, stream):
    upstream = MockUpstream(error=_raise(exc_type))

    resp = through(upstream, chat_body(stream=stream))

    assert resp.status_code == 502
    assert resp.json() == _FAILED_BODY
    assert SECRET not in resp.text


@pytest.mark.parametrize(
    ("exc_type", "status", "body"),
    [(httpx.ReadTimeout, 504, _TIMEOUT_BODY), (httpx.ConnectError, 502, _FAILED_BODY)],
)
def test_models_failure_maps_like_chat(exc_type, status, body):
    upstream = MockUpstream(error=_raise(exc_type))

    resp = through(upstream, {}, method="GET", path="/v1/models")

    assert resp.status_code == status
    assert resp.json() == body


def test_failure_is_logged_with_the_route_and_without_details(caplog):
    upstream = MockUpstream(error=_raise(httpx.ConnectError))

    with caplog.at_level(logging.WARNING, logger="admina.proxy.gateway"):
        through(upstream, chat_body(stream=False))

    messages = [r.getMessage() for r in caplog.records if r.name == "admina.proxy.gateway"]
    assert messages == ["Gateway upstream 'default' failed: ConnectError"]
    assert all(SECRET not in m for m in messages)


@pytest.mark.parametrize("stream", [False, True], ids=["json", "stream"])
def test_total_timeout_before_the_response_is_504(stream):
    upstream = MockUpstream(fixture("plain_content")["chunks"], before_headers=1.0)

    started = time.monotonic()
    resp = through(upstream, chat_body(stream=stream), settings(ADMINA_GATEWAY_TIMEOUT_TOTAL=0.2))

    assert resp.status_code == 504
    assert resp.json() == _TIMEOUT_BODY
    assert time.monotonic() - started < 0.9


# ── Failures during a stream ──────────────────────────────────

_STREAM_TIMEOUT_EVENT = _event(_TIMEOUT_BODY)
_STREAM_FAILED_EVENT = _event(_FAILED_BODY)


def test_total_timeout_during_a_stream_ends_it_with_one_error_event():
    events = fixture("plain_content")["chunks"]
    upstream = MockUpstream(events, delay=1.0)

    started = time.monotonic()
    resp = through(upstream, chat_body(), settings(ADMINA_GATEWAY_TIMEOUT_TOTAL=0.3))

    assert resp.status_code == 200
    assert resp.content == events[0] + _STREAM_TIMEOUT_EVENT
    assert time.monotonic() - started < 0.9
    assert upstream.closed


@pytest.mark.parametrize("redaction", [False, True], ids=["passthrough", "governed"])
@pytest.mark.parametrize(
    ("exc_type", "event"),
    [
        (httpx.ReadTimeout, _STREAM_TIMEOUT_EVENT),
        (httpx.ReadError, _STREAM_FAILED_EVENT),
        (httpx.RemoteProtocolError, _STREAM_FAILED_EVENT),
    ],
    ids=["ReadTimeout", "ReadError", "RemoteProtocolError"],
)
def test_upstream_failure_during_a_stream_ends_it_with_one_error_event(exc_type, event, redaction):
    events = fixture("plain_content")["chunks"][:3]
    upstream = MockUpstream(events, error_after=_raise(exc_type))

    resp = through(upstream, chat_body(), settings(PII_REDACTION_ENABLED=redaction))

    assert resp.status_code == 200
    assert resp.content.endswith(event)
    assert resp.content.count(b'"error"') == 1
    assert b"[DONE]" not in resp.content
    assert SECRET.encode() not in resp.content
    if not redaction:
        assert resp.content == b"".join(events) + event


def test_error_event_follows_a_complete_event():
    """A failure in the middle of an event drops the partial event."""
    events = fixture("plain_content")["chunks"]
    partial = events[1][:20]
    upstream = MockUpstream([events[0], partial], error_after=_raise(httpx.ReadError))

    resp = through(upstream, chat_body())

    assert resp.content == events[0] + _STREAM_FAILED_EVENT


# ── Timeouts and pool from the settings ───────────────────────


def test_default_timeouts_and_pool():
    from admina.proxy.gateway_transport import gateway_limits, gateway_timeout

    cfg = settings()
    assert cfg.ADMINA_GATEWAY_TIMEOUT_CONNECT == 30.0
    assert cfg.ADMINA_GATEWAY_TIMEOUT_READ == 30.0
    assert cfg.ADMINA_GATEWAY_TIMEOUT_TOTAL == 0.0
    assert gateway_timeout(cfg) == httpx.Timeout(30.0)
    assert gateway_limits(cfg) == httpx.Limits(max_connections=100, max_keepalive_connections=20)


def test_timeouts_and_pool_come_from_the_settings():
    from admina.proxy.gateway_transport import build_gateway_http_client

    cfg = settings(
        ADMINA_GATEWAY_TIMEOUT_CONNECT=5,
        ADMINA_GATEWAY_TIMEOUT_READ=600,
        ADMINA_GATEWAY_TIMEOUT_TOTAL=3600,
        ADMINA_GATEWAY_MAX_CONNECTIONS=7,
        ADMINA_GATEWAY_MAX_KEEPALIVE_CONNECTIONS=3,
    )
    client = build_gateway_http_client(cfg)
    try:
        assert client.timeout == httpx.Timeout(connect=5, read=600, write=600, pool=5)
        pool = client._transport._pool
        assert (pool._max_connections, pool._max_keepalive_connections) == (7, 3)
    finally:
        asyncio.run(client.aclose())


def test_zero_timeouts_mean_no_limit():
    from admina.proxy.gateway_transport import gateway_timeout

    cfg = settings(ADMINA_GATEWAY_TIMEOUT_CONNECT=0, ADMINA_GATEWAY_TIMEOUT_READ=0)
    assert gateway_timeout(cfg) == httpx.Timeout(None)


@pytest.mark.parametrize(
    "field",
    [
        "ADMINA_GATEWAY_TIMEOUT_CONNECT",
        "ADMINA_GATEWAY_TIMEOUT_READ",
        "ADMINA_GATEWAY_TIMEOUT_TOTAL",
        "ADMINA_GATEWAY_MAX_KEEPALIVE_CONNECTIONS",
    ],
)
def test_negative_values_are_rejected(field):
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match=field):
        settings(**{field: -1})


def test_pool_needs_at_least_one_connection():
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="ADMINA_GATEWAY_MAX_CONNECTIONS"):
        settings(ADMINA_GATEWAY_MAX_CONNECTIONS=0)


def test_lifespan_builds_the_gateway_client_from_the_settings(monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_TIMEOUT_CONNECT", 5.0)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_TIMEOUT_READ", 600.0)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_MAX_CONNECTIONS", 9)
    state = run_lifespan(monkeypatch, None)

    assert state.gateway_http_client.timeout == httpx.Timeout(
        connect=5, read=600, write=600, pool=5
    )
    assert state.gateway_http_client._transport._pool._max_connections == 9
    assert state.gateway_http_client.is_closed
    # /mcp keeps a client of its own.
    assert state.http_client is not state.gateway_http_client
    assert state.http_client.is_closed


def test_no_fixed_timeout_in_the_gateway_code():
    root = Path(__file__).resolve().parent.parent / "admina" / "proxy"
    literal_timeout = re.compile(r"(?:timeout\s*=|Timeout\()\s*\d")
    for source in (root / "api" / "gateway.py", root / "gateway_transport.py"):
        assert not literal_timeout.search(source.read_text()), source.name
    main = (root / "main.py").read_text()
    assert "state.gateway_http_client = build_gateway_http_client(settings)" in main
