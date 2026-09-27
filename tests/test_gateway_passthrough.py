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

"""Passthrough of upstream responses by the OpenAI-compatible gateway.

With ``ADMINA_GATEWAY_STREAM_MODE=passthrough`` and no response
transformation (PII redaction off), a streamed chat completion reaches the
client with exactly the bytes a direct call to the upstream returns, each
SSE event as soon as it is complete. A non-streaming response body is
forwarded unchanged whatever the stream mode.
"""

from __future__ import annotations

import asyncio
import gzip
import json

import pytest

pytest.importorskip("fastapi")

from _gateway_stream import (
    EMAIL,
    FIXTURES,
    MockUpstream,
    asgi_post,
    chat_body,
    direct,
    fixture,
    fixture_bytes,
    gateway_app,
    run_lifespan,
    settings,
    split_every,
    through,
)

# ── Byte-for-byte streams ─────────────────────────────────────


def test_every_fixture_kind_is_present():
    assert FIXTURES == [
        "crlf",
        "keepalive_comments",
        "logprobs",
        "n2_interleaved",
        "plain_content",
        "reasoning_content",
        "tool_calls",
        "usage",
    ]


@pytest.mark.parametrize("split", ["as-served", "7-byte-pieces"])
@pytest.mark.parametrize("name", FIXTURES)
def test_stream_bytes_equal_a_direct_call(name, split):
    pieces = fixture(name)["chunks"]
    if split == "7-byte-pieces":
        pieces = split_every(fixture_bytes(name), 7)
    upstream = MockUpstream(pieces)
    body = chat_body(name)

    expected = direct(upstream, body)
    resp = through(upstream, body)

    assert resp.status_code == expected.status_code == 200
    assert resp.content == expected.content == fixture_bytes(name)
    assert resp.headers["content-type"] == expected.headers["content-type"]
    # The request went upstream as a stream, with the caller's options.
    sent = upstream.requests[-1]
    assert str(sent.url) == "http://upstream.test/v1/chat/completions"
    assert json.loads(sent.content) == {**body, "stream": True}


def test_stream_keeps_the_upstream_content_type():
    upstream = MockUpstream(
        fixture("plain_content")["chunks"], content_type="text/event-stream; charset=utf-8"
    )

    resp = through(upstream, chat_body("plain_content"))

    assert resp.headers["content-type"] == "text/event-stream; charset=utf-8"


def test_stream_without_done_is_not_completed_by_the_gateway():
    pieces = fixture("plain_content")["chunks"][:-1]  # no data: [DONE]
    upstream = MockUpstream(pieces)

    resp = through(upstream, chat_body("plain_content"))

    assert resp.content == b"".join(pieces)
    assert b"[DONE]" not in resp.content


def test_stream_mode_governed_parses_the_stream():
    upstream = MockUpstream(fixture("crlf")["chunks"])

    resp = through(upstream, chat_body("crlf"), stream_mode="governed")

    assert resp.status_code == 200
    assert resp.content != fixture_bytes("crlf")
    assert b"\r\n" not in resp.content
    assert b"Line one." in resp.content and b" Line two." in resp.content


def test_redaction_on_uses_the_governed_path_in_passthrough_mode():
    pieces = [
        b'data: {"choices":[{"index":0,"delta":{"content":"mail ' + EMAIL.encode() + b'"},'
        b'"finish_reason":null}]}\n\n',
        b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
        b"data: [DONE]\n\n",
    ]
    upstream = MockUpstream(pieces)

    resp = through(upstream, chat_body(), settings(PII_REDACTION_ENABLED=True))

    assert EMAIL.encode() not in resp.content
    assert b"[EMAIL]" in resp.content


@pytest.mark.parametrize("stream", [True, False], ids=["stream", "json"])
def test_compressed_upstream_body_reaches_the_client_decoded(stream):
    raw = fixture_bytes("plain_content")
    upstream = MockUpstream([gzip.compress(raw)], headers={"content-encoding": "gzip"})
    body = chat_body("plain_content", stream=stream)

    expected = direct(upstream, body)
    resp = through(upstream, body)

    assert resp.content == expected.content == raw
    assert "content-encoding" not in resp.headers


# ── Non-streaming bodies ──────────────────────────────────────

_RAW_COMPLETION = (
    b'{\n  "id": "chatcmpl-0004",\n  "object": "chat.completion",\n  "created": 1767225603,\n'
    b'  "model": "example-model",\n  "choices": [{"index": 0, "message": {"role": "assistant",'
    b' "content": "Caf\\u00e9 or caf\xc3\xa9?", "reasoning_content": "Both spellings."},'
    b' "logprobs": null, "finish_reason": "stop"}],\n'
    b'  "usage": {"prompt_tokens": 5, "completion_tokens": 4, "total_tokens": 9}\n}\n'
)


@pytest.mark.parametrize("stream_mode", ["passthrough", "governed"])
def test_json_body_bytes_equal_a_direct_call(stream_mode):
    upstream = MockUpstream([_RAW_COMPLETION], content_type="application/json")
    body = chat_body(stream=False)

    expected = direct(upstream, body)
    resp = through(upstream, body, stream_mode=stream_mode)

    assert resp.status_code == expected.status_code == 200
    assert resp.content == expected.content == _RAW_COMPLETION
    assert resp.headers["content-type"] == "application/json"


def test_models_list_bytes_equal_a_direct_call():
    raw = b'{"object": "list", "data": [{"id": "example-model", "object": "model"}]}\n'
    upstream = MockUpstream([raw], content_type="application/json")

    resp = through(upstream, {}, method="GET", path="/v1/models")

    assert resp.status_code == 200
    assert resp.content == raw


# ── Flush per event ───────────────────────────────────────────


def test_each_event_reaches_the_client_before_the_next_is_produced():
    events = fixture("plain_content")["chunks"][1:4]
    upstream = MockUpstream(events, delay=0.2)
    sent: list[tuple[int, bytes]] = []

    async def on_message(message: dict) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            sent.append((upstream.produced, message["body"]))

    async def go() -> None:
        async with upstream.client() as client:
            app = gateway_app(client)
            await asgi_post(app, chat_body("plain_content"), on_message, asyncio.Event())

    asyncio.run(go())

    # Each event left the gateway while the upstream had produced only it.
    assert sent == [(1, events[0]), (2, events[1]), (3, events[2])]


def test_events_split_across_reads_are_sent_whole():
    events = fixture("plain_content")["chunks"][1:4]
    upstream = MockUpstream(split_every(b"".join(events), 5))
    sent: list[bytes] = []

    async def on_message(message: dict) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            sent.append(message["body"])

    async def go() -> None:
        async with upstream.client() as client:
            await asgi_post(gateway_app(client), chat_body(), on_message, asyncio.Event())

    asyncio.run(go())

    assert sent == events


# ── Client disconnect ─────────────────────────────────────────


def _proxy_app(monkeypatch, client):
    """The real proxy app (auth and body-limit middleware included)."""
    from _gateway_stream import UPSTREAM, FakeFirewall, FakeLoopBreaker, FakePII

    from admina.proxy import main as proxy_main
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", False)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_UPSTREAM", UPSTREAM)
    state = ProxyState(
        firewall=FakeFirewall(),
        pii_redactor=FakePII(),
        loop_breaker=FakeLoopBreaker(),
        forensic_box=None,
        governance_guards=[],
        auth_providers=[],
        gateway_http_client=client,
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    return proxy_main.app


@pytest.mark.parametrize("stream_mode", ["passthrough", "governed"])
@pytest.mark.parametrize("app_kind", ["router", "proxy"])
def test_client_disconnect_cancels_the_upstream_stream(monkeypatch, app_kind, stream_mode):
    events = fixture("plain_content")["chunks"][1:3] * 20
    upstream = MockUpstream(events, delay=0.05)
    disconnect = asyncio.Event()

    async def on_message(message: dict) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            disconnect.set()

    async def go() -> None:
        async with upstream.client() as client:
            if app_kind == "router":
                app = gateway_app(client, stream_mode=stream_mode)
            else:
                app = _proxy_app(monkeypatch, client)
                app.state.proxy.gateway_stream_mode = stream_mode
            await asyncio.wait_for(asgi_post(app, chat_body(), on_message, disconnect), 2.0)

    asyncio.run(go())

    assert upstream.closed
    assert upstream.stopped_by == "CancelledError"
    assert upstream.produced < len(events)


# ── Stream mode setting ───────────────────────────────────────


def test_stream_mode_defaults_to_passthrough():
    from admina.proxy.gateway_transport import resolve_stream_mode

    assert settings().ADMINA_GATEWAY_STREAM_MODE == ""
    assert resolve_stream_mode(settings()) == "passthrough"


@pytest.mark.parametrize(
    ("env", "yaml_mode", "expected"),
    [
        ("", "", "passthrough"),
        ("", "governed", "governed"),
        ("governed", "", "governed"),
        ("passthrough", "governed", "passthrough"),
        (" Governed ", "", "governed"),
    ],
)
def test_stream_mode_env_then_yaml_then_default(env, yaml_mode, expected):
    from admina.core.config import GatewayConfig
    from admina.proxy.gateway_transport import resolve_stream_mode

    cfg = settings(ADMINA_GATEWAY_STREAM_MODE=env)
    assert resolve_stream_mode(cfg, GatewayConfig(stream_mode=yaml_mode)) == expected


def test_stream_mode_setting_rejects_unknown_values():
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="ADMINA_GATEWAY_STREAM_MODE"):
        settings(ADMINA_GATEWAY_STREAM_MODE="raw")


@pytest.mark.parametrize(
    ("value", "stream_mode", "errors"),
    [
        ("passthrough", "passthrough", []),
        ("Governed", "governed", []),
        ("raw", "", ["gateway.stream_mode must be one of: passthrough | governed"]),
        (3, "", ["gateway.stream_mode must be one of: passthrough | governed"]),
    ],
)
def test_yaml_stream_mode_is_parsed(tmp_path, value, stream_mode, errors):
    import yaml

    from admina.core.config import load_config

    path = tmp_path / "admina.yaml"
    path.write_text(yaml.safe_dump({"gateway": {"stream_mode": value}}))

    gateway = load_config(path).gateway

    assert gateway.stream_mode == stream_mode
    assert gateway.errors == errors


def test_lifespan_resolves_the_stream_mode(monkeypatch, tmp_path):
    from admina.core.config import load_config
    from admina.proxy import main as proxy_main

    path = tmp_path / "admina.yaml"
    path.write_text("gateway:\n  stream_mode: governed\n")
    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_STREAM_MODE", "")
    state = run_lifespan(monkeypatch, load_config(path))

    assert state.gateway_stream_mode == "governed"


def test_shipped_yaml_example_keeps_the_default_stream_mode():
    from pathlib import Path

    from admina.core.config import load_config

    example = Path(__file__).resolve().parent.parent / "admina.yaml.example"
    gateway = load_config(example).gateway

    assert gateway.stream_mode == ""
    assert "# stream_mode: passthrough" in example.read_text()


def test_passthrough_does_not_touch_the_body_it_forwards():
    """A request the upstream answers with an unexpected content type is
    still forwarded unchanged in passthrough."""
    raw = b"not an event stream"
    upstream = MockUpstream([raw], content_type="text/plain")

    resp = through(upstream, chat_body())

    assert resp.content == raw
    assert resp.headers["content-type"] == "text/plain"
