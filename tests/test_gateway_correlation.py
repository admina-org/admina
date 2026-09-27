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

"""Correlation of gateway calls: request id, recorded and forwarded
headers, W3C trace context.

- ``ADMINA_GATEWAY_REQUEST_ID_HEADER`` names the header whose value is
  recorded as ``request_id`` (none by default);
- ``ADMINA_GATEWAY_RECORD_HEADERS`` lists the headers recorded in
  ``context``, and no others;
- ``ADMINA_GATEWAY_FORWARD_HEADERS`` lists the headers forwarded upstream,
  besides the route's ``Authorization`` and ``X-Admina-Event-Id``;
- a valid ``traceparent`` is recorded as ``trace_id`` and, when listed,
  forwarded with ``tracestate``; with OpenTelemetry on, the gateway span is
  a child of the incoming span.
"""

from __future__ import annotations

import json

import pytest
from pydantic import SecretStr, ValidationError

pytest.importorskip("fastapi")

from _gateway_stream import UPSTREAM, MockUpstream, chat_body, settings, through

from admina.core.trace_context import parse_trace_context
from admina.proxy.config import Settings
from admina.proxy.gateway_upstreams import GatewayUpstreams

TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT_ID = "00f067aa0ba902b7"
TRACEPARENT = f"00-{TRACE_ID}-{PARENT_ID}-01"
TRACESTATE = "vendor1=opaque1,vendor2=opaque2"
RECORD = "X-Request-Id,X-Example-Purpose,X-Example-Client"
FORWARD = "traceparent,tracestate,X-Request-Id"


class _Recorder:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> dict:
        self.events.append(event)
        return {"record_hash": "0" * 64}

    def request_record(self) -> dict:
        (event,) = [e for e in self.events if e["event_type"] == "gateway_request"]
        return event


def _upstream() -> MockUpstream:
    body = {
        "id": "c1",
        "object": "chat.completion",
        "model": "example-model",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
        ],
    }
    return MockUpstream([json.dumps(body).encode()], content_type="application/json")


def _send(headers: dict[str, str], *, state: dict | None = None, **over):
    upstream = _upstream()
    recorder = _Recorder()
    resp = through(
        upstream,
        chat_body(stream=False),
        settings(**over),
        state={"forensic_box": recorder, **(state or {})},
        headers=headers,
    )
    assert resp.status_code == 200
    return upstream, recorder.request_record()


# ── Request id ────────────────────────────────────────────────


def test_request_id_from_the_configured_header():
    _, record = _send(
        {"X-Request-Id": "req-0001", "X-Session-Id": "s-1"},
        ADMINA_GATEWAY_REQUEST_ID_HEADER="X-Request-Id",
    )
    assert record["request_id"] == "req-0001"
    assert record["session_id"] == "s-1"


def test_no_request_id_header_by_default(monkeypatch):
    monkeypatch.delenv("ADMINA_GATEWAY_REQUEST_ID_HEADER", raising=False)
    assert Settings().ADMINA_GATEWAY_REQUEST_ID_HEADER == ""
    _, record = _send({"X-Request-Id": "req-0001", "X-Session-Id": "s-1"})
    assert record["request_id"] is None
    assert record["session_id"] == "s-1"


def test_request_id_absent_from_the_request():
    _, record = _send({}, ADMINA_GATEWAY_REQUEST_ID_HEADER="X-Request-Id")
    assert record["request_id"] is None


def test_request_id_is_bounded_and_single_line():
    long_id = "r" * 300
    _, record = _send({"X-Request-Id": long_id}, ADMINA_GATEWAY_REQUEST_ID_HEADER="x-request-id")
    assert record["request_id"] == "r" * 128


def test_request_id_loses_line_breaks():
    from starlette.datastructures import Headers

    from admina.proxy.gateway_correlation import request_id_of

    headers = Headers(raw=[(b"x-request-id", b"req-\r\n0001")])
    assert request_id_of(headers, "x-request-id") == "req-0001"


# ── Recorded headers ──────────────────────────────────────────


def test_record_headers_go_to_context_only_when_listed():
    _, record = _send(
        {
            "X-Request-Id": "req-0001",
            "X-Example-Purpose": "summary",
            "X-Example-Client": "cli",
            "X-Other": "not recorded",
            "Cookie": "session=secret",
        },
        ADMINA_GATEWAY_RECORD_HEADERS=RECORD,
    )
    assert record["context"] == {
        "x-request-id": "req-0001",
        "x-example-purpose": "summary",
        "x-example-client": "cli",
    }
    assert "not recorded" not in json.dumps(record)
    assert "secret" not in json.dumps(record)


def test_record_headers_absent_from_the_request_are_left_out():
    _, record = _send({"X-Example-Purpose": "summary"}, ADMINA_GATEWAY_RECORD_HEADERS=RECORD)
    assert record["context"] == {"x-example-purpose": "summary"}


def test_record_headers_are_bounded():
    _, record = _send({"X-Example-Purpose": "p" * 300}, ADMINA_GATEWAY_RECORD_HEADERS=RECORD)
    assert record["context"] == {"x-example-purpose": "p" * 128}


def test_no_context_by_default():
    _, record = _send({"X-Example-Purpose": "summary"})
    assert record["context"] == {}


# ── Forwarded headers ─────────────────────────────────────────


_CLIENT_HEADERS = {
    "traceparent": TRACEPARENT,
    "tracestate": TRACESTATE,
    "X-Request-Id": "req-0001",
    "X-Example-Purpose": "summary",
    "Authorization": "Bearer client-token",
    "Cookie": "session=secret",
    "X-Admina-Scan-Policy": "v1; ruleset=" + "0" * 64,
    "X-API-Key": "client-key",
}


# Header names the upstream client puts on every request.
_CLIENT_DEFAULTS = {
    "host",
    "accept",
    "accept-encoding",
    "connection",
    "user-agent",
    "content-length",
    "content-type",
}


def test_forward_headers_reach_the_upstream_and_nothing_else():
    upstreams = GatewayUpstreams.single(UPSTREAM, api_key=SecretStr("canary-upstream-key"))
    upstream, _ = _send(
        _CLIENT_HEADERS,
        state={"gateway_upstreams": upstreams},
        ADMINA_GATEWAY_FORWARD_HEADERS=FORWARD,
    )
    sent = upstream.requests[0].headers
    assert sent["traceparent"] == TRACEPARENT
    assert sent["tracestate"] == TRACESTATE
    assert sent["x-request-id"] == "req-0001"
    assert sent["authorization"] == "Bearer canary-upstream-key"
    assert "x-admina-event-id" in sent
    extra = set(sent.keys()) - _CLIENT_DEFAULTS
    assert extra == {
        "traceparent",
        "tracestate",
        "x-request-id",
        "authorization",
        "x-admina-event-id",
    }
    assert "cookie" not in sent and "x-api-key" not in sent


def test_no_client_header_is_forwarded_by_default(monkeypatch):
    monkeypatch.delenv("ADMINA_GATEWAY_FORWARD_HEADERS", raising=False)
    assert Settings().ADMINA_GATEWAY_FORWARD_HEADERS == ""
    upstream, _ = _send(_CLIENT_HEADERS)
    sent = upstream.requests[0].headers
    extra = set(sent.keys()) - _CLIENT_DEFAULTS
    assert extra == {"x-admina-event-id"}


# ── Header settings ───────────────────────────────────────────


def test_header_settings_are_normalised():
    cfg = Settings(
        ADMINA_GATEWAY_REQUEST_ID_HEADER=" X-Request-Id ",
        ADMINA_GATEWAY_RECORD_HEADERS=" X-Request-Id , X-Example-Purpose,,x-request-id",
        ADMINA_GATEWAY_FORWARD_HEADERS="TraceParent, tracestate",
    )
    assert cfg.ADMINA_GATEWAY_REQUEST_ID_HEADER == "x-request-id"
    assert cfg.ADMINA_GATEWAY_RECORD_HEADERS == "x-request-id,x-example-purpose"
    assert cfg.ADMINA_GATEWAY_FORWARD_HEADERS == "traceparent,tracestate"


@pytest.mark.parametrize(
    "setting, value",
    [
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "traceparent,Authorization"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "Cookie"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "X-API-Key"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "X-Admina-Upstream"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "x-admina-event-id"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "Host"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "Content-Length"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "Transfer-Encoding"),
        ("ADMINA_GATEWAY_RECORD_HEADERS", "Authorization"),
        ("ADMINA_GATEWAY_RECORD_HEADERS", "X-Example-Purpose,Cookie"),
        ("ADMINA_GATEWAY_RECORD_HEADERS", "x-api-key"),
        ("ADMINA_GATEWAY_REQUEST_ID_HEADER", "Authorization"),
        ("ADMINA_GATEWAY_REQUEST_ID_HEADER", "X-Request-Id,X-Other"),
        ("ADMINA_GATEWAY_RECORD_HEADERS", "X Request"),
        ("ADMINA_GATEWAY_FORWARD_HEADERS", "x-request-id:"),
    ],
)
def test_header_settings_refuse_credentials_and_invalid_names(setting, value):
    with pytest.raises(ValidationError):
        Settings(**{setting: value})


# ── W3C trace context ─────────────────────────────────────────


def test_traceparent_is_recorded_and_forwarded():
    upstream, record = _send(
        {"traceparent": TRACEPARENT, "tracestate": TRACESTATE},
        ADMINA_GATEWAY_FORWARD_HEADERS=FORWARD,
    )
    assert record["trace_id"] == TRACE_ID
    sent = upstream.requests[0].headers
    assert sent["traceparent"] == TRACEPARENT
    assert sent["tracestate"] == TRACESTATE


def test_traceparent_is_recorded_when_not_forwarded():
    upstream, record = _send({"traceparent": TRACEPARENT})
    assert record["trace_id"] == TRACE_ID
    assert "traceparent" not in upstream.requests[0].headers


def test_no_trace_id_without_traceparent():
    _, record = _send({})
    assert record["trace_id"] is None


MALFORMED = [
    "00-" + TRACE_ID + "-" + PARENT_ID,  # no flags
    "00-" + TRACE_ID.upper() + "-" + PARENT_ID + "-01",  # upper-case hex
    "ff-" + TRACE_ID + "-" + PARENT_ID + "-01",  # forbidden version
    "00-" + "0" * 32 + "-" + PARENT_ID + "-01",  # zero trace id
    "00-" + TRACE_ID + "-" + "0" * 16 + "-01",  # zero parent id
    "00-" + TRACE_ID + "-" + PARENT_ID + "-01-extra",  # version 00 with more fields
    "00-" + TRACE_ID[:-1] + "-" + PARENT_ID + "-01",  # short trace id
    "00_" + TRACE_ID + "_" + PARENT_ID + "_01",  # wrong separator
    "",
]


@pytest.mark.parametrize("value", MALFORMED)
def test_malformed_traceparent_is_ignored(value):
    upstream, record = _send(
        {"traceparent": value, "tracestate": TRACESTATE},
        ADMINA_GATEWAY_FORWARD_HEADERS=FORWARD,
    )
    assert record["trace_id"] is None
    sent = upstream.requests[0].headers
    assert "traceparent" not in sent
    assert "tracestate" not in sent


def test_trace_context_parsing():
    assert parse_trace_context([TRACEPARENT], []).trace_id == TRACE_ID
    assert parse_trace_context([f" {TRACEPARENT} "], []).parent_id == PARENT_ID
    # A later version may carry more fields: the first four are read.
    later = parse_trace_context([f"01-{TRACE_ID}-{PARENT_ID}-03-future"], ["a=1", "b=2"])
    assert later.trace_id == TRACE_ID
    assert later.traceparent == f"01-{TRACE_ID}-{PARENT_ID}-03-future"
    assert later.tracestate == "a=1,b=2"
    # More than one traceparent header: invalid.
    assert parse_trace_context([TRACEPARENT, TRACEPARENT], []) is None
    assert parse_trace_context([], [TRACESTATE]) is None


# ── OpenTelemetry span ────────────────────────────────────────


def _otel():
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from admina.domains.compliance.otel import OTELGovernanceExporter

    spans = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(spans))
    exporter = OTELGovernanceExporter.__new__(OTELGovernanceExporter)
    exporter._enabled = True
    exporter._tracer = provider.get_tracer("test")
    return exporter, spans


def test_gateway_span_is_a_child_of_the_incoming_span():
    exporter, spans = _otel()
    upstream, record = _send(
        {"traceparent": TRACEPARENT, "tracestate": TRACESTATE},
        state={"otel_exporter": exporter},
        ADMINA_GATEWAY_FORWARD_HEADERS=FORWARD,
    )
    (span,) = spans.get_finished_spans()
    assert span.parent is not None
    assert f"{span.parent.span_id:016x}" == PARENT_ID
    assert f"{span.context.trace_id:032x}" == TRACE_ID
    assert record["trace_id"] == TRACE_ID
    assert span.attributes["admina.event_id"] == record["event_id"]
    assert span.attributes["admina.action"] == "ALLOW"
    assert span.attributes["http.response.status_code"] == 200
    # The upstream sees the gateway span as its parent, in the same trace.
    sent = upstream.requests[0].headers
    assert sent["traceparent"] == f"00-{TRACE_ID}-{span.context.span_id:016x}-01"
    assert sent["tracestate"] == TRACESTATE


def test_gateway_span_without_an_incoming_trace_starts_one():
    exporter, spans = _otel()
    _, record = _send({}, state={"otel_exporter": exporter})
    (span,) = spans.get_finished_spans()
    assert span.parent is None
    assert record["trace_id"] == f"{span.context.trace_id:032x}"


def test_no_span_when_opentelemetry_is_off():
    class _Off:
        enabled = False

        def start_span(self, *args, **kwargs):
            raise AssertionError("no span expected")

    _, record = _send({"traceparent": TRACEPARENT}, state={"otel_exporter": _Off()})
    assert record["trace_id"] == TRACE_ID
