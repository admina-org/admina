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

"""The body the gateway forwards upstream for a chat completion.

``ADMINA_GATEWAY_FORWARD_FIELDS``, ``ADMINA_GATEWAY_MAX_N`` and
``ADMINA_GATEWAY_MAX_COMPLETION_TOKENS`` are off by default, and the body is
then forwarded as received. The field list keeps ``model``, ``messages``,
``stream`` and the fields of a limit that is set; the limits lower ``n``,
``max_tokens`` and ``max_completion_tokens``, add ``max_tokens`` when the
request sets neither token field, and refuse (400, ``invalid_value``) a value
that is not an integer of at least 1. The request is scanned as received and
the forwarded ``messages``, whose hash is ``request_sha256``, never change.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from _gateway_stream import EMAIL, FakeFirewall, MockUpstream, settings, through
from pydantic import ValidationError

import admina
from admina.proxy.config import Settings
from admina.proxy.gateway_outcome import messages_sha256

MESSAGES = [{"role": "user", "content": "hello"}]
BODY = {
    "model": "example-model",
    "messages": MESSAGES,
    "temperature": 0.2,
    "n": 9,
    "example_extension": {"template": "custom"},
}
LIMIT = 256
_COMPLETION = {
    "id": "c1",
    "object": "chat.completion",
    "model": "example-model",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
}


class _Recorder:
    """Keeps every forensic record."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def record(self, event: dict) -> dict:
        self.events.append(event)
        return {"record_hash": "0" * 64}

    @property
    def request(self) -> dict:
        (event,) = (e for e in self.events if e["event_type"] == "gateway_request")
        return event


def _upstream(stream: bool) -> MockUpstream:
    if stream:
        return MockUpstream([b'data: {"choices": []}\n\n', b"data: [DONE]\n\n"])
    return MockUpstream([json.dumps(_COMPLETION).encode()], content_type="application/json")


def _send(body: dict, *, firewall=None, **over):
    upstream = _upstream(bool(body.get("stream")))
    recorder = _Recorder()
    state: dict = {"forensic_box": recorder}
    if firewall is not None:
        state["firewall"] = firewall
    resp = through(upstream, body, settings(**over), state=state)
    return resp, upstream, recorder


def _forwarded(upstream: MockUpstream) -> dict:
    (request,) = upstream.requests
    return json.loads(request.content)


def _invalid(field: str) -> dict:
    return {
        "error": {
            "message": f"'{field}' must be an integer of at least 1.",
            "type": "invalid_request_error",
            "param": field,
            "code": "invalid_value",
        }
    }


def _assert_refused(resp, upstream: MockUpstream, recorder: _Recorder, field: str) -> None:
    assert resp.status_code == 400
    assert resp.json() == _invalid(field)
    assert upstream.requests == []
    assert recorder.events == []
    assert "x-admina-event-id" not in resp.headers
    assert "x-admina-action" not in resp.headers
    assert resp.headers["x-admina-version"] == admina.__version__


# ── Defaults ──────────────────────────────────────────────────


def test_settings_default_to_off():
    cfg = Settings()
    assert cfg.ADMINA_GATEWAY_FORWARD_FIELDS == ""
    assert cfg.ADMINA_GATEWAY_MAX_N == 0
    assert cfg.ADMINA_GATEWAY_MAX_COMPLETION_TOKENS == 0


@pytest.mark.parametrize("stream", [False, True])
def test_body_is_forwarded_as_received_by_default(stream):
    body = {**BODY, "stream": stream, "max_tokens": 100_000, "n": "9", "chat_template": "{{ x }}"}
    resp, upstream, _ = _send(body)
    assert resp.status_code == 200
    assert _forwarded(upstream) == body


def test_no_token_field_is_added_by_default():
    _, upstream, _ = _send(BODY)
    forwarded = _forwarded(upstream)
    assert "max_tokens" not in forwarded
    assert "max_completion_tokens" not in forwarded


def test_router_settings_without_these_fields_are_off():
    from admina.proxy.gateway_body import ForwardSettings

    assert ForwardSettings.of(SimpleNamespace()) == ForwardSettings()
    assert ForwardSettings().fields(BODY) == BODY


# ── ADMINA_GATEWAY_FORWARD_FIELDS ─────────────────────────────


def test_only_listed_fields_and_the_required_ones_are_forwarded():
    body = {**BODY, "stream": False, "top_p": 0.9, "chat_template": "{{ x }}"}
    _, upstream, _ = _send(body, ADMINA_GATEWAY_FORWARD_FIELDS="temperature,seed")
    assert _forwarded(upstream) == {
        "model": "example-model",
        "messages": MESSAGES,
        "stream": False,
        "temperature": 0.2,
    }


def test_streaming_request_keeps_stream_whatever_the_list():
    body = {**BODY, "stream": True, "stream_options": {"include_usage": True}}
    resp, upstream, _ = _send(body, ADMINA_GATEWAY_FORWARD_FIELDS="temperature")
    assert resp.status_code == 200
    assert _forwarded(upstream) == {
        "model": "example-model",
        "messages": MESSAGES,
        "stream": True,
        "temperature": 0.2,
    }


def test_listed_field_names_are_case_sensitive():
    _, upstream, _ = _send(BODY, ADMINA_GATEWAY_FORWARD_FIELDS="Temperature")
    assert "temperature" not in _forwarded(upstream)


def test_fields_left_out_are_still_scanned():
    body = {**BODY, "example_extension": {"template": "INJECT"}}
    resp, upstream, recorder = _send(
        body, firewall=FakeFirewall(), ADMINA_GATEWAY_FORWARD_FIELDS="temperature"
    )
    assert resp.headers["x-admina-action"] == "BLOCK"
    assert upstream.requests == []
    assert recorder.request["action"] == "BLOCK"


def test_forward_fields_setting_is_normalised():
    cfg = Settings(ADMINA_GATEWAY_FORWARD_FIELDS=" temperature , top_p,,temperature")
    assert cfg.ADMINA_GATEWAY_FORWARD_FIELDS == "temperature,top_p"


@pytest.mark.parametrize("value", ["max tokens", "temperature;n", "temperature,*", "top.p", "é"])
def test_forward_fields_setting_refuses_invalid_names(value):
    with pytest.raises(ValidationError):
        Settings(ADMINA_GATEWAY_FORWARD_FIELDS=value)


@pytest.mark.parametrize(
    "setting", ["ADMINA_GATEWAY_MAX_N", "ADMINA_GATEWAY_MAX_COMPLETION_TOKENS"]
)
@pytest.mark.parametrize("value", [-1, "many"])
def test_limit_settings_refuse_invalid_values(setting, value):
    with pytest.raises(ValidationError):
        Settings(**{setting: value})


# ── ADMINA_GATEWAY_MAX_N ──────────────────────────────────────


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("n, sent", [(10**30, 4), (9, 4), (5, 4), (4, 4), (1, 1)])
def test_n_over_the_limit_is_lowered(n, sent, stream):
    body = {**BODY, "n": n, "stream": stream}
    resp, upstream, _ = _send(body, ADMINA_GATEWAY_MAX_N=4)
    assert resp.status_code == 200
    forwarded = _forwarded(upstream)
    assert forwarded["n"] == sent
    assert forwarded == {**body, "n": sent}


def test_absent_n_stays_absent():
    body = {k: v for k, v in BODY.items() if k != "n"}
    _, upstream, _ = _send(body, ADMINA_GATEWAY_MAX_N=4)
    assert "n" not in _forwarded(upstream)


def test_null_n_is_forwarded_as_it_is():
    _, upstream, _ = _send({**BODY, "n": None}, ADMINA_GATEWAY_MAX_N=4)
    assert _forwarded(upstream)["n"] is None


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("value", [0, -1, True, False, 2.0, 2.5, "2", [2], {"n": 2}])
def test_n_that_is_not_an_integer_of_at_least_one_is_refused(value, stream):
    body = {**BODY, "n": value, "stream": stream}
    resp, upstream, recorder = _send(body, ADMINA_GATEWAY_MAX_N=4)
    _assert_refused(resp, upstream, recorder, "n")


def test_n_is_not_checked_without_its_limit():
    _, upstream, _ = _send({**BODY, "n": "2"}, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT)
    assert _forwarded(upstream)["n"] == "2"


# ── ADMINA_GATEWAY_MAX_COMPLETION_TOKENS ──────────────────────


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("field", ["max_tokens", "max_completion_tokens"])
@pytest.mark.parametrize(
    "value, sent", [(10**30, LIMIT), (LIMIT + 1, LIMIT), (LIMIT, LIMIT), (16, 16), (1, 1)]
)
def test_token_field_over_the_limit_is_lowered(field, value, sent, stream):
    body = {**BODY, field: value, "stream": stream}
    resp, upstream, _ = _send(body, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT)
    assert resp.status_code == 200
    assert _forwarded(upstream) == {**body, field: sent}


@pytest.mark.parametrize(
    "tokens, sent",
    [
        ({"max_tokens": 10_000, "max_completion_tokens": 20_000}, (LIMIT, LIMIT)),
        ({"max_tokens": 10, "max_completion_tokens": 20_000}, (10, LIMIT)),
        ({"max_tokens": 20_000, "max_completion_tokens": 10}, (LIMIT, 10)),
    ],
)
def test_both_token_fields_are_lowered(tokens, sent):
    _, upstream, _ = _send({**BODY, **tokens}, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT)
    forwarded = _forwarded(upstream)
    assert (forwarded["max_tokens"], forwarded["max_completion_tokens"]) == sent


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("extra", [{}, {"max_tokens": None}])
def test_request_without_a_token_field_gets_max_tokens(extra, stream):
    body = {**BODY, **extra, "stream": stream}
    _, upstream, _ = _send(body, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT)
    forwarded = _forwarded(upstream)
    assert forwarded["max_tokens"] == LIMIT
    assert "max_completion_tokens" not in forwarded


def test_null_max_completion_tokens_alone_gets_max_tokens():
    body = {**BODY, "max_completion_tokens": None}
    _, upstream, _ = _send(body, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT)
    forwarded = _forwarded(upstream)
    assert forwarded["max_tokens"] == LIMIT
    assert forwarded["max_completion_tokens"] is None


def test_max_completion_tokens_alone_does_not_get_max_tokens():
    body = {**BODY, "max_completion_tokens": 64}
    _, upstream, _ = _send(body, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT)
    forwarded = _forwarded(upstream)
    assert forwarded["max_completion_tokens"] == 64
    assert "max_tokens" not in forwarded


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("field", ["max_tokens", "max_completion_tokens"])
@pytest.mark.parametrize("value", [0, -1, True, 64.0, "64", [64], {"value": 64}])
def test_token_field_that_is_not_an_integer_of_at_least_one_is_refused(field, value, stream):
    body = {**BODY, field: value, "stream": stream}
    resp, upstream, recorder = _send(body, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT)
    _assert_refused(resp, upstream, recorder, field)


def test_token_fields_are_not_checked_without_their_limit():
    body = {**BODY, "max_tokens": "64", "n": 2}
    _, upstream, _ = _send(body, ADMINA_GATEWAY_MAX_N=4)
    assert _forwarded(upstream)["max_tokens"] == "64"


# ── Together ──────────────────────────────────────────────────


def test_limited_fields_are_forwarded_whatever_the_list():
    body = {**BODY, "max_tokens": 10, "top_p": 0.9}
    _, upstream, _ = _send(
        body,
        ADMINA_GATEWAY_FORWARD_FIELDS="temperature",
        ADMINA_GATEWAY_MAX_N=4,
        ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT,
    )
    assert _forwarded(upstream) == {
        "model": "example-model",
        "messages": MESSAGES,
        "temperature": 0.2,
        "n": 4,
        "max_tokens": 10,
    }


def test_refusal_names_the_first_limited_field():
    body = {**BODY, "n": "2", "max_tokens": "64"}
    resp, upstream, recorder = _send(
        body, ADMINA_GATEWAY_MAX_N=4, ADMINA_GATEWAY_MAX_COMPLETION_TOKENS=LIMIT
    )
    _assert_refused(resp, upstream, recorder, "n")


@pytest.mark.parametrize("pii", [False, True])
def test_settings_leave_the_messages_and_their_hash_unchanged(pii):
    messages = [
        {"role": "system", "content": "Answer briefly."},
        {"role": "user", "content": f"Write to {EMAIL} about record 7."},
    ]
    body = {**BODY, "messages": messages, "max_tokens": 10_000}
    on = {
        "ADMINA_GATEWAY_FORWARD_FIELDS": "temperature",
        "ADMINA_GATEWAY_MAX_N": 4,
        "ADMINA_GATEWAY_MAX_COMPLETION_TOKENS": LIMIT,
    }
    _, plain, plain_records = _send(body, PII_REDACTION_ENABLED=pii)
    _, limited, limited_records = _send(body, PII_REDACTION_ENABLED=pii, **on)
    sent = _forwarded(limited)["messages"]
    assert sent == _forwarded(plain)["messages"]
    assert (EMAIL in json.dumps(sent)) is not pii
    assert limited_records.request["request_sha256"] == messages_sha256(sent)
    assert limited_records.request["request_sha256"] == plain_records.request["request_sha256"]
