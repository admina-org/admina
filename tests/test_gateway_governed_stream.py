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

"""Governed streaming: every field kept, every text field redacted.

With PII redaction on (or ``ADMINA_GATEWAY_STREAM_MODE=governed``) each
upstream chunk is parsed and re-serialised. The gateway sends one chunk for
each upstream chunk, with all of its fields: ids, choice indexes (n > 1),
roles, tool call ids and names, finish reasons, logprobs and the final usage
chunk. The text a model generates (``content``, ``reasoning_content``,
``reasoning``, ``refusal``, tool and function call arguments) goes through
the PII redactor, per choice and per field, so that an entity split across
chunks is caught; held-back text is sent with the choice's finish chunk.
Token texts in ``logprobs`` are redacted one by one.
"""

from __future__ import annotations

import copy
import json

import pytest

pytest.importorskip("fastapi")

from _gateway_stream import EMAIL, FIXTURES, MockUpstream, chat_body, fixture, settings, through

_TEXT_FIELDS = ("content", "reasoning_content", "reasoning", "refusal")
_REDACTION_ON = settings(PII_REDACTION_ENABLED=True)


def _events(raw: bytes) -> list:
    """SSE output as a list: dict (data chunk), "[DONE]" or ("comment", text)."""
    out: list = []
    for block in raw.replace(b"\r\n", b"\n").split(b"\n\n"):
        for line in block.decode("utf-8").split("\n"):
            if line.startswith(":"):
                out.append(("comment", line))
            elif line.startswith("data:"):
                payload = line[len("data:") :].strip()
                out.append("[DONE]" if payload == "[DONE]" else json.loads(payload))
    return out


def _chunks(events: list) -> list[dict]:
    return [e for e in events if isinstance(e, dict)]


def _choices(chunks: list[dict], index: int) -> list[dict]:
    return [c for chunk in chunks for c in chunk.get("choices") or [] if c.get("index") == index]


def _text(chunks: list[dict], field: str, index: int = 0) -> str:
    return "".join((c.get("delta") or {}).get(field) or "" for c in _choices(chunks, index))


def _arguments(chunks: list[dict], index: int = 0, call: int = 0) -> str:
    parts = []
    for choice in _choices(chunks, index):
        for tc in (choice.get("delta") or {}).get("tool_calls") or []:
            if tc.get("index") == call:
                parts.append((tc.get("function") or {}).get("arguments") or "")
    return "".join(parts)


def _without_text(chunk: dict) -> dict:
    """*chunk* without generated text: what must reach the client unchanged."""
    chunk = copy.deepcopy(chunk)
    for choice in chunk.get("choices") or []:
        delta = choice.get("delta") or {}
        for field in _TEXT_FIELDS:
            delta.pop(field, None)
        calls = []
        for call in delta.pop("tool_calls", None) or []:
            function = call.get("function") or {}
            function.pop("arguments", None)
            if not function:
                call.pop("function", None)
            if set(call) - {"index"}:
                calls.append(call)
        if calls:
            delta["tool_calls"] = calls
        choice["delta"] = delta
    return chunk


def _upstream_chunk(delta: dict, *, index: int = 0, finish=None, logprobs=None) -> bytes:
    body = {
        "id": "chatcmpl-0005",
        "object": "chat.completion.chunk",
        "created": 1767225604,
        "model": "example-model",
        "choices": [
            {"index": index, "delta": delta, "logprobs": logprobs, "finish_reason": finish}
        ],
    }
    return b"data: " + json.dumps(body).encode() + b"\n\n"


_DONE = b"data: [DONE]\n\n"
_HEAD, _TAIL = EMAIL[:12], EMAIL[12:]  # "jane.doe@exa", "mple.com"


def _governed(pieces: list[bytes], *, redaction: bool = True) -> tuple[bytes, list]:
    cfg = _REDACTION_ON if redaction else settings()
    resp = through(MockUpstream(pieces), chat_body(), cfg, stream_mode="governed")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    return resp.content, _events(resp.content)


# ── Every field kept ──────────────────────────────────────────


@pytest.mark.parametrize("name", FIXTURES)
def test_every_non_text_field_reaches_the_client(name):
    upstream_events = _events(b"".join(fixture(name)["chunks"]))

    _raw, events = _governed(fixture(name)["chunks"])

    upstream_chunks, chunks = _chunks(upstream_events), _chunks(events)
    assert [_without_text(c) for c in chunks] == [_without_text(c) for c in upstream_chunks]
    assert ("[DONE]" in events) == ("[DONE]" in upstream_events)
    assert [e for e in events if isinstance(e, tuple)] == [
        e for e in upstream_events if isinstance(e, tuple)
    ]


@pytest.mark.parametrize("name", FIXTURES)
def test_text_without_personal_data_reaches_the_client_whole(name):
    upstream_chunks = _chunks(_events(b"".join(fixture(name)["chunks"])))

    _raw, events = _governed(fixture(name)["chunks"])

    chunks = _chunks(events)
    for index in (0, 1):
        for field in _TEXT_FIELDS:
            assert _text(chunks, field, index) == _text(upstream_chunks, field, index)
        assert _arguments(chunks, index) == _arguments(upstream_chunks, index)


@pytest.mark.parametrize("name", FIXTURES)
def test_governed_without_redaction_keeps_every_chunk(name):
    upstream_events = _events(b"".join(fixture(name)["chunks"]))

    _raw, events = _governed(fixture(name)["chunks"], redaction=False)

    assert events == upstream_events


def test_usage_chunk_is_kept_as_sent():
    upstream_chunks = _chunks(_events(b"".join(fixture("usage")["chunks"])))

    _raw, events = _governed(fixture("usage")["chunks"])

    assert _chunks(events)[-1] == upstream_chunks[-1]
    assert _chunks(events)[-1]["choices"] == []


def test_logprobs_are_kept():
    upstream_chunks = _chunks(_events(b"".join(fixture("logprobs")["chunks"])))

    _raw, events = _governed(fixture("logprobs")["chunks"])

    assert [c["choices"][0]["logprobs"] for c in _chunks(events)] == [
        c["choices"][0]["logprobs"] for c in upstream_chunks
    ]


# ── Every text field redacted ─────────────────────────────────


@pytest.mark.parametrize("field", _TEXT_FIELDS)
def test_text_field_is_redacted_across_chunks(field):
    pieces = [
        _upstream_chunk({"role": "assistant", "content": ""}),
        _upstream_chunk({field: f"Write to {_HEAD}"}),
        _upstream_chunk({field: f"{_TAIL} today."}),
        _upstream_chunk({}, finish="stop"),
        _DONE,
    ]

    raw, events = _governed(pieces)

    assert _text(_chunks(events), field) == "Write to [EMAIL] today."
    assert _HEAD.encode() not in raw and _TAIL.encode() not in raw
    assert len(_chunks(events)) == 4
    assert events[-1] == "[DONE]"


def test_tool_call_arguments_are_redacted_across_chunks():
    pieces = [
        _upstream_chunk({"role": "assistant", "content": None}),
        _upstream_chunk(
            {
                "tool_calls": [
                    {
                        "index": 0,
                        "id": "call_0002",
                        "type": "function",
                        "function": {"name": "send_mail", "arguments": ""},
                    }
                ]
            }
        ),
        _upstream_chunk({"tool_calls": [{"index": 0, "function": {"arguments": '{"to": "'}}]}),
        _upstream_chunk({"tool_calls": [{"index": 0, "function": {"arguments": _HEAD}}]}),
        _upstream_chunk({"tool_calls": [{"index": 0, "function": {"arguments": _TAIL + '"}'}}]}),
        _upstream_chunk({}, finish="tool_calls"),
        _DONE,
    ]

    raw, events = _governed(pieces)
    chunks = _chunks(events)

    assert json.loads(_arguments(chunks)) == {"to": "[EMAIL]"}
    assert _HEAD.encode() not in raw and _TAIL.encode() not in raw
    first_call = chunks[1]["choices"][0]["delta"]["tool_calls"][0]
    assert (first_call["id"], first_call["type"], first_call["function"]["name"]) == (
        "call_0002",
        "function",
        "send_mail",
    )
    assert chunks[-1]["choices"][0]["finish_reason"] == "tool_calls"


def test_two_tool_calls_are_redacted_separately():
    pieces = [
        _upstream_chunk(
            {"tool_calls": [{"index": 0, "id": "call_a", "function": {"arguments": _HEAD}}]}
        ),
        _upstream_chunk(
            {"tool_calls": [{"index": 1, "id": "call_b", "function": {"arguments": "plain"}}]}
        ),
        _upstream_chunk({"tool_calls": [{"index": 0, "function": {"arguments": _TAIL}}]}),
        _upstream_chunk({}, finish="tool_calls"),
    ]

    _raw, events = _governed(pieces)
    chunks = _chunks(events)

    assert _arguments(chunks, call=0) == "[EMAIL]"
    assert _arguments(chunks, call=1) == "plain"


def test_legacy_function_call_arguments_are_redacted():
    pieces = [
        _upstream_chunk({"function_call": {"name": "send_mail", "arguments": _HEAD}}),
        _upstream_chunk({"function_call": {"arguments": _TAIL}}),
        _upstream_chunk({}, finish="function_call"),
    ]

    raw, events = _governed(pieces)

    arguments = "".join(
        (c["choices"][0]["delta"].get("function_call") or {}).get("arguments", "")
        for c in _chunks(events)
    )
    assert arguments == "[EMAIL]"
    assert _HEAD.encode() not in raw
    assert _chunks(events)[0]["choices"][0]["delta"]["function_call"]["name"] == "send_mail"


def test_choices_are_redacted_separately_and_keep_their_index():
    pieces = [
        _upstream_chunk({"content": "Red "}, index=0),
        _upstream_chunk({"content": _HEAD}, index=1),
        _upstream_chunk({"content": "apples"}, index=0),
        _upstream_chunk({"content": _TAIL}, index=1),
        _upstream_chunk({}, index=1, finish="stop"),
        _upstream_chunk({}, index=0, finish="length"),
        _DONE,
    ]

    raw, events = _governed(pieces)
    chunks = _chunks(events)

    assert [c["choices"][0]["index"] for c in chunks] == [0, 1, 0, 1, 1, 0]
    assert _text(chunks, "content", 0) == "Red apples"
    assert _text(chunks, "content", 1) == "[EMAIL]"
    assert [c["choices"][0]["finish_reason"] for c in chunks][-2:] == ["stop", "length"]
    assert _HEAD.encode() not in raw


def test_logprob_tokens_are_redacted():
    def entry(token: str, logprob: float) -> dict:
        return {"token": token, "logprob": logprob, "bytes": list(token.encode())}

    logprobs = {"content": [{**entry(EMAIL, -0.1), "top_logprobs": [entry(EMAIL, -0.1)]}]}
    pieces = [_upstream_chunk({"content": EMAIL}, logprobs=logprobs), _DONE]

    raw, events = _governed(pieces)

    sent = _chunks(events)[0]["choices"][0]["logprobs"]["content"][0]
    assert sent["token"] == "[EMAIL]"
    assert sent["bytes"] == list(b"[EMAIL]")
    assert sent["logprob"] == -0.1
    assert sent["top_logprobs"] == [
        {"token": "[EMAIL]", "logprob": -0.1, "bytes": list(b"[EMAIL]")}
    ]
    assert EMAIL.encode() not in raw


# ── End of the stream ─────────────────────────────────────────


def test_held_text_is_sent_before_done_when_no_finish_chunk_comes():
    pieces = [_upstream_chunk({"content": f"Hello {EMAIL}"}), _DONE]

    raw, events = _governed(pieces)
    chunks = _chunks(events)

    assert _text(chunks, "content") == "Hello [EMAIL]"
    assert chunks[-1]["id"] == "chatcmpl-0005"
    assert chunks[-1]["choices"] == [
        {"index": 0, "delta": {"content": "Hello [EMAIL]"}, "finish_reason": None}
    ]
    assert events[-1] == "[DONE]"
    assert EMAIL.encode() not in raw


def test_held_text_is_sent_when_the_stream_ends_without_done():
    pieces = [_upstream_chunk({"content": f"Hello {EMAIL}"})]

    raw, events = _governed(pieces)

    assert _text(_chunks(events), "content") == "Hello [EMAIL]"
    assert "[DONE]" not in events
    assert EMAIL.encode() not in raw


def test_data_that_is_not_a_json_object_is_dropped():
    pieces = [
        f"data: not json {EMAIL}\n\n".encode(),
        b"data: [1, 2]\n\n",
        _upstream_chunk({"content": "ok"}),
        _DONE,
    ]

    raw, events = _governed(pieces)

    assert EMAIL.encode() not in raw
    assert b"not json" not in raw and b"[1" not in raw
    assert _text(_chunks(events), "content") == "ok"
    assert {c["id"] for c in _chunks(events)} == {"chatcmpl-0005"}


def test_comment_lines_are_redacted():
    pieces = [f": note {EMAIL}\n\n".encode(), _upstream_chunk({"content": "ok"}), _DONE]

    raw, events = _governed(pieces)

    assert events[0] == ("comment", ": note [EMAIL]")
    assert EMAIL.encode() not in raw


def test_redaction_is_the_default_path_in_passthrough_mode():
    pieces = [
        _upstream_chunk({"reasoning_content": EMAIL}),
        _upstream_chunk({"tool_calls": [{"index": 0, "function": {"arguments": EMAIL}}]}),
        _upstream_chunk({}, finish="stop"),
        _DONE,
    ]

    resp = through(MockUpstream(pieces), chat_body(), _REDACTION_ON, stream_mode="passthrough")

    assert EMAIL.encode() not in resp.content
    assert b"[EMAIL]" in resp.content
