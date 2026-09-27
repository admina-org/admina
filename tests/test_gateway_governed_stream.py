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

"""Governed completions: every field kept, every string redacted.

With PII redaction on (or ``ADMINA_GATEWAY_STREAM_MODE=governed``) each
upstream chunk is parsed and re-serialised. The gateway sends one chunk for
each upstream chunk, with all of its fields: ids, choice indexes (n > 1),
roles, tool call ids and names, finish reasons and the final usage chunk.
With redaction on, every string of a choice goes through the PII redactor,
per choice and per path, so that an entity split across chunks is caught:
``content`` (a string or a list of parts), reasoning text, tool and
function call arguments and any other field. Held-back text is sent with
the choice's finish chunk. Structural values (index, id, type, role, name,
finish reason) are kept; ``logprobs`` and ``token_ids`` are sent as
``null``; strings outside the choices are redacted as whole values, except
the chunk identity. Non-streaming completions follow the same rules for
``logprobs``, ``token_ids`` and the fields outside the choices.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re

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
    """*chunk* without generated text, and with ``logprobs`` null: what
    must reach the client unchanged while redacting."""
    chunk = copy.deepcopy(chunk)
    for choice in chunk.get("choices") or []:
        if "logprobs" in choice:
            choice["logprobs"] = None
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


def _upstream_chunk(
    delta: dict,
    *,
    index: int = 0,
    finish=None,
    logprobs=None,
    extra: dict | None = None,
    top: dict | None = None,
) -> bytes:
    """One upstream chunk; *extra* adds choice fields, *top* chunk fields."""
    choice = {"index": index, "delta": delta, "logprobs": logprobs, "finish_reason": finish}
    body = {
        "id": "chatcmpl-0005",
        "object": "chat.completion.chunk",
        "created": 1767225604,
        "model": "example-model",
        "choices": [{**choice, **(extra or {})}],
        **(top or {}),
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


def test_logprobs_are_kept_when_redaction_is_off():
    upstream_chunks = _chunks(_events(b"".join(fixture("logprobs")["chunks"])))

    _raw, events = _governed(fixture("logprobs")["chunks"], redaction=False)

    assert [c["choices"][0]["logprobs"] for c in _chunks(events)] == [
        c["choices"][0]["logprobs"] for c in upstream_chunks
    ]


class _EveryWord:
    """A PII engine that flags every word, as an over-eager engine can."""

    def redact(self, text: str) -> dict:
        redacted, count = re.subn(r"\w+", "[X]", text)
        return {"redacted_text": redacted, "entities": [], "count": count}

    def get_stats(self) -> dict:
        return {}


_STRUCTURAL = ("index", "id", "type", "role", "name", "finish_reason")
_IDENTITY = ("id", "object", "created", "model", "system_fingerprint")


def _structural_values(value, path=()) -> set:
    """(path, value) of every structural scalar at any depth of *value*."""
    found = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in _STRUCTURAL and not isinstance(item, (dict, list)):
                found.add(((*path, key), item))
            else:
                found |= _structural_values(item, (*path, key))
    elif isinstance(value, list):
        for pos, item in enumerate(value):
            found |= _structural_values(item, (*path, pos))
    return found


def _governed_stream_only(pieces: list[bytes], pii) -> list:
    """*pieces* through the governed stream path alone, with *pii*."""
    from admina.proxy.api.gateway import _governed_sse_stream

    async def lines():
        for line in b"".join(pieces).decode("utf-8").splitlines():
            yield line

    async def collect() -> str:
        return "".join([part async for part in _governed_sse_stream(lines(), pii)])

    return _events(asyncio.run(collect()).encode("utf-8"))


@pytest.mark.parametrize("name", FIXTURES)
def test_structural_values_are_kept_by_an_engine_that_flags_every_word(name):
    upstream_chunks = _chunks(_events(b"".join(fixture(name)["chunks"])))

    chunks = _chunks(_governed_stream_only(fixture(name)["chunks"], _EveryWord()))

    assert len(chunks) == len(upstream_chunks)
    for sent, received in zip(chunks, upstream_chunks, strict=True):
        assert {k: sent.get(k) for k in _IDENTITY} == {k: received.get(k) for k in _IDENTITY}
        assert _structural_values(received["choices"]) <= _structural_values(sent["choices"])


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


def _token(text: str) -> dict:
    entry = {"token": text, "logprob": -0.1, "bytes": list(text.encode())}
    return {**entry, "top_logprobs": [entry]}


# Tokens of "Write to jane.doe@example.com today.", three chunks of them: the
# address is split over five tokens and three chunks.
_TOKENS = [["Write", " to", " jane"], [".doe", "@exa"], ["mple", ".com", " today", "."]]
_ADDRESS_TOKENS = (" jane", ".doe", "@exa", "mple", ".com")


def _address_tokens_in(raw: bytes) -> list[str]:
    """The tokens of the address found in *raw* as JSON strings, and its
    local part found anywhere."""
    found = [t for t in _ADDRESS_TOKENS if json.dumps(t).encode() in raw]
    return found + (["jane"] if b"jane" in raw else [])


def test_logprobs_are_null_while_redacting():
    pieces = [
        _upstream_chunk({"content": "".join(part)}, logprobs={"content": [_token(t) for t in part]})
        for part in _TOKENS
    ]
    pieces += [_upstream_chunk({}, finish="stop"), _DONE]

    raw, events = _governed(pieces)
    chunks = _chunks(events)

    assert _text(chunks, "content") == "Write to [EMAIL] today."
    assert [c["choices"][0]["logprobs"] for c in chunks] == [None] * len(chunks)
    assert _address_tokens_in(raw) == []
    assert b'"token"' not in raw and b'"bytes"' not in raw


def test_refusal_logprobs_are_null_while_redacting():
    pieces = [
        _upstream_chunk({"refusal": "".join(part)}, logprobs={"refusal": [_token(t) for t in part]})
        for part in _TOKENS
    ]
    pieces += [_upstream_chunk({}, finish="stop"), _DONE]

    raw, events = _governed(pieces)

    assert _text(_chunks(events), "refusal") == "Write to [EMAIL] today."
    assert _address_tokens_in(raw) == []


def test_token_ids_are_null_while_redacting():
    pieces = [
        _upstream_chunk({"content": f"Hello {EMAIL}"}, extra={"token_ids": [9906, 57010]}),
        _upstream_chunk({}, finish="stop", extra={"token_ids": []}),
        _DONE,
    ]

    raw, events = _governed(pieces)

    assert [c["choices"][0]["token_ids"] for c in _chunks(events)] == [None, None]
    assert b"9906" not in raw


def test_token_ids_are_kept_when_redaction_is_off():
    pieces = [_upstream_chunk({"content": "Hello"}, extra={"token_ids": [9906]}), _DONE]

    _raw, events = _governed(pieces, redaction=False)

    assert _chunks(events)[0]["choices"][0]["token_ids"] == [9906]


def _parts(chunks: list[dict], field: str, index: int = 0) -> list:
    """The list items of delta *field* of choice *index*, over all chunks."""
    return [
        item for c in _choices(chunks, index) for item in (c.get("delta") or {}).get(field) or []
    ]


def test_content_parts_are_redacted_across_chunks():
    pieces = [
        _upstream_chunk({"role": "assistant", "content": []}),
        _upstream_chunk({"content": [{"type": "text", "text": f"Write to {_HEAD}"}]}),
        _upstream_chunk({"content": [{"type": "text", "text": f"{_TAIL} today."}]}),
        _upstream_chunk({}, finish="stop"),
        _DONE,
    ]

    raw, events = _governed(pieces)
    parts = _parts(_chunks(events), "content")

    assert "".join(p["text"] for p in parts) == "Write to [EMAIL] today."
    assert {p["type"] for p in parts} == {"text"}
    assert _HEAD.encode() not in raw and _TAIL.encode() not in raw


def test_reasoning_details_are_redacted_across_chunks():
    def detail(text: str) -> dict:
        return {"type": "reasoning.text", "text": text, "index": 0}

    pieces = [
        _upstream_chunk({"reasoning_details": [detail(f"Write to {_HEAD}")]}),
        _upstream_chunk({"reasoning_details": [detail(f"{_TAIL} today.")]}),
        _upstream_chunk({}, finish="stop"),
        _DONE,
    ]

    raw, events = _governed(pieces)
    details = _parts(_chunks(events), "reasoning_details")

    assert "".join(d["text"] for d in details) == "Write to [EMAIL] today."
    assert {(d["type"], d["index"]) for d in details} == {("reasoning.text", 0)}
    assert _HEAD.encode() not in raw and _TAIL.encode() not in raw


def test_audio_transcript_is_redacted_across_chunks():
    pieces = [
        _upstream_chunk({"audio": {"id": "audio_0001", "transcript": f"Write to {_HEAD}"}}),
        _upstream_chunk({"audio": {"transcript": f"{_TAIL} today."}}),
        _upstream_chunk({}, finish="stop"),
        _DONE,
    ]

    raw, events = _governed(pieces)
    audio = [(c.get("delta") or {}).get("audio") or {} for c in _choices(_chunks(events), 0)]

    assert "".join(a.get("transcript", "") for a in audio) == "Write to [EMAIL] today."
    assert audio[0]["id"] == "audio_0001"
    assert _HEAD.encode() not in raw and _TAIL.encode() not in raw


@pytest.mark.parametrize(
    ("where", "shape"),
    [
        ("delta", lambda text: {"x_note": text}),
        ("delta", lambda text: {"x_meta": {"summary": [text]}}),
        ("choice", lambda text: {"x_trace": text}),
    ],
    ids=["delta-string", "delta-nested", "choice-field"],
)
def test_other_fields_of_a_choice_are_redacted_across_chunks(where, shape):
    def chunk(text: str) -> bytes:
        if where == "delta":
            return _upstream_chunk(shape(text))
        return _upstream_chunk({}, extra=shape(text))

    pieces = [
        chunk(f"Write to {_HEAD}"),
        chunk(f"{_TAIL} today."),
        _upstream_chunk({}, finish="stop"),
    ]
    pieces.append(_DONE)

    raw, events = _governed(pieces)

    assert _HEAD.encode() not in raw and _TAIL.encode() not in raw
    assert b"Write to [EMAIL] today." in raw


def test_held_text_of_a_list_item_goes_back_to_its_item():
    pieces = [
        _upstream_chunk({"content": [{"type": "text", "text": f"Hello {EMAIL}"}]}),
        _DONE,
    ]

    _raw, events = _governed(pieces)
    chunks = _chunks(events)

    assert chunks[-1]["choices"] == [
        {
            "index": 0,
            "delta": {"content": [{"type": "text", "text": "Hello [EMAIL]"}]},
            "finish_reason": None,
        }
    ]


def test_strings_outside_the_choices_are_redacted_as_whole_values():
    top = {"system_fingerprint": "fp_0001", "x_note": f"to {EMAIL}", "x_meta": {"items": [EMAIL]}}
    error = {"error": {"message": f"failed for {EMAIL}", "type": "server_error", "code": 500}}
    pieces = [
        _upstream_chunk({"content": "ok"}, top=top),
        b"data: " + json.dumps(error).encode() + b"\n\n",
    ]

    raw, events = _governed(pieces)
    first, second, last = _chunks(events)

    assert (first["x_note"], first["x_meta"]) == ("to [EMAIL]", {"items": ["[EMAIL]"]})
    assert {k: first[k] for k in _IDENTITY} == {
        "id": "chatcmpl-0005",
        "object": "chat.completion.chunk",
        "created": 1767225604,
        "model": "example-model",
        "system_fingerprint": "fp_0001",
    }
    assert second == {
        "error": {"message": "failed for [EMAIL]", "type": "server_error", "code": 500}
    }
    # The held-back "ok" comes last, with the identity of the last chunk that had one.
    assert (last["id"], last["model"], _text([last], "content")) == (
        "chatcmpl-0005",
        "example-model",
        "ok",
    )
    assert EMAIL.encode() not in raw


def test_values_nested_deeper_than_the_limit_are_dropped_while_redacting():
    deep: object = "bottom text"
    for _ in range(40):
        deep = {"x": deep}
    pieces = [
        _upstream_chunk({"content": "ok", "x_deep": deep}),
        _upstream_chunk({}, finish="stop"),
    ]

    raw, events = _governed(pieces)

    assert b"bottom text" not in raw
    assert _text(_chunks(events), "content") == "ok"


# ── Non-streaming completions ─────────────────────────────────


def _completion(choice: dict, **top) -> bytes:
    body = {
        "id": "chatcmpl-0006",
        "object": "chat.completion",
        "created": 1767225605,
        "model": "example-model",
        "choices": [{"index": 0, "finish_reason": "stop", **choice}],
        **top,
    }
    return json.dumps(body).encode()


def _non_streaming(body: bytes, cfg=_REDACTION_ON):
    upstream = MockUpstream([body], content_type="application/json")
    resp = through(upstream, chat_body(stream=False), cfg)
    assert resp.status_code == 200
    return resp


def test_completion_logprobs_and_token_ids_are_null_while_redacting():
    tokens = [t for part in _TOKENS for t in part]
    body = _completion(
        {
            "message": {"role": "assistant", "content": "".join(tokens)},
            "logprobs": {"content": [_token(t) for t in tokens]},
            "token_ids": [9906, 57010],
        }
    )

    resp = _non_streaming(body)
    choice = resp.json()["choices"][0]

    assert choice["message"]["content"] == "Write to [EMAIL] today."
    assert (choice["logprobs"], choice["token_ids"]) == (None, None)
    assert _address_tokens_in(resp.content) == []


def test_completion_strings_outside_the_choices_are_redacted_while_redacting():
    body = _completion({"message": {"role": "assistant", "content": "ok"}}, x_note=f"to {EMAIL}")

    resp = _non_streaming(body)

    assert resp.json()["x_note"] == "to [EMAIL]"
    assert resp.json()["id"] == "chatcmpl-0006"
    assert EMAIL.encode() not in resp.content


def test_completion_is_forwarded_unchanged_when_redaction_is_off():
    body = _completion(
        {"message": {"role": "assistant", "content": "ok"}, "logprobs": {"content": [_token("ok")]}}
    )

    assert _non_streaming(body, settings()).content == body


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


def _nested(value: object, levels: int) -> object:
    for _ in range(levels):
        value = {"x": value}
    return value


def test_completion_values_are_redacted_at_any_depth_within_the_limit():
    message = {"role": "assistant", "content": "ok", "x_deep": _nested(f"to {EMAIL}", 10)}

    resp = _non_streaming(_completion({"message": message}))

    assert resp.json()["choices"][0]["message"]["x_deep"] == _nested("to [EMAIL]", 10)
    assert EMAIL.encode() not in resp.content


def test_completion_values_nested_deeper_than_the_limit_are_dropped_while_redacting():
    message = {"role": "assistant", "content": "ok", "x_deep": _nested("bottom text", 40)}

    resp = _non_streaming(_completion({"message": message}))

    assert b"bottom text" not in resp.content
    assert resp.json()["choices"][0]["message"]["content"] == "ok"
