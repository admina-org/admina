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

"""Unit tests for the gateway's pure OpenAI/SSE helpers."""

from __future__ import annotations

import asyncio
import json

from admina.proxy.api.gateway import (
    _extract_prompt_text,
    _parse_sse_data,
    _sse_format,
)


def test_extract_prompt_text_joins_string_contents():
    messages = [
        {"role": "system", "content": "be terse"},
        {"role": "user", "content": "email me at a@b.com"},
    ]
    assert _extract_prompt_text(messages) == "be terse\nemail me at a@b.com"


def test_extract_prompt_text_handles_vision_parts():
    messages = [
        {"role": "user", "content": [{"type": "text", "text": "hello"}, {"type": "image_url"}]}
    ]
    assert _extract_prompt_text(messages) == "hello"


def test_extract_prompt_text_ignores_malformed():
    assert _extract_prompt_text([{"role": "user"}, "not-a-dict", {"content": 5}]) == ""


def test_sse_format_is_data_line_with_double_newline():
    out = _sse_format({"a": 1})
    assert out == 'data: {"a":1}\n\n'


def test_parse_sse_data_roundtrip():
    line = _sse_format({"choices": [{"delta": {"content": "hi"}}]}).strip()
    assert _parse_sse_data(line) == {"choices": [{"delta": {"content": "hi"}}]}


def test_parse_sse_data_done_and_junk_return_none():
    assert _parse_sse_data("data: [DONE]") is None
    assert _parse_sse_data(": keep-alive") is None
    assert _parse_sse_data("data: not json") is None
    assert _parse_sse_data("") is None


def test_parse_sse_data_matches_json():
    payload = {"choices": [{"delta": {"content": "abc"}, "finish_reason": None}]}
    assert _parse_sse_data("data: " + json.dumps(payload)) == payload


def test_synthetic_completion_shape():
    from admina.proxy.api.gateway import _synthetic_completion

    body = _synthetic_completion("llama3", "blocked!")
    assert body["object"] == "chat.completion"
    assert body["model"] == "llama3"
    choice = body["choices"][0]
    assert choice["finish_reason"] == "content_filter"
    assert choice["message"] == {"role": "assistant", "content": "blocked!"}
    assert body["id"].startswith("chatcmpl-admina-")


def test_synthetic_stream_shape():
    from admina.proxy.api.gateway import _parse_sse_data, _synthetic_stream

    lines = _synthetic_stream("llama3", "blocked!")
    assert lines[-1] == "data: [DONE]\n\n"
    first = _parse_sse_data(lines[0].strip())
    assert first["object"] == "chat.completion.chunk"
    choice = first["choices"][0]
    assert choice["delta"] == {"role": "assistant", "content": "blocked!"}
    assert choice["finish_reason"] == "content_filter"


class _EchoPII:
    """PII engine that finds nothing: the stream's windows still hold text
    back, so the tests prove cross-chunk reconstruction and the flush."""

    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}


async def _aiter(seq):
    for item in seq:
        yield item


async def _collect(gen):
    return [chunk async for chunk in gen]


def _first_choices(sse_chunks):
    for raw in sse_chunks:
        parsed = _parse_sse_data(raw.strip())
        if parsed and parsed.get("choices"):
            yield parsed["choices"][0]


def _reassemble(sse_chunks):
    return "".join(c.get("delta", {}).get("content") or "" for c in _first_choices(sse_chunks))


def test_governed_sse_reassembles_across_chunks_and_terminates():
    from admina.proxy.api.gateway import _governed_sse_stream, _sse_format

    upstream = [
        _sse_format({"choices": [{"delta": {"role": "assistant"}, "finish_reason": None}]}),
        _sse_format({"choices": [{"delta": {"content": "Hel"}, "finish_reason": None}]}),
        _sse_format({"choices": [{"delta": {"content": "lo"}, "finish_reason": None}]}),
        _sse_format({"choices": [{"delta": {}, "finish_reason": "stop"}]}),
        "data: [DONE]\n\n",
    ]
    out = asyncio.run(_collect(_governed_sse_stream(_aiter(upstream), _EchoPII())))
    assert out[-1] == "data: [DONE]\n\n"
    assert _reassemble(out) == "Hello"


def test_governed_sse_preserves_finish_reason():
    from admina.proxy.api.gateway import _governed_sse_stream, _sse_format

    upstream = [
        _sse_format({"choices": [{"delta": {"content": "hi"}, "finish_reason": None}]}),
        _sse_format({"choices": [{"delta": {}, "finish_reason": "stop"}]}),
        "data: [DONE]\n\n",
    ]
    out = asyncio.run(_collect(_governed_sse_stream(_aiter(upstream), _EchoPII())))
    reasons = [c.get("finish_reason") for c in _first_choices(out)]
    assert "stop" in reasons


def test_governed_sse_empty_stream_sends_nothing():
    from admina.proxy.api.gateway import _governed_sse_stream

    out = asyncio.run(_collect(_governed_sse_stream(_aiter([]), _EchoPII())))
    assert out == []


def test_governed_sse_no_finish_chunk_still_flushes_tail():
    from admina.proxy.api.gateway import _governed_sse_stream, _sse_format

    # Upstream ends without a finish_reason chunk; the held tail must still flush.
    upstream = [
        _sse_format({"choices": [{"delta": {"content": "Hello"}, "finish_reason": None}]}),
        "data: [DONE]\n\n",
    ]
    out = asyncio.run(_collect(_governed_sse_stream(_aiter(upstream), _EchoPII())))
    assert out[-1] == "data: [DONE]\n\n"
    assert _reassemble(out) == "Hello"
