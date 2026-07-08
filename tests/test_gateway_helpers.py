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

import json

from admina.proxy.api.gateway import (
    _delta_content,
    _extract_prompt_text,
    _finish_reason,
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


def test_delta_content_extracts_or_empty():
    assert _delta_content({"choices": [{"delta": {"content": "x"}}]}) == "x"
    assert _delta_content({"choices": [{"delta": {}}]}) == ""
    assert _delta_content({"choices": [{"delta": {"content": None}}]}) == ""
    assert _delta_content({}) == ""


def test_finish_reason_extracts_or_none():
    assert _finish_reason({"choices": [{"finish_reason": "stop"}]}) == "stop"
    assert _finish_reason({"choices": [{"delta": {"content": "x"}}]}) is None
    assert _finish_reason({}) is None


def test_parse_then_delta_content_matches_json():
    payload = {"choices": [{"delta": {"content": "abc"}, "finish_reason": None}]}
    parsed = _parse_sse_data("data: " + json.dumps(payload))
    assert _delta_content(parsed) == "abc"
