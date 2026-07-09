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

"""OpenAI-compatible governance gateway.

A fifth governed surface (after /mcp, /api/v1/validate, GovernedModel,
GovernedAgent): an OpenAI-compatible HTTP API that forwards to a
configurable upstream while applying the canonical governance pipeline
inline. Any OpenAI-compatible front-end can point at Admina instead of
the upstream and get governance with no further configuration.

Routes (prefix /v1):
  POST /v1/chat/completions   — streaming (SSE) and non-streaming
  GET  /v1/models             — passthrough with optional allow-list
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator


def _extract_prompt_text(messages: list) -> str:
    """Concatenate the text of every chat message for governance scanning.

    Handles both string ``content`` and OpenAI vision-style content parts
    (a list of ``{"type": "text", "text": ...}`` dicts). Non-string,
    non-list content and malformed entries are skipped.
    """
    parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            if content:
                parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    parts.append(part["text"])
    return "\n".join(parts)


def _sse_format(obj: dict) -> str:
    """Serialise *obj* as a single SSE ``data:`` event (compact JSON)."""
    return f"data: {json.dumps(obj, separators=(',', ':'))}\n\n"


def _parse_sse_data(line: str) -> dict | None:
    """Parse one upstream SSE line into a dict.

    Returns None for keep-alives, the ``[DONE]`` sentinel, empty payloads,
    and any non-JSON body — callers treat None as "skip this line".
    """
    line = line.strip()
    if not line.startswith("data:"):
        return None
    payload = line[len("data:") :].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _delta_content(chunk: dict) -> str:
    """Return ``choices[0].delta.content`` or "" when absent/None."""
    try:
        return chunk["choices"][0]["delta"].get("content") or ""
    except (KeyError, IndexError, TypeError, AttributeError):
        return ""


def _finish_reason(chunk: dict) -> str | None:
    """Return ``choices[0].finish_reason`` or None when absent."""
    try:
        return chunk["choices"][0].get("finish_reason")
    except (KeyError, IndexError, TypeError):
        return None


def _synthetic_completion(model: str, message: str) -> dict:
    """A non-streaming OpenAI completion carrying the governance block.

    Shaped so OpenAI-compatible UIs render it as a normal (if refused)
    response instead of surfacing a raw HTTP error.
    """
    return {
        "id": f"chatcmpl-admina-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": message},
                "finish_reason": "content_filter",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _synthetic_stream(model: str, message: str) -> list[str]:
    """SSE lines for a blocked streaming request: one content_filter chunk
    then ``data: [DONE]`` — never a completion object on a streaming
    request (that would break SSE parsing on the client)."""
    chunk = {
        "id": f"chatcmpl-admina-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"role": "assistant", "content": message},
                "finish_reason": "content_filter",
            }
        ],
    }
    return [_sse_format(chunk), "data: [DONE]\n\n"]


def _content_chunk(template: dict, content: str, model: str) -> dict:
    """A content-bearing chat.completion.chunk cloned from *template*'s
    identity fields (id/created/model) with a fresh redacted delta."""
    return {
        "id": template.get("id", ""),
        "object": "chat.completion.chunk",
        "created": template.get("created", int(time.time())),
        "model": template.get("model", model),
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}],
    }


def _finish_chunk(template: dict, reason: str, model: str) -> dict:
    """A terminal chat.completion.chunk (empty delta) preserving the
    upstream finish_reason so clients close the turn correctly."""
    return {
        "id": template.get("id", ""),
        "object": "chat.completion.chunk",
        "created": template.get("created", int(time.time())),
        "model": template.get("model", model),
        "choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
    }


class _PassthroughRedactor:
    """Drop-in for StreamRedactor used when PII redaction is disabled:
    echoes each delta immediately, holds nothing, redacts nothing."""

    def feed(self, delta: str) -> list[str]:
        return [delta] if delta else []

    def finish(self) -> tuple[str, dict]:
        return "", {"pii_count": 0}


async def _aiter_list(items) -> AsyncIterator[str]:
    """Adapt a synchronous list of SSE lines to an async iterator."""
    for item in items:
        yield item


async def _governed_sse_stream(lines, redactor, model: str) -> AsyncIterator[str]:
    """Re-emit upstream SSE as governed SSE.

    Content deltas are recomposed and redacted through *redactor* (feed);
    at the upstream's finish chunk the window is flushed (finish) and the
    trailing redacted tail is emitted before the terminal finish marker.
    The stream always ends with ``data: [DONE]``. Role-only and empty
    deltas are dropped; identity fields (id/created/model) are preserved.
    """
    flushed = False
    async for raw in lines:
        stripped = (raw or "").strip()
        if not stripped or stripped == "data: [DONE]":
            continue
        chunk = _parse_sse_data(stripped)
        if chunk is None:
            continue
        content = _delta_content(chunk)
        if content:
            for safe in redactor.feed(content):
                if safe:
                    yield _sse_format(_content_chunk(chunk, safe, model))
        reason = _finish_reason(chunk)
        if reason is not None and not flushed:
            tail, _summary = redactor.finish()
            flushed = True
            if tail:
                yield _sse_format(_content_chunk(chunk, tail, model))
            yield _sse_format(_finish_chunk(chunk, reason, model))
    if not flushed:
        tail, _summary = redactor.finish()
        if tail:
            yield _sse_format(_content_chunk({}, tail, model))
    yield "data: [DONE]\n\n"
