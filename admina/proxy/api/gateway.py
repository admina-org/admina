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
