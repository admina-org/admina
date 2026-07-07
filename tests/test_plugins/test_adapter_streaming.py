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

"""Real send_stream() implementations for the built-in adapters."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from admina.plugins.builtin.adapters.anthropic import AnthropicAdapter
from admina.plugins.builtin.adapters.ollama import OllamaAdapter
from admina.plugins.builtin.adapters.openai import OpenAIAdapter
from admina.plugins.builtin.adapters.vllm import VLLMAdapter


def _openai_chunk(text: str | None) -> SimpleNamespace:
    delta = SimpleNamespace(content=text)
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta)])


class _FakeCompletions:
    def __init__(self, texts: list[str | None]) -> None:
        self._texts = texts

    def create(self, **kwargs: Any):
        assert kwargs.get("stream") is True
        return iter([_openai_chunk(t) for t in self._texts])


class _FakeOpenAIClient:
    def __init__(self, texts: list[str | None]) -> None:
        self.chat = SimpleNamespace(completions=_FakeCompletions(texts))


def _collect_openai(texts: list[str | None]) -> list[str]:
    adapter = OpenAIAdapter(default_model="gpt-4o")
    adapter._client = _FakeOpenAIClient(texts)

    async def _run() -> list[str]:
        out: list[str] = []
        async for d in adapter.send_stream("hi"):
            out.append(d)
        return out

    return asyncio.run(_run())


def test_openai_send_stream_yields_text_deltas() -> None:
    assert _collect_openai(["Hel", "lo ", "world"]) == ["Hel", "lo ", "world"]


def test_openai_send_stream_skips_empty_content() -> None:
    # A trailing chunk with content=None (finish frame) must be dropped.
    assert _collect_openai(["a", None, "b"]) == ["a", "b"]


def test_vllm_send_stream_requires_model() -> None:
    adapter = VLLMAdapter(default_model=None)

    async def _run() -> None:
        async for _ in adapter.send_stream("hi"):
            pass

    with pytest.raises(ValueError):
        asyncio.run(_run())


def test_vllm_send_stream_delegates_when_model_present() -> None:
    adapter = VLLMAdapter(default_model="meta-llama/Llama-3-8B")
    adapter._client = _FakeOpenAIClient(["a", "b"])

    async def _run() -> list[str]:
        out: list[str] = []
        async for d in adapter.send_stream("hi"):
            out.append(d)
        return out

    assert asyncio.run(_run()) == ["a", "b"]


class _FakeOllamaClient:
    def __init__(self, texts: list[str]) -> None:
        self._texts = texts

    def chat(self, **kwargs: Any):
        assert kwargs.get("stream") is True
        return iter([{"message": {"content": t}} for t in self._texts])


def test_ollama_send_stream_yields_message_content() -> None:
    adapter = OllamaAdapter(default_model="llama3.1:8b")
    adapter._client = _FakeOllamaClient(["Ci", "ao"])

    async def _run() -> list[str]:
        out: list[str] = []
        async for d in adapter.send_stream("hi"):
            out.append(d)
        return out

    assert asyncio.run(_run()) == ["Ci", "ao"]


def _anthropic_event(evt_type: str, text: str | None = None) -> SimpleNamespace:
    delta = SimpleNamespace(text=text) if text is not None else SimpleNamespace()
    return SimpleNamespace(type=evt_type, delta=delta)


class _FakeMessages:
    def __init__(self, events: list[SimpleNamespace]) -> None:
        self._events = events

    def create(self, **kwargs: Any):
        assert kwargs.get("stream") is True
        return iter(self._events)


class _FakeAnthropicClient:
    def __init__(self, events: list[SimpleNamespace]) -> None:
        self.messages = _FakeMessages(events)


def test_anthropic_send_stream_yields_content_block_deltas() -> None:
    events = [
        _anthropic_event("message_start"),
        _anthropic_event("content_block_delta", "Hel"),
        _anthropic_event("content_block_delta", "lo"),
        _anthropic_event("message_stop"),
    ]
    adapter = AnthropicAdapter(default_model="claude-3-5-sonnet-20241022")
    adapter._client = _FakeAnthropicClient(events)

    async def _run() -> list[str]:
        out: list[str] = []
        async for d in adapter.send_stream("hi"):
            out.append(d)
        return out

    assert asyncio.run(_run()) == ["Hel", "lo"]


def test_anthropic_send_stream_requires_model() -> None:
    adapter = AnthropicAdapter(default_model=None)

    async def _run() -> None:
        async for _ in adapter.send_stream("hi"):
            pass

    with pytest.raises(ValueError):
        asyncio.run(_run())
