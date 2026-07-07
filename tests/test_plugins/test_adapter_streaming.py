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
