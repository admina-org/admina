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

"""BaseModelAdapter.send_stream default fallback."""

from __future__ import annotations

import asyncio
from typing import Any

from admina.plugins.base import BaseModelAdapter


class _OnlySend(BaseModelAdapter):
    name = "only-send"

    async def send(self, prompt: str, context: Any = None, **kwargs: Any) -> dict:
        return {"text": f"echo:{prompt}", "metadata": {"tokens": 3}}

    def supports_model(self, model_name: str) -> bool:
        return True


def test_fallback_yields_single_send_chunk() -> None:
    async def _collect() -> list[str]:
        out: list[str] = []
        async for c in _OnlySend().send_stream("hi"):
            out.append(c)
        return out

    assert asyncio.run(_collect()) == ["echo:hi"]


def test_fallback_forwards_context_and_kwargs() -> None:
    class _Recorder(_OnlySend):
        seen: dict = {}

        async def send(self, prompt: str, context: Any = None, **kwargs: Any) -> dict:
            _Recorder.seen = {"context": context, "kwargs": kwargs}
            return {"text": "ok", "metadata": {}}

    async def _run() -> None:
        async for _ in _Recorder().send_stream("p", context="sys", model="m"):
            pass

    asyncio.run(_run())
    assert _Recorder.seen == {"context": "sys", "kwargs": {"model": "m"}}
