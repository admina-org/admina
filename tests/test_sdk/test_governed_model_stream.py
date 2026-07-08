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

"""Tests for GovernedModel.stream()."""

from __future__ import annotations

import asyncio
from typing import Any

from admina.sdk.governed_model import GovernedModel


class StreamMock:
    """Adapter that streams a fixed list of deltas."""

    name = "stream-mock"

    def __init__(self, deltas: list[str]) -> None:
        self._deltas = deltas
        self.stream_called = False

    async def send(self, prompt: str, context: Any = None, **kwargs: Any) -> dict:
        return {"text": "".join(self._deltas), "metadata": {}}

    async def send_stream(self, prompt: str, context: Any = None, **kwargs: Any):
        self.stream_called = True
        for d in self._deltas:
            yield d

    def supports_model(self, model_name: str) -> bool:
        return True


def _collect(model: GovernedModel, prompt: str) -> list[str]:
    async def _run() -> list[str]:
        out: list[str] = []
        async for c in model.stream(prompt):
            out.append(c)
        return out

    return asyncio.run(_run())


def test_stream_yields_deltas_and_reassembles() -> None:
    adapter = StreamMock(["Hello ", "streamed ", "world"])
    model = GovernedModel(
        "m", adapter=adapter, audit=False, firewall_enabled=False, pii_redaction=False
    )
    out = _collect(model, "hi")
    assert adapter.stream_called is True
    assert "".join(out) == "Hello streamed world"


def test_last_stream_result_shape_and_action_allow() -> None:
    adapter = StreamMock(["ok"])
    model = GovernedModel(
        "gpt-x", adapter=adapter, audit=False, firewall_enabled=False, pii_redaction=False
    )
    _collect(model, "hi")
    r = model.last_stream_result
    assert set(r) == {
        "action",
        "pii_count",
        "model",
        "input_tokens",
        "output_tokens",
        "finish_reason",
        "time_to_first_token_ms",
        "duration_ms",
    }
    assert r["action"] == "ALLOW"
    assert r["pii_count"] == 0
    assert r["model"] == "gpt-x"
    assert r["time_to_first_token_ms"] is not None
    assert r["duration_ms"] >= 0


def test_no_adapter_raises() -> None:
    model = GovernedModel("m", adapter=None, pii_redaction=False)

    async def _run() -> None:
        async for _ in model.stream("hi"):
            pass

    try:
        asyncio.run(_run())
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "No model adapter configured" in str(exc)
