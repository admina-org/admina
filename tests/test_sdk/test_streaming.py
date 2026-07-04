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

"""Tests for admina.sdk.streaming.StreamRedactor."""

from __future__ import annotations

import re

import pytest

from admina.sdk.streaming import StreamRedactor


class FakeEmailRedactor:
    """Hermetic PIIBridge: regex email masking, no spaCy, no I/O."""

    _RX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")

    def redact(self, text: str) -> dict:
        ents = [{"type": "EMAIL"} for _ in self._RX.finditer(text)]
        red = self._RX.sub("[EMAIL]", text)
        return {
            "redacted_text": red,
            "count": len(ents),
            "entities": ents,
            "categories": ["EMAIL"] if ents else [],
        }


def _drain(redactor: StreamRedactor, deltas: list[str]) -> str:
    out: list[str] = []
    for d in deltas:
        out.extend(redactor.feed(d))
    tail, _summary = redactor.finish()
    out.append(tail)
    return "".join(out)


def test_window_validation() -> None:
    with pytest.raises(ValueError):
        StreamRedactor(FakeEmailRedactor(), window_chars=0)


def test_short_input_held_until_finish() -> None:
    r = StreamRedactor(FakeEmailRedactor(), window_chars=64)
    # Everything fits inside the window → nothing emitted incrementally.
    assert r.feed("hello ") == []
    assert r.feed("world") == []
    tail, summary = r.finish()
    assert tail == "hello world"
    assert summary == {"pii_count": 0}


def test_empty_stream() -> None:
    r = StreamRedactor(FakeEmailRedactor(), window_chars=8)
    tail, summary = r.finish()
    assert tail == ""
    assert summary == {"pii_count": 0}


def test_reassembled_clean_text_is_lossless() -> None:
    text = "the quick brown fox jumps over the lazy dog again and again"
    r = StreamRedactor(FakeEmailRedactor(), window_chars=8)
    got = _drain(r, list(text))  # one char per feed
    assert got == text
