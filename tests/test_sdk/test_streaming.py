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


def test_head_emitted_once_window_exceeded() -> None:
    r = StreamRedactor(FakeEmailRedactor(), window_chars=4)
    # 5 chars > window(4): the leading char(s) beyond the trailing window emit.
    emitted = r.feed("abcde")
    assert emitted == ["a"]  # last 4 raw chars ("bcde") stay pending
    tail, _ = r.finish()
    assert tail == "bcde"


def test_lag_is_about_one_window() -> None:
    r = StreamRedactor(FakeEmailRedactor(), window_chars=4)
    out: list[str] = []
    for ch in "hello world":  # 11 chars
        out.extend(r.feed(ch))
    # At most the last `window` chars remain unemitted before finish().
    assert len("".join(out)) >= 11 - 4
    tail, _ = r.finish()
    assert "".join(out) + tail == "hello world"


def test_pii_wholly_inside_stream_is_redacted_and_counted() -> None:
    r = StreamRedactor(FakeEmailRedactor(), window_chars=8)
    text = "reach me at bob@corp.io later today please"
    out: list[str] = []
    for ch in text:
        out.extend(r.feed(ch))
    tail, summary = r.finish()
    result = "".join(out) + tail
    assert "bob@corp.io" not in result
    assert "[EMAIL]" in result
    assert summary["pii_count"] == 1


def test_pii_count_zero_when_clean() -> None:
    r = StreamRedactor(FakeEmailRedactor(), window_chars=8)
    for ch in "no personal data here at all":
        r.feed(ch)
    _tail, summary = r.finish()
    assert summary["pii_count"] == 0


def test_email_split_across_deltas_is_redacted() -> None:
    # The canonical case from the spec: "john.doe@" + "example.com".
    r = StreamRedactor(FakeEmailRedactor(), window_chars=32)
    out: list[str] = []
    out.extend(r.feed("please contact john.doe@"))
    out.extend(r.feed("example.com for access"))
    tail, summary = r.finish()
    result = "".join(out) + tail
    assert "john.doe@example.com" not in result
    assert "[EMAIL]" in result
    assert summary["pii_count"] == 1


def test_boundary_entity_not_emitted_before_complete() -> None:
    # The left half of the email must never leak in an early delta.
    r = StreamRedactor(FakeEmailRedactor(), window_chars=32)
    early = r.feed("mail: alice@")
    assert all("alice@" not in d for d in early)
