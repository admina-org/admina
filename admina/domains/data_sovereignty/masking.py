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

"""Admina — masks of the PII engines.

A placeholder is a mask already in the text: an upper-case name in square
brackets, such as ``[EMAIL]``, ``[IBAN]`` or ``[IP_ADDR]``. The engines never
mask a placeholder again: a detected span that covers one is reduced to the
parts of it outside the placeholders (:func:`outside_placeholders`).
"""

from __future__ import annotations

import re

PLACEHOLDER_RX = re.compile(r"\[[A-Z][A-Z0-9_]*\]")
"""A mask already in the text."""

_WORD_RX = re.compile(r"\w")

Span = tuple[int, int]


def placeholder_spans(text: str) -> list[Span]:
    """The ``(start, end)`` of each placeholder in *text*, in order."""
    if "[" not in text:
        return []
    return [m.span() for m in PLACEHOLDER_RX.finditer(text)]


def outside_placeholders(start: int, end: int, placeholders: list[Span], text: str) -> list[Span]:
    """The parts of ``text[start:end]`` outside *placeholders*, in order.

    Each part is trimmed of surrounding whitespace, and a part without a
    word character is left out: a span that lies inside a placeholder gives
    no part at all, a span without a placeholder gives itself (trimmed).
    """
    parts: list[Span] = []
    position = start
    for p_start, p_end in placeholders:
        if p_end <= position:
            continue
        if p_start >= end:
            break
        parts.append((position, min(p_start, end)))
        position = max(position, p_end)
    if position < end:
        parts.append((position, end))
    kept: list[Span] = []
    for a, b in parts:
        while a < b and text[a].isspace():
            a += 1
        while b > a and text[b - 1].isspace():
            b -= 1
        if a < b and _WORD_RX.search(text, a, b):
            kept.append((a, b))
    return kept
