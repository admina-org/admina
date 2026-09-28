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

Mask styles (``ADMINA_PII_MASK_STYLE``, :data:`MASK_STYLES`):

- ``typed`` (default): each span is replaced by the mask of its type, such
  as ``[EMAIL]`` or ``[PERSON]``.
- ``omissis``: each span is replaced by ``[OMISSIS]``, and the categories an
  engine masks as a whole sentence (``sentence_categories``, such as health
  or judicial data) have their whole sentence replaced
  (:func:`mask_omissis`). No type is left in the text.

Sentences come from the engine, or from :func:`sentence_spans`, a simple
splitter: a sentence ends at a line break, or at ``.``, ``!``, ``?`` or
``…`` followed by white space and an upper-case letter (after opening quotes
or brackets); so an abbreviation followed by a number or a lower-case word
(``art. 9``) does not end a sentence. A sentence span leaves out the white
space around it and its final punctuation.

A placeholder is a mask already in the text: an upper-case name in square
brackets, such as ``[EMAIL]``, ``[IBAN]``, ``[IP_ADDR]`` or ``[OMISSIS]``. The
engines never mask a placeholder again: a detected span that covers one is
reduced to the parts of it outside the placeholders
(:func:`outside_placeholders`).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable

MASK_STYLES = ("typed", "omissis")
"""The values of ``ADMINA_PII_MASK_STYLE``; the first is the default."""

OMISSIS = "[OMISSIS]"
"""The mask of every span in the ``omissis`` style."""

PLACEHOLDER_RX = re.compile(r"\[[A-Z][A-Z0-9_]*\]")
"""A mask already in the text."""

# The end of a sentence: final punctuation with any closing quotes and
# brackets, then white space; or a line break.
_SENTENCE_END_RX = re.compile(r"[.!?…]+[\"'»”’)\]]*\s+|\n")
_OPENING = "\"'«“‘(["
_FINAL_PUNCTUATION = ".!?…"

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


def normalize_mask_style(value: str | None) -> str:
    """*value* as a mask style: case and surrounding space are ignored, and
    None or an empty value is ``typed``.

    Raises:
        ValueError: *value* is not one of :data:`MASK_STYLES`.
    """
    style = (value or "").strip().lower() or MASK_STYLES[0]
    if style not in MASK_STYLES:
        raise ValueError(f"PII mask style must be one of {' | '.join(MASK_STYLES)} (got {value!r})")
    return style


def sentence_spans(text: str) -> list[Span]:
    """The ``(start, end)`` of each sentence of *text*, in order, without
    the white space around it and its final punctuation (see the module
    documentation)."""
    spans: list[Span] = []
    start = 0
    for end_mark in _SENTENCE_END_RX.finditer(text):
        after = end_mark.end()
        if end_mark.group() != "\n":
            following = text[after:].lstrip(_OPENING)[:1]
            if not following.isupper():
                continue
        _add_sentence(spans, text, start, end_mark.start())
        start = after
    _add_sentence(spans, text, start, len(text))
    return spans


def _add_sentence(spans: list[Span], text: str, start: int, end: int) -> None:
    trimmed = _trimmed(text, start, end)
    if trimmed is None:
        return
    a, b = trimmed
    while b > a and text[b - 1] in _FINAL_PUNCTUATION:
        b -= 1
    if a < b:
        spans.append((a, b))


def _trimmed(text: str, start: int, end: int) -> Span | None:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return (start, end) if start < end else None


def mask_omissis(
    text: str,
    spans: Iterable[tuple[int, int, str]],
    *,
    sentence_categories: Collection[str] = (),
    sentences: Iterable[Span] | None = None,
) -> str:
    """*text* with each ``(start, end, category)`` span replaced by
    :data:`OMISSIS`; a span of one of *sentence_categories* extends to the
    sentences it overlaps (*sentences*, by default :func:`sentence_spans`,
    each trimmed of white space). Overlapping spans become one mask."""
    ranges: list[Span] = []
    sentence_list: list[Span] | None = None
    for start, end, category in spans:
        if category in sentence_categories:
            if sentence_list is None:
                source = sentence_spans(text) if sentences is None else sentences
                sentence_list = [t for s in source if (t := _trimmed(text, *s)) is not None]
            covering = [(a, b) for a, b in sentence_list if a < end and start < b]
            if covering:
                start = min(start, covering[0][0])
                end = max(end, covering[-1][1])
        ranges.append((start, end))
    out: list[str] = []
    position = 0
    for start, end in _merged(ranges):
        out.append(text[position:start])
        out.append(OMISSIS)
        position = end
    out.append(text[position:])
    return "".join(out)


def _merged(ranges: list[Span]) -> list[Span]:
    merged: list[Span] = []
    for start, end in sorted(ranges):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
