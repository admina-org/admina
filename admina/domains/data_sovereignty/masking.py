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
space around it and its final punctuation. Splitting a text takes time
linear in its length, and extending a span to its sentences time
logarithmic in their number.

A placeholder is a mask of Admina already in the text: the ``mask`` of a
category of :data:`admina.domains.data_sovereignty.pii.PII_CATEGORIES` (such
as ``[EMAIL]``, ``[IBAN]``, ``[IP_ADDR]`` or ``[LOCATION]``), a category name
in square brackets (``[IP_ADDRESS]``, ``[GPE]``, …) or ``[OMISSIS]``
(:func:`placeholder_pattern`). Other text in square brackets is text like
any other. The engines never mask a placeholder again: a detected span that
covers one is reduced to the parts of it outside the placeholders
(:func:`outside_placeholders`).
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections.abc import Collection, Iterable
from functools import cache
from itertools import accumulate
from operator import itemgetter

MASK_STYLES = ("typed", "omissis")
"""The values of ``ADMINA_PII_MASK_STYLE``; the first is the default."""

OMISSIS = "[OMISSIS]"
"""The mask of every span in the ``omissis`` style."""


@cache
def placeholder_pattern() -> re.Pattern[str]:
    """The placeholders (see the module documentation) as one alternation
    of literal strings, built at the first call."""
    # pii imports this module: its categories are read at the first call.
    from admina.domains.data_sovereignty.pii import PII_CATEGORIES

    masks = {OMISSIS}
    for category, config in PII_CATEGORIES.items():
        masks.add(config["mask"])
        masks.add(f"[{category}]")
    return re.compile("|".join(re.escape(mask) for mask in sorted(masks)))


# The end of a sentence: a line break, with the white space after it; or a
# run of final punctuation with any closing quotes and brackets, then white
# space with a line break, or white space before a character that is not
# white space (group 1, after any opening quotes and brackets), where the
# caller ends the sentence when that character is upper case. A run of final
# punctuation is matched from its first character only and every quantifier
# is possessive, so matching takes time linear in the length of the text.
_SENTENCE_END_RX = re.compile(
    r"\n\s*+"
    r"|(?<![.!?…])[.!?…]++[\"'»”’)\]]*+"
    r"(?:[^\S\n]*+\n\s*+|\s++(?=[\"'«“‘(\[]*+(\S)))"
)
_FINAL_PUNCTUATION = ".!?…"

_WORD_RX = re.compile(r"\w")

Span = tuple[int, int]

_END = itemgetter(1)


def placeholder_spans(text: str) -> list[Span]:
    """The ``(start, end)`` of each placeholder in *text*, in order."""
    if "[" not in text:
        return []
    return [m.span() for m in placeholder_pattern().finditer(text)]


def outside_placeholders(start: int, end: int, placeholders: list[Span], text: str) -> list[Span]:
    """The parts of ``text[start:end]`` outside *placeholders* (the spans of
    :func:`placeholder_spans`: in order, not overlapping), in order.

    Each part is trimmed of surrounding whitespace, and a part without a
    word character is left out: a span that lies inside a placeholder gives
    no part at all, a span without a placeholder gives itself (trimmed).
    """
    parts: list[Span] = []
    position = start
    # From the first placeholder that ends after start.
    index = bisect_right(placeholders, start, key=_END)
    while index < len(placeholders):
        p_start, p_end = placeholders[index]
        if p_start >= end:
            break
        parts.append((position, min(p_start, end)))
        position = max(position, p_end)
        index += 1
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


def replace_spans(text: str, spans: Iterable[tuple[int, int, str]]) -> str:
    """*text* with each ``(start, end, mask)`` of *spans* (in order, not
    overlapping) replaced by its mask, built in one pass: in time linear in
    the length of *text* and of the masks."""
    out: list[str] = []
    position = 0
    for start, end, mask in spans:
        out.append(text[position:start])
        out.append(mask)
        position = end
    out.append(text[position:])
    return "".join(out)


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
        following = end_mark.group(1)
        if following is not None and not following.isupper():
            continue
        _add_sentence(spans, text, start, end_mark.start())
        start = end_mark.end()
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
    sentences it overlaps (*sentences*, in any order, by default
    :func:`sentence_spans`, each trimmed of white space): from the first
    start to the last end among them. Overlapping spans become one mask."""
    ranges: list[Span] = []
    index: _SentenceIndex | None = None
    for start, end, category in spans:
        if category in sentence_categories:
            if index is None:
                source = sentence_spans(text) if sentences is None else sentences
                index = _SentenceIndex([t for s in source if (t := _trimmed(text, *s)) is not None])
            start, end = index.extended(start, end)
        ranges.append((start, end))
    out: list[str] = []
    position = 0
    for start, end in _merged(ranges):
        out.append(text[position:start])
        out.append(OMISSIS)
        position = end
    out.append(text[position:])
    return "".join(out)


class _SentenceIndex:
    """Sentences sorted by start, searched in logarithmic time."""

    def __init__(self, sentences: list[Span]) -> None:
        ordered = sorted(sentences)
        self._starts = [a for a, _b in ordered]
        # The furthest end among the sentences up to each one.
        self._reach = list(accumulate((b for _a, b in ordered), max))

    def extended(self, start: int, end: int) -> Span:
        """``(start, end)`` extended to the sentences it overlaps."""
        first = bisect_right(self._reach, start)  # the first that ends after start
        stop = bisect_left(self._starts, end)  # the sentences before it start before end
        if first >= stop:
            return start, end
        return min(start, self._starts[first]), max(end, self._reach[stop - 1])


def _merged(ranges: list[Span]) -> list[Span]:
    merged: list[Span] = []
    for start, end in sorted(ranges):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
