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

"""E-mail matching: ``iter_email_matches`` yields the matches of ``EMAIL_RX``.

The PII redactor and the spaCy + regex PII engine match the EMAIL category
with ``iter_email_matches``; its matches (spans, text, order) equal those of
``EMAIL_RX.finditer`` on every input.
"""

from __future__ import annotations

import asyncio
import functools
import random
import re

import pytest

from admina.domains.data_sovereignty import pii
from admina.domains.data_sovereignty.email_matching import EMAIL_RX, iter_email_matches
from admina.plugins.builtin.pii import spacy_regex

_EXAMPLES = [
    "",
    "no address here",
    "email me at alice.rossi@example.com when you are ready",
    "first@one.org, second@two.net; third@three.io",
    "UPPER@CASE.COM and a+tag@b.cd and %a@b.cd",
    " -foo@bar.com",
    "x-foo@bar.com",
    "--foo@bar.com",
    ".a@b.cd",
    "a.b@c.de.",
    "_a@c.de a_b@c.de",
    "a@b.c",
    "a@b.cc1",
    "a@b.cc-d",
    "a@b.c|c",
    "a@b.cd|",
    "a@b.com.x@y.org",
    "a@b.cc%x@y.org",
    "a@b.cc_x@y.org",
    "a@b@c.de",
    "x@@y.com",
    "@y.com",
    "a@y.com@z.com",
    "a@b.cc@d.ee@f.gg",
    "a@b.cd\nb@c.de",
    "é.x@y.org",
    "éx@y.org",
    "éé.a.b@c.de",
    "٣a@b.cd",
    "a.a.a.a.a@x",
    "a.a.a.a.a@x.y",
    "a." * 50 + "@x.yz",
    "a." * 50 + "@",
    "x@" + "a." * 50,
    "a@" * 50,
    "a.@" * 50,
    "a@b.cc " * 20,
]

# Random texts are made of address-like pieces (local part, "@", domain,
# ".", top-level domain, separator) built from these parts; empty parts and
# separators join neighbouring pieces. "é" and "٣" are word
# characters outside the local-part class; "|" is in the top-level domain
# class.
_LOCAL_PARTS = ("a", "Bc", "9", "_", ".", "-", "%", "+", "é", "٣")
_DOMAIN_PARTS = ("a", "bc", "Xy", "9", ".", "-", "_", "@")
_TLD_CHARS = "abXY|9."
_SEPARATORS = ("", "", " ", ",", "\n", "@", ".", "-", "|", "é", "_", "1")


def _random_text(rng: random.Random) -> str:
    pieces = []
    for _ in range(rng.randint(0, 5)):
        local = "".join(rng.choices(_LOCAL_PARTS, k=rng.randint(0, 4)))
        domain = "".join(rng.choices(_DOMAIN_PARTS, k=rng.randint(0, 3)))
        tld = "".join(rng.choices(_TLD_CHARS, k=rng.randint(0, 3)))
        pieces.append(f"{local}@{domain}.{tld}{rng.choice(_SEPARATORS)}")
    return "".join(pieces)


def _spans(matches) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group()) for m in matches]


def _email_only() -> dict[str, dict]:
    return {name: {**cfg, "enabled": name == "EMAIL"} for name, cfg in pii.PII_CATEGORIES.items()}


@functools.cache
def _regex_only_redactor() -> pii.PIIRedactor:
    redactor = pii.PIIRedactor()
    redactor.nlp = None  # regex categories only
    return redactor


def _regex_only_engine() -> spacy_regex.SpaCyRegexPIIEngine:
    engine = spacy_regex.SpaCyRegexPIIEngine()
    engine._nlp_loaded = True  # regex pass only
    return engine


def test_email_pattern_source():
    assert EMAIL_RX.pattern == r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    assert EMAIL_RX.flags == re.compile("").flags


def test_pii_categories_use_the_email_pattern():
    assert pii.REGEX_PII_PATTERNS["EMAIL"] is EMAIL_RX
    assert spacy_regex._PATTERNS["EMAIL"] is EMAIL_RX


@pytest.mark.parametrize("text", _EXAMPLES)
def test_email_matches_equal_finditer(text):
    assert _spans(iter_email_matches(text)) == _spans(EMAIL_RX.finditer(text))


def test_email_matches_equal_finditer_on_random_texts():
    rng = random.Random(8191)
    with_matches = 0
    for _ in range(20_000):
        text = _random_text(rng)
        expected = _spans(EMAIL_RX.finditer(text))
        assert _spans(iter_email_matches(text)) == expected, repr(text)
        with_matches += bool(expected)
    assert with_matches >= 2_000


def test_email_matches_are_pattern_matches():
    matches = list(iter_email_matches("write to a@b.cd or c@d.ef"))
    assert [m.re for m in matches] == [EMAIL_RX, EMAIL_RX]
    assert [m.group() for m in matches] == ["a@b.cd", "c@d.ef"]


@pytest.mark.parametrize("text", _EXAMPLES)
def test_redactor_email_entities_equal_finditer(text):
    result = _regex_only_redactor().redact(text, categories=_email_only())
    expected = [(m.start(), m.end()) for m in EMAIL_RX.finditer(text)]
    assert [(e["start"], e["end"]) for e in result["entities"]] == expected
    assert result["redacted_text"] == EMAIL_RX.sub("[EMAIL]", text)


@pytest.mark.parametrize("text", _EXAMPLES)
def test_engine_email_matches_equal_finditer(text):
    found = asyncio.run(_regex_only_engine().detect(text, categories=["EMAIL"]))
    assert [(m["start"], m["end"], m["text"]) for m in found] == _spans(EMAIL_RX.finditer(text))
