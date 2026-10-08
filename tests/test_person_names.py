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


"""A PERSON entity of an NER model is masked only when it reads as a name:
no digit, and at least one word with a capital initial.

The English spaCy model labels lowercase Italian phrases as PERSON ("il
codice articolo", "la pratica n. 2026/000457"); such spans are not masked,
by the PII redactor, the spaCy + regex engine and the Presidio engine.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from admina.domains.data_sovereignty.names import is_name_like
from admina.domains.data_sovereignty.pii import PIIRedactor


@pytest.mark.parametrize(
    "text",
    ["Mario Rossi", "John Smith", "il signor Rossi", "O'Brien", "JOHN"],
)
def test_names(text):
    assert is_name_like(text)


@pytest.mark.parametrize(
    "text",
    ["il codice articolo", "la pratica n. 2026/000457", "John 3", "", "  "],
)
def test_not_names(text):
    assert not is_name_like(text)


class _Nlp:
    """Labels each given phrase of the text as PERSON."""

    def __init__(self, *phrases: str) -> None:
        self.phrases = phrases

    def __call__(self, text: str) -> SimpleNamespace:
        ents = []
        for phrase in self.phrases:
            start = text.find(phrase)
            if start >= 0:
                ents.append(
                    SimpleNamespace(
                        start_char=start,
                        end_char=start + len(phrase),
                        text=phrase,
                        label_="PERSON",
                    )
                )
        return SimpleNamespace(ents=ents)


def test_the_redactor_masks_names_only():
    redactor = PIIRedactor()
    redactor.nlp = _Nlp("il codice articolo", "Mario Rossi")
    out = redactor.redact("il codice articolo AB-12 è di Mario Rossi")
    assert out["redacted_text"] == "il codice articolo AB-12 è di [PERSON]"


def test_the_spacy_regex_engine_reports_names_only():
    from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

    engine = SpaCyRegexPIIEngine()
    engine._nlp, engine._nlp_loaded = _Nlp("il codice articolo", "Mario Rossi"), True
    found = asyncio.run(engine.detect("il codice articolo AB-12 è di Mario Rossi"))
    assert [(m["type"], m["text"]) for m in found] == [("PERSON", "Mario Rossi")]
