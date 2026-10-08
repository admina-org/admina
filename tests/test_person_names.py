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
no digit, and no lowercase word that is a stop word of English, Italian,
German, French, Spanish or Portuguese.

The English spaCy model labels phrases as PERSON ("il codice articolo",
"ci vediamo domani", "das Wetter", "grab a coffee"); such spans are not
masked, by the PII redactor, the spaCy + regex engine and the Presidio
engine. Names written in lowercase are masked.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from admina.domains.data_sovereignty.names import is_name_like
from admina.domains.data_sovereignty.pii import PIIRedactor


@pytest.mark.parametrize(
    "text",
    [
        "Mario Rossi",
        "mario rossi",
        "john smith",
        "giovanni esposito",
        "O'Brien",
        "JOHN",
        "Sara Rossi",
        "sara rossi",  # "sara" is an Italian stop word, kept as a name
        "Mia",
        "will smith",  # "will" is an English stop word, kept as a name
        "Il Signore",  # capitalised words are not checked
    ],
)
def test_names(text):
    assert is_name_like(text)


@pytest.mark.parametrize(
    "text",
    [
        "il codice articolo",
        "la pratica n. 2026/000457",
        "ci vediamo domani",
        "ci vediamo, domani",
        "(il) progetto",
        "ho parlato",
        "das Wetter",
        "il cliente",
        "grab a coffee",
        "email john.doe@example.org",
        "Mario/Rossi",
        "John 3",
        "",
        "  ",
    ],
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


def test_the_redactor_masks_lowercase_names():
    redactor = PIIRedactor()
    redactor.nlp = _Nlp("il cliente", "giovanni esposito")
    out = redactor.redact("il cliente è giovanni esposito")
    assert out["redacted_text"] == "il cliente è [PERSON]"


def test_the_spacy_regex_engine_reports_names_only():
    from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

    engine = SpaCyRegexPIIEngine()
    engine._nlp, engine._nlp_loaded = _Nlp("il codice articolo", "Mario Rossi"), True
    found = asyncio.run(engine.detect("il codice articolo AB-12 è di Mario Rossi"))
    assert [(m["type"], m["text"]) for m in found] == [("PERSON", "Mario Rossi")]
