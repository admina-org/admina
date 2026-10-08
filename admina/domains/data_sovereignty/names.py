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


"""Whether a PERSON entity of an NER model reads as a name.

The PII engines mask a PERSON entity only when :func:`is_name_like` holds:
no digit or character that a name does not hold (``@ / \\ _ # : =``, as in
an e-mail address or a path), and no lowercase word that is a stop word of English, Italian,
German, French, Spanish or Portuguese (the stop-word lists of spaCy, without
the words that are also first names, such as "will", "may" and "sara"). The
English spaCy model labels phrases as PERSON ("il codice articolo", "ci
vediamo domani", "das Wetter", "grab a coffee"); they hold such words.
Names written in lowercase pass ("mario rossi"), and capitalised words are
not checked ("Sara", "Il Signore").
"""

from __future__ import annotations

import functools
import importlib

# The stop-word lists of spaCy whose lowercase words reject a PERSON span.
_STOP_WORD_LANGUAGES = ("en", "it", "de", "fr", "es", "pt")

# Characters of e-mail addresses, paths and identifiers, not of names.
_NOT_IN_NAMES = frozenset("@/\\_#:=")

# Stripped from both ends of a word before the comparison.
_PUNCTUATION = ".,;:!?\"'()[]«»“”‘’"

# Words of those lists that are also first names.
_FIRST_NAMES = frozenset({"ali", "may", "mia", "sara", "will"})


@functools.cache
def _stop_words() -> frozenset[str]:
    """The stop words of :data:`_STOP_WORD_LANGUAGES`, without
    :data:`_FIRST_NAMES`; empty without spaCy (no NER runs then)."""
    words: set[str] = set()
    for lang in _STOP_WORD_LANGUAGES:
        try:
            module = importlib.import_module(f"spacy.lang.{lang}.stop_words")
        except ImportError:
            return frozenset()
        words |= module.STOP_WORDS
    return frozenset(words - _FIRST_NAMES)


def is_name_like(text: str) -> bool:
    """True when *text* has a word, no digit nor character of
    :data:`_NOT_IN_NAMES`, and no lowercase word that is a stop word of
    English, Italian, German, French, Spanish or Portuguese."""
    words = text.split()
    if not words or any(ch.isdigit() or ch in _NOT_IN_NAMES for ch in text):
        return False
    stop = _stop_words()
    bare = (word.strip(_PUNCTUATION) for word in words)
    return not any(word in stop for word in bare if word.islower())
