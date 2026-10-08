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
no digit, and at least one word with a capital initial. The English spaCy
model labels lowercase phrases of other languages as PERSON (Italian "il
codice articolo", "la pratica n. 2026/000457"); a name written all in
lowercase is not masked either.
"""

from __future__ import annotations


def is_name_like(text: str) -> bool:
    """True when *text* has no digit and a word that starts with a capital."""
    if any(ch.isdigit() for ch in text):
        return False
    return any(word[:1].isupper() for word in text.split())
