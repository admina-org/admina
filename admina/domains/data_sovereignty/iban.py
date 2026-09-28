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

"""IBAN matching for the IBAN PII category.

An IBAN is two upper-case letters of a country in :data:`IBAN_LENGTHS`, two
check digits and upper-case letters and digits up to the country's length
(Italy: 27 characters), written compact or with a single space before any
character after the check digits, and not followed by a letter or a digit.
Its ISO 7064 mod-97 checksum must be valid. :data:`IBAN_RX` finds where an
IBAN may start; :func:`iter_iban_matches` reads each one from there with a
regular expression of its country's length, in time linear in ``len(text)``
(at most 67 characters per start).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

# IBAN length of each country of the IBAN registry (ISO 13616).
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
    "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
    "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "YE": 30,
}  # fmt: skip

IBAN_RX = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}[0-9]{2}(?= ?[A-Z0-9])")
"""Where an IBAN may start: a country code and two check digits."""

_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

# The characters after the check digits, for each length: each one after an
# optional single space, then no letter or digit.
_REST_RX: dict[int, re.Pattern[str]] = {
    count: re.compile(rf"(?: ?[A-Z0-9]){{{count}}}(?![^\W_])")
    for count in {length - 4 for length in IBAN_LENGTHS.values()}
}

# Letters as the numbers of the mod-97 check (A = 10, …, Z = 35).
_AS_DIGITS = str.maketrans({chr(code): str(code - 55) for code in range(ord("A"), ord("Z") + 1)})


@dataclass(frozen=True)
class IbanMatch:
    """An IBAN found in a text, with the ``start()``, ``end()`` and
    ``group()`` of a ``re.Match``."""

    _start: int
    _end: int
    _text: str

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def group(self) -> str:
        return self._text


def is_valid_iban(value: str) -> bool:
    """True when *value*, compact or with spaces, has the length of its
    country and a valid mod-97 checksum."""
    compact = value.replace(" ", "")
    length = IBAN_LENGTHS.get(compact[:2])
    if length is None or len(compact) != length or not _CHARS.issuperset(compact):
        return False
    if not compact[2:4].isdigit():
        return False
    return int((compact[4:] + compact[:4]).translate(_AS_DIGITS)) % 97 == 1


def iter_iban_matches(text: str) -> Iterator[IbanMatch]:
    """Yield each IBAN in *text*, in order, without overlaps."""
    last_end = 0
    for candidate in IBAN_RX.finditer(text):
        start = candidate.start()
        if start < last_end:
            continue
        length = IBAN_LENGTHS.get(text[start : start + 2])
        if length is None:
            continue
        rest = _REST_RX[length - 4].match(text, candidate.end())
        if rest is None:
            continue
        end = rest.end()
        value = text[start:end]
        if is_valid_iban(value):
            yield IbanMatch(start, end, value)
            last_end = end
