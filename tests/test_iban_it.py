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

"""IBAN and Italian phone numbers in the spaCy + regex PII engine.

An IBAN is masked when it has its country's length (Italy: 27), written
compact or with single spaces, and a valid ISO 7064 mod-97 checksum. Italian
phone numbers are masked in the usual national and international formats.
Every IBAN and number here is synthetic.
"""

from __future__ import annotations

import pytest

from admina.domains.data_sovereignty import iban as iban_matching
from admina.domains.data_sovereignty.pii import PIIRedactor


def synthetic_iban(country: str, bban: str) -> str:
    """An IBAN of *country* and *bban* with valid check digits."""
    digits = "".join(str(int(c, 36)) for c in bban + country + "00")
    return f"{country}{98 - int(digits) % 97:02d}{bban}"


def spaced(iban: str) -> str:
    return " ".join(iban[i : i + 4] for i in range(0, len(iban), 4))


IT = synthetic_iban("IT", "Z" + "99999" + "99999" + "000000001234")
DE = synthetic_iban("DE", "999999990000001234")
GB = synthetic_iban("GB", "ZZZZ" + "999999" + "00001234")
IT_BAD = IT[:2] + f"{(int(IT[2:4]) + 1) % 100:02d}" + IT[4:]


@pytest.fixture(scope="module")
def regex_only() -> PIIRedactor:
    redactor = PIIRedactor()
    redactor.nlp = None  # the regex categories only
    return redactor


def _masked(redactor: PIIRedactor, text: str) -> str:
    return redactor.redact(text)["redacted_text"]


def test_synthetic_ibans_have_the_country_lengths():
    assert (len(IT), len(DE), len(GB)) == (27, 22, 22)
    assert iban_matching.is_valid_iban(IT)
    assert not iban_matching.is_valid_iban(IT_BAD)


@pytest.mark.parametrize("value", [IT, spaced(IT)], ids=["compact", "spaced"])
def test_italian_iban_is_masked(regex_only, value):
    out = _masked(regex_only, f"bonifico su {value} entro venerdì")
    assert out == "bonifico su [IBAN] entro venerdì"


@pytest.mark.parametrize("value", [IT, spaced(IT)], ids=["compact", "spaced"])
def test_italian_iban_is_masked_by_the_default_engine(value):
    out = PIIRedactor().redact(f"IBAN: {value}")["redacted_text"]
    assert "[IBAN]" in out
    assert not any(group in out for group in spaced(IT).split()[1:])


@pytest.mark.parametrize("value", [IT_BAD, spaced(IT_BAD)], ids=["compact", "spaced"])
def test_iban_with_a_wrong_checksum_is_not_masked(regex_only, value):
    text = f"codice {value} di prova"
    assert _masked(regex_only, text) == text


@pytest.mark.parametrize(
    "value", [DE, spaced(DE), GB, spaced(GB)], ids=["de", "de-spaced", "gb", "gb-spaced"]
)
def test_other_country_lengths(regex_only, value):
    assert _masked(regex_only, f"pay {value} today") == "pay [IBAN] today"


def test_iban_followed_by_more_characters_is_not_masked(regex_only):
    text = f"ref {IT}7 end"
    assert _masked(regex_only, text) == text


def test_two_ibans_one_after_the_other(regex_only):
    out = _masked(regex_only, f"{spaced(IT)} {DE}")
    assert out == "[IBAN] [IBAN]"


def test_iban_matches_have_spans_and_text():
    text = f"a {spaced(IT)} b {GB}."
    found = [(m.start(), m.end(), m.group()) for m in iban_matching.iter_iban_matches(text)]
    start = text.index(GB)
    assert found == [
        (2, 2 + len(spaced(IT)), spaced(IT)),
        (start, start + len(GB), GB),
    ]


def test_iban_with_an_unknown_country_code_is_not_masked(regex_only):
    text = "code QQ12 3456 7890 1234 5678"
    assert _masked(regex_only, text) == text


# ── Italian phone numbers ─────────────────────────────────────


@pytest.mark.parametrize(
    "number",
    [
        "+39 333 123 4567",
        "+39 3331234567",
        "+393331234567",
        "0039 333 1234567",
        "333 1234567",
        "333-123-4567",
        "333 123 4567",
        "3331234567",
        "06 12345678",
        "06 1234 5678",
        "055 123456",
        "055-1234567",
        "055/1234567",
        "+39 06 12345678",
        "+39 055 1234567",
        "+390612345678",
    ],
)
def test_italian_phone_numbers_are_masked(regex_only, number):
    assert _masked(regex_only, f"chiamare il {number} oggi") == "chiamare il [PHONE] oggi"


@pytest.mark.parametrize(
    "text",
    [
        "importo di 3.500.000 euro",
        "scadenza 06/12/2025",
        "scadenza 06-12-2025",
        "CAP 00100",
        "anno 2026, comma 3",
        "pratica 300 000 000",
    ],
)
def test_other_numbers_are_not_phone_numbers(regex_only, text):
    assert _masked(regex_only, text) == text


@pytest.mark.parametrize("number", ["415-555-0132", "+1-555-987-6543", "(212) 555-0188"])
def test_us_phone_numbers_are_still_masked(regex_only, number):
    assert "[PHONE]" in _masked(regex_only, f"call {number} now")


# ── Card numbers and phone numbers ────────────────────────────


def luhn_card(prefix: str) -> str:
    """The 16-digit number of the 15 digits *prefix* and a Luhn check digit."""
    total = 0
    for position, char in enumerate(reversed(prefix)):
        digit = int(char) * (2 if position % 2 == 0 else 1)
        total += digit - 9 if digit > 9 else digit
    return prefix + str(-total % 10)


def card_layouts(card: str) -> dict[str, str]:
    groups = [card[i : i + 4] for i in range(0, 16, 4)]
    return {"spaced": " ".join(groups), "hyphenated": "-".join(groups), "compact": card}


# The second group of each starts like an Italian area code (0 and 1-9).
_CARD_PREFIXES = ["400005665566555", "452601815908301", "510506123456789", "601102055512345"]


@pytest.mark.parametrize("layout", ["spaced", "hyphenated", "compact"])
@pytest.mark.parametrize("prefix", _CARD_PREFIXES)
def test_card_numbers_are_masked_whole(regex_only, prefix, layout):
    card = card_layouts(luhn_card(prefix))[layout]
    assert _masked(regex_only, f"carta {card} ok") == "carta [CREDIT_CARD] ok"


def test_card_numbers_of_any_digits_are_masked_whole(regex_only):
    import random

    rng = random.Random(20260928)
    for _ in range(2000):
        card = luhn_card("".join(rng.choice("0123456789") for _ in range(15)))
        for layout, value in card_layouts(card).items():
            masked = _masked(regex_only, f"carta {value} ok")
            assert masked == "carta [CREDIT_CARD] ok", f"{layout} {value}: {masked}"


def test_card_and_phone_numbers_in_one_text(regex_only):
    card = card_layouts(luhn_card(_CARD_PREFIXES[0]))["spaced"]
    text = f"carta {card}, tel. 055 123456 o 333 1234567"
    assert _masked(regex_only, text) == "carta [CREDIT_CARD], tel. [PHONE] o [PHONE]"


# ── Matching time on long inputs ──────────────────────────────


# A time budget on 64k characters: run with `pytest -m benchmark` (CI runs
# -m "not benchmark"; shared runners vary between runs).
@pytest.mark.benchmark
@pytest.mark.parametrize("unit", ["IT60", "IT60 ", "IT60X", "IT60 X", "A1 ", "1 ", "+39 3"])
def test_matching_time_on_long_runs(regex_only, unit):
    from types import SimpleNamespace

    from admina.domains.agent_security import pattern_timing as pt

    text = (unit * (pt.DEFAULT_SIZE // len(unit) + 1))[: pt.DEFAULT_SIZE]
    matchers = {
        "iban": lambda t: list(iban_matching.iter_iban_matches(t)),
        "redactor": regex_only.redact,
    }
    for name, find in matchers.items():
        ms = pt.search_ms(SimpleNamespace(search=find), text, budget_ms=pt.DEFAULT_BUDGET_MS)
        assert ms <= pt.DEFAULT_BUDGET_MS, f"{name}: {ms:.1f} ms"
