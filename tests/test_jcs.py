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

"""RFC 8785 (JSON Canonicalization Scheme) serialisation.

The vectors come from RFC 8785: the example of section 3.2.2, the property
sorting example of section 3.2.3 and the number serialisation samples of
appendix B (IEEE 754 bit patterns and their ECMAScript form).
"""

from __future__ import annotations

import json
import struct

import pytest

from admina.core.jcs import canonicalize


def _text(value) -> str:
    return canonicalize(value).decode("utf-8")


# ── Section 3.2.2: whitespace, numbers, strings and literals ──


def test_rfc8785_section_3_2_2_example():
    source = (
        '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
        ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
        ' "literals": [null, true, false]}'
    )
    expected = (
        '{"literals":[null,true,false],'
        '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
    )
    assert _text(json.loads(source)) == expected


def test_output_is_utf8_bytes():
    assert canonicalize({"k": "€"}) == '{"k":"€"}'.encode()


# ── Section 3.2.3: property sorting by UTF-16 code units ──────


def test_rfc8785_section_3_2_3_sorting():
    source = (
        '{"\\u20ac": "Euro Sign", "\\r": "Carriage Return",'
        ' "\\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One",'
        ' "\\ud83d\\ude00": "Emoji: Grinning Face", "\\u0080": "Control",'
        ' "\\u00f6": "Latin Small Letter O With Diaeresis"}'
    )
    keys = list(json.loads(_text(json.loads(source))))
    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


def test_non_bmp_key_sorts_before_high_bmp_key():
    # U+1F600 is D83D DE00 in UTF-16, before U+FB33; code point order differs.
    assert _text({"דּ": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"דּ":1}'


def test_nested_objects_are_sorted_and_arrays_keep_order():
    value = {"b": [3, {"z": 1, "a": 2}, 1], "a": {"y": None, "x": True}}
    assert _text(value) == '{"a":{"x":true,"y":null},"b":[3,{"a":2,"z":1},1]}'


def test_tuple_is_an_array():
    assert _text(("a", 1)) == '["a",1]'


# ── Appendix B: number serialisation ──────────────────────────

_APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def _double(bits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(bits))[0]


@pytest.mark.parametrize(("bits", "expected"), _APPENDIX_B, ids=[b for b, _ in _APPENDIX_B])
def test_rfc8785_appendix_b_numbers(bits, expected):
    assert _text(_double(bits)) == expected


@pytest.mark.parametrize("bits", ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"])
def test_nan_and_infinity_are_rejected(bits):
    with pytest.raises(ValueError):
        canonicalize(_double(bits))


def test_minus_zero_is_zero():
    assert _text(-0.0) == "0"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (10**21, "1e+21"),
        (10**20, "100000000000000000000"),
        (0, "0"),
        (-7, "-7"),
        (2**53, "9007199254740992"),
        # Exactly representable, printed with the shortest digits (as 2**68
        # in appendix B).
        (2**60, "1152921504606847000"),
        (1.5, "1.5"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (123e-20, "1.23e-18"),
        (0.1, "0.1"),
    ],
)
def test_number_forms(value, expected):
    assert _text(value) == expected


def test_integer_not_exactly_representable_is_rejected():
    with pytest.raises(ValueError):
        canonicalize(2**53 + 1)


def test_integer_too_large_for_a_double_is_rejected():
    with pytest.raises(ValueError):
        canonicalize(10**400)


def test_booleans_are_literals_not_numbers():
    assert _text([True, False, None]) == "[true,false,null]"


# ── Strings ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ('"', '"\\""'),
        ("\\", '"\\\\"'),
        ("\b\f\n\r\t", '"\\b\\f\\n\\r\\t"'),
        ("\x00\x1f", '"\\u0000\\u001f"'),
        ("\x7f", '"\x7f"'),
        ("/", '"/"'),
        ("  ", '"  "'),
        ("é€😀", '"é€😀"'),
    ],
)
def test_string_escapes(value, expected):
    assert _text(value) == expected


_TWO_CHARACTER_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _rfc8785_string(text: str) -> str:
    """RFC 8785 section 3.2.2.2, character by character."""
    out = []
    for char in text:
        if char in _TWO_CHARACTER_ESCAPES:
            out.append(_TWO_CHARACTER_ESCAPES[char])
        elif ord(char) < 0x20:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(char)
    return '"' + "".join(out) + '"'


def test_every_latin1_and_special_character_is_serialised_as_rfc8785_says():
    code_points = [*range(0x100), 0x2028, 0x2029, 0xFEFF, 0xFFFF, 0x10FFFF]
    for code_point in code_points:
        for text in (chr(code_point), f"a{chr(code_point)}b{chr(code_point)}"):
            expected = _rfc8785_string(text)
            assert _text(text) == expected, hex(code_point)
            assert _text({text: text}) == "{" + expected + ":" + expected + "}", hex(code_point)


def test_lone_surrogate_is_rejected():
    with pytest.raises(ValueError):
        canonicalize("a\ud800b")


def test_lone_surrogate_in_key_is_rejected():
    with pytest.raises(ValueError):
        canonicalize({"\udc00": 1})


# ── Unsupported input ─────────────────────────────────────────


@pytest.mark.parametrize("value", [{1: "a"}, {("a",): 1}])
def test_non_string_key_is_rejected(value):
    with pytest.raises(TypeError):
        canonicalize(value)


@pytest.mark.parametrize("value", [{1, 2}, b"bytes", object()])
def test_unsupported_type_is_rejected(value):
    with pytest.raises(TypeError):
        canonicalize(value)
