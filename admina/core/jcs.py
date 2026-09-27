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

"""Admina — JSON Canonicalization Scheme (RFC 8785).

:func:`canonicalize` serialises a JSON value to the canonical UTF-8 bytes of
RFC 8785, so that the same data hashes to the same digest in any language:

- no whitespace between tokens;
- object members sorted by their names compared as UTF-16 code units;
- strings with only ``"``, ``\\``, and the control characters U+0000-U+001F
  escaped (``\\b``, ``\\t``, ``\\n``, ``\\f``, ``\\r``, else ``\\u00xx`` in
  lower case); every other character is written as it is;
- numbers in the ECMAScript ``Number.prototype.toString`` form of their
  IEEE 754 double value (``1e+21``, ``0.000001``, ``1e-7``, ``-0`` → ``0``).

Accepted values: ``None``, ``bool``, ``int``, ``float``, ``str``, ``list`` and
``tuple`` (arrays), and ``dict`` with ``str`` keys. ``TypeError`` for any
other type or key; ``ValueError`` for NaN and infinities, for integers that
a double cannot hold exactly, and for strings with unpaired surrogates
(which RFC 8785 does not allow).
"""

from __future__ import annotations

import math
from decimal import Decimal
from json.encoder import encode_basestring
from typing import Any

__all__ = ["canonicalize"]


def canonicalize(value: Any) -> bytes:
    """The RFC 8785 canonical form of *value*, as UTF-8 bytes."""
    parts: list[str] = []
    _write(value, parts)
    return "".join(parts).encode("utf-8")


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, int):
        out.append(_number(_exact_double(value)))
    elif isinstance(value, float):
        out.append(_number(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for position, item in enumerate(value):
            if position:
                out.append(",")
            _write(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"object keys must be strings, not {type(key).__name__}")
            _check_unicode(key)
        out.append("{")
        for position, key in enumerate(sorted(value, key=_utf16_units)):
            if position:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _write(value[key], out)
        out.append("}")
    else:
        raise TypeError(f"{type(value).__name__} is not a JSON value")


def _utf16_units(key: str) -> bytes:
    # Big-endian UTF-16 bytes compare like the sequence of their code units.
    return key.encode("utf-16-be")


def _check_unicode(text: str) -> None:
    # Strict UTF-8 encoding fails exactly on surrogate code points.
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("strings must not contain unpaired surrogates") from None


def _string(text: str) -> str:
    _check_unicode(text)
    # The json module escapes what RFC 8785 escapes, the same way: '"', '\\'
    # and U+0000-U+001F (\b \t \n \f \r, else \u00xx in lower case).
    return encode_basestring(text)


def _exact_double(value: int) -> float:
    """*value* as a double, when a double holds it exactly."""
    try:
        double = float(value)
    except OverflowError as exc:
        raise ValueError(f"integer {value} is out of the range of a double") from exc
    if int(double) != value:
        raise ValueError(f"integer {value} cannot be represented exactly as a double")
    return double


def _number(value: float) -> str:
    """ECMAScript ``Number.prototype.toString`` of *value*."""
    if not math.isfinite(value):
        raise ValueError("NaN and infinities are not JSON numbers")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr() gives the shortest digits that read back as the same double,
    # the digits ECMAScript uses too.
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(map(str, digit_tuple))
    stripped = digits.rstrip("0")
    exponent = int(exponent) + len(digits) - len(stripped)
    digits = stripped
    k = len(digits)
    n = exponent + k  # value = 0.<digits> × 10^n
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * -n + digits
    else:
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        text = f"{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    return sign + text
