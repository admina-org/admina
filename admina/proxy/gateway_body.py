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

"""The body the gateway forwards upstream for a chat completion.

By default the upstream receives the request body as received, with its
``messages`` as governed (PII redacted when redaction applies). Three
settings, all off by default, change the other top-level fields:

- ``ADMINA_GATEWAY_FORWARD_FIELDS`` lists the fields forwarded
  (comma-separated, case-sensitive; empty = every field). ``model``,
  ``messages`` and ``stream`` are always forwarded, and so are the fields a
  limit that is set applies to; any other field not listed is left out.
- ``ADMINA_GATEWAY_MAX_N`` is the largest ``n`` forwarded (0 = no limit): a
  larger ``n`` is lowered to it. An absent or ``null`` ``n`` is forwarded as
  it is (the upstream's default, one choice).
- ``ADMINA_GATEWAY_MAX_COMPLETION_TOKENS`` is the largest ``max_tokens`` and
  ``max_completion_tokens`` forwarded (0 = no limit): each one that is
  larger is lowered to it. A request that sets neither (absent or ``null``)
  is forwarded with ``max_tokens`` set to it.

While a limit is set, a field it applies to must be absent, ``null`` or an
integer of at least 1 (``true``, ``2.0`` and ``"2"`` are not):
:meth:`ForwardSettings.fields` raises :class:`ForwardedValueError` for any
other value, and the gateway answers 400 before the request is governed.

The settings change the forwarded body only: the firewall scans the request
as received, and the forwarded ``messages``, whose hash is
``request_sha256``, are never changed by them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from typing import Any

__all__ = [
    "ALWAYS_FORWARDED",
    "ForwardSettings",
    "ForwardedValueError",
    "forward_field_names",
]

#: Fields forwarded whatever ``ADMINA_GATEWAY_FORWARD_FIELDS`` lists.
ALWAYS_FORWARDED = frozenset({"model", "messages", "stream"})

_N_FIELD = "n"
_TOKEN_FIELDS = ("max_tokens", "max_completion_tokens")
_FIELD_NAME = re.compile(r"[A-Za-z0-9_-]+")


class ForwardedValueError(ValueError):
    """A field a limit applies to holds a value other than an integer of at
    least 1; :attr:`field` names it."""

    def __init__(self, field: str) -> None:
        super().__init__(f"'{field}' must be an integer of at least 1.")
        self.field = field


@cache
def forward_field_names(value: str) -> tuple[str, ...]:
    """The ``ADMINA_GATEWAY_FORWARD_FIELDS`` names, without duplicates
    (empty = every field). ``ValueError`` for a name that is not made of
    ASCII letters, digits, ``_`` and ``-``."""
    names: list[str] = []
    for item in value.split(","):
        name = item.strip()
        if not name:
            continue
        if not _FIELD_NAME.fullmatch(name):
            raise ValueError(f"ADMINA_GATEWAY_FORWARD_FIELDS: {name!r} is not a field name")
        if name not in names:
            names.append(name)
    return tuple(names)


@dataclass(frozen=True)
class ForwardSettings:
    """The fields forwarded upstream and the limits on them."""

    #: ``ADMINA_GATEWAY_FORWARD_FIELDS`` (empty = every field).
    names: tuple[str, ...] = ()
    #: ``ADMINA_GATEWAY_MAX_N`` (0 = no limit).
    max_n: int = 0
    #: ``ADMINA_GATEWAY_MAX_COMPLETION_TOKENS`` (0 = no limit).
    max_completion_tokens: int = 0

    @classmethod
    def of(cls, cfg: Any) -> ForwardSettings:
        """The settings of *cfg*; off for any it does not have."""
        return cls(
            names=forward_field_names(getattr(cfg, "ADMINA_GATEWAY_FORWARD_FIELDS", "")),
            max_n=getattr(cfg, "ADMINA_GATEWAY_MAX_N", 0),
            max_completion_tokens=getattr(cfg, "ADMINA_GATEWAY_MAX_COMPLETION_TOKENS", 0),
        )

    def fields(self, body: dict) -> dict:
        """The top-level fields of the request *body* forwarded upstream,
        limits applied (a new dict; *body* is not changed).
        :class:`ForwardedValueError` for a value a limit refuses, ``n``
        first."""
        if self.names:
            kept = set(self.names) | ALWAYS_FORWARDED
            if self.max_n:
                kept.add(_N_FIELD)
            if self.max_completion_tokens:
                kept.update(_TOKEN_FIELDS)
            fields = {key: value for key, value in body.items() if key in kept}
        else:
            fields = dict(body)
        if self.max_n:
            _lower(fields, _N_FIELD, self.max_n)
        if self.max_completion_tokens:
            present = [name for name in _TOKEN_FIELDS if fields.get(name) is not None]
            for name in present:
                _lower(fields, name, self.max_completion_tokens)
            if not present:
                fields["max_tokens"] = self.max_completion_tokens
        return fields


def _lower(fields: dict, name: str, limit: int) -> None:
    """Lower the integer *name* of *fields* to *limit*; nothing when it is
    absent or ``null``. :class:`ForwardedValueError` for any other value
    than an integer of at least 1."""
    value = fields.get(name)
    if value is None:
        return
    if type(value) is not int or value < 1:
        raise ForwardedValueError(name)
    if value > limit:
        fields[name] = limit
