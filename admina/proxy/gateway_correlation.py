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

"""Correlation of the gateway's chat completions with the caller's request.

- ``ADMINA_GATEWAY_REQUEST_ID_HEADER`` names the header whose value is
  recorded as ``request_id`` (:func:`request_id_of`);
- ``ADMINA_GATEWAY_RECORD_HEADERS`` lists the headers recorded in
  ``context``, lower-case name to value (:func:`context_of`);
- ``ADMINA_GATEWAY_FORWARD_HEADERS`` lists the headers forwarded upstream
  (:func:`forwarded_headers`): ``traceparent`` and ``tracestate`` only with a
  valid trace context (:mod:`admina.core.trace_context`), any other header
  as received.

Recorded values lose CR and LF and surrounding whitespace, and keep at most
128 characters. Credentials (``Authorization``, ``Proxy-Authorization``,
``Cookie``, ``X-API-Key``) can be neither recorded nor forwarded; the
headers of the connection and of the body, and ``X-Admina-*``, cannot be
forwarded (the gateway sets its own).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import cache
from typing import Any

from admina.core.trace_context import TraceContext, parse_trace_context

__all__ = [
    "HEADER_VALUE_MAX",
    "context_of",
    "forward_header_names",
    "forwarded_headers",
    "record_header_names",
    "request_id_header_name",
    "request_id_of",
    "trace_context_of",
]

#: Longest recorded header value, in characters.
HEADER_VALUE_MAX = 128

# An HTTP field name (RFC 9110 token).
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_LINE_BREAKS = re.compile(r"[\r\n]")

_CREDENTIALS = frozenset({"authorization", "proxy-authorization", "cookie", "x-api-key"})
_NOT_FORWARDED = _CREDENTIALS | {
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
    "content-length",
    "content-type",
    "content-encoding",
}
_ADMINA_PREFIX = "x-admina-"


def _header_names(
    value: str, setting: str, refused: frozenset[str], prefix: str | None = None
) -> tuple[str, ...]:
    names: list[str] = []
    for item in value.split(","):
        name = item.strip().lower()
        if not name:
            continue
        if not _TOKEN.fullmatch(name):
            raise ValueError(f"{setting}: {item.strip()!r} is not a header name")
        if name in refused or (prefix is not None and name.startswith(prefix)):
            raise ValueError(f"{setting}: {name!r} cannot be listed")
        if name not in names:
            names.append(name)
    return tuple(names)


@cache
def request_id_header_name(value: str) -> str:
    """The ``ADMINA_GATEWAY_REQUEST_ID_HEADER`` name, lower case ("" = none).
    ``ValueError`` for a list, an invalid name or a credential."""
    names = _header_names(value, "ADMINA_GATEWAY_REQUEST_ID_HEADER", _CREDENTIALS)
    if len(names) > 1:
        raise ValueError("ADMINA_GATEWAY_REQUEST_ID_HEADER names one header")
    return names[0] if names else ""


@cache
def record_header_names(value: str) -> tuple[str, ...]:
    """The ``ADMINA_GATEWAY_RECORD_HEADERS`` names, lower case, without
    duplicates. ``ValueError`` for an invalid name or a credential."""
    return _header_names(value, "ADMINA_GATEWAY_RECORD_HEADERS", _CREDENTIALS)


@cache
def forward_header_names(value: str) -> tuple[str, ...]:
    """The ``ADMINA_GATEWAY_FORWARD_HEADERS`` names, lower case, without
    duplicates. ``ValueError`` for an invalid name, a credential, a header
    of the connection or of the body, or an ``X-Admina-*`` header."""
    return _header_names(value, "ADMINA_GATEWAY_FORWARD_HEADERS", _NOT_FORWARDED, _ADMINA_PREFIX)


def _recorded(value: str) -> str:
    return _LINE_BREAKS.sub("", value).strip()[:HEADER_VALUE_MAX]


def _joined(headers: Any, name: str) -> str | None:
    values = headers.getlist(name)
    return ", ".join(values) if values else None


def request_id_of(headers: Any, name: str) -> str | None:
    """The request id: the value of header *name*, recorded form; None when
    no header is configured, or the request has none (or an empty one)."""
    if not name:
        return None
    value = headers.get(name)
    return (_recorded(value) or None) if value is not None else None


def context_of(headers: Any, names: Iterable[str]) -> dict[str, str]:
    """The headers of *names* that the request has, name to recorded value."""
    context: dict[str, str] = {}
    for name in names:
        value = _joined(headers, name)
        if value is not None:
            context[name] = _recorded(value)
    return context


def trace_context_of(headers: Any) -> TraceContext | None:
    """The request's W3C trace context, or None."""
    return parse_trace_context(headers.getlist("traceparent"), headers.getlist("tracestate"))


def forwarded_headers(
    headers: Any, names: Iterable[str], trace: TraceContext | None
) -> dict[str, str]:
    """The headers of *names* to send upstream: *trace* for ``traceparent``
    and ``tracestate`` (nothing without it), the request's values (without
    CR and LF) for the others."""
    out: dict[str, str] = {}
    for name in names:
        if name == "traceparent":
            value = trace.traceparent if trace is not None else None
        elif name == "tracestate":
            value = trace.tracestate if trace is not None else None
        else:
            joined = _joined(headers, name)
            value = _LINE_BREAKS.sub("", joined) if joined is not None else None
        if value:
            out[name] = value
    return out
