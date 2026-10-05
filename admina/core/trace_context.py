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

"""Admina — W3C Trace Context (``traceparent`` and ``tracestate``).

:func:`parse_trace_context` reads the trace context of an incoming request,
without OpenTelemetry. A ``traceparent`` is valid when there is exactly one
and it reads ``<version>-<trace-id>-<parent-id>-<flags>`` in lowercase hex
(2, 32, 16 and 2 digits), the version is not ``ff``, neither id is all
zeros, and version ``00`` has nothing after the flags (a later version may
have more fields, after a ``-``). ``tracestate`` counts only with a valid
``traceparent``; several ``tracestate`` headers are joined with commas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["TraceContext", "parse_trace_context"]

_TRACEPARENT = re.compile(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?")
_LINE_BREAKS = re.compile(r"[\r\n]")


@dataclass(frozen=True)
class TraceContext:
    """A valid W3C trace context."""

    #: The ``traceparent`` value, as received (surrounding whitespace removed).
    traceparent: str
    #: 32 lowercase hex digits.
    trace_id: str
    #: 16 lowercase hex digits: the span of the caller.
    parent_id: str
    #: The trace flags (bit 0: sampled).
    flags: int
    #: The ``tracestate`` value, or None.
    tracestate: str | None = None

    @classmethod
    def of(
        cls, trace_id: str, parent_id: str, flags: int, tracestate: str | None = None
    ) -> TraceContext:
        """The version ``00`` trace context of these ids (lowercase hex)."""
        return cls(f"00-{trace_id}-{parent_id}-{flags:02x}", trace_id, parent_id, flags, tracestate)


def parse_trace_context(traceparents: list[str], tracestates: list[str]) -> TraceContext | None:
    """The trace context of the ``traceparent`` and ``tracestate`` header
    values of a request, or None when there is no valid ``traceparent``."""
    if len(traceparents) != 1:
        return None
    value = traceparents[0].strip()
    match = _TRACEPARENT.fullmatch(value)
    if match is None:
        return None
    version, trace_id, parent_id, flags, rest = match.groups()
    if version == "ff" or (version == "00" and rest is not None):
        return None
    if trace_id == "0" * 32 or parent_id == "0" * 16:
        return None
    states = (_LINE_BREAKS.sub("", v).strip() for v in tracestates)
    state = ",".join(s for s in states if s)
    return TraceContext(
        traceparent=value,
        trace_id=trace_id,
        parent_id=parent_id,
        flags=int(flags, 16),
        tracestate=state or None,
    )
