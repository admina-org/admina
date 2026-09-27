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

"""The outcome of a gateway chat completion: its response headers and its
completion record.

Once a request has its event id, every response carries (see
:meth:`GatewayCall.headers`):

- ``X-Admina-Event-Id``: the ``event_id`` of the call's forensic records;
- ``X-Admina-Action``: the action taken, upper case (``ALLOW`` or
  ``BLOCK``); ``ALLOW`` in ``observe`` and ``dry-run`` mode, with the
  action enforce mode would take in ``X-Admina-Would-Action``;
- ``X-Admina-Risk``: the risk level, upper case;
- ``X-Admina-Categories``: the names of the firewall categories that
  matched, comma-separated (empty when none), never text;
- ``X-Admina-Record-Hash``: the ``record_hash`` of the request record,
  written before the request is forwarded (absent without a forensic store).

The completion record (:func:`completion_record`, ``event_type =
"gateway_response"``) is written once the response has ended. It has the
``event_id`` of the request record and holds hashes, statuses, counts and
names, never text.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

from admina.core.jcs import canonicalize
from admina.core.types import EventType

__all__ = [
    "ACTION_HEADER",
    "CATEGORIES_HEADER",
    "EVENT_ID_HEADER",
    "RECORD_HASH_HEADER",
    "RISK_HEADER",
    "VERSION_HEADER",
    "WOULD_ACTION_HEADER",
    "Delivery",
    "GatewayCall",
    "completion_record",
    "firewall_categories",
    "messages_sha256",
]

EVENT_ID_HEADER = "X-Admina-Event-Id"
ACTION_HEADER = "X-Admina-Action"
WOULD_ACTION_HEADER = "X-Admina-Would-Action"
RISK_HEADER = "X-Admina-Risk"
CATEGORIES_HEADER = "X-Admina-Categories"
RECORD_HASH_HEADER = "X-Admina-Record-Hash"
VERSION_HEADER = "X-Admina-Version"

# Characters kept in a category name; any other becomes "_".
_NOT_NAME = re.compile(r"[^A-Za-z0-9_.:-]")
_NAME_MAX = 64
# A finish_reason value kept in the record.
_FINISH_REASON = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
# An SSE event that may carry a finish_reason or usage.
_MAY_SUMMARISE = re.compile(rb'"finish_reason"\s*:\s*"|"usage"\s*:\s*\{')


def _category(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    return _NOT_NAME.sub("_", name)[:_NAME_MAX] or None


def firewall_categories(verdict: Any) -> tuple[str, ...]:
    """The category names in a firewall result, in order, without
    duplicates: ``patterns[].pattern`` (Python engine, also under
    ``fast_path``) or ``matched_patterns`` (Rust engine). Characters other
    than letters, digits and ``_ . : -`` become ``_``."""
    if not isinstance(verdict, dict):
        return ()
    raw: list[Any] = []
    for source in (verdict, verdict.get("fast_path")):
        patterns = source.get("patterns") if isinstance(source, dict) else None
        if isinstance(patterns, list):
            raw.extend(p.get("pattern") for p in patterns if isinstance(p, dict))
    matched = verdict.get("matched_patterns")
    if isinstance(matched, list):
        raw.extend(matched)
    names = (_category(name) for name in raw)
    return tuple(dict.fromkeys(name for name in names if name))


def messages_sha256(messages: Any) -> str | None:
    """SHA-256 (64 lowercase hex) of the RFC 8785 canonical form of
    *messages*; None when it has none (an unpaired surrogate, an integer
    beyond a double, a value that is not JSON)."""
    try:
        return hashlib.sha256(canonicalize(messages)).hexdigest()
    except (TypeError, ValueError):
        return None


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _usage(value: Any) -> dict | None:
    """The numbers of a ``usage`` object, one level of nesting included."""
    if not isinstance(value, dict):
        return None
    usage: dict[str, Any] = {}
    for key, item in value.items():
        if _number(item):
            usage[key] = item
        elif isinstance(item, dict):
            nested = {k: v for k, v in item.items() if _number(v)}
            if nested:
                usage[key] = nested
    return usage


def _json_object(data: bytes) -> dict | None:
    """*data* parsed as a JSON object, or None."""
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):  # ValueError: JSON and UTF-8 errors
        return None
    return value if isinstance(value, dict) else None


def _first_choice(choices: Any) -> dict | None:
    """The choice with index 0, or at position 0 when it has no index."""
    if not isinstance(choices, list):
        return None
    for position, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        index = choice.get("index", position)
        if index == 0 and not isinstance(index, bool):
            return choice
    return None


class Delivery:
    """The bytes sent to the client: their SHA-256, and the ``finish_reason``
    of the first choice and the ``usage`` they carry.

    A stream goes through :meth:`relay`: each piece is counted once the
    server has taken it (when the next piece is asked for), so that a
    client that goes away is not counted for a piece it did not get. A
    whole body is given to :meth:`body`. Only SSE events and bodies that may
    hold a ``finish_reason`` or a ``usage`` object are parsed.
    """

    def __init__(self) -> None:
        self._sha = hashlib.sha256()
        self.finish_reason: str | None = None
        self.usage: dict | None = None
        #: True once the whole body has been sent (set back to False by the
        #: caller when sending it failed).
        self.completed = False
        #: Class name of an exception raised while streaming, or None.
        self.error: str | None = None

    @property
    def sha256(self) -> str:
        return self._sha.hexdigest()

    def body(self, content: bytes) -> None:
        """A whole (non-streaming) body, sent."""
        self._sha.update(content)
        self.completed = True
        if _MAY_SUMMARISE.search(content):
            self._summarise(_json_object(content))

    async def relay(self, chunks: AsyncIterator[Any]) -> AsyncIterator[Any]:
        """*chunks* (bytes or text), counted as they are sent."""
        try:
            async for chunk in chunks:
                yield chunk
                self._piece(chunk if isinstance(chunk, bytes) else chunk.encode("utf-8"))
        except Exception as exc:
            self.error = type(exc).__name__
            raise
        self.completed = True

    def _piece(self, data: bytes) -> None:
        self._sha.update(data)
        if not _MAY_SUMMARISE.search(data):
            return
        for line in data.splitlines():
            if line.startswith(b"data:"):
                self._summarise(_json_object(line[len(b"data:") :]))

    def _summarise(self, data: dict | None) -> None:
        if data is None:
            return
        choice = _first_choice(data.get("choices"))
        reason = choice.get("finish_reason") if choice is not None else None
        if isinstance(reason, str) and _FINISH_REASON.fullmatch(reason):
            self.finish_reason = reason
        usage = _usage(data.get("usage"))
        if usage is not None:
            self.usage = usage


@dataclass
class GatewayCall:
    """One chat completion, from its request record to its completion record."""

    event_id: str
    #: Name of the upstream route.
    upstream: str
    stream: bool
    #: time.perf_counter() when the request arrived.
    arrived: float
    request_id: str | None = None
    action: str = "ALLOW"
    risk_level: str = "LOW"
    categories: tuple[str, ...] = ()
    would_action: str | None = None
    record_hash: str | None = None
    upstream_status: int | None = None
    #: Class name of the exception that ended the upstream exchange.
    error: str | None = None
    #: The OpenTelemetry span of the call, or None.
    span: Any = None

    def failed(self, exc: BaseException) -> None:
        """The upstream exchange ended with *exc*."""
        self.error = type(exc).__name__

    def headers(self) -> dict[str, str]:
        headers = {
            EVENT_ID_HEADER: self.event_id,
            ACTION_HEADER: self.action,
            RISK_HEADER: self.risk_level,
            CATEGORIES_HEADER: ",".join(self.categories),
        }
        if self.would_action is not None:
            headers[WOULD_ACTION_HEADER] = self.would_action
        if self.record_hash is not None:
            headers[RECORD_HASH_HEADER] = self.record_hash
        return headers


def completion_record(call: GatewayCall, status_code: int, delivery: Delivery) -> dict[str, Any]:
    """The ``gateway_response`` record of *call*, whose response was sent
    with *status_code*. ``cancelled`` is true when the client went away
    before the end of the response; ``error`` is the class name of the
    exception that ended the exchange, if any."""
    error = call.error or delivery.error
    return {
        "event_id": call.event_id,
        "event_type": EventType.GATEWAY_RESPONSE,
        "request_id": call.request_id,
        "method": "chat.completions",
        "upstream": call.upstream,
        "stream": call.stream,
        "action": call.action,
        "status_code": status_code,
        "upstream_status_code": call.upstream_status,
        "finish_reason": delivery.finish_reason,
        "usage": delivery.usage,
        "duration_ms": round((time.perf_counter() - call.arrived) * 1000, 2),
        "response_sha256": delivery.sha256,
        "cancelled": not delivery.completed and error is None,
        "error": error,
    }
