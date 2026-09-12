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

"""
Admina — Egress Policy — Agent Security domain

Destination-based control over outbound tool calls. The HTTP method is never
consulted: a call is judged by where it goes and whether it carries data,
because a method is an assertion by the resource being evaluated, not a
security boundary.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

__all__ = ["EgressStatus", "EgressIntent", "analyze"]

# Mirrors _MAX_SCAN_DEPTH in admina/domains/governance.py so the egress walk
# and the PII/firewall walk agree on how deep a payload is inspected.
_MAX_SCAN_DEPTH = 6

# Argument names that declare a network destination. Their presence means the
# call is an egress attempt even when the value cannot be resolved.
_NETWORK_KEYS = frozenset(
    {
        "url",
        "uri",
        "host",
        "hostname",
        "endpoint",
        "address",
        "server",
        "target",
        "base_url",
        "api_url",
        "webhook",
    }
)

# A hostname with at least one dot and an alphabetic TLD. Deliberately strict:
# a false negative here downgrades to UNRESOLVABLE (denied in enforce) when the
# value sits under a network key, which is the safe direction.
_HOST_RX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\."
    r"[A-Za-z]{2,63}$"
)

# Argument names that carry a request payload by convention.
_PAYLOAD_KEYS = frozenset({"body", "data", "payload", "json", "content", "text", "params"})

# A free-form string at or above this length, sitting beside a destination, is
# treated as a payload. Below it, values look like flags and settings.
_PAYLOAD_MIN_CHARS = 16

# Remote annotations. Recorded, never trusted: see the module docstring.
_REMOTE_HINT_KEYS = frozenset({"readonlyhint", "read_only_hint"})


class EgressStatus(str, Enum):
    """Whether the call is an egress attempt, and whether its target is known."""

    NO_EGRESS = "no_egress"
    RESOLVED = "resolved"
    UNRESOLVABLE = "unresolvable"


@dataclass
class EgressIntent:
    """What a single tool call is trying to reach, and whether it carries data."""

    status: EgressStatus = EgressStatus.NO_EGRESS
    destinations: list[str] = field(default_factory=list)
    write_shaped: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)


def _host_from_string(value: str) -> str | None:
    """Return a normalised host for a URL, bare hostname or IP literal."""
    v = value.strip()
    if not v:
        return None
    if "://" in v:
        host = urlsplit(v).hostname
        return host.lower() if host else None
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if _HOST_RX.match(v):
        return v.lower()
    return None


def _walk(
    obj: Any,
    depth: int,
    hosts: list[str],
    network_keys: list[str],
    unresolved: list[str],
) -> None:
    if depth > _MAX_SCAN_DEPTH:
        return
    if isinstance(obj, str):
        host = _host_from_string(obj)
        if host and host not in hosts:
            hosts.append(host)
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in _NETWORK_KEYS:
                network_keys.append(key)
                if not (isinstance(value, str) and _host_from_string(value)):
                    unresolved.append(key)
            _walk(value, depth + 1, hosts, network_keys, unresolved)
        return
    if isinstance(obj, list):
        for item in obj:
            _walk(item, depth + 1, hosts, network_keys, unresolved)


def _classify_write_shaped(obj: Any, depth: int, hosts: list[str]) -> str | None:
    """Return the reason the call is payload-bearing, or None."""
    if depth > _MAX_SCAN_DEPTH:
        return None
    if isinstance(obj, str):
        if _host_from_string(obj):
            query = urlsplit(obj).query if "://" in obj else ""
            return "url query string" if query else None
        if len(obj.strip()) >= _PAYLOAD_MIN_CHARS:
            return "free-form payload value"
        return None
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in _PAYLOAD_KEYS and value:
                return f"payload field {key!r}"
            reason = _classify_write_shaped(value, depth + 1, hosts)
            if reason:
                return reason
        return None
    if isinstance(obj, list):
        for item in obj:
            reason = _classify_write_shaped(item, depth + 1, hosts)
            if reason:
                return reason
    return None


def _remote_hint(obj: Any, depth: int = 0) -> bool | None:
    if depth > _MAX_SCAN_DEPTH:
        return None
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.lower().replace("-", "_") in _REMOTE_HINT_KEYS:
                return bool(value)
            found = _remote_hint(value, depth + 1)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _remote_hint(item, depth + 1)
            if found is not None:
                return found
    return None


def analyze(
    params: Any,
    tool_name: str = "",
    read_only_tools: frozenset[str] = frozenset(),
) -> EgressIntent:
    """Characterise the outbound intent of a tool call in a single pass."""
    hosts: list[str] = []
    network_keys: list[str] = []
    unresolved: list[str] = []
    _walk(params, 0, hosts, network_keys, unresolved)

    if unresolved:
        status = EgressStatus.UNRESOLVABLE
    elif hosts:
        status = EgressStatus.RESOLVED
    elif network_keys:
        status = EgressStatus.UNRESOLVABLE
    else:
        status = EgressStatus.NO_EGRESS

    evidence: dict[str, Any] = {}
    if unresolved:
        evidence["unresolvable_fields"] = sorted(set(unresolved))

    hint = _remote_hint(params)
    if hint is not None:
        evidence["remote_read_only_hint"] = hint

    write_shaped = False
    if status is not EgressStatus.NO_EGRESS:
        if tool_name and tool_name in read_only_tools:
            evidence["write_shaped_reason"] = "read_only_tools override"
        else:
            reason = _classify_write_shaped(params, 0, hosts)
            if reason:
                write_shaped = True
                evidence["write_shaped_reason"] = reason

    return EgressIntent(
        status=status,
        destinations=hosts,
        write_shaped=write_shaped,
        evidence=evidence,
    )
