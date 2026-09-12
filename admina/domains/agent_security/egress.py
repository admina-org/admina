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
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from admina.core.types import RiskLevel

__all__ = [
    "EgressStatus",
    "EgressIntent",
    "analyze",
    "EgressDecision",
    "EgressPolicy",
    "resolve_egress_mode",
]

logger = logging.getLogger("admina.egress")

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
# value sits under a network key, which is the safe direction. It is also
# deliberately *not* sufficient on its own: it accepts "notes.txt" and
# "os.path" too, so a scheme-less match only counts under a network key (see
# _host_from_string's allow_bare_host).
_HOST_RX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\."
    r"[A-Za-z]{2,63}$"
)

# A single-label hostname with no dot: Docker/compose service names
# ("redis", "upstream-mcp") and "localhost". Deliberately excludes $, {, },
# and _, so a shell/template placeholder like ${TARGET_ENDPOINT} never
# matches. Used only where the string sits under a network-declaring key
# (see _walk) and, symmetrically, to accept the same shape as an allowlist
# entry (see EgressPolicy._compile_entry) — never inside _host_from_string,
# where a bare English word must not become a "host".
_SINGLE_LABEL_RX = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

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


def _host_from_string(value: str, allow_bare_host: bool = False) -> str | None:
    """Return a normalised host for a URL, IP literal or bare hostname.

    A string carrying ``"://"`` and an IP literal are unambiguous and are
    recognised wherever they appear in the arguments. A scheme-less dotted
    token is not: ``notes.txt``, ``report.docx``, ``users.accounts`` and
    ``os.path`` all satisfy :data:`_HOST_RX`. It is therefore accepted only
    when *allow_bare_host* is set, which :func:`_walk` does solely for values
    sitting under a key in :data:`_NETWORK_KEYS` — the same gate already
    applied to :data:`_SINGLE_LABEL_RX`, and for the same reason: the
    argument name, not the shape of the value, is what declares a
    destination. Without it a local file tool is read as an egress attempt
    and is refused under default-deny.
    """
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
    if allow_bare_host and _HOST_RX.match(v):
        return v.lower()
    return None


def _walk(
    obj: Any,
    depth: int,
    hosts: list[str],
    network_keys: list[str],
    unresolved: list[str],
) -> bool:
    """Collect destinations. Returns True if the walk was cut short by depth.

    A truncated walk means part of the arguments was never inspected, so the
    caller cannot claim the call has no destination — see :func:`analyze`.
    """
    if depth > _MAX_SCAN_DEPTH:
        # Only a string, dict or list could have hidden a destination; an
        # int, float, bool or None could not, so skipping one loses nothing
        # and must not be reported as an incomplete scan.
        return isinstance(obj, str | dict | list)
    if isinstance(obj, str):
        host = _host_from_string(obj)
        if host and host not in hosts:
            hosts.append(host)
        return False
    truncated = False
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in _NETWORK_KEYS:
                network_keys.append(key)
                host = None
                if isinstance(value, str):
                    host = _host_from_string(value, allow_bare_host=True)
                    if host is None and _SINGLE_LABEL_RX.match(value.strip()):
                        host = value.strip().lower()
                if host is None:
                    unresolved.append(key)
                elif host not in hosts:
                    hosts.append(host)
                if isinstance(value, str):
                    # Read in full just above; a string has no children, so
                    # recursing would only risk a spurious depth truncation
                    # when the key itself sat on the last scanned level.
                    continue
            truncated |= _walk(value, depth + 1, hosts, network_keys, unresolved)
        return truncated
    if isinstance(obj, list):
        for item in obj:
            truncated |= _walk(item, depth + 1, hosts, network_keys, unresolved)
    return truncated


def _classify_write_shaped(obj: Any, depth: int) -> str | None:
    """Return the reason the call is payload-bearing, or None."""
    if depth > _MAX_SCAN_DEPTH:
        return None
    if isinstance(obj, str):
        # Bare hostnames are recognised here regardless of the key: the
        # question this function asks is "is this string a payload?", and a
        # dotted token answering "no" only ever makes the call look *less*
        # payload-bearing. That is the conservative direction, and it keeps
        # the write-shaped verdict unchanged by the destination gate above.
        if _host_from_string(obj, allow_bare_host=True):
            query = urlsplit(obj).query if "://" in obj else ""
            return "url query string" if len(query) >= _PAYLOAD_MIN_CHARS else None
        if len(obj.strip()) >= _PAYLOAD_MIN_CHARS:
            return "free-form payload value"
        return None
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in _PAYLOAD_KEYS and value:
                return f"payload field {key!r}"
            reason = _classify_write_shaped(value, depth + 1)
            if reason:
                return reason
        return None
    if isinstance(obj, list):
        for item in obj:
            reason = _classify_write_shaped(item, depth + 1)
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
    """Characterise the outbound intent and payload shape of a tool call."""
    hosts: list[str] = []
    network_keys: list[str] = []
    unresolved: list[str] = []
    truncated = _walk(params, 0, hosts, network_keys, unresolved)

    if unresolved:
        status = EgressStatus.UNRESOLVABLE
    elif hosts:
        status = EgressStatus.RESOLVED
    elif network_keys:
        status = EgressStatus.UNRESOLVABLE
    elif truncated:
        # The walk stopped at _MAX_SCAN_DEPTH with nothing found. "Nothing
        # found" is then a statement about the scan, not about the call, so
        # it cannot be reported as NO_EGRESS — that outcome is the one the
        # policy passes through unconditionally, which would make burying a
        # URL below the depth cap a way to walk past the control entirely.
        # Spec §5.2: an egress attempt whose target cannot be established is
        # denied under enforce, and truncating the scan is one way of
        # failing to establish it.
        status = EgressStatus.UNRESOLVABLE
    else:
        status = EgressStatus.NO_EGRESS

    evidence: dict[str, Any] = {}
    if unresolved:
        evidence["unresolvable_fields"] = sorted(set(unresolved))
    if truncated:
        # Recorded even when a destination *was* found shallower: the
        # operator can then see that the verdict rests on a partial scan.
        evidence["scan_truncated"] = True

    write_shaped = False
    if status is not EgressStatus.NO_EGRESS:
        hint = _remote_hint(params)
        if hint is not None:
            evidence["remote_read_only_hint"] = hint

        if tool_name and tool_name in read_only_tools:
            evidence["write_shaped_reason"] = "read_only_tools override"
        else:
            reason = _classify_write_shaped(params, 0)
            if reason:
                write_shaped = True
                evidence["write_shaped_reason"] = reason

    return EgressIntent(
        status=status,
        destinations=hosts,
        write_shaped=write_shaped,
        evidence=evidence,
    )


@dataclass
class EgressDecision:
    """Outcome of evaluating one EgressIntent against the policy."""

    allowed: bool = True
    reason: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    blocked: list[str] = field(default_factory=list)


class EgressPolicy:
    """Destination allowlist, plus the operator settings the stage reads.

    The policy also holds a quarantine set, but nothing in the shipped
    proxy, SDK or CLI calls :meth:`set_quarantine`: in a real deployment the
    set is always empty and the quarantine branch of :meth:`evaluate` cannot
    fire. It is reserved for a future out-of-band consumer.

    ``read_only_tools`` holds the tool names the operator has declared
    non-mutating. It is carried here rather than looked up per call so the
    pipeline stage reads no configuration on the request path.
    """

    def __init__(
        self,
        allow: list[str],
        quarantine: frozenset[str] = frozenset(),
        read_only_tools: frozenset[str] = frozenset(),
    ) -> None:
        self._exact: set[str] = set()
        self._wildcards: list[str] = []
        self._networks: list[Any] = []
        for entry in allow:
            self._compile_entry(entry)
        self._quarantine = quarantine
        self.read_only_tools = read_only_tools

    def _compile_entry(self, entry: str) -> None:
        value = (entry or "").strip().lower()
        if not value:
            return
        if value.startswith("*."):
            suffix = value[2:]
            if suffix:
                self._wildcards.append(suffix)
            return
        if "/" in value:
            try:
                self._networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                logger.warning("Skipping malformed egress CIDR %r", entry)
            return
        try:
            self._exact.add(str(ipaddress.ip_address(value)))
            return
        except ValueError:
            pass
        if _HOST_RX.match(value) or _SINGLE_LABEL_RX.match(value):
            self._exact.add(value)
        else:
            logger.warning("Skipping malformed egress allow entry %r", entry)

    def set_quarantine(self, hosts: frozenset[str]) -> None:
        """Replace the quarantine set. Called by the out-of-band refresh."""
        self._quarantine = hosts

    def _is_allowed(self, host: str) -> bool:
        if host in self._exact:
            return True
        for suffix in self._wildcards:
            if host.endswith("." + suffix):
                return True
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def evaluate(self, intent: EgressIntent, mode: str) -> EgressDecision:
        """Decide on one call. ``mode`` is "observe" or "enforce"."""
        enforcing = mode == "enforce"

        if intent.status is EgressStatus.NO_EGRESS:
            return EgressDecision(allowed=True)

        if intent.status is EgressStatus.UNRESOLVABLE:
            fields = intent.evidence.get("unresolvable_fields", [])
            if fields:
                reason = f"unresolvable destination in {fields}"
            elif intent.evidence.get("scan_truncated"):
                reason = "unresolvable destination: arguments nested past the scan depth limit"
            else:
                reason = "unresolvable destination in arguments"
            return EgressDecision(
                allowed=not enforcing,
                reason=reason,
                risk_level=RiskLevel.HIGH,
                blocked=[],
            )

        quarantined = [h for h in intent.destinations if h in self._quarantine]
        if quarantined and intent.write_shaped:
            return EgressDecision(
                allowed=not enforcing,
                reason="destination quarantined for writes",
                risk_level=RiskLevel.CRITICAL,
                blocked=quarantined,
            )

        unlisted = [h for h in intent.destinations if not self._is_allowed(h)]
        if unlisted:
            return EgressDecision(
                allowed=not enforcing,
                reason="destination not on the egress allowlist",
                risk_level=RiskLevel.HIGH,
                blocked=unlisted,
            )

        return EgressDecision(allowed=True)


_VALID_EGRESS_MODES = frozenset({"observe", "enforce"})


def resolve_egress_mode(governance_mode: str, egress_mode: str | None = None) -> str:
    """Compose the global governance mode with the egress-specific mode.

    The global mode is a ceiling: when governance is observing or dry-running,
    egress never blocks, whatever the egress mode says. Otherwise the egress
    mode decides, defaulting to "observe" so that upgrading a deployment that
    already runs enforce does not silently turn on default-deny.

    Both arguments are normalised the same way. ``GovernedModel`` stores its
    ``mode`` verbatim, so ``GovernedModel(mode="Observe")`` must lower the
    ceiling exactly as ``"observe"`` does — otherwise the §5.4 ceiling is
    defeated by capitalisation.
    """
    governance_mode = (governance_mode or "").strip().lower()
    if governance_mode in ("observe", "dry-run", "dry_run"):
        return "observe"
    value = egress_mode if egress_mode is not None else os.environ.get("ADMINA_EGRESS_MODE", "")
    value = (value or "").strip().lower()
    if value not in _VALID_EGRESS_MODES:
        if value:
            logger.warning("Invalid ADMINA_EGRESS_MODE %r — falling back to 'observe'", value)
        return "observe"
    return value
