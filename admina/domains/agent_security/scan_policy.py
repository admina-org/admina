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

"""Admina — scan scope of chat messages.

Which parts of a chat request the firewall scans:

- **Request.** Every string of the request body, keys included
  (:func:`request_texts`): the messages, the tool definitions (``tools``),
  ``response_format`` and any other field. The ``arguments`` string of a
  message's tool call (or legacy ``function_call``) is scanned as the JSON
  it holds, each string of it a text of its own; when it is not JSON, as it
  is. Text nested more than :data:`REQUEST_SCAN_DEPTH` levels deep is not
  collected and the result says so (``truncated``), so that the caller can
  refuse the request. Roles and blocks (below) narrow the messages only.
- **Roles.** Messages whose ``role`` is ``system``, ``user``, ``assistant``
  or ``tool`` are scanned when the role is in scope; messages with any
  other role, or none, are always scanned. The operator sets the roles in
  scope (``ADMINA_GATEWAY_SCAN_ROLES``, default all four).
- **Scan policy.** When the operator enables scan policies
  (``ADMINA_GATEWAY_SCAN_POLICY_ENABLED``, off by default), a request may
  narrow the scope with the ``X-Admina-Scan-Policy`` header::

      v1; roles=user,tool; prescanned=source,document; ruleset=<sha256>

  ``roles`` (optional) keeps only these of the configured roles.
  ``prescanned`` (optional) names tags whose blocks, ``<tag …>…</tag>`` in
  message text, were already scanned by the caller and are skipped; only
  tags the operator allows (``gateway.prescan_tags``) are honoured.
  ``ruleset`` (required) is the
  :func:`~admina.domains.agent_security.ruleset.ruleset_sha256` the caller
  scanned with. The policy applies only when that ruleset is one the proxy
  accepts; otherwise (``ruleset_mismatch``) or when the header is malformed
  (unknown version or key, duplicate key, unknown role, invalid tag or
  ruleset, several headers) the request is scanned in full, never refused.
  While scan policies are off the header is ignored (``ignored``) and the
  request is scanned in full. Any caller that can reach the gateway can
  send the header, and the active ruleset is public (``X-Admina-Ruleset``),
  so scan policies are for deployments where every such caller is trusted
  to scan what it declares.
- **Blocks.** A block is skipped only when every tag of the allowed names in
  the text pairs up, one opening tag followed by its closing tag. An
  unclosed, nested or stray tag leaves the whole text to the scan. Tag names
  are case-sensitive. Only the caller can tell its own blocks from text an
  untrusted party wrote in the same form, so it must keep these tags out of
  untrusted text.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any

from admina.core.config import PRESCAN_TAG_NAME
from admina.domains.governance import _extract_text_fields

__all__ = [
    "REQUEST_SCAN_DEPTH",
    "SCAN_POLICY_HEADER",
    "SCAN_ROLES",
    "RequestTexts",
    "ScanPolicy",
    "ScanPolicyError",
    "ScanScope",
    "parse_scan_policy",
    "parse_scan_roles",
    "request_texts",
    "resolve_scan_scope",
    "scope_texts",
    "strip_prescanned",
]

SCAN_POLICY_HEADER = "X-Admina-Scan-Policy"
#: Roles the scan scope can include or leave out, in canonical order.
SCAN_ROLES = ("system", "user", "assistant", "tool")

_ALL_ROLES = frozenset(SCAN_ROLES)
_VERSION = "v1"
_KEYS = frozenset({"roles", "prescanned", "ruleset"})
_MAX_HEADER = 4096
_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
# Depth of a message in the body the pipeline scans, {"params": {"messages":
# [...]}}: scanning a message from here keeps the pipeline's depth limit.
_MESSAGE_DEPTH = 3
#: Deepest level of a chat request whose text :func:`request_texts` collects.
#: The body is level 0 and its fields level 1; the JSON read from a tool
#: call's ``arguments`` is at the level of that string.
REQUEST_SCAN_DEPTH = 32


class ScanPolicyError(ValueError):
    """A malformed ``X-Admina-Scan-Policy`` value."""


@dataclass(frozen=True)
class ScanPolicy:
    """A parsed ``X-Admina-Scan-Policy`` value."""

    #: Roles to scan; None when the header names none.
    roles: frozenset[str] | None
    #: Tags declared as already scanned.
    tags: frozenset[str]
    #: Ruleset the caller scanned with (lowercase hex).
    ruleset: str


@dataclass(frozen=True)
class ScanScope:
    """What the firewall scans for one request, and why."""

    roles: frozenset[str]
    #: Tags whose blocks are skipped.
    tags: frozenset[str]
    #: "none" (no header), "accepted", "ruleset_mismatch", "malformed" or
    #: "ignored" (scan policies off).
    status: str
    #: Ruleset the header declared, when it could be read.
    ruleset: str | None

    @property
    def accepted(self) -> bool:
        return self.status == "accepted"

    @property
    def narrowed(self) -> bool:
        """True when some text of the request is not scanned."""
        return self.roles != _ALL_ROLES or bool(self.tags)

    def record(self) -> dict[str, Any]:
        """The scope as stored in the forensic record (``prescan``)."""
        return {
            "accepted": self.accepted,
            "status": self.status,
            "roles": [role for role in SCAN_ROLES if role in self.roles],
            "tags": sorted(self.tags),
            "ruleset": self.ruleset,
        }


@lru_cache(maxsize=32)
def parse_scan_roles(value: str) -> frozenset[str]:
    """Roles from a comma-separated list (``ADMINA_GATEWAY_SCAN_ROLES``);
    empty = every role. Case-insensitive.

    Raises:
        ValueError: A name that is not one of :data:`SCAN_ROLES`, or an
            empty item.
    """
    if not value.strip():
        return _ALL_ROLES
    return frozenset(_roles(value.split(",")))


def _roles(items: Iterable[str]) -> list[str]:
    roles = [item.strip().lower() for item in items]
    unknown = [role for role in roles if role not in _ALL_ROLES]
    if unknown:
        raise ValueError(f"roles must be among {', '.join(SCAN_ROLES)} (got {unknown!r})")
    return roles


def parse_scan_policy(value: str) -> ScanPolicy:
    """Parse one ``X-Admina-Scan-Policy`` value.

    Raises:
        ScanPolicyError: The value is malformed.
    """
    if len(value) > _MAX_HEADER:
        raise ScanPolicyError("the value is too long")
    version, *fields = (part.strip() for part in value.split(";"))
    if version != _VERSION:
        raise ScanPolicyError(f"unknown version {version[:16]!r}")
    params: dict[str, str] = {}
    for part in fields:
        if not part:
            continue
        key, sep, item = part.partition("=")
        key = key.strip().lower()
        if not sep or key not in _KEYS:
            raise ScanPolicyError(f"unexpected field {key[:32]!r}")
        if key in params:
            raise ScanPolicyError(f"duplicate field {key!r}")
        params[key] = item.strip()

    ruleset = params.get("ruleset", "")
    if not _HEX64.fullmatch(ruleset):
        raise ScanPolicyError("ruleset must be a SHA-256 in hex")
    roles = None
    if "roles" in params:
        try:
            roles = frozenset(_roles(params["roles"].split(",")))
        except ValueError as exc:
            raise ScanPolicyError(str(exc)) from exc
    tags: frozenset[str] = frozenset()
    if params.get("prescanned"):
        names = [name.strip() for name in params["prescanned"].split(",")]
        if not all(PRESCAN_TAG_NAME.fullmatch(name) for name in names):
            raise ScanPolicyError("prescanned must list tag names")
        tags = frozenset(names)
    return ScanPolicy(roles=roles, tags=tags, ruleset=ruleset.lower())


def resolve_scan_scope(
    values: Sequence[str],
    *,
    scan_roles: frozenset[str],
    prescan_tags: Iterable[str],
    accepted_rulesets: Iterable[str],
    policy_enabled: bool,
) -> ScanScope:
    """The scope of a request.

    Args:
        values: The ``X-Admina-Scan-Policy`` values of the request.
        scan_roles: Roles the operator scans (``ADMINA_GATEWAY_SCAN_ROLES``).
        prescan_tags: Tags the operator allows (``gateway.prescan_tags``).
        accepted_rulesets: Rulesets a policy may declare.
        policy_enabled: Whether a policy may narrow the scope at all
            (``ADMINA_GATEWAY_SCAN_POLICY_ENABLED``); when false, *values*
            are ignored.
    """
    full = ScanScope(roles=frozenset(scan_roles), tags=frozenset(), status="none", ruleset=None)
    if not values:
        return full
    if not policy_enabled:
        return replace(full, status="ignored")
    if len(values) != 1:
        return replace(full, status="malformed")
    try:
        policy = parse_scan_policy(values[0])
    except ScanPolicyError:
        return replace(full, status="malformed")
    if policy.ruleset not in set(accepted_rulesets):
        return replace(full, status="ruleset_mismatch", ruleset=policy.ruleset)
    roles = full.roles if policy.roles is None else full.roles & policy.roles
    return ScanScope(
        roles=roles,
        tags=policy.tags & frozenset(prescan_tags),
        status="accepted",
        ruleset=policy.ruleset,
    )


def scope_texts(messages: Any, scope: ScanScope) -> list[str] | None:
    """The texts of *messages* the firewall scans under *scope*.

    None when the scope leaves nothing out (or *messages* is not a list):
    the pipeline then scans every string of the request, as without a
    scope. Otherwise every string of each message in scope (content, name,
    tool calls, …) with the skipped blocks removed from its content.
    """
    if not scope.narrowed or not isinstance(messages, list):
        return None
    texts: list[str] = []
    for message in messages:
        if isinstance(message, dict):
            role = message.get("role")
            if isinstance(role, str) and role in _ALL_ROLES and role not in scope.roles:
                continue
            if scope.tags:
                message = _without_blocks(message, scope.tags)
        texts.extend(_extract_text_fields(message, _MESSAGE_DEPTH))
    return texts


@dataclass(frozen=True)
class RequestTexts:
    """The texts of a chat request the firewall scans."""

    texts: list[str]
    #: True when text lies deeper than :data:`REQUEST_SCAN_DEPTH` and is not
    #: in :attr:`texts`.
    truncated: bool


def request_texts(body: dict, scope: ScanScope) -> RequestTexts:
    """Every string of the chat request *body*, keys included, under *scope*.

    Messages of a role out of scope are left out and the skipped blocks are
    removed from the content of the others, as in :func:`scope_texts`; every
    other field is taken whole. The ``arguments`` string of a message's tool
    call (or legacy ``function_call``) gives the strings of the JSON it holds,
    or itself when it is not JSON.
    """
    walk = _TextWalk()
    for key, value in body.items():
        walk.add(key, 1)
        if key == "messages" and isinstance(value, list):
            for message in value:
                if isinstance(message, dict):
                    role = message.get("role")
                    if isinstance(role, str) and role in _ALL_ROLES and role not in scope.roles:
                        continue
                    if scope.tags:
                        message = _without_blocks(message, scope.tags)
                walk.add(message, 2, in_message=True)
        else:
            walk.add(value, 1)
    return RequestTexts(texts=walk.texts, truncated=walk.truncated)


class _TextWalk:
    """Collects the strings of a JSON value down to :data:`REQUEST_SCAN_DEPTH`."""

    def __init__(self) -> None:
        self.texts: list[str] = []
        self.truncated = False

    def add(self, value: Any, depth: int, *, in_message: bool = False) -> None:
        """Collect *value*, at *depth*; inside a message, *in_message*."""
        if depth > REQUEST_SCAN_DEPTH:
            # A string, or a container with something in it, would have had
            # text; an empty value or a number, nothing.
            if isinstance(value, (str, dict, list)) and value:
                self.truncated = True
            return
        if isinstance(value, str):
            self.texts.append(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                self.add(key, depth + 1)
                if in_message and key == "arguments" and isinstance(item, str):
                    # Read once: strings inside the arguments stay strings.
                    self.add(_arguments(item), depth + 1)
                else:
                    self.add(item, depth + 1, in_message=in_message)
        elif isinstance(value, list):
            for item in value:
                self.add(item, depth + 1, in_message=in_message)


def _arguments(text: str) -> Any:
    """The JSON value that tool call arguments hold, or *text* when they
    hold none."""
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return text


def _without_blocks(message: dict, tags: frozenset[str]) -> dict:
    content = message.get("content")
    if isinstance(content, str):
        return {**message, "content": strip_prescanned(content, tags)}
    if isinstance(content, list):
        parts = [
            {**part, "text": strip_prescanned(part["text"], tags)}
            if isinstance(part, dict) and isinstance(part.get("text"), str)
            else part
            for part in content
        ]
        return {**message, "content": parts}
    return message


def strip_prescanned(text: str, tags: Iterable[str]) -> str:
    """*text* without its ``<tag …>…</tag>`` blocks of *tags*, each block
    replaced by a newline; *text* unchanged when a tag of those names is
    unclosed, nested or stray."""
    names = tuple(sorted(tags))
    if not names or "<" not in text:
        return text
    tokens = iter(_block_tags(names).finditer(text))
    kept: list[str] = []
    position = 0
    for opening in tokens:
        name = opening.group("open")
        closing = next(tokens, None)
        if name is None or closing is None or closing.group("close") != name:
            return text
        kept.append(text[position : opening.start()])
        kept.append("\n")
        position = closing.end()
    kept.append(text[position:])
    return "".join(kept)


@lru_cache(maxsize=64)
def _block_tags(names: tuple[str, ...]) -> re.Pattern[str]:
    """Opening (with attributes) or closing tags of *names*. Linear: each
    attempt stops at the next ``<``."""
    alternatives = "|".join(re.escape(name) for name in names)
    return re.compile(rf"<(?P<open>{alternatives})(?:\s[^<>]*)?>|</(?P<close>{alternatives})\s*>")
