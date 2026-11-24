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

"""Review of the tool calls of a completion (``ADMINA_GATEWAY_TOOL_CALL_GATE``).

Each call is reviewed before the client receives it. The tool must be one the
request declares (``tools`` or ``functions``), its arguments must be JSON, and
the destinations of its arguments, shell commands included, must pass the
egress policy of the ``gateway_tool_calls`` surface.

In ``enforce`` mode a blocked call is taken out of the completion and a notice
is added to its text; a choice left with no call ends with ``stop``. In
``observe`` and ``dry-run`` mode, and for egress while ``ADMINA_EGRESS_MODE`` is
not ``enforce``, the call is sent and the finding is recorded as ``would_action``.

In a stream the fragments of each call are held until the finish chunk of its
choice (or the end of the stream, or ``data: [DONE]``); every other event goes
on as it comes. A stream that fails before that releases nothing.

The forensic record (``event_type = "gateway_tool_call"``) is written before the
calls are sent. It holds names, checks, destinations and the SHA-256 of the
arguments, never the arguments.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from admina.core.types import EventType
from admina.domains.agent_security.egress import analyze

__all__ = [
    "CallReview",
    "StreamToolGate",
    "ToolCallGate",
    "gate_completion",
    "tool_call_record",
]

logger = logging.getLogger("admina.gateway")

CHECK_DECLARED = "declared"
CHECK_ARGUMENTS = "arguments"
CHECK_EGRESS = "egress"
CHECK_ERROR = "error"

_CALL_FINISH_REASONS = ("tool_calls", "function_call")
_OBSERVING_MODES = ("observe", "dry-run", "dry_run")
_MAX_NAME = 128


@dataclass(frozen=True)
class CallReview:
    """What the gate found out about one call. *check* is None for a call
    with no finding; *blocked* says the finding takes the call out."""

    name: str
    choice: int
    arguments_sha256: str
    check: str | None = None
    reason: str = ""
    destinations: tuple[str, ...] = ()
    blocked: bool = False

    @property
    def flagged(self) -> bool:
        return self.check is not None

    def notice(self) -> str:
        return f"[admina] blocked call to `{self.name}`: {self.reason}"

    def record(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "name": self.name,
            "choice": self.choice,
            "action": "BLOCK" if self.blocked else "ALLOW",
            "check": self.check,
            "reason": self.reason,
            "destinations": list(self.destinations),
            "arguments_sha256": self.arguments_sha256,
        }
        if self.flagged and not self.blocked:
            entry["would_action"] = "BLOCK"
        return entry


def _declared_tools(request: dict) -> frozenset[str]:
    names = set()
    tools = request.get("tools")
    for tool in tools if isinstance(tools, list) else ():
        if isinstance(tool, dict):
            inner = tool.get("function") or tool.get("custom")
            name = inner.get("name") if isinstance(inner, dict) else tool.get("name")
            if isinstance(name, str):
                names.add(name)
    functions = request.get("functions")
    for function in functions if isinstance(functions, list) else ():
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            names.add(function["name"])
    return frozenset(names)


def _parsed_arguments(arguments: str) -> tuple[bool, Any]:
    """``(readable, value)`` of the arguments of a call; no text is no argument."""
    if not arguments.strip():
        return True, {}
    try:
        return True, json.loads(arguments)
    except (ValueError, RecursionError):
        return False, None


class ToolCallGate:
    """Reviews the calls of the completions of one request.

    Args:
        request: The chat completion request, as received.
        egress_policy: The policy of the ``gateway_tool_calls`` surface, or None.
        governance_mode: ``GOVERNANCE_MODE``.
        egress_mode: The egress mode, from ``resolve_egress_mode``.
    """

    def __init__(
        self, request: dict, egress_policy: Any, governance_mode: str, egress_mode: str
    ) -> None:
        self._declared = _declared_tools(request)
        self._egress_policy = egress_policy
        mode = (governance_mode or "").strip().lower()
        self._enforcing = mode not in _OBSERVING_MODES
        self._egress_enforcing = egress_mode == "enforce"

    def review(self, name: Any, arguments: Any, choice: int = 0) -> CallReview:
        name = (name if isinstance(name, str) else "")[:_MAX_NAME]
        text = arguments if isinstance(arguments, str) else json.dumps(arguments, default=str)
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        base = {"name": name, "choice": choice, "arguments_sha256": digest}
        try:
            return self._findings(name, text, base)
        except Exception as exc:  # noqa: BLE001 — a call that was not checked is not sent
            logger.error("Tool call review failed: %s", type(exc).__name__)
            return CallReview(
                **base, check=CHECK_ERROR, reason="the review did not finish", blocked=True
            )

    def _findings(self, name: str, text: str, base: dict[str, Any]) -> CallReview:
        if name not in self._declared:
            reason = "the request does not declare this tool"
            return CallReview(**base, check=CHECK_DECLARED, reason=reason, blocked=self._enforcing)
        readable, parsed = _parsed_arguments(text)
        if not readable:
            reason = "the arguments are not JSON"
            return CallReview(**base, check=CHECK_ARGUMENTS, reason=reason, blocked=self._enforcing)
        policy = self._egress_policy
        if policy is None:
            return CallReview(**base)
        intent = analyze(parsed, name, policy.read_only_tools, read_commands=True)
        decision = policy.evaluate(intent, "enforce")
        destinations = tuple(intent.destinations)
        if decision.allowed:
            return CallReview(**base, destinations=destinations)
        named = ", ".join(decision.blocked)
        return CallReview(
            **base,
            check=CHECK_EGRESS,
            reason=f"{decision.reason}: {named}" if named else decision.reason,
            destinations=destinations,
            blocked=self._enforcing and self._egress_enforcing,
        )


def tool_call_record(
    reviews: Iterable[CallReview],
    *,
    event_id: str,
    request_event_id: str,
    agent_id: str,
    session_id: str,
    upstream: str,
    stream: bool,
) -> dict[str, Any]:
    """The forensic record of the reviewed calls of one completion."""
    reviews = list(reviews)
    record: dict[str, Any] = {
        "event_id": event_id,
        "event_type": EventType.GATEWAY_TOOL_CALL,
        "request_event_id": request_event_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "method": "chat.completions",
        "upstream": upstream,
        "stream": stream,
        "action": "BLOCK" if any(r.blocked for r in reviews) else "ALLOW",
        "risk_level": "HIGH" if any(r.flagged for r in reviews) else "LOW",
        "calls": [review.record() for review in reviews],
    }
    if any(r.flagged and not r.blocked for r in reviews):
        record["would_action"] = "BLOCK"
    return record


def _function_of(call: Any) -> dict:
    function = call.get("function") if isinstance(call, dict) else None
    return function if isinstance(function, dict) else {}


def _with_notice(content: Any, notice: str) -> Any:
    """*content* of a message with *notice* added at its end."""
    if isinstance(content, list):
        return [*content, {"type": "text", "text": notice}]
    return f"{content}\n{notice}" if isinstance(content, str) and content else notice


def _choice_index(choice: dict, position: int) -> int:
    index = choice.get("index")
    return index if isinstance(index, int) and not isinstance(index, bool) else position


def gate_completion(data: dict, gate: ToolCallGate) -> tuple[bool, list[CallReview]]:
    """Review the calls of the non-streaming completion *data*, taking the
    blocked ones out in place; ``(changed, reviews)``."""
    reviews: list[CallReview] = []
    changed = False
    choices = data.get("choices")
    for position, choice in enumerate(choices if isinstance(choices, list) else ()):
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            continue
        index = _choice_index(choice, position)
        blocked = []
        calls = message.get("tool_calls")
        if isinstance(calls, list):
            kept = []
            for call in calls:
                function = _function_of(call)
                review = gate.review(function.get("name"), function.get("arguments", ""), index)
                reviews.append(review)
                if review.blocked:
                    blocked.append(review)
                else:
                    kept.append(call)
            if blocked:
                message["tool_calls"] = kept
                if not kept:
                    del message["tool_calls"]
        legacy = message.get("function_call")
        if isinstance(legacy, dict):
            review = gate.review(legacy.get("name"), legacy.get("arguments", ""), index)
            reviews.append(review)
            if review.blocked:
                blocked.append(review)
                del message["function_call"]
        if not blocked:
            continue
        changed = True
        for review in blocked:
            message["content"] = _with_notice(message.get("content"), review.notice())
        if "tool_calls" not in message and "function_call" not in message:
            if choice.get("finish_reason") in _CALL_FINISH_REASONS:
                choice["finish_reason"] = "stop"
    return changed, reviews


@dataclass
class _HeldCall:
    """A call being assembled from the fragments of a stream."""

    id: Any = None
    type: Any = None
    name: str = ""
    arguments: str = ""


# The slot of a legacy function_call among the calls of a choice.
_FUNCTION_CALL = -1


@dataclass
class _Step:
    """What one line of a stream gives: *lines* to send, and the *reviews*
    of the calls released by them, to record before they are sent."""

    lines: list[str] = field(default_factory=list)
    reviews: list[CallReview] = field(default_factory=list)


def _data_line(chunk: dict) -> str:
    return f"data: {json.dumps(chunk, separators=(',', ':'))}"


class StreamToolGate:
    """Holds and reviews the calls of one stream, line by line (see the
    module docstring). A line with nothing to hold goes on unchanged."""

    def __init__(self, gate: ToolCallGate) -> None:
        self._gate = gate
        self._held: dict[int, dict[int, _HeldCall]] = {}
        self._identity: dict[str, Any] = {}

    def due(self, line: str) -> bool:
        """True when *line* may release calls, so reviewing it takes time."""
        if not self._held:
            return False
        return '"finish_reason":null' not in line and '"finish_reason": null' not in line

    def line(self, line: str) -> _Step:
        """The step for one upstream SSE *line*."""
        if not line.startswith("data:"):
            return _Step([line])
        payload = line[len("data:") :].strip()
        if payload == "[DONE]":
            step = self.end()
            step.lines.append(line)
            return step
        try:
            chunk = json.loads(payload)
        except ValueError:
            return _Step([line])
        if not isinstance(chunk, dict) or not isinstance(chunk.get("choices"), list):
            return _Step([line])
        self._identity = {k: chunk[k] for k in ("id", "object", "created", "model") if k in chunk}
        return self._chunk(chunk, line)

    def end(self) -> _Step:
        """Release the calls still held, at the end of the stream."""
        step = _Step()
        for index in sorted(self._held):
            self._release(index, step)
        return step

    def _chunk(self, chunk: dict, line: str) -> _Step:
        step = _Step()
        changed = False
        choices = []
        for position, choice in enumerate(chunk["choices"]):
            if not isinstance(choice, dict):
                choices.append(choice)
                continue
            index = _choice_index(choice, position)
            taken = self._take_calls(index, choice)
            finish = choice.get("finish_reason")
            finished = finish is not None
            if finished and index in self._held:
                kept = self._release(index, step)
                if not kept and finish in _CALL_FINISH_REASONS:
                    choice["finish_reason"] = "stop"
                    changed = True
            changed = changed or taken
            if taken and not finished and not choice.get("delta"):
                continue  # only fragments: nothing else to send
            choices.append(choice)
        if not changed:
            step.lines.append(line)
        elif choices or chunk.get("usage") is not None:
            step.lines.append(_data_line({**chunk, "choices": choices}))
        return step

    def _take_calls(self, index: int, choice: dict) -> bool:
        """Move the call fragments of *choice* out of its delta; True if any."""
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            return False
        taken = False
        if "tool_calls" in delta:
            taken = True
            calls = delta.pop("tool_calls")
            for position, call in enumerate(calls if isinstance(calls, list) else ()):
                slot = call.get("index") if isinstance(call, dict) else None
                slot = slot if isinstance(slot, int) and slot >= 0 else position
                held = self._held.setdefault(index, {}).setdefault(slot, _HeldCall())
                if isinstance(call, dict):
                    held.id = call.get("id") or held.id
                    held.type = call.get("type") or held.type
                self._add(held, _function_of(call))
        if "function_call" in delta:
            taken = True
            function = delta.pop("function_call")
            held = self._held.setdefault(index, {}).setdefault(_FUNCTION_CALL, _HeldCall())
            self._add(held, function if isinstance(function, dict) else {})
        return taken

    @staticmethod
    def _add(held: _HeldCall, function: dict) -> None:
        name, arguments = function.get("name"), function.get("arguments")
        held.name += name if isinstance(name, str) else ""
        held.arguments += arguments if isinstance(arguments, str) else ""

    def _release(self, index: int, step: _Step) -> bool:
        """Review the calls held for choice *index*; add the lines of those
        kept and of the notices to *step*. True if a call was kept."""
        held = self._held.pop(index)
        tool_calls: list[dict] = []
        function_call = None
        notices = []
        for slot in sorted(held):
            call = held[slot]
            review = self._gate.review(call.name, call.arguments, index)
            step.reviews.append(review)
            if review.blocked:
                notices.append(review.notice())
                continue
            function = {"name": call.name, "arguments": call.arguments}
            if slot == _FUNCTION_CALL:
                function_call = function
            else:
                entry = {"index": len(tool_calls), "function": function}
                if call.id is not None:
                    entry["id"] = call.id
                if call.type is not None:
                    entry["type"] = call.type
                tool_calls.append(entry)
        if notices:
            step.lines.append(self._delta_line(index, {"content": "\n".join(notices)}))
        if tool_calls:
            step.lines.append(self._delta_line(index, {"tool_calls": tool_calls}))
        if function_call is not None:
            step.lines.append(self._delta_line(index, {"function_call": function_call}))
        return bool(tool_calls) or function_call is not None

    def _delta_line(self, index: int, delta: dict) -> str:
        choice = {"index": index, "delta": delta, "finish_reason": None}
        return _data_line({**self._identity, "choices": [choice]})
