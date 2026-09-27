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

"""Firewall scan of completion text (``ADMINA_GATEWAY_SCAN_RESPONSE``).

The text scanned is the ``content`` of each choice (a string or a list of
text parts): ``message.content`` of a non-streaming completion, the
``delta.content`` pieces of a stream joined per choice. Each choice is
checked on its own, like each message of a request.

The outcome is stored in a forensic record of its own,
``event_type = "gateway_response_scan"``, linked to the request record by
``request_event_id``; like the request record it holds category names,
risk levels and signals, never text.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

from admina.core.types import EventType, GovernanceAction, RiskLevel
from admina.domains.governance import GovernanceResult, safe_serialize

__all__ = [
    "completion_texts",
    "firewall_decision",
    "response_scan_record",
    "stream_texts",
]


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part["text"]
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        )
    return ""


def _choice_index(choice: dict, position: int) -> int:
    index = choice.get("index")
    return index if isinstance(index, int) and not isinstance(index, bool) else position


def completion_texts(data: dict) -> list[str]:
    """The content of each choice of a non-streaming completion."""
    texts = []
    choices = data.get("choices")
    for choice in choices if isinstance(choices, list) else ():
        message = choice.get("message") if isinstance(choice, dict) else None
        if isinstance(message, dict):
            texts.append(_content_text(message.get("content")))
    return [text for text in texts if text]


def stream_texts(parts: Sequence[bytes | str]) -> list[str]:
    """The content of each choice of a stream, from the SSE data sent."""
    raw = "".join(
        part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
        for part in parts
    )
    by_choice: dict[int, list[str]] = {}
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            chunk = json.loads(line[len("data:") :])
        except ValueError:
            continue  # [DONE] and anything that is not JSON
        choices = chunk.get("choices") if isinstance(chunk, dict) else None
        for position, choice in enumerate(choices if isinstance(choices, list) else ()):
            if not isinstance(choice, dict) or not isinstance(choice.get("delta"), dict):
                continue
            text = _content_text(choice["delta"].get("content"))
            if text:
                by_choice.setdefault(_choice_index(choice, position), []).append(text)
    return ["".join(by_choice[index]) for index in sorted(by_choice)]


def firewall_decision(firewall: Any, texts: list[str], mode: str) -> GovernanceResult:
    """The firewall's decision on *texts*: BLOCK at the first flagged text,
    downgraded to ALLOW with ``would_action`` in ``observe`` / ``dry-run``
    *mode*. The check is stored as ``checks["response_firewall"]``."""
    started = time.perf_counter()
    verdict: dict[str, Any] = {"is_injection": False, "risk_level": RiskLevel.LOW}
    for text in texts:
        verdict = firewall.check(text)
        if verdict.get("is_injection"):
            break
    result = GovernanceResult(checks={"response_firewall": verdict}, mode=mode)
    if verdict.get("is_injection"):
        result.risk_level = verdict.get("risk_level") or RiskLevel.HIGH
        if mode in ("observe", "dry-run"):
            result.would_action = GovernanceAction.BLOCK
        else:
            result.action = GovernanceAction.BLOCK
    result.latency_ms = (time.perf_counter() - started) * 1000
    return result


def response_scan_record(
    result: GovernanceResult,
    *,
    event_id: str,
    request_event_id: str,
    agent_id: str,
    session_id: str,
    upstream: str,
    stream: bool,
) -> dict[str, Any]:
    """The forensic record of a response scan. A stream is never blocked:
    its action is ALLOW, with ``would_action`` BLOCK when flagged."""
    blocked = result.action == GovernanceAction.BLOCK
    would_block = result.would_action == GovernanceAction.BLOCK or (stream and blocked)
    record: dict[str, Any] = {
        "event_id": event_id,
        "event_type": EventType.GATEWAY_RESPONSE_SCAN,
        "request_event_id": request_event_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "method": "chat.completions",
        "upstream": upstream,
        "stream": stream,
        "action": "BLOCK" if blocked and not stream else "ALLOW",
        "risk_level": str(safe_serialize(result.risk_level)).upper(),
        "governance_latency_ms": round(result.latency_ms, 2),
        "checks": {key: safe_serialize(value) for key, value in result.checks.items()},
    }
    if would_block:
        record["would_action"] = "BLOCK"
    return record
