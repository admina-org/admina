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

"""Admina governance plugin for Cheshire Cat AI.

Intercepts the Cat's message pipeline via hooks to validate content
through an Admina sidecar proxy before sending replies or recalling
memories. Every interaction is audited to a forensic black box.

Install:
    1. Start the Admina sidecar:  ./setup.sh
    2. Copy this plugin folder into the Cat's plugins/ directory
    3. Activate from the Cat admin panel

Environment:
    ADMINA_PROXY_URL  — Admina sidecar URL (default: http://localhost:18790)
"""

from __future__ import annotations

import json
import logging
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

from cat.mad_hatter.decorators import hook

logger = logging.getLogger("admina.cheshirecat")

_PROXY_URL = os.environ.get("ADMINA_PROXY_URL", "http://localhost:18790")
_TIMEOUT = int(os.environ.get("ADMINA_TIMEOUT", "5"))


# ── Helpers ──────────────────────────────────────────────────


def _call_admina(endpoint: str, payload: dict) -> dict | None:
    """Call an Admina sidecar endpoint. Returns None on failure."""
    url = f"{_PROXY_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (URLError, OSError, json.JSONDecodeError) as exc:
        logger.warning("Admina proxy unreachable (%s): %s", url, exc)
        return None


def _validate(content: str, session_id: str = "cheshirecat") -> dict | None:
    """Validate content through Admina governance pipeline."""
    return _call_admina(
        "/api/v1/validate",
        {
            "content": content,
            "session_id": session_id,
        },
    )


def _audit(event: dict) -> dict | None:
    """Log an event to the Admina forensic black box."""
    return _call_admina("/api/v1/audit", {"event": event})


# ── Cheshire Cat Hooks ───────────────────────────────────────


@hook(priority=0)
def agent_fast_reply(fast_reply: dict, cat) -> dict:
    """Intercept user messages BEFORE the agent processes them.

    If the user message contains an injection or PII, the agent
    receives a sanitised version (or a block notice).
    """
    user_msg = cat.working_memory.get("user_message_json", {})
    text = user_msg.get("text", "")
    if not text:
        return fast_reply

    session_id = user_msg.get("user_id", "cheshirecat")
    result = _validate(text, session_id=session_id)

    if result is None:
        # Proxy unreachable — fail open with warning
        logger.warning("Admina proxy unreachable; allowing message without governance")
        return fast_reply

    if result.get("action") == "BLOCK":
        # Block the message entirely — return a governance notice
        _audit(
            {
                "action": "message_blocked",
                "input": text[:200],
                "risk_level": result.get("risk_level", "HIGH"),
                "reason": "injection_detected",
                "session_id": session_id,
            }
        )
        return {
            "output": (
                "This message was blocked by Admina governance: "
                f"{result.get('risk_level', 'HIGH')} risk detected. "
                "Please rephrase your request."
            )
        }

    if result.get("action") == "MODIFY" and result.get("redacted_content"):
        # Replace PII in the working memory so the LLM never sees it
        user_msg["text"] = result["redacted_content"]
        cat.working_memory["user_message_json"] = user_msg
        _audit(
            {
                "action": "pii_redacted",
                "session_id": session_id,
                "entities": result.get("checks", {}).get("pii_redaction", {}).get("entities", []),
            }
        )

    return fast_reply


@hook(priority=0)
def before_cat_sends_message(message: dict, cat) -> dict:
    """Govern the Cat's outgoing reply before it reaches the user.

    Validates the response text for PII leakage and audits the
    interaction to the forensic black box.
    """
    text = message.get("content", "")
    if not text:
        return message

    user_msg = cat.working_memory.get("user_message_json", {})
    session_id = user_msg.get("user_id", "cheshirecat")

    result = _validate(text, session_id=session_id)

    if result is not None:
        if result.get("action") == "MODIFY" and result.get("redacted_content"):
            message["content"] = result["redacted_content"]

        if result.get("action") == "BLOCK":
            message["content"] = (
                "[Response blocked by Admina governance — "
                f"{result.get('risk_level', 'HIGH')} risk content detected]"
            )

    # Audit the full interaction
    _audit(
        {
            "action": "cat_reply",
            "input": user_msg.get("text", "")[:200],
            "output": message.get("content", "")[:200],
            "status": "governed",
            "session_id": session_id,
        }
    )

    return message


@hook(priority=0)
def before_cat_recalls_memories(default_query: str, cat) -> str:
    """Validate the RAG query before it hits the vector store.

    Ensures no injected content is used as a retrieval query and
    redacts any PII from the search terms.
    """
    if not default_query:
        return default_query

    user_msg = cat.working_memory.get("user_message_json", {})
    session_id = user_msg.get("user_id", "cheshirecat")

    result = _validate(default_query, session_id=session_id)

    if result is None:
        return default_query

    if result.get("action") == "BLOCK":
        _audit(
            {
                "action": "rag_query_blocked",
                "input": default_query[:200],
                "risk_level": result.get("risk_level", "HIGH"),
                "session_id": session_id,
            }
        )
        return ""  # empty query = no retrieval

    if result.get("action") == "MODIFY" and result.get("redacted_content"):
        return result["redacted_content"]

    return default_query
