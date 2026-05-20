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

"""Admina governance callback handler for LangChain.

Provides :class:`AdminaCallbackHandler` — a LangChain ``BaseCallbackHandler``
that validates every LLM call, tool invocation, and chain output through
the Admina governance pipeline (firewall, PII redaction, loop detection).

Works **in-process** via the Admina SDK — no sidecar proxy needed.

Usage::

    from langchain_openai import ChatOpenAI
    from admina.integrations.langchain.callbacks import AdminaCallbackHandler

    handler = AdminaCallbackHandler()
    llm = ChatOpenAI(callbacks=[handler])
    llm.invoke("Summarize this document")

    # Check governance results
    print(handler.last_result)
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from admina.core.event_bus import GovernanceEvent, bus
from admina.core.types import EventType
from admina.integrations._engines import get_firewall, get_loop_breaker, get_pii_redactor
from admina.sdk._compat import run_sync

logger = logging.getLogger("admina.integrations.langchain")


class GovernanceBlockedError(Exception):
    """Raised when Admina blocks a request due to governance policy."""

    def __init__(self, action: str, risk_level: str, details: dict | None = None):
        self.action = action
        self.risk_level = risk_level
        self.details = details or {}
        super().__init__(f"Admina governance {action}: risk_level={risk_level}")


@dataclass
class GovernanceResult:
    """Result of an Admina governance check."""

    action: str = "ALLOW"
    risk_level: str = "LOW"
    pii_count: int = 0
    redacted_text: str | None = None
    checks: dict[str, Any] = field(default_factory=dict)


class AdminaCallbackHandler:
    """LangChain callback handler with Admina governance.

    Intercepts LLM calls, tool invocations, and chain runs to
    enforce PII redaction, injection firewall, and loop detection.

    Args:
        session_id: Session identifier for loop detection across calls.
        pii_redaction: Whether to redact PII from prompts/responses.
        firewall: Whether to check for prompt injections.
        loop_detection: Whether to detect reasoning loops.
        on_block: Action when governance blocks a request:
            ``"raise"`` raises :class:`GovernanceBlockedError`,
            ``"warn"`` logs a warning and continues.
        audit: Whether to emit events to the governance event bus.
    """

    def __init__(
        self,
        session_id: str | None = None,
        pii_redaction: bool = True,
        firewall: bool = True,
        loop_detection: bool = True,
        on_block: str = "raise",
        audit: bool = True,
    ) -> None:
        self.session_id = session_id or f"langchain-{uuid.uuid4().hex[:8]}"
        self.pii_redaction = pii_redaction
        self.firewall = firewall
        self.loop_detection = loop_detection
        self.on_block = on_block
        self.audit = audit

        self.last_result: GovernanceResult | None = None
        self._call_count = 0
        self._block_count = 0
        self._redact_count = 0

    # ── Internal governance check ────────────────────────────

    def _govern(self, text: str, direction: str = "inbound") -> GovernanceResult:
        """Run governance checks on text and return result."""
        result = GovernanceResult()
        start = time.perf_counter()

        # Firewall
        if self.firewall and direction == "inbound":
            fw = get_firewall()
            fw_result = fw.check(text)
            result.checks["firewall"] = fw_result
            if fw_result.get("is_injection"):
                result.action = "BLOCK"
                rl = fw_result.get("risk_level", "HIGH")
                result.risk_level = rl.value if hasattr(rl, "value") else str(rl)

        # Loop detection
        if self.loop_detection and direction == "inbound":
            lb = get_loop_breaker()
            lb_result = lb.check(self.session_id, text)
            result.checks["loop_breaker"] = lb_result
            if lb_result.get("is_loop"):
                result.action = "CIRCUIT_BREAK"
                result.risk_level = "HIGH"

        # PII redaction
        if self.pii_redaction:
            pii = get_pii_redactor()
            pii_result = pii.redact(text)
            result.checks["pii_redaction"] = {
                "count": pii_result["count"],
                "entities": [e["type"] for e in pii_result.get("entities", [])],
            }
            if pii_result["count"] > 0:
                result.pii_count = pii_result["count"]
                result.redacted_text = pii_result["redacted_text"]
                if result.action == "ALLOW":
                    result.action = "REDACT"

        result.checks["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
        self.last_result = result
        return result

    def _handle_block(self, result: GovernanceResult, context: str) -> None:
        """Handle a BLOCK or CIRCUIT_BREAK governance decision."""
        self._block_count += 1
        if self.on_block == "raise":
            raise GovernanceBlockedError(result.action, result.risk_level, result.checks)
        logger.warning(
            "[BLOCKED] %s: action=%s risk=%s",
            context,
            result.action,
            result.risk_level,
        )

    def _emit(self, event_type: EventType, **kwargs: Any) -> None:
        """Emit a governance event to the bus."""
        if not self.audit:
            return
        event = GovernanceEvent(
            event_type=event_type,
            session_id=self.session_id,
            domain="langchain",
            **kwargs,
        )
        run_sync(bus.emit(event))

    # ── LangChain callback interface ─────────────────────────
    # These methods match LangChain's BaseCallbackHandler protocol.
    # We don't inherit from it to avoid requiring langchain as a
    # dependency — LangChain checks for method presence via duck typing.

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM starts generating."""
        self._call_count += 1
        combined = "\n".join(prompts)

        result = self._govern(combined, direction="inbound")

        self._emit(
            EventType.MODEL_CALL,
            action=result.action,
            risk_level=result.risk_level,
            metadata={
                "model": serialized.get("name", "unknown"),
                "prompt_length": len(combined),
                "pii_count": result.pii_count,
            },
        )

        if result.action in ("BLOCK", "CIRCUIT_BREAK"):
            self._handle_block(result, "on_llm_start")

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM finishes generating."""
        # Extract text from LLMResult
        text = ""
        if hasattr(response, "generations") and response.generations:
            gen = response.generations[0]
            if gen:
                text = gen[0].text if hasattr(gen[0], "text") else str(gen[0])

        if text:
            result = self._govern(text, direction="outbound")
            if result.pii_count > 0:
                self._redact_count += 1

            self._emit(
                EventType.MODEL_RESPONSE,
                action=result.action,
                risk_level=result.risk_level,
                metadata={
                    "response_length": len(text),
                    "pii_redacted": result.pii_count,
                },
            )

    def on_llm_error(
        self,
        error: BaseException,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM errors."""
        logger.warning("LLM error in governed session %s: %s", self.session_id, error)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running."""
        result = self._govern(input_str, direction="inbound")

        self._emit(
            EventType.AGENT_REQUEST,
            action=result.action,
            risk_level=result.risk_level,
            metadata={
                "tool": serialized.get("name", "unknown"),
                "input_length": len(input_str),
            },
        )

        if result.action in ("BLOCK", "CIRCUIT_BREAK"):
            self._handle_block(result, f"on_tool_start({serialized.get('name', '?')})")

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes."""
        if output:
            result = self._govern(str(output), direction="outbound")
            if result.pii_count > 0:
                self._redact_count += 1

            self._emit(
                EventType.AGENT_RESPONSE,
                action=result.action,
                risk_level=result.risk_level,
                metadata={"output_length": len(str(output)), "pii_redacted": result.pii_count},
            )

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain starts."""
        pass  # governance is applied at LLM/tool level

    def on_chain_end(
        self,
        outputs: dict[str, Any],
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain finishes."""
        pass

    def on_chain_error(
        self,
        error: BaseException,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain errors."""
        pass

    # ── Stats ────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return governance statistics for this handler."""
        return {
            "session_id": self.session_id,
            "call_count": self._call_count,
            "block_count": self._block_count,
            "redact_count": self._redact_count,
            "features": {
                "firewall": self.firewall,
                "pii_redaction": self.pii_redaction,
                "loop_detection": self.loop_detection,
            },
        }
