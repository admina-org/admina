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

"""Admina governance callbacks for CrewAI.

Provides :func:`admina_step_callback` and :func:`admina_task_callback`
for use with CrewAI's ``step_callback`` and ``task_callback`` hooks.
Every agent step (LLM reasoning, tool use) is validated through the
Admina governance pipeline.

Works **in-process** via the Admina SDK — no sidecar proxy needed.

Usage::

    from crewai import Agent, Task, Crew
    from admina.integrations.crewai.callbacks import admina_step_callback, admina_task_callback

    agent = Agent(
        role="Researcher",
        goal="Find quarterly revenue",
        step_callback=admina_step_callback,
    )

    crew = Crew(
        agents=[agent],
        tasks=[task],
        task_callback=admina_task_callback,
    )
    crew.kickoff()
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

logger = logging.getLogger("admina.integrations.crewai")


class GovernanceBlockedError(Exception):
    """Raised when Admina blocks a CrewAI step."""

    def __init__(self, action: str, risk_level: str, details: dict | None = None):
        self.action = action
        self.risk_level = risk_level
        self.details = details or {}
        super().__init__(f"Admina governance {action}: risk_level={risk_level}")


@dataclass
class GovernanceResult:
    """Result of an Admina governance check on a CrewAI step."""

    action: str = "ALLOW"
    risk_level: str = "LOW"
    pii_count: int = 0
    redacted_text: str | None = None
    checks: dict[str, Any] = field(default_factory=dict)


def _govern(
    text: str,
    session_id: str,
    direction: str = "inbound",
    *,
    firewall: bool = True,
    loop_detection: bool = True,
    pii_redaction: bool = True,
) -> GovernanceResult:
    """Run the Admina governance pipeline on text."""
    result = GovernanceResult()
    start = time.perf_counter()

    # Firewall (inbound only)
    if firewall and direction == "inbound":
        fw = get_firewall()
        fw_result = fw.check(text)
        result.checks["firewall"] = fw_result
        if fw_result.get("is_injection"):
            result.action = "BLOCK"
            rl = fw_result.get("risk_level", "HIGH")
            result.risk_level = rl.value if hasattr(rl, "value") else str(rl)

    # Loop detection (inbound only)
    if loop_detection and direction == "inbound":
        lb = get_loop_breaker()
        lb_result = lb.check(session_id, text)
        result.checks["loop_breaker"] = lb_result
        if lb_result.get("is_loop"):
            result.action = "CIRCUIT_BREAK"
            result.risk_level = "HIGH"

    # PII redaction (both directions)
    if pii_redaction:
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
    return result


def _emit(event_type: EventType, session_id: str, **kwargs: Any) -> None:
    """Emit a governance event to the bus."""
    event = GovernanceEvent(
        event_type=event_type,
        session_id=session_id,
        domain="crewai",
        **kwargs,
    )
    run_sync(bus.emit(event))


# ── CrewAI Callbacks ─────────────────────────────────────────


class AdminaStepCallback:
    """Callable that governs each CrewAI agent step.

    Use as ``step_callback`` on a CrewAI ``Agent`` or ``Crew``.

    Args:
        session_id: Session ID for loop detection.
        pii_redaction: Enable PII redaction.
        firewall: Enable injection firewall.
        loop_detection: Enable loop breaker.
        on_block: ``"raise"`` or ``"warn"``.
        audit: Emit events to governance bus.
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
        self.session_id = session_id or f"crewai-{uuid.uuid4().hex[:8]}"
        self.pii_redaction = pii_redaction
        self.firewall = firewall
        self.loop_detection = loop_detection
        self.on_block = on_block
        self.audit = audit

        self.last_result: GovernanceResult | None = None
        self._step_count = 0
        self._block_count = 0
        self._redact_count = 0

    def __call__(self, step_output: Any) -> Any:
        """Called by CrewAI after each agent step.

        Args:
            step_output: The CrewAI ``AgentAction`` or ``AgentFinish`` object.

        Returns:
            The (possibly modified) step output.
        """
        self._step_count += 1

        # Extract text from CrewAI step output
        text = self._extract_text(step_output)
        if not text:
            return step_output

        result = _govern(
            text,
            self.session_id,
            direction="inbound",
            firewall=self.firewall,
            loop_detection=self.loop_detection,
            pii_redaction=self.pii_redaction,
        )
        self.last_result = result

        if self.audit:
            _emit(
                EventType.AGENT_REQUEST,
                session_id=self.session_id,
                action=result.action,
                risk_level=result.risk_level,
                metadata={
                    "step": self._step_count,
                    "text_length": len(text),
                    "pii_count": result.pii_count,
                },
            )

        if result.action in ("BLOCK", "CIRCUIT_BREAK"):
            self._block_count += 1
            if self.on_block == "raise":
                raise GovernanceBlockedError(result.action, result.risk_level, result.checks)
            logger.warning(
                "[BLOCKED] CrewAI step %d: action=%s risk=%s",
                self._step_count,
                result.action,
                result.risk_level,
            )

        if result.pii_count > 0:
            self._redact_count += 1

        return step_output

    @staticmethod
    def _extract_text(step_output: Any) -> str:
        """Extract text content from a CrewAI step output."""
        if isinstance(step_output, str):
            return step_output
        if isinstance(step_output, dict):
            return step_output.get("text", step_output.get("output", ""))
        # CrewAI AgentAction has .tool_input, AgentFinish has .return_values
        if hasattr(step_output, "tool_input"):
            return str(step_output.tool_input)
        if hasattr(step_output, "return_values"):
            vals = step_output.return_values
            if isinstance(vals, dict):
                return vals.get("output", str(vals))
            return str(vals)
        if hasattr(step_output, "text"):
            return step_output.text
        return str(step_output)

    def get_stats(self) -> dict[str, Any]:
        """Return governance statistics."""
        return {
            "session_id": self.session_id,
            "step_count": self._step_count,
            "block_count": self._block_count,
            "redact_count": self._redact_count,
        }


class AdminaTaskCallback:
    """Callable that governs CrewAI task outputs.

    Use as ``task_callback`` on a CrewAI ``Crew``.

    Args:
        session_id: Session ID for auditing.
        pii_redaction: Enable PII redaction on task output.
        audit: Emit events to governance bus.
    """

    def __init__(
        self,
        session_id: str | None = None,
        pii_redaction: bool = True,
        audit: bool = True,
    ) -> None:
        self.session_id = session_id or f"crewai-task-{uuid.uuid4().hex[:8]}"
        self.pii_redaction = pii_redaction
        self.audit = audit

        self.last_result: GovernanceResult | None = None
        self._task_count = 0

    def __call__(self, task_output: Any) -> Any:
        """Called by CrewAI after each task completes.

        Args:
            task_output: The CrewAI ``TaskOutput`` object.

        Returns:
            The (possibly modified) task output.
        """
        self._task_count += 1

        # Extract text from task output
        text = ""
        if isinstance(task_output, str):
            text = task_output
        elif hasattr(task_output, "raw"):
            text = str(task_output.raw)
        elif hasattr(task_output, "output"):
            text = str(task_output.output)

        if not text:
            return task_output

        result = _govern(
            text,
            self.session_id,
            direction="outbound",
            pii_redaction=self.pii_redaction,
        )
        self.last_result = result

        if self.audit:
            _emit(
                EventType.AGENT_RESPONSE,
                session_id=self.session_id,
                action=result.action,
                risk_level=result.risk_level,
                metadata={
                    "task": self._task_count,
                    "output_length": len(text),
                    "pii_redacted": result.pii_count,
                },
            )

        return task_output

    def get_stats(self) -> dict[str, Any]:
        """Return task governance statistics."""
        return {
            "session_id": self.session_id,
            "task_count": self._task_count,
        }


# ── Convenience instances ────────────────────────────────────
# These can be used directly without instantiation:
#   Agent(step_callback=admina_step_callback)
#   Crew(task_callback=admina_task_callback)

admina_step_callback = AdminaStepCallback()
admina_task_callback = AdminaTaskCallback()
