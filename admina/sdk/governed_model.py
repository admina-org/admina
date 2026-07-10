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

"""Admina — GovernedModel SDK primitive.

Wraps a model adapter with automatic PII redaction and governance
event emission on every call.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from admina.core.event_bus import EventType, GovernanceEvent, bus
from admina.domains.governance import normalize_guard_fail_mode
from admina.plugins.base import BaseModelAdapter
from admina.sdk._compat import run_sync
from admina.sdk.retry import RetryPolicy, run_with_retry
from admina.sdk.streaming import StreamRedactor

__all__ = ["GovernedModel", "GovernedResponse", "BaseModelAdapter"]


@dataclass
class GovernedResponse:
    """Response from GovernedModel.ask().

    Attributes:
        text: The model's response text (PII-redacted).
        metadata: Model metadata (tokens, latency, etc.).
        governance: Governance decisions applied to this call.
        action: Governance action taken: ``"ALLOW"``, ``"REDACT"``, or ``"BLOCK"`` (loop circuit-break is also reported as ``"BLOCK"``).
    """

    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    governance: dict[str, Any] = field(default_factory=dict)
    action: str = "ALLOW"


def _load_pii_redactor() -> Any:
    """Engine from admina.engines (honors ADMINA_ENGINE and pii_engine)."""
    from admina.engines import get_pii_engine

    return get_pii_engine()


def _load_firewall() -> Any:
    """Engine from admina.engines (honors ADMINA_ENGINE and YAML firewall overrides)."""
    from admina.engines import get_firewall

    return get_firewall()


def _load_loop_breaker() -> Any:
    """Engine from admina.engines (honors ADMINA_ENGINE)."""
    from admina.engines import get_loop_breaker

    return get_loop_breaker()


class GovernedModel:
    """SDK primitive for governed model inference.

    Wraps a model adapter with automatic PII redaction on prompts
    and responses, injection firewall, pluggable guards, and event
    emission on every call.

    Args:
        model_name: Name of the model to use (e.g. "llama3").
        adapter: A BaseModelAdapter instance, or None for default.
        audit: Whether to emit governance events.
        pii_redaction: Whether to run PII redaction on prompts/responses.
        firewall_enabled: Whether to run the injection firewall on the prompt.
        loop_detection: Whether to run loop detection (requires session_id per call).
        governance_guards: Pluggable governance guards to run in order.
        mode: Governance mode ('enforce', 'observe', 'dry-run').
    """

    def __init__(
        self,
        model_name: str,
        adapter: BaseModelAdapter | None = None,
        audit: bool = True,
        pii_redaction: bool = True,
        firewall_enabled: bool = True,
        loop_detection: bool = False,
        governance_guards: list | None = None,
        mode: str = "enforce",
        retry: RetryPolicy | None = None,
    ) -> None:
        """Initialize GovernedModel.

        Args:
            model_name: Model identifier passed to the adapter.
            adapter: Adapter instance. Can be resolved via
                :class:`PluginRegistry` or passed explicitly.
            audit: If True, emit events to the event bus.
            pii_redaction: If True, redact PII from prompts and responses.
            firewall_enabled: If True, run the injection firewall on every prompt.
            loop_detection: If True, run loop detection when a session_id is supplied.
            governance_guards: Optional list of pluggable guard objects.
            mode: Governance enforcement mode.
            retry: Optional RetryPolicy for transient adapter errors. Default None
                (single attempt, unchanged behaviour).
        """
        self.model_name = model_name
        self._adapter = adapter
        self._audit = audit
        self._pii_redaction = pii_redaction
        self._firewall_enabled = firewall_enabled
        self._loop_detection = loop_detection
        self._guards = governance_guards or []
        self._mode = mode
        self._guard_fail_mode = normalize_guard_fail_mode(os.environ.get("ADMINA_GUARD_FAIL_MODE"))
        self._retry = retry
        self._session_id = str(uuid.uuid4())
        self._pii_redactor: Any = None
        self._firewall: Any = None
        self._loop_breaker: Any = None
        self.last_stream_result: dict[str, Any] | None = None

    def _get_pii_redactor(self) -> Any:
        """Return the PII redactor, creating it lazily."""
        if self._pii_redactor is None:
            self._pii_redactor = _load_pii_redactor()
        return self._pii_redactor

    def _get_firewall(self) -> Any:
        """Return the firewall, creating it lazily."""
        if self._firewall is None:
            self._firewall = _load_firewall()
        return self._firewall

    def _get_loop_breaker(self) -> Any:
        """Return the loop breaker, creating it lazily."""
        if self._loop_breaker is None:
            self._loop_breaker = _load_loop_breaker()
        return self._loop_breaker

    async def ask(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> GovernedResponse:
        """Send a governed prompt to the model.

        Runs the full governance pipeline (injection firewall, PII redaction,
        pluggable guards), calls the adapter if allowed, redacts the response,
        and emits governance events.

        Args:
            prompt: The user prompt.
            context: Optional context passed to the adapter.
            **kwargs: Additional arguments forwarded to the adapter.
                Pass ``session_id`` to enable loop detection across calls.

        Returns:
            GovernedResponse with redacted text, action, metadata, and governance info.
            On a blocked prompt, returns action="BLOCK" with empty text.

        Raises:
            RuntimeError: If no adapter is configured.
        """
        if self._adapter is None:
            raise RuntimeError(
                "No model adapter configured. Pass an adapter to GovernedModel() "
                "or resolve one via PluginRegistry."
            )

        from admina.domains.governance import redact_response_result, run_pipeline

        explicit_session = kwargs.pop("session_id", None)
        loop_on = self._loop_detection and explicit_session is not None
        sid = explicit_session or self._session_id

        start_us = time.time() * 1_000_000

        # 1. Emit MODEL_CALL event
        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.MODEL_CALL,
                    session_id=sid,
                    domain="ai-infra",
                    metadata={"model": self.model_name, "adapter": self._adapter.name},
                )
            )

        # 2. Run full governance pipeline on the prompt
        pre = await run_pipeline(
            body={"params": {"content": prompt}},
            content_str=prompt,
            session_id=sid,
            agent_id=self.model_name,
            request_id=str(uuid.uuid4()),
            params={"content": prompt},
            firewall=self._get_firewall(),
            pii_redactor=self._get_pii_redactor(),
            loop_breaker=self._get_loop_breaker(),
            governance_guards=self._guards,
            injection_enabled=self._firewall_enabled,
            pii_enabled=self._pii_redaction,
            loop_enabled=loop_on,
            mode=self._mode,
            guard_fail_mode=self._guard_fail_mode,
        )

        pre_action = pre.gov_response.action  # uppercase: ALLOW/BLOCK/CIRCUIT_BREAK
        pii_check = pre.checks.get("pii_redaction", {})
        pii_prompt_count = pii_check.get("count", 0)
        pii_prompt_entities = pii_check.get("entities", [])

        governance: dict[str, Any] = {
            "pii_prompt": {
                "redacted": pii_prompt_count > 0,
                "count": pii_prompt_count,
                "entities": pii_prompt_entities,
            },
            "pii_response": {"redacted": False, "count": 0},
            "pipeline": pre.checks,
        }

        # 3. Short-circuit on BLOCK / CIRCUIT_BREAK
        if pre_action in ("BLOCK", "CIRCUIT_BREAK"):
            latency_us = time.time() * 1_000_000 - start_us
            governance["latency_us"] = latency_us
            if self._audit:
                await bus.emit(
                    GovernanceEvent(
                        event_type=EventType.MODEL_RESPONSE,
                        session_id=sid,
                        domain="ai-infra",
                        action="BLOCK",
                        metadata={
                            "model": self.model_name,
                            "latency_us": latency_us,
                            "pii_prompt_count": pii_prompt_count,
                            "pii_response_count": 0,
                        },
                    )
                )
            return GovernedResponse(
                text="",
                action="BLOCK",
                metadata={},
                governance=governance,
            )

        # 4. Extract the PII-redacted prompt from pipeline result
        redacted_prompt = pre.redacted_body.get("params", {}).get("content", prompt)

        # 5. Call adapter
        kwargs.setdefault("model", self.model_name)
        adapter_result = await run_with_retry(
            lambda: self._adapter.send(redacted_prompt, context=context, **kwargs),
            self._retry,
        )
        raw_text = adapter_result.get("text", "")
        adapter_metadata = adapter_result.get("metadata", {})

        # 6. PII redaction on response
        response_text = raw_text
        pii_response_count = 0
        if self._pii_redaction:
            response_text, pii_response_count = redact_response_result(
                raw_text, self._get_pii_redactor()
            )
            governance["pii_response"] = {
                "redacted": pii_response_count > 0,
                "count": pii_response_count,
            }

        latency_us = time.time() * 1_000_000 - start_us
        governance["latency_us"] = latency_us

        # 7. Compute action
        action = "REDACT" if (pii_prompt_count > 0 or pii_response_count > 0) else "ALLOW"

        # 8. Emit MODEL_RESPONSE event
        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.MODEL_RESPONSE,
                    session_id=sid,
                    domain="ai-infra",
                    action=action,
                    metadata={
                        "model": self.model_name,
                        "latency_us": latency_us,
                        "pii_prompt_count": pii_prompt_count,
                        "pii_response_count": pii_response_count,
                    },
                )
            )

        # 9. Return GovernedResponse
        return GovernedResponse(
            text=response_text,
            action=action,
            metadata=adapter_metadata,
            governance=governance,
        )

    async def stream(self, prompt: str, **kwargs: Any):
        """Stream a governed response as redacted text deltas.

        Runs the same pre-stream pipeline as :meth:`ask` (loop → firewall →
        PII) over the prompt, then pipes adapter deltas through a
        :class:`~admina.sdk.streaming.StreamRedactor` so PII spanning a
        delta boundary is still caught. On a blocked prompt the iterator
        yields nothing and ``last_stream_result["action"] == "BLOCK"`` —
        ``stream`` never raises for governance decisions (mirrors ``ask``).

        The full outcome lands in :attr:`last_stream_result` after the
        iterator is exhausted.

        Args:
            prompt: The user prompt.
            **kwargs: Forwarded to the adapter. ``context`` (system prompt),
                ``session_id`` (loop detection), and ``stream_window_chars``
                (recomposition window, default 64) are consumed here.

        Yields:
            PII-redacted text deltas.

        Raises:
            RuntimeError: If no adapter is configured.
        """
        if self._adapter is None:
            raise RuntimeError(
                "No model adapter configured. Pass an adapter to GovernedModel() "
                "or resolve one via PluginRegistry."
            )

        from admina.domains.governance import run_pipeline

        context = kwargs.pop("context", None)
        window = kwargs.pop("stream_window_chars", 64)
        explicit_session = kwargs.pop("session_id", None)
        loop_on = self._loop_detection and explicit_session is not None
        sid = explicit_session or self._session_id

        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.MODEL_CALL,
                    session_id=sid,
                    domain="ai-infra",
                    metadata={"model": self.model_name, "adapter": self._adapter.name},
                )
            )

        pre = await run_pipeline(
            body={"params": {"content": prompt}},
            content_str=prompt,
            session_id=sid,
            agent_id=self.model_name,
            request_id=str(uuid.uuid4()),
            params={"content": prompt},
            firewall=self._get_firewall(),
            pii_redactor=self._get_pii_redactor(),
            loop_breaker=self._get_loop_breaker(),
            governance_guards=self._guards,
            injection_enabled=self._firewall_enabled,
            pii_enabled=self._pii_redaction,
            loop_enabled=loop_on,
            mode=self._mode,
        )

        pre_action = pre.gov_response.action
        pii_prompt_count = pre.checks.get("pii_redaction", {}).get("count", 0)
        start = time.monotonic()

        if pre_action in ("BLOCK", "CIRCUIT_BREAK"):
            self.last_stream_result = {
                "action": "BLOCK",
                "pii_count": pii_prompt_count,
                "model": self.model_name,
                "input_tokens": None,
                "output_tokens": None,
                "finish_reason": "content_filter",
                "time_to_first_token_ms": None,
                "duration_ms": (time.monotonic() - start) * 1000,
            }
            if self._audit:
                await bus.emit(
                    GovernanceEvent(
                        event_type=EventType.MODEL_RESPONSE,
                        session_id=sid,
                        domain="ai-infra",
                        action="BLOCK",
                        metadata={"model": self.model_name, "pii_prompt_count": pii_prompt_count},
                    )
                )
            return

        redacted_prompt = pre.redacted_body.get("params", {}).get("content", prompt)
        kwargs.setdefault("model", self.model_name)

        redactor = (
            StreamRedactor(self._get_pii_redactor(), window_chars=window)
            if self._pii_redaction
            else None
        )
        ttft_ms: float | None = None
        pii_response_count = 0

        async for raw in self._adapter.send_stream(redacted_prompt, context=context, **kwargs):
            if ttft_ms is None:
                ttft_ms = (time.monotonic() - start) * 1000
            if redactor is None:
                if raw:
                    yield raw
            else:
                for safe in redactor.feed(raw):
                    yield safe

        if redactor is not None:
            tail, summary = redactor.finish()
            if tail:
                yield tail
            pii_response_count = summary["pii_count"]

        action = "REDACT" if (pii_prompt_count + pii_response_count) > 0 else "ALLOW"
        self.last_stream_result = {
            "action": action,
            "pii_count": pii_prompt_count + pii_response_count,
            "model": self.model_name,
            "input_tokens": None,
            "output_tokens": None,
            "finish_reason": "stop",
            "time_to_first_token_ms": ttft_ms,
            "duration_ms": (time.monotonic() - start) * 1000,
        }

        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.MODEL_RESPONSE,
                    session_id=sid,
                    domain="ai-infra",
                    action=action,
                    metadata={
                        "model": self.model_name,
                        "pii_prompt_count": pii_prompt_count,
                        "pii_response_count": pii_response_count,
                    },
                )
            )

    def ask_sync(self, prompt: str, **kwargs: Any) -> GovernedResponse:
        """Synchronous convenience wrapper around ask().

        Args:
            prompt: The user prompt.
            **kwargs: Forwarded to ask().

        Returns:
            GovernedResponse.
        """
        return run_sync(self.ask(prompt, **kwargs))
