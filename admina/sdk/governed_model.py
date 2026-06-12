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

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from admina.core.event_bus import EventType, GovernanceEvent, bus
from admina.plugins.base import BaseModelAdapter
from admina.sdk._compat import run_sync

__all__ = ["GovernedModel", "GovernedResponse", "BaseModelAdapter"]


@dataclass
class GovernedResponse:
    """Response from GovernedModel.ask().

    Attributes:
        text: The model's response text (PII-redacted).
        metadata: Model metadata (tokens, latency, etc.).
        governance: Governance decisions applied to this call.
    """

    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    governance: dict[str, Any] = field(default_factory=dict)


def _load_pii_redactor() -> Any:
    """Lazily load the PII redactor to avoid import-time spaCy load."""
    from admina.domains.data_sovereignty.pii import PIIRedactor

    return PIIRedactor()


class GovernedModel:
    """SDK primitive for governed model inference.

    Wraps a model adapter with automatic PII redaction on prompts
    and responses, and emits governance events for every call.

    Args:
        model_name: Name of the model to use (e.g. "llama3").
        adapter: A BaseModelAdapter instance, or None for default.
        audit: Whether to emit governance events.
        pii_redaction: Whether to run PII redaction on prompts/responses.
    """

    def __init__(
        self,
        model_name: str,
        adapter: BaseModelAdapter | None = None,
        audit: bool = True,
        pii_redaction: bool = True,
    ) -> None:
        """Initialize GovernedModel.

        Args:
            model_name: Model identifier passed to the adapter.
            adapter: Adapter instance. Can be resolved via
                :class:`PluginRegistry` or passed explicitly.
            audit: If True, emit events to the event bus.
            pii_redaction: If True, redact PII from prompts and responses.
        """
        self.model_name = model_name
        self._adapter = adapter
        self._audit = audit
        self._pii_redaction = pii_redaction
        self._pii_redactor: Any = None

    def _get_pii_redactor(self) -> Any:
        """Return the PII redactor, creating it lazily."""
        if self._pii_redactor is None:
            self._pii_redactor = _load_pii_redactor()
        return self._pii_redactor

    async def ask(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> GovernedResponse:
        """Send a governed prompt to the model.

        Applies PII redaction, calls the adapter, redacts the response,
        and emits governance events.

        Args:
            prompt: The user prompt.
            context: Optional context passed to the adapter.
            **kwargs: Additional arguments forwarded to the adapter.

        Returns:
            GovernedResponse with redacted text, metadata, and governance info.

        Raises:
            RuntimeError: If no adapter is configured.
        """
        if self._adapter is None:
            raise RuntimeError(
                "No model adapter configured. Pass an adapter to GovernedModel() "
                "or resolve one via PluginRegistry."
            )

        session_id = kwargs.pop("session_id", None) or str(uuid.uuid4())
        start_us = time.time() * 1_000_000
        governance: dict[str, Any] = {
            "pii_prompt": {"redacted": False, "count": 0},
            "pii_response": {"redacted": False, "count": 0},
        }

        # 1. Emit MODEL_CALL event
        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.MODEL_CALL,
                    session_id=session_id,
                    domain="ai-infra",
                    metadata={"model": self.model_name, "adapter": self._adapter.name},
                )
            )

        # 2. Run PII redaction on prompt
        redacted_prompt = prompt
        if self._pii_redaction:
            pii_result = self._get_pii_redactor().redact(prompt)
            redacted_prompt = pii_result["redacted_text"]
            governance["pii_prompt"] = {
                "redacted": pii_result["count"] > 0,
                "count": pii_result["count"],
                "entities": pii_result["entities"],
            }

        # 3. Call adapter — forward this model's name unless the caller
        #    overrode it per-call with an explicit `model=` kwarg.
        kwargs.setdefault("model", self.model_name)
        adapter_result = await self._adapter.send(
            redacted_prompt,
            context=context,
            **kwargs,
        )
        raw_text = adapter_result.get("text", "")
        adapter_metadata = adapter_result.get("metadata", {})

        # 4. Run PII redaction on response
        response_text = raw_text
        if self._pii_redaction:
            pii_result = self._get_pii_redactor().redact(raw_text)
            response_text = pii_result["redacted_text"]
            governance["pii_response"] = {
                "redacted": pii_result["count"] > 0,
                "count": pii_result["count"],
                "entities": pii_result["entities"],
            }

        latency_us = time.time() * 1_000_000 - start_us
        governance["latency_us"] = latency_us

        # 5. Emit MODEL_RESPONSE event
        if self._audit:
            action = "ALLOW"
            if governance["pii_prompt"]["redacted"] or governance["pii_response"]["redacted"]:
                action = "REDACT"
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.MODEL_RESPONSE,
                    session_id=session_id,
                    domain="ai-infra",
                    action=action,
                    metadata={
                        "model": self.model_name,
                        "latency_us": latency_us,
                        "pii_prompt_count": governance["pii_prompt"]["count"],
                        "pii_response_count": governance["pii_response"]["count"],
                    },
                )
            )

        # 6. Return GovernedResponse
        return GovernedResponse(
            text=response_text,
            metadata=adapter_metadata,
            governance=governance,
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
