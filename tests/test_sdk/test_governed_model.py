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

"""Tests for sdk.governed_model module."""

from __future__ import annotations

import asyncio
from typing import Any

from admina.core.event_bus import EventBus, EventType, GovernanceEvent
from admina.sdk.governed_model import BaseModelAdapter, GovernedModel, GovernedResponse

# ---------------------------------------------------------------------------
# Mock adapter for testing
# ---------------------------------------------------------------------------


class MockAdapter(BaseModelAdapter):
    """Test adapter that echoes the prompt."""

    def __init__(self, response_text: str = "mock response") -> None:
        self._response_text = response_text
        self.last_prompt: str | None = None
        self.call_count: int = 0

    async def send(self, prompt: str, context: Any = None, **kwargs: Any) -> dict:
        """Record the prompt and return canned response."""
        self.last_prompt = prompt
        self.call_count += 1
        return {
            "text": self._response_text,
            "metadata": {"tokens": 10, "latency_ms": 1.0},
        }

    def supports_model(self, model_name: str) -> bool:
        return True

    @property
    def name(self) -> str:
        return "mock"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGovernedResponse:
    """Tests for the GovernedResponse dataclass."""

    def test_defaults(self) -> None:
        """GovernedResponse has sensible defaults."""
        r = GovernedResponse(text="hello")
        assert r.text == "hello"
        assert r.metadata == {}
        assert r.governance == {}


class TestGovernedModelBasic:
    """Basic GovernedModel tests with PII redaction disabled."""

    def test_ask_returns_governed_response(self) -> None:
        """ask() returns a GovernedResponse."""
        adapter = MockAdapter(response_text="the answer")
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=False)
        result = asyncio.run(model.ask("hello"))

        assert isinstance(result, GovernedResponse)
        assert result.text == "the answer"
        assert result.metadata["tokens"] == 10

    def test_ask_forwards_prompt(self) -> None:
        """ask() forwards the prompt to the adapter."""
        adapter = MockAdapter()
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=False)
        asyncio.run(model.ask("what is 2+2?"))

        assert adapter.last_prompt == "what is 2+2?"
        assert adapter.call_count == 1

    def test_ask_forwards_context(self) -> None:
        """ask() passes context to adapter.send()."""

        class ContextAdapter(MockAdapter):
            def __init__(self) -> None:
                super().__init__()
                self.last_context: Any = None

            async def send(self, prompt: str, context: Any = None, **kwargs: Any) -> dict:
                self.last_context = context
                return await super().send(prompt, context, **kwargs)

        adapter = ContextAdapter()
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=False)
        asyncio.run(model.ask("hi", context={"doc": "test"}))

        assert adapter.last_context == {"doc": "test"}

    def test_ask_sync_works(self) -> None:
        """ask_sync() returns same result as ask()."""
        adapter = MockAdapter(response_text="sync answer")
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=False)
        result = model.ask_sync("hello")

        assert isinstance(result, GovernedResponse)
        assert result.text == "sync answer"

    def test_ask_sync_inside_running_loop(self) -> None:
        """ask_sync() works even when called from within an async context."""

        async def _inner():
            adapter = MockAdapter(response_text="from loop")
            model = GovernedModel("test-model", adapter=adapter, pii_redaction=False)
            return model.ask_sync("hello")

        result = asyncio.run(_inner())
        assert isinstance(result, GovernedResponse)
        assert result.text == "from loop"

    def test_no_adapter_raises(self) -> None:
        """ask() raises RuntimeError when no adapter is set."""
        model = GovernedModel("test-model", adapter=None, pii_redaction=False)
        try:
            asyncio.run(model.ask("hello"))
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "No model adapter configured" in str(e)


class TestGovernedModelPII:
    """Tests for PII redaction in GovernedModel."""

    def test_pii_redacted_in_prompt(self) -> None:
        """PII in the prompt is redacted before reaching the adapter."""
        adapter = MockAdapter()
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=True)
        asyncio.run(model.ask("Contact me at test@example.com"))

        # The adapter should receive redacted text
        assert "test@example.com" not in adapter.last_prompt
        assert "[EMAIL]" in adapter.last_prompt

    def test_pii_redacted_in_response(self) -> None:
        """PII in the model response is redacted."""
        adapter = MockAdapter(response_text="Call 123-456-7890 for info")
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=True)
        result = asyncio.run(model.ask("hello"))

        # The raw phone number must not appear in the output
        assert "123-456-7890" not in result.text
        # PII was detected in the response
        assert result.governance["pii_response"]["redacted"] is True
        assert result.governance["pii_response"]["count"] >= 1

    def test_governance_tracks_pii(self) -> None:
        """governance dict tracks PII redaction details."""
        adapter = MockAdapter()
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=True)
        result = asyncio.run(model.ask("Email: test@example.com"))

        assert result.governance["pii_prompt"]["redacted"] is True
        assert result.governance["pii_prompt"]["count"] >= 1

    def test_no_pii_clean_pass(self) -> None:
        """Clean text passes through without redaction flags."""
        adapter = MockAdapter(response_text="all good")
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=True)
        result = asyncio.run(model.ask("what is the weather"))

        assert result.governance["pii_prompt"]["redacted"] is False
        assert result.governance["pii_prompt"]["count"] == 0

    def test_pii_disabled(self) -> None:
        """PII redaction can be disabled."""
        adapter = MockAdapter()
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=False)
        asyncio.run(model.ask("Email: test@example.com"))

        assert adapter.last_prompt == "Email: test@example.com"


class TestGovernedModelEvents:
    """Tests for event emission."""

    def test_emits_model_call_event(self) -> None:
        """ask() emits a MODEL_CALL event."""
        # Use a fresh bus to isolate
        import admina.sdk.governed_model as gm

        original_bus = gm.bus
        test_bus = EventBus()
        gm.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.MODEL_CALL, events.append)

            adapter = MockAdapter()
            model = GovernedModel("llama3", adapter=adapter, pii_redaction=False)
            asyncio.run(model.ask("hello"))

            assert len(events) == 1
            assert events[0].event_type == EventType.MODEL_CALL
            assert events[0].domain == "ai-infra"
            assert events[0].metadata["model"] == "llama3"
        finally:
            gm.bus = original_bus

    def test_emits_model_response_event(self) -> None:
        """ask() emits a MODEL_RESPONSE event."""
        import admina.sdk.governed_model as gm

        original_bus = gm.bus
        test_bus = EventBus()
        gm.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.MODEL_RESPONSE, events.append)

            adapter = MockAdapter()
            model = GovernedModel("llama3", adapter=adapter, pii_redaction=False)
            asyncio.run(model.ask("hello"))

            assert len(events) == 1
            assert events[0].event_type == EventType.MODEL_RESPONSE
            assert events[0].action == "ALLOW"
        finally:
            gm.bus = original_bus

    def test_redact_action_on_pii(self) -> None:
        """MODEL_RESPONSE action is REDACT when PII was found."""
        import admina.sdk.governed_model as gm

        original_bus = gm.bus
        test_bus = EventBus()
        gm.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.MODEL_RESPONSE, events.append)

            adapter = MockAdapter()
            model = GovernedModel("llama3", adapter=adapter, pii_redaction=True)
            asyncio.run(model.ask("Email me at user@test.com"))

            assert len(events) == 1
            assert events[0].action == "REDACT"
        finally:
            gm.bus = original_bus

    def test_audit_disabled(self) -> None:
        """No events emitted when audit=False."""
        import admina.sdk.governed_model as gm

        original_bus = gm.bus
        test_bus = EventBus()
        gm.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe_all(events.append)

            adapter = MockAdapter()
            model = GovernedModel("llama3", adapter=adapter, audit=False, pii_redaction=False)
            asyncio.run(model.ask("hello"))

            assert len(events) == 0
        finally:
            gm.bus = original_bus

    def test_governance_has_latency(self) -> None:
        """governance dict includes latency_us."""
        adapter = MockAdapter()
        model = GovernedModel("test-model", adapter=adapter, pii_redaction=False)
        result = asyncio.run(model.ask("hello"))

        assert "latency_us" in result.governance
        assert result.governance["latency_us"] > 0
