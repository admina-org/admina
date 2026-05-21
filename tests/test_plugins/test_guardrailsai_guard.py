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

"""Tests for the GuardrailsAI governance guard plugin.

All tests use mock validators — guardrails-ai is NOT required to be
installed for the test suite to pass.
"""

from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

from admina.plugins.base import BaseGovernanceGuard


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


# ── Helpers: fake guardrails module ─────────────────────────────


def _make_fake_guardrails(
    validation_passed: bool = True,
    error: str = "",
    failed_validations: list | None = None,
):
    """Build a fake ``guardrails`` module with controllable outcomes.

    Returns a context-manager that patches ``sys.modules`` so that
    ``import guardrails`` and ``import guardrails.hub`` resolve to
    our fakes.
    """
    if failed_validations is None:
        failed_validations = []

    outcome = SimpleNamespace(
        validation_passed=validation_passed,
        error=error,
        failed_validations=failed_validations,
    )

    # Fake Guard class
    class FakeGuard:
        def use_many(self, *validators):
            return self

        def validate(self, text: str):
            return outcome

    # Fake hub validators
    class FakeToxicLanguage:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeDetectPII:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeDetectJailbreak:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeBiasCheck:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    # Build fake modules
    hub = ModuleType("guardrails.hub")
    hub.ToxicLanguage = FakeToxicLanguage  # type: ignore[attr-defined]
    hub.DetectPII = FakeDetectPII  # type: ignore[attr-defined]
    hub.DetectJailbreak = FakeDetectJailbreak  # type: ignore[attr-defined]
    hub.BiasCheck = FakeBiasCheck  # type: ignore[attr-defined]

    guardrails_mod = ModuleType("guardrails")
    guardrails_mod.Guard = FakeGuard  # type: ignore[attr-defined]

    return {
        "guardrails": guardrails_mod,
        "guardrails.hub": hub,
    }


# ═══════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════


class TestGuardrailsAIGuardInterface:
    """Verify the domain implements BaseGovernanceGuard correctly."""

    def test_is_governance_domain(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(config={"validators": []})
            assert isinstance(domain, BaseGovernanceGuard)

    def test_name_property(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(config={"validators": []})
            assert domain.name == "guardrailsai"


class TestGuardrailsAIGuardInit:
    """Test __init__ validation and configuration."""

    def test_remote_mode_rejected(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            with pytest.raises(ValueError, match="inference_mode='local'"):
                GuardrailsAIGuard(config={"inference_mode": "remote"})

    def test_local_mode_accepted(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(config={"inference_mode": "local", "validators": []})
            assert domain.name == "guardrailsai"

    def test_default_mode_is_local(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            # No inference_mode key → defaults to local, no error
            domain = GuardrailsAIGuard(config={"validators": []})
            assert domain.name == "guardrailsai"

    def test_unknown_validator_raises(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            with pytest.raises(ValueError, match="Unknown GuardrailsAI validator"):
                GuardrailsAIGuard(config={"validators": [{"name": "nonexistent_validator"}]})

    def test_loads_validators_from_config(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(
                config={
                    "validators": [
                        {"name": "toxic_language", "threshold": 0.8},
                        {"name": "detect_pii", "pii_entities": ["EMAIL"]},
                    ],
                }
            )
            assert domain._validator_count == 2


class TestGuardrailsAIGuardImportError:
    """Test behavior when guardrails-ai is not installed."""

    def test_import_error_message(self):
        # Remove guardrails from modules to simulate not installed
        with patch.dict(sys.modules, {"guardrails": None}):
            # Need to reimport to trigger the check
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                _import_guardrails,
            )

            with pytest.raises(ImportError, match="guardrails-ai"):
                _import_guardrails()


class TestGuardrailsAIGuardInspect:
    """Test inspect_request and inspect_response."""

    def test_empty_content_allows(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(config={"validators": []})

            result = _run(domain.inspect_request({"content": ""}))
            assert result["action"] == "ALLOW"
            assert result["risk_level"] == "LOW"
            assert result["guard"] == "guardrailsai"

    def test_missing_content_allows(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(config={"validators": []})

            result = _run(domain.inspect_request({}))
            assert result["action"] == "ALLOW"

    def test_validation_passed_allows(self):
        fake_mods = _make_fake_guardrails(validation_passed=True)
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(
                config={
                    "validators": [{"name": "toxic_language"}],
                }
            )

            result = _run(domain.inspect_request({"content": "Hello world"}))
            assert result["action"] == "ALLOW"
            assert result["risk_level"] == "LOW"
            assert result["metadata"]["validators_run"] == 1

    def test_validation_failed_blocks(self):
        class FakeFailedValidator:
            __class__ = type("ToxicLanguage", (), {})

        fake_mods = _make_fake_guardrails(
            validation_passed=False,
            error="Content is toxic",
            failed_validations=[FakeFailedValidator()],
        )
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(
                config={
                    "validators": [{"name": "toxic_language"}],
                }
            )

            result = _run(domain.inspect_request({"content": "toxic text"}))
            assert result["action"] == "BLOCK"
            assert result["risk_level"] == "HIGH"
            assert result["details"] == "Content is toxic"
            assert "ToxicLanguage" in result["metadata"]["failed"]

    def test_inspect_response_same_as_request(self):
        fake_mods = _make_fake_guardrails(validation_passed=True)
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(
                config={
                    "validators": [{"name": "toxic_language"}],
                }
            )

            req_result = _run(domain.inspect_request({"content": "test"}))
            resp_result = _run(domain.inspect_response({"content": "test"}))
            assert req_result["action"] == resp_result["action"]
            assert req_result["risk_level"] == resp_result["risk_level"]

    def test_inspect_response_blocks_toxic(self):
        fake_mods = _make_fake_guardrails(
            validation_passed=False,
            error="Toxic response",
            failed_validations=[],
        )
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                GuardrailsAIGuard,
            )

            domain = GuardrailsAIGuard(
                config={
                    "validators": [{"name": "toxic_language"}],
                }
            )

            result = _run(domain.inspect_response({"content": "bad output"}))
            assert result["action"] == "BLOCK"


class TestGuardrailsAIValidatorLoading:
    """Test the _load_validator helper."""

    def test_load_known_validators(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                _load_validator,
            )

            v = _load_validator("toxic_language", {"threshold": 0.5})
            assert v.kwargs["threshold"] == 0.5
            assert v.kwargs["on_fail"] == "noop"

    def test_on_fail_defaults_to_noop(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                _load_validator,
            )

            v = _load_validator("detect_pii", {})
            assert v.kwargs["on_fail"] == "noop"

    def test_on_fail_not_overwritten_if_set(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                _load_validator,
            )

            v = _load_validator("detect_pii", {"on_fail": "exception"})
            assert v.kwargs["on_fail"] == "exception"

    def test_unknown_validator_raises_valueerror(self):
        fake_mods = _make_fake_guardrails()
        with patch.dict(sys.modules, fake_mods):
            from admina.plugins.builtin.guards.guardrailsai_guard import (
                _load_validator,
            )

            with pytest.raises(ValueError, match="Unknown GuardrailsAI validator"):
                _load_validator("not_real", {})
