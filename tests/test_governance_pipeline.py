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

"""Tests for the extracted governance pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure proxy/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "proxy"))

from admina.proxy.governance import (
    _extract_text_fields,
    run_pipeline,
    safe_serialize,
)

# ── Mock objects ─────────────────────────────────────────────


class MockFirewall:
    def check(self, text):
        if "INJECT" in text:
            return {"is_injection": True, "risk_level": "high", "patterns": ["test"]}
        return {"is_injection": False, "risk_level": "low", "patterns": []}


class MockPII:
    def redact(self, text):
        if "@" in text:
            return {
                "redacted_text": text.replace("@", "[AT]"),
                "entities": [{"type": "EMAIL"}],
                "count": 1,
            }
        return {"redacted_text": text, "entities": [], "count": 0}


class MockLoopBreaker:
    def __init__(self, *, is_loop=False, similarity=0.0):
        self._is_loop = is_loop
        self._similarity = similarity

    def check(self, session_id, content):
        return {"is_loop": self._is_loop, "similarity": self._similarity}


class MockGuard:
    def __init__(self, name, action="ALLOW", risk_level="low"):
        self.name = name
        self._action = action
        self._risk_level = risk_level

    async def inspect_request(self, payload):
        return {"action": self._action, "risk_level": self._risk_level}


class FailingGuard:
    name = "failing"

    async def inspect_request(self, payload):
        raise RuntimeError("guard crashed")


# ── Helper function tests ────────────────────────────────────


class TestExtractTextFields:
    def test_string(self):
        assert _extract_text_fields("hello") == ["hello"]

    def test_dict(self):
        # Keys are now scanned alongside values (injection/PII in field names).
        result = _extract_text_fields({"a": "x", "b": "y"})
        assert sorted(result) == ["a", "b", "x", "y"]

    def test_nested(self):
        # Keys "a" and "b" are extracted in addition to the nested value.
        result = _extract_text_fields({"a": {"b": "deep"}})
        assert set(result) == {"a", "b", "deep"}

    def test_list(self):
        result = _extract_text_fields(["a", "b"])
        assert result == ["a", "b"]

    def test_depth_limit(self):
        # DoS cap: content nested beyond _MAX_SCAN_DEPTH is not returned.
        # Build 10 levels deep; the leaf string "hello" at depth 10 must be dropped.
        deep = "hello"
        for _ in range(10):
            deep = {"nested": deep}
        result = _extract_text_fields(deep)
        assert "hello" not in result

    def test_empty(self):
        assert _extract_text_fields({}) == []


class TestSafeSerialize:
    def test_enum_value(self):
        from admina.core.types import GovernanceAction

        assert safe_serialize(GovernanceAction.BLOCK) == "block"

    def test_plain_value(self):
        assert safe_serialize("hello") == "hello"

    def test_number(self):
        assert safe_serialize(42) == 42


# ── Pipeline tests ───────────────────────────────────────────


def _base_kwargs(**overrides):
    defaults = {
        "body": {"method": "tools/call", "params": {"text": "hello"}},
        "content_str": "hello",
        "session_id": "s1",
        "agent_id": "a1",
        "request_id": "r1",
        "params": {"text": "hello"},
        "firewall": MockFirewall(),
        "pii_redactor": MockPII(),
        "loop_breaker": MockLoopBreaker(),
        "governance_guards": [],
    }
    defaults.update(overrides)
    return defaults


@pytest.mark.anyio
async def test_clean_request_allows():
    result = await run_pipeline(**_base_kwargs())
    assert result.action.value == "allow"
    assert result.risk_level.value == "low"
    assert result.gov_response is not None
    assert result.gov_response.action == "ALLOW"


@pytest.mark.anyio
async def test_injection_blocks():
    result = await run_pipeline(
        **_base_kwargs(
            body={"method": "tools/call", "params": {"text": "INJECT this"}},
            content_str="INJECT this",
            params={"text": "INJECT this"},
        )
    )
    assert result.action.value == "block"
    assert "firewall" in result.checks
    assert result.gov_response.action == "BLOCK"


@pytest.mark.anyio
async def test_injection_disabled():
    result = await run_pipeline(
        **_base_kwargs(
            body={"method": "tools/call", "params": {"text": "INJECT this"}},
            content_str="INJECT this",
            params={"text": "INJECT this"},
            injection_enabled=False,
        )
    )
    assert result.action.value == "allow"


@pytest.mark.anyio
async def test_pii_redacts():
    result = await run_pipeline(
        **_base_kwargs(
            body={"method": "tools/call", "params": {"text": "email alice@test.com"}},
            content_str="email alice@test.com",
            params={"text": "email alice@test.com"},
        )
    )
    assert result.action.value == "allow"
    assert result.checks["pii_redaction"]["count"] == 1
    assert result.redacted_body != result.checks  # redacted body was modified


@pytest.mark.anyio
async def test_pii_disabled():
    result = await run_pipeline(
        **_base_kwargs(
            body={"method": "tools/call", "params": {"text": "email alice@test.com"}},
            content_str="email alice@test.com",
            params={"text": "email alice@test.com"},
            pii_enabled=False,
        )
    )
    assert "pii_redaction" not in result.checks


@pytest.mark.anyio
async def test_loop_breaker_circuit_breaks():
    result = await run_pipeline(
        **_base_kwargs(
            loop_breaker=MockLoopBreaker(is_loop=True, similarity=0.98),
        )
    )
    assert result.action.value == "circuit_break"
    assert result.risk_level.value == "high"
    assert result.gov_response.domain == "loop_breaker"


@pytest.mark.anyio
async def test_guard_blocks():
    guard = MockGuard("test_guard", action="BLOCK", risk_level="high")
    result = await run_pipeline(**_base_kwargs(governance_guards=[guard]))
    assert result.action.value == "block"
    assert "guard_test_guard" in result.checks


@pytest.mark.anyio
async def test_guard_allows():
    guard = MockGuard("permissive", action="ALLOW")
    result = await run_pipeline(**_base_kwargs(governance_guards=[guard]))
    assert result.action.value == "allow"


@pytest.mark.anyio
async def test_failing_guard_does_not_crash():
    result = await run_pipeline(**_base_kwargs(governance_guards=[FailingGuard()]))
    assert result.action.value == "allow"
    assert result.checks["guard_failing"]["action"] == "ERROR"
    assert result.checks["guard_failing"].get("error") is not None


@pytest.mark.anyio
async def test_empty_body():
    result = await run_pipeline(
        **_base_kwargs(
            body={},
            content_str="",
            params={},
        )
    )
    assert result.action.value == "allow"


@pytest.mark.anyio
async def test_latency_recorded():
    result = await run_pipeline(**_base_kwargs())
    assert result.latency_ms > 0


@pytest.mark.anyio
async def test_gov_response_has_request_id():
    result = await run_pipeline(**_base_kwargs(request_id="test-req-123"))
    assert result.gov_response.request_id == "test-req-123"


@pytest.mark.anyio
async def test_loop_breaker_skips_firewall():
    """When loop is detected, firewall should not run."""
    result = await run_pipeline(
        **_base_kwargs(
            body={"method": "tools/call", "params": {"text": "INJECT this"}},
            content_str="INJECT this",
            params={"text": "INJECT this"},
            loop_breaker=MockLoopBreaker(is_loop=True),
        )
    )
    assert result.action.value == "circuit_break"
    assert "firewall" not in result.checks


@pytest.mark.anyio
async def test_multiple_guards_first_block_wins():
    guards = [
        MockGuard("first", action="BLOCK", risk_level="high"),
        MockGuard("second", action="ALLOW"),
    ]
    result = await run_pipeline(**_base_kwargs(governance_guards=guards))
    assert result.action.value == "block"
    assert "guard_first" in result.checks
    assert "guard_second" not in result.checks


class TestGovernanceMode:
    """The pipeline supports enforce / observe / dry-run modes."""

    @pytest.mark.anyio
    async def test_enforce_blocks_injection(self) -> None:
        body = {"params": {"text": "INJECT bad stuff"}}
        result = await run_pipeline(
            body=body,
            content_str="INJECT bad stuff",
            session_id="s",
            agent_id="a",
            request_id="r",
            params=body["params"],
            firewall=MockFirewall(),
            pii_redactor=MockPII(),
            loop_breaker=MockLoopBreaker(),
            governance_guards=[],
            mode="enforce",
        )
        assert result.action.value == "block"
        assert result.would_action is None
        assert result.mode == "enforce"

    @pytest.mark.anyio
    async def test_observe_does_not_block(self) -> None:
        body = {"params": {"text": "INJECT bad stuff"}}
        result = await run_pipeline(
            body=body,
            content_str="INJECT bad stuff",
            session_id="s",
            agent_id="a",
            request_id="r",
            params=body["params"],
            firewall=MockFirewall(),
            pii_redactor=MockPII(),
            loop_breaker=MockLoopBreaker(),
            governance_guards=[],
            mode="observe",
        )
        assert result.action.value == "allow"
        assert result.would_action is not None
        assert result.would_action.value == "block"
        assert result.mode == "observe"

    @pytest.mark.anyio
    async def test_dry_run_mode(self) -> None:
        body = {"params": {"text": "INJECT bad stuff"}}
        result = await run_pipeline(
            body=body,
            content_str="INJECT bad stuff",
            session_id="s",
            agent_id="a",
            request_id="r",
            params=body["params"],
            firewall=MockFirewall(),
            pii_redactor=MockPII(),
            loop_breaker=MockLoopBreaker(),
            governance_guards=[],
            mode="dry-run",
        )
        assert result.action.value == "allow"
        assert result.would_action.value == "block"
        assert result.mode == "dry-run"

    @pytest.mark.anyio
    async def test_observe_does_not_downgrade_clean_traffic(self) -> None:
        body = {"params": {"text": "hello world"}}
        result = await run_pipeline(
            body=body,
            content_str="hello world",
            session_id="s",
            agent_id="a",
            request_id="r",
            params=body["params"],
            firewall=MockFirewall(),
            pii_redactor=MockPII(),
            loop_breaker=MockLoopBreaker(),
            governance_guards=[],
            mode="observe",
        )
        assert result.action.value == "allow"
        assert result.would_action is None
