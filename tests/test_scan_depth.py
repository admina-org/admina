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

"""Text nested past the scan depth of the governance pipeline.

``/mcp`` and ``/api/v1/validate`` scan every string of the request down to
:data:`~admina.domains.governance.SCAN_DEPTH` levels, as the gateway does.
Text deeper than that is neither scanned nor redacted, so the request is
refused (``checks["scan_depth"]``) in ``enforce`` mode, and recorded as a
would-be block in ``observe``.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from admina.domains.governance import (
    SCAN_DEPTH,
    _extract_text_fields,
    _has_deep_text,
    run_pipeline,
)


class _Firewall:
    def check(self, text):
        hit = "INJECT" in text
        return {"is_injection": hit, "risk_level": "high" if hit else "low"}


class _PII:
    def redact(self, text):
        count = text.count("@")
        return {"redacted_text": text.replace("@", "[AT]"), "entities": [], "count": count}


class _LoopBreaker:
    def check(self, session_id, content):
        return {"is_loop": False, "similarity": 0.0}


def _nested(value, levels: int):
    for _ in range(levels):
        value = {"k": value}
    return value


def _run(params: dict, **overrides):
    kwargs = {
        "body": {"method": "tools/call", "params": params},
        "content_str": "",
        "session_id": "s1",
        "agent_id": "a1",
        "request_id": "r1",
        "params": params,
        "firewall": _Firewall(),
        "pii_redactor": _PII(),
        "loop_breaker": _LoopBreaker(),
        "governance_guards": [],
    }
    kwargs.update(overrides)
    return asyncio.run(run_pipeline(**kwargs))


def test_scan_depth_is_the_gateway_depth():
    from admina.domains.agent_security.scan_policy import REQUEST_SCAN_DEPTH

    assert SCAN_DEPTH == REQUEST_SCAN_DEPTH


def test_text_ten_levels_deep_is_scanned():
    result = _run({"arguments": _nested("INJECT", 10)})
    assert result.action.value == "block"
    assert "firewall" in result.checks
    assert "scan_depth" not in result.checks


def test_text_past_the_depth_blocks_in_enforce():
    result = _run({"arguments": _nested("harmless", SCAN_DEPTH + 2)})
    assert result.action.value == "block"
    assert result.checks["scan_depth"] == {"action": "BLOCK", "reason": "depth_limit_exceeded"}


def test_text_past_the_depth_is_a_would_be_block_in_observe():
    result = _run({"arguments": _nested("harmless", SCAN_DEPTH + 2)}, mode="observe")
    assert result.action.value == "allow"
    assert result.would_action.value == "block"
    assert "scan_depth" in result.checks


@pytest.mark.parametrize("leaf", [42, None, True, {}, [], ""])
def test_numbers_and_empty_values_past_the_depth_hold_no_text(leaf):
    assert not _has_deep_text(leaf, SCAN_DEPTH + 1)
    assert _run({"arguments": leaf}).action.value == "allow"


@pytest.mark.parametrize("value", ["x", [1], {"a": 1}])
def test_strings_and_non_empty_values_past_the_depth_hold_text(value):
    # As for the gateway: a non-empty container past the depth could hold text.
    assert _has_deep_text(value, SCAN_DEPTH + 1)


def test_a_key_past_the_depth_is_text():
    result = _run({"arguments": _nested(42, SCAN_DEPTH + 2)})
    assert "scan_depth" in result.checks


def test_pii_alone_blocks_text_it_cannot_reach():
    result = _run({"arguments": _nested("a@b", SCAN_DEPTH + 2)}, injection_enabled=False)
    assert result.action.value == "block"
    assert "scan_depth" in result.checks


def test_nothing_enabled_leaves_deep_text_alone():
    result = _run(
        {"arguments": _nested("a@b", SCAN_DEPTH + 2)},
        injection_enabled=False,
        pii_enabled=False,
    )
    assert result.action.value == "allow"


def test_extract_text_fields_stops_at_the_depth():
    assert _extract_text_fields(_nested("x", SCAN_DEPTH)) == ["k"] * SCAN_DEPTH + ["x"]
    assert "x" not in _extract_text_fields(_nested("x", SCAN_DEPTH + 1))


# ── /api/v1/validate ──────────────────────────────────────────


def _validate(payload: dict) -> httpx.Response:
    from fastapi import FastAPI

    from admina.proxy.api.integration import create_integration_endpoints

    app = FastAPI()
    app.include_router(
        create_integration_endpoints(
            get_firewall=lambda: _Firewall(),
            get_pii_scanner=lambda: _PII(),
            get_loop_breaker=lambda: _LoopBreaker(),
            get_forensic_box=lambda: None,
        )
    )

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/api/v1/validate", json=payload)

    return asyncio.run(go())


@pytest.mark.parametrize("content", [{"text": "hello"}, ["hello"], 42])
def test_validate_refuses_content_that_is_not_a_string(content):
    response = _validate({"content": content})
    assert response.status_code == 400
    assert "string" in response.json()["detail"]


def test_validate_accepts_a_string():
    assert _validate({"content": "hello"}).status_code == 200
