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

"""Wiring tests for the egress stage inside run_pipeline.

The egress module itself (analyze, EgressPolicy, resolve_egress_mode) is
tested in isolation elsewhere; this file only exercises the pipeline seam —
position (after PII, before guards), the skip-when-None contract, and that
the resulting checks["egress"] dict reaches the persisted event details.
"""

import pytest

from admina.core.types import GovernanceAction
from admina.domains.agent_security.egress import EgressPolicy
from admina.domains.governance import build_governance_details, run_pipeline
from admina.engines import get_firewall, get_loop_breaker, get_pii_engine


async def _run(params, policy, mode):
    return await run_pipeline(
        body={"params": params},
        content_str=str(params),
        session_id="s1",
        agent_id="a1",
        request_id="r1",
        params=params,
        firewall=get_firewall(),
        pii_redactor=get_pii_engine(),
        loop_breaker=get_loop_breaker(),
        governance_guards=[],
        loop_enabled=False,
        egress_policy=policy,
        egress_mode=mode,
    )


@pytest.mark.anyio
class TestEgressStage:
    async def test_unlisted_destination_is_blocked_in_enforce(self):
        r = await _run(
            {"url": "https://publictestwiki.com/w.pl?action=edit&text=a long enough payload"},
            EgressPolicy(allow=["api.openai.com"]),
            "enforce",
        )
        assert r.action == GovernanceAction.BLOCK
        assert r.checks["egress"]["allowed"] is False
        assert r.checks["egress"]["destinations"] == ["publictestwiki.com"]
        # The ruling on top of the brief: name which destination caused the
        # block, since a single call can carry several destinations of which
        # only some are unlisted.
        assert r.checks["egress"]["blocked"] == ["publictestwiki.com"]

    async def test_allowlisted_destination_passes(self):
        r = await _run(
            {"url": "https://api.openai.com/v1/chat"},
            EgressPolicy(allow=["api.openai.com"]),
            "enforce",
        )
        assert r.action == GovernanceAction.ALLOW

    async def test_observe_records_without_blocking(self):
        r = await _run(
            {"url": "https://publictestwiki.com/w.pl?action=edit&text=a long enough payload"},
            EgressPolicy(allow=[]),
            "observe",
        )
        assert r.action == GovernanceAction.ALLOW
        assert r.checks["egress"]["destinations"] == ["publictestwiki.com"]
        assert r.checks["egress"]["write_shaped"] is True

    async def test_non_network_tool_is_untouched_under_default_deny(self):
        r = await _run({"expression": "2 + 2"}, EgressPolicy(allow=[]), "enforce")
        assert r.action == GovernanceAction.ALLOW
        assert r.checks["egress"]["status"] == "no_egress"

    async def test_stage_is_skipped_when_policy_is_none(self):
        r = await _run({"url": "https://anything.com"}, None, "enforce")
        assert r.action == GovernanceAction.ALLOW
        assert "egress" not in r.checks


@pytest.mark.anyio
async def test_egress_check_reaches_persisted_details():
    """The coordination detector consumes details["egress"]; it must be there."""
    r = await _run(
        {"url": "https://api.openai.com/v1/chat", "body": {"note": "a long enough payload"}},
        EgressPolicy(allow=["api.openai.com"]),
        "enforce",
    )
    details = build_governance_details(r)
    assert details["egress"]["destinations"] == ["api.openai.com"]
    assert details["egress"]["write_shaped"] is True
