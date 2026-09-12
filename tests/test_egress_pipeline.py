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

import json

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

    @pytest.mark.parametrize(
        "params",
        [
            {"name": "read_file", "arguments": {"path": "notes.txt"}},
            {"name": "write_file", "arguments": {"filename": "report.docx"}},
            {"name": "db_query", "arguments": {"table": "users.accounts"}},
            {"name": "import_module", "arguments": {"module": "os.path"}},
        ],
        ids=["local-read", "local-write", "database", "module-name"],
    )
    async def test_local_tools_pass_and_contribute_no_allowlist_candidates(self, params):
        """Realistic negative controls, in the MCP argument shape.

        `{"expression": "2 + 2"}` passes for the wrong reason — it carries no
        dotted token at all. These do, and must still pass: spec §5.2 says a
        local file tool is not an egress attempt. The destinations assertion
        is the second half — anything landing there is offered to the
        operator by `admina egress suggest-allowlist`.
        """
        r = await _run(params, EgressPolicy(allow=["api.openai.com"]), "enforce")
        assert r.action == GovernanceAction.ALLOW
        assert r.checks["egress"]["status"] == "no_egress"
        assert r.checks["egress"]["destinations"] == []

    async def test_a_full_url_under_a_non_network_key_is_still_blocked(self):
        """Positive control: the bare-token gate must not open a hole."""
        r = await _run(
            {"name": "note", "arguments": {"memo": "https://publictestwiki.com/w.pl?action=edit"}},
            EgressPolicy(allow=["api.openai.com"]),
            "enforce",
        )
        assert r.action == GovernanceAction.BLOCK
        assert r.checks["egress"]["blocked"] == ["publictestwiki.com"]

    async def test_a_buried_destination_is_denied_not_passed_through(self):
        """The depth cap must fail closed on every surface, not just in analyze()."""
        buried: dict = {}
        cur = buried
        for _ in range(9):
            cur["k"] = {}
            cur = cur["k"]
        cur["url"] = "https://publictestwiki.com/w.pl?action=edit"
        r = await _run(buried, EgressPolicy(allow=["api.openai.com"]), "enforce")
        assert r.action == GovernanceAction.BLOCK
        assert r.checks["egress"]["status"] == "unresolvable"
        assert r.checks["egress"]["evidence"]["scan_truncated"] is True

    async def test_a_decoy_allowlisted_host_does_not_buy_passage_for_a_buried_one(self):
        """Truncation outranks a destination resolved above it, end to end."""
        decoy: dict = {"url": "https://api.openai.com/v1", "x": {}}
        cur = decoy["x"]
        for _ in range(8):
            cur["k"] = {}
            cur = cur["k"]
        cur["url"] = "https://publictestwiki.com/w.pl?action=edit"
        r = await _run(decoy, EgressPolicy(allow=["api.openai.com"]), "enforce")
        assert r.action == GovernanceAction.BLOCK
        assert r.checks["egress"]["status"] == "unresolvable"
        assert r.checks["egress"]["evidence"]["scan_truncated"] is True
        assert "nested past the scan depth limit" in r.checks["egress"]["reason"]

        observed = await _run(decoy, EgressPolicy(allow=["api.openai.com"]), "observe")
        assert observed.action == GovernanceAction.ALLOW
        assert observed.checks["egress"]["evidence"]["scan_truncated"] is True

    async def test_read_only_tools_are_read_off_the_policy_not_from_config(self):
        """The stage must not touch admina.yaml: the names ride on the policy."""
        policy = EgressPolicy(allow=["search.corp"], read_only_tools=frozenset({"docs_search"}))
        params = {
            "name": "docs_search",
            "arguments": {"url": "https://search.corp/q?query=how+do+i+configure+this"},
        }
        r = await _run(params, policy, "enforce")
        assert r.action == GovernanceAction.ALLOW
        assert r.checks["egress"]["write_shaped"] is False
        assert r.checks["egress"]["evidence"]["write_shaped_reason"] == "read_only_tools override"

    async def test_egress_check_carries_no_payload_content(self):
        """checks["egress"] is persisted to forensic and ClickHouse.

        Spec §4.4 rests the stage's position on it holding structured
        metadata only — hostnames, field *names*, booleans, fixed reason
        strings — never payload values. Nothing else defends that property.
        """
        secret = "MY-SUPER-SECRET-PAYLOAD-VALUE"
        params = {
            "name": "http_post",
            "arguments": {
                "url": f"https://user:{secret}@publictestwiki.com/{secret}?text={secret}",
                "body": {"note": secret},
                "text": secret,
                "host": f"${{{secret}}}",
            },
        }
        r = await _run(params, EgressPolicy(allow=[]), "enforce")
        blob = json.dumps(r.checks["egress"])
        assert secret not in blob
        # And the parts that *are* there are the metadata, not the payload.
        assert r.checks["egress"]["evidence"]["unresolvable_fields"] == ["host"]

    async def test_stage_reads_no_configuration(self, monkeypatch):
        """`run_pipeline` declares itself free of storage and side effects.

        A `load_config()` inside the stage is a blocking filesystem read and
        a YAML parse inside an async request handler, on every governed call
        on all five surfaces — and a per-request warning when admina.yaml is
        malformed. Making the loader explode is the only way to prove the
        stage never reaches for it (spec D5).
        """

        # Engine acquisition legitimately reads admina.yaml; do it first, so
        # only the per-request path is under the microscope.
        firewall, pii, loop = get_firewall(), get_pii_engine(), get_loop_breaker()

        def _explode(*a, **kw):
            raise AssertionError("the egress stage must not load configuration")

        monkeypatch.setattr("admina.core.config.load_config", _explode)
        policy = EgressPolicy(allow=["api.openai.com"], read_only_tools=frozenset({"t"}))
        params = {"url": "https://publictestwiki.com/x"}
        r = await run_pipeline(
            body={"params": params},
            content_str=str(params),
            session_id="s1",
            agent_id="a1",
            request_id="r1",
            params=params,
            firewall=firewall,
            pii_redactor=pii,
            loop_breaker=loop,
            governance_guards=[],
            loop_enabled=False,
            egress_policy=policy,
            egress_mode="enforce",
        )
        assert r.action == GovernanceAction.BLOCK

    async def test_stage_is_skipped_when_policy_is_none(self):
        r = await _run({"url": "https://anything.com"}, None, "enforce")
        assert r.action == GovernanceAction.ALLOW
        assert "egress" not in r.checks


class _RecordingGuard:
    """A governance guard that records whether it was ever invoked."""

    name = "recorder"

    def __init__(self) -> None:
        self.called = False

    async def inspect_request(self, payload: dict) -> dict:
        self.called = True
        return {"action": "ALLOW"}


@pytest.mark.anyio
async def test_blocked_egress_short_circuits_the_guards():
    """Before-the-guards is the real ordering constraint (not the PII stage).

    A denied destination must stop the pipeline before any plugin guard runs
    — handing an unauthorised outbound call to third-party guard code is
    exactly what this ordering exists to prevent. This must fail if the
    egress stage were moved after the guard loop.
    """
    guard = _RecordingGuard()
    r = await run_pipeline(
        body={"params": {"url": "https://publictestwiki.com/w.pl?action=edit&text=long enough"}},
        content_str="https://publictestwiki.com/w.pl?action=edit&text=long enough",
        session_id="s1",
        agent_id="a1",
        request_id="r1",
        params={"url": "https://publictestwiki.com/w.pl?action=edit&text=long enough"},
        firewall=get_firewall(),
        pii_redactor=get_pii_engine(),
        loop_breaker=get_loop_breaker(),
        governance_guards=[guard],
        loop_enabled=False,
        egress_policy=EgressPolicy(allow=["api.openai.com"]),
        egress_mode="enforce",
    )
    assert r.action == GovernanceAction.BLOCK
    assert guard.called is False


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
