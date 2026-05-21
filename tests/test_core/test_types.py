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

"""Tests for core.types — GovernanceRequest, GovernanceResponse, RiskLevel."""

from __future__ import annotations

from admina.core.types import GovernanceRequest, GovernanceResponse, RiskLevel


class TestRiskLevel:
    """RiskLevel is the single source of truth across all domains."""

    def test_values(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_str_mixin(self):
        # str mixin allows direct JSON serialisation
        assert str(RiskLevel.HIGH) == "RiskLevel.HIGH"
        assert RiskLevel.HIGH == "high"

    def test_ordering_via_values(self):
        levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert levels == sorted(levels, key=lambda lvl: list(RiskLevel).index(lvl))


class TestGovernanceRequest:
    def test_defaults(self):
        req = GovernanceRequest(content="hello")
        assert req.direction == "inbound"
        assert req.protocol == "unknown"
        assert req.request_id  # auto-generated UUID

    def test_to_dict_excludes_raw(self):
        req = GovernanceRequest(content="test", raw={"original": "payload"})
        d = req.to_dict()
        assert "raw" not in d
        assert d["content"] == "test"


class TestGovernanceResponse:
    def test_defaults(self):
        resp = GovernanceResponse(content="ok")
        assert resp.action == "ALLOW"
        assert resp.risk_level == "LOW"

    def test_to_dict(self):
        resp = GovernanceResponse(content="blocked", action="BLOCK", risk_level="HIGH")
        d = resp.to_dict()
        assert d["action"] == "BLOCK"
        assert d["risk_level"] == "HIGH"


class TestDomainImports:
    """Domain modules must use core.types, not proxy/config."""

    def test_risk_level_from_core_types(self):
        from admina.core.types import RiskLevel as RL

        assert RL.HIGH == "high"

    def test_domain_firewall_not_importing_proxy_config(self):
        import inspect

        from admina.domains.agent_security import firewall as fw_mod

        assert "from config import" not in inspect.getsource(fw_mod)

    def test_domain_loop_breaker_not_importing_proxy_config(self):
        import inspect

        from admina.domains.agent_security import loop_breaker as lb_mod

        assert "from config import" not in inspect.getsource(lb_mod)
