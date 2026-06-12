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

"""Tests for the OISG adequacy score engine and API endpoint.

Covers:
  - Unit tests for ``compute_oisg_score`` with various engine combinations.
  - Unit tests for ``get_level`` classification.
  - API endpoint tests for ``GET /api/dashboard/oisg``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI

from admina.domains.compliance.oisg import (
    CRITERIA,
    MAX_PILLAR_SCORE,
    MAX_TOTAL_SCORE,
    PILLAR_COLORS,
    OISGResult,
    compute_oisg_score,
    get_level,
)

# ── Stubs ───────────────────────────────────────────────────


class _FakeForensicBox:
    def __init__(self, *, has_records: bool = True) -> None:
        self.record_count = 5 if has_records else 0
        self.chain_head = "abc123def456" if has_records else "GENESIS"


class _FakeCompliance:
    assessments: list[dict] = []

    def classify_risk(self, description: str) -> dict:
        return {"risk_category": "limited", "confidence": 0.8}

    def gap_analysis(self, risk_category: str, current_compliance: dict) -> dict:
        return {"compliance_score": 0.0, "gaps": [], "gap_count": 0}


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "LOW"}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


class _FakeOTEL:
    pass


class _FakeGuard:
    name = "test_guard"

    async def inspect_request(self, payload: dict) -> dict:
        return {"action": "ALLOW", "risk_level": "LOW"}


@dataclass
class _FakeAIInfra:
    enabled: bool = False

    @dataclass
    class _RAG:
        enabled: bool = False

    rag: _RAG = field(default_factory=_RAG)


@dataclass
class _FakeDashboardConfig:
    enabled: bool = True


@dataclass
class _FakeComplianceConfig:
    eu_ai_act_enabled: bool = True


@dataclass
class _FakeConfig:
    ai_infra: _FakeAIInfra = field(default_factory=_FakeAIInfra)
    dashboard: _FakeDashboardConfig = field(default_factory=_FakeDashboardConfig)
    compliance: _FakeComplianceConfig = field(default_factory=_FakeComplianceConfig)
    admina_api_key: str = ""


@dataclass
class _FakeSettings:
    CLICKHOUSE_DB: str = "admina"
    UPSTREAM_MCP_URL: str = "http://mock:9000"
    AI_INFRA_LLM_ENABLED: bool = False
    ADMINA_API_KEY: str = ""


# ══════════════════════════════════════════════════════════════
#  Unit tests — get_level
# ══════════════════════════════════════════════════════════════


class TestGetLevel:
    def test_critical_gaps(self) -> None:
        assert get_level(0) == "Critical gaps"
        assert get_level(24) == "Critical gaps"

    def test_partial_coverage(self) -> None:
        assert get_level(25) == "Partial coverage"
        assert get_level(49) == "Partial coverage"

    def test_good_coverage(self) -> None:
        assert get_level(50) == "Good coverage"
        assert get_level(79) == "Good coverage"

    def test_oisg_adequate(self) -> None:
        assert get_level(80) == "OISG adequate"
        assert get_level(100) == "OISG adequate"


# ══════════════════════════════════════════════════════════════
#  Unit tests — compute_oisg_score
# ══════════════════════════════════════════════════════════════


class TestComputeOISGScore:
    def test_all_defaults_returns_valid_result(self) -> None:
        result = compute_oisg_score()
        assert isinstance(result, OISGResult)
        assert 0 <= result.total <= MAX_TOTAL_SCORE
        assert result.level in (
            "Critical gaps",
            "Partial coverage",
            "Good coverage",
            "OISG adequate",
        )
        assert result.computed_at != ""

    def test_four_pillars_present(self) -> None:
        result = compute_oisg_score()
        assert set(result.pillars.keys()) == {"open", "intelligent", "secure", "governed"}

    def test_each_pillar_has_five_criteria(self) -> None:
        result = compute_oisg_score()
        for pillar in result.pillars.values():
            assert len(pillar.criteria) == 5

    def test_pillar_score_range(self) -> None:
        result = compute_oisg_score()
        for pillar in result.pillars.values():
            assert 0 <= pillar.score <= MAX_PILLAR_SCORE

    def test_total_equals_pillar_sum(self) -> None:
        result = compute_oisg_score()
        assert result.total == sum(p.score for p in result.pillars.values())

    def test_minimal_config_low_score(self) -> None:
        """With no engines running, the score should be low."""
        result = compute_oisg_score()
        # Only the "always true" criteria should pass (O2, O3, O4, I2 = 20)
        assert result.total >= 20
        assert result.total < 60

    def test_full_engines_higher_score(self) -> None:
        """With all engines active, the score should be high."""
        result = compute_oisg_score(
            firewall=_FakeFirewall(),
            pii_redactor=_FakePII(),
            loop_breaker=_FakeLoopBreaker(),
            forensic_box=_FakeForensicBox(),
            compliance_engine=_FakeCompliance(),
            otel_exporter=_FakeOTEL(),
            governance_guards=[_FakeGuard()],
            config=_FakeConfig(
                ai_infra=_FakeAIInfra(enabled=True, rag=_FakeAIInfra._RAG(enabled=True)),
                admina_api_key="secret-key",
            ),
            engine_status={"rust_available": True, "rust_version": "0.9.0"},
        )
        # Should satisfy most criteria
        assert result.total >= 80
        assert result.level == "OISG adequate"

    def test_to_dict_serializable(self) -> None:
        result = compute_oisg_score(
            firewall=_FakeFirewall(),
            forensic_box=_FakeForensicBox(),
            compliance_engine=_FakeCompliance(),
        )
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "total" in d
        assert "pillars" in d
        assert "open" in d["pillars"]
        assert "criteria" in d["pillars"]["open"]

    def test_open_always_true_criteria(self) -> None:
        """O2 (open source), O3 (MCP), O4 (community) are always satisfied."""
        result = compute_oisg_score()
        open_criteria = result.pillars["open"].criteria
        # O2 = index 1, O3 = index 2, O4 = index 3
        assert open_criteria[1].satisfied is True  # O2
        assert open_criteria[2].satisfied is True  # O3
        assert open_criteria[3].satisfied is True  # O4

    def test_intelligent_sovereign_always_true(self) -> None:
        """I2 (sovereign execution) is always satisfied."""
        result = compute_oisg_score()
        assert result.pillars["intelligent"].criteria[1].satisfied is True

    def test_secure_firewall_criterion(self) -> None:
        """S1 depends on firewall being active."""
        result_no_fw = compute_oisg_score(firewall=None)
        assert result_no_fw.pillars["secure"].criteria[0].satisfied is False

        result_fw = compute_oisg_score(firewall=_FakeFirewall())
        assert result_fw.pillars["secure"].criteria[0].satisfied is True

    def test_secure_pii_criterion(self) -> None:
        """S4 depends on PII redactor being active."""
        result_no = compute_oisg_score(pii_redactor=None)
        assert result_no.pillars["secure"].criteria[3].satisfied is False

        result_yes = compute_oisg_score(pii_redactor=_FakePII())
        assert result_yes.pillars["secure"].criteria[3].satisfied is True

    def test_governed_forensic_criterion(self) -> None:
        """G2 depends on forensic box being active."""
        result_no = compute_oisg_score(forensic_box=None)
        assert result_no.pillars["governed"].criteria[1].satisfied is False

        result_yes = compute_oisg_score(forensic_box=_FakeForensicBox())
        assert result_yes.pillars["governed"].criteria[1].satisfied is True

    def test_governed_compliance_criterion(self) -> None:
        """G1 depends on compliance engine being active."""
        result_no = compute_oisg_score(compliance_engine=None)
        assert result_no.pillars["governed"].criteria[0].satisfied is False

        result_yes = compute_oisg_score(compliance_engine=_FakeCompliance())
        assert result_yes.pillars["governed"].criteria[0].satisfied is True

    def test_governed_oversight_criterion(self) -> None:
        """G3 depends on governance guards being configured."""
        result_no = compute_oisg_score(governance_guards=[])
        assert result_no.pillars["governed"].criteria[2].satisfied is False

        result_yes = compute_oisg_score(governance_guards=[_FakeGuard()])
        assert result_yes.pillars["governed"].criteria[2].satisfied is True

    def test_secure_auth_criterion(self) -> None:
        """S2 depends on API key being configured."""
        result_no = compute_oisg_score(config=_FakeConfig(admina_api_key=""))
        assert result_no.pillars["secure"].criteria[1].satisfied is False

        result_yes = compute_oisg_score(config=_FakeConfig(admina_api_key="key123"))
        assert result_yes.pillars["secure"].criteria[1].satisfied is True

    def test_s2_satisfied_when_api_key_configured(self) -> None:
        """S2 reads api_key_configured param directly, overriding config fallback."""
        result = compute_oisg_score(api_key_configured=True)
        s2 = next(c for c in result.pillars["secure"].criteria if c.id == "s2")
        assert s2.satisfied is True

        result = compute_oisg_score(api_key_configured=False)
        s2 = next(c for c in result.pillars["secure"].criteria if c.id == "s2")
        assert s2.satisfied is False


# ══════════════════════════════════════════════════════════════
#  Unit tests — criteria definitions
# ══════════════════════════════════════════════════════════════


class TestCriteriaDefinitions:
    def test_four_pillars_defined(self) -> None:
        assert set(CRITERIA.keys()) == {"open", "intelligent", "secure", "governed"}

    def test_five_criteria_each(self) -> None:
        for pillar, items in CRITERIA.items():
            assert len(items) == 5, f"{pillar} has {len(items)} criteria"

    def test_unique_ids(self) -> None:
        all_ids = [c["id"] for items in CRITERIA.values() for c in items]
        assert len(all_ids) == len(set(all_ids))

    def test_pillar_colors_defined(self) -> None:
        assert set(PILLAR_COLORS.keys()) == {"open", "intelligent", "secure", "governed"}
        for colors in PILLAR_COLORS.values():
            assert "light" in colors
            assert "dark" in colors


# ══════════════════════════════════════════════════════════════
#  API endpoint tests — GET /api/dashboard/oisg
# ══════════════════════════════════════════════════════════════


def _build_test_app(
    *,
    forensic_box: Any = None,
    compliance: Any = None,
    firewall: Any = None,
    pii_redactor: Any = None,
    loop_breaker: Any = None,
    otel_exporter: Any = None,
    governance_guards: list | None = None,
    config: Any = None,
    engine_status: dict | None = None,
    metrics: dict | None = None,
    settings: Any = None,
) -> FastAPI:
    from admina.proxy.api.dashboard import create_dashboard_endpoints

    if compliance is None:
        compliance = _FakeCompliance()
    if metrics is None:
        metrics = {
            "requests_total": 10,
            "requests_blocked": 0,
            "requests_allowed": 10,
            "requests_redacted": 0,
            "avg_latency_ms": 1.5,
            "started_at": datetime.now(UTC).isoformat(),
        }
    if engine_status is None:
        engine_status = {"engine": "rust", "rust_available": True, "rust_version": "0.9.0"}
    if governance_guards is None:
        governance_guards = []

    app = FastAPI()
    dash = create_dashboard_endpoints(
        get_metrics=lambda: metrics,
        get_forensic_box=lambda: forensic_box,
        get_compliance=lambda: compliance,
        get_clickhouse=lambda: None,
        get_settings=lambda: settings if settings is not None else _FakeSettings(),
        get_firewall=lambda: firewall,
        get_pii_redactor=lambda: pii_redactor,
        get_loop_breaker=lambda: loop_breaker,
        get_otel_exporter=lambda: otel_exporter,
        get_governance_guards=lambda: governance_guards,
        get_config=lambda: config,
        get_engine_status=lambda: engine_status,
    )
    app.include_router(dash)
    return app


def _run(coro):
    return asyncio.run(coro)


def _client(app: FastAPI) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


class TestDashboardOISGEndpoint:
    """GET /api/dashboard/oisg"""

    def test_returns_200(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/oisg")

        r = _run(go())
        assert r.status_code == 200

    def test_has_required_fields(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/oisg")).json()

        data = _run(go())
        assert "total" in data
        assert "max_total" in data
        assert "level" in data
        assert "pillars" in data
        assert "colors" in data
        assert data["max_total"] == 100

    def test_score_range(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/oisg")).json()

        data = _run(go())
        assert 0 <= data["total"] <= 100

    def test_pillars_present(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/oisg")).json()

        data = _run(go())
        pillars = data["pillars"]
        assert set(pillars.keys()) == {"open", "intelligent", "secure", "governed"}

    def test_pillar_criteria_structure(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/oisg")).json()

        data = _run(go())
        for pkey, pillar in data["pillars"].items():
            assert "score" in pillar
            assert "max_score" in pillar
            assert "criteria" in pillar
            assert len(pillar["criteria"]) == 5
            for c in pillar["criteria"]:
                assert "id" in c
                assert "label" in c
                assert "satisfied" in c
                assert "reason" in c

    def test_colors_present(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/oisg")).json()

        data = _run(go())
        colors = data["colors"]
        assert set(colors.keys()) == {"open", "intelligent", "secure", "governed"}

    def test_full_engines_high_score(self) -> None:
        app = _build_test_app(
            firewall=_FakeFirewall(),
            pii_redactor=_FakePII(),
            loop_breaker=_FakeLoopBreaker(),
            forensic_box=_FakeForensicBox(),
            compliance=_FakeCompliance(),
            otel_exporter=_FakeOTEL(),
            governance_guards=[_FakeGuard()],
            config=_FakeConfig(
                ai_infra=_FakeAIInfra(enabled=True, rag=_FakeAIInfra._RAG(enabled=True)),
            ),
            settings=_FakeSettings(ADMINA_API_KEY="secret-key"),
        )

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/oisg")).json()

        data = _run(go())
        # S2 (API key auth) must be genuinely satisfied — not just obscured by loose threshold
        s2 = next(c for c in data["pillars"]["secure"]["criteria"] if c["id"] == "s2")
        assert s2["satisfied"] is True, "S2 must be satisfied when ADMINA_API_KEY is set"
        assert data["total"] >= 80
        assert data["level"] == "OISG adequate"

    def test_minimal_engines_lower_score(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/oisg")).json()

        data = _run(go())
        assert data["total"] < 80
