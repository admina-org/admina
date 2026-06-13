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

"""Tests for dashboard backend API and integration endpoints.

Covers ``/api/dashboard/*`` and ``/api/v1/{validate,audit}``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

# ── Lightweight stubs so we don't need real infra ────────────


class _FakeForensicBox:
    """Minimal stand-in for ForensicBlackBox."""

    def __init__(self, *, has_records: bool = True) -> None:
        self.record_count = 5 if has_records else 0
        self.chain_head = "abc123def456" if has_records else "GENESIS"

    def record(self, event: dict) -> dict:
        self.record_count += 1
        return {
            "sequence_number": self.record_count,
            "record_hash": "h" * 64,
            "previous_hash": self.chain_head,
            "stored": True,
        }

    def get_stats(self) -> dict:
        return {
            "record_count": self.record_count,
            "chain_head": self.chain_head[:16] + "...",
            "storage_available": True,
        }


class _FakeCompliance:
    """Minimal stand-in for EUAIActCompliance."""

    def __init__(self) -> None:
        self.assessments: list[dict] = []

    def gap_analysis(self, risk_category: str, current_compliance: dict) -> dict:
        result = {
            "applicable": risk_category in ("high", "unacceptable"),
            "compliance_score": 0.0,
            "total_checks": 28,
            "passed_checks": 0,
            "gaps": [
                {
                    "requirement": "Risk Management System",
                    "article": "Art. 9",
                    "check": "c",
                    "status": "NOT_MET",
                }
            ],
            "gap_count": 28,
            "status": "GAPS_FOUND",
            "enforcement_deadline": "2027-12-02",
            "assessed_at": datetime.now(UTC).isoformat(),
        }
        self.assessments.append(result)
        return result

    def get_stats(self) -> dict:
        return {"total_assessments": len(self.assessments)}


class _FakeFirewall:
    def check(self, text: str) -> dict:
        is_bad = "DROP TABLE" in text.upper()
        return {"is_injection": is_bad, "risk_level": "HIGH" if is_bad else "LOW"}

    def get_stats(self) -> dict:
        return {}


class _FakePII:
    def redact(self, text: str) -> dict:
        has_pii = "@" in text
        if has_pii:
            return {"redacted_text": "[REDACTED]", "entities": ["EMAIL"], "count": 1}
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreakerForced:
    """Loop breaker stub that always reports a loop (is_loop=True)."""

    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": True, "similarity": 0.95}

    def get_stats(self) -> dict:
        return {}


class _FakeRedis:
    """Minimal async Redis stand-in."""

    async def ping(self) -> bool:
        return True

    async def info(self, section: str = "") -> dict:
        return {"used_memory_human": "1.5M", "used_memory": 1572864}


@dataclass
class _FakeSettings:
    CLICKHOUSE_DB: str = "admina"
    UPSTREAM_MCP_URL: str = "http://mock-mcp:9000"
    AI_INFRA_LLM_ENABLED: bool = False
    ADMINA_API_KEY: str = ""
    ALLOW_UNAUTHENTICATED: bool = True
    GOVERNANCE_MODE: str = "enforce"


# ── Build a test app ─────────────────────────────────────────


_UNSET = object()


def _build_test_app(
    *,
    forensic_box: Any = _UNSET,
    compliance: Any = None,
    clickhouse: Any = None,
    metrics: dict | None = None,
    redis: Any = _UNSET,
    settings: Any = None,
    loop_breaker: Any = None,
) -> FastAPI:
    """Create a minimal FastAPI app with dashboard + integration routers."""
    from admina.proxy.api.dashboard import create_dashboard_endpoints
    from admina.proxy.api.integration import create_integration_endpoints

    if forensic_box is _UNSET:
        forensic_box = _FakeForensicBox()
    if compliance is None:
        compliance = _FakeCompliance()
    if redis is _UNSET:
        redis = _FakeRedis()
    if settings is None:
        settings = _FakeSettings()
    if metrics is None:
        metrics = {
            "requests_total": 10,
            "requests_blocked": 0,
            "requests_allowed": 10,
            "requests_redacted": 0,
            "avg_latency_ms": 1.5,
            "started_at": datetime.now(UTC).isoformat(),
        }

    engine_status = {"engine": "rust", "rust_available": True, "rust_version": "0.9.0"}

    app = FastAPI()

    dash = create_dashboard_endpoints(
        get_metrics=lambda: metrics,
        get_forensic_box=lambda: forensic_box,
        get_compliance=lambda: compliance,
        get_clickhouse=lambda: clickhouse,
        get_settings=lambda: settings,
        get_redis=lambda: redis,
        get_engine_status=lambda: engine_status,
        get_http_client=lambda: None,
    )
    app.include_router(dash)

    _loop_breaker_instance = loop_breaker if loop_breaker is not None else _FakeLoopBreaker()
    integ = create_integration_endpoints(
        get_firewall=lambda: _FakeFirewall(),
        get_pii_scanner=lambda: _FakePII(),
        get_loop_breaker=lambda: _loop_breaker_instance,
        get_forensic_box=lambda: forensic_box,
        get_settings=lambda: settings,
    )
    app.include_router(integ)
    return app


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


def _client(app: FastAPI) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ══════════════════════════════════════════════════════════════
#  Dashboard endpoint tests
# ══════════════════════════════════════════════════════════════


class TestDashboardScore:
    """GET /api/dashboard/score"""

    def test_score_returns_200(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/score")

        r = _run(go())
        assert r.status_code == 200

    def test_score_has_required_fields(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/score")).json()

        data = _run(go())
        assert "score" in data
        assert "max_score" in data
        assert "breakdown" in data
        assert data["max_score"] == 100

    def test_score_range(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/score")).json()

        data = _run(go())
        assert 0 <= data["score"] <= 100

    def test_score_breakdown_keys(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/score")).json()["breakdown"]

        bd = _run(go())
        expected_keys = {
            "data_residency",
            "interactions_audited",
            "eu_ai_act_coverage",
            "no_recent_attacks",
            "forensic_chain_valid",
        }
        assert set(bd.keys()) == expected_keys

    def test_score_with_no_forensic(self) -> None:
        app = _build_test_app(forensic_box=_FakeForensicBox(has_records=False))

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/score")).json()

        data = _run(go())
        bd = data["breakdown"]
        assert bd["interactions_audited"] == 0
        assert bd["forensic_chain_valid"] == 0

    def test_score_with_active_forensic(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/score")).json()

        data = _run(go())
        bd = data["breakdown"]
        assert bd["interactions_audited"] == 25
        assert bd["forensic_chain_valid"] == 10

    def test_score_no_attacks_bonus(self) -> None:
        app = _build_test_app(
            metrics={
                "requests_total": 10,
                "requests_blocked": 0,
                "requests_allowed": 10,
                "requests_redacted": 0,
                "avg_latency_ms": 1.0,
                "started_at": datetime.now(UTC).isoformat(),
            }
        )

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/score")).json()

        data = _run(go())
        assert data["breakdown"]["no_recent_attacks"] == 15

    def test_score_attacks_penalty(self) -> None:
        app = _build_test_app(
            metrics={
                "requests_total": 10,
                "requests_blocked": 3,
                "requests_allowed": 7,
                "requests_redacted": 0,
                "avg_latency_ms": 1.0,
                "started_at": datetime.now(UTC).isoformat(),
            }
        )

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/score")).json()

        data = _run(go())
        assert data["breakdown"]["no_recent_attacks"] == 0


class TestDashboardFeed:
    """GET /api/dashboard/feed"""

    def test_feed_no_clickhouse(self) -> None:
        app = _build_test_app(clickhouse=None)

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/feed")

        r = _run(go())
        assert r.status_code == 200
        data = r.json()
        assert data["events"] == []
        assert "error" in data

    def test_feed_with_limit_param(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/feed?limit=10&offset=0")

        r = _run(go())
        assert r.status_code == 200

    def test_feed_rejects_invalid_limit(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/feed?limit=-1")

        r = _run(go())
        assert r.status_code == 422


class TestDashboardCompliance:
    """GET /api/dashboard/compliance"""

    def test_compliance_returns_200(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/compliance")

        r = _run(go())
        assert r.status_code == 200

    def test_compliance_has_deadline(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/compliance")).json()

        data = _run(go())
        assert data["enforcement_deadline"] == "2027-12-02"

    def test_compliance_no_assessment_returns_placeholder(self) -> None:
        """Without prior assessment, endpoint returns a read-only
        placeholder with all checks marked NOT_MET, and does NOT
        pollute compliance.assessments."""
        comp = _FakeCompliance()
        app = _build_test_app(compliance=comp)

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/compliance")).json()

        data = _run(go())
        assert data["has_assessment"] is False
        assert "latest" in data
        assert data["latest"]["status"] == "NO_ASSESSMENT"
        assert data["latest"]["compliance_score"] == 0
        # Placeholder must list every Art. 9-15 check as a gap so the UI
        # grid renders all 7 articles at 0%
        assert data["latest"]["gap_count"] == 28
        assert len(data["latest"]["gaps"]) == 28
        articles = {g["article"] for g in data["latest"]["gaps"]}
        assert articles == {f"Art. {n}" for n in range(9, 16)}
        # Endpoint must be read-only — no assessment recorded
        assert len(comp.assessments) == 0

    def test_compliance_endpoint_is_idempotent(self) -> None:
        """Calling the endpoint multiple times must not create assessments."""
        comp = _FakeCompliance()
        app = _build_test_app(compliance=comp)

        async def go():
            async with _client(app) as c:
                await c.get("/api/dashboard/compliance")
                await c.get("/api/dashboard/compliance")
                return (await c.get("/api/dashboard/compliance")).json()

        data = _run(go())
        assert data["has_assessment"] is False
        assert len(comp.assessments) == 0

    def test_compliance_with_prior_assessment(self) -> None:
        comp = _FakeCompliance()
        comp.gap_analysis("high", {})
        app = _build_test_app(compliance=comp)

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/compliance")).json()

        data = _run(go())
        assert data["has_assessment"] is True
        assert data["total_assessments"] >= 1


class TestDashboardSovereignty:
    """GET /api/dashboard/sovereignty"""

    def test_sovereignty_returns_200(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/sovereignty")

        r = _run(go())
        assert r.status_code == 200

    def test_sovereignty_has_zones(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/sovereignty")).json()

        data = _run(go())
        assert "zones" in data
        assert "local" in data["zones"]
        assert data["data_residency_enforced"] is True


# ══════════════════════════════════════════════════════════════
#  Integration endpoint tests
# ══════════════════════════════════════════════════════════════


class TestValidateEndpoint:
    """POST /api/v1/validate"""

    def test_validate_allow(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post("/api/v1/validate", json={"content": "hello world"})

        r = _run(go())
        assert r.status_code == 200
        data = r.json()
        assert data["action"] == "ALLOW"
        assert data["risk_level"] == "LOW"

    def test_validate_block_injection(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post(
                    "/api/v1/validate",
                    json={"content": "DROP TABLE users; --"},
                )

        r = _run(go())
        assert r.status_code == 200
        data = r.json()
        assert data["action"] == "BLOCK"

    def test_validate_modify_pii(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post(
                    "/api/v1/validate",
                    json={"content": "Contact me at user@example.com"},
                )

        r = _run(go())
        data = r.json()
        assert data["action"] == "MODIFY"
        assert data["redacted_content"] is not None

    def test_validate_empty_content_400(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post("/api/v1/validate", json={"content": ""})

        r = _run(go())
        assert r.status_code == 400

    def test_validate_missing_content_400(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post("/api/v1/validate", json={"foo": "bar"})

        r = _run(go())
        assert r.status_code == 400

    def test_validate_has_checks(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.post("/api/v1/validate", json={"content": "hi"})).json()

        data = _run(go())
        assert "checks" in data
        assert "loop_breaker" in data["checks"]
        assert "firewall" in data["checks"]
        assert "pii_redaction" in data["checks"]

    def test_validate_has_latency(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.post("/api/v1/validate", json={"content": "test"})).json()

        data = _run(go())
        assert "latency_ms" in data
        assert data["latency_ms"] >= 0

    def test_validate_risk_level_uppercase_on_block(self) -> None:
        """A firewall-triggered BLOCK must report an UPPERCASE risk_level."""
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post(
                    "/api/v1/validate",
                    json={"content": "DROP TABLE users; --"},
                )

        r = _run(go())
        body = r.json()
        assert body["action"] == "BLOCK"
        assert body["risk_level"] == body["risk_level"].upper(), (
            f"risk_level must be uppercase; got {body['risk_level']!r}"
        )
        assert body["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_validate_honors_observe_mode(self) -> None:
        """In observe mode a firewall-triggered block is downgraded to ALLOW."""
        observe_settings = _FakeSettings(GOVERNANCE_MODE="observe")
        app = _build_test_app(settings=observe_settings)

        async def go():
            async with _client(app) as c:
                return await c.post(
                    "/api/v1/validate",
                    json={"content": "DROP TABLE users; --"},
                )

        r = _run(go())
        assert r.json()["action"] == "ALLOW"

    def test_validate_loop_reports_block_not_circuit_break(self) -> None:
        """A loop-triggered CIRCUIT_BREAK must surface as BLOCK to REST consumers.

        External callers (n8n, CheshireCat, OpenClaw) have never received
        CIRCUIT_BREAK from this endpoint; the contract maps loop→BLOCK.
        """
        app = _build_test_app(loop_breaker=_FakeLoopBreakerForced())

        async def go():
            async with _client(app) as c:
                return await c.post(
                    "/api/v1/validate",
                    json={"content": "repeated content"},
                )

        r = _run(go())
        body = r.json()
        assert body["action"] == "BLOCK", (
            f"loop must map to BLOCK for external REST consumers; got {body['action']!r}"
        )
        assert body["checks"]["loop_breaker"]["is_loop"] is True


class TestAuditEndpoint:
    """POST /api/v1/audit"""

    def test_audit_success(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post(
                    "/api/v1/audit",
                    json={"event": {"action": "ALLOW", "method": "tools/call"}},
                )

        r = _run(go())
        assert r.status_code == 200
        data = r.json()
        assert data["recorded"] is True
        assert "sequence_number" in data
        assert "record_hash" in data

    def test_audit_missing_event_400(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post("/api/v1/audit", json={"foo": "bar"})

        r = _run(go())
        assert r.status_code == 400

    def test_audit_event_not_dict_400(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.post("/api/v1/audit", json={"event": "not-a-dict"})

        r = _run(go())
        assert r.status_code == 400

    def test_audit_no_forensic_box(self) -> None:
        app = _build_test_app(forensic_box=None)

        async def go():
            async with _client(app) as c:
                return await c.post(
                    "/api/v1/audit",
                    json={"event": {"action": "ALLOW"}},
                )

        r = _run(go())
        data = r.json()
        assert data["recorded"] is False
        assert "error" in data


# ══════════════════════════════════════════════════════════════
#  Infrastructure health endpoint tests
# ══════════════════════════════════════════════════════════════


class TestDashboardInfra:
    """GET /api/dashboard/infra"""

    def test_infra_returns_200(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/infra")

        r = _run(go())
        assert r.status_code == 200

    def test_infra_has_services(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/infra")).json()

        data = _run(go())
        assert "services" in data
        assert "proxy" in data["services"]
        assert data["services"]["proxy"]["status"] == "healthy"

    def test_infra_has_counts(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/infra")).json()

        data = _run(go())
        assert "healthy_count" in data
        assert "total_count" in data
        assert "overall" in data
        assert data["total_count"] >= 1

    def test_infra_redis_healthy(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/infra")).json()

        data = _run(go())
        redis_svc = data["services"]["redis"]
        assert redis_svc["status"] == "healthy"
        assert "latency_ms" in redis_svc
        assert "used_memory_human" in redis_svc

    def test_infra_forensic_healthy(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/infra")).json()

        data = _run(go())
        forensic_svc = data["services"]["forensic"]
        assert forensic_svc["status"] == "healthy"
        assert "record_count" in forensic_svc

    def test_infra_no_redis(self) -> None:
        app = _build_test_app(redis=None)

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/infra")).json()

        data = _run(go())
        assert data["services"]["redis"]["status"] == "not_configured"

    def test_infra_no_forensic(self) -> None:
        app = _build_test_app(forensic_box=None)

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/infra")).json()

        data = _run(go())
        assert data["services"]["forensic"]["status"] == "not_configured"

    def test_infra_has_checked_at(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/infra")).json()

        data = _run(go())
        assert "checked_at" in data

    def test_infra_empty_upstream_marked_not_configured(self) -> None:
        """Empty UPSTREAM_MCP_URL must not crash the endpoint."""
        settings = _FakeSettings(UPSTREAM_MCP_URL="")
        http = httpx.AsyncClient()
        app = _build_test_app(settings=settings)
        app.dependency_overrides = {}
        # Rebuild with real http client to exercise the upstream branch
        from admina.proxy.api.dashboard import create_dashboard_endpoints

        app2 = FastAPI()
        app2.include_router(
            create_dashboard_endpoints(
                get_metrics=lambda: {
                    "requests_total": 0,
                    "requests_blocked": 0,
                    "requests_allowed": 0,
                    "requests_redacted": 0,
                    "avg_latency_ms": 0.0,
                    "started_at": datetime.now(UTC).isoformat(),
                },
                get_forensic_box=lambda: _FakeForensicBox(),
                get_compliance=lambda: _FakeCompliance(),
                get_clickhouse=lambda: None,
                get_settings=lambda: settings,
                get_redis=lambda: None,
                get_engine_status=lambda: {},
                get_http_client=lambda: http,
            )
        )

        async def go():
            async with _client(app2) as c:
                resp = await c.get("/api/dashboard/infra")
                return resp.status_code, resp.json()

        status, data = _run(go())
        assert status == 200
        assert data["services"]["upstream_mcp"]["status"] == "not_configured"

    def test_infra_unreachable_upstream_marked_unreachable(self) -> None:
        """httpx connection errors must be caught — endpoint stays 200."""
        settings = _FakeSettings(UPSTREAM_MCP_URL="http://127.0.0.1:1")
        http = httpx.AsyncClient(timeout=0.5)
        from admina.proxy.api.dashboard import create_dashboard_endpoints

        app2 = FastAPI()
        app2.include_router(
            create_dashboard_endpoints(
                get_metrics=lambda: {
                    "requests_total": 0,
                    "requests_blocked": 0,
                    "requests_allowed": 0,
                    "requests_redacted": 0,
                    "avg_latency_ms": 0.0,
                    "started_at": datetime.now(UTC).isoformat(),
                },
                get_forensic_box=lambda: _FakeForensicBox(),
                get_compliance=lambda: _FakeCompliance(),
                get_clickhouse=lambda: None,
                get_settings=lambda: settings,
                get_redis=lambda: None,
                get_engine_status=lambda: {},
                get_http_client=lambda: http,
            )
        )

        async def go():
            async with _client(app2) as c:
                resp = await c.get("/api/dashboard/infra")
                return resp.status_code, resp.json()

        status, data = _run(go())
        assert status == 200
        assert data["services"]["upstream_mcp"]["status"] == "unreachable"


# ══════════════════════════════════════════════════════════════
#  Model status endpoint tests
# ══════════════════════════════════════════════════════════════


class TestDashboardModels:
    """GET /api/dashboard/models"""

    def test_models_returns_200(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/models")

        r = _run(go())
        assert r.status_code == 200

    def test_models_has_engine(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/models")).json()

        data = _run(go())
        assert "engine" in data
        assert data["engine"]["engine"] == "rust"
        assert data["engine"]["rust_available"] is True

    def test_models_has_governance_engine(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/models")).json()

        data = _run(go())
        assert "models" in data
        assert len(data["models"]) >= 1
        gov_model = data["models"][0]
        assert gov_model["name"] == "admina-governance-engine"
        assert gov_model["status"] == "active"
        assert gov_model["backend"] == "rust"

    def test_models_ai_infra_disabled(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/models")).json()

        data = _run(go())
        assert data["ai_infra_enabled"] is False

    def test_models_has_count(self) -> None:
        app = _build_test_app()

        async def go():
            async with _client(app) as c:
                return (await c.get("/api/dashboard/models")).json()

        data = _run(go())
        assert "model_count" in data
        assert data["model_count"] >= 1


# ══════════════════════════════════════════════════════════════
#  WebSocket route registration test
# ══════════════════════════════════════════════════════════════


class TestDashboardLiveWebSocket:
    """WS /api/dashboard/live"""

    def test_websocket_route_registered(self) -> None:
        app = _build_test_app()
        routes = [r.path for r in app.routes]
        assert "/api/dashboard/live" in routes

    def test_websocket_rejects_without_credential(self) -> None:
        from starlette.testclient import TestClient
        from starlette.websockets import WebSocketDisconnect

        settings = _FakeSettings()
        settings.ADMINA_API_KEY = "secret-key"
        settings.ALLOW_UNAUTHENTICATED = False
        app = _build_test_app(settings=settings)
        client = TestClient(app)
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with client.websocket_connect("/api/dashboard/live"):
                pass
        assert excinfo.value.code == 1008

    def test_websocket_rejects_wrong_key(self) -> None:
        from starlette.testclient import TestClient
        from starlette.websockets import WebSocketDisconnect

        settings = _FakeSettings()
        settings.ADMINA_API_KEY = "secret-key"
        settings.ALLOW_UNAUTHENTICATED = False
        app = _build_test_app(settings=settings)
        client = TestClient(app)
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with client.websocket_connect("/api/dashboard/live?api_key=wrong"):
                pass
        assert excinfo.value.code == 1008

    def test_websocket_accepts_correct_key_query(self) -> None:
        from starlette.testclient import TestClient

        settings = _FakeSettings()
        settings.ADMINA_API_KEY = "secret-key"
        settings.ALLOW_UNAUTHENTICATED = False
        app = _build_test_app(settings=settings)
        client = TestClient(app)
        with client.websocket_connect("/api/dashboard/live?api_key=secret-key") as ws:
            ws.close()

    def test_websocket_accepts_correct_key_header(self) -> None:
        from starlette.testclient import TestClient

        settings = _FakeSettings()
        settings.ADMINA_API_KEY = "secret-key"
        settings.ALLOW_UNAUTHENTICATED = False
        app = _build_test_app(settings=settings)
        client = TestClient(app)
        with client.websocket_connect(
            "/api/dashboard/live", headers={"X-API-Key": "secret-key"}
        ) as ws:
            ws.close()

    def test_websocket_allows_unauthenticated_when_flag_set(self) -> None:
        from starlette.testclient import TestClient

        settings = _FakeSettings()
        settings.ADMINA_API_KEY = ""
        settings.ALLOW_UNAUTHENTICATED = True
        app = _build_test_app(settings=settings)
        client = TestClient(app)
        with client.websocket_connect("/api/dashboard/live") as ws:
            ws.close()


# ══════════════════════════════════════════════════════════════
#  Dashboard suggestions — would_action analytics
# ══════════════════════════════════════════════════════════════


import json as _json


@dataclass
class _CHResult:
    result_rows: list


class _FakeCH:
    """Minimal ClickHouse stub — returns pre-canned rows for each query call."""

    def __init__(self, rows_by_call: list[list]) -> None:
        # Each entry is the result_rows for the n-th ch.query() call.
        self._calls = iter(rows_by_call)

    def query(self, _sql: str) -> _CHResult:
        try:
            return _CHResult(result_rows=next(self._calls))
        except StopIteration:
            return _CHResult(result_rows=[])


@dataclass
class _ObserveSettings:
    CLICKHOUSE_DB: str = "admina"
    UPSTREAM_MCP_URL: str = "http://mock-mcp:9000"
    AI_INFRA_LLM_ENABLED: bool = False
    ADMINA_API_KEY: str = ""
    ALLOW_UNAUTHENTICATED: bool = True
    GOVERNANCE_MODE: str = "observe"


class TestDashboardSuggestionsWouldAction:
    """Suggestions endpoint correctly counts would-have-blocked events from persisted details."""

    def _make_details(self, **extra) -> str:
        """Build a details JSON with an injection hit in the firewall sub-key."""
        d = {
            "firewall": {
                "is_injection": True,
                "risk_level": "high",
                "patterns": [{"pattern": "prompt_injection", "risk_level": "high"}],
            },
            "loop_breaker": {"is_loop": False, "similarity": 0.0},
        }
        d.update(extra)
        return _json.dumps(d)

    def test_suggestions_no_clickhouse_returns_error(self) -> None:
        app = _build_test_app(clickhouse=None)

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/suggestions?min_count=1")

        r = _run(go())
        assert r.status_code == 200
        data = r.json()
        assert "error" in data

    def test_observe_mode_with_would_action_events_produces_nonzero_would_blocked(self) -> None:
        """In observe mode, events that carry would_action=block must produce
        a non-zero cat_would_blocked count and trigger a would_block_in_enforce
        suggestion rather than the 'safe to switch to enforce' message."""
        # Build 6 events, all with would_action=block (injection caught in observe mode).
        row = ("allow", "high", self._make_details(would_action="block"))
        main_rows = [row] * 6  # 6 would-have-blocked events
        # Second query (trend) returns empty.
        ch = _FakeCH(rows_by_call=[main_rows, []])
        settings = _ObserveSettings()
        app = _build_test_app(clickhouse=ch, settings=settings)

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/suggestions?min_count=1")

        r = _run(go())
        assert r.status_code == 200
        data = r.json()
        types = {s["type"] for s in data["suggestions"]}
        # Must see a would_block_in_enforce suggestion — not observe_clean.
        assert "would_block_in_enforce" in types, (
            "Expected would_block_in_enforce suggestion when would_action events are present; "
            f"got: {types}"
        )
        assert "observe_clean" not in types, (
            "observe_clean must NOT fire when there are would-have-blocked events"
        )

    def test_observe_mode_no_would_action_events_produces_observe_clean(self) -> None:
        """Without would_action in stored details, the dashboard falls back to
        the 'safe to switch to enforce' message (the pre-fix behavior for clean traffic)."""
        row = ("allow", "low", _json.dumps({"loop_breaker": {"is_loop": False, "similarity": 0.0}}))
        main_rows = [row] * 3
        ch = _FakeCH(rows_by_call=[main_rows, []])
        settings = _ObserveSettings()
        app = _build_test_app(clickhouse=ch, settings=settings)

        async def go():
            async with _client(app) as c:
                return await c.get("/api/dashboard/suggestions?min_count=1")

        r = _run(go())
        assert r.status_code == 200
        data = r.json()
        types = {s["type"] for s in data["suggestions"]}
        assert "observe_clean" in types
