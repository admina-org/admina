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

"""Dashboard feed, trend and suggestions without ClickHouse.

With no ClickHouse client the three endpoints read the recent records of
the forensic store: one event per governed request (/mcp and the gateway),
newest first. Other forensic records (coordination verdicts, events posted
to /api/v1/audit) are not feed events. The gateway's own records reach the
feed through the same path.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI

from admina.core.types import EventType, GovernanceAction, RiskLevel
from admina.domains.compliance.forensic import ForensicBlackBox
from admina.proxy.api.dashboard import create_dashboard_endpoints
from admina.proxy.api.gateway import create_gateway_endpoints


def _settings(**over: Any) -> SimpleNamespace:
    base = dict(
        CLICKHOUSE_DB="admina",
        GOVERNANCE_MODE="enforce",
        ADMINA_API_KEY="",
        ALLOW_UNAUTHENTICATED=True,
        CORS_ORIGINS="",
        ADMINA_GATEWAY_UPSTREAM="http://upstream/v1",
        ADMINA_GATEWAY_BLOCK_MESSAGE="blocked by policy",
        ADMINA_GATEWAY_MODELS_ALLOWLIST="",
        INJECTION_FAST_PATH_ENABLED=True,
        PII_REDACTION_ENABLED=False,
        GUARD_FAIL_MODE="open",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _app(forensic_box: Any, *, settings: Any = None, state: Any = None) -> FastAPI:
    settings = settings or _settings()
    app = FastAPI()
    app.include_router(
        create_dashboard_endpoints(
            get_metrics=lambda: {},
            get_forensic_box=lambda: forensic_box,
            get_compliance=lambda: None,
            get_clickhouse=lambda: None,
            get_settings=lambda: settings,
        )
    )
    if state is not None:
        app.include_router(
            create_gateway_endpoints(get_state=lambda: state, get_settings=lambda: settings)
        )
    return app


def _get(app: FastAPI, url: str) -> httpx.Response:
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            return await c.get(url)

    return asyncio.run(go())


def _governed(fbox: ForensicBlackBox, n: int, **over: Any) -> None:
    for i in range(n):
        event = {
            "event_id": f"ev-{i}",
            "event_type": EventType.MCP_REQUEST,
            "agent_id": "agent-a",
            "session_id": "s1",
            "method": "tools/call",
            "action": GovernanceAction.ALLOW,
            "risk_level": RiskLevel.LOW,
            "governance_latency_ms": 0.5,
            "checks": {"firewall": {"is_injection": False, "patterns": []}},
        }
        event.update(over)
        fbox.record(event)


def _blocked(fbox: ForensicBlackBox, n: int, pattern: str = "instruction_override") -> None:
    _governed(
        fbox,
        n,
        event_type=EventType.GATEWAY_REQUEST,
        method="chat.completions",
        action="BLOCK",
        risk_level="critical",
        checks={"firewall": {"is_injection": True, "patterns": [{"pattern": pattern}]}},
    )


def _age(fbox: ForensicBlackBox, hours: float) -> None:
    """Move the timestamp of every recent record *hours* into the past."""
    for record in fbox._recent:
        ts = datetime.fromisoformat(record["timestamp_utc"]) - timedelta(hours=hours)
        record["timestamp_utc"] = ts.isoformat()


# ── feed ──────────────────────────────────────────────────────


def test_feed_reads_recent_forensic_records_newest_first() -> None:
    fbox = ForensicBlackBox()
    _governed(fbox, 3)

    data = _get(_app(fbox), "/api/dashboard/feed").json()

    assert data["source"] == "forensic_recent"
    assert "error" not in data
    assert data["count"] == 3
    assert [e["event_id"] for e in data["events"]] == ["ev-2", "ev-1", "ev-0"]
    first = data["events"][0]
    assert first["event_type"] == "mcp_request"
    assert first["action"] == "allow"
    assert first["risk_level"] == "low"
    assert first["method"] == "tools/call"
    assert json.loads(first["details"]) == {"firewall": {"is_injection": False, "patterns": []}}


def test_feed_keeps_the_clickhouse_row_columns() -> None:
    fbox = ForensicBlackBox()
    _governed(fbox, 1)

    event = _get(_app(fbox), "/api/dashboard/feed").json()["events"][0]

    assert set(event) == {
        "event_id",
        "timestamp",
        "event_type",
        "agent_id",
        "session_id",
        "method",
        "tool_name",
        "action",
        "risk_level",
        "details",
        "latency_ms",
        "request_hash",
        "response_hash",
    }


def test_feed_paginates_recent_records() -> None:
    fbox = ForensicBlackBox()
    _governed(fbox, 5)

    data = _get(_app(fbox), "/api/dashboard/feed?limit=2&offset=1").json()

    assert [e["event_id"] for e in data["events"]] == ["ev-3", "ev-2"]
    assert data["count"] == 2


def test_feed_leaves_out_records_that_are_not_governed_requests() -> None:
    fbox = ForensicBlackBox()
    _governed(fbox, 1)
    fbox.record({"event_type": "agent_action", "source": "api_v1_audit", "note": "external"})
    fbox.record(
        {
            "event_id": "ev-0:coordination",
            "event_type": EventType.POLICY_VIOLATION,
            "action": "block",
            "checks": {},
        }
    )

    data = _get(_app(fbox), "/api/dashboard/feed").json()

    assert [e["event_id"] for e in data["events"]] == ["ev-0"]


def test_feed_carries_would_action_in_details() -> None:
    fbox = ForensicBlackBox()
    _governed(fbox, 1, would_action=GovernanceAction.BLOCK)

    event = _get(_app(fbox), "/api/dashboard/feed").json()["events"][0]

    assert json.loads(event["details"])["would_action"] == "block"


def test_feed_without_clickhouse_or_forensic_store_reports_the_error() -> None:
    data = _get(_app(None), "/api/dashboard/feed").json()

    assert data == {"events": [], "count": 0, "error": "ClickHouse not available"}


def test_feed_with_a_store_that_keeps_no_recent_records_reports_the_error() -> None:
    store = SimpleNamespace(record_count=0, chain_head="GENESIS")

    data = _get(_app(store), "/api/dashboard/feed").json()

    assert data["events"] == []
    assert data["error"] == "ClickHouse not available"


def test_feed_shows_gateway_requests() -> None:
    fbox = ForensicBlackBox()
    state = SimpleNamespace(
        firewall=SimpleNamespace(
            check=lambda text: {
                "is_injection": "INJECT" in text,
                "risk_level": "high",
                "patterns": [],
            }
        ),
        pii_redactor=None,
        loop_breaker=None,
        egress_policy=None,
        governance_guards=[],
        forensic_box=fbox,
        http_client=None,
    )
    app = _app(fbox, state=state)

    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            await c.post(
                "/v1/chat/completions",
                json={"model": "m", "messages": [{"role": "user", "content": "INJECT now"}]},
            )
            return await c.get("/api/dashboard/feed")

    data = asyncio.run(go()).json()

    assert data["count"] == 1
    event = data["events"][0]
    assert event["event_type"] == "gateway_request"
    assert event["method"] == "chat.completions"
    assert event["action"] == "block"
    assert "INJECT now" not in json.dumps(data)


# ── trend ─────────────────────────────────────────────────────


def test_trend_counts_recent_records_per_bucket_and_action() -> None:
    fbox = ForensicBlackBox()
    _governed(fbox, 3)
    _blocked(fbox, 2)

    data = _get(_app(fbox), "/api/dashboard/trend?window_hours=1&bucket_minutes=1440").json()

    assert data["source"] == "forensic_recent"
    assert data["bucket_minutes"] == 1440
    assert data["bucket_count"] == 1
    bucket = data["buckets"][0]
    assert (bucket["allow"], bucket["block"], bucket["total"]) == (3, 2, 5)
    start = datetime.fromisoformat(bucket["ts"])
    assert start.tzinfo is not None
    assert start.timestamp() % 86400 == 0


def test_trend_leaves_out_records_older_than_the_window() -> None:
    fbox = ForensicBlackBox()
    _governed(fbox, 2)
    _age(fbox, 3)
    _blocked(fbox, 1)

    data = _get(_app(fbox), "/api/dashboard/trend?window_hours=2&bucket_minutes=1440").json()

    assert sum(b["total"] for b in data["buckets"]) == 1


def test_trend_without_any_store_reports_the_error() -> None:
    data = _get(_app(None), "/api/dashboard/trend").json()

    assert data["buckets"] == []
    assert data["error"] == "ClickHouse not available"


# ── suggestions ───────────────────────────────────────────────


def test_suggestions_analyse_recent_records() -> None:
    fbox = ForensicBlackBox()
    _blocked(fbox, 10)
    _governed(fbox, 2)

    data = _get(_app(fbox), "/api/dashboard/suggestions?min_count=5").json()

    assert data["source"] == "forensic_recent"
    assert data["events_analyzed"] == 12
    assert data["blocked_by_category"] == {"instruction_override": 10}
    types = {s["type"] for s in data["suggestions"]}
    assert "high_block_share" in types
    # Nothing blocked in the previous window, and at least twice min_count
    # now: a new category, not a surge.
    assert "trend_new_category" in types


def test_suggestions_compare_with_the_previous_window() -> None:
    fbox = ForensicBlackBox()
    _blocked(fbox, 5)
    _age(fbox, 30)
    _blocked(fbox, 12)

    data = _get(_app(fbox), "/api/dashboard/suggestions?window_hours=24&min_count=5").json()

    assert data["events_analyzed"] == 12
    surge = [s for s in data["suggestions"] if s["type"] == "trend_surge"]
    assert len(surge) == 1
    assert (surge[0]["previous"], surge[0]["current"]) == (5, 12)


def test_suggestions_with_no_recent_events() -> None:
    data = _get(_app(ForensicBlackBox()), "/api/dashboard/suggestions").json()

    assert data["events_analyzed"] == 0
    assert data["suggestions"][0]["type"] == "no_data"


def test_suggestions_without_any_store_report_the_error() -> None:
    data = _get(_app(None), "/api/dashboard/suggestions").json()

    assert data["suggestions"] == []
    assert data["error"] == "ClickHouse not available"


def test_suggestions_csv_from_recent_records() -> None:
    fbox = ForensicBlackBox()
    _blocked(fbox, 6)

    r = _get(_app(fbox), "/api/dashboard/suggestions?min_count=5&format=csv")

    assert r.headers["content-type"].startswith("text/csv")
    assert "instruction_override" in r.text
