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

"""Dashboard backend API endpoints.

Provides the governance score, live event feed, compliance gap
summary, data sovereignty statistics, and OISG adequacy assessment
for the Admina dashboard.
"""

from __future__ import annotations

import asyncio
import csv as _csv
import io as _io
import json
import logging
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Query, Response, WebSocket, WebSocketDisconnect

from admina.core.event_bus import GovernanceEvent, bus
from admina.domains.compliance.oisg import PILLAR_COLORS, compute_oisg_score

logger = logging.getLogger("admina.api.dashboard")


def _suggestions_to_csv(payload: dict) -> Response:
    """Render the suggestions payload as CSV for spreadsheet consumption."""
    buf = _io.StringIO()
    w = _csv.writer(buf)
    w.writerow(
        [
            "type",
            "category",
            "severity",
            "count",
            "blocked",
            "would_blocked",
            "previous",
            "current",
            "ratio",
            "share_pct",
            "message",
        ]
    )
    for s in payload.get("suggestions", []):
        w.writerow(
            [
                s.get("type", ""),
                s.get("category", ""),
                s.get("severity", ""),
                s.get("count", ""),
                s.get("blocked", ""),
                s.get("would_blocked", ""),
                s.get("previous", ""),
                s.get("current", ""),
                s.get("ratio", ""),
                s.get("share_pct", ""),
                (s.get("message") or "").replace("\n", " "),
            ]
        )
    return Response(content=buf.getvalue(), media_type="text/csv")


# ── Governance score ─────────────────────────────────────────
def _compute_governance_score(
    *,
    metrics: dict[str, Any],
    forensic_box: Any | None,
    compliance_engine: Any,
) -> dict[str, Any]:
    """Compute weighted governance score (0-100).

    Formula (from roadmap section 3.2):
      - Data residency 100% enforced?  +25
      - All interactions audited?      +25
      - EU AI Act gap coverage (% articles covered x 25)  +25
      - No blocked attacks in last 24h?  +15
      - Forensic chain valid?           +10
    """
    breakdown: dict[str, int] = {}

    # Data residency — enforced if proxy is running (always true in proxy mode)
    breakdown["data_residency"] = 25

    # All interactions audited — true if forensic box is active
    audited = forensic_box is not None and forensic_box.record_count > 0
    breakdown["interactions_audited"] = 25 if audited else 0

    # EU AI Act gap coverage — use last assessment if available
    gap_score = 0
    assessments = getattr(compliance_engine, "assessments", [])
    if assessments:
        latest = assessments[-1]
        coverage_pct = latest.get("compliance_score", 0) / 100
        gap_score = round(coverage_pct * 25)
    breakdown["eu_ai_act_coverage"] = gap_score

    # No blocked attacks in last 24h
    blocked = metrics.get("requests_blocked", 0)
    breakdown["no_recent_attacks"] = 15 if blocked == 0 else 0

    # Forensic chain valid
    chain_valid = forensic_box is not None and forensic_box.chain_head != "GENESIS"
    breakdown["forensic_chain_valid"] = 10 if chain_valid else 0

    total = sum(breakdown.values())
    return {
        "score": total,
        "max_score": 100,
        "breakdown": breakdown,
        "computed_at": datetime.now(UTC).isoformat(),
    }


# ── WebSocket live feed ──────────────────────────────────────
_ws_clients: set[WebSocket] = set()


async def _broadcast_event(event: GovernanceEvent) -> None:
    """Forward event bus events to all connected WebSocket clients."""
    payload = json.dumps(
        {
            "event_type": event.event_type.value,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "action": event.action,
            "risk_level": event.risk_level,
            "domain": event.domain,
            "metadata": event.metadata,
        }
    )
    dead: list[WebSocket] = []
    for ws in list(_ws_clients):
        try:
            await ws.send_text(payload)
        except (OSError, RuntimeError):
            dead.append(ws)
    for ws in dead:
        _ws_clients.discard(ws)


# Subscribe the broadcaster to the event bus at import time.
bus.subscribe_all(_broadcast_event)


# ── Factory for stateful endpoints ───────────────────────────
def create_dashboard_endpoints(
    *,
    get_metrics: Any,
    get_forensic_box: Any,
    get_compliance: Any,
    get_clickhouse: Any,
    get_settings: Any,
    get_redis: Any = None,
    get_engine_status: Any = None,
    get_http_client: Any = None,
    get_firewall: Any = None,
    get_pii_redactor: Any = None,
    get_loop_breaker: Any = None,
    get_otel_exporter: Any = None,
    get_governance_guards: Any = None,
    get_config: Any = None,
) -> APIRouter:
    """Create a new APIRouter with dashboard endpoints.

    A fresh router is created on each call so that closures bind
    to the correct proxy state (important for test isolation).

    Args:
        get_metrics: Callable returning the proxy metrics dict.
        get_forensic_box: Callable returning ForensicBlackBox | None.
        get_compliance: Callable returning EUAIActCompliance.
        get_clickhouse: Callable returning ClickHouse client | None.
        get_settings: Callable returning the Settings object.
        get_redis: Callable returning the async Redis client | None.
        get_engine_status: Callable returning engine status dict.
        get_http_client: Callable returning httpx.AsyncClient | None.
        get_firewall: Callable returning the firewall engine | None.
        get_pii_redactor: Callable returning the PII redactor | None.
        get_loop_breaker: Callable returning the loop breaker | None.
        get_otel_exporter: Callable returning OTEL exporter | None.
        get_governance_guards: Callable returning list of guards.
        get_config: Callable returning AdminaConfig | None.

    Returns:
        The configured APIRouter.
    """
    router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

    # ClickHouse client does not support concurrent queries within the
    # same session.  The dashboard JS fires all endpoints in parallel
    # via Promise.all, so we serialise ClickHouse access with a lock.
    _ch_lock = asyncio.Lock()

    @router.websocket("/live")
    async def dashboard_live(websocket: WebSocket) -> None:
        """WebSocket endpoint for live governance event feed.

        Requires the same credential as the HTTP endpoints. Browsers
        cannot set custom headers on the ``WebSocket`` constructor, so
        the API key is also accepted via the ``api_key`` query
        parameter; the dashboard nginx forwards the static
        ``X-API-Key`` header transparently.
        """
        settings = get_settings()
        expected = getattr(settings, "ADMINA_API_KEY", "") or ""
        if expected:
            # Accept the credential from the X-API-Key header, the
            # ?api_key=... query param, or the admina_session cookie
            # set by the bundled dashboard at GET /.
            provided = (
                websocket.headers.get("X-API-Key")
                or websocket.query_params.get("api_key")
                or websocket.cookies.get("admina_session")
                or ""
            )
            if not provided or not secrets.compare_digest(provided, expected):
                await websocket.close(code=1008)
                return
        elif not getattr(settings, "ALLOW_UNAUTHENTICATED", False):
            await websocket.close(code=1008)
            return

        await websocket.accept()
        _ws_clients.add(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            _ws_clients.discard(websocket)

    @router.get("/score")
    async def dashboard_score() -> dict[str, Any]:
        """Governance score (weighted composite 0-100)."""
        return _compute_governance_score(
            metrics=get_metrics(),
            forensic_box=get_forensic_box(),
            compliance_engine=get_compliance(),
        )

    @router.get("/feed")
    async def dashboard_feed(
        limit: int = Query(50, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        """Recent governance events (paginated)."""
        ch = get_clickhouse()
        if not ch:
            return {"events": [], "count": 0, "error": "ClickHouse not available"}
        try:
            loop = asyncio.get_running_loop()
            db = get_settings().CLICKHOUSE_DB
            async with _ch_lock:
                result = await loop.run_in_executor(
                    None,
                    lambda: ch.query(
                        f"SELECT * FROM {db}.governance_events "
                        f"ORDER BY timestamp DESC LIMIT {int(limit)} OFFSET {int(offset)}"
                    ),
                )
            events = [dict(zip(result.column_names, row)) for row in result.result_rows]
            return {"events": events, "count": len(events)}
        except (OSError, RuntimeError, Exception) as exc:
            logger.warning("ClickHouse feed query failed: %s", exc)
            return {"events": [], "count": 0, "error": str(exc)}

    @router.get("/compliance")
    async def dashboard_compliance() -> dict[str, Any]:
        """EU AI Act gap analysis summary for the dashboard.

        IMPORTANT: this endpoint is read-only.  It does NOT create an
        assessment when none exists — that would pollute the engine's
        ``assessments`` list and make ``has_assessment`` always-true after
        the first dashboard load.  Instead we synthesise a placeholder
        ``latest`` whose ``gaps`` list covers every Art. 9-15 check, so
        the UI renders the same article grid (all at 0%) it would render
        for a real assessment with no evidence declared.
        """
        comp = get_compliance()
        from admina.domains.compliance.eu_ai_act import (
            EU_AI_ACT_DEADLINES,
            EU_AI_ACT_ENFORCEMENT_DEADLINE,
            HIGH_RISK_REQUIREMENTS,
        )

        assessments = getattr(comp, "assessments", [])
        if not assessments:
            gaps = [
                {
                    "requirement": req["name"],
                    "article": req["article"],
                    "check": check,
                    "status": "NOT_MET",
                }
                for req in HIGH_RISK_REQUIREMENTS.values()
                for check in req["checks"]
            ]
            placeholder = {
                "applicable": True,
                "compliance_score": 0,
                "total_checks": len(gaps),
                "passed_checks": 0,
                "gaps": gaps,
                "gap_count": len(gaps),
                "status": "NO_ASSESSMENT",
                "enforcement_deadline": EU_AI_ACT_ENFORCEMENT_DEADLINE,
                "deadlines": EU_AI_ACT_DEADLINES,
                "assessed_at": None,
            }
            return {
                "has_assessment": False,
                "latest": placeholder,
                "enforcement_deadline": EU_AI_ACT_ENFORCEMENT_DEADLINE,
                "deadlines": EU_AI_ACT_DEADLINES,
            }

        return {
            "has_assessment": True,
            "latest": assessments[-1],
            "total_assessments": len(assessments),
            "enforcement_deadline": EU_AI_ACT_ENFORCEMENT_DEADLINE,
            "deadlines": EU_AI_ACT_DEADLINES,
        }

    @router.get("/sovereignty")
    async def dashboard_sovereignty() -> dict[str, Any]:
        """Data zone statistics for the sovereignty map."""
        zones = {
            "local": {
                "name": "Local (on-premise)",
                "status": "enforced",
                "description": "All data processed locally through Admina proxy",
            },
        }
        ch = get_clickhouse()
        event_count = 0
        if ch:
            try:
                loop = asyncio.get_running_loop()
                db = get_settings().CLICKHOUSE_DB
                async with _ch_lock:
                    result = await loop.run_in_executor(
                        None,
                        lambda: ch.query(f"SELECT count() FROM {db}.governance_events"),
                    )
                event_count = result.result_rows[0][0] if result.result_rows else 0
            except (OSError, RuntimeError, Exception):
                pass

        return {
            "zones": zones,
            "total_governed_events": event_count,
            "data_residency_enforced": True,
        }

    @router.get("/infra")
    async def dashboard_infra() -> dict[str, Any]:
        """Infrastructure health: container status, response times, disk."""
        services: dict[str, dict[str, Any]] = {}

        # Proxy — always running if we can serve this request
        services["proxy"] = {"status": "healthy", "port": 8080}

        # Redis
        redis = get_redis() if get_redis else None
        if redis is not None:
            try:
                t0 = time.perf_counter()
                await redis.ping()
                latency = round((time.perf_counter() - t0) * 1000, 2)
                info = await redis.info("memory")
                services["redis"] = {
                    "status": "healthy",
                    "latency_ms": latency,
                    "used_memory_human": info.get("used_memory_human", "—"),
                    "used_memory_bytes": info.get("used_memory", 0),
                }
            except (OSError, RuntimeError) as exc:
                services["redis"] = {"status": "unhealthy", "error": str(exc)}
        else:
            services["redis"] = {"status": "not_configured"}

        # ClickHouse
        ch = get_clickhouse()
        if ch is not None:
            try:
                loop = asyncio.get_running_loop()
                async with _ch_lock:
                    t0 = time.perf_counter()
                    await loop.run_in_executor(None, lambda: ch.query("SELECT 1"))
                    latency = round((time.perf_counter() - t0) * 1000, 2)
                    db = get_settings().CLICKHOUSE_DB
                    row_result = await loop.run_in_executor(
                        None,
                        lambda: ch.query(f"SELECT count() FROM {db}.governance_events"),
                    )
                row_count = row_result.result_rows[0][0] if row_result.result_rows else 0
                services["clickhouse"] = {
                    "status": "healthy",
                    "latency_ms": latency,
                    "event_count": row_count,
                }
            except (OSError, RuntimeError, Exception) as exc:
                services["clickhouse"] = {
                    "status": "unhealthy",
                    "error": str(exc),
                }
        else:
            services["clickhouse"] = {"status": "not_configured"}

        # Forensic store
        fbox = get_forensic_box() if get_forensic_box else None
        if fbox is not None:
            stats = fbox.get_stats()
            services["forensic"] = {
                "status": "healthy" if stats.get("storage_available") else "in_memory",
                "record_count": stats.get("record_count", 0),
            }
        else:
            services["forensic"] = {"status": "not_configured"}

        # Upstream MCP
        http = get_http_client() if get_http_client else None
        upstream = get_settings().UPSTREAM_MCP_URL if get_settings else ""
        if http is None or not upstream.startswith(("http://", "https://")):
            services["upstream_mcp"] = {"status": "not_configured"}
        else:
            try:
                import httpx

                t0 = time.perf_counter()
                resp = await http.get(f"{upstream}/health", timeout=3.0)
                latency = round((time.perf_counter() - t0) * 1000, 2)
                services["upstream_mcp"] = {
                    "status": "healthy" if resp.status_code < 500 else "degraded",
                    "latency_ms": latency,
                    "url": upstream,
                }
            except (OSError, RuntimeError, httpx.HTTPError):
                services["upstream_mcp"] = {
                    "status": "unreachable",
                    "url": upstream,
                }

        healthy_count = sum(1 for s in services.values() if s.get("status") == "healthy")
        return {
            "services": services,
            "healthy_count": healthy_count,
            "total_count": len(services),
            "overall": "healthy" if healthy_count == len(services) else "degraded",
            "checked_at": datetime.now(UTC).isoformat(),
        }

    @router.get("/models")
    async def dashboard_models() -> dict[str, Any]:
        """Model status: active models, engine info, GPU utilization."""
        engine = get_engine_status() if get_engine_status else {}

        models: list[dict[str, Any]] = []

        # The governance engine itself is always "active"
        models.append(
            {
                "name": "admina-governance-engine",
                "type": "governance",
                "backend": engine.get("engine", "python"),
                "version": engine.get("rust_version") or "pure-python",
                "status": "active",
            }
        )

        # The ai_infra domain is opt-in; check whether it is configured.
        ai_infra_enabled = False
        try:
            cfg = get_settings()
            ai_infra_enabled = getattr(cfg, "AI_INFRA_LLM_ENABLED", False)
        except (AttributeError, ValueError):
            pass

        gpu_info: dict[str, Any] | None = None
        if ai_infra_enabled:
            # Probe Ollama if configured
            http = get_http_client() if get_http_client else None
            if http is not None:
                try:
                    ollama_url = getattr(get_settings(), "OLLAMA_URL", "http://ollama:11434")
                    resp = await http.get(f"{ollama_url}/api/tags", timeout=3.0)
                    if resp.status_code == 200:
                        for m in resp.json().get("models", []):
                            models.append(
                                {
                                    "name": m.get("name", "unknown"),
                                    "type": "llm",
                                    "backend": "ollama",
                                    "size": m.get("size"),
                                    "status": "loaded",
                                }
                            )
                except (OSError, RuntimeError, ValueError):
                    pass

        return {
            "models": models,
            "model_count": len(models),
            "engine": engine,
            "ai_infra_enabled": ai_infra_enabled,
            "gpu": gpu_info,
        }

    @router.get("/suggestions")
    async def dashboard_suggestions(
        window_hours: int = Query(24, ge=1, le=720),
        min_count: int = Query(5, ge=1, le=10000),
        format: str = Query("json", pattern="^(json|csv)$"),
    ) -> Any:
        """Statistical, no-LLM policy suggestions based on the recent feed.

        Looks at the last `window_hours` of governance events, aggregates
        block/allow counts per pattern category, and produces actionable
        recommendations: categories to silence, mode toggles to consider,
        custom patterns to harden. The output is consumed by the dashboard
        and surfaced as-is.

        Args:
            window_hours: lookback window in hours (default 24, max 720 = 30d).
            min_count: skip categories with fewer than this many events.
        """
        ch = get_clickhouse()
        if not ch:
            return {
                "window_hours": window_hours,
                "events_analyzed": 0,
                "suggestions": [],
                "error": "ClickHouse not available",
            }

        try:
            loop = asyncio.get_running_loop()
            db = get_settings().CLICKHOUSE_DB
            mode = getattr(get_settings(), "GOVERNANCE_MODE", "enforce")

            # Aggregate by action + risk + a flat category extracted from details.
            # Schema: (event_id, timestamp, event_type, agent_id, session_id,
            #          method, tool_name, action, risk_level, details, ...)
            query = (
                f"SELECT action, risk_level, details "
                f"FROM {db}.governance_events "
                f"WHERE timestamp >= now() - INTERVAL {int(window_hours)} HOUR"
            )
            async with _ch_lock:
                result = await loop.run_in_executor(None, lambda: ch.query(query))

            total = len(result.result_rows)
            if total == 0:
                return {
                    "window_hours": window_hours,
                    "events_analyzed": 0,
                    "mode": mode,
                    "suggestions": [
                        {
                            "type": "no_data",
                            "severity": "info",
                            "message": (
                                f"No events in the last {window_hours}h. Nothing to "
                                "suggest yet — generate some traffic first."
                            ),
                            "actions": [],
                        }
                    ],
                }

            # Per-category counters
            cat_total: dict[str, int] = {}
            cat_blocked: dict[str, int] = {}
            cat_would_blocked: dict[str, int] = {}
            for row in result.result_rows:
                action, _risk, details_raw = row[0], row[1], row[2]
                # Action is stored lowercase in ClickHouse — normalise once.
                action_upper = (action or "").upper()
                try:
                    d = json.loads(details_raw) if details_raw else {}
                except (TypeError, ValueError):
                    d = {}
                # The pipeline stores firewall patterns under
                # details.firewall.patterns: [{pattern, risk_level}, ...]
                # (also nested under fast_path.patterns when only the fast
                # path matched).
                fw = d.get("firewall", {}) or {}
                patterns = list(fw.get("patterns") or [])
                if not patterns and isinstance(fw.get("fast_path"), dict):
                    patterns = list(fw["fast_path"].get("patterns") or [])
                cats = {p.get("pattern") for p in patterns if p.get("pattern")}
                # No firewall patterns: still count loop_breaker / pii / guard categories
                if (d.get("loop_breaker", {}) or {}).get("is_loop"):
                    cats.add("loop_breaker")
                if d.get("would_action") and not cats:
                    cats.add("(unknown)")
                would = (d.get("would_action") or "").upper()
                for cat in cats or {"(none)"}:
                    cat_total[cat] = cat_total.get(cat, 0) + 1
                    if action_upper in ("BLOCK", "CIRCUIT_BREAK"):
                        cat_blocked[cat] = cat_blocked.get(cat, 0) + 1
                    if would in ("BLOCK", "CIRCUIT_BREAK"):
                        cat_would_blocked[cat] = cat_would_blocked.get(cat, 0) + 1

            # Build suggestions
            suggestions: list[dict[str, Any]] = []

            # 1. High-volume categories — candidate for review
            for cat, count in sorted(cat_total.items(), key=lambda kv: -kv[1]):
                if count < min_count or cat in ("(none)", "(unknown)"):
                    continue
                share = round(count * 100 / total, 1)
                blocked = cat_blocked.get(cat, 0)
                would = cat_would_blocked.get(cat, 0)
                if mode == "enforce" and share >= 30:
                    suggestions.append(
                        {
                            "type": "high_block_share",
                            "category": cat,
                            "count": count,
                            "blocked": blocked,
                            "share_pct": share,
                            "severity": "info" if share < 60 else "warn",
                            "message": (
                                f"Category '{cat}' accounts for {share}% of traffic in "
                                f"the last {window_hours}h ({blocked} blocked). If many "
                                "are false positives, consider tuning."
                            ),
                            "actions": [
                                "Inspect samples: GET /api/dashboard/feed?limit=100",
                                "Switch to observe mode for tuning: ADMINA_GOVERNANCE_MODE=observe",
                                f"Disable temporarily via admina.yaml: "
                                f"agent_security.firewall.disabled_categories: ['{cat}']",
                            ],
                        }
                    )
                if mode in ("observe", "dry-run") and would >= min_count:
                    suggestions.append(
                        {
                            "type": "would_block_in_enforce",
                            "category": cat,
                            "count": count,
                            "would_blocked": would,
                            "share_pct": share,
                            "severity": "info",
                            "message": (
                                f"In enforce mode, category '{cat}' would have blocked "
                                f"{would} request(s) in the last {window_hours}h. "
                                "Review the samples before flipping the mode."
                            ),
                            "actions": [
                                "Inspect: GET /api/dashboard/feed?limit=100",
                                "Once tuned, switch to: ADMINA_GOVERNANCE_MODE=enforce",
                            ],
                        }
                    )

            # 2. Mode-specific guidance
            if mode == "enforce" and not cat_blocked:
                suggestions.append(
                    {
                        "type": "enforce_no_blocks",
                        "severity": "info",
                        "message": (
                            "Enforce mode active for the last "
                            f"{window_hours}h with zero blocks. Either traffic is "
                            "clean or your patterns are too permissive — sample a "
                            "few requests to confirm."
                        ),
                        "actions": ["Inspect: GET /api/dashboard/feed?limit=50"],
                    }
                )
            elif mode in ("observe", "dry-run") and not cat_would_blocked:
                suggestions.append(
                    {
                        "type": "observe_clean",
                        "severity": "info",
                        "message": (
                            f"Observe mode for {window_hours}h with zero "
                            "would-have-blocked events. Safe to switch to enforce."
                        ),
                        "actions": ["Set ADMINA_GOVERNANCE_MODE=enforce"],
                    }
                )

            # 3. Loop breaker hot signal
            lb_count = cat_total.get("loop_breaker", 0)
            if lb_count >= max(min_count, 10):
                suggestions.append(
                    {
                        "type": "loop_breaker_active",
                        "category": "loop_breaker",
                        "count": lb_count,
                        "severity": "warn",
                        "message": (
                            f"Loop breaker fired {lb_count} time(s) in {window_hours}h. "
                            "If these are legitimate template loops, consider lowering "
                            "the similarity threshold or raising max_consecutive."
                        ),
                        "actions": [
                            "Tune ADMINA_LOOP_SIMILARITY_THRESHOLD (default 0.85)",
                            "Tune ADMINA_LOOP_MAX_CONSECUTIVE (default 3)",
                        ],
                    }
                )

            # 4. Trend awareness — compare current window vs the
            # immediately-preceding equal window. If a category's blocked
            # rate has surged ≥2x with absolute count ≥ min_count, flag it.
            try:
                prev_query = (
                    f"SELECT details FROM {db}.governance_events "
                    f"WHERE timestamp >= now() - INTERVAL {int(window_hours * 2)} HOUR "
                    f"  AND timestamp <  now() - INTERVAL {int(window_hours)} HOUR "
                    f"  AND lower(action) IN ('block','circuit_break')"
                )
                async with _ch_lock:
                    prev_res = await loop.run_in_executor(
                        None,
                        lambda: ch.query(prev_query),
                    )
                prev_blocked: dict[str, int] = {}
                for (det_raw,) in prev_res.result_rows:
                    try:
                        d = json.loads(det_raw) if det_raw else {}
                    except (TypeError, ValueError):
                        continue
                    fw = d.get("firewall", {}) or {}
                    pats = list(fw.get("patterns") or []) or list(
                        (fw.get("fast_path") or {}).get("patterns") or []
                    )
                    for p in pats:
                        c = p.get("pattern")
                        if c:
                            prev_blocked[c] = prev_blocked.get(c, 0) + 1

                for cat, cur in cat_blocked.items():
                    if cat in ("(none)", "(unknown)") or cur < min_count:
                        continue
                    prev = prev_blocked.get(cat, 0)
                    if prev == 0 and cur >= min_count * 2:
                        suggestions.append(
                            {
                                "type": "trend_new_category",
                                "category": cat,
                                "previous": prev,
                                "current": cur,
                                "severity": "warn",
                                "message": (
                                    f"Category '{cat}' was silent in the previous "
                                    f"{window_hours}h and now blocks {cur} requests. "
                                    "Investigate — could be a new attack campaign or "
                                    "a legitimate workflow that needs whitelisting."
                                ),
                                "actions": [
                                    "Inspect: GET /api/dashboard/feed?limit=100",
                                ],
                            }
                        )
                    elif prev > 0 and cur >= 2 * prev and cur >= min_count:
                        ratio = round(cur / prev, 1)
                        suggestions.append(
                            {
                                "type": "trend_surge",
                                "category": cat,
                                "previous": prev,
                                "current": cur,
                                "ratio": ratio,
                                "severity": "warn",
                                "message": (
                                    f"'{cat}' blocks surged {ratio}x ({prev} → {cur}) "
                                    f"compared to the previous {window_hours}h. "
                                    "Likely a new attack pattern variant."
                                ),
                                "actions": [
                                    "Inspect samples and consider adding a custom_pattern",
                                    "Or temporarily switch the category to observe mode",
                                ],
                            }
                        )
            except (OSError, RuntimeError, Exception) as exc:
                logger.debug("Trend comparison skipped: %s", exc)

            payload = {
                "window_hours": window_hours,
                "events_analyzed": total,
                "mode": mode,
                "by_category": cat_total,
                "blocked_by_category": cat_blocked,
                "would_blocked_by_category": cat_would_blocked,
                "suggestions": suggestions,
            }
            if format == "csv":
                return _suggestions_to_csv(payload)
            return payload
        except (OSError, RuntimeError, Exception) as exc:
            logger.warning("Suggestions query failed: %s", exc)
            return {
                "window_hours": window_hours,
                "events_analyzed": 0,
                "suggestions": [],
                "error": str(exc),
            }

    @router.get("/trend")
    async def dashboard_trend(
        window_hours: int = Query(24, ge=1, le=720),
        bucket_minutes: int = Query(15, ge=1, le=1440),
    ) -> dict[str, Any]:
        """Time-series of governance events for charting.

        Returns counts per bucket for the last `window_hours`, broken
        down by action (allow / block / circuit_break / redact). The
        bucket size is configurable so the same endpoint feeds both a
        24h-by-15min sparkline and a 30d-by-6h trend chart.

        Args:
            window_hours: lookback window in hours (max 720 = 30d).
            bucket_minutes: aggregation bucket size in minutes.
        """
        ch = get_clickhouse()
        if not ch:
            return {
                "window_hours": window_hours,
                "bucket_minutes": bucket_minutes,
                "buckets": [],
                "error": "ClickHouse not available",
            }
        try:
            loop = asyncio.get_running_loop()
            db = get_settings().CLICKHOUSE_DB
            # toStartOfInterval truncates each event to its bucket start;
            # aggregate per (bucket, action). Returns at most
            # window_hours * 60 / bucket_minutes rows × N actions.
            query = (
                f"SELECT toStartOfInterval(timestamp, INTERVAL {int(bucket_minutes)} MINUTE) AS bucket, "
                f"       lower(action) AS act, count() AS n "
                f"FROM {db}.governance_events "
                f"WHERE timestamp >= now() - INTERVAL {int(window_hours)} HOUR "
                f"GROUP BY bucket, act ORDER BY bucket"
            )
            async with _ch_lock:
                result = await loop.run_in_executor(None, lambda: ch.query(query))

            # Pivot rows into per-bucket records: {ts, allow, block, circuit_break, redact}
            buckets: dict[str, dict[str, int]] = {}
            for bucket, act, n in result.result_rows:
                key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket)
                buckets.setdefault(key, {})[act] = int(n)

            series = []
            for ts in sorted(buckets):
                row = buckets[ts]
                series.append(
                    {
                        "ts": ts,
                        "allow": row.get("allow", 0),
                        "block": row.get("block", 0),
                        "circuit_break": row.get("circuit_break", 0),
                        "redact": row.get("redact", 0),
                        "total": sum(row.values()),
                    }
                )

            return {
                "window_hours": window_hours,
                "bucket_minutes": bucket_minutes,
                "bucket_count": len(series),
                "buckets": series,
            }
        except (OSError, RuntimeError, Exception) as exc:
            logger.warning("Trend query failed: %s", exc)
            return {
                "window_hours": window_hours,
                "bucket_minutes": bucket_minutes,
                "buckets": [],
                "error": str(exc),
            }

    @router.get("/oisg")
    async def dashboard_oisg() -> dict[str, Any]:
        """OISG adequacy score (Open Intelligent Secure Governed, 0-100)."""
        result = compute_oisg_score(
            firewall=get_firewall() if get_firewall else None,
            pii_redactor=get_pii_redactor() if get_pii_redactor else None,
            loop_breaker=get_loop_breaker() if get_loop_breaker else None,
            forensic_box=get_forensic_box(),
            compliance_engine=get_compliance(),
            otel_exporter=get_otel_exporter() if get_otel_exporter else None,
            governance_guards=get_governance_guards() if get_governance_guards else [],
            config=get_config() if get_config else None,
            engine_status=get_engine_status() if get_engine_status else {},
            metrics=get_metrics(),
        )
        return {**result.to_dict(), "colors": PILLAR_COLORS}

    return router
