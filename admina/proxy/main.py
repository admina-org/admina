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

"""
Admina — AI Governance Proxy
The governance layer for AI agents, LLMs, and autonomous systems.
https://admina.org
"""

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import logging
import os
import re
import secrets as _secrets
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import clickhouse_connect
import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import admina.plugins.builtin.transports.mcp as mcp_transport
from admina import __version__
from admina.core.event_bus import GovernanceEvent as BusGovernanceEvent
from admina.core.event_bus import bus as governance_bus
from admina.core.types import EventType, GovernanceAction
from admina.domains.compliance.forensic import ForensicBlackBox
from admina.domains.compliance.otel import OTELGovernanceExporter
from admina.domains.governance import (
    build_governance_details,
    redact_response_result,
    run_pipeline,
    safe_serialize,
)
from admina.engines import (
    engine_status,
    get_firewall,
    get_loop_breaker,
    get_pii_engine,
)
from admina.proxy.api.dashboard import create_dashboard_endpoints
from admina.proxy.api.integration import create_integration_endpoints
from admina.proxy.config import GovernanceEvent, settings
from admina.proxy.multi_upstream import MultiUpstreamRouter
from admina.proxy.state import ProxyState

# ── Admina config (for OISG score) ──────────────────────────
try:
    from admina.core.config import load_config as _load_admina_config

    _admina_config = _load_admina_config()
except (ImportError, ValueError, OSError):  # pragma: no cover
    _admina_config = None

# ── SQL identifier validation ────────────────────────────────
_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _validate_identifier(name: str, label: str = "identifier") -> None:
    """Raise ValueError if *name* is not a safe SQL identifier."""
    if not _SAFE_IDENTIFIER.match(name):
        raise ValueError(f"Unsafe {label}: {name!r}")


# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("admina.proxy")


# ── Background tasks ─────────────────────────────────────────
# Hold strong references to fire-and-forget tasks. Without this set,
# Python may garbage-collect the task object before the coroutine
# completes — see https://docs.python.org/3/library/asyncio-task.html
# #asyncio.create_task.
_background_tasks: set[asyncio.Task] = set()


def _spawn(coro: Any) -> asyncio.Task:
    """Schedule *coro* as a background task and keep a strong ref."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


def instantiate_plugins(
    registry: Any,
    category: str,
    plugin_config: dict[str, Any] | None = None,
) -> list:
    """Instantiate every registered plugin of *category*.

    Plugins whose ``__init__`` accepts a ``config`` parameter receive
    their block from admina.yaml ``plugin_config:`` (keyed by plugin
    name); the others are constructed with no arguments.
    """
    plugin_config = plugin_config or {}
    instances = []
    for name, cls in registry.list(category).items():
        try:
            params = inspect.signature(cls.__init__).parameters
            if "config" in params:
                instances.append(cls(config=plugin_config.get(name)))
            else:
                instances.append(cls())
        except ImportError as exc:
            logger.warning(
                "Skipping %s plugin %r: optional dependency missing (%s)",
                category,
                name,
                exc,
            )
        except Exception as exc:  # noqa: BLE001 — third-party/user-config code, isolate
            logger.error(
                "Skipping %s plugin %r: constructor failed (%s) — check its plugin_config block",
                category,
                name,
                exc,
                exc_info=True,
            )
    return instances


# ── Startup / Shutdown ───────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    logger.info("Admina Proxy starting...")

    # Build ProxyState
    state = ProxyState(
        firewall=get_firewall(),
        pii_redactor=get_pii_engine(),
        loop_breaker=get_loop_breaker(
            window_size=settings.LOOP_WINDOW_SIZE,
            similarity_threshold=settings.LOOP_SIMILARITY_THRESHOLD,
            max_consecutive=settings.LOOP_MAX_CONSECUTIVE,
        ),
        router=MultiUpstreamRouter(default_upstream=settings.UPSTREAM_MCP_URL),
    )

    # ── Plugin discovery ──────────────────────────────────────
    _plugin_modules = list(_admina_config.plugins) if _admina_config else []
    state.registry.discover(extra_modules=_plugin_modules or None)

    _plugin_cfg = dict(getattr(_admina_config, "plugin_config", {}) or {}) if _admina_config else {}
    state.governance_guards = instantiate_plugins(state.registry, "governance_guard", _plugin_cfg)
    state.alert_channels = instantiate_plugins(state.registry, "alert_channel", _plugin_cfg)
    state.auth_providers = instantiate_plugins(state.registry, "auth_provider", _plugin_cfg)
    # Drop providers that declare themselves unconfigured (e.g. keyless APIKeyAuthProvider).
    # A provider without is_configured() defaults to True — kept.
    state.auth_providers = [
        p for p in state.auth_providers if getattr(p, "is_configured", lambda: True)()
    ]
    if state.governance_guards:
        logger.info(
            "Governance guards loaded: %s",
            [g.name for g in state.governance_guards],
        )
    if state.alert_channels:
        logger.info(
            "Alert channels loaded: %s",
            [c.channel_name for c in state.alert_channels],
        )
    if state.auth_providers:
        logger.info(
            "Auth providers loaded: %s",
            [p.provider_name for p in state.auth_providers],
        )

    # ── OTEL exporter — subscribe to event bus ────────────────
    otel_endpoint = getattr(settings, "OTEL_ENDPOINT", "http://localhost:4317")
    state.otel_exporter = OTELGovernanceExporter(endpoint=otel_endpoint)
    if state.otel_exporter.enabled:

        async def _otel_subscriber(event: BusGovernanceEvent) -> None:
            state.otel_exporter.trace_governance_decision(
                domain=event.domain or "unknown",
                action=event.action or "UNKNOWN",
                risk_level=event.risk_level or "LOW",
                latency_us=event.metadata.get("latency_us", 0),
                session_id=event.session_id,
                metadata=event.metadata,
            )

        governance_bus.subscribe(EventType.GOVERNANCE_DECISION, _otel_subscriber)
        logger.info("OTEL exporter subscribed to governance events")

    # ── Alert channels — subscribe to governance decisions ────
    if state.alert_channels:

        async def _alert_bus_subscriber(event: BusGovernanceEvent) -> None:
            if event.action in ("BLOCK", "CIRCUIT_BREAK"):
                alert = {
                    "level": event.risk_level or "HIGH",
                    "domain": event.domain or "unknown",
                    "summary": f"{event.action} — session {event.session_id}",
                    "details": event.metadata,
                    "session_id": event.session_id,
                }
                await _fire_alerts(state.alert_channels, alert)

        governance_bus.subscribe(EventType.GOVERNANCE_DECISION, _alert_bus_subscriber)
        logger.info("Alert channels subscribed to governance events")

    # Warn if running without auth in non-dev context
    if not settings.ADMINA_API_KEY and not state.auth_providers:
        logger.warning(
            "ADMINA_API_KEY is not set and no auth providers loaded — "
            "all endpoints are unauthenticated. "
            "Set ADMINA_API_KEY or configure an auth provider for production."
        )

    # Redis — optional, skip gracefully if URL is empty or malformed
    state.redis = None
    if settings.REDIS_URL and settings.REDIS_URL.startswith(("redis://", "rediss://", "unix://")):
        try:
            state.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await state.redis.ping()
            logger.info("Redis connected")
        except (OSError, ValueError, aioredis.RedisError) as e:
            logger.warning("Redis not available: %s — continuing without rate-limit cache", e)
            state.redis = None
    else:
        logger.info("Redis disabled (REDIS_URL is empty or non-redis scheme)")

    # Forensic backend: filesystem (default) | s3 (boto3 generic) | memory.
    # MinIO servers are supported through the s3 backend (they speak the S3
    # API); the legacy minio-SDK backend was removed in 0.9.5.
    boto3_client = None

    if settings.FORENSIC_BACKEND == "s3":
        try:
            import boto3

            kwargs = {
                "service_name": "s3",
                "region_name": settings.FORENSIC_S3_REGION,
            }
            if settings.FORENSIC_S3_ENDPOINT:
                kwargs["endpoint_url"] = settings.FORENSIC_S3_ENDPOINT
            if settings.FORENSIC_S3_ACCESS_KEY:
                kwargs["aws_access_key_id"] = settings.FORENSIC_S3_ACCESS_KEY
                kwargs["aws_secret_access_key"] = settings.FORENSIC_S3_SECRET_KEY
            boto3_client = boto3.client(**kwargs)
            boto3_client.list_buckets()
            logger.info(
                "S3 forensic backend connected (endpoint=%s)",
                settings.FORENSIC_S3_ENDPOINT or "default AWS",
            )
        except ImportError:
            logger.warning(
                "FORENSIC_BACKEND=s3 requires boto3 (pip install boto3) — "
                "falling back to filesystem"
            )
            boto3_client = None
        except Exception as e:  # noqa: BLE001
            logger.warning("S3 not reachable: %s — falling back to filesystem", e)
            boto3_client = None

    if boto3_client is not None:
        state.forensic_box = ForensicBlackBox(
            boto3_client=boto3_client,
            bucket=settings.FORENSIC_S3_BUCKET,
            s3_object_lock=settings.FORENSIC_S3_LOCK,
            s3_lock_days=settings.FORENSIC_S3_LOCK_DAYS,
            s3_auto_create_locked_bucket=settings.FORENSIC_S3_LOCK_AUTO_BUCKET,
            s3_max_retries=settings.FORENSIC_S3_MAX_RETRIES,
            s3_base_delay_s=settings.FORENSIC_S3_BASE_DELAY_S,
        )
        if settings.FORENSIC_S3_LOCK:
            logger.info(
                "Forensic Object Lock ENABLED: every record locked for %d days "
                "in COMPLIANCE mode (WORM)",
                settings.FORENSIC_S3_LOCK_DAYS,
            )
    elif settings.FORENSIC_BACKEND == "filesystem":
        if not settings.FORENSIC_BASE_DIR:
            logger.warning(
                "FORENSIC_BACKEND=filesystem but FORENSIC_BASE_DIR is empty — "
                "downgrading to in-memory backend (records will be lost on restart)"
            )
            state.forensic_box = ForensicBlackBox()
        else:
            state.forensic_box = ForensicBlackBox(filesystem_dir=settings.FORENSIC_BASE_DIR)
            logger.info(
                "Forensic backend: filesystem at %s",
                settings.FORENSIC_BASE_DIR,
            )
    else:
        # Default: in-memory only. Loud warning so the operator
        # knows the proxy is running with no audit persistence.
        state.forensic_box = ForensicBlackBox()
        logger.warning(
            "Forensic backend: IN-MEMORY ONLY — events will be LOST on restart. "
            "Set FORENSIC_BACKEND=filesystem (with FORENSIC_BASE_DIR) or =s3 "
            "for persistence."
        )

    # ClickHouse — optional, skip if host is empty
    state.clickhouse = None
    if settings.CLICKHOUSE_HOST:
        try:
            state.clickhouse = clickhouse_connect.get_client(
                host=settings.CLICKHOUSE_HOST,
                port=settings.CLICKHOUSE_PORT,
                database=settings.CLICKHOUSE_DB,
                password=settings.CLICKHOUSE_PASSWORD,
            )
            _init_clickhouse_tables(state.clickhouse)
            logger.info("ClickHouse connected")
        except (OSError, clickhouse_connect.driver.exceptions.DatabaseError) as e:
            logger.warning("ClickHouse not available: %s — analytics disabled", e)
            state.clickhouse = None
    else:
        logger.info("ClickHouse disabled (CLICKHOUSE_HOST is empty)")

    # HTTP Client for upstream MCP
    state.http_client = httpx.AsyncClient(timeout=30.0)

    # Multi-upstream router (for OpenClaw integration)
    routing_path = os.environ.get("ROUTING_CONFIG_PATH", "")
    if routing_path:
        state.router.load_config(routing_path)
        logger.info("Multi-upstream routing: %d servers configured", len(state.router.routes))

    # Publish state on app
    app.state.proxy = state

    logger.info("=" * 60)
    logger.info("  Admina Governance Proxy — READY  v%s", __version__)
    _eng = engine_status()
    _eng_label = (
        "%s v%s" % (_eng["engine"].upper(), _eng["rust_version"])
        if _eng["rust_available"]
        else "%s (install admina-core for Rust speed)" % _eng["engine"].upper()
    )
    logger.info("  Engine: %s", _eng_label)
    logger.info("  Upstream MCP: %s", settings.UPSTREAM_MCP_URL)
    logger.info(
        "  Auth: %s",
        "ON" if settings.ADMINA_API_KEY else "OFF (set ADMINA_API_KEY for production)",
    )
    logger.info(
        "  Rate Limiting: %s",
        "ON (Redis)" if state.redis else "OFF (Redis unavailable)",
    )
    if state.router.is_multi_upstream:
        logger.info("  OpenClaw mode: routing %d MCP servers", len(state.router.routes))
    logger.info("  Firewall: ON | PII Redaction: ON | Loop Breaker: ON")
    logger.info("=" * 60)

    yield

    # Shutdown
    if state.redis:
        await state.redis.close()
    if state.http_client:
        await state.http_client.aclose()
    logger.info("Admina Proxy stopped")


def _init_clickhouse_tables(client):
    """Create governance events table in ClickHouse."""
    _validate_identifier(settings.CLICKHOUSE_DB, "CLICKHOUSE_DB")
    client.command(f"CREATE DATABASE IF NOT EXISTS {settings.CLICKHOUSE_DB}")
    client.command(f"""
        CREATE TABLE IF NOT EXISTS {settings.CLICKHOUSE_DB}.governance_events (
            event_id String,
            timestamp DateTime64(3),
            event_type String,
            agent_id String,
            session_id String,
            method String,
            tool_name String,
            action String,
            risk_level String,
            details String,
            latency_ms Float64,
            request_hash String,
            response_hash String
        ) ENGINE = MergeTree()
        ORDER BY (timestamp, event_id)
        TTL toDateTime(timestamp) + INTERVAL 7 YEAR
    """)
    logger.info("ClickHouse tables initialized")


# ── FastAPI App ──────────────────────────────────────────────
app = FastAPI(
    title="Admina Governance Proxy",
    description="AI Governance & Security for Autonomous Agents",
    version=__version__,
    lifespan=lifespan,
    servers=[
        {"url": "http://localhost:3000", "description": "Dashboard (nginx proxy)"},
        {"url": "http://localhost:8080", "description": "Proxy (direct)"},
    ],
)

_cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",")]
if "*" in _cors_origins:
    logger.warning(
        "CORS_ORIGINS contains wildcard '*' — all cross-origin requests will be accepted"
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "X-Session-Id",
        "X-Agent-Id",
        "Authorization",
        "X-API-Key",
    ],
)


def _get_state(request: Request) -> ProxyState:
    """Retrieve ProxyState from the app."""
    return request.app.state.proxy


# ── Dashboard & Integration API Routers ──────────────────────
# The lambdas close over `app` so they resolve state at call time (after lifespan).
_dashboard_router = create_dashboard_endpoints(
    get_metrics=lambda: app.state.proxy.metrics,
    get_forensic_box=lambda: app.state.proxy.forensic_box,
    get_compliance=lambda: app.state.proxy.compliance,
    get_clickhouse=lambda: app.state.proxy.clickhouse,
    get_settings=lambda: settings,
    get_redis=lambda: app.state.proxy.redis,
    get_engine_status=lambda: engine_status(),
    get_http_client=lambda: app.state.proxy.http_client,
    get_firewall=lambda: app.state.proxy.firewall,
    get_pii_redactor=lambda: app.state.proxy.pii_redactor,
    get_loop_breaker=lambda: app.state.proxy.loop_breaker,
    get_otel_exporter=lambda: app.state.proxy.otel_exporter,
    get_governance_guards=lambda: app.state.proxy.governance_guards,
    get_config=lambda: _admina_config,
    verify_credential=lambda **kw: verify_credential(**kw),
)
app.include_router(_dashboard_router)

_integration_router = create_integration_endpoints(
    get_firewall=lambda: app.state.proxy.firewall,
    get_pii_scanner=lambda: app.state.proxy.pii_redactor,
    get_loop_breaker=lambda: app.state.proxy.loop_breaker,
    get_forensic_box=lambda: app.state.proxy.forensic_box,
    get_settings=lambda: settings,
)
app.include_router(_integration_router)


# ── Bundled dashboard (no-Docker dev mode) ────────────────────
# When running `admina dev` (default, no Docker), the proxy serves
# the dashboard SPA on the same port. In Docker mode nginx serves it
# separately on :3000, so this code path is harmless there too —
# nginx hits /api/* before /, and / is fine either way.
_DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard" / "static"
_DASHBOARD_CACHE: str | None = None


def _dashboard_index_html() -> str:
    """Return the dashboard index.html with %%VERSION%% / %%GIT_COMMIT%%
    substituted in-process (no nginx build-time templating)."""
    global _DASHBOARD_CACHE
    if _DASHBOARD_CACHE is not None:
        return _DASHBOARD_CACHE
    index_path = _DASHBOARD_DIR / "index.html"
    html = index_path.read_text(encoding="utf-8")
    html = html.replace("%%VERSION%%", f"v{__version__}")
    html = html.replace("%%GIT_COMMIT%%", "local")
    # Local mode has no nginx, so the basic-auth placeholder must be
    # neutralised to avoid the browser seeing the literal placeholder.
    html = html.replace("__ADMINA_API_KEY__", "")
    _DASHBOARD_CACHE = html
    return html


_DASHBOARD_COOKIE = "admina_session"
# Dashboard session cookie lifetime (seconds). The signed token expires
# after this window, after which the browser must re-load GET / to get a
# fresh one (still gated by the API key check).
_DASHBOARD_SESSION_TTL = 86400


def _issue_dashboard_token(now: int | None = None) -> str:
    """Mint a signed, expiring session token for the dashboard cookie.

    The token is ``<expiry>.<sig>`` where ``sig`` is an HMAC-SHA256 of the
    expiry keyed by ``ADMINA_API_KEY``. The API key itself never leaves the
    server — only a derived signature does — so the cookie carries no
    clear-text secret (addresses CodeQL py/clear-text-storage).
    """
    exp = (now if now is not None else int(time.time())) + _DASHBOARD_SESSION_TTL
    payload = str(exp)
    sig = hmac.new(
        settings.ADMINA_API_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    raw = f"{payload}.{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _verify_dashboard_token(token: str, now: int | None = None) -> bool:
    """Validate a dashboard session token: signature intact and not expired."""
    if not settings.ADMINA_API_KEY or not token:
        return False
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        payload, sig = raw.rsplit(".", 1)
    except (ValueError, UnicodeDecodeError):
        return False
    expected = hmac.new(
        settings.ADMINA_API_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not _secrets.compare_digest(sig, expected):
        return False
    try:
        exp = int(payload)
    except ValueError:
        return False
    return (now if now is not None else int(time.time())) < exp


def verify_credential(
    *,
    headers: Any = None,
    query_params: Any = None,
    cookies: Any = None,
) -> bool:
    """Authenticate from credential parts (header / query / cookie).

    Accepts the raw ``ADMINA_API_KEY`` via ``X-API-Key`` /
    ``Authorization: Bearer`` / ``?api_key=`` (constant-time compare), OR the
    signed ``admina_session`` cookie (verified, never the raw key). Single
    source of truth shared by the HTTP middleware, the WebSocket upgrade, and
    the API-key auth provider so they cannot drift.
    """
    headers = headers or {}
    query_params = query_params or {}
    cookies = cookies or {}
    if not settings.ADMINA_API_KEY:
        return False
    auth_header = headers.get("Authorization") or headers.get("authorization") or ""
    raw = (
        headers.get("X-API-Key")
        or headers.get("x-api-key")
        or auth_header.removeprefix("Bearer ").strip()
        or query_params.get("api_key")
        or ""
    )
    if raw and _secrets.compare_digest(raw, settings.ADMINA_API_KEY):
        return True
    return _verify_dashboard_token(cookies.get(_DASHBOARD_COOKIE, ""))


if _DASHBOARD_DIR.is_dir():
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles

    app.mount(
        "/vendor",
        StaticFiles(directory=_DASHBOARD_DIR / "vendor"),
        name="dashboard-vendor",
    )

    @app.get("/heimdall.png", include_in_schema=False)
    async def _dashboard_logo() -> Response:
        return Response(
            content=(_DASHBOARD_DIR / "heimdall.png").read_bytes(),
            media_type="image/png",
        )

    @app.get("/", include_in_schema=False)
    async def _dashboard_root() -> HTMLResponse:
        # Issue a session cookie carrying the API key so subsequent
        # /api/* fetches and the WebSocket auto-authenticate without
        # the dashboard JS needing to know the key.
        resp = HTMLResponse(_dashboard_index_html())
        if settings.ADMINA_API_KEY:
            resp.set_cookie(
                _DASHBOARD_COOKIE,
                # A signed, expiring token — NOT the API key itself, so the
                # secret never leaves the server in clear text.
                _issue_dashboard_token(),
                httponly=True,
                samesite="lax",
                # Off by default for local HTTP dev; set
                # DASHBOARD_COOKIE_SECURE=true behind HTTPS in production so
                # the session cookie is never sent over plain HTTP.
                secure=settings.DASHBOARD_COOKIE_SECURE,
                max_age=_DASHBOARD_SESSION_TTL,
            )
        return resp


# ── Auth Middleware ───────────────────────────────────────────
# /health and the OpenAPI docs are always public.
# Dashboard static assets are also public so the SPA can boot.
_AUTH_EXEMPT = {
    "/",
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/metrics",
    "/heimdall.png",
}
_AUTH_EXEMPT_PREFIXES = ("/vendor/",)


@app.middleware("http")
async def auth_middleware(request: Request, call_next) -> JSONResponse:
    path = request.url.path
    if path in _AUTH_EXEMPT or path.startswith(_AUTH_EXEMPT_PREFIXES):
        return await call_next(request)

    state = _get_state(request)

    # 1. Try plugin auth providers first (if any are loaded)
    if state.auth_providers:
        for provider in state.auth_providers:
            try:
                user = await provider.authenticate(request)
                if user:
                    request.state.user = user
                    return await call_next(request)
            except (ValueError, RuntimeError, OSError):
                continue  # try next provider
        # All providers failed — reject
        return JSONResponse(
            status_code=401,
            content={
                "error": "Unauthorized",
                "detail": "Authentication failed across all providers",
            },
        )

    # 2. Fallback: static ADMINA_API_KEY check.
    # API clients present the raw key via X-API-Key / Authorization: Bearer.
    # Browsers present the `admina_session` cookie issued by the bundled
    # dashboard at GET /, which holds a signed expiring token — verified by
    # signature, never the raw key.
    # query-param key auth is WebSocket-only (browsers can't set WS headers); HTTP uses the header
    if settings.ADMINA_API_KEY:
        if not verify_credential(
            headers=request.headers,
            query_params={},
            cookies=request.cookies,
        ):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "detail": "Provide your API key via X-API-Key header or Authorization: Bearer <key>",
                },
            )
        return await call_next(request)

    # 3. No API key and no auth providers — block unless explicitly allowed
    if settings.ALLOW_UNAUTHENTICATED:
        return await call_next(request)

    return JSONResponse(
        status_code=401,
        content={
            "error": "Unauthorized",
            "detail": (
                "No authentication configured. "
                "Run 'admina dev' to auto-generate credentials, "
                "or set ADMINA_API_KEY in .env, "
                "or set ALLOW_UNAUTHENTICATED=true for local development."
            ),
        },
    )


# ── Admin API ─────────────────────────────────────────────────
@app.get("/health", tags=["admin"], summary="Liveness probe")
async def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "admina-proxy",
        "version": __version__,
        "engine": engine_status(),
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get(
    "/metrics",
    tags=["admin"],
    summary="Prometheus metrics exposition",
    response_class=Response,
)
async def prometheus_metrics(request: Request) -> Response:
    """Plain-text Prometheus exposition for /metrics scraping.

    Public endpoint (no API key) — Prometheus scraping is normally
    network-restricted at the firewall/pod level, not via auth.
    Producing the format inline avoids a hard dependency on
    prometheus_client (kept lightweight for the OSS distribution).
    """
    state = _get_state(request)
    m = state.metrics
    fw_stats = state.firewall.get_stats() if state.firewall else {}
    lb_stats = state.loop_breaker.get_stats() if state.loop_breaker else {}
    pii_stats = state.pii_redactor.get_stats() if state.pii_redactor else {}
    fbox_stats = state.forensic_box.get_stats() if state.forensic_box else {}
    eng = engine_status()

    lines: list[str] = []

    def _metric(name: str, value, help_text: str, mtype: str = "counter", labels: str = "") -> None:
        lines.append(f"# HELP admina_{name} {help_text}")
        lines.append(f"# TYPE admina_{name} {mtype}")
        suffix = f"{{{labels}}}" if labels else ""
        lines.append(f"admina_{name}{suffix} {value}")

    _metric("requests_total", m.get("requests_total", 0), "Total governance requests processed")
    _metric(
        "requests_blocked_total", m.get("requests_blocked", 0), "Total governance requests blocked"
    )
    _metric(
        "requests_allowed_total",
        m.get("requests_allowed", 0),
        "Total governance requests allowed through",
    )
    _metric(
        "requests_redacted_total",
        m.get("requests_redacted", 0),
        "Total requests in which PII was redacted",
    )
    _metric(
        "avg_latency_ms",
        round(m.get("avg_latency_ms", 0.0), 2),
        "Rolling average pipeline latency in milliseconds",
        "gauge",
    )

    # Firewall pattern hits, broken down per category
    for cat, count in (fw_stats.get("detections_by_type") or {}).items():
        safe = "".join(c if c.isalnum() or c == "_" else "_" for c in cat)
        _metric(
            "firewall_detections_total",
            count,
            "Firewall pattern detections per category",
            labels=f'category="{safe}"',
        )
    _metric(
        "firewall_total_checked", fw_stats.get("total_checked", 0), "Firewall total inputs scanned"
    )
    _metric(
        "firewall_total_blocked", fw_stats.get("total_blocked", 0), "Firewall total inputs blocked"
    )

    _metric(
        "loop_breaker_total_blocked", lb_stats.get("total_blocked", 0), "Loop breaker activations"
    )
    _metric(
        "loop_breaker_active_sessions",
        lb_stats.get("active_sessions", 0),
        "Loop breaker sessions currently tracked",
        "gauge",
    )

    _metric("pii_total_redacted", pii_stats.get("total_redacted", 0), "Total PII entities redacted")

    if fbox_stats:
        _metric(
            "forensic_record_count",
            fbox_stats.get("record_count", 0),
            "Forensic chain length (records appended)",
            "gauge",
        )

    # Engine info as a labelled gauge with constant value 1
    engine_name = eng.get("engine", "unknown")
    rust_avail = "yes" if eng.get("rust_available") else "no"
    lines.append("# HELP admina_engine_info Static info about the running engine")
    lines.append("# TYPE admina_engine_info gauge")
    lines.append(
        f'admina_engine_info{{engine="{engine_name}",rust_available="{rust_avail}",'
        f'version="{__version__}"}} 1'
    )

    body = "\n".join(lines) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/api/stats", tags=["admin"], summary="Proxy and engine statistics")
async def get_stats(request: Request) -> dict[str, Any]:
    state = _get_state(request)
    return {
        "proxy": state.metrics,
        "engine": engine_status(),
        "firewall": state.firewall.get_stats(),
        "loop_breaker": state.loop_breaker.get_stats(),
        "pii_redactor": state.pii_redactor.get_stats(),
        "forensic_blackbox": (state.forensic_box.get_stats() if state.forensic_box else {}),
        "compliance": state.compliance.get_stats(),
        "routing": (state.router.get_stats() if state.router.is_multi_upstream else {}),
    }


@app.get("/api/events", tags=["admin"], summary="Recent governance events")
async def get_events(request: Request, limit: int = 50) -> dict[str, Any]:
    """Retrieve recent governance events from ClickHouse."""
    state = _get_state(request)
    if not state.clickhouse:
        return {"events": [], "error": "ClickHouse not available"}
    _validate_identifier(settings.CLICKHOUSE_DB, "CLICKHOUSE_DB")
    limit = max(1, min(int(limit), 1000))
    try:
        loop = asyncio.get_running_loop()
        ch = state.clickhouse
        result = await loop.run_in_executor(
            None,
            lambda: ch.query(
                f"SELECT * FROM {settings.CLICKHOUSE_DB}.governance_events "
                f"ORDER BY timestamp DESC LIMIT {limit}"
            ),
        )
        events = [dict(zip(result.column_names, row)) for row in result.result_rows]
        return {"events": events, "count": len(events)}
    except (OSError, clickhouse_connect.driver.exceptions.DatabaseError) as e:
        logger.warning("events query failed: %s", e)
        return {"events": [], "error": "Events query failed"}


# ── EU AI Act API ────────────────────────────────────────────
@app.post(
    "/api/compliance/classify",
    tags=["compliance"],
    summary="Classify a system under the EU AI Act risk taxonomy",
)
async def classify_risk(request: Request, body: dict) -> dict[str, Any]:
    state = _get_state(request)
    result = state.compliance.classify_risk(
        system_description=body.get("description", ""),
        use_case=body.get("use_case", ""),
        data_types=body.get("data_types", []),
    )
    return result


@app.post(
    "/api/compliance/gap-analysis",
    tags=["compliance"],
    summary="Compute the compliance gap report for a risk category",
)
async def gap_analysis(request: Request, body: dict) -> dict[str, Any]:
    state = _get_state(request)
    result = state.compliance.gap_analysis(
        risk_category=body.get("risk_category", "high"),
        current_compliance=body.get("current_compliance", {}),
    )
    return result


@app.post(
    "/api/compliance/report",
    tags=["compliance"],
    summary="Generate a structured EU AI Act compliance report",
)
async def generate_compliance_report(request: Request, body: dict) -> dict[str, Any]:
    state = _get_state(request)
    classification = state.compliance.classify_risk(
        body.get("description", ""),
        body.get("use_case", ""),
        body.get("data_types", []),
    )
    gap_result = state.compliance.gap_analysis(
        classification["risk_category"],
        body.get("current_compliance", {}),
    )
    report = state.compliance.generate_report(
        body.get("system_name", "Unknown System"),
        classification,
        gap_result,
    )
    return report


# ── NIS2 API ────────────────────────────────────────────────
@app.get(
    "/api/compliance/nis2/areas",
    tags=["compliance"],
    summary="List NIS2 Art. 21 measure areas and their controls",
)
async def nis2_areas(request: Request) -> dict[str, Any]:
    state = _get_state(request)
    return {"areas": state.nis2.list_areas(), "stats": state.nis2.get_stats()}


@app.post(
    "/api/compliance/nis2/assess",
    tags=["compliance"],
    summary="Run NIS2 self-assessment (returns coverage score and gaps)",
)
async def nis2_assess(request: Request, body: dict) -> dict[str, Any]:
    state = _get_state(request)
    return state.nis2.assess(current_compliance=body.get("current_compliance", {}))


# ── GDPR API ────────────────────────────────────────────────
@app.get(
    "/api/compliance/gdpr/records",
    tags=["compliance"],
    summary="List Art. 30 records of processing activities",
)
async def gdpr_list_records(request: Request) -> dict[str, Any]:
    state = _get_state(request)
    return {"records": state.gdpr.list(), "stats": state.gdpr.get_stats()}


@app.post(
    "/api/compliance/gdpr/records",
    tags=["compliance"],
    summary="Create a new Art. 30 record",
)
async def gdpr_create_record(request: Request, body: dict) -> dict[str, Any]:
    state = _get_state(request)
    return state.gdpr.create(payload=body)


@app.get(
    "/api/compliance/gdpr/records/{activity_id}",
    tags=["compliance"],
    summary="Get a single Art. 30 record",
)
async def gdpr_get_record(request: Request, activity_id: str) -> dict[str, Any]:
    state = _get_state(request)
    rec = state.gdpr.get(activity_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="record not found")
    return rec


@app.put(
    "/api/compliance/gdpr/records/{activity_id}",
    tags=["compliance"],
    summary="Update an Art. 30 record",
)
async def gdpr_update_record(request: Request, activity_id: str, body: dict) -> dict[str, Any]:
    state = _get_state(request)
    rec = state.gdpr.update(activity_id, body)
    if rec is None:
        raise HTTPException(status_code=404, detail="record not found")
    return rec


@app.delete(
    "/api/compliance/gdpr/records/{activity_id}",
    tags=["compliance"],
    summary="Delete an Art. 30 record",
)
async def gdpr_delete_record(request: Request, activity_id: str) -> dict[str, Any]:
    state = _get_state(request)
    if not state.gdpr.delete(activity_id):
        raise HTTPException(status_code=404, detail="record not found")
    return {"deleted": True, "id": activity_id}


@app.post(
    "/api/compliance/gdpr/dpia/template",
    tags=["compliance"],
    summary="Render an Art. 35 DPIA scaffold (Markdown) from operator-supplied facts",
    response_class=Response,
)
async def gdpr_dpia_template(body: dict) -> Response:
    from admina.domains.compliance.gdpr import render_dpia_template

    md = render_dpia_template(body)
    return Response(content=md, media_type="text/markdown; charset=utf-8")


# ── Consolidated compliance report ──────────────────────────
@app.get(
    "/api/compliance/report",
    tags=["compliance"],
    summary="Consolidated compliance snapshot (EU AI Act + NIS2 + GDPR + cross-matrix)",
)
async def consolidated_compliance_report(
    request: Request,
    format: str = "json",
) -> Any:
    """Consolidated report.

    Aggregates the latest snapshot from the three compliance domains
    plus the proxy's runtime stats. Three serialisations are supported:
    JSON (default, machine-readable), CSV (one section per file would
    be cleaner — for now it's a flat key/value listing), and Markdown
    (human-readable, ready to paste into a wiki or email).
    """
    from admina.domains.compliance.cross_regulation import (
        coverage_summary as cross_summary,
    )

    state = _get_state(request)

    # Latest snapshots — defensive: each module may not have any data yet
    eu_latest = state.compliance.assessments[-1] if state.compliance.assessments else None
    nis2_latest = state.nis2.assessments[-1] if state.nis2.assessments else None

    snapshot: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "admina_version": __version__,
        "engine": engine_status(),
        "proxy_metrics": state.metrics,
        "eu_ai_act": {
            "stats": state.compliance.get_stats(),
            "latest_assessment": eu_latest,
        },
        "nis2": {
            "stats": state.nis2.get_stats(),
            "latest_assessment": nis2_latest,
        },
        "gdpr": {
            "stats": state.gdpr.get_stats(),
            "records": state.gdpr.list(),
        },
        "cross_regulation": cross_summary(),
        "forensic_blackbox": (state.forensic_box.get_stats() if state.forensic_box else {}),
    }

    fmt = (format or "json").lower()
    if fmt == "json":
        return snapshot

    if fmt == "csv":
        import csv as _csv
        import io as _io

        buf = _io.StringIO()
        w = _csv.writer(buf)
        w.writerow(["section", "key", "value"])

        def _emit(section: str, obj: Any, prefix: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    _emit(section, v, f"{prefix}.{k}" if prefix else k)
            elif isinstance(obj, list):
                w.writerow([section, prefix, f"<list:{len(obj)} items>"])
            else:
                w.writerow([section, prefix, str(obj)])

        for section in (
            "eu_ai_act",
            "nis2",
            "gdpr",
            "cross_regulation",
            "forensic_blackbox",
            "proxy_metrics",
            "engine",
        ):
            _emit(section, snapshot.get(section, {}))
        return Response(content=buf.getvalue(), media_type="text/csv")

    if fmt == "markdown":
        lines = [
            "# Admina compliance report",
            "",
            f"_Generated_: {snapshot['generated_at']}",
            f"_Admina version_: {snapshot['admina_version']}",
            "",
            "## Proxy traffic",
            f"- Total requests: **{snapshot['proxy_metrics'].get('requests_total', 0)}**",
            f"- Blocked: **{snapshot['proxy_metrics'].get('requests_blocked', 0)}**",
            f"- PII redacted: **{snapshot['proxy_metrics'].get('requests_redacted', 0)}**",
            f"- Avg latency (ms): {snapshot['proxy_metrics'].get('avg_latency_ms', 0)}",
            "",
            "## EU AI Act",
        ]
        eu_stats = snapshot["eu_ai_act"]["stats"]
        lines.append(f"- Assessments performed: {eu_stats.get('total_assessments', 0)}")
        if eu_latest:
            lines.append(f"- Latest score: **{eu_latest.get('compliance_score', 0)}%**")
            lines.append(f"- Open gaps: {len(eu_latest.get('gaps', []))}")
        lines += ["", "## NIS2"]
        nis2_stats = snapshot["nis2"]["stats"]
        lines.append(f"- Areas tracked: {nis2_stats.get('areas_count', 0)}")
        lines.append(f"- Total controls: {nis2_stats.get('controls_count', 0)}")
        if nis2_latest:
            lines.append(f"- Latest coverage: **{nis2_latest.get('coverage_score', 0)}%**")
            lines.append(f"- Open gaps: {len(nis2_latest.get('gaps', []))}")
        lines += ["", "## GDPR"]
        gdpr_stats = snapshot["gdpr"]["stats"]
        lines.append(f"- Processing activities recorded: {gdpr_stats.get('total_activities', 0)}")
        lines.append(
            f"- With third-country transfers: {gdpr_stats.get('with_third_country_transfers', 0)}"
        )
        lines += ["", "## Cross-regulation coverage"]
        cr = snapshot["cross_regulation"]
        lines.append(f"- Controls in matrix: {cr['total_controls']}")
        for reg, n in cr["controls_per_regulation"].items():
            lines.append(f"  - {reg}: {n} controls")
        lines += ["", "## Forensic"]
        fb = snapshot["forensic_blackbox"]
        if fb:
            lines.append(f"- Records on chain: **{fb.get('record_count', 0)}**")
            lines.append(f"- Chain head: `{(fb.get('chain_head') or 'GENESIS')[:16]}...`")
        else:
            lines.append("- Forensic backend not configured")
        lines += [
            "",
            "---",
            "*OSS-tier report. PDF / Excel / branded reporting are not "
            "included in admina-framework.*",
        ]
        return Response(
            content="\n".join(lines) + "\n",
            media_type="text/markdown; charset=utf-8",
        )

    raise HTTPException(
        status_code=400,
        detail=f"unknown format {format!r}: use json | csv | markdown",
    )


# ── Cross-regulation matrix API ─────────────────────────────
@app.get(
    "/api/compliance/matrix",
    tags=["compliance"],
    summary="Cross-regulation control matrix (AI Act ↔ NIS2 ↔ GDPR)",
)
async def compliance_matrix(format: str = "json") -> Any:
    from admina.domains.compliance.cross_regulation import (
        CROSS_REGULATION_MATRIX,
        coverage_summary,
        to_markdown,
    )

    if format == "markdown":
        return Response(
            content=to_markdown(),
            media_type="text/markdown; charset=utf-8",
        )
    return {
        "summary": coverage_summary(),
        "controls": CROSS_REGULATION_MATRIX,
    }


# ── MCP Proxy Endpoint ──────────────────────────────────────
@app.post("/mcp", tags=["proxy"], summary="MCP JSON-RPC governance proxy")
@app.post("/mcp/{path:path}", tags=["proxy"], include_in_schema=False)
async def mcp_proxy(request: Request, path: str = "") -> JSONResponse:
    """
    Main MCP proxy endpoint.
    All agent traffic flows through here for governance inspection.
    """
    state = _get_state(request)
    start_time = time.perf_counter()
    # Sanitize header values: strip CRLF (Redis key injection) and cap length
    session_id = re.sub(r"[\r\n]", "", request.headers.get("X-Session-Id", "default"))[:128]
    agent_id = re.sub(r"[\r\n]", "", request.headers.get("X-Agent-Id", "unknown"))[:128]

    state.inc_metric("requests_total")

    # ─── Rate Limiting (Redis) ─────────────────────────────
    if state.redis and settings.RATE_LIMIT_MAX_REQUESTS > 0:
        # Per-session rate limit
        rl_key = f"admina:ratelimit:{session_id}"
        try:
            count = await state.redis.incr(rl_key)
            if count == 1:
                await state.redis.expire(rl_key, settings.RATE_LIMIT_WINDOW_SECONDS)
            if count > settings.RATE_LIMIT_MAX_REQUESTS:
                state.inc_metric("requests_blocked")
                return JSONResponse(
                    status_code=429,
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32000,
                            "message": "Rate limit exceeded",
                            "data": {
                                "session_id": session_id,
                                "limit": settings.RATE_LIMIT_MAX_REQUESTS,
                                "window_seconds": settings.RATE_LIMIT_WINDOW_SECONDS,
                            },
                        },
                    },
                )
        except (OSError, aioredis.RedisError) as e:
            logger.warning("Rate limit check failed: %s", e)

        # Per-IP rate limit (non-bypassable fallback)
        client_ip = request.client.host if request.client else "unknown"
        rl_ip_key = f"admina:ratelimit:ip:{client_ip}"
        try:
            ip_count = await state.redis.incr(rl_ip_key)
            if ip_count == 1:
                await state.redis.expire(rl_ip_key, settings.RATE_LIMIT_WINDOW_SECONDS)
            if ip_count > settings.RATE_LIMIT_MAX_REQUESTS * settings.RATE_LIMIT_IP_MULTIPLIER:
                state.inc_metric("requests_blocked")
                return JSONResponse(
                    status_code=429,
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32000,
                            "message": "Rate limit exceeded (IP)",
                            "data": {
                                "limit": settings.RATE_LIMIT_MAX_REQUESTS
                                * settings.RATE_LIMIT_IP_MULTIPLIER,
                                "window_seconds": settings.RATE_LIMIT_WINDOW_SECONDS,
                            },
                        },
                    },
                )
        except (OSError, aioredis.RedisError) as e:
            logger.warning("IP rate limit check failed: %s", e)

    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    gov_request = mcp_transport.parse_request(body, session_id=session_id, agent_id=agent_id)
    event_id = gov_request.request_id
    method = gov_request.method
    params = gov_request.metadata.get("params", {})
    content_str = gov_request.content

    # ─── Token size guard ─────────────────────────────────────
    if settings.MAX_REQUEST_TOKENS > 0 and len(content_str) > settings.MAX_REQUEST_TOKENS:
        state.inc_metric("requests_blocked")
        return JSONResponse(
            status_code=413,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32000,
                    "message": "Request too large",
                    "data": {
                        "content_length": len(content_str),
                        "max_tokens": settings.MAX_REQUEST_TOKENS,
                    },
                },
            },
        )

    # ─── Governance Pipeline ─────────────────────────────────
    pipeline_result = await run_pipeline(
        body=body,
        content_str=content_str,
        session_id=session_id,
        agent_id=agent_id,
        request_id=event_id,
        params=params,
        firewall=state.firewall,
        pii_redactor=state.pii_redactor,
        loop_breaker=state.loop_breaker,
        governance_guards=state.governance_guards,
        injection_enabled=settings.INJECTION_FAST_PATH_ENABLED,
        pii_enabled=settings.PII_REDACTION_ENABLED,
        mode=settings.GOVERNANCE_MODE,
    )

    persisted_details = build_governance_details(pipeline_result)
    redacted_body = pipeline_result.redacted_body
    governance_latency = pipeline_result.latency_ms
    gov_response = pipeline_result.gov_response
    action = pipeline_result.action
    risk_level = pipeline_result.risk_level

    if pipeline_result.checks.get("pii_redaction", {}).get("count", 0) > 0:
        state.inc_metric("requests_redacted")
    _spawn(
        governance_bus.emit(
            BusGovernanceEvent(
                event_type=EventType.GOVERNANCE_DECISION,
                session_id=session_id,
                action=gov_response.action,
                risk_level=gov_response.risk_level,
                domain="proxy",
                metadata=gov_response.to_dict(),
            )
        )
    )

    # ── Fire alerts on block/circuit-break (non-blocking) ─────
    if action in (GovernanceAction.BLOCK, GovernanceAction.CIRCUIT_BREAK) and state.alert_channels:
        _alert = {
            "level": gov_response.risk_level,
            "domain": gov_response.domain,
            "summary": f"{gov_response.action} — {method} from agent {agent_id}",
            "details": {k: safe_serialize(v) for k, v in pipeline_result.checks.items()},
            "event_id": event_id,
            "session_id": session_id,
        }
        _spawn(_fire_alerts(state.alert_channels, _alert))

    # ─── Forensic Black Box (non-blocking) ─────────────────────
    forensic_record = None
    if state.forensic_box:
        _loop = asyncio.get_running_loop()
        forensic_record = await _loop.run_in_executor(
            None,
            lambda: state.forensic_box.record(
                {
                    "event_id": event_id,
                    "event_type": EventType.MCP_REQUEST,
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "method": method,
                    "action": action,
                    "risk_level": risk_level,
                    "governance_latency_ms": round(governance_latency, 2),
                    "checks": {k: safe_serialize(v) for k, v in pipeline_result.checks.items()},
                }
            ),
        )

    # ─── Store to ClickHouse (fire-and-forget) ─────────────────
    _spawn(
        _store_event_async(
            state.clickhouse,
            GovernanceEvent(
                event_id=event_id,
                timestamp=datetime.now(UTC).isoformat(),
                event_type=EventType.MCP_REQUEST,
                agent_id=agent_id,
                session_id=session_id,
                method=method,
                tool_name=params.get("name", "") if isinstance(params, dict) else "",
                action=action,
                risk_level=risk_level,
                details=persisted_details,
                latency_ms=governance_latency,
                request_hash=hashlib.sha256(content_str.encode()).hexdigest()[:32],
            ),
        )
    )

    # ─── Respond based on governance decision ─────────────────
    if action == GovernanceAction.BLOCK:
        state.inc_metric("requests_blocked")
        if state.router.is_multi_upstream and path.startswith("route/"):
            state.router.record_block(path.removeprefix("route/").split("/")[0])
        logger.warning(
            "[BLOCKED] request %s: %s (risk=%s)",
            event_id,
            method,
            risk_level,
        )
        return JSONResponse(
            status_code=403,
            content=mcp_transport.format_block_response(gov_response, body),
        )

    if action == GovernanceAction.CIRCUIT_BREAK:
        state.inc_metric("requests_blocked")
        if state.router.is_multi_upstream and path.startswith("route/"):
            state.router.record_block(path.removeprefix("route/").split("/")[0])
        logger.warning("CIRCUIT BREAK for session %s: reasoning loop detected", session_id)
        return JSONResponse(
            status_code=429,
            content=mcp_transport.format_circuit_break_response(gov_response, body),
        )

    # ─── Forward to upstream MCP server ───────────────────────
    state.inc_metric("requests_allowed")
    try:
        server_name = None
        if path.startswith("route/"):
            server_name = path.removeprefix("route/").split("/")[0]

        # Tool-based routing: resolve server by tool name if in multi-upstream mode
        if not server_name and state.router.is_multi_upstream:
            tool_name = params.get("name", "") if isinstance(params, dict) else ""
            if tool_name:
                tool_route = state.router.resolve_by_tool(tool_name)
                if tool_route:
                    server_name = tool_route.name

        if server_name and state.router.is_multi_upstream:
            upstream_url = state.router.get_upstream_url(server_name)
            extra_headers = state.router.get_upstream_headers(server_name)
            logger.debug("Routing to server '%s' -> %s", server_name, upstream_url)
        else:
            upstream_url = f"{settings.UPSTREAM_MCP_URL}/mcp"
            if path and not path.startswith("route/"):
                upstream_url = f"{settings.UPSTREAM_MCP_URL}/mcp/{path}"
            extra_headers = {}

        upstream_response = await state.http_client.post(
            upstream_url,
            json=redacted_body,
            headers={
                "X-Session-Id": session_id,
                "X-Agent-Id": agent_id,
                "X-Admina-Event-Id": event_id,
                **extra_headers,
            },
        )

        response_data = upstream_response.json()

        # Redact PII from response too (bidirectional — dict-shaped results included)
        if settings.PII_REDACTION_ENABLED and "result" in response_data:
            response_data["result"], _resp_pii_count = redact_response_result(
                response_data["result"], state.pii_redactor
            )

        # ─── Governance Guards: inspect response ──────────────
        if state.governance_guards:
            resp_payload = {"content": json.dumps(response_data, default=str)}
            for guard in state.governance_guards:
                try:
                    guard_result = await guard.inspect_response(resp_payload)
                    if guard_result.get("action") in ("BLOCK", "REDACT"):
                        state.inc_metric("requests_blocked")
                        logger.warning(
                            "Guard %r blocked response for event %s",
                            guard.name,
                            event_id,
                        )
                        return JSONResponse(
                            status_code=403,
                            content=mcp_transport.format_block_response(
                                gov_response,
                                body,
                            ),
                        )
                except (ValueError, RuntimeError, OSError, TypeError) as exc:
                    logger.error(
                        "Guard %r failed its contract on response inspection and was skipped: %s",
                        guard.name,
                        exc,
                        exc_info=True,
                    )
                    # follow-up: optional fail-closed mode
                    # Response guard errors are not collected into pipeline_result.checks
                    # (that result is already built before this path runs); the ERROR log
                    # with exc_info is the audit trail for response-side contract failures.

        total_latency = (time.perf_counter() - start_time) * 1000
        state.update_avg_latency(total_latency)

        headers = mcp_transport.format_allow_headers(
            gov_response,
            forensic_hash=(
                forensic_record.get("record_hash", "")[:16] if forensic_record else None
            ),
        )

        return JSONResponse(content=response_data, headers=headers)

    except httpx.ConnectError:
        logger.error("Upstream MCP server unreachable: %s", settings.UPSTREAM_MCP_URL)
        return JSONResponse(
            status_code=502,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32603,
                    "message": "Upstream MCP server unreachable",
                    "data": {"event_id": event_id},
                },
            },
        )
    except (httpx.HTTPError, OSError, ValueError, RuntimeError) as e:
        logger.error("Proxy error: %s", e)
        return JSONResponse(
            status_code=500,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32603,
                    "message": "Internal proxy error",
                    "data": {"event_id": event_id},
                },
            },
        )


# ── Helpers ──────────────────────────────────────────────────


def _store_event_sync(clickhouse_client, event: GovernanceEvent):
    """Store governance event to ClickHouse (synchronous — run in thread pool)."""
    if not clickhouse_client:
        return
    _validate_identifier(settings.CLICKHOUSE_DB, "CLICKHOUSE_DB")
    try:
        clickhouse_client.insert(
            f"{settings.CLICKHOUSE_DB}.governance_events",
            [
                [
                    event.event_id,
                    datetime.fromisoformat(event.timestamp),
                    (
                        event.event_type.value
                        if hasattr(event.event_type, "value")
                        else event.event_type
                    ),
                    event.agent_id,
                    event.session_id,
                    event.method,
                    event.tool_name,
                    (event.action.value if hasattr(event.action, "value") else event.action),
                    (
                        event.risk_level.value
                        if hasattr(event.risk_level, "value")
                        else event.risk_level
                    ),
                    json.dumps(event.details, default=str),
                    event.latency_ms,
                    event.request_hash,
                    event.response_hash,
                ]
            ],
            column_names=[
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
            ],
        )
    except (OSError, clickhouse_connect.driver.exceptions.DatabaseError) as e:
        logger.warning("Failed to store event: %s", e)


async def _fire_alerts(channels: list, alert: dict) -> None:
    """Dispatch a governance alert to all registered alert channels."""
    for ch in channels:
        try:
            await ch.send_alert(alert)
        except (OSError, ValueError, RuntimeError) as exc:
            logger.warning("Alert channel %r failed: %s", getattr(ch, "channel_name", "?"), exc)


async def _store_event_async(clickhouse_client, event: GovernanceEvent):
    """Non-blocking wrapper: runs ClickHouse insert in the thread pool."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _store_event_sync, clickhouse_client, event)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
