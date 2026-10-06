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

"""ADMINA_ENABLED_SURFACES switches the proxy's surfaces on and off.

Surfaces: ``gateway`` (/v1/*), ``mcp`` (/mcp, /mcp/*), ``integration``
(/api/v1/*), ``compliance`` (/api/compliance/*) and ``dashboard``
(/api/dashboard/*, /api/stats, /api/events, the live feed and the dashboard
shell). Unset = all of them. A disabled surface answers 404 before
authentication and its routes are not mounted; /health and /metrics are
always served.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytest.importorskip("fastapi")

from _proxy_app import API_KEY, CHAT, isolate, serve, subprocess_env, with_key
from pydantic import ValidationError

from admina.proxy.config import Settings
from admina.proxy.surfaces import SURFACES, parse_surfaces, surface_of

GATEWAY = [
    CHAT,
    {"method": "GET", "url": "/v1/models"},
    {"method": "GET", "url": "/v1/admina/ruleset"},
]

OTHER_SURFACES = [
    {"method": "POST", "url": "/mcp", "json": {"jsonrpc": "2.0", "id": 1, "method": "ping"}},
    {"method": "POST", "url": "/mcp/tools", "json": {"jsonrpc": "2.0", "id": 1, "method": "ping"}},
    {"method": "POST", "url": "/api/v1/validate", "json": {"content": "hello"}},
    {"method": "POST", "url": "/api/v1/audit", "json": {"action": "x"}},
    {"method": "GET", "url": "/api/v1/forensic/verify"},
    {"method": "POST", "url": "/api/compliance/classify", "json": {"description": "x"}},
    {"method": "GET", "url": "/api/compliance/matrix"},
    {"method": "GET", "url": "/api/dashboard/score"},
    {"method": "GET", "url": "/api/dashboard/session"},
    {"method": "GET", "url": "/api/stats"},
    {"method": "GET", "url": "/api/events"},
    {"method": "GET", "url": "/"},
    {"method": "GET", "url": "/heimdall.png"},
    {"method": "GET", "url": "/vendor/alpinejs.min.js"},
]

ALWAYS_ON = [{"method": "GET", "url": "/health"}, {"method": "GET", "url": "/metrics"}]


@pytest.fixture
def proxy(monkeypatch):
    from admina.proxy import main as proxy_main

    def start(surfaces: str | None) -> None:
        monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
        monkeypatch.setattr(proxy_main.settings, "ADMINA_DASHBOARD_ENABLED", True)
        if surfaces is not None:
            monkeypatch.setattr(proxy_main.settings, "ADMINA_ENABLED_SURFACES", surfaces)
        isolate(monkeypatch)

    return start


# ── Only the gateway ──────────────────────────────────────────


def test_gateway_only_serves_the_gateway(proxy):
    proxy("gateway")
    responses, _ = serve([with_key(r) for r in GATEWAY])
    assert [r.status_code for r in responses] == [200, 200, 200]
    assert responses[0].json()["choices"][0]["message"]["content"] == "hi"
    assert responses[1].json()["data"] == [{"id": "m1"}]


@pytest.mark.parametrize("keyed", [False, True], ids=["without_key", "with_key"])
def test_gateway_only_answers_404_on_every_other_surface(proxy, keyed):
    proxy("gateway")
    requests = [with_key(r) if keyed else r for r in OTHER_SURFACES]
    responses, _ = serve(requests)
    assert {r["url"]: resp.status_code for r, resp in zip(requests, responses)} == {
        r["url"]: 404 for r in requests
    }


def test_gateway_only_still_serves_health_and_metrics_without_a_key(proxy):
    proxy("gateway")
    responses, _ = serve(ALWAYS_ON)
    assert [r.status_code for r in responses] == [200, 200]


def test_gateway_disabled_answers_404_on_v1(proxy):
    proxy("mcp,integration")
    responses, _ = serve([with_key(r) for r in GATEWAY] + GATEWAY)
    assert [r.status_code for r in responses] == [404] * 6


# ── The dashboard in the OISG score ───────────────────────────


@pytest.mark.parametrize(
    ("surfaces", "dashboard_enabled", "served"),
    [
        ("", True, True),
        ("gateway,mcp,integration,compliance", True, False),
        ("dashboard", True, True),
        ("", False, False),
    ],
)
def test_the_dashboard_is_enabled_by_both_switches(
    monkeypatch, surfaces, dashboard_enabled, served
):
    """ADMINA_ENABLED_SURFACES and ADMINA_DASHBOARD_ENABLED both decide
    whether the proxy serves the dashboard, and so OISG G4."""
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_ENABLED_SURFACES", surfaces)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_DASHBOARD_ENABLED", dashboard_enabled)
    assert proxy_main._dashboard_enabled() is served


def test_oisg_g4_sees_admina_dashboard_enabled(proxy, monkeypatch):
    """With the dashboard off, the /api/dashboard/* API is still served to
    API-key clients, and its OISG G4 reports no dashboard."""
    from admina.proxy import main as proxy_main

    proxy(None)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_DASHBOARD_ENABLED", False)

    def no_otel(state):
        state.otel_exporter = None

    request = with_key({"method": "GET", "url": "/api/dashboard/oisg"})
    responses, _ = serve([request], prepare=no_otel)
    assert responses[0].status_code == 200
    criteria = responses[0].json()["pillars"]["governed"]["criteria"]
    g4 = next(c for c in criteria if c["id"] == "g4")
    assert g4["satisfied"] is False
    assert "no dashboard" in g4["reason"]


# ── Default: every surface, as in 0.12 ────────────────────────


@pytest.mark.parametrize("value", [None, "", " , "], ids=["unset", "empty", "blank_items"])
def test_default_serves_every_surface(proxy, value):
    proxy(value)
    requests = [with_key(r) for r in GATEWAY + OTHER_SURFACES] + ALWAYS_ON
    responses, _ = serve(requests)
    codes = {r["url"]: resp.status_code for r, resp in zip(requests, responses)}
    not_found = {url for url, code in codes.items() if code == 404}
    assert not_found == set(), codes
    assert codes["/v1/chat/completions"] == 200
    assert codes["/api/v1/validate"] == 200
    assert codes["/api/compliance/classify"] == 200
    assert codes["/api/stats"] == 200
    assert codes["/"] == 200


def test_default_still_requires_the_key_elsewhere(proxy):
    proxy(None)
    responses, _ = serve([OTHER_SURFACES[0], OTHER_SURFACES[2], CHAT])
    assert [r.status_code for r in responses] == [401, 401, 401]


# ── Background work of disabled surfaces ──────────────────────


def _engines(state) -> dict:
    return {
        "loop_breaker": state.loop_breaker is not None,
        "coordination": state.coordination is not None,
        "quarantine_refresh": state.quarantine_refresh is not None,
        "pipeline_executor": state.pipeline_executor is not None,
    }


def test_gateway_only_starts_no_loop_breaker_and_no_coordination(proxy):
    proxy("gateway")
    _, running = serve([], inspect=_engines)
    assert running == {
        "loop_breaker": False,
        "coordination": False,
        "quarantine_refresh": False,
        "pipeline_executor": True,
    }


def test_default_starts_the_loop_breaker_and_the_coordination_loop(proxy):
    proxy(None)
    _, running = serve([], inspect=_engines)
    assert running == {
        "loop_breaker": True,
        "coordination": True,
        "quarantine_refresh": True,
        "pipeline_executor": True,
    }


@pytest.mark.parametrize("surfaces", ["integration", "mcp"])
def test_surfaces_that_run_the_loop_breaker_build_it(proxy, surfaces):
    proxy(surfaces)
    _, running = serve([], inspect=_engines)
    assert running["loop_breaker"] is True
    assert running["coordination"] is (surfaces == "mcp")
    assert running["pipeline_executor"] is False


# ── Routes of disabled surfaces are not mounted ───────────────

_ROUTES = (
    "import json; from admina.proxy.main import app; "
    "print(json.dumps({'routes': sorted({getattr(r, 'path', '') for r in app.routes}), "
    "'openapi': sorted(app.openapi()['paths'])}))"
)


def _mounted(surfaces: str | None) -> dict:
    env = subprocess_env("ADMINA_ENABLED_SURFACES", REDIS_URL="", CLICKHOUSE_HOST="")
    if surfaces is not None:
        env["ADMINA_ENABLED_SURFACES"] = surfaces
    proc = subprocess.run(
        [sys.executable, "-c", _ROUTES], env=env, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_gateway_only_mounts_no_other_route():
    mounted = _mounted("gateway")
    other = [
        p for p in mounted["routes"] + mounted["openapi"] if surface_of(p) not in (None, "gateway")
    ]
    assert other == []
    assert "/" not in mounted["routes"]
    assert {"/v1/chat/completions", "/v1/models", "/health", "/metrics"} <= set(mounted["routes"])
    assert "/api/dashboard/live" not in mounted["routes"]
    assert {"/v1/chat/completions", "/health", "/metrics"} <= set(mounted["openapi"])


def test_default_mounts_every_surface():
    mounted = _mounted(None)
    assert {surface_of(p) for p in mounted["routes"]} >= set(SURFACES)
    assert "/api/dashboard/live" in mounted["routes"]


# ── The setting ───────────────────────────────────────────────


def test_setting_is_normalised(monkeypatch):
    monkeypatch.setenv("ADMINA_ENABLED_SURFACES", " Dashboard , gateway,,")
    assert Settings(_env_file=None).ADMINA_ENABLED_SURFACES == "gateway,dashboard"


def test_unknown_surface_is_a_settings_error(monkeypatch):
    monkeypatch.setenv("ADMINA_ENABLED_SURFACES", "gateway,admin")
    with pytest.raises(ValidationError, match="admin"):
        Settings(_env_file=None)


def test_unknown_surface_stops_the_proxy():
    env = subprocess_env(REDIS_URL="", CLICKHOUSE_HOST="", ADMINA_ENABLED_SURFACES="x")
    proc = subprocess.run(
        [sys.executable, "-c", "import admina.proxy.main"],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode != 0
    assert "ADMINA_ENABLED_SURFACES" in proc.stderr


def test_parse_surfaces():
    assert parse_surfaces("") == SURFACES
    assert parse_surfaces("mcp,gateway") == ("gateway", "mcp")
    with pytest.raises(ValueError, match="unknown"):
        parse_surfaces("gateway,unknown")


@pytest.mark.parametrize(
    ("path", "surface"),
    [
        ("/v1", "gateway"),
        ("/v1/chat/completions", "gateway"),
        ("/v1x", None),
        ("/mcp", "mcp"),
        ("/mcp/route/a/b", "mcp"),
        ("/mcpx", None),
        ("/api/v1/validate", "integration"),
        ("/api/compliance/gdpr/records/1", "compliance"),
        ("/api/dashboard/live", "dashboard"),
        ("/api/stats", "dashboard"),
        ("/api/events", "dashboard"),
        ("/", "dashboard"),
        ("/heimdall.png", "dashboard"),
        ("/vendor/x.js", "dashboard"),
        ("/health", None),
        ("/metrics", None),
        ("/docs", None),
        ("/openapi.json", None),
    ],
)
def test_surface_of(path, surface):
    assert surface_of(path) == surface
