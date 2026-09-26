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

"""Dashboard browser sessions on the real proxy app.

The bundled dashboard is served at ``GET /``. Serving it must never hand out
an authorized session: a browser session is created only by presenting the
API key to ``POST /api/dashboard/session``, and it only authorizes read-only
requests to the dashboard API. Every other protected surface (MCP proxy,
OpenAI-compatible gateway, integration and compliance APIs) requires the API
key itself.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time

import httpx
import pytest

pytest.importorskip("fastapi")

_KEY = "dashboard-session-test-key-0123456789"
_COOKIE = "admina_dashboard_session"


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low", "patterns": []}

    def get_stats(self) -> dict:
        return {}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoop:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}

    def get_stats(self) -> dict:
        return {}


class _FakeHTTP:
    async def post(self, url, **kw):
        return httpx.Response(
            200,
            content=json.dumps(
                {
                    "id": "c1",
                    "object": "chat.completion",
                    "model": "llama3",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "hi"},
                            "finish_reason": "stop",
                        }
                    ],
                }
            ).encode(),
            headers={"content-type": "application/json"},
        )

    async def get(self, url, **kw):
        return httpx.Response(200, json={"object": "list", "data": []})


def _providers(mode: str) -> list:
    """Auth providers loaded in the proxy for each deployment shape.

    ``fallback``: no plugin provider — the static ADMINA_API_KEY check runs.
    ``apikey-plugin``: the built-in API-key provider is loaded (the default
    when ADMINA_API_KEY is set in the environment).
    """
    if mode == "apikey-plugin":
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        return [APIKeyAuthProvider(api_key=_KEY)]
    return []


@pytest.fixture(params=["fallback", "apikey-plugin"])
def proxy_app(request, monkeypatch):
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", _KEY)
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", False)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_GATEWAY_UPSTREAM", "http://upstream/v1")
    monkeypatch.setattr(proxy_main.settings, "DASHBOARD_COOKIE_SECURE", False)

    state = ProxyState(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoop(),
        router=MultiUpstreamRouter(default_upstream="http://upstream"),
        http_client=_FakeHTTP(),
        redis=None,
        clickhouse=None,
        forensic_box=None,
        governance_guards=[],
        alert_channels=[],
        auth_providers=_providers(request.param),
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    return proxy_main.app


def _run(app, steps, *, base_url: str = "http://test"):
    """Run ``steps(client)`` against *app* with a cookie-keeping client."""

    async def go():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
            return await steps(client)

    return asyncio.run(go())


def _set_cookie(resp: httpx.Response, name: str) -> str | None:
    """Return the raw Set-Cookie header for cookie *name*, if any."""
    for header in resp.headers.get_list("set-cookie"):
        if header.split("=", 1)[0].strip() == name:
            return header
    return None


def _attrs(set_cookie: str) -> dict[str, str]:
    """Parse the attributes of a Set-Cookie header (lower-cased keys)."""
    out: dict[str, str] = {}
    for part in set_cookie.split(";")[1:]:
        k, _, v = part.strip().partition("=")
        out[k.lower()] = v
    return out


def _login(c, key: str = _KEY):
    return c.post("/api/dashboard/session", headers={"X-API-Key": key})


_CHAT = {"model": "llama3", "messages": [{"role": "user", "content": "hi"}]}


# ── GET / never mints an authorized session ──────────────────


def test_root_serves_dashboard_without_setting_a_cookie(proxy_app):
    async def steps(c):
        return await c.get("/")

    resp = _run(proxy_app, steps)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "set-cookie" not in resp.headers


def test_root_refuses_framing_and_caching(proxy_app):
    async def steps(c):
        return await c.get("/")

    resp = _run(proxy_app, steps)
    assert resp.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "no-store" in resp.headers["cache-control"]


def test_cookies_from_root_do_not_authorize_protected_routes(proxy_app):
    async def steps(c):
        await c.get("/")
        return {
            "stats": (await c.get("/api/stats")).status_code,
            "score": (await c.get("/api/dashboard/score")).status_code,
            "gateway": (await c.post("/v1/chat/completions", json=_CHAT)).status_code,
            "validate": (await c.post("/api/v1/validate", json={"content": "hello"})).status_code,
        }

    codes = _run(proxy_app, steps)
    assert codes == {"stats": 401, "score": 401, "gateway": 401, "validate": 401}


def test_session_status_without_credentials_is_401(proxy_app):
    async def steps(c):
        return await c.get("/api/dashboard/session")

    assert _run(proxy_app, steps).status_code == 401


# ── Sign-in: the API key is exchanged for a scoped session ───


def test_login_sets_hardened_session_cookie(proxy_app):
    async def steps(c):
        return await _login(c)

    resp = _run(proxy_app, steps)
    assert resp.status_code == 200
    assert "no-store" in resp.headers["cache-control"]
    body = resp.json()
    assert body["authenticated"] is True
    assert body["expires_at"] > time.time()

    header = _set_cookie(resp, _COOKIE)
    assert header is not None
    attrs = _attrs(header)
    assert "httponly" in attrs
    assert attrs["samesite"].lower() == "strict"
    assert attrs["path"] == "/api/"
    assert int(attrs["max-age"]) == 3600
    # Plain HTTP and DASHBOARD_COOKIE_SECURE off: no Secure flag, or the
    # browser would drop the cookie on a local http:// dashboard.
    assert "secure" not in attrs
    # The cookie carries a derived signature, never the key itself.
    assert _KEY not in header


def test_login_over_https_sets_secure_cookie(proxy_app):
    async def steps(c):
        return await _login(c)

    resp = _run(proxy_app, steps, base_url="https://test")
    assert resp.status_code == 200
    assert "secure" in _attrs(_set_cookie(resp, _COOKIE))


def test_cookie_secure_setting_forces_secure_flag(proxy_app, monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "DASHBOARD_COOKIE_SECURE", True)

    async def steps(c):
        return await _login(c)

    resp = _run(proxy_app, steps)
    assert "secure" in _attrs(_set_cookie(resp, _COOKIE))


def test_login_honours_configured_ttl(proxy_app, monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_DASHBOARD_SESSION_TTL", 600)

    async def steps(c):
        return await _login(c)

    resp = _run(proxy_app, steps)
    assert int(_attrs(_set_cookie(resp, _COOKIE))["max-age"]) == 600
    assert resp.json()["expires_at"] <= time.time() + 600


def test_login_accepts_bearer_key(proxy_app):
    async def steps(c):
        return await c.post("/api/dashboard/session", headers={"Authorization": f"Bearer {_KEY}"})

    resp = _run(proxy_app, steps)
    assert resp.status_code == 200
    assert _set_cookie(resp, _COOKIE) is not None


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong-key-0123456789abcdef"}])
def test_login_rejects_missing_or_wrong_key(proxy_app, headers):
    async def steps(c):
        return await c.post("/api/dashboard/session", headers=headers)

    resp = _run(proxy_app, steps)
    assert resp.status_code == 401
    assert _set_cookie(resp, _COOKIE) is None


def test_non_ascii_key_header_is_rejected_not_an_error(proxy_app):
    async def steps(c):
        h = {"X-API-Key": "cl\xe9-0123456789abcdef".encode("latin-1")}
        return (
            (await c.post("/api/dashboard/session", headers=h)).status_code,
            (await c.get("/api/stats", headers=h)).status_code,
        )

    assert _run(proxy_app, steps) == (401, 401)


def test_login_does_not_accept_the_key_as_query_param(proxy_app):
    async def steps(c):
        return await c.post(f"/api/dashboard/session?api_key={_KEY}")

    resp = _run(proxy_app, steps)
    assert resp.status_code == 401
    assert _set_cookie(resp, _COOKIE) is None


def test_session_cannot_be_renewed_without_the_key(proxy_app):
    async def steps(c):
        await _login(c)
        return await c.post("/api/dashboard/session")

    resp = _run(proxy_app, steps)
    assert resp.status_code == 401
    assert _set_cookie(resp, _COOKIE) is None


def test_login_unavailable_without_a_configured_key(monkeypatch, proxy_app):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.app.state.proxy, "auth_providers", [])

    async def steps(c):
        return await c.post("/api/dashboard/session", headers={"X-API-Key": ""})

    resp = _run(proxy_app, steps)
    assert resp.status_code == 404
    assert _set_cookie(resp, _COOKIE) is None


# ── Scope: the session only reaches the read-only dashboard API ──


def test_session_authorizes_dashboard_reads(proxy_app):
    async def steps(c):
        await _login(c)
        return {
            "score": (await c.get("/api/dashboard/score")).status_code,
            "stats": (await c.get("/api/stats")).status_code,
            "status": (await c.get("/api/dashboard/session")).json(),
        }

    out = _run(proxy_app, steps)
    assert out["score"] == 200
    assert out["stats"] == 200
    assert out["status"]["authenticated"] is True
    assert out["status"]["session"] is True


def test_session_rejected_outside_the_dashboard_api(proxy_app):
    async def steps(c):
        await _login(c)
        return {
            "gateway_chat": (await c.post("/v1/chat/completions", json=_CHAT)).status_code,
            "gateway_models": (await c.get("/v1/models")).status_code,
            "mcp": (
                await c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            ).status_code,
            "validate": (await c.post("/api/v1/validate", json={"content": "hello"})).status_code,
            "events": (await c.get("/api/events")).status_code,
            "classify": (
                await c.post("/api/compliance/classify", json={"description": "x"})
            ).status_code,
        }

    codes = _run(proxy_app, steps)
    assert set(codes.values()) == {401}, codes


@pytest.mark.parametrize(
    "raw_path",
    [
        "/api/dashboard/../../v1/models",
        "/api/dashboard/../events",
        "/api/dashboard/%2e%2e/%2e%2e/v1/models",
    ],
)
def test_session_scope_is_not_escaped_by_dot_segments(proxy_app, raw_path):
    """Paths are matched literally: a dot-segment path that starts with the
    dashboard prefix never reaches a handler outside the dashboard API."""
    from urllib.parse import unquote

    from admina.proxy import dashboard_session as ds

    token = ds.issue_token(_KEY, ttl=3600)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "server": ("test", 80),
        "client": ("127.0.0.1", 1234),
        "root_path": "",
        "path": unquote(raw_path),
        "raw_path": raw_path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"test"), (b"cookie", f"{_COOKIE}={token}".encode())],
    }
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(proxy_app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    assert status == 404


def test_session_rejected_for_writes_on_dashboard_paths(proxy_app):
    async def steps(c):
        await _login(c)
        return await c.post("/api/dashboard/score", json={})

    assert _run(proxy_app, steps).status_code == 401


def test_api_key_header_still_reaches_every_surface(proxy_app):
    async def steps(c):
        h = {"X-API-Key": _KEY}
        return {
            "gateway": (await c.post("/v1/chat/completions", json=_CHAT, headers=h)).status_code,
            "stats": (await c.get("/api/stats", headers=h)).status_code,
            "score": (await c.get("/api/dashboard/score", headers=h)).status_code,
        }

    assert _run(proxy_app, steps) == {"gateway": 200, "stats": 200, "score": 200}


def _legacy_token(key: str, exp: int) -> str:
    payload = str(exp)
    sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}.{sig}".encode()).decode("ascii")


@pytest.mark.parametrize("cookie_name", ["admina_session", _COOKIE])
def test_tokens_in_the_previous_format_are_rejected(proxy_app, cookie_name):
    token = _legacy_token(_KEY, int(time.time()) + 3600)

    async def steps(c):
        return await c.get("/api/dashboard/score", headers={"Cookie": f"{cookie_name}={token}"})

    assert _run(proxy_app, steps).status_code == 401


def test_session_is_bound_to_the_key(proxy_app, monkeypatch):
    from admina.proxy import dashboard_session as ds
    from admina.proxy import main as proxy_main

    token = ds.issue_token(_KEY, ttl=3600)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "rotated-key-0123456789abcdef")
    for p in proxy_main.app.state.proxy.auth_providers:
        monkeypatch.setattr(p, "_api_key", "rotated-key-0123456789abcdef")

    async def steps(c):
        return await c.get("/api/dashboard/score", headers={"Cookie": f"{_COOKIE}={token}"})

    assert _run(proxy_app, steps).status_code == 401


def test_expired_session_is_rejected(proxy_app):
    from admina.proxy import dashboard_session as ds

    token = ds.issue_token(_KEY, ttl=60, now=int(time.time()) - 120)

    async def steps(c):
        return await c.get("/api/dashboard/score", headers={"Cookie": f"{_COOKIE}={token}"})

    assert _run(proxy_app, steps).status_code == 401


def test_logout_clears_the_session(proxy_app):
    async def steps(c):
        await _login(c)
        out = await c.delete("/api/dashboard/session")
        after = await c.get("/api/dashboard/score")
        return out, after

    out, after = _run(proxy_app, steps)
    assert out.status_code == 200
    cleared = _set_cookie(out, _COOKIE)
    assert cleared is not None
    assert int(_attrs(cleared)["max-age"]) == 0
    assert _attrs(cleared)["path"] == "/api/"
    assert after.status_code == 401


# ── Surfaces can be switched off ─────────────────────────────


def test_dashboard_disabled_removes_shell_and_sign_in(proxy_app, monkeypatch):
    from admina.proxy import dashboard_session as ds
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_DASHBOARD_ENABLED", False)
    token = ds.issue_token(_KEY, ttl=3600)

    async def steps(c):
        return {
            "root": (await c.get("/")).status_code,
            "vendor": (await c.get("/vendor/alpinejs.min.js")).status_code,
            "logo": (await c.get("/heimdall.png")).status_code,
            "login": (await _login(c)).status_code,
            "cookie": (
                await c.get("/api/dashboard/score", headers={"Cookie": f"{_COOKIE}={token}"})
            ).status_code,
            "key": (await c.get("/api/dashboard/score", headers={"X-API-Key": _KEY})).status_code,
        }

    assert _run(proxy_app, steps) == {
        "root": 404,
        "vendor": 404,
        "logo": 404,
        "login": 404,
        "cookie": 401,
        "key": 200,
    }


def test_dashboard_disabled_from_admina_yaml(proxy_app, monkeypatch):
    from admina.core.config import AdminaConfig, DashboardConfig
    from admina.proxy import main as proxy_main

    cfg = AdminaConfig()
    cfg.dashboard = DashboardConfig(enabled=False)
    monkeypatch.setattr(proxy_main, "_admina_config", cfg)

    async def steps(c):
        return (await c.get("/")).status_code, (await _login(c)).status_code

    assert _run(proxy_app, steps) == (404, 404)


def test_api_docs_public_by_default(proxy_app):
    async def steps(c):
        return [(await c.get(p)).status_code for p in ("/docs", "/redoc", "/openapi.json")]

    assert _run(proxy_app, steps) == [200, 200, 200]


def test_api_docs_can_be_disabled(proxy_app, monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_DOCS_ENABLED", False)

    async def steps(c):
        return [(await c.get(p)).status_code for p in ("/docs", "/redoc", "/openapi.json")]

    assert _run(proxy_app, steps) == [404, 404, 404]


# ── Live feed (WebSocket) ────────────────────────────────────


def test_live_feed_accepts_session_and_rejects_anonymous(proxy_app):
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from admina.proxy import dashboard_session as ds

    client = TestClient(proxy_app)
    token = ds.issue_token(_KEY, ttl=3600)
    with client.websocket_connect(
        "/api/dashboard/live", headers={"Cookie": f"{_COOKIE}={token}"}
    ) as ws:
        ws.close()

    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(
            "/api/dashboard/live",
            headers={"Cookie": f"admina_session={_legacy_token(_KEY, int(time.time()) + 3600)}"},
        ):
            pass
    assert excinfo.value.code == 1008


def test_live_feed_ignores_session_when_dashboard_disabled(proxy_app, monkeypatch):
    from starlette.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect

    from admina.proxy import dashboard_session as ds
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_DASHBOARD_ENABLED", False)
    client = TestClient(proxy_app)
    token = ds.issue_token(_KEY, ttl=3600)
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(
            "/api/dashboard/live", headers={"Cookie": f"{_COOKIE}={token}"}
        ):
            pass
    assert excinfo.value.code == 1008


# ── Settings ────────────────────────────────────────────────


def test_session_settings_defaults():
    from admina.proxy.config import Settings

    s = Settings(_env_file=None)
    assert s.ADMINA_DASHBOARD_SESSION_TTL == 3600
    assert s.ADMINA_DASHBOARD_ENABLED is True
    assert s.ADMINA_API_DOCS_ENABLED is True


@pytest.mark.parametrize("ttl", [0, 59, 43201])
def test_session_ttl_is_bounded(ttl):
    from pydantic import ValidationError

    from admina.proxy.config import Settings

    with pytest.raises(ValidationError):
        Settings(ADMINA_DASHBOARD_SESSION_TTL=ttl, _env_file=None)


# ── Token and scope primitives ───────────────────────────────


class TestSessionToken:
    def test_round_trip(self):
        from admina.proxy import dashboard_session as ds

        now = int(time.time())
        tok = ds.issue_token(_KEY, ttl=600, now=now)
        assert ds.token_expiry(_KEY, tok, now=now) == now + 600
        assert ds.verify_token(_KEY, tok) is True

    def test_tokens_are_unique(self):
        from admina.proxy import dashboard_session as ds

        now = int(time.time())
        assert ds.issue_token(_KEY, ttl=600, now=now) != ds.issue_token(_KEY, ttl=600, now=now)

    def test_token_does_not_contain_the_key(self):
        from admina.proxy import dashboard_session as ds

        tok = ds.issue_token(_KEY, ttl=600)
        padded = tok + "=" * (-len(tok) % 4)
        assert _KEY not in base64.urlsafe_b64decode(padded).decode()
        assert _KEY not in tok

    def test_tampered_token_rejected(self):
        from admina.proxy import dashboard_session as ds

        tok = ds.issue_token(_KEY, ttl=600)
        padded = tok + "=" * (-len(tok) % 4)
        version, exp, nonce, sig = base64.urlsafe_b64decode(padded).decode().split(".")
        forged = f"{version}.{int(exp) + 86400}.{nonce}.{sig}"
        forged_tok = base64.urlsafe_b64encode(forged.encode()).decode().rstrip("=")
        assert ds.verify_token(_KEY, forged_tok) is False

    def test_expired_token_rejected(self):
        from admina.proxy import dashboard_session as ds

        now = int(time.time())
        tok = ds.issue_token(_KEY, ttl=60, now=now - 61)
        assert ds.verify_token(_KEY, tok, now=now) is False

    def test_other_key_rejected(self):
        from admina.proxy import dashboard_session as ds

        tok = ds.issue_token("key-one-0123456789abcdef", ttl=600)
        assert ds.verify_token("key-two-0123456789abcdef", tok) is False

    def test_previous_format_rejected(self):
        from admina.proxy import dashboard_session as ds

        assert ds.verify_token(_KEY, _legacy_token(_KEY, int(time.time()) + 600)) is False

    @pytest.mark.parametrize("token", ["", "garbage", "notbase64.sig", "a" * 5000, "djIuMS4yLjM"])
    def test_garbage_rejected(self, token):
        from admina.proxy import dashboard_session as ds

        assert ds.verify_token(_KEY, token) is False

    def test_no_key_never_verifies_or_issues(self):
        from admina.proxy import dashboard_session as ds

        with pytest.raises(ValueError):
            ds.issue_token("", ttl=600)
        assert ds.verify_token("", ds.issue_token(_KEY, ttl=600)) is False

    def test_ttl_out_of_range_rejected(self):
        from admina.proxy import dashboard_session as ds

        with pytest.raises(ValueError):
            ds.issue_token(_KEY, ttl=ds.MAX_TTL_SECONDS + 1)
        with pytest.raises(ValueError):
            ds.issue_token(_KEY, ttl=ds.MIN_TTL_SECONDS - 1)


@pytest.mark.parametrize(
    ("method", "path", "allowed"),
    [
        ("GET", "/api/dashboard/score", True),
        ("HEAD", "/api/dashboard/feed", True),
        ("GET", "/api/stats", True),
        ("GET", "/api/dashboard/session", True),
        ("DELETE", "/api/dashboard/session", True),
        ("POST", "/api/dashboard/session", False),
        ("POST", "/api/dashboard/score", False),
        ("DELETE", "/api/dashboard/score", False),
        ("GET", "/api/dashboard", False),
        ("GET", "/api/events", False),
        ("GET", "/api/v1/audit/x", False),
        ("POST", "/api/v1/validate", False),
        ("POST", "/v1/chat/completions", False),
        ("GET", "/v1/models", False),
        ("POST", "/mcp", False),
        ("GET", "/api/compliance/matrix", False),
    ],
)
def test_session_scope(method, path, allowed):
    from admina.proxy import dashboard_session as ds

    assert ds.session_allowed(method, path) is allowed
