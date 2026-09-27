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

"""The auth middleware authenticates a request once and runs its handler once.

An exception raised by the handler is not an authentication failure: it
reaches the application's normal 500 handler, and the handler is not run a
second time for the next auth provider. Credentials that no provider
accepts still get 401.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

pytest.importorskip("fastapi")

_BODY = {"model": "example-model", "messages": [{"role": "user", "content": "hello"}]}


class _Provider:
    """Auth provider returning a preset user (or None), or raising."""

    def __init__(self, name: str, *, user: dict | None = None, error: Exception | None = None):
        self.provider_name = name
        self._user = user
        self._error = error
        self.calls = 0

    async def authenticate(self, request) -> dict | None:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._user


def _user(name: str) -> dict:
    return {"user_id": name, "roles": ["api"], "metadata": {}}


class _Handler:
    """Stands in for the first step of the gateway handler (route selection,
    before the body is read): counts runs and raises."""

    def __init__(self, error: Exception):
        self.error = error
        self.runs = 0

    def __call__(self, *args, **kwargs):
        self.runs += 1
        raise self.error


def _app(monkeypatch, providers: list, *, api_key: str = "", handler: _Handler | None = None):
    from admina.proxy import main as proxy_main
    from admina.proxy.api import gateway
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", api_key)
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", False)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    if handler is not None:
        monkeypatch.setattr(gateway, "_select_upstream", handler)
    state = ProxyState(auth_providers=providers, forensic_box=None, governance_guards=[])
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)
    return proxy_main.app


def _post(app, headers: dict | None = None) -> httpx.Response:
    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/v1/chat/completions", json=_BODY, headers=headers or {})

    return asyncio.run(go())


@pytest.mark.parametrize(
    "error",
    [ValueError("upstream body is not JSON"), RuntimeError("boom"), OSError("disk")],
    ids=["ValueError", "RuntimeError", "OSError"],
)
def test_handler_error_is_a_server_error_and_runs_once_with_two_providers(monkeypatch, error):
    first, second = _Provider("first", user=_user("a")), _Provider("second", user=_user("b"))
    handler = _Handler(error)
    app = _app(monkeypatch, [first, second], handler=handler)

    resp = _post(app)

    assert resp.status_code == 500
    assert handler.runs == 1
    assert (first.calls, second.calls) == (1, 0)
    # The generic 500 page, without the exception text.
    assert str(error) not in resp.text


def test_second_provider_authenticates_when_the_first_fails(monkeypatch):
    first = _Provider("first", error=ValueError("bad token"))
    second = _Provider("second", user=_user("b"))
    handler = _Handler(ValueError("upstream body is not JSON"))
    app = _app(monkeypatch, [first, second], handler=handler)

    resp = _post(app)

    assert resp.status_code == 500
    assert handler.runs == 1
    assert (first.calls, second.calls) == (1, 1)


def test_request_that_no_provider_accepts_gets_401(monkeypatch):
    rejecting = [_Provider("first"), _Provider("second", error=ValueError("bad token"))]
    handler = _Handler(ValueError("never reached"))
    app = _app(monkeypatch, rejecting, handler=handler)

    resp = _post(app, headers={"Authorization": "Bearer wrong-key"})

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authentication failed across all providers"
    assert handler.runs == 0
    assert [p.calls for p in rejecting] == [1, 1]


def test_wrong_api_key_still_gets_401(monkeypatch):
    handler = _Handler(ValueError("never reached"))
    app = _app(monkeypatch, [], api_key="canary-admina-key-0123456789", handler=handler)

    resp = _post(app, headers={"Authorization": "Bearer wrong-key"})

    assert resp.status_code == 401
    assert handler.runs == 0


def test_handler_error_without_providers_is_a_server_error(monkeypatch):
    key = "canary-admina-key-0123456789"
    handler = _Handler(ValueError("upstream body is not JSON"))
    app = _app(monkeypatch, [], api_key=key, handler=handler)

    resp = _post(app, headers={"Authorization": f"Bearer {key}"})

    assert resp.status_code == 500
    assert handler.runs == 1
