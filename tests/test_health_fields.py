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

"""GET /health reports the governance mode, the enabled surfaces, the active
firewall ruleset and whether the forensic store accepts writes, next to the
existing fields (``engine.*`` unchanged). Nothing secret is in it."""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil

import httpx
import pytest

pytest.importorskip("fastapi")

from _proxy_app import API_KEY, CHAT, isolate, serve, with_key
from pydantic import SecretStr

from admina.domains.agent_security.ruleset import ruleset_sha256
from admina.domains.compliance.forensic import ForensicBlackBox
from admina.engines import engine_status
from admina.proxy.surfaces import SURFACES

FIELDS = {
    "status",
    "service",
    "version",
    "mode",
    "surfaces",
    "ruleset_sha256",
    "forensic_writable",
    "engine",
    "timestamp",
}


def _health(monkeypatch, forensic_box=None, **state_fields) -> dict:
    """GET /health on the real app with an injected state."""
    from admina.proxy import main as proxy_main
    from admina.proxy.multi_upstream import MultiUpstreamRouter
    from admina.proxy.state import ProxyState

    state = ProxyState(
        router=MultiUpstreamRouter(default_upstream="http://mcp.test"),
        forensic_box=forensic_box,
        **state_fields,
    )
    monkeypatch.setattr(proxy_main.app.state, "proxy", state, raising=False)

    async def go() -> httpx.Response:
        transport = httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/health")

    response = asyncio.run(go())
    assert response.status_code == 200
    return response.json()


# ── Fields ────────────────────────────────────────────────────


def test_fields(monkeypatch):
    from admina import __version__

    body = _health(monkeypatch)
    assert set(body) == FIELDS
    assert body["status"] == "healthy"
    assert body["service"] == "admina-proxy"
    assert body["version"] == __version__
    assert body["mode"] == "enforce"
    assert body["surfaces"] == list(SURFACES)


def test_engine_fields_are_unchanged(monkeypatch):
    engine = _health(monkeypatch)["engine"]
    assert engine == engine_status()
    assert {"engine", "rust_available", "rust_version", "selection", "active", "pii_active"} == set(
        engine
    )


@pytest.mark.parametrize("mode", ["enforce", "observe", "dry-run"])
def test_mode(monkeypatch, mode):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "GOVERNANCE_MODE", mode)
    assert _health(monkeypatch)["mode"] == mode


@pytest.mark.parametrize(
    ("value", "expected"),
    [("gateway", ["gateway"]), ("dashboard,gateway", ["gateway", "dashboard"]), ("", SURFACES)],
)
def test_surfaces(monkeypatch, value, expected):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_ENABLED_SURFACES", value)
    assert _health(monkeypatch)["surfaces"] == list(expected)


# ── ruleset_sha256 ────────────────────────────────────────────


def test_ruleset_without_a_resolved_scan_config_is_the_default(monkeypatch):
    assert _health(monkeypatch)["ruleset_sha256"] == ruleset_sha256()


def test_ruleset_is_the_active_one_of_the_running_proxy(monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    isolate(monkeypatch)
    responses, state = serve(
        [
            {"method": "GET", "url": "/health"},
            with_key(CHAT),
            with_key({"method": "GET", "url": "/v1/admina/ruleset"}),
        ]
    )
    engine = state.firewall.engine
    core_version = engine_status()["rust_version"] if engine == "rust" else None
    expected = ruleset_sha256(
        proxy_main._admina_config, engine=engine, admina_core_version=core_version
    )
    assert responses[0].json()["ruleset_sha256"] == expected
    assert responses[1].headers["X-Admina-Ruleset"] == expected
    assert responses[2].json()["ruleset_sha256"] == expected


# ── forensic_writable ─────────────────────────────────────────


def test_forensic_writable_on_a_writable_directory(monkeypatch, tmp_path):
    box = ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"))
    before = sorted(p.name for p in (tmp_path / "forensic").iterdir())
    assert _health(monkeypatch, box)["forensic_writable"] is True
    # The probe file is removed again.
    assert sorted(p.name for p in (tmp_path / "forensic").iterdir()) == before


@pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root writes to any directory"
)
def test_forensic_not_writable_on_a_read_only_directory(monkeypatch, tmp_path):
    directory = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(directory))
    directory.chmod(0o500)
    try:
        assert _health(monkeypatch, box)["forensic_writable"] is False
    finally:
        directory.chmod(0o700)


def test_forensic_not_writable_when_the_directory_is_gone(monkeypatch, tmp_path):
    directory = tmp_path / "forensic"
    box = ForensicBlackBox(filesystem_dir=str(directory))
    shutil.rmtree(directory)
    directory.write_text("not a directory")
    assert _health(monkeypatch, box)["forensic_writable"] is False


def test_forensic_writable_is_null_for_the_memory_store(monkeypatch):
    assert _health(monkeypatch, ForensicBlackBox())["forensic_writable"] is None


def test_forensic_writable_is_null_without_a_store(monkeypatch):
    assert _health(monkeypatch, None)["forensic_writable"] is None


class _FakeS3:
    """The boto3 S3 calls the forensic store makes; put_object can fail."""

    def __init__(self) -> None:
        self.fail = False
        self.objects: dict[str, bytes] = {}

    def head_bucket(self, **_kw):
        return {}

    def get_object(self, **kw):
        raise KeyError(kw["Key"])

    def list_objects_v2(self, **_kw):
        return {"Contents": []}

    def put_object(self, **kw):
        if self.fail:
            raise OSError("bucket unavailable")
        self.objects[kw["Key"]] = kw["Body"]
        return {}


def test_forensic_writable_is_the_last_s3_write(monkeypatch):
    s3 = _FakeS3()
    box = ForensicBlackBox(boto3_client=s3, bucket="b", s3_max_retries=0)
    assert _health(monkeypatch, box)["forensic_writable"] is None
    box.record({"event_id": "e1"})
    assert _health(monkeypatch, box)["forensic_writable"] is True
    s3.fail = True
    box.record({"event_id": "e2"})
    assert _health(monkeypatch, box)["forensic_writable"] is False
    s3.fail = False
    box.record({"event_id": "e3"})
    assert _health(monkeypatch, box)["forensic_writable"] is True


def test_running_proxy_reports_its_filesystem_store(monkeypatch, tmp_path):
    isolate(monkeypatch, forensic_backend="filesystem", forensic_dir=str(tmp_path / "forensic"))
    responses, _ = serve([{"method": "GET", "url": "/health"}])
    assert responses[0].json()["forensic_writable"] is True


# ── Nothing secret ────────────────────────────────────────────


def test_no_secret_in_the_payload(monkeypatch, tmp_path):
    from admina.proxy import main as proxy_main

    api_key = "canary-" + secrets.token_hex(16)
    state_key = "canary-" + secrets.token_hex(16)
    upstream_key = "canary-" + secrets.token_hex(16)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", api_key)
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY", state_key)
    monkeypatch.setattr(
        proxy_main.settings, "ADMINA_GATEWAY_UPSTREAM_API_KEY", SecretStr(upstream_key)
    )
    isolate(monkeypatch, forensic_backend="filesystem", forensic_dir=str(tmp_path / "forensic"))
    responses, _ = serve([{"method": "GET", "url": "/health"}])
    assert responses[0].status_code == 200
    for key in (api_key, state_key, upstream_key):
        assert key not in responses[0].text


def test_health_stays_public_when_metrics_and_docs_need_the_key(monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_METRICS_REQUIRE_AUTH", True)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_DOCS_REQUIRE_AUTH", True)
    assert _health(monkeypatch)["status"] == "healthy"
