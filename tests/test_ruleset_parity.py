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

"""The ruleset document, and the same ruleset_sha256 from the SDK and the proxy.

:func:`~admina.domains.agent_security.ruleset.ruleset_document` is the
canonical JSON the hash is computed over, with ``ruleset_format`` so that a
change of its shape is explicit. The SDK
(:func:`admina.sdk.active_ruleset_sha256`) and the proxy
(``X-Admina-Ruleset``, ``GET /v1/admina/ruleset``) compute the hash of the
same firewall from the same admina.yaml.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import textwrap

import httpx
import pytest

from admina.core.config import AdminaConfig
from admina.domains.agent_security.pattern_packs import PATTERN_PACK_DIRS_ENV
from admina.domains.agent_security.ruleset import (
    RULESET_FORMAT,
    ruleset_document,
    ruleset_object,
    ruleset_sha256,
)

pytest.importorskip("fastapi")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(PATTERN_PACK_DIRS_ENV, raising=False)


def test_the_object_names_its_format():
    assert RULESET_FORMAT == 1
    assert ruleset_object(AdminaConfig())["ruleset_format"] == 1


@pytest.mark.parametrize("engine", ["python", "rust"])
def test_the_hash_is_the_sha256_of_the_document(engine):
    kwargs = {"engine": engine, "admina_core_version": "0.13.0"}
    document = ruleset_document(AdminaConfig(), **kwargs)
    assert isinstance(document, str)
    assert hashlib.sha256(document.encode("utf-8")).hexdigest() == ruleset_sha256(
        AdminaConfig(), **kwargs
    )
    assert json.loads(document) == ruleset_object(AdminaConfig(), **kwargs)


def _config_file(tmp_path, monkeypatch) -> None:
    path = tmp_path / "admina.yaml"
    path.write_text(
        textwrap.dedent(
            """\
            domains:
              agent_security:
                firewall:
                  heuristic_threshold: 0.7
                  allowed_tags: [Source]
                  custom_patterns:
                    - regex: '\\bexample\\s+secret\\b'
                      category: example_custom
                      risk_level: high
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    monkeypatch.setenv("ADMINA_ENGINE", "python")


def test_sdk_and_proxy_compute_the_same_hash(tmp_path, monkeypatch):
    from admina.core.config import load_config
    from admina.engines import get_firewall
    from admina.proxy.gateway_scan import build_gateway_scan_config
    from admina.sdk import active_ruleset_sha256

    _config_file(tmp_path, monkeypatch)
    proxy = build_gateway_scan_config(get_firewall(), load_config())
    assert active_ruleset_sha256() == proxy.ruleset_sha256
    assert proxy.ruleset_sha256 != ruleset_sha256(AdminaConfig())  # the file counts


def test_the_endpoint_serves_the_document(tmp_path, monkeypatch):
    from admina.core.config import load_config
    from admina.engines import get_firewall
    from admina.proxy.gateway_scan import build_gateway_scan_config
    from admina.sdk import active_ruleset_sha256

    _config_file(tmp_path, monkeypatch)
    scan = build_gateway_scan_config(get_firewall(), load_config())

    from fastapi import FastAPI

    from admina.proxy.api.gateway import create_gateway_endpoints
    from admina.proxy.config import Settings

    app = FastAPI()
    app.state.proxy = type("State", (), {"gateway_scan": scan})()
    app.include_router(
        create_gateway_endpoints(
            get_state=lambda: app.state.proxy, get_settings=lambda: Settings(_env_file=None)
        )
    )

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/v1/admina/ruleset")

    data = asyncio.run(go()).json()
    assert data["ruleset_format"] == RULESET_FORMAT
    document = data["ruleset_document"]
    assert hashlib.sha256(document.encode("utf-8")).hexdigest() == data["ruleset_sha256"]
    assert data["ruleset_sha256"] == active_ruleset_sha256()


def test_sdk_and_proxy_agree_on_the_rust_engine(tmp_path, monkeypatch):
    pytest.importorskip("admina_core")
    from admina.core.config import load_config
    from admina.engines import get_firewall
    from admina.proxy.gateway_scan import build_gateway_scan_config
    from admina.sdk import active_ruleset_sha256

    path = tmp_path / "admina.yaml"
    path.write_text("domains: {agent_security: {firewall: {allowed_tags: [source]}}}\n")
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    proxy = build_gateway_scan_config(get_firewall(), load_config())
    assert proxy.engine == "rust"
    assert active_ruleset_sha256() == proxy.ruleset_sha256
