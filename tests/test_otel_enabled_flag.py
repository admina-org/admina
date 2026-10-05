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

"""``OTEL_ENABLED`` switches the OpenTelemetry exporter of the proxy.

- ``true`` (default): the proxy builds the OTLP exporter, to
  ``OTEL_ENDPOINT``, when the ``telemetry`` extra is installed and
  ``ADMINA_OFFLINE`` is off.
- ``false``: no exporter is built and nothing is exported: the proxy makes
  no connection for telemetry, and the gateway opens no span.

The ``no_network`` fixture (``_network_guard``) refuses network access and
records every attempt.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from _proxy_app import API_KEY, CHAT, isolate, upstream, with_key

pytest.importorskip("fastapi")
otel = pytest.importorskip("admina.domains.compliance.otel")
if not otel._OTEL_AVAILABLE:
    pytest.skip("the telemetry extra is not installed", allow_module_level=True)


class _Exporter:
    """Stands in for the OTLP span exporter: records how it was built."""

    built: list[dict[str, Any]] = []

    def __init__(self, **kwargs: Any) -> None:
        type(self).built.append(kwargs)

    def shutdown(self) -> None:
        pass


class _Processor:
    def __init__(self, exporter: Any) -> None:
        self.exporter = exporter

    def on_start(self, *args: Any, **kwargs: Any) -> None:
        pass

    def on_end(self, *args: Any) -> None:
        pass

    def shutdown(self) -> None:
        pass

    def force_flush(self, *args: Any) -> bool:
        return True


@pytest.fixture
def proxy(monkeypatch):
    """The proxy with its real OTEL exporter class, whose OTLP exporter and
    span processor are recorded instead of started."""
    from admina.proxy import main as proxy_main

    isolate(monkeypatch)
    monkeypatch.setattr(proxy_main, "OTELGovernanceExporter", otel.OTELGovernanceExporter)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    monkeypatch.setattr(proxy_main.settings, "OTEL_ENDPOINT", "http://collector.example:4317")
    monkeypatch.setenv("ADMINA_OFFLINE", "false")
    _Exporter.built = []
    monkeypatch.setattr(otel, "OTLPSpanExporter", _Exporter)
    monkeypatch.setattr(otel, "BatchSpanProcessor", _Processor)
    # The global tracer provider is left as it is.
    monkeypatch.setattr(otel.trace, "set_tracer_provider", lambda provider: None)
    return proxy_main


def _run(proxy_main) -> tuple[Any, httpx.Response]:
    """Start the proxy, send one gateway chat completion and return the
    state and the response."""

    async def go() -> tuple[Any, httpx.Response]:
        async with proxy_main.lifespan(proxy_main.app):
            state = proxy_main.app.state.proxy
            await state.gateway_http_client.aclose()
            state.gateway_http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
            transport = httpx.ASGITransport(app=proxy_main.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.request(**with_key(CHAT))
            return state, response

    return asyncio.run(go())


def test_the_setting_is_read_from_the_environment(monkeypatch):
    from admina.proxy.config import Settings

    monkeypatch.delenv("OTEL_ENABLED", raising=False)
    assert Settings(_env_file=None).OTEL_ENABLED is True
    monkeypatch.setenv("OTEL_ENABLED", "false")
    assert Settings(_env_file=None).OTEL_ENABLED is False


def test_disabled_the_proxy_builds_no_exporter_and_connects_nowhere(proxy, monkeypatch, no_network):
    monkeypatch.setattr(proxy.settings, "OTEL_ENABLED", False)
    state, response = _run(proxy)
    assert response.status_code == 200
    assert _Exporter.built == []
    assert state.otel_exporter.enabled is False
    assert no_network == []


def test_disabled_the_gateway_opens_no_span(proxy, monkeypatch):
    monkeypatch.setattr(proxy.settings, "OTEL_ENABLED", False)
    spans: list = []
    monkeypatch.setattr(
        otel.OTELGovernanceExporter, "start_span", lambda self, *a, **kw: spans.append(a)
    )
    _run(proxy)
    assert spans == []


def test_enabled_by_default_the_proxy_builds_the_exporter(proxy):
    assert proxy.settings.OTEL_ENABLED is True
    state, response = _run(proxy)
    assert response.status_code == 200
    assert state.otel_exporter.enabled is True
    assert [kw["endpoint"] for kw in _Exporter.built] == ["http://collector.example:4317"]


def test_offline_wins_over_enabled(proxy, monkeypatch, no_network):
    monkeypatch.setenv("ADMINA_OFFLINE", "true")
    state, _ = _run(proxy)
    assert state.otel_exporter.enabled is False
    assert _Exporter.built == []
    assert no_network == []
