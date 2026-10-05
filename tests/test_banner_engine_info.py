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

"""The startup banner and ``admina_engine_info`` report the running engines.

Both come from ``engine_status()`` of the engines the proxy built, the
``admina-core`` version and the settings that switch the firewall and PII
redaction: the banner never says "PII Redaction: ON" with
``PII_REDACTION_ENABLED=false``, nor names the Rust engine for a Python
firewall.
"""

from __future__ import annotations

import logging
import re

import pytest

pytest.importorskip("fastapi")

from _proxy_app import isolate, serve

from admina import __version__

_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no admina.yaml
    for name in ("ADMINA_CONFIG", "ADMINA_ENGINE", "ADMINA_PII_ENGINE"):
        monkeypatch.delenv(name, raising=False)


def _run(monkeypatch, caplog, *, engine: str, pii: bool) -> tuple[list[str], dict, dict]:
    """Start the proxy; return its banner lines, the labels of
    admina_engine_info and the engine status of /health."""
    from admina.proxy import main as proxy_main

    monkeypatch.setenv("ADMINA_ENGINE", engine)
    monkeypatch.setattr(proxy_main.settings, "PII_REDACTION_ENABLED", pii)
    isolate(monkeypatch)
    with caplog.at_level(logging.INFO, logger="admina.proxy"):
        responses, _state = serve(
            [{"method": "GET", "url": "/metrics"}, {"method": "GET", "url": "/health"}]
        )
    banner = [r.getMessage() for r in caplog.records if r.name == "admina.proxy"]
    info = [
        line for line in responses[0].text.splitlines() if line.startswith("admina_engine_info{")
    ]
    assert len(info) == 1
    assert info[0].endswith("} 1")
    labels = dict(_LABEL.findall(info[0]))
    return banner, labels, responses[1].json()["engine"]


def _core(status: dict) -> str:
    version = status["rust_version"]
    return f"admina-core {version}" if version else "admina-core not installed"


def test_python_engine_with_pii_off(monkeypatch, caplog):
    banner, labels, status = _run(monkeypatch, caplog, engine="python", pii=False)
    assert (status["firewall"], status["loop_breaker"], status["pii"]) == (
        "python",
        "python",
        "python",
    )
    assert f"  Engine selection: ADMINA_ENGINE=python ({_core(status)})" in banner
    assert (
        "  Firewall: ON (python engine) | PII Redaction: OFF (gateway and /mcp) | "
        "Loop Breaker: ON (python engine)"
    ) in banner
    assert not [line for line in banner if "RUST" in line.upper() and "admina-core" not in line]
    assert labels == {
        "engine": "python",
        "firewall": "python",
        "loop_breaker": "python",
        "pii": "python",
        "pii_redaction": "off",
        "rust_available": "yes" if status["rust_available"] else "no",
        "rust_version": status["rust_version"] or "",
        "selection": "python",
        "version": __version__,
    }


def test_rust_engine_with_pii_on(monkeypatch, caplog):
    pytest.importorskip("admina_core")
    import admina_core

    banner, labels, status = _run(monkeypatch, caplog, engine="rust", pii=True)
    assert status["rust_version"] == admina_core.version()
    assert (status["firewall"], status["loop_breaker"], status["pii"]) == ("rust", "rust", "rust")
    assert f"  Engine selection: ADMINA_ENGINE=rust (admina-core {admina_core.version()})" in banner
    assert (
        "  Firewall: ON (rust engine) | PII Redaction: ON (rust engine) | "
        "Loop Breaker: ON (rust engine)"
    ) in banner
    assert labels == {
        "engine": "rust",
        "firewall": "rust",
        "loop_breaker": "rust",
        "pii": "rust",
        "pii_redaction": "on",
        "rust_available": "yes",
        "rust_version": admina_core.version(),
        "selection": "rust",
        "version": __version__,
    }


def test_auto_with_admina_core_reports_the_mixed_engines(monkeypatch, caplog):
    pytest.importorskip("admina_core")
    banner, labels, status = _run(monkeypatch, caplog, engine="auto", pii=True)
    assert (status["firewall"], status["pii"]) == ("rust", "python")
    assert (
        "  Firewall: ON (rust engine) | PII Redaction: ON (python engine) | "
        "Loop Breaker: ON (rust engine)"
    ) in banner
    assert (labels["engine"], labels["firewall"], labels["pii"]) == ("rust", "rust", "python")


def test_firewall_off_and_no_loop_breaker(monkeypatch, caplog):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "INJECTION_FAST_PATH_ENABLED", False)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_ENABLED_SURFACES", "gateway")
    banner, labels, status = _run(monkeypatch, caplog, engine="python", pii=True)
    assert (
        "  Firewall: OFF (gateway and /mcp) | PII Redaction: ON (python engine) | Loop Breaker: OFF"
    ) in banner
    assert status["loop_breaker"] is None
    assert labels["loop_breaker"] == "none"
