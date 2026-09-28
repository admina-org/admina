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

"""The engines the proxy actually built, next to the engine selection.

``engine_status()`` reports ``firewall``, ``loop_breaker`` and ``pii``: the
engine of each object it is given, the ones the proxy built at startup.
``/health`` and ``/api/stats`` report them from the running proxy, so an
admina.yaml that makes the firewall Python under ``ADMINA_ENGINE=auto``
shows ``engine.firewall = "python"`` while ``engine.active`` still reports
the selection. The keys of 0.12 are unchanged.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("fastapi")

from _proxy_app import API_KEY, isolate, serve, with_key

LEGACY_KEYS = {"engine", "rust_available", "rust_version", "selection", "active", "pii_active"}
EFFECTIVE_KEYS = {"firewall", "loop_breaker", "pii"}

CUSTOM_PATTERN_YAML = textwrap.dedent(
    """\
    schema_version: 1
    domains:
      agent_security:
        firewall:
          custom_patterns:
            - regex: "\\\\bexample\\\\s+marker\\\\b"
              category: example_custom
              risk_level: high
    """
)


@pytest.fixture(autouse=True)
def _no_config(monkeypatch, tmp_path):
    """No admina.yaml unless a test writes one; no engine selection."""
    monkeypatch.chdir(tmp_path)
    for name in ("ADMINA_CONFIG", "ADMINA_ENGINE", "ADMINA_PII_ENGINE"):
        monkeypatch.delenv(name, raising=False)


def _engines():
    from admina import engines

    return engines


def _health_and_stats(monkeypatch, surfaces: str = "") -> tuple[dict, dict, object]:
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    monkeypatch.setattr(proxy_main.settings, "ADMINA_ENABLED_SURFACES", surfaces)
    isolate(monkeypatch)
    responses, state = serve(
        [
            {"method": "GET", "url": "/health"},
            with_key({"method": "GET", "url": "/api/stats"}),
        ]
    )
    assert [r.status_code for r in responses] == [200, 200]
    return responses[0].json(), responses[1].json(), state


# ── engine_status() of built objects ─────────────────────────


class _Named:
    def __init__(self, engine: str) -> None:
        self.engine = engine

    def get_stats(self) -> dict:
        return {"engine": self.engine}


def test_engine_status_reports_the_engine_of_each_object():
    engines = _engines()
    status = engines.engine_status(
        firewall=_Named("rust"), loop_breaker=_Named("python"), pii_engine=_Named("rust")
    )
    assert status["firewall"] == "rust"
    assert status["loop_breaker"] == "python"
    assert status["pii"] == "rust"
    assert LEGACY_KEYS <= set(status)


def test_engine_status_without_objects_reports_none():
    status = _engines().engine_status()
    assert set(status) == LEGACY_KEYS | EFFECTIVE_KEYS
    assert status["firewall"] is None
    assert status["loop_breaker"] is None
    assert status["pii"] is None


def test_a_firewall_that_names_no_engine_is_python():
    class _Plain:
        def check(self, text: str) -> dict:
            return {"is_injection": False}

    assert _engines().engine_status(firewall=_Plain())["firewall"] == "python"


def test_pii_engines_are_named_by_their_engine(example_pii_plugin):
    engines = _engines()
    assert engines.engine_status(pii_engine=engines.get_pii_engine("spacy-regex"))["pii"] in (
        "python",
        "rust",
    )
    plugin = engines.get_pii_engine(example_pii_plugin)
    assert engines.engine_status(pii_engine=plugin)["pii"] == example_pii_plugin


def test_the_built_firewall_is_reported_not_the_selection(monkeypatch, tmp_path):
    pytest.importorskip("admina_core")
    engines = _engines()
    (tmp_path / "admina.yaml").write_text(CUSTOM_PATTERN_YAML, encoding="utf-8")
    firewall = engines.get_firewall()
    status = engines.engine_status(firewall=firewall)
    assert status["selection"] == "auto"
    assert status["active"] == "rust"
    assert status["firewall"] == "python"


# ── /health and /api/stats of the running proxy ──────────────


def test_health_reports_the_rust_firewall_without_overrides(monkeypatch):
    pytest.importorskip("admina_core")
    health, _stats, state = _health_and_stats(monkeypatch)
    engine = health["engine"]
    assert engine["firewall"] == "rust"
    assert engine["active"] == "rust"
    assert engine["rust_available"] is True
    assert engine["selection"] == "auto"
    assert state.firewall.engine == "rust"


def test_health_reports_the_python_firewall_of_custom_patterns_under_auto(monkeypatch, tmp_path):
    (tmp_path / "admina.yaml").write_text(CUSTOM_PATTERN_YAML, encoding="utf-8")
    health, _stats, state = _health_and_stats(monkeypatch)
    engine = health["engine"]
    assert engine["firewall"] == "python"
    assert engine["selection"] == "auto"
    # active still reports the selection: rust whenever admina-core is installed.
    assert engine["active"] == ("rust" if engine["rust_available"] else "python")
    assert state.firewall.engine == "python"


def test_health_and_stats_agree(monkeypatch, tmp_path):
    (tmp_path / "admina.yaml").write_text(CUSTOM_PATTERN_YAML, encoding="utf-8")
    health, stats, _state = _health_and_stats(monkeypatch)
    assert stats["engine"] == health["engine"]
    assert stats["firewall"]["engine"] == health["engine"]["firewall"]
    assert stats["pii_redactor"]["engine"] == health["engine"]["pii"]
    assert stats["loop_breaker"]["engine"] == health["engine"]["loop_breaker"]


def test_health_keeps_the_keys_of_0_12(monkeypatch):
    health, _stats, _state = _health_and_stats(monkeypatch)
    assert set(health["engine"]) == LEGACY_KEYS | EFFECTIVE_KEYS


def test_no_loop_breaker_is_reported_when_none_is_built(monkeypatch):
    health, stats, state = _health_and_stats(monkeypatch, surfaces="gateway,dashboard")
    assert state.loop_breaker is None
    assert health["engine"]["loop_breaker"] is None
    assert stats["engine"]["loop_breaker"] is None


def test_pii_stays_python_under_auto(monkeypatch):
    health, _stats, _state = _health_and_stats(monkeypatch)
    assert health["engine"]["pii"] == "python"
    assert health["engine"]["pii_active"] == "python"


def test_explicit_rust_reports_rust_everywhere(monkeypatch):
    pytest.importorskip("admina_core")
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    health, _stats, _state = _health_and_stats(monkeypatch)
    engine = health["engine"]
    assert (engine["firewall"], engine["loop_breaker"], engine["pii"]) == ("rust", "rust", "rust")
    assert engine["active"] == "rust"
    assert engine["selection"] == "rust"


def test_python_selection_reports_python_everywhere(monkeypatch):
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    health, _stats, _state = _health_and_stats(monkeypatch)
    engine = health["engine"]
    assert (engine["firewall"], engine["loop_breaker"], engine["pii"]) == (
        "python",
        "python",
        "python",
    )
    assert engine["active"] == "python"
