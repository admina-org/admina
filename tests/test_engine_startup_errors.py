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

"""An explicit ``ADMINA_ENGINE=rust`` that cannot be honoured is an error.

With ``ADMINA_ENGINE=rust``, a firewall key of admina.yaml that only the
Python firewall applies (``custom_patterns``, ``disabled_categories``,
``disabled_patterns``, ``pattern_packs``) or a missing ``admina-core`` makes
the engine factories raise :class:`EngineSelectionError`, the SDK included,
and the proxy does not start. ``auto`` and ``python`` select as before.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "pattern_packs"

PYTHON_ONLY = {
    "custom_patterns": (
        "      custom_patterns:\n"
        '        - regex: "\\\\bexample\\\\s+marker\\\\b"\n'
        "          category: example_custom\n"
        "          risk_level: high\n"
    ),
    "disabled_categories": "      disabled_categories: [tool_abuse]\n",
    "disabled_patterns": "      disabled_patterns: [tool_abuse.en.1]\n",
    "pattern_packs": (
        f"      pattern_pack_dirs: [{FIXTURES}]\n      pattern_packs: [example-pack]\n"
    ),
}


def _yaml(tmp_path: Path, firewall: str) -> Path:
    path = tmp_path / "admina.yaml"
    path.write_text(
        "schema_version: 1\ndomains:\n  agent_security:\n    firewall:\n" + firewall,
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no admina.yaml unless a test writes one
    for name in ("ADMINA_CONFIG", "ADMINA_ENGINE", "ADMINA_PII_ENGINE", "ADMINA_PATTERN_PACK_DIRS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def engines():
    from admina import engines as module

    return module


@pytest.fixture
def engines_without_core(monkeypatch):
    """admina.engines imported again while ``import admina_core`` fails; the
    modules imported before are put back after the test."""
    import admina

    importlib.import_module("admina.engines")
    saved = _engine_modules()
    monkeypatch.setattr(admina, "engines", saved["admina.engines"])
    for name in saved:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "admina_core", None)  # import fails
    module = importlib.import_module("admina.engines")
    assert module._rust_available is False
    yield module
    for name in set(_engine_modules()) - set(saved):
        del sys.modules[name]


def _engine_modules() -> dict:
    return {
        name: module
        for name, module in sys.modules.items()
        if name == "admina.engines" or name.startswith("admina.engines.")
    }


# ── Explicit rust with Python-only keys ──────────────────────


@pytest.mark.parametrize("key", sorted(PYTHON_ONLY))
def test_rust_with_a_python_only_key_is_an_error(monkeypatch, tmp_path, engines, key):
    pytest.importorskip("admina_core")
    _yaml(tmp_path, PYTHON_ONLY[key])
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    with pytest.raises(engines.EngineSelectionError, match=key) as caught:
        engines.get_firewall()
    assert "ADMINA_ENGINE=rust" in str(caught.value)
    assert isinstance(caught.value, ValueError)


def test_the_error_names_every_python_only_key(monkeypatch, tmp_path, engines):
    pytest.importorskip("admina_core")
    _yaml(tmp_path, "".join(PYTHON_ONLY.values()))
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    with pytest.raises(engines.EngineSelectionError) as caught:
        engines.get_firewall()
    message = str(caught.value)
    for key in PYTHON_ONLY:
        assert f"agent_security.firewall.{key}" in message
    assert "pattern_pack_dirs" not in message


def test_the_python_only_keys_are_the_documented_four(engines):
    assert engines.PYTHON_ONLY_FIREWALL_KEYS == (
        "custom_patterns",
        "disabled_categories",
        "disabled_patterns",
        "pattern_packs",
    )


@pytest.mark.parametrize(
    "firewall",
    [
        "      custom_patterns: []\n      disabled_categories: []\n"
        "      disabled_patterns: []\n      pattern_packs: []\n",
        "      custom_patterns:\n      disabled_categories:\n",
        "      heuristic_threshold: 0.7\n      allowed_tags: [source]\n",
        f"      pattern_pack_dirs: [{FIXTURES}]\n      strict_pack_timing: true\n",
    ],
    ids=["empty-lists", "null-values", "heuristic-keys", "pack-dirs-without-packs"],
)
def test_rust_with_no_python_only_key_set_builds_the_rust_firewall(
    monkeypatch, tmp_path, engines, firewall
):
    pytest.importorskip("admina_core")
    _yaml(tmp_path, firewall)
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    assert engines.get_firewall().engine == "rust"


def test_the_sdk_raises_the_same_error(monkeypatch, tmp_path, engines):
    pytest.importorskip("admina_core")
    from admina.sdk import governed_agent, governed_model

    _yaml(tmp_path, PYTHON_ONLY["custom_patterns"])
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    for loader in (governed_model._load_firewall, governed_agent._load_firewall):
        with pytest.raises(ValueError, match="custom_patterns") as caught:
            loader()
        assert type(caught.value).__name__ == "EngineSelectionError"


# ── auto and python are unaffected ───────────────────────────


@pytest.mark.parametrize("key", sorted(PYTHON_ONLY))
def test_auto_with_a_python_only_key_uses_the_python_firewall(
    monkeypatch, tmp_path, engines, caplog, key
):
    _yaml(tmp_path, PYTHON_ONLY[key])
    monkeypatch.setenv("ADMINA_ENGINE", "auto")
    with caplog.at_level(logging.WARNING, logger="admina.engines"):
        firewall = engines.get_firewall()
    assert firewall.engine == "python"
    if engines._rust_available:
        messages = [r.getMessage() for r in caplog.records]
        assert any("falling back to the Python bridge" in m and key in m for m in messages)


@pytest.mark.parametrize("key", sorted(PYTHON_ONLY))
def test_python_with_a_python_only_key_uses_the_python_firewall(
    monkeypatch, tmp_path, engines, key
):
    _yaml(tmp_path, PYTHON_ONLY[key])
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    assert engines.get_firewall().engine == "python"


def test_unset_selection_is_auto(monkeypatch, tmp_path, engines):
    _yaml(tmp_path, PYTHON_ONLY["disabled_categories"])
    assert engines.get_firewall().engine == "python"


# ── Explicit rust without admina-core ────────────────────────


def test_rust_without_admina_core_is_an_error(monkeypatch, engines_without_core):
    engines = engines_without_core
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    for factory in (engines.get_firewall, engines.get_loop_breaker, engines.get_pii_engine):
        with pytest.raises(engines.EngineSelectionError, match="admina-core is not installed"):
            factory()
    with pytest.raises(engines.EngineSelectionError, match="ADMINA_ENGINE=rust"):
        engines.engine_status()


def test_auto_and_python_without_admina_core_use_python(monkeypatch, engines_without_core):
    engines = engines_without_core
    for selection in ("auto", "python"):
        monkeypatch.setenv("ADMINA_ENGINE", selection)
        assert engines.get_firewall().engine == "python"
        assert engines.get_loop_breaker().get_stats()["engine"] == "python"
        assert engines.get_pii_engine().get_stats()["engine"] == "python"
        status = engines.engine_status()
        assert (status["active"], status["pii_active"]) == ("python", "python")


def test_the_engines_module_is_put_back(engines):
    # Runs after the tests above: the module in use still sees admina-core
    # when it is installed.
    import admina

    assert admina.engines is sys.modules["admina.engines"]
    try:
        import admina_core  # noqa: F401
    except ImportError:
        return
    assert admina.engines._rust_available is True


# ── The proxy does not start ─────────────────────────────────


def _start(monkeypatch) -> None:
    from _proxy_app import isolate
    from fastapi import FastAPI

    from admina.proxy import main as proxy_main

    isolate(monkeypatch)

    async def go() -> None:
        async with proxy_main.lifespan(FastAPI()):
            pass

    asyncio.run(go())


def test_the_proxy_does_not_start_with_rust_and_a_python_only_key(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("admina_core")
    _yaml(tmp_path, PYTHON_ONLY["pattern_packs"])
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    with pytest.raises(ValueError, match="pattern_packs") as caught:
        _start(monkeypatch)
    assert type(caught.value).__name__ == "EngineSelectionError"


def test_the_proxy_does_not_start_with_rust_and_no_admina_core(monkeypatch):
    pytest.importorskip("fastapi")
    from admina.proxy import main as proxy_main

    # The engines module the proxy imported, whatever other tests reloaded.
    monkeypatch.setitem(proxy_main.get_firewall.__globals__, "_rust_available", False)
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    with pytest.raises(ValueError, match="admina-core is not installed") as caught:
        _start(monkeypatch)
    assert type(caught.value).__name__ == "EngineSelectionError"


def test_the_proxy_starts_with_auto_and_a_python_only_key(monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    _yaml(tmp_path, PYTHON_ONLY["custom_patterns"])
    monkeypatch.setenv("ADMINA_ENGINE", "auto")
    _start(monkeypatch)


def test_the_error_message(monkeypatch, tmp_path, engines):
    pytest.importorskip("admina_core")
    _yaml(tmp_path, PYTHON_ONLY["custom_patterns"] + PYTHON_ONLY["disabled_categories"])
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    with pytest.raises(engines.EngineSelectionError) as caught:
        engines.get_firewall()
    assert str(caught.value) == (
        "ADMINA_ENGINE=rust, but admina.yaml sets agent_security.firewall.custom_patterns, "
        "agent_security.firewall.disabled_categories, which only the Python firewall "
        "applies: remove them, or set ADMINA_ENGINE=python (or auto) to run the Python "
        "firewall"
    )
