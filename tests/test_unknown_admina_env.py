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

"""ADMINA_* variables that no part of Admina reads are reported at startup.

The proxy logs a warning listing them (process environment and ``.env``
file); with ``ADMINA_CONFIG_STRICT=true`` they stop it. The settings of the
proxy, the variables read by the engines, the SDK, the builtin plugins and
the other components of the stack, and the per-route key variables of the
gateway are known. Variables starting with ``ADMINA_<NAME>_`` are left to a
plugin distribution that registers an entry point ``<name>`` (``-`` read as
``_``) in ``admina.plugins``, ``admina.pii_engines`` or
``admina.pattern_packs``, and ``ADMINA_ENV_ALLOW_PREFIXES`` lists further
prefixes.
"""

from __future__ import annotations

import ast
import asyncio
import logging
import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from admina.proxy.config import Settings
from admina.proxy.env_check import (
    KNOWN_VARIABLES,
    known_variables,
    plugin_prefixes,
    unknown_variables,
)

PACKAGE = Path(__file__).resolve().parents[1] / "admina"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no admina.yaml, no .env


# ── Which variables are unknown ──────────────────────────────


def test_an_unknown_variable_is_reported():
    environ = {"ADMINA_FOO": "1", "ADMINA_ENGINE": "rust", "PATH": "/bin", "HOME": "/root"}
    assert unknown_variables(environ) == ["ADMINA_FOO"]


def test_the_list_is_sorted_and_case_insensitive():
    environ = {"ADMINA_ZETA": "1", "admina_alpha": "1", "admina_api_key": "x"}
    assert unknown_variables(environ) == ["ADMINA_ZETA", "admina_alpha"]


def test_every_proxy_setting_is_known():
    names = set()
    for name, field in Settings.model_fields.items():
        alias = field.validation_alias
        names.add(alias if isinstance(alias, str) else name)
    admina_names = {name for name in names if name.startswith("ADMINA_")}
    assert {"ADMINA_GOVERNANCE_MODE", "ADMINA_GUARD_FAIL_MODE", "ADMINA_API_KEY"} <= admina_names
    assert admina_names <= known_variables()
    assert unknown_variables(dict.fromkeys(admina_names, "1")) == []


def test_the_new_settings_are_known():
    assert {"ADMINA_CONFIG_STRICT", "ADMINA_ENV_ALLOW_PREFIXES"} <= known_variables()


@pytest.mark.parametrize(
    "name",
    [
        "ADMINA_GATEWAY_UPSTREAM_MAIN_API_KEY",
        "ADMINA_GATEWAY_UPSTREAM_MAIN_API_KEY_FILE",
        "ADMINA_GATEWAY_UPSTREAM_UTIL_2_API_KEY_FILE",
    ],
)
def test_per_route_key_variables_are_known(name):
    assert unknown_variables({name: "x"}) == []


def test_a_near_miss_of_a_route_key_is_unknown():
    assert unknown_variables({"ADMINA_GATEWAY_UPSTREAM_MAIN_APIKEY": "x"}) == [
        "ADMINA_GATEWAY_UPSTREAM_MAIN_APIKEY"
    ]


def _variables_read_by_the_package() -> set[str]:
    """Every string constant of the package that is an ADMINA_ name."""
    name = re.compile(r"ADMINA_[A-Z0-9_]*[A-Z0-9]")
    found = set()
    for path in PACKAGE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if name.fullmatch(node.value):
                    found.add(node.value)
    return found


def test_every_variable_the_package_names_is_known():
    names = _variables_read_by_the_package()
    assert len(names) > 40
    assert sorted(names - known_variables()) == []


def test_known_variables_outside_the_settings_are_not_settings():
    settings_names = {
        (field.validation_alias if isinstance(field.validation_alias, str) else name)
        for name, field in Settings.model_fields.items()
    }
    assert not KNOWN_VARIABLES & settings_names


# ── Allowed prefixes ─────────────────────────────────────────


def test_allowed_prefixes_are_not_reported():
    environ = {"ADMINA_OTHER_URL": "x", "ADMINA_OTHERWISE": "x", "ADMINA_FOO": "1"}
    assert unknown_variables(environ, allow_prefixes=["ADMINA_OTHER_", " "]) == [
        "ADMINA_FOO",
        "ADMINA_OTHERWISE",
    ]


def test_plugin_entry_points_register_their_prefix(example_pii_plugin):
    prefixes = plugin_prefixes()
    assert "ADMINA_EXAMPLE_PII_" in prefixes
    assert "ADMINA_FACTORY_PII_" in prefixes
    environ = {"ADMINA_EXAMPLE_PII_MODEL": "x", "ADMINA_EXAMPLE_PIIX": "x"}
    assert unknown_variables(environ, allow_prefixes=prefixes) == ["ADMINA_EXAMPLE_PIIX"]


@pytest.mark.parametrize("group", ["admina.plugins", "admina.pattern_packs"])
def test_entry_points_of_every_plugin_group_register_their_prefix(monkeypatch, group):
    from importlib import metadata

    point = metadata.EntryPoint("example-pack.v2", "example_pkg:loader", group)
    real = metadata.entry_points

    def fake(**kwargs):
        if kwargs.get("group") == group:
            return metadata.EntryPoints([point])
        return real(**kwargs)

    monkeypatch.setattr(metadata, "entry_points", fake)
    assert "ADMINA_EXAMPLE_PACK_V2_" in plugin_prefixes()


# ── At proxy startup ─────────────────────────────────────────


def _start(monkeypatch, **settings) -> None:
    from _proxy_app import isolate
    from fastapi import FastAPI

    from admina.proxy import main as proxy_main

    isolate(monkeypatch)
    for name, value in settings.items():
        monkeypatch.setattr(proxy_main.settings, name, value)

    async def go() -> None:
        async with proxy_main.lifespan(FastAPI()):
            pass

    asyncio.run(go())


def _unknown_warnings(caplog) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING
        and "ADMINA_" in r.getMessage()
        and "not read" in r.getMessage()
    ]


def test_startup_warns_listing_unknown_variables(monkeypatch, caplog):
    monkeypatch.setenv("ADMINA_FOO", "1")
    monkeypatch.setenv("ADMINA_BAR_BAZ", "1")
    with caplog.at_level(logging.WARNING):
        _start(monkeypatch)
    warnings = _unknown_warnings(caplog)
    assert warnings == [
        "ADMINA_* variables not read by Admina: ADMINA_BAR_BAZ, ADMINA_FOO "
        "(ADMINA_CONFIG_STRICT=true makes them an error; ADMINA_ENV_ALLOW_PREFIXES "
        "lists the prefixes of other components)"
    ]


def test_startup_reads_the_dotenv_file_too(monkeypatch, tmp_path, caplog):
    (tmp_path / ".env").write_text("ADMINA_FROM_DOTENV=1\nADMINA_ENGINE=auto\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        _start(monkeypatch)
    warnings = _unknown_warnings(caplog)
    assert len(warnings) == 1
    assert "ADMINA_FROM_DOTENV" in warnings[0]
    assert "ADMINA_ENGINE" not in warnings[0]


def test_startup_fails_in_strict_mode(monkeypatch):
    # The class of the proxy module as imported now (other tests re-import
    # the package).
    from admina.proxy.env_check import UnknownVariablesError

    monkeypatch.setenv("ADMINA_FOO", "1")
    with pytest.raises(UnknownVariablesError, match="ADMINA_FOO") as caught:
        _start(monkeypatch, ADMINA_CONFIG_STRICT=True)
    assert isinstance(caught.value, ValueError)


def test_startup_is_quiet_with_known_and_allowed_variables(monkeypatch, caplog, example_pii_plugin):
    monkeypatch.setenv("ADMINA_ENGINE", "auto")
    monkeypatch.setenv("ADMINA_GATEWAY_UPSTREAM_DEFAULT_API_KEY", "upstream-key-0123456789")
    monkeypatch.setenv("ADMINA_EXAMPLE_PII_MODEL", "x")
    monkeypatch.setenv("ADMINA_OTHER_SERVICE_URL", "http://other.test")
    with caplog.at_level(logging.WARNING):
        _start(
            monkeypatch,
            ADMINA_CONFIG_STRICT=True,
            ADMINA_ENV_ALLOW_PREFIXES="ADMINA_OTHER_SERVICE_",
        )
    assert _unknown_warnings(caplog) == []


def test_startup_never_logs_values(monkeypatch, caplog):
    monkeypatch.setenv("ADMINA_SECRET_TYPO", "value-that-must-not-appear")
    with caplog.at_level(logging.DEBUG):
        _start(monkeypatch)
    assert "value-that-must-not-appear" not in caplog.text
