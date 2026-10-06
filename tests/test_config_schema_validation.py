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

"""admina.yaml is checked against its schema (``schema_version: 1``).

A value of the wrong type is an error, with the path of its key, whenever
the file is loaded: :func:`load_config` raises :class:`ConfigSchemaError`
and the proxy does not start. A key the schema does not know is reported
by :func:`check_config`: the proxy logs it as a warning at startup, and
``ADMINA_CONFIG_STRICT=true`` makes it an error. An empty value (null) is
not checked. ``admina.yaml.example`` and the ``admina init`` template
validate.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import textwrap
from pathlib import Path

import pytest

from admina.core.config import (
    ConfigFileError,
    ConfigSchemaError,
    check_config,
    config_path,
    load_config,
)

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "admina.yaml.example"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name in ("ADMINA_CONFIG", "ADMINA_ENGINE", "ADMINA_PII_ENGINE", "ADMINA_PII_MASK_STYLE"):
        monkeypatch.delenv(name, raising=False)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "admina.yaml"
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


# ── Files that must validate ─────────────────────────────────


def test_the_example_validates():
    check = check_config(EXAMPLE, strict=True)
    assert check.unknown == ()
    assert check.path == EXAMPLE
    load_config(EXAMPLE)


@pytest.mark.parametrize(
    "enabled", list(itertools.product([False, True], repeat=4)), ids=lambda flags: str(flags)
)
def test_the_init_template_validates(tmp_path, enabled):
    from admina.cli.main import AVAILABLE_DOMAINS, _jinja_env

    domains = dict(zip(AVAILABLE_DOMAINS, enabled, strict=True))
    text = (
        _jinja_env()
        .get_template("admina.yaml.j2")
        .render(project_name="example", domains=domains, admina_version="0")
    )
    path = tmp_path / "admina.yaml"
    path.write_text(text, encoding="utf-8")
    assert check_config(path, strict=True).unknown == ()
    load_config(path)


def test_keys_of_this_release_validate(tmp_path):
    path = _write(
        tmp_path,
        """\
        schema_version: 1
        domains:
          agent_security:
            firewall:
              heuristic_threshold: 1
              allowed_tags: [source]
              custom_patterns:
                - regex: "\\\\bexample\\\\b"
                  category: example
                  risk_level: high
              disabled_categories: [tool_abuse]
              disabled_patterns: [tool_abuse.en.1]
              pattern_packs: []
              pattern_pack_dirs: []
              strict_pack_timing: false
            egress:
              enabled: true
              surfaces: [mcp, gateway]
              fanin: {window_seconds: 60, min_agents: 2}
              quarantine_ttl_seconds: 60
          compliance:
            forensic: {backend: filesystem, base_dir: /var/lib/admina/forensic}
        gateway:
          upstreams:
            main: {url: "http://main.upstream.test/v1", api_key_file: /run/secrets/key}
            util: {url: "http://util.upstream.test/v1"}
          default_upstream: main
          stream_mode: governed
          prescan_tags: [source]
          prescan_rulesets: []
        pii_engine: presidio
        pii_mask_style: omissis
        presidio:
          nlp_models: {it: blank}
        plugins: [example_plugin]
        plugin_config:
          example-guard: {threshold: 0.8, nested: {anything: [1, 2]}}
        """,
    )
    assert check_config(path, strict=True).unknown == ()


def test_free_form_blocks_are_not_checked(tmp_path):
    path = _write(
        tmp_path,
        """\
        domains:
          agent_security:
            domains:
              guardrailsai: {enabled: false, anything: [1]}
            firewall:
              custom_patterns:
                - regex: example
                  note: entries are checked when the firewall is built
        integrations:
          example: {enabled: true, whatever: 1}
        plugin_config:
          example: [1, 2, 3]
        """,
    )
    assert check_config(path, strict=True).unknown == ()


def test_empty_values_are_not_checked(tmp_path):
    path = _write(
        tmp_path,
        """\
        schema_version: 1
        domains:
          agent_security:
            firewall:
              custom_patterns:
              disabled_categories:
            egress:
              surfaces:
          compliance:
            forensic:
        gateway:
        pii_mask_style:
        """,
    )
    assert check_config(path, strict=True).unknown == ()
    load_config(path)


def test_no_file_is_nothing_to_check():
    assert config_path() is None
    check = check_config()
    assert check.path is None
    assert check.unknown == ()


def test_config_path_is_the_file_load_config_reads(monkeypatch, tmp_path):
    cwd_file = _write(tmp_path, "schema_version: 1\n")
    assert config_path() == cwd_file
    named = tmp_path / "named" / "admina.yaml"
    named.parent.mkdir()
    named.write_text("schema_version: 1\n", encoding="utf-8")
    monkeypatch.setenv("ADMINA_CONFIG", str(named))
    assert config_path() == named


# ── Unknown keys ─────────────────────────────────────────────


TYPO = """\
schema_version: 1
domains:
  agent_security:
    firewal:
      custom_patterns: []
"""


def test_a_typo_key_is_reported_with_its_path(tmp_path):
    path = _write(tmp_path, TYPO)
    assert check_config(path).unknown == ("domains.agent_security.firewal",)
    load_config(path)  # not an error when the file is loaded


def test_a_typo_key_is_an_error_in_strict_mode(tmp_path):
    path = _write(tmp_path, TYPO)
    with pytest.raises(ConfigSchemaError, match=r"domains\.agent_security\.firewal\b"):
        check_config(path, strict=True)


@pytest.mark.parametrize(
    ("text", "unknown"),
    [
        ("dashbord: {enabled: true}\n", "dashbord"),
        (
            "domains:\n  agent_security:\n    firewall:\n      disabled_pattern: []\n",
            "domains.agent_security.firewall.disabled_pattern",
        ),
        (
            "gateway:\n  upstreams:\n    main: {url: http://u.test/v1, api_key: x}\n",
            "gateway.upstreams.main.api_key",
        ),
        (
            "alert_channels:\n  - type: webhook\n    uri: https://hooks.test\n",
            "alert_channels[0].uri",
        ),
        ("presidio:\n  models: {it: blank}\n", "presidio.models"),
    ],
    ids=["top-level", "firewall", "upstream-route", "alert-channel", "presidio"],
)
def test_unknown_keys_anywhere(tmp_path, text, unknown):
    path = _write(tmp_path, text)
    assert check_config(path).unknown == (unknown,)


def test_every_unknown_key_is_listed_once(tmp_path):
    path = _write(tmp_path, "zeta: 1\nalpha: 2\ndomains:\n  beta: {}\n")
    assert check_config(path).unknown == ("alpha", "domains.beta", "zeta")


# ── Wrong types ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            "domains:\n  agent_security:\n    loop_breaker:\n      window_size: ten\n",
            "domains.agent_security.loop_breaker.window_size: must be an integer",
        ),
        (
            "domains:\n  agent_security:\n    proxy:\n      port: true\n",
            "domains.agent_security.proxy.port: must be an integer",
        ),
        (
            "domains:\n  agent_security:\n    firewall:\n      heuristic_threshold: high\n",
            "domains.agent_security.firewall.heuristic_threshold: "
            "must be a finite number greater than 0",
        ),
        (
            "domains:\n  agent_security:\n    firewall:\n      enabled: sometimes\n",
            "domains.agent_security.firewall.enabled: must be true or false",
        ),
        (
            "domains:\n  agent_security:\n    firewall: [custom_patterns]\n",
            "domains.agent_security.firewall: must be a mapping",
        ),
        (
            "domains:\n  agent_security:\n    firewall:\n      pattern_packs: example-pack\n",
            "domains.agent_security.firewall.pattern_packs: must be a list of strings",
        ),
        (
            "domains:\n  agent_security:\n    egress:\n      allow: 5\n",
            "domains.agent_security.egress.allow: must be a list of strings",
        ),
        ('dashboard: {port: "3000"}\n', "dashboard.port: must be an integer"),
        ("pii_engine: [spacy-regex]\n", "pii_engine: must be a string"),
        ("plugins: example_plugin\n", "plugins: must be a list of strings"),
        ("alert_channels: {type: log}\n", "alert_channels: must be a list of mappings"),
        ("alert_channels: [log]\n", "alert_channels: must be a list of mappings"),
        (
            "domains:\n  agent_security:\n    firewall:\n      custom_patterns: {regex: x}\n",
            "domains.agent_security.firewall.custom_patterns: must be a list",
        ),
        ("schema_version: one\n", "schema_version: must be an integer"),
    ],
)
def test_a_wrong_type_is_an_error_with_the_key_path(tmp_path, text, message):
    path = _write(tmp_path, text)
    with pytest.raises(ConfigSchemaError, match="admina.yaml") as caught:
        load_config(path)
    assert message in str(caught.value)
    assert isinstance(caught.value, ValueError)
    with pytest.raises(ConfigSchemaError):
        check_config(path)


def test_every_wrong_type_is_listed(tmp_path):
    path = _write(
        tmp_path,
        "pii_engine: 1\ndomains:\n  agent_security:\n    proxy: {port: x, upstream: 2}\n",
    )
    with pytest.raises(ConfigSchemaError) as caught:
        load_config(path)
    message = str(caught.value)
    for key in (
        "pii_engine",
        "domains.agent_security.proxy.port",
        "domains.agent_security.proxy.upstream",
    ):
        assert f"{key}: must be" in message


def test_a_named_file_with_a_wrong_type_is_a_config_file_error(monkeypatch, tmp_path):
    named = tmp_path / "named.yaml"
    named.write_text("pii_engine: 1\n", encoding="utf-8")
    monkeypatch.setenv("ADMINA_CONFIG", str(named))
    with pytest.raises(ConfigFileError, match="pii_engine: must be a string"):
        load_config()


@pytest.mark.parametrize(
    "text",
    [
        "gateway:\n  upstreams:\n    main: {url: 5}\n",
        "gateway:\n  prescan_tags: source\n",
        "presidio:\n  nlp_models: [it]\n",
    ],
)
def test_gateway_and_presidio_values_are_left_to_their_readers(tmp_path, text):
    # Their readers name the key and stop the proxy (gateway) or the
    # Presidio engine (presidio).
    path = _write(tmp_path, text)
    config = load_config(path)
    assert config.gateway.errors or config.presidio.errors
    assert check_config(path, strict=True).unknown == ()


def test_integers_are_numbers_and_quoted_version_is_accepted(tmp_path):
    path = _write(
        tmp_path,
        'schema_version: "1"\n'
        "domains:\n  agent_security:\n    loop_breaker: {similarity_threshold: 1}\n",
    )
    assert check_config(path, strict=True).unknown == ()


# ── In the SDK ───────────────────────────────────────────────
#
# The engine factories read the file that load_config reads and raise its
# error, whatever key it names: a wrong type elsewhere in the file does not
# make them use their defaults for the keys that are right.

SDK_FILE = """\
    pii_engine: presidio
    pii_mask_style: omissis
    dashboard:
      port: "3000"
    """


@pytest.mark.parametrize(
    "factory",
    ["pii_mask_style", "get_pii_engine", "get_pii_scanner", "get_egress_policy", "get_firewall"],
)
def test_engine_factories_raise_on_a_wrong_type(tmp_path, factory):
    import admina.engines as engines

    _write(tmp_path, SDK_FILE)
    with pytest.raises(ValueError, match=r"dashboard\.port: must be an integer") as caught:
        getattr(engines, factory)()
    # By name: other tests import the package again.
    assert type(caught.value).__name__ == "ConfigSchemaError"


def test_governed_data_raises_on_a_wrong_type(tmp_path):
    from admina.sdk.governed_data import BaseDataConnector, GovernedData

    class _Connector(BaseDataConnector):
        async def ingest(self, source, **kwargs):
            return {"doc_count": 1, "chunk_count": 1}

        async def query(self, query, **kwargs):
            return []

        @property
        def name(self) -> str:
            return "example"

    _write(tmp_path, SDK_FILE)
    data = GovernedData(connector=_Connector(), audit=False)
    with pytest.raises(ValueError, match=r"dashboard\.port: must be an integer") as caught:
        asyncio.run(data.ingest("Contact: someone@example.com"))
    assert type(caught.value).__name__ == "ConfigSchemaError"


def test_engine_factories_read_a_valid_file(tmp_path):
    import admina.engines as engines

    _write(tmp_path, "pii_mask_style: omissis\ndashboard:\n  port: 3000\n")
    assert engines.pii_mask_style() == "omissis"


def test_engine_factories_use_their_defaults_when_the_file_cannot_be_read(monkeypatch):
    import admina.engines as engines
    from admina.domains.agent_security.egress import analyze

    def _unreadable(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr("admina.core.config.load_config", _unreadable)
    assert engines.pii_mask_style() == "typed"
    # An empty allowlist: every destination is blocked.
    policy = engines.get_egress_policy()
    assert not policy.evaluate(analyze({"url": "https://example.com"}), "enforce").allowed


# ── At proxy startup ─────────────────────────────────────────


def _start(monkeypatch, **settings) -> None:
    pytest.importorskip("fastapi")
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


def test_startup_warns_about_unknown_keys(monkeypatch, tmp_path, caplog):
    path = _write(tmp_path, TYPO)
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    with caplog.at_level(logging.WARNING):
        _start(monkeypatch)
    warnings = [
        r.getMessage() for r in caplog.records if "domains.agent_security.firewal" in r.getMessage()
    ]
    assert warnings == [
        f"admina.yaml {path}: unknown keys, not read: domains.agent_security.firewal "
        "(ADMINA_CONFIG_STRICT=true makes them an error)"
    ]


def test_startup_fails_on_unknown_keys_in_strict_mode(monkeypatch, tmp_path):
    path = _write(tmp_path, TYPO)
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    with pytest.raises(ValueError, match=r"domains\.agent_security\.firewal\b") as caught:
        _start(monkeypatch, ADMINA_CONFIG_STRICT=True)
    # By name: other tests import the package again.
    assert type(caught.value).__name__ == "ConfigSchemaError"


def test_startup_fails_on_a_wrong_type(monkeypatch, tmp_path):
    _write(tmp_path, "domains:\n  agent_security:\n    egress:\n      allow: 5\n")
    with pytest.raises(ValueError, match="domains.agent_security.egress.allow") as caught:
        _start(monkeypatch)
    assert type(caught.value).__name__ == "ConfigSchemaError"


def test_startup_is_quiet_with_a_valid_file(monkeypatch, tmp_path, caplog):
    path = _write(tmp_path, EXAMPLE.read_text(encoding="utf-8"))
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    with caplog.at_level(logging.WARNING):
        _start(monkeypatch, ADMINA_CONFIG_STRICT=True)
    assert not [r for r in caplog.records if "unknown keys" in r.getMessage()]
