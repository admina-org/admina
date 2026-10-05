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

"""ADMINA_CONFIG names the admina.yaml that Admina loads.

When it is set, exactly that file is read by ``load_config()`` and so by
every reader of it: the firewall overrides, the egress policy, the PII
engine selection and the proxy. A file that cannot be read or parsed is
an error, never a silent fallback to the defaults. When it is unset (or
empty), the search in the current directory and in the package directory
is unchanged.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from _proxy_app import subprocess_env

from admina import engines
from admina.core.config import ConfigFileError, load_config

MARKER = "zebra protocol seven"

NAMED_YAML = textwrap.dedent(
    r"""
    domains:
      agent_security:
        firewall:
          custom_patterns:
            - regex: 'zebra\s+protocol\s+seven'
              category: config_path_marker
              risk_level: high
        egress:
          enabled: true
          read_only_tools: [lookup_named]
    pii_engine: named-engine
    """
)

CWD_YAML = textwrap.dedent(
    """
    domains:
      agent_security:
        egress:
          enabled: true
          read_only_tools: [lookup_cwd]
    pii_engine: cwd-engine
    """
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("ADMINA_CONFIG", "ADMINA_PII_ENGINE", "ADMINA_ENGINE"):
        monkeypatch.delenv(name, raising=False)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def cwd_with_other_yaml(tmp_path, monkeypatch) -> Path:
    """A working directory holding an admina.yaml that must not be read."""
    cwd = tmp_path / "cwd"
    _write(cwd / "admina.yaml", CWD_YAML)
    monkeypatch.chdir(cwd)
    return cwd


@pytest.fixture
def named_yaml(tmp_path) -> Path:
    return _write(tmp_path / "etc" / "admina" / "gateway.yaml", NAMED_YAML)


# ── ADMINA_CONFIG set: exactly that file ──────────────────────


class TestNamedFileIsLoaded:
    def test_load_config_reads_the_named_file(self, monkeypatch, cwd_with_other_yaml, named_yaml):
        monkeypatch.setenv("ADMINA_CONFIG", str(named_yaml))
        cfg = load_config()
        assert cfg.pii_engine == "named-engine"
        assert cfg.agent_security.egress.read_only_tools == ["lookup_named"]

    def test_relative_path_is_resolved_from_the_working_directory(
        self, monkeypatch, cwd_with_other_yaml
    ):
        _write(cwd_with_other_yaml / "conf" / "admina.yaml", NAMED_YAML)
        monkeypatch.setenv("ADMINA_CONFIG", "conf/admina.yaml")
        assert load_config().pii_engine == "named-engine"

    def test_firewall_overrides_come_from_the_named_file(
        self, monkeypatch, cwd_with_other_yaml, named_yaml
    ):
        monkeypatch.setenv("ADMINA_CONFIG", str(named_yaml))
        extras, disabled = engines._load_firewall_yaml_overrides()
        assert [(regex, category) for regex, category, _ in extras] == [
            (r"zebra\s+protocol\s+seven", "config_path_marker")
        ]
        assert disabled == []
        firewall = engines.get_firewall()
        assert firewall.engine == "python"
        assert firewall.check(f"please follow the {MARKER} now")["is_injection"] is True

    def test_egress_policy_comes_from_the_named_file(
        self, monkeypatch, cwd_with_other_yaml, named_yaml
    ):
        monkeypatch.setenv("ADMINA_CONFIG", str(named_yaml))
        policy = engines.get_egress_policy()
        assert policy is not None
        assert policy.read_only_tools == frozenset({"lookup_named"})

    def test_egress_disabled_in_the_named_file(self, tmp_path, monkeypatch, cwd_with_other_yaml):
        path = _write(
            tmp_path / "off.yaml",
            "domains:\n  agent_security:\n    egress:\n      enabled: false\n",
        )
        monkeypatch.setenv("ADMINA_CONFIG", str(path))
        assert engines.get_egress_policy() is None

    def test_pii_engine_comes_from_the_named_file(
        self, monkeypatch, cwd_with_other_yaml, named_yaml
    ):
        sentinel = object()
        factories = {**engines._PII_ENGINE_FACTORIES, "named-engine": lambda: sentinel}
        monkeypatch.setattr(engines, "_PII_ENGINE_FACTORIES", factories)
        monkeypatch.setenv("ADMINA_CONFIG", str(named_yaml))
        assert engines.get_pii_engine() is sentinel

    def test_explicit_arguments_still_win(self, tmp_path, monkeypatch, named_yaml):
        other = _write(tmp_path / "other" / "admina.yaml", CWD_YAML)
        monkeypatch.setenv("ADMINA_CONFIG", str(named_yaml))
        assert load_config(yaml_path=other).pii_engine == "cwd-engine"
        assert load_config(search_paths=[other.parent]).pii_engine == "cwd-engine"


# ── ADMINA_CONFIG set but unusable: an error, never the defaults ──


def _unusable_paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "missing": tmp_path / "absent" / "admina.yaml",
        "directory": _write(tmp_path / "dir" / "keep", "x").parent,
        "invalid_yaml": _write(tmp_path / "invalid.yaml", "domains: [unclosed\n"),
        "not_a_mapping": _write(tmp_path / "list.yaml", "- one\n- two\n"),
    }


@pytest.mark.parametrize("case", ["missing", "directory", "invalid_yaml", "not_a_mapping"])
def test_unusable_file_is_an_error(tmp_path, monkeypatch, cwd_with_other_yaml, case):
    path = _unusable_paths(tmp_path)[case]
    monkeypatch.setenv("ADMINA_CONFIG", str(path))
    with pytest.raises(ConfigFileError, match="ADMINA_CONFIG") as excinfo:
        load_config()
    assert str(path) in str(excinfo.value)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="root reads any file")
def test_unreadable_file_is_an_error(tmp_path, monkeypatch, cwd_with_other_yaml):
    path = _write(tmp_path / "locked.yaml", NAMED_YAML)
    path.chmod(0)
    try:
        monkeypatch.setenv("ADMINA_CONFIG", str(path))
        with pytest.raises(ConfigFileError, match="ADMINA_CONFIG"):
            load_config()
    finally:
        path.chmod(0o600)


@pytest.mark.parametrize(
    "loader",
    [
        engines._load_firewall_yaml_overrides,
        engines.get_firewall,
        engines.get_egress_policy,
        engines.get_pii_engine,
    ],
    ids=["firewall_overrides", "firewall", "egress_policy", "pii_engine"],
)
def test_engines_do_not_fall_back_when_the_file_is_missing(
    tmp_path, monkeypatch, cwd_with_other_yaml, loader
):
    # The engines import admina.core.config when called: take the error class
    # from the module they get (another test may have re-imported it).
    from admina.core.config import ConfigFileError

    monkeypatch.setenv("ADMINA_CONFIG", str(tmp_path / "absent.yaml"))
    with pytest.raises(ConfigFileError):
        loader()


def _import_proxy(env_extra: dict[str, str], cwd: Path, code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=cwd,
        env=subprocess_env("ADMINA_", REDIS_URL="", CLICKHOUSE_HOST="", **env_extra),
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_proxy_does_not_start_when_the_file_is_missing(tmp_path, cwd_with_other_yaml):
    missing = tmp_path / "absent.yaml"
    proc = _import_proxy(
        {"ADMINA_CONFIG": str(missing)}, cwd_with_other_yaml, "import admina.proxy.main"
    )
    assert proc.returncode != 0
    assert "ConfigFileError" in proc.stderr
    assert "ADMINA_CONFIG" in proc.stderr
    assert str(missing) in proc.stderr


def test_proxy_loads_the_named_file(named_yaml, cwd_with_other_yaml):
    proc = _import_proxy(
        {"ADMINA_CONFIG": str(named_yaml)},
        cwd_with_other_yaml,
        "from admina.proxy import main; "
        "print(main._admina_config.pii_engine, "
        "main._admina_config.agent_security.egress.read_only_tools)",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "named-engine ['lookup_named']"


# ── ADMINA_CONFIG unset or empty: the 0.12 search ─────────────


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_without_the_variable_the_working_directory_is_searched(
    monkeypatch, cwd_with_other_yaml, value
):
    if value is not None:
        monkeypatch.setenv("ADMINA_CONFIG", value)
    cfg = load_config()
    assert cfg.pii_engine == "cwd-engine"
    assert cfg.agent_security.egress.read_only_tools == ["lookup_cwd"]


def test_without_the_variable_and_without_a_file_the_env_fallback_is_used(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = load_config(search_paths=[tmp_path])
    assert cfg.pii_engine == "spacy-regex"
    assert load_config().pii_engine == "spacy-regex"
