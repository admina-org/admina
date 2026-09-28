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

"""Firewall pattern packs (``agent_security.firewall.pattern_packs``).

A pack is a YAML or JSON mapping ``{name, version, description, patterns:
[{id, regex, category, risk_level}]}``, found by name among the entry
points of ``admina.pattern_packs`` and in the directories of
``pattern_pack_dirs`` (or ``ADMINA_PATTERN_PACK_DIRS``). Its patterns are
known as ``<pack>:<id>``. A pack that no source provides, that two sources
provide, or that does not validate stops the firewall from being built
(``PatternPackError``); a pattern over the time budget is a warning, or an
error with ``strict_pack_timing``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from importlib import metadata
from pathlib import Path

import pytest
import yaml

from admina.core.config import load_config
from admina.core.types import RiskLevel
from admina.domains.agent_security import pattern_packs as pp
from admina.domains.agent_security.firewall import InjectionFirewall
from admina.domains.agent_security.pattern_packs import PatternPackError

FIXTURES = Path(__file__).parent / "fixtures" / "pattern_packs"
PLUGIN_DIR = Path(__file__).parent / "fixtures" / "pattern_pack_plugin"
EXAMPLES = Path(__file__).parent.parent / "examples" / "pattern_packs"

_EXAMPLE = yaml.safe_load((FIXTURES / "example-pack.yaml").read_text(encoding="utf-8"))
_SLOW_REGEX = r"\bexample\s+(?:slow\s+)?\s*marker\b"  # quadratic on long whitespace runs


@pytest.fixture(autouse=True)
def _no_pack_dirs_env(monkeypatch):
    monkeypatch.delenv(pp.PATTERN_PACK_DIRS_ENV, raising=False)


def _example(**changes) -> dict:
    data = json.loads(json.dumps(_EXAMPLE))
    data.update(changes)
    return data


def _write(directory: Path, name: str, data, suffix: str = ".yaml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}{suffix}"
    text = json.dumps(data) if suffix == ".json" else yaml.safe_dump(data, sort_keys=False)
    path.write_text(text, encoding="utf-8")
    return path


def _entry_points(monkeypatch, *pairs: tuple[str, str]) -> None:
    """The ``admina.pattern_packs`` group holds *pairs* ``(name, value)``;
    values point into ``fixtures/pattern_pack_plugin``."""
    monkeypatch.syspath_prepend(str(PLUGIN_DIR))
    points = [metadata.EntryPoint(name, value, pp.PATTERN_PACKS_GROUP) for name, value in pairs]
    real = metadata.entry_points

    def fake(**kwargs):
        if kwargs.get("group") == pp.PATTERN_PACKS_GROUP:
            return metadata.EntryPoints(points)
        return real(**kwargs)

    monkeypatch.setattr(metadata, "entry_points", fake)


def _check_example(pack: pp.PatternPack) -> None:
    assert pack.name == "example-pack"
    assert pack.version == "1.0.0"
    assert pack.description == "Example patterns for the tests."
    assert [p.id for p in pack.patterns] == ["internal_notes", "admin_role"]
    assert [p.qualified_id for p in pack.patterns] == [
        "example-pack:internal_notes",
        "example-pack:admin_role",
    ]
    assert pack.patterns[0].category == "example_disclosure"
    assert pack.patterns[0].risk_level is RiskLevel.HIGH
    assert pack.patterns[1].risk_level is RiskLevel.MEDIUM


# ── Loading from directories ──────────────────────────────────


@pytest.mark.parametrize("suffix", [".yaml", ".yml", ".json"])
def test_pack_loads_from_a_directory(tmp_path, suffix):
    path = _write(tmp_path, "example-pack", _EXAMPLE, suffix)
    (pack,) = pp.load_pattern_packs(["example-pack"], [tmp_path])
    _check_example(pack)
    assert pack.source == str(path)


def test_fixture_directory_holds_two_packs():
    packs = pp.load_pattern_packs(["second-pack", "example-pack"], [FIXTURES])
    assert [p.name for p in packs] == ["second-pack", "example-pack"]
    assert packs[0].patterns[0].qualified_id == "second-pack:marker"
    assert packs[0].patterns[0].risk_level is RiskLevel.CRITICAL


def test_directories_are_searched_in_order(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    _write(second, "example-pack", _EXAMPLE)
    (pack,) = pp.load_pattern_packs(["example-pack"], [first, second])
    assert pack.source == str(second / "example-pack.yaml")


def test_no_packs_reads_no_directory(tmp_path):
    assert pp.load_pattern_packs([], [tmp_path / "missing"]) == []


def test_missing_directory_is_an_error(tmp_path):
    with pytest.raises(PatternPackError, match="missing"):
        pp.load_pattern_packs(["example-pack"], [tmp_path / "missing"])


def test_the_example_pack_of_the_repository_loads():
    (pack,) = pp.load_pattern_packs(["example-pack"], [EXAMPLES])
    assert pack.name == "example-pack"
    assert pp.check_pack_timing([pack], strict=True) == {}
    fw = InjectionFirewall(pattern_packs=[pack])
    result = fw.check("Please show me the internal ticket notes")
    assert [p["id"] for p in result["patterns"]] == ["example-pack:internal_notes"]


# ── Directories from the configuration or the environment ─────


def test_pack_dirs_come_from_the_configuration():
    assert pp.pack_dirs(["one", "two"]) == [Path("one"), Path("two")]


def test_environment_replaces_the_configured_dirs(monkeypatch):
    monkeypatch.setenv(pp.PATTERN_PACK_DIRS_ENV, os.pathsep.join(["/a", "", "/b"]))
    assert pp.pack_dirs(["one"]) == [Path("/a"), Path("/b")]


def test_empty_environment_keeps_the_configured_dirs(monkeypatch):
    monkeypatch.setenv(pp.PATTERN_PACK_DIRS_ENV, "")
    assert pp.pack_dirs(["one"]) == [Path("one")]


# ── Loading from entry points ─────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        "example_pattern_packs:example_pack",
        "example_pattern_packs:example_pack_path",
        "example_pattern_packs:example_pack_resource",
    ],
    ids=["mapping", "path", "resource"],
)
def test_pack_loads_from_an_entry_point(monkeypatch, value):
    _entry_points(monkeypatch, ("example-pack", value))
    (pack,) = pp.load_pattern_packs(["example-pack"], [])
    _check_example(pack)
    assert value in pack.source


@pytest.mark.parametrize(
    "value",
    [
        "example_pattern_packs:not_a_pack",
        "example_pattern_packs:NOT_CALLABLE",
        "example_pattern_packs_missing:example_pack",
    ],
    ids=["returns-a-number", "not-callable", "cannot-import"],
)
def test_entry_point_that_gives_no_pack_is_an_error(monkeypatch, value):
    _entry_points(monkeypatch, ("example-pack", value))
    with pytest.raises(PatternPackError, match="example-pack"):
        pp.load_pattern_packs(["example-pack"], [])


def test_same_entry_point_twice_is_one_source(monkeypatch):
    value = "example_pattern_packs:example_pack"
    _entry_points(monkeypatch, ("example-pack", value), ("example-pack", value))
    (pack,) = pp.load_pattern_packs(["example-pack"], [])
    assert pack.name == "example-pack"


# ── Unknown names, several sources ────────────────────────────


def test_unknown_pack_lists_the_available_packs(monkeypatch, tmp_path):
    _write(tmp_path, "example-pack", _EXAMPLE)
    _write(tmp_path, "second-pack", _example(name="second-pack"), ".json")
    (tmp_path / "notes.txt").write_text("not a pack")
    _entry_points(monkeypatch, ("entry-pack", "example_pattern_packs:example_pack"))
    with pytest.raises(PatternPackError) as excinfo:
        pp.load_pattern_packs(["missing-pack"], [tmp_path])
    message = str(excinfo.value)
    assert "missing-pack" in message
    assert "available: entry-pack, example-pack, second-pack" in message


def test_unknown_pack_without_sources(tmp_path):
    with pytest.raises(PatternPackError, match=r"available: \(none\)"):
        pp.load_pattern_packs(["missing-pack"], [tmp_path])


def test_same_name_in_two_directories_is_an_error(tmp_path):
    one = _write(tmp_path / "one", "example-pack", _EXAMPLE)
    two = _write(tmp_path / "two", "example-pack", _EXAMPLE, ".json")
    with pytest.raises(PatternPackError) as excinfo:
        pp.load_pattern_packs(["example-pack"], [tmp_path / "one", tmp_path / "two"])
    assert str(one) in str(excinfo.value) and str(two) in str(excinfo.value)


def test_same_name_twice_in_one_directory_is_an_error(tmp_path):
    _write(tmp_path, "example-pack", _EXAMPLE, ".yaml")
    _write(tmp_path, "example-pack", _EXAMPLE, ".yml")
    with pytest.raises(PatternPackError, match="more than one source"):
        pp.load_pattern_packs(["example-pack"], [tmp_path])


def test_same_name_in_a_directory_and_an_entry_point_is_an_error(monkeypatch, tmp_path):
    _write(tmp_path, "example-pack", _EXAMPLE)
    _entry_points(monkeypatch, ("example-pack", "example_pattern_packs:example_pack"))
    with pytest.raises(PatternPackError, match="more than one source"):
        pp.load_pattern_packs(["example-pack"], [tmp_path])


def test_same_name_in_two_entry_points_is_an_error(monkeypatch):
    _entry_points(
        monkeypatch,
        ("example-pack", "example_pattern_packs:example_pack"),
        ("example-pack", "example_pattern_packs:example_pack_path"),
    )
    with pytest.raises(PatternPackError, match="more than one source"):
        pp.load_pattern_packs(["example-pack"], [])


def test_pack_listed_twice_is_an_error(tmp_path):
    _write(tmp_path, "example-pack", _EXAMPLE)
    with pytest.raises(PatternPackError, match="more than once"):
        pp.load_pattern_packs(["example-pack", "example-pack"], [tmp_path])


@pytest.mark.parametrize("name", ["../example-pack", "Example-Pack", "-pack", "", "a b"])
def test_invalid_pack_name_is_an_error(tmp_path, name):
    with pytest.raises(PatternPackError, match="pack name"):
        pp.load_pattern_packs([name], [tmp_path])


# ── Schema ────────────────────────────────────────────────────

_PATTERN = _EXAMPLE["patterns"][0]

_SCHEMA_ERRORS = [
    ("not-a-mapping", ["a", "b"], "(pack)"),
    ("no-name", {k: v for k, v in _EXAMPLE.items() if k != "name"}, "name"),
    ("bad-name", _example(name="Example Pack"), "name"),
    ("other-name", _example(name="other-pack"), "name"),
    ("no-version", {k: v for k, v in _EXAMPLE.items() if k != "version"}, "version"),
    ("number-version", _example(version=1.0), "version"),
    ("empty-version", _example(version=""), "version"),
    ("bad-description", _example(description=["x"]), "description"),
    ("no-patterns", {k: v for k, v in _EXAMPLE.items() if k != "patterns"}, "patterns"),
    ("empty-patterns", _example(patterns=[]), "patterns"),
    ("patterns-not-a-list", _example(patterns={"id": "x"}), "patterns"),
    ("pattern-not-a-mapping", _example(patterns=["x"]), "patterns[0]"),
    (
        "no-id",
        _example(patterns=[{k: v for k, v in _PATTERN.items() if k != "id"}]),
        "patterns[0].id",
    ),
    ("bad-id", _example(patterns=[dict(_PATTERN, id="Bad Id")]), "patterns[0].id"),
    ("colon-id", _example(patterns=[dict(_PATTERN, id="a:b")]), "patterns[0].id"),
    ("duplicate-id", _example(patterns=[_PATTERN, dict(_PATTERN)]), "patterns[1].id"),
    (
        "no-regex",
        _example(patterns=[{k: v for k, v in _PATTERN.items() if k != "regex"}]),
        "patterns[0].regex",
    ),
    ("bad-regex", _example(patterns=[dict(_PATTERN, regex="(unclosed")]), "patterns[0].regex"),
    ("number-regex", _example(patterns=[dict(_PATTERN, regex=5)]), "patterns[0].regex"),
    ("empty-regex", _example(patterns=[dict(_PATTERN, regex="")]), "patterns[0].regex"),
    (
        "bad-category",
        _example(patterns=[dict(_PATTERN, category="Bad Category")]),
        "patterns[0].category",
    ),
    (
        "bad-risk",
        _example(patterns=[dict(_PATTERN, risk_level="extreme")]),
        "patterns[0].risk_level",
    ),
    (
        "upper-risk",
        _example(patterns=[dict(_PATTERN, risk_level="HIGH")]),
        "patterns[0].risk_level",
    ),
    ("extra-key", _example(extra=1), "extra"),
    ("extra-pattern-key", _example(patterns=[dict(_PATTERN, extra=1)]), "patterns[0].extra"),
]


@pytest.mark.parametrize(
    "data,key_path", [(d, k) for _, d, k in _SCHEMA_ERRORS], ids=[i for i, _, _ in _SCHEMA_ERRORS]
)
@pytest.mark.parametrize("suffix", [".yaml", ".json"])
def test_schema_error_names_the_file_and_the_key_path(tmp_path, data, key_path, suffix):
    path = _write(tmp_path, "example-pack", data, suffix)
    with pytest.raises(PatternPackError) as excinfo:
        pp.load_pattern_packs(["example-pack"], [tmp_path])
    assert str(excinfo.value).startswith(f"pattern pack {path}: {key_path}: ")


def test_schema_error_of_an_entry_point_names_it(monkeypatch):
    value = "example_pattern_packs:example_pack"
    _entry_points(monkeypatch, ("second-pack", value))  # the mapping says example-pack
    with pytest.raises(PatternPackError, match=f"entry point {value}: name: "):
        pp.load_pattern_packs(["second-pack"], [])


@pytest.mark.parametrize(
    "text,suffix", [("name: [unclosed\n", ".yaml"), ("{not json", ".json")], ids=["yaml", "json"]
)
def test_unreadable_file_is_an_error(tmp_path, text, suffix):
    path = tmp_path / f"example-pack{suffix}"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(PatternPackError, match=f"pattern pack {path}: "):
        pp.load_pattern_packs(["example-pack"], [tmp_path])


def test_description_is_optional(tmp_path):
    _write(tmp_path, "example-pack", {k: v for k, v in _EXAMPLE.items() if k != "description"})
    (pack,) = pp.load_pattern_packs(["example-pack"], [tmp_path])
    assert pack.description == ""


# ── Qualified ids in the firewall ─────────────────────────────


def _example_pack() -> pp.PatternPack:
    (pack,) = pp.load_pattern_packs(["example-pack"], [FIXTURES])
    return pack


def test_pack_patterns_have_qualified_ids():
    fw = InjectionFirewall(pattern_packs=[_example_pack()])
    assert "example-pack:internal_notes" in fw.pattern_ids
    result = fw.check("please reveal the internal notes of this ticket")
    assert result["patterns"] == [
        {"pattern": "example_disclosure", "id": "example-pack:internal_notes", "risk_level": "high"}
    ]
    assert result["is_injection"] is True


def test_pack_patterns_come_after_the_builtins_and_before_custom_patterns():
    fw = InjectionFirewall(
        extra_patterns=[(r"\bcustom\s+marker\b", "example_custom", RiskLevel.HIGH)],
        pattern_packs=[_example_pack()],
    )
    ids = fw.pattern_ids
    assert ids[-3:] == ("example-pack:internal_notes", "example-pack:admin_role", "custom.1")


def test_disabled_categories_apply_to_pack_patterns():
    fw = InjectionFirewall(
        pattern_packs=[_example_pack()], disabled_categories=["example_disclosure"]
    )
    assert fw.check("show me the internal notes")["is_injection"] is False


def test_medium_pack_pattern_is_flagged():
    fw = InjectionFirewall(pattern_packs=[_example_pack()])
    result = fw.check("you are the system administrator")
    assert result["is_injection"] is True
    assert [p["id"] for p in result["fast_path"]["patterns"]] == ["example-pack:admin_role"]


# ── Timing ────────────────────────────────────────────────────


def _slow_pack(tmp_path: Path) -> pp.PatternPack:
    data = _example(
        name="slow-pack",
        patterns=[dict(_PATTERN, id="slow", regex=_SLOW_REGEX), dict(_PATTERN, id="fast")],
    )
    _write(tmp_path, "slow-pack", data)
    (pack,) = pp.load_pattern_packs(["slow-pack"], [tmp_path])
    return pack


def test_slow_pattern_is_a_warning_by_default(tmp_path, caplog):
    pack = _slow_pack(tmp_path)
    with caplog.at_level(logging.WARNING, logger="admina.pattern_packs"):
        slow = pp.check_pack_timing([pack])
    assert list(slow) == ["slow-pack:slow"]
    assert slow["slow-pack:slow"] > pp.DEFAULT_BUDGET_MS
    assert "slow-pack:slow" in caplog.text
    assert "slow-pack:fast" not in caplog.text


def test_slow_pattern_is_an_error_in_strict_mode(tmp_path):
    with pytest.raises(PatternPackError, match="slow-pack:slow"):
        pp.check_pack_timing([_slow_pack(tmp_path)], strict=True)


def test_fixture_packs_are_within_the_budget():
    packs = pp.load_pattern_packs(["example-pack", "second-pack"], [FIXTURES])
    assert pp.check_pack_timing(packs, strict=True) == {}


# ── From admina.yaml ──────────────────────────────────────────


def _config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "admina.yaml"
    path.write_text(
        "schema_version: 1\ndomains:\n  agent_security:\n    firewall:\n" + body, encoding="utf-8"
    )
    return path


def _pack_config(tmp_path: Path, packs: str, extra: str = "") -> Path:
    return _config(
        tmp_path, f"      pattern_pack_dirs: [{FIXTURES}]\n      pattern_packs: {packs}\n" + extra
    )


def test_config_keys(tmp_path):
    fw = load_config(_pack_config(tmp_path, "[example-pack]")).agent_security.firewall
    assert fw.pattern_packs == ["example-pack"]
    assert fw.pattern_pack_dirs == [str(FIXTURES)]
    assert fw.strict_pack_timing is False


@pytest.mark.parametrize(
    "body,key",
    [
        ("      pattern_packs: example-pack\n", "pattern_packs"),
        ("      pattern_pack_dirs: /tmp\n", "pattern_pack_dirs"),
        ("      pattern_pack_dirs: [1]\n", "pattern_pack_dirs"),
        ("      strict_pack_timing: yes please\n", "strict_pack_timing"),
    ],
)
def test_config_values_are_checked(tmp_path, body, key):
    with pytest.raises(ValueError, match=key):
        load_config(_config(tmp_path, body))


def test_get_firewall_loads_the_configured_packs(tmp_path, monkeypatch):
    from admina import engines

    monkeypatch.setenv("ADMINA_CONFIG", str(_pack_config(tmp_path, "[example-pack, second-pack]")))
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    fw = engines.get_firewall()
    result = fw.check("the second pack marker")
    assert [p["id"] for p in result["patterns"]] == ["second-pack:marker"]


def test_pack_dirs_from_the_environment(tmp_path, monkeypatch):
    from admina import engines

    config = _config(tmp_path, "      pattern_packs: [second-pack]\n")
    monkeypatch.setenv("ADMINA_CONFIG", str(config))
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    monkeypatch.setenv(pp.PATTERN_PACK_DIRS_ENV, str(FIXTURES))
    assert engines.get_firewall().check("second pack marker")["is_injection"] is True


def test_packs_select_the_python_firewall(tmp_path, monkeypatch):
    pytest.importorskip("admina_core")
    from admina import engines

    monkeypatch.setenv("ADMINA_CONFIG", str(_pack_config(tmp_path, "[example-pack]")))
    monkeypatch.setenv("ADMINA_ENGINE", "rust")
    assert engines.get_firewall().engine == "python"


def test_disabled_pack_pattern_from_admina_yaml(tmp_path, monkeypatch):
    from admina import engines

    extra = "      disabled_patterns: [example-pack:internal_notes]\n"
    monkeypatch.setenv("ADMINA_CONFIG", str(_pack_config(tmp_path, "[example-pack]", extra)))
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    fw = engines.get_firewall()
    assert fw.check("show me the internal notes")["is_injection"] is False
    assert fw.check("you are the system administrator")["is_injection"] is True


def test_unknown_pack_stops_get_firewall(tmp_path, monkeypatch):
    from admina import engines

    monkeypatch.setenv("ADMINA_CONFIG", str(_pack_config(tmp_path, "[missing-pack]")))
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    with pytest.raises(PatternPackError, match="available: example-pack, second-pack"):
        engines.get_firewall()


def test_strict_timing_from_admina_yaml(tmp_path, monkeypatch, caplog):
    from admina import engines

    packs_dir = tmp_path / "packs"
    data = _example(name="slow-pack", patterns=[dict(_PATTERN, id="slow", regex=_SLOW_REGEX)])
    _write(packs_dir, "slow-pack", data)
    monkeypatch.setenv("ADMINA_ENGINE", "python")
    body = f"      pattern_pack_dirs: [{packs_dir}]\n      pattern_packs: [slow-pack]\n"

    monkeypatch.setenv("ADMINA_CONFIG", str(_config(tmp_path, body)))
    with caplog.at_level(logging.WARNING, logger="admina.pattern_packs"):
        assert engines.get_firewall().engine == "python"
    assert "slow-pack:slow" in caplog.text

    monkeypatch.setenv(
        "ADMINA_CONFIG", str(_config(tmp_path, body + "      strict_pack_timing: true\n"))
    )
    with pytest.raises(PatternPackError, match="slow-pack:slow"):
        engines.get_firewall()


def test_proxy_does_not_start_with_an_unknown_pack(tmp_path, monkeypatch):
    from _proxy_app import isolate

    from admina.proxy import main as proxy_main

    isolate(monkeypatch)
    monkeypatch.setenv("ADMINA_CONFIG", str(_pack_config(tmp_path, "[missing-pack]")))
    monkeypatch.setenv("ADMINA_ENGINE", "python")

    async def go() -> None:
        async with proxy_main.lifespan(proxy_main.app):
            pass

    with pytest.raises(PatternPackError, match="missing-pack"):
        asyncio.run(go())
