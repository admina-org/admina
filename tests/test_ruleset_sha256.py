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

"""ruleset_sha256(): the SHA-256 of the canonical form of a firewall ruleset.

The vectors pin ``admina_version`` so they do not move with a version bump;
the Python-engine vectors change when a builtin pattern changes, which is
the point of the hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
from dataclasses import replace

import pytest

import admina
from admina.core.config import AdminaConfig, FirewallConfig, load_config
from admina.core.jcs import canonicalize
from admina.domains.agent_security import firewall as firewall_module
from admina.domains.agent_security.ruleset import ruleset_object, ruleset_sha256

_VERSION = "0.13.0"
_HEX64 = re.compile(r"[0-9a-f]{64}")

_CUSTOM = {
    "regex": r"\bexample\s+secret\s+phrase\b",
    "category": "example_custom",
    "risk_level": "high",
}


def _custom_config() -> FirewallConfig:
    return FirewallConfig(
        custom_patterns=[dict(_CUSTOM)],
        disabled_categories=["tool_abuse"],
        pattern_packs=["example-pack"],
    )


# ── Test vectors ──────────────────────────────────────────────

_RUST_CANONICAL = (
    b'{"admina_version":"0.13.0","builtin":{"admina_core_version":"0.9.3"},'
    b'"custom_patterns":[],"disabled_categories":[],"disabled_patterns":[],"engine":"rust",'
    b'"heuristic_threshold_milli":700,"pattern_packs":[]}'
)
_RUST_VECTOR = "f3302142af311422e4eb8f3821adff008f20caafbb7d1bcff8aacb046613a1c3"
_PYTHON_VECTOR = "3486a8b0056ec3169abf913986fb7f54bbc942f44464c055eae5b65cd9158217"
_PYTHON_CUSTOM_VECTOR = "cf5c6ddf4f808f3fb22255bcad12d06368e38008595de0be66ff15f40e1a3ee2"


def test_rust_vector_canonical_bytes():
    obj = ruleset_object(
        AdminaConfig(), engine="rust", admina_core_version="0.9.3", admina_version=_VERSION
    )
    assert canonicalize(obj) == _RUST_CANONICAL


def test_rust_vector():
    digest = ruleset_sha256(
        AdminaConfig(), engine="rust", admina_core_version="0.9.3", admina_version=_VERSION
    )
    assert digest == hashlib.sha256(_RUST_CANONICAL).hexdigest() == _RUST_VECTOR


def test_python_vector_object():
    obj = ruleset_object(AdminaConfig(), engine="python", admina_version=_VERSION)
    assert obj == {
        "admina_version": _VERSION,
        "engine": "python",
        "builtin": [
            {"regex": regex, "category": category, "risk_level": level.value}
            for regex, category, level in firewall_module.INJECTION_PATTERNS
        ],
        "pattern_packs": [],
        "custom_patterns": [],
        "disabled_categories": [],
        "disabled_patterns": [],
        "heuristic_threshold_milli": 700,
    }


def test_python_vector():
    assert ruleset_sha256(AdminaConfig(), admina_version=_VERSION) == _PYTHON_VECTOR


def test_python_vector_with_custom_patterns():
    obj = ruleset_object(_custom_config(), admina_version=_VERSION)
    assert obj["custom_patterns"] == [_CUSTOM]
    assert obj["disabled_categories"] == ["tool_abuse"]
    assert obj["pattern_packs"] == ["example-pack"]
    assert all(entry["category"] != "tool_abuse" for entry in obj["builtin"])
    assert ruleset_sha256(_custom_config(), admina_version=_VERSION) == _PYTHON_CUSTOM_VECTOR


def test_digest_is_sha256_of_the_canonical_object():
    cfg = _custom_config()
    expected = hashlib.sha256(canonicalize(ruleset_object(cfg))).hexdigest()
    assert ruleset_sha256(cfg) == expected


# ── Shape ─────────────────────────────────────────────────────


@pytest.mark.parametrize("engine", ["python", "rust"])
def test_digest_is_64_lowercase_hex(engine):
    digest = ruleset_sha256(AdminaConfig(), engine=engine, admina_core_version="0.9.3")
    assert _HEX64.fullmatch(digest)


def test_default_version_is_the_installed_admina():
    assert ruleset_object()["admina_version"] == admina.__version__


def test_no_config_means_defaults():
    assert ruleset_sha256() == ruleset_sha256(AdminaConfig())


def test_accepts_the_firewall_section_or_the_whole_config():
    cfg = replace(AdminaConfig(), agent_security=replace(AdminaConfig().agent_security))
    cfg.agent_security.firewall = _custom_config()
    assert ruleset_sha256(cfg) == ruleset_sha256(_custom_config())


def _floats(value) -> list:
    if isinstance(value, float):
        return [value]
    if isinstance(value, dict):
        return [f for v in value.values() for f in _floats(v)]
    if isinstance(value, list):
        return [f for v in value for f in _floats(v)]
    return []


@pytest.mark.parametrize("engine", ["python", "rust"])
def test_no_float_in_the_hashed_object(engine):
    cfg = replace(_custom_config(), heuristic_threshold=0.65)
    obj = ruleset_object(cfg, engine=engine, admina_core_version="0.9.3")
    assert _floats(obj) == []
    assert obj["heuristic_threshold_milli"] == 650


# ── What changes the hash ─────────────────────────────────────


def test_changes_with_a_builtin_pattern(monkeypatch):
    before = ruleset_sha256()
    patterns = list(firewall_module.INJECTION_PATTERNS)
    regex, category, level = patterns[0]
    patterns[0] = (regex + "x", category, level)
    monkeypatch.setattr(firewall_module, "INJECTION_PATTERNS", patterns)
    assert ruleset_sha256() != before


@pytest.mark.parametrize(
    "change",
    [
        {"custom_patterns": [dict(_CUSTOM, regex=r"\bother\s+phrase\b")]},
        {"custom_patterns": [dict(_CUSTOM, category="other_category")]},
        {"custom_patterns": [dict(_CUSTOM, risk_level="medium")]},
        {"custom_patterns": []},
        {"disabled_categories": []},
        {"disabled_categories": ["tool_abuse", "jailbreak"]},
        {"disabled_patterns": ["role_hijack.en.1"]},
        {"disabled_patterns": ["role_hijack.en.1", "role_hijack.en.2"]},
        {"pattern_packs": []},
        {"pattern_packs": ["example-pack", "second-pack"]},
        {"heuristic_threshold": 0.5},
    ],
    ids=[
        "custom-regex",
        "custom-category",
        "custom-risk",
        "no-custom",
        "no-disabled",
        "more-disabled",
        "disabled-id",
        "more-disabled-ids",
        "no-packs",
        "more-packs",
        "threshold",
    ],
)
def test_changes_with_the_configuration(change):
    assert ruleset_sha256(replace(_custom_config(), **change)) != ruleset_sha256(_custom_config())


def test_disabled_patterns_are_sorted_without_duplicates():
    a = replace(_custom_config(), disabled_patterns=["tool_abuse.en.2", "jailbreak.en.1"] * 2)
    b = replace(_custom_config(), disabled_patterns=["jailbreak.en.1", "tool_abuse.en.2"])
    assert ruleset_object(a)["disabled_patterns"] == ["jailbreak.en.1", "tool_abuse.en.2"]
    assert ruleset_sha256(a) == ruleset_sha256(b)


def test_disabled_patterns_keep_the_builtin_list():
    """The builtin list leaves out disabled categories only; disabled ids
    are listed in ``disabled_patterns``."""
    cfg = FirewallConfig(disabled_patterns=["role_hijack.en.1"])
    assert ruleset_object(cfg)["builtin"] == ruleset_object(FirewallConfig())["builtin"]


def test_changes_with_the_admina_version():
    assert ruleset_sha256(admina_version="0.13.0") != ruleset_sha256(admina_version="0.13.1")


def test_changes_with_the_rust_core_version():
    one = ruleset_sha256(engine="rust", admina_core_version="0.9.3")
    two = ruleset_sha256(engine="rust", admina_core_version="0.9.4")
    assert one != two


def test_python_and_rust_engines_differ():
    assert ruleset_sha256(engine="python") != ruleset_sha256(
        engine="rust", admina_core_version="0.9.3"
    )


def test_disabled_categories_are_sorted_without_duplicates():
    a = replace(_custom_config(), disabled_categories=["tool_abuse", "jailbreak", "jailbreak"])
    b = replace(_custom_config(), disabled_categories=["jailbreak", "tool_abuse"])
    assert ruleset_object(a)["disabled_categories"] == ["jailbreak", "tool_abuse"]
    assert ruleset_sha256(a) == ruleset_sha256(b)


def test_disabled_category_removes_its_builtins():
    cfg = FirewallConfig(disabled_categories=["jailbreak"])
    builtin = ruleset_object(cfg)["builtin"]
    expected = [p for p in firewall_module.INJECTION_PATTERNS if p[1] != "jailbreak"]
    assert len(builtin) == len(expected) < len(firewall_module.INJECTION_PATTERNS)


def test_custom_patterns_as_the_firewall_loads_them():
    cfg = FirewallConfig(
        custom_patterns=[
            {"regex": "a\\s+b"},  # category and risk level defaulted
            {"regex": "c\\s+d", "category": "cat", "risk_level": "CRITICAL"},
            {"category": "no-regex"},  # malformed: skipped
            {"regex": "e", "risk_level": "extreme"},  # malformed: skipped
            "not a mapping",  # malformed: skipped
        ]
    )
    assert ruleset_object(cfg)["custom_patterns"] == [
        {"regex": "a\\s+b", "category": "user_custom", "risk_level": "medium"},
        {"regex": "c\\s+d", "category": "cat", "risk_level": "critical"},
    ]


# ── Arguments ─────────────────────────────────────────────────


def test_unknown_engine_is_rejected():
    with pytest.raises(ValueError):
        ruleset_sha256(engine="java")


def test_rust_engine_uses_the_installed_core_version():
    admina_core = pytest.importorskip("admina_core")
    assert ruleset_object(engine="rust")["builtin"] == {
        "admina_core_version": admina_core.version()
    }


def test_rust_engine_without_core_version_needs_admina_core(monkeypatch):
    monkeypatch.setitem(sys.modules, "admina_core", None)  # import fails
    with pytest.raises(ValueError):
        ruleset_sha256(engine="rust")


@pytest.mark.parametrize("threshold", [True, "0.7", None, float("nan")])
def test_threshold_must_be_a_number(threshold):
    with pytest.raises(ValueError):
        ruleset_sha256(FirewallConfig(heuristic_threshold=threshold))


@pytest.mark.parametrize(
    "change",
    [{"pattern_packs": [1]}, {"disabled_categories": [None]}, {"disabled_patterns": [2]}],
)
def test_names_must_be_strings(change):
    with pytest.raises(ValueError):
        ruleset_sha256(replace(_custom_config(), **change))


# ── From admina.yaml ──────────────────────────────────────────


def test_same_hash_whatever_the_yaml_key_order(tmp_path):
    first = tmp_path / "a.yaml"
    second = tmp_path / "b.yaml"
    first.write_text(
        textwrap.dedent(
            """\
            domains:
              agent_security:
                firewall:
                  heuristic_threshold: 0.7
                  pattern_packs: [example-pack]
                  disabled_categories: [tool_abuse]
                  custom_patterns:
                    - regex: "\\\\bexample\\\\s+secret\\\\s+phrase\\\\b"
                      category: example_custom
                      risk_level: high
            """
        ),
        encoding="utf-8",
    )
    second.write_text(
        textwrap.dedent(
            """\
            # the same rules, keys in another order
            domains:
              agent_security:
                firewall:
                  custom_patterns:
                    - risk_level: high
                      category: example_custom
                      regex: "\\\\bexample\\\\s+secret\\\\s+phrase\\\\b"
                  disabled_categories: [tool_abuse]
                  pattern_packs: [example-pack]
                  heuristic_threshold: 0.7
            """
        ),
        encoding="utf-8",
    )
    one = ruleset_sha256(load_config(first))
    assert one == ruleset_sha256(load_config(second)) == ruleset_sha256(_custom_config())


# ── Import and determinism ────────────────────────────────────

_SNIPPET = textwrap.dedent(
    """\
    import json, sys
    from admina.core.config import FirewallConfig
    from admina.domains.agent_security.ruleset import ruleset_sha256
    cfg = FirewallConfig(
        custom_patterns=[{CUSTOM}],
        disabled_categories=["tool_abuse"],
        pattern_packs=["example-pack"],
    )
    print(json.dumps({{
        "digest": ruleset_sha256(cfg, admina_version="0.13.0"),
        "fastapi": "fastapi" in sys.modules,
        "starlette": "starlette" in sys.modules,
    }}))
    """
)


def _run_snippet(hash_seed: str) -> dict:
    env = {**os.environ, "PYTHONHASHSEED": hash_seed}
    code = _SNIPPET.format(CUSTOM=repr(_CUSTOM))
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, env=env
    )
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_importable_without_fastapi():
    result = _run_snippet("0")
    assert result["fastapi"] is False
    assert result["starlette"] is False


def test_deterministic_across_processes():
    expected = ruleset_sha256(_custom_config(), admina_version=_VERSION)
    assert _run_snippet("1")["digest"] == expected
    assert _run_snippet("12345")["digest"] == expected
