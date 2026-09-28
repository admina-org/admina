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

"""Admina — the schema of ``admina.yaml`` (``schema_version: 1``).

:func:`find_problems` walks a parsed file and returns two lists of key
paths (``domains.agent_security.firewall.pattern_packs``,
``alert_channels[0].url``):

- **errors**: values of the wrong type, each as ``<path>: must be …``
  (true or false, an integer, a number, a string, a list of strings, a list
  of mappings, a mapping);
- **unknown**: keys the schema does not know.

An empty value (null) is not checked: the reader of the key treats it as
before. The values of ``gateway`` and ``presidio`` are checked by their own
readers, which name the key too (the proxy does not start, the Presidio
engine is not built): only their unknown keys are reported here. Some
blocks are free-form and not checked inside: ``plugin_config`` (one block
per plugin), ``integrations``, ``agent_security.domains`` and the entries
of ``custom_patterns``, which the firewall checks when it is built (a
malformed entry is skipped with a warning).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = ["SCHEMA", "SchemaProblems", "find_problems"]


@dataclass(frozen=True)
class _Scalar:
    kind: str  # bool | int | number | str

    def describe(self) -> str:
        return {
            "bool": "true or false",
            "int": "an integer",
            "number": "a number",
            "str": "a string",
        }[self.kind]

    def accepts(self, value: Any) -> bool:
        if self.kind == "bool":
            return isinstance(value, bool)
        if isinstance(value, bool):
            return False
        if self.kind == "int":
            return isinstance(value, int)
        if self.kind == "number":
            return isinstance(value, int | float)
        return isinstance(value, str)


@dataclass(frozen=True)
class _Any:
    """Anything: a free-form block."""


@dataclass(frozen=True)
class _Version:
    """``schema_version``: an integer, also written as a string of digits
    (read with ``int()``)."""


@dataclass(frozen=True)
class _Section:
    """A mapping with the keys of *fields*."""

    fields: Mapping[str, Any]


@dataclass(frozen=True)
class _MapOf:
    """A mapping with keys of the user's choice (route names, plugin names,
    language codes), each value a *value*."""

    value: Any


@dataclass(frozen=True)
class _OwnReader:
    """A block whose values its reader checks: only unknown keys are
    reported for it."""

    node: Any


@dataclass(frozen=True)
class _List:
    """A list of *item* (a scalar, a section or anything)."""

    item: Any

    def describe(self) -> str:
        if isinstance(self.item, _Scalar) and self.item.kind == "str":
            return "a list of strings"
        if isinstance(self.item, _Section):
            return "a list of mappings"
        return "a list"


BOOL = _Scalar("bool")
INT = _Scalar("int")
NUMBER = _Scalar("number")
STR = _Scalar("str")
STRINGS = _List(STR)
ANY = _Any()


#: The keys of admina.yaml. Keep in step with ``admina.core.config`` (the
#: readers of the file), ``admina.yaml.example`` and the ``admina init``
#: template; tests/test_config_schema_validation.py checks the last two.
SCHEMA = _Section(
    {
        "schema_version": _Version(),
        "version": ANY,  # older name of schema_version
        "domains": _Section(
            {
                "data_sovereignty": _Section(
                    {
                        "enabled": BOOL,
                        "pii": _Section({"enabled": BOOL, "categories": STRINGS, "ner_model": STR}),
                        "residency": _Section(
                            {"enabled": BOOL, "allowed_zones": STRINGS, "block_outbound": BOOL}
                        ),
                        "classification": _Section({"enabled": BOOL}),
                    }
                ),
                "ai_infra": _Section(
                    {
                        "enabled": BOOL,
                        "llm": _Section(
                            {
                                "enabled": BOOL,
                                "backend": STR,
                                "model": STR,
                                "gpu_autodetect": BOOL,
                                "vram_limit_mb": INT,
                            }
                        ),
                        "rag": _Section(
                            {
                                "enabled": BOOL,
                                "backend": STR,
                                "chunk_size": INT,
                                "chunk_overlap": INT,
                                "embedding_backend": STR,
                                "embedding_model": STR,
                            }
                        ),
                        "webui": _Section(
                            {
                                "enabled": BOOL,
                                "port": INT,
                                "auth_mode": STR,
                                "signup_enabled": BOOL,
                            }
                        ),
                    }
                ),
                "agent_security": _Section(
                    {
                        "enabled": BOOL,
                        "proxy": _Section({"port": INT, "upstream": STR}),
                        "firewall": _Section(
                            {
                                "enabled": BOOL,
                                "mode": STR,
                                "heuristic_threshold": NUMBER,
                                "allowed_tags": STRINGS,
                                "custom_patterns": _List(ANY),
                                "disabled_categories": STRINGS,
                                "disabled_patterns": STRINGS,
                                "pattern_packs": STRINGS,
                                "pattern_pack_dirs": STRINGS,
                                "strict_pack_timing": BOOL,
                            }
                        ),
                        "loop_breaker": _Section(
                            {
                                "enabled": BOOL,
                                "window_size": INT,
                                "similarity_threshold": NUMBER,
                                "max_consecutive": INT,
                            }
                        ),
                        "egress": _Section(
                            {
                                "enabled": BOOL,
                                "allow": STRINGS,
                                "read_only_tools": STRINGS,
                                "surfaces": STRINGS,
                                "coordination_declared": STRINGS,
                                "fanin": _Section({"window_seconds": INT, "min_agents": INT}),
                                "quarantine_ttl_seconds": INT,
                            }
                        ),
                        # Blocks of optional plugins (e.g. guardrailsai).
                        "domains": ANY,
                    }
                ),
                "compliance": _Section(
                    {
                        "enabled": BOOL,
                        "forensic": _Section(
                            {"backend": STR, "storage": STR, "bucket": STR, "base_dir": STR}
                        ),
                        "eu_ai_act": _Section({"enabled": BOOL}),
                        "nis2": _Section({"enabled": BOOL}),
                        "gdpr": _Section({"enabled": BOOL, "ropa_path": STR}),
                        "cross_regulation": _Section({"enabled": BOOL}),
                        "otel": _Section({"endpoint": STR}),
                    }
                ),
            }
        ),
        "gateway": _OwnReader(
            _Section(
                {
                    "upstreams": _MapOf(_Section({"url": STR, "api_key_file": STR})),
                    "default_upstream": STR,
                    "stream_mode": STR,
                    "prescan_tags": STRINGS,
                    "prescan_rulesets": STRINGS,
                }
            )
        ),
        "dashboard": _Section({"enabled": BOOL, "port": INT}),
        "forensic_store": STR,
        "auth_provider": STR,
        "pii_engine": STR,
        "pii_mask_style": STR,
        "presidio": _OwnReader(_Section({"nlp_models": _MapOf(STR)})),
        "alert_channels": _List(_Section({"type": STR, "url": STR, "events": STRINGS})),
        "plugins": STRINGS,
        "plugin_config": _MapOf(ANY),
        "integrations": ANY,
    }
)


@dataclass(frozen=True)
class SchemaProblems:
    """What :func:`find_problems` found, in file order."""

    errors: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)


def find_problems(data: Mapping[str, Any]) -> SchemaProblems:
    """The values of the wrong type and the unknown keys of the parsed
    admina.yaml *data*."""
    problems = SchemaProblems()
    _check(SCHEMA, data, "", problems, types=True)
    return problems


def _join(path: str, key: Any) -> str:
    return f"{path}.{key}" if path else str(key)


def _check(node: Any, value: Any, path: str, problems: SchemaProblems, *, types: bool) -> None:
    """Check *value* at *path* against *node*; with *types* false only
    unknown keys are reported."""
    if value is None or isinstance(node, _Any):
        return
    if isinstance(node, _OwnReader):
        _check(node.node, value, path, problems, types=False)
        return
    errors = problems.errors if types else []
    if isinstance(node, _Version):
        if not (INT.accepts(value) or (isinstance(value, str) and value.strip().isdigit())):
            errors.append(f"{path}: must be an integer")
        return
    if isinstance(node, _Scalar):
        if not node.accepts(value):
            errors.append(f"{path}: must be {node.describe()}")
        return
    if isinstance(node, _List):
        _check_list(node, value, path, problems, types=types)
        return
    if not isinstance(value, Mapping):
        errors.append(f"{path}: must be a mapping")
        return
    for key, item in value.items():
        where = _join(path, key)
        if isinstance(node, _MapOf):
            _check(node.value, item, where, problems, types=types)
        elif key in node.fields:
            _check(node.fields[key], item, where, problems, types=types)
        else:
            problems.unknown.append(where)


def _check_list(
    node: _List, value: Any, path: str, problems: SchemaProblems, *, types: bool
) -> None:
    errors = problems.errors if types else []
    if not isinstance(value, list):
        errors.append(f"{path}: must be {node.describe()}")
        return
    if isinstance(node.item, _Scalar):
        if not all(node.item.accepts(item) for item in value):
            errors.append(f"{path}: must be {node.describe()}")
        return
    if isinstance(node.item, _Section) and not all(isinstance(item, Mapping) for item in value):
        errors.append(f"{path}: must be {node.describe()}")
        return
    for index, item in enumerate(value):
        _check(node.item, item, f"{path}[{index}]", problems, types=types)
