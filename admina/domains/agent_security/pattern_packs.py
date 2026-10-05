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

"""Admina — firewall pattern packs.

A pattern pack is a named, versioned set of firewall patterns that the
Python firewall adds to its builtin patterns when
``agent_security.firewall.pattern_packs`` names it. A pack is a YAML or
JSON mapping::

    name: example-pack              # [a-z0-9][a-z0-9-]*
    version: "1.0.0"                # a string
    description: Example patterns.  # optional string
    patterns:                       # at least one
      - id: internal_notes          # [a-z0-9][a-z0-9_.-]*, unique in the pack
        regex: "\\\\binternal\\\\s++notes\\\\b"
        category: example_disclosure  # [a-z0-9][a-z0-9_]*
        risk_level: high            # low | medium | high | critical

No other key is accepted. Each pattern is known to the firewall by its
qualified id ``<name>:<id>`` (``example-pack:internal_notes``), which
check results report and ``disabled_patterns`` accepts; its category
works as a builtin category (``disabled_categories``, statistics). Patterns
are compiled with the flags of the builtin patterns (case-insensitive,
``.`` matching newlines).

Sources, searched for each name listed in ``pattern_packs``:

1. the entry points of the group ``admina.pattern_packs``
   (:data:`PATTERN_PACKS_GROUP`): an installed distribution maps a pack
   name to a loader, a callable without arguments that returns the pack
   mapping or the path of a pack file (a path, a string, or a package
   resource from :func:`importlib.resources.files`)::

       [project.entry-points."admina.pattern_packs"]
       example-pack = "example_pkg.packs:example_pack"

2. the directories of ``agent_security.firewall.pattern_pack_dirs``, in
   order, or those of ``ADMINA_PATTERN_PACK_DIRS``
   (:data:`PATTERN_PACK_DIRS_ENV`, separated by :data:`os.pathsep`), which
   replaces them when set and not empty: files ``<name>.yaml``,
   ``<name>.yml`` and ``<name>.json``. Relative directories are resolved
   from the working directory.

A name must come from exactly one source. A name that no source provides,
that two sources provide (two entry points with different values, two
files, or an entry point and a file), that is listed twice or that is not a
valid pack name, a directory that does not exist, and a pack that does not
validate (the error names the file or entry point and the key path, such
as ``patterns[1].risk_level``) raise :class:`PatternPackError`: the
firewall is not built and the proxy does not start. The ``name`` of a pack
must be the name it was loaded by.

:func:`check_pack_timing` times each pattern with
:func:`~admina.domains.agent_security.pattern_timing.probe_pattern`: a
pattern over the time budget (50 ms on 64k-character inputs) is logged as
a warning naming its qualified id, or raises :class:`PatternPackError`
with ``agent_security.firewall.strict_pack_timing: true``.

Packs, their directories and ``disabled_patterns`` apply to the Python
firewall: with a pack listed, :func:`admina.engines.get_firewall` uses the
Python firewall even when the Rust engine is selected.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from admina.core.types import RiskLevel
from admina.domains.agent_security.pattern_timing import (
    DEFAULT_BUDGET_MS,
    DEFAULT_FLAGS,
    probe_pattern,
)

if TYPE_CHECKING:
    from admina.core.config import FirewallConfig
    from admina.domains.agent_security.firewall import FirewallPattern

__all__ = [
    "DEFAULT_BUDGET_MS",
    "PACK_SUFFIXES",
    "PATTERN_PACKS_GROUP",
    "PATTERN_PACK_DIRS_ENV",
    "PackPattern",
    "PatternPack",
    "PatternPackError",
    "check_pack_timing",
    "configured_packs",
    "load_pattern_packs",
    "pack_dirs",
    "parse_pack",
]

logger = logging.getLogger("admina.pattern_packs")

PATTERN_PACKS_GROUP = "admina.pattern_packs"
"""Entry-point group of the pattern packs of installed distributions."""

PATTERN_PACK_DIRS_ENV = "ADMINA_PATTERN_PACK_DIRS"
"""Environment variable listing pack directories (replaces the YAML key)."""

PACK_SUFFIXES = (".yaml", ".yml", ".json")
"""Suffixes of pack files, in the order they are looked for."""

_NAME_RX = re.compile(r"[a-z0-9][a-z0-9-]*")
_ID_RX = re.compile(r"[a-z0-9][a-z0-9_.-]*")
_CATEGORY_RX = re.compile(r"[a-z0-9][a-z0-9_]*")
_PACK_KEYS = ("name", "version", "description", "patterns")
_PATTERN_KEYS = ("id", "regex", "category", "risk_level")
_RISK_LEVELS = ", ".join(level.value for level in RiskLevel)


class PatternPackError(ValueError):
    """A pattern pack cannot be found, loaded or used."""


@dataclass(frozen=True)
class PackPattern:
    """A pattern of a pack."""

    pack: str
    id: str
    regex: str
    category: str
    risk_level: RiskLevel

    @property
    def qualified_id(self) -> str:
        """``<pack>:<id>``: the id the firewall knows the pattern by."""
        return f"{self.pack}:{self.id}"


@dataclass(frozen=True)
class PatternPack:
    """A loaded, validated pattern pack."""

    name: str
    version: str
    description: str
    patterns: tuple[PackPattern, ...]
    source: str
    """The file, or ``entry point <value>``, the pack was read from."""

    def firewall_patterns(self) -> list[FirewallPattern]:
        """The patterns as firewall patterns with their qualified ids."""
        from admina.domains.agent_security.firewall import FirewallPattern

        return [
            FirewallPattern(p.qualified_id, p.regex, p.category, p.risk_level)
            for p in self.patterns
        ]


# ── Validation ────────────────────────────────────────────────


def parse_pack(data: Any, source: str, *, name: str | None = None) -> PatternPack:
    """Validate a pack mapping read from *source* (for error messages);
    *name*, when given, is the name the pack must have.

    Raises:
        PatternPackError: the mapping is not a valid pack.
    """

    def fail(path: str, problem: str) -> PatternPackError:
        return PatternPackError(f"pattern pack {source}: {path}: {problem}")

    if not isinstance(data, Mapping):
        raise fail("(pack)", f"must be a mapping, not {type(data).__name__}")
    _no_other_keys(data, _PACK_KEYS, "", fail)

    pack_name = data.get("name")
    if not isinstance(pack_name, str) or not _NAME_RX.fullmatch(pack_name):
        raise fail("name", f"must match {_NAME_RX.pattern} (got {pack_name!r})")
    if name is not None and pack_name != name:
        raise fail("name", f"must be {name!r}, the name the pack is loaded by (got {pack_name!r})")
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise fail("version", f"must be a non-empty string (got {version!r})")
    description = data.get("description", "")
    if not isinstance(description, str):
        raise fail("description", f"must be a string (got {description!r})")
    entries = data.get("patterns")
    if not isinstance(entries, list) or not entries:
        raise fail("patterns", "must be a non-empty list")

    patterns: list[PackPattern] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        path = f"patterns[{index}]"
        if not isinstance(entry, Mapping):
            raise fail(path, f"must be a mapping, not {type(entry).__name__}")
        _no_other_keys(entry, _PATTERN_KEYS, f"{path}.", fail)
        pattern_id = entry.get("id")
        if not isinstance(pattern_id, str) or not _ID_RX.fullmatch(pattern_id):
            raise fail(f"{path}.id", f"must match {_ID_RX.pattern} (got {pattern_id!r})")
        if pattern_id in seen:
            raise fail(f"{path}.id", f"{pattern_id!r} is the id of another pattern of the pack")
        seen.add(pattern_id)
        regex = entry.get("regex")
        if not isinstance(regex, str) or not regex:
            raise fail(f"{path}.regex", f"must be a non-empty string (got {regex!r})")
        try:
            re.compile(regex, DEFAULT_FLAGS)
        except re.error as exc:
            raise fail(f"{path}.regex", f"is not a valid regular expression: {exc}") from exc
        category = entry.get("category")
        if not isinstance(category, str) or not _CATEGORY_RX.fullmatch(category):
            raise fail(f"{path}.category", f"must match {_CATEGORY_RX.pattern} (got {category!r})")
        risk = entry.get("risk_level")
        if risk not in {level.value for level in RiskLevel}:
            raise fail(f"{path}.risk_level", f"must be one of {_RISK_LEVELS} (got {risk!r})")
        patterns.append(PackPattern(pack_name, pattern_id, regex, category, RiskLevel(risk)))
    return PatternPack(pack_name, version, description, tuple(patterns), source)


def _no_other_keys(
    data: Mapping, allowed: Sequence[str], prefix: str, fail: Callable[[str, str], Exception]
) -> None:
    for key in data:
        if key not in allowed:
            raise fail(f"{prefix}{key}", f"is not a pack key (allowed: {', '.join(allowed)})")


def _parse_text(text: str, suffix: str, source: str, name: str) -> PatternPack:
    try:
        data = json.loads(text) if suffix == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        kind = "JSON" if suffix == ".json" else "YAML"
        raise PatternPackError(f"pattern pack {source}: not valid {kind}: {exc}") from exc
    return parse_pack(data, source, name=name)


def _read_file(path: Path, name: str, source: str | None = None) -> PatternPack:
    source = source or str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PatternPackError(f"pattern pack {source}: cannot be read: {exc}") from exc
    return _parse_text(text, path.suffix.lower(), source, name)


# ── Sources ───────────────────────────────────────────────────


def pack_dirs(configured: Iterable[str] = ()) -> list[Path]:
    """The pack directories: those of :data:`PATTERN_PACK_DIRS_ENV` when it
    is set and not empty, else *configured*
    (``agent_security.firewall.pattern_pack_dirs``).

    Raises:
        PatternPackError: *configured* holds something other than strings.
    """
    from_env = os.environ.get(PATTERN_PACK_DIRS_ENV, "")
    if from_env.strip():
        return [Path(part) for part in from_env.split(os.pathsep) if part.strip()]
    values = list(configured or ())
    if not all(isinstance(value, str) for value in values):
        raise PatternPackError("agent_security.firewall.pattern_pack_dirs must list strings")
    return [Path(value) for value in values]


def _entry_points() -> dict[str, list[metadata.EntryPoint]]:
    """The entry points of :data:`PATTERN_PACKS_GROUP` by name, one per
    distinct value."""
    found: dict[str, dict[str, metadata.EntryPoint]] = {}
    for entry_point in metadata.entry_points(group=PATTERN_PACKS_GROUP):
        found.setdefault(entry_point.name, {}).setdefault(entry_point.value, entry_point)
    return {name: list(by_value.values()) for name, by_value in found.items()}


def _files(directories: Sequence[Path], name: str) -> list[Path]:
    return [
        d / f"{name}{suffix}"
        for d in directories
        for suffix in PACK_SUFFIXES
        if (d / f"{name}{suffix}").is_file()
    ]


def _available(directories: Sequence[Path], entry_points: Mapping[str, Any]) -> list[str]:
    """The pack names of *entry_points* and of the files of *directories*
    (a directory that cannot be listed adds none)."""
    names = set(entry_points)
    for directory in directories:
        try:
            paths = list(directory.iterdir())
        except OSError:
            continue
        names.update(
            path.stem
            for path in paths
            if path.suffix.lower() in PACK_SUFFIXES
            and _NAME_RX.fullmatch(path.stem)
            and path.is_file()
        )
    return sorted(names)


def _load_entry_point(entry_point: metadata.EntryPoint, name: str) -> PatternPack:
    source = f"entry point {entry_point.value}"
    try:
        loader = entry_point.load()
    except Exception as exc:  # noqa: BLE001 — third-party code, reported by class
        raise PatternPackError(
            f"pattern pack {name!r}: {source} cannot be loaded ({type(exc).__name__}: {exc})"
        ) from exc
    if not callable(loader):
        raise PatternPackError(f"pattern pack {name!r}: {source} is not callable")
    try:
        result = loader()
    except Exception as exc:  # noqa: BLE001 — third-party code, reported by class
        raise PatternPackError(
            f"pattern pack {name!r}: {source} failed ({type(exc).__name__}: {exc})"
        ) from exc
    if isinstance(result, Mapping):
        return parse_pack(result, source, name=name)
    if isinstance(result, (str, os.PathLike)):
        return _read_file(Path(result), name, f"{source} ({result})")
    if hasattr(result, "read_text") and hasattr(result, "name"):  # importlib.resources
        suffix = Path(str(result.name)).suffix.lower()
        try:
            text = result.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PatternPackError(f"pattern pack {source}: cannot be read: {exc}") from exc
        return _parse_text(text, suffix, f"{source} ({result.name})", name)
    raise PatternPackError(
        f"pattern pack {name!r}: {source} returned {type(result).__name__}, "
        "not a pack mapping or the path of a pack file"
    )


def load_pattern_packs(
    names: Iterable[str], directories: Iterable[Path | str]
) -> list[PatternPack]:
    """Load the packs *names*, in their order, from the entry points of
    :data:`PATTERN_PACKS_GROUP` and the files of *directories*.

    Nothing is read when *names* is empty.

    Raises:
        PatternPackError: see the module docstring.
    """
    names = list(names or ())
    if not names:
        return []
    dirs = [Path(d) for d in directories or ()]
    for name in names:
        if not isinstance(name, str) or not _NAME_RX.fullmatch(name):
            raise PatternPackError(
                f"pattern_packs: {name!r} is not a valid pack name ({_NAME_RX.pattern})"
            )
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        raise PatternPackError(f"pattern_packs: {', '.join(repeated)} listed more than once")
    for directory in dirs:
        if not directory.is_dir():
            raise PatternPackError(
                f"pattern pack directory {directory} is missing or not a directory"
            )

    entry_points = _entry_points()
    packs: list[PatternPack] = []
    for name in names:
        from_entry_points = entry_points.get(name, [])
        files = _files(dirs, name)
        sources = [f"entry point {ep.value}" for ep in from_entry_points] + [str(f) for f in files]
        if not sources:
            available = ", ".join(_available(dirs, entry_points)) or "(none)"
            raise PatternPackError(
                f"pattern pack {name!r} not found in the entry points of {PATTERN_PACKS_GROUP} "
                f"or in the pack directories; available: {available}"
            )
        if len(sources) > 1:
            raise PatternPackError(
                f"pattern pack {name!r} comes from more than one source: {', '.join(sources)}"
            )
        if from_entry_points:
            packs.append(_load_entry_point(from_entry_points[0], name))
        else:
            packs.append(_read_file(files[0], name))
    return packs


# ── Timing ────────────────────────────────────────────────────


@functools.cache
def _worst_ms(regex: str) -> float:
    return probe_pattern(regex, flags=DEFAULT_FLAGS)


def check_pack_timing(
    packs: Iterable[PatternPack], *, strict: bool = False, budget_ms: float = DEFAULT_BUDGET_MS
) -> dict[str, float]:
    """Time every pattern of *packs* on long inputs
    (:func:`~admina.domains.agent_security.pattern_timing.probe_pattern`,
    each regex once per process) and return the worst time, in ms, of each
    pattern over *budget_ms*, by qualified id. Each is logged as a warning.

    Raises:
        PatternPackError: *strict* and a pattern is over the budget.
    """
    slow = {
        pattern.qualified_id: worst
        for pack in packs
        for pattern in pack.patterns
        if (worst := _worst_ms(pattern.regex)) > budget_ms
    }
    if slow and strict:
        listed = ", ".join(f"{pid} ({ms:.0f} ms)" for pid, ms in slow.items())
        raise PatternPackError(
            f"pattern pack patterns over the {budget_ms:.0f} ms time budget on long inputs: "
            f"{listed} (agent_security.firewall.strict_pack_timing is true)"
        )
    for pattern_id, worst in slow.items():
        logger.warning(
            "Pattern pack pattern %s takes %.0f ms on a long input (budget %.0f ms): "
            "rewrite it to match in linear time",
            pattern_id,
            worst,
            budget_ms,
        )
    return slow


def configured_packs(config: FirewallConfig, *, timing: bool = True) -> list[PatternPack]:
    """The packs of ``agent_security.firewall`` (``pattern_packs``, with
    :func:`pack_dirs` of ``pattern_pack_dirs``); with *timing*, checked by
    :func:`check_pack_timing` (strict with ``strict_pack_timing``).

    Raises:
        PatternPackError: as :func:`load_pattern_packs` and
            :func:`check_pack_timing`; ``strict_pack_timing`` is not a
            boolean.
    """
    strict = config.strict_pack_timing
    if not isinstance(strict, bool):
        raise PatternPackError("agent_security.firewall.strict_pack_timing must be true or false")
    packs = load_pattern_packs(config.pattern_packs, pack_dirs(config.pattern_pack_dirs))
    if timing:
        check_pack_timing(packs, strict=strict)
    return packs
