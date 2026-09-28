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

"""Admina — firewall ruleset identity.

:func:`ruleset_sha256` names the set of firewall rules a configuration
applies: two processes that compute the same value scan text with the same
rules. The proxy reports it (``X-Admina-Ruleset``, ``GET /v1/admina/ruleset``)
and a caller that has already scanned part of a prompt with the SDK declares
it (``X-Admina-Scan-Policy``).

The value is the SHA-256, as 64 lowercase hex characters, of the RFC 8785
(JCS, :mod:`admina.core.jcs`) serialisation of this object, which holds
strings and integers only::

    {
      "admina_version": "<admina.__version__>",
      "engine": "python" | "rust",
      "builtin": [{"regex": "...", "category": "...", "risk_level": "..."}, ...],
      "pattern_packs": ["<name>", ...],
      "custom_patterns": [{"regex": "...", "category": "...", "risk_level": "..."}, ...],
      "disabled_categories": ["<category>", ...],
      "disabled_patterns": ["<pattern id>", ...],
      "allowed_tags": ["<tag>", ...],
      "heuristic_threshold_milli": <int>
    }

- ``builtin``: for the ``python`` engine, the builtin patterns of
  :data:`~admina.domains.agent_security.firewall.INJECTION_PATTERNS` in
  their order, without those of a disabled category; ``risk_level`` is the
  lowercase level name. For the ``rust`` engine, whose patterns are compiled
  into ``admina-core``, the object ``{"admina_core_version": "<version>"}``.
- ``pattern_packs``: the names under ``agent_security.firewall.pattern_packs``
  in ``admina.yaml``, in their order.
- ``custom_patterns``: the entries of ``agent_security.firewall.custom_patterns``
  as the firewall loads them (:func:`~admina.domains.agent_security.firewall.
  parse_custom_patterns`): in their order, ``category`` defaulted to
  ``user_custom``, ``risk_level`` lowercase and defaulted to ``medium``,
  malformed entries left out.
- ``disabled_categories``: ``agent_security.firewall.disabled_categories``,
  sorted by code point, without duplicates.
- ``disabled_patterns``: ``agent_security.firewall.disabled_patterns``,
  sorted by code point, without duplicates (``builtin`` keeps the patterns
  they name).
- ``allowed_tags``: ``agent_security.firewall.allowed_tags`` in lower case,
  sorted by code point, without duplicates.
- ``heuristic_threshold_milli``: ``agent_security.firewall.heuristic_threshold``
  × 1000, rounded to the nearest integer (Python :func:`round`).

JCS sorts the members, so the order of keys in ``admina.yaml`` does not
matter. This module does not import FastAPI or the proxy.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

import admina
from admina.core.config import AdminaConfig, FirewallConfig
from admina.core.jcs import canonicalize
from admina.domains.agent_security import firewall as _firewall

__all__ = ["RULESET_ENGINES", "ruleset_object", "ruleset_sha256"]

#: Firewall engines a ruleset can be computed for.
RULESET_ENGINES = ("python", "rust")


def ruleset_object(
    config: AdminaConfig | FirewallConfig | None = None,
    *,
    engine: str = "python",
    admina_core_version: str | None = None,
    admina_version: str | None = None,
) -> dict[str, Any]:
    """The object :func:`ruleset_sha256` hashes (see the module docstring).

    Args:
        config: The configuration, or its ``agent_security.firewall``
            section; ``None`` = the defaults.
        engine: ``"python"`` or ``"rust"``: the firewall engine the rules
            run on.
        admina_core_version: Version of ``admina-core`` (``rust`` only);
            defaults to the installed one.
        admina_version: Defaults to the installed ``admina.__version__``.

    Raises:
        ValueError: Unknown engine; ``rust`` without a version and without
            ``admina-core``; a threshold that is not a finite number; a
            pack or category name that is not a string.
    """
    if engine not in RULESET_ENGINES:
        raise ValueError(f"engine must be one of {', '.join(RULESET_ENGINES)} (got {engine!r})")
    fw = _firewall_section(config)
    disabled = _names(fw.disabled_categories, "disabled_categories")
    if engine == "python":
        builtin: Any = [
            _pattern(regex, category, level)
            for regex, category, level in _firewall.INJECTION_PATTERNS
            if category not in disabled
        ]
    else:
        builtin = {"admina_core_version": admina_core_version or _installed_core_version()}
    return {
        "admina_version": admina_version or admina.__version__,
        "engine": engine,
        "builtin": builtin,
        "pattern_packs": _names(fw.pattern_packs, "pattern_packs"),
        "custom_patterns": [
            _pattern(regex, category, level)
            for regex, category, level in _firewall.parse_custom_patterns(fw.custom_patterns)
        ],
        "disabled_categories": sorted(set(disabled)),
        "disabled_patterns": sorted(set(_names(fw.disabled_patterns, "disabled_patterns"))),
        "allowed_tags": sorted({tag.lower() for tag in _names(fw.allowed_tags, "allowed_tags")}),
        "heuristic_threshold_milli": _milli(fw.heuristic_threshold),
    }


def ruleset_sha256(
    config: AdminaConfig | FirewallConfig | None = None,
    *,
    engine: str = "python",
    admina_core_version: str | None = None,
    admina_version: str | None = None,
) -> str:
    """SHA-256 (64 lowercase hex characters) of the ruleset of *config*.

    Arguments as :func:`ruleset_object`.
    """
    obj = ruleset_object(
        config,
        engine=engine,
        admina_core_version=admina_core_version,
        admina_version=admina_version,
    )
    return hashlib.sha256(canonicalize(obj)).hexdigest()


def _firewall_section(config: AdminaConfig | FirewallConfig | None) -> FirewallConfig:
    if config is None:
        return FirewallConfig()
    if isinstance(config, FirewallConfig):
        return config
    return config.agent_security.firewall


def _pattern(regex: Any, category: Any, level: Any) -> dict[str, Any]:
    return {"regex": regex, "category": category, "risk_level": getattr(level, "value", level)}


def _names(values: Any, key: str) -> list[str]:
    names = list(values or ())
    if not all(isinstance(name, str) for name in names):
        raise ValueError(f"agent_security.firewall.{key} must list strings")
    return names


def _milli(threshold: Any) -> int:
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise ValueError("agent_security.firewall.heuristic_threshold must be a number")
    if not math.isfinite(threshold):
        raise ValueError("agent_security.firewall.heuristic_threshold must be finite")
    return round(threshold * 1000)


def _installed_core_version() -> str:
    try:
        import admina_core  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ValueError(
            "admina_core_version is required for the rust engine when admina-core is not installed"
        ) from exc
    return str(admina_core.version())
