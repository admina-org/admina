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

"""Firewall ruleset and prescan settings of the OpenAI-compatible gateway.

Resolved once at startup (:func:`build_gateway_scan_config`) from the
firewall engine in use and ``admina.yaml``: the active ruleset
(:func:`~admina.domains.agent_security.ruleset.ruleset_sha256`), the other
rulesets a request may declare in ``X-Admina-Scan-Policy``
(``gateway.prescan_rulesets``) and the tags whose blocks it may declare as
already scanned (``gateway.prescan_tags``).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from typing import Any

from admina.core.config import AdminaConfig
from admina.domains.agent_security.ruleset import ruleset_object, ruleset_sha256

__all__ = [
    "RULESET_HEADER",
    "GatewayScanConfig",
    "build_gateway_scan_config",
    "default_gateway_scan_config",
]

#: Response header carrying the active ruleset.
RULESET_HEADER = "X-Admina-Ruleset"


@dataclass(frozen=True)
class GatewayScanConfig:
    """The gateway's firewall ruleset and prescan settings."""

    #: ruleset_sha256() of the configuration, for the engine in use.
    ruleset_sha256: str
    #: "python" or "rust".
    engine: str
    #: Version of admina-core behind the rust engine, else None.
    admina_core_version: str | None
    #: gateway.prescan_rulesets, lowercase.
    prescan_rulesets: tuple[str, ...] = ()
    #: gateway.prescan_tags.
    prescan_tags: frozenset[str] = frozenset()

    @property
    def accepted_rulesets(self) -> tuple[str, ...]:
        """Rulesets accepted in ``X-Admina-Scan-Policy``: the active one
        first, then ``gateway.prescan_rulesets``, without duplicates."""
        return tuple(dict.fromkeys((self.ruleset_sha256, *self.prescan_rulesets)))


def build_gateway_scan_config(firewall: Any, config: AdminaConfig | None) -> GatewayScanConfig:
    """The scan settings for *firewall* (its ``engine``, ``"python"`` when
    it names none) and *config* (``None`` = the defaults)."""
    config = config or AdminaConfig()
    engine = getattr(firewall, "engine", "python")
    builtin = ruleset_object(config, engine=engine)["builtin"]
    core_version = builtin["admina_core_version"] if engine == "rust" else None
    return GatewayScanConfig(
        ruleset_sha256=ruleset_sha256(config, engine=engine, admina_core_version=core_version),
        engine=engine,
        admina_core_version=core_version,
        prescan_rulesets=tuple(config.gateway.prescan_rulesets),
        prescan_tags=frozenset(config.gateway.prescan_tags),
    )


@cache
def default_gateway_scan_config() -> GatewayScanConfig:
    """Scan settings of a gateway router used without the proxy startup:
    the default configuration on the Python engine."""
    return build_gateway_scan_config(None, None)
