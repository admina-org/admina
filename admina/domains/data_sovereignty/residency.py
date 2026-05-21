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

"""Admina — Data residency enforcement.

Ensures data stays within allowed geographic/logical zones.
Blocks outbound transfers that violate zone policy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("admina.data_sovereignty.residency")

# Default configuration
_DEFAULT_ALLOWED_ZONES = ["local", "eu"]
_DEFAULT_BLOCK_OUTBOUND = True


@dataclass
class ResidencyViolation:
    """A residency policy violation."""

    source_zone: str
    target_zone: str
    reason: str
    blocked: bool = True


class ResidencyEnforcer:
    """Enforces data residency policies.

    Validates that data operations stay within allowed zones.
    Used by GovernedData to check every ingest/query operation.

    Args:
        allowed_zones: List of permitted zone identifiers.
        block_outbound: Whether to block transfers outside allowed zones.
    """

    def __init__(
        self,
        allowed_zones: list[str] | None = None,
        block_outbound: bool = _DEFAULT_BLOCK_OUTBOUND,
    ) -> None:
        self._allowed_zones = allowed_zones or list(_DEFAULT_ALLOWED_ZONES)
        self._block_outbound = block_outbound
        self._checks_total = 0
        self._violations_total = 0

    def check(
        self,
        *,
        source_zone: str = "local",
        target_zone: str | None = None,
        data_type: str = "unknown",
    ) -> dict[str, Any]:
        """Check whether a data operation complies with residency policy.

        Args:
            source_zone: Where the data currently resides.
            target_zone: Where the data would move (None = stays in place).
            data_type: Category of data for logging.

        Returns:
            Dict with ``allowed`` (bool), ``zone`` info, and optional ``violation``.
        """
        self._checks_total += 1
        effective_target = target_zone or source_zone

        # Check source zone is allowed
        if source_zone not in self._allowed_zones:
            self._violations_total += 1
            return {
                "allowed": False,
                "source_zone": source_zone,
                "target_zone": effective_target,
                "violation": f"Source zone '{source_zone}' not in allowed zones: {self._allowed_zones}",
            }

        # Check target zone if different from source
        if target_zone and target_zone != source_zone:
            if target_zone not in self._allowed_zones:
                self._violations_total += 1
                blocked = self._block_outbound
                return {
                    "allowed": not blocked,
                    "source_zone": source_zone,
                    "target_zone": target_zone,
                    "violation": f"Transfer to zone '{target_zone}' blocked (allowed: {self._allowed_zones})",
                    "blocked": blocked,
                }

        return {
            "allowed": True,
            "source_zone": source_zone,
            "target_zone": effective_target,
        }

    def get_stats(self) -> dict[str, Any]:
        """Return enforcement statistics."""
        return {
            "allowed_zones": self._allowed_zones,
            "block_outbound": self._block_outbound,
            "checks_total": self._checks_total,
            "violations_total": self._violations_total,
        }
