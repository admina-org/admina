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

"""Admina — Automatic data sensitivity classification.

Tags data as public/internal/confidential/restricted based on PII scan
results and configurable rules. Special categories of personal data (GDPR
art. 9 and 10, :data:`SPECIAL_CATEGORIES`, plus those a PII engine
declares) are ``restricted``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from enum import Enum
from typing import Any

logger = logging.getLogger("admina.data_sovereignty.classification")


class SensitivityLevel(str, Enum):
    """Data sensitivity levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# PII categories that trigger elevated classification (names in lower case;
# categories are compared case-insensitively).
_CONFIDENTIAL_PII = {"credit_card", "ssn", "iban"}

SPECIAL_CATEGORIES: frozenset[str] = frozenset(
    {
        # GDPR art. 9: special categories of personal data
        "health",
        "medical",
        "genetic",
        "biometric",
        "racial_or_ethnic_origin",
        "political_opinions",
        "religious_or_philosophical_beliefs",
        "trade_union_membership",
        "sex_life",
        "sexual_orientation",
        # GDPR art. 10: criminal convictions and offences
        "criminal",
        "criminal_convictions",
        "criminal_offences",
    }
)
"""Categories classified ``restricted``, in lower case."""


class DataClassifier:
    """Classifies data sensitivity based on PII scan results.

    Uses the output of PIIRedactor.redact() to determine the sensitivity
    level of a data record. Integrated into GovernedData.ingest().

    Args:
        default_level: Sensitivity level when no PII is detected.
        special_categories: More categories classified ``restricted``, such as
            the special categories a PII engine declares
            (``special_categories`` of the engine); any case.
    """

    def __init__(
        self,
        default_level: SensitivityLevel = SensitivityLevel.INTERNAL,
        *,
        special_categories: Iterable[str] = (),
    ) -> None:
        self._default_level = default_level
        self._restricted = SPECIAL_CATEGORIES | {c.lower() for c in special_categories}
        self._classifications_total = 0

    def classify(
        self, *, pii_categories: list[str] | None = None, text: str = ""
    ) -> dict[str, Any]:
        """Classify data sensitivity.

        Args:
            pii_categories: List of PII category names found (e.g., ["email", "phone"]).
            text: Original text (not used for classification, available for custom rules).

        Returns:
            Dict with ``level`` (SensitivityLevel), ``reason``, ``pii_found``.
        """
        self._classifications_total += 1
        categories = set(pii_categories or [])

        restricted = {c for c in categories if c.lower() in self._restricted}
        if restricted:
            return {
                "level": SensitivityLevel.RESTRICTED.value,
                "reason": f"Contains restricted PII: {restricted}",
                "pii_found": list(categories),
            }

        confidential = {c for c in categories if c.lower() in _CONFIDENTIAL_PII}
        if confidential:
            return {
                "level": SensitivityLevel.CONFIDENTIAL.value,
                "reason": f"Contains confidential PII: {confidential}",
                "pii_found": list(categories),
            }

        if categories:
            return {
                "level": SensitivityLevel.CONFIDENTIAL.value,
                "reason": f"Contains PII: {categories}",
                "pii_found": list(categories),
            }

        return {
            "level": self._default_level.value,
            "reason": "No PII detected",
            "pii_found": [],
        }

    def get_stats(self) -> dict[str, Any]:
        """Return classification statistics."""
        return {"classifications_total": self._classifications_total}
