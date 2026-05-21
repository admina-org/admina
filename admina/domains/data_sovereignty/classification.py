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
results and configurable rules.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger("admina.data_sovereignty.classification")


class SensitivityLevel(str, Enum):
    """Data sensitivity levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# PII categories that trigger elevated classification
_CONFIDENTIAL_PII = {"credit_card", "ssn", "iban"}
_RESTRICTED_PII = {"medical", "biometric", "criminal"}


class DataClassifier:
    """Classifies data sensitivity based on PII scan results.

    Uses the output of PIIRedactor.redact() to determine the sensitivity
    level of a data record. Integrated into GovernedData.ingest().

    Args:
        default_level: Sensitivity level when no PII is detected.
    """

    def __init__(self, default_level: SensitivityLevel = SensitivityLevel.INTERNAL) -> None:
        self._default_level = default_level
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

        if categories & _RESTRICTED_PII:
            return {
                "level": SensitivityLevel.RESTRICTED.value,
                "reason": f"Contains restricted PII: {categories & _RESTRICTED_PII}",
                "pii_found": list(categories),
            }

        if categories & _CONFIDENTIAL_PII:
            return {
                "level": SensitivityLevel.CONFIDENTIAL.value,
                "reason": f"Contains confidential PII: {categories & _CONFIDENTIAL_PII}",
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
