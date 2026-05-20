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

"""Admina — EU AI Act compliance template plugin.

Loads requirements from ``eu_ai_act.yaml`` and implements the
:class:`BaseComplianceTemplate` interface for risk classification
and gap analysis.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import yaml  # PyYAML — already a core dependency

from admina.plugins.base import BaseComplianceTemplate

logger = logging.getLogger("admina.plugins.compliance.eu_ai_act")

_YAML_PATH = Path(__file__).parent / "eu_ai_act.yaml"

# Keywords used for risk classification (kept in code for performance)
_UNACCEPTABLE_KW = [
    "social scoring",
    "social credit",
    "real-time biometric",
    "mass surveillance",
    "subliminal manipulation",
]
_HIGH_RISK_KW = [
    "credit scor",
    "recruitment",
    "hiring",
    "law enforcement",
    "critical infrastructure",
    "healthcare",
    "medical",
    "education",
    "migration",
    "border",
    "judicial",
    "biometric",
    "financial",
    "trading",
    "insurance",
]
_SENSITIVE_DATA = {"health", "biometric", "financial", "criminal", "genetic"}
_LIMITED_KW = [
    "chatbot",
    "conversational",
    "content generation",
    "emotion recognition",
    "deepfake",
    "synthetic media",
]


class EUAIActComplianceTemplate(BaseComplianceTemplate):
    """Compliance template for the EU AI Act.

    Loads structured requirements from the bundled YAML file and
    provides risk classification and gap analysis.
    """

    def __init__(self) -> None:
        self._data = self._load_yaml()

    @staticmethod
    def _load_yaml() -> dict:
        """Load the bundled YAML requirements file."""
        try:
            return yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError) as exc:
            logger.warning("Failed to load EU AI Act YAML: %s", exc)
            return {}

    # ── BaseComplianceTemplate interface ────────────────────────

    def get_requirements(self) -> list[dict]:
        """Return the list of EU AI Act requirements.

        Returns:
            List of ``{"id": str, "title": str, "article": str,
            "checks": list[str]}``.
        """
        reqs: list[dict] = []
        for req_id, req_info in self._data.get("requirements", {}).items():
            reqs.append(
                {
                    "id": req_id,
                    "title": req_info["name"],
                    "article": req_info["article"],
                    "checks": req_info["checks"],
                }
            )
        return reqs

    def evaluate(self, governance_state: dict) -> dict:
        """Evaluate current governance state against EU AI Act.

        Args:
            governance_state: A dict with:
                - ``risk_category`` (str): the classified risk level.
                - ``current_compliance`` (dict[str, list[bool]]): check results.

        Returns:
            ``{"score": float, "gaps": list, "covered": list,
            "enforcement_deadline": str}``.
        """
        risk = governance_state.get("risk_category", "minimal")
        compliance = governance_state.get("current_compliance", {})

        if risk not in ("high", "unacceptable"):
            return {
                "score": 1.0,
                "gaps": [],
                "covered": [],
                "enforcement_deadline": self._data.get("enforcement_deadline", "2027-12-02"),
            }

        gaps: list[dict] = []
        covered: list[dict] = []
        total = 0
        passed = 0

        for req_id, req_info in self._data.get("requirements", {}).items():
            checks = compliance.get(req_id, [False] * len(req_info["checks"]))
            for check_desc, is_met in zip(req_info["checks"], checks):
                total += 1
                entry = {
                    "requirement": req_info["name"],
                    "article": req_info["article"],
                    "check": check_desc,
                }
                if is_met:
                    passed += 1
                    covered.append(entry)
                else:
                    gaps.append(entry)

        score = round(passed / max(total, 1), 4)

        return {
            "score": score,
            "gaps": gaps,
            "covered": covered,
            "total_checks": total,
            "passed_checks": passed,
            "enforcement_deadline": self._data.get("enforcement_deadline", "2027-12-02"),
            "assessed_at": datetime.now(UTC).isoformat(),
        }

    @property
    def framework_name(self) -> str:
        """Framework name."""
        return "EU AI Act"

    # ── Extra utility (not part of ABC) ─────────────────────────

    def classify_risk(
        self,
        system_description: str,
        use_case: str,
        data_types: list[str] | None = None,
    ) -> str:
        """Classify an AI system's risk under the EU AI Act.

        Returns:
            One of ``"unacceptable"``, ``"high"``, ``"limited"``, ``"minimal"``.
        """
        desc = system_description.lower()
        uc = use_case.lower()

        if any(kw in desc or kw in uc for kw in _UNACCEPTABLE_KW):
            return "unacceptable"

        score = 0
        if any(kw in desc or kw in uc for kw in _HIGH_RISK_KW):
            score += 2
        if data_types and any(d.lower() in _SENSITIVE_DATA for d in data_types):
            score += 1
        if score >= 2:
            return "high"

        if any(kw in desc or kw in uc for kw in _LIMITED_KW):
            return "limited"

        return "minimal"
