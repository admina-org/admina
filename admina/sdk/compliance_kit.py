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

"""Admina — ComplianceKit SDK primitive.

Wraps the existing EU AI Act compliance engine and provides a unified
interface for risk classification, gap analysis, and report generation
across compliance frameworks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from admina.core.event_bus import EventType, GovernanceEvent, bus
from admina.domains.compliance.eu_ai_act import EUAIActCompliance
from admina.sdk._compat import run_sync

__all__ = ["ComplianceKit"]


@dataclass
class RiskClassification:
    """Result of a risk classification.

    Attributes:
        risk_category: The risk category (unacceptable, high, limited, minimal).
        level: Numeric risk level (1-4).
        description: Human-readable description.
        action: Required action for this risk level.
        framework: The compliance framework used.
    """

    risk_category: str
    level: int = 1
    description: str = ""
    action: str = ""
    framework: str = "eu_ai_act"


@dataclass
class GapReport:
    """Result of a gap analysis.

    Attributes:
        applicable: Whether gap analysis applies to this risk level.
        compliance_score: Percentage of checks passed (0-100).
        total_checks: Total number of checks evaluated.
        passed_checks: Number of checks passed.
        gaps: List of unmet requirements.
        status: COMPLIANT or GAPS_FOUND.
        framework: The compliance framework used.
        message: Optional message (e.g. for non-applicable cases).
    """

    applicable: bool = False
    compliance_score: float = 0.0
    total_checks: int = 0
    passed_checks: int = 0
    gaps: list[dict[str, Any]] = field(default_factory=list)
    status: str = "GAPS_FOUND"
    framework: str = "eu_ai_act"
    message: str = ""


@dataclass
class Report:
    """A generated compliance report.

    Attributes:
        title: Report title.
        generated_at: ISO timestamp of generation.
        framework: The compliance framework.
        classification: Risk classification details.
        gap_analysis: Gap analysis details.
        recommendations: List of recommended actions.
        content: Full report content dict.
    """

    title: str = ""
    generated_at: str = ""
    framework: str = "eu_ai_act"
    classification: dict[str, Any] = field(default_factory=dict)
    gap_analysis: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    content: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize the report to JSON string.

        Returns:
            JSON string of the report content.
        """
        return json.dumps(self.content, indent=2, default=str)


class ComplianceKit:
    """SDK primitive for compliance checking and reporting.

    Provides risk classification, gap analysis, and report generation
    across compliance frameworks. Currently supports EU AI Act with
    extensibility for additional frameworks via plugin templates.

    Args:
        frameworks: List of framework names to activate.
            Defaults to ["eu_ai_act"].
        audit: Whether to emit governance events.
    """

    def __init__(
        self,
        frameworks: list[str] | None = None,
        audit: bool = True,
    ) -> None:
        """Initialize ComplianceKit.

        Args:
            frameworks: Framework names to activate. Defaults to ["eu_ai_act"].
            audit: If True, emit events to the event bus.
        """
        self._frameworks = frameworks or ["eu_ai_act"]
        self._audit = audit
        self._engines: dict[str, Any] = {}
        self._init_engines()

    def _init_engines(self) -> None:
        """Initialize compliance engines for configured frameworks."""
        for fw in self._frameworks:
            if fw == "eu_ai_act":
                self._engines[fw] = EUAIActCompliance()

    def _get_engine(self, framework: str) -> Any:
        """Get the compliance engine for a framework.

        Args:
            framework: Framework name.

        Returns:
            The compliance engine instance.

        Raises:
            ValueError: If the framework is not supported.
        """
        engine = self._engines.get(framework)
        if engine is None:
            raise ValueError(
                f"Framework '{framework}' is not supported. Available: {list(self._engines.keys())}"
            )
        return engine

    def classify_risk(
        self,
        description: str,
        use_case: str,
        data_types: list[str] | None = None,
        framework: str = "eu_ai_act",
    ) -> RiskClassification:
        """Classify an AI system's risk level.

        Args:
            description: Description of the AI system.
            use_case: The use case or application domain.
            data_types: Types of data processed (e.g. ["health", "financial"]).
            framework: Compliance framework to use.

        Returns:
            RiskClassification with category, level, and required action.
        """
        engine = self._get_engine(framework)
        result = engine.classify_risk(
            description,
            use_case,
            data_types or [],
        )

        classification = RiskClassification(
            risk_category=result["risk_category"],
            level=result.get("level", 1),
            description=result.get("description", ""),
            action=result.get("action", ""),
            framework=framework,
        )

        if self._audit:
            _emit_sync(
                GovernanceEvent(
                    event_type=EventType.COMPLIANCE_CHECK,
                    domain="compliance",
                    action="ALLOW",
                    metadata={
                        "operation": "classify_risk",
                        "framework": framework,
                        "risk_category": classification.risk_category,
                        "level": classification.level,
                    },
                )
            )

        return classification

    def gap_analysis(
        self,
        framework: str = "eu_ai_act",
        risk_category: str = "high",
        current_compliance: dict[str, list[bool] | bool] | None = None,
    ) -> GapReport:
        """Perform a compliance gap analysis.

        Args:
            framework: Compliance framework to evaluate.
            risk_category: The risk category to analyze gaps for.
            current_compliance: Dict mapping requirement keys to either
                a list of booleans (one per check) or a single boolean
                (treated as a single check that is fully met or unmet).

        Returns:
            GapReport with score, gaps, and status.

        Raises:
            ValueError: If a value is not a bool or list of bools.
        """
        engine = self._get_engine(framework)
        normalised: dict[str, list[bool]] = {}
        for key, value in (current_compliance or {}).items():
            if isinstance(value, bool):
                normalised[key] = [value]
            elif isinstance(value, list) and all(isinstance(v, bool) for v in value):
                normalised[key] = value
            else:
                raise ValueError(
                    f"current_compliance[{key!r}] must be bool or list[bool], "
                    f"got {type(value).__name__}"
                )
        result = engine.gap_analysis(risk_category, normalised)

        report = GapReport(
            applicable=result.get("applicable", False),
            compliance_score=result.get("compliance_score", 0.0),
            total_checks=result.get("total_checks", 0),
            passed_checks=result.get("passed_checks", 0),
            gaps=result.get("gaps", []),
            status=result.get("status", "GAPS_FOUND"),
            framework=framework,
            message=result.get("message", ""),
        )

        if self._audit:
            _emit_sync(
                GovernanceEvent(
                    event_type=EventType.COMPLIANCE_CHECK,
                    domain="compliance",
                    metadata={
                        "operation": "gap_analysis",
                        "framework": framework,
                        "applicable": report.applicable,
                        "compliance_score": report.compliance_score,
                        "gap_count": len(report.gaps),
                    },
                )
            )

        return report

    def generate_report(
        self,
        system_name: str,
        description: str,
        use_case: str,
        data_types: list[str] | None = None,
        current_compliance: dict[str, list[bool]] | None = None,
        framework: str = "eu_ai_act",
    ) -> Report:
        """Generate a full compliance report.

        Runs risk classification and gap analysis, then produces a
        structured report with recommendations.

        Args:
            system_name: Name of the AI system.
            description: Description of the AI system.
            use_case: The use case or application domain.
            data_types: Types of data processed.
            current_compliance: Current compliance state for gap analysis.
            framework: Compliance framework to use.

        Returns:
            Report with classification, gaps, and recommendations.
        """
        engine = self._get_engine(framework)

        classification = engine.classify_risk(
            description,
            use_case,
            data_types or [],
        )
        gap_result = engine.gap_analysis(
            classification["risk_category"],
            current_compliance or {},
        )
        report_data = engine.generate_report(
            system_name,
            classification,
            gap_result,
        )

        report = Report(
            title=report_data.get("report_title", ""),
            generated_at=report_data.get("generated_at", ""),
            framework=framework,
            classification=classification,
            gap_analysis=gap_result,
            recommendations=report_data.get("recommendations", []),
            content=report_data,
        )

        if self._audit:
            _emit_sync(
                GovernanceEvent(
                    event_type=EventType.COMPLIANCE_CHECK,
                    domain="compliance",
                    metadata={
                        "operation": "generate_report",
                        "framework": framework,
                        "system_name": system_name,
                        "risk_category": classification["risk_category"],
                    },
                )
            )

        return report

    @property
    def supported_frameworks(self) -> list[str]:
        """Return list of supported framework names."""
        return list(self._engines.keys())


def _emit_sync(event: GovernanceEvent) -> None:
    """Emit an event synchronously.

    Uses an event loop if available, otherwise creates one.

    Args:
        event: The governance event to emit.
    """
    run_sync(bus.emit(event))
