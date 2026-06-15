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

"""Tests for sdk.compliance_kit module."""

from __future__ import annotations

from admina.core.event_bus import EventBus, EventType, GovernanceEvent
from admina.sdk.compliance_kit import (
    ComplianceKit,
    GapReport,
    Report,
    RiskClassification,
)

# ---------------------------------------------------------------------------
# Tests: dataclasses
# ---------------------------------------------------------------------------


class TestDataclasses:
    """Tests for ComplianceKit dataclasses."""

    def test_risk_classification_defaults(self) -> None:
        """RiskClassification has sensible defaults."""
        rc = RiskClassification(risk_category="minimal")
        assert rc.risk_category == "minimal"
        assert rc.level == 1
        assert rc.framework == "eu_ai_act"

    def test_gap_report_defaults(self) -> None:
        """GapReport has sensible defaults."""
        gr = GapReport()
        assert gr.applicable is False
        assert gr.compliance_score == 0.0
        assert gr.gaps == []

    def test_report_defaults(self) -> None:
        """Report has sensible defaults."""
        r = Report()
        assert r.title == ""
        assert r.content == {}

    def test_report_to_json(self) -> None:
        """Report.to_json() returns valid JSON."""
        r = Report(content={"key": "value"})
        j = r.to_json()
        assert '"key"' in j
        assert '"value"' in j


# ---------------------------------------------------------------------------
# Tests: risk classification
# ---------------------------------------------------------------------------


class TestClassifyRisk:
    """Tests for ComplianceKit.classify_risk()."""

    def test_minimal_risk(self) -> None:
        """Spam filter classified as minimal risk."""
        kit = ComplianceKit(audit=False)
        result = kit.classify_risk(
            description="Email spam filter",
            use_case="Filtering spam emails",
        )
        assert isinstance(result, RiskClassification)
        assert result.risk_category == "minimal"
        assert result.level == 1

    def test_limited_risk(self) -> None:
        """Chatbot classified as limited risk."""
        kit = ComplianceKit(audit=False)
        result = kit.classify_risk(
            description="Customer service chatbot",
            use_case="Conversational assistant for FAQs",
        )
        assert result.risk_category == "limited"
        assert result.level == 2

    def test_high_risk(self) -> None:
        """Healthcare system classified as high risk."""
        kit = ComplianceKit(audit=False)
        result = kit.classify_risk(
            description="Medical diagnosis AI system",
            use_case="Healthcare diagnostics",
            data_types=["health"],
        )
        assert result.risk_category == "high"
        assert result.level == 3

    def test_unacceptable_risk(self) -> None:
        """Social scoring classified as unacceptable."""
        kit = ComplianceKit(audit=False)
        result = kit.classify_risk(
            description="Social scoring system for citizens",
            use_case="Government social credit rating",
        )
        assert result.risk_category == "unacceptable"
        assert result.level == 4

    def test_framework_set(self) -> None:
        """Classification includes the framework name."""
        kit = ComplianceKit(audit=False)
        result = kit.classify_risk(
            description="A system",
            use_case="general",
        )
        assert result.framework == "eu_ai_act"


# ---------------------------------------------------------------------------
# Tests: gap analysis
# ---------------------------------------------------------------------------


class TestGapAnalysis:
    """Tests for ComplianceKit.gap_analysis()."""

    def test_high_risk_all_gaps(self) -> None:
        """High-risk with no compliance has all gaps."""
        kit = ComplianceKit(audit=False)
        result = kit.gap_analysis(risk_category="high")

        assert isinstance(result, GapReport)
        assert result.applicable is True
        assert result.compliance_score == 0.0
        assert result.status == "GAPS_FOUND"
        assert len(result.gaps) == result.total_checks

    def test_high_risk_partial_compliance(self) -> None:
        """High-risk with partial compliance shows some gaps."""
        kit = ComplianceKit(audit=False)
        result = kit.gap_analysis(
            risk_category="high",
            current_compliance={
                "record_keeping": [True, True, True, True],
                "transparency": [True, True, True, True],
            },
        )

        assert result.applicable is True
        assert result.passed_checks == 8
        assert result.compliance_score > 0.0
        assert result.status == "GAPS_FOUND"  # Not all checks pass

    def test_high_risk_full_compliance(self) -> None:
        """High-risk with all checks passed is COMPLIANT."""
        kit = ComplianceKit(audit=False)
        all_passed = {
            "risk_management": [True, True, True, True],
            "data_governance": [True, True, True, True],
            "technical_documentation": [True, True, True, True],
            "record_keeping": [True, True, True, True],
            "transparency": [True, True, True, True],
            "human_oversight": [True, True, True, True],
            "accuracy_robustness": [True, True, True, True],
        }
        result = kit.gap_analysis(
            risk_category="high",
            current_compliance=all_passed,
        )

        assert result.compliance_score == 100.0
        assert result.status == "COMPLIANT"
        assert len(result.gaps) == 0

    def test_minimal_risk_not_applicable(self) -> None:
        """Gap analysis not applicable for minimal risk."""
        kit = ComplianceKit(audit=False)
        result = kit.gap_analysis(risk_category="minimal")

        assert result.applicable is False
        assert result.message != ""

    def test_limited_risk_not_applicable(self) -> None:
        """Gap analysis not applicable for limited risk."""
        kit = ComplianceKit(audit=False)
        result = kit.gap_analysis(risk_category="limited")

        assert result.applicable is False

    def test_accepts_single_bool_per_requirement(self) -> None:
        """A single bool is normalised to a one-element list."""
        kit = ComplianceKit(audit=False)
        result = kit.gap_analysis(
            risk_category="high",
            current_compliance={"record_keeping": True, "transparency": False},
        )
        assert result.applicable is True
        assert result.passed_checks == 1

    def test_accepts_mixed_bool_and_list(self) -> None:
        """Mixed bool / list[bool] values are accepted."""
        kit = ComplianceKit(audit=False)
        result = kit.gap_analysis(
            risk_category="high",
            current_compliance={
                "record_keeping": True,
                "transparency": [True, True, True, True],
            },
        )
        assert result.applicable is True
        assert result.passed_checks == 5

    def test_rejects_non_bool_values(self) -> None:
        """Non-bool / non-list values raise ValueError."""
        import pytest

        kit = ComplianceKit(audit=False)
        with pytest.raises(ValueError, match="bool or list"):
            kit.gap_analysis(
                risk_category="high",
                current_compliance={"record_keeping": "not a bool"},  # type: ignore[dict-item]
            )

    def test_gap_analysis_bool_is_not_full_compliance(self) -> None:
        """A single True per requirement must not yield 100% / COMPLIANT.

        A bare bool normalises to one check met, leaving the remaining
        checks in each requirement unmet — the engine must pad rather than
        zip-truncate.
        """
        from admina.domains.compliance.eu_ai_act import HIGH_RISK_REQUIREMENTS

        kit = ComplianceKit(audit=False)
        report = kit.gap_analysis(
            framework="eu_ai_act",
            risk_category="high",
            current_compliance={k: True for k in HIGH_RISK_REQUIREMENTS},
        )
        # one bool per requirement = 1-of-4 checks met, NOT 100%
        assert report.compliance_score < 100.0
        assert report.status != "COMPLIANT"

    def test_generate_report_accepts_bool_without_crashing(self) -> None:
        """generate_report passes raw bool values to the engine without TypeError."""
        kit = ComplianceKit(audit=False)
        rep = kit.generate_report(
            system_name="TestSystem",
            description="Medical diagnosis AI",
            use_case="Healthcare diagnostics",
            data_types=["health"],
            current_compliance={"risk_management": True},
        )
        assert rep is not None


# ---------------------------------------------------------------------------
# Tests: report generation
# ---------------------------------------------------------------------------


class TestGenerateReport:
    """Tests for ComplianceKit.generate_report()."""

    def test_report_structure(self) -> None:
        """Report has all expected fields."""
        kit = ComplianceKit(audit=False)
        report = kit.generate_report(
            system_name="TestAI",
            description="A test AI system",
            use_case="general purpose",
        )

        assert isinstance(report, Report)
        assert "TestAI" in report.title
        assert report.framework == "eu_ai_act"
        assert report.generated_at != ""
        assert report.classification != {}

    def test_high_risk_report_has_gaps(self) -> None:
        """High-risk system report includes gap analysis."""
        kit = ComplianceKit(audit=False)
        report = kit.generate_report(
            system_name="MedicalAI",
            description="Medical diagnosis AI",
            use_case="Healthcare diagnostics",
            data_types=["health"],
        )

        assert report.classification["risk_category"] == "high"
        assert report.gap_analysis.get("applicable") is True
        assert len(report.recommendations) > 0

    def test_minimal_risk_report(self) -> None:
        """Minimal risk report has non-applicable gap analysis."""
        kit = ComplianceKit(audit=False)
        report = kit.generate_report(
            system_name="SpamFilter",
            description="Email spam filter",
            use_case="Filtering spam",
        )

        assert report.classification["risk_category"] == "minimal"
        assert report.gap_analysis.get("applicable") is False

    def test_report_to_json(self) -> None:
        """Report can be serialized to JSON."""
        kit = ComplianceKit(audit=False)
        report = kit.generate_report(
            system_name="TestAI",
            description="Test system",
            use_case="general",
        )

        json_str = report.to_json()
        assert "TestAI" in json_str
        assert "EU AI Act" in json_str


# ---------------------------------------------------------------------------
# Tests: framework management
# ---------------------------------------------------------------------------


class TestFrameworks:
    """Tests for framework support."""

    def test_default_framework(self) -> None:
        """Default framework is eu_ai_act."""
        kit = ComplianceKit(audit=False)
        assert "eu_ai_act" in kit.supported_frameworks

    def test_unsupported_framework_raises(self) -> None:
        """Unsupported framework raises ValueError."""
        kit = ComplianceKit(audit=False)
        try:
            kit.classify_risk(
                description="test",
                use_case="test",
                framework="hipaa",
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "hipaa" in str(e)


# ---------------------------------------------------------------------------
# Tests: event emission
# ---------------------------------------------------------------------------


class TestComplianceKitEvents:
    """Tests for event emission."""

    def test_classify_emits_event(self) -> None:
        """classify_risk() emits COMPLIANCE_CHECK event."""
        import admina.sdk.compliance_kit as ck_mod

        original_bus = ck_mod.bus
        test_bus = EventBus()
        ck_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.COMPLIANCE_CHECK, events.append)

            kit = ComplianceKit(audit=True)
            kit.classify_risk(description="test", use_case="general")

            assert len(events) == 1
            assert events[0].domain == "compliance"
            assert events[0].metadata["operation"] == "classify_risk"
        finally:
            ck_mod.bus = original_bus

    def test_gap_analysis_emits_event(self) -> None:
        """gap_analysis() emits COMPLIANCE_CHECK event."""
        import admina.sdk.compliance_kit as ck_mod

        original_bus = ck_mod.bus
        test_bus = EventBus()
        ck_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.COMPLIANCE_CHECK, events.append)

            kit = ComplianceKit(audit=True)
            kit.gap_analysis(risk_category="high")

            assert len(events) == 1
            assert events[0].metadata["operation"] == "gap_analysis"
        finally:
            ck_mod.bus = original_bus

    def test_audit_disabled_no_events(self) -> None:
        """No events when audit=False."""
        import admina.sdk.compliance_kit as ck_mod

        original_bus = ck_mod.bus
        test_bus = EventBus()
        ck_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe_all(events.append)

            kit = ComplianceKit(audit=False)
            kit.classify_risk(description="test", use_case="general")
            kit.gap_analysis(risk_category="high")

            assert len(events) == 0
        finally:
            ck_mod.bus = original_bus
