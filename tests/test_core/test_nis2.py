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

"""Tests for NIS2 base self-assessment module."""

from __future__ import annotations

from admina.domains.compliance.nis2 import (
    NIS2_AREAS,
    NIS2_TRANSPOSITION_DEADLINE,
    NIS2Compliance,
)


class TestNIS2AreasCatalogue:
    """The static catalogue covers all 10 measure areas of Art. 21(2)."""

    def test_ten_areas(self) -> None:
        # Art. 21(2) lists letters (a) through (j) — 10 areas.
        assert len(NIS2_AREAS) == 10

    def test_all_areas_have_required_fields(self) -> None:
        for area_id, meta in NIS2_AREAS.items():
            assert "title" in meta and meta["title"]
            assert "article" in meta and meta["article"].startswith("Art. 21")
            assert "controls" in meta and len(meta["controls"]) >= 1

    def test_transposition_deadline_is_set(self) -> None:
        assert NIS2_TRANSPOSITION_DEADLINE == "2024-10-17"


class TestNIS2Assessment:
    def test_empty_assessment_is_zero_percent(self) -> None:
        nis2 = NIS2Compliance()
        result = nis2.assess(current_compliance={})
        assert result["coverage_score"] == 0.0
        assert result["status"] == "GAPS_FOUND"
        assert result["satisfied_controls"] == 0
        assert len(result["gaps"]) == 10  # every area is missing

    def test_full_compliance_is_100_percent(self) -> None:
        nis2 = NIS2Compliance()
        full = {area_id: [True] * len(meta["controls"]) for area_id, meta in NIS2_AREAS.items()}
        result = nis2.assess(current_compliance=full)
        assert result["coverage_score"] == 100.0
        assert result["status"] == "FULLY_COMPLIANT"
        assert result["gaps"] == []

    def test_partial_assessment_reports_gaps(self) -> None:
        nis2 = NIS2Compliance()
        # Tick only the first control of "incident_handling"
        result = nis2.assess(
            current_compliance={
                "incident_handling": [True, False, False, False],
            }
        )
        assert 0 < result["coverage_score"] < 100
        # At least one gap is for "incident_handling" with 3 missing controls
        ih_gap = next(g for g in result["gaps"] if g["area"] == "incident_handling")
        assert len(ih_gap["missing_controls"]) == 3

    def test_truncates_or_pads_declared_controls(self) -> None:
        # Declaring more booleans than controls in an area should not crash
        nis2 = NIS2Compliance()
        result = nis2.assess(
            current_compliance={
                "cryptography": [True, True, True, True, True, True, True],  # over-declared
            }
        )
        crypto = result["areas"]["cryptography"]
        assert crypto["satisfied"] == crypto["total"]
        assert crypto["coverage_pct"] == 100.0

    def test_assessment_history_capped_at_100(self) -> None:
        nis2 = NIS2Compliance()
        for _ in range(150):
            nis2.assess(current_compliance={})
        assert len(nis2.assessments) == 100

    def test_get_stats_basic(self) -> None:
        nis2 = NIS2Compliance()
        nis2.assess(current_compliance={})
        stats = nis2.get_stats()
        assert stats["total_assessments"] == 1
        assert stats["areas_count"] == 10
        assert stats["controls_count"] == sum(len(a["controls"]) for a in NIS2_AREAS.values())
        assert stats["transposition_deadline"] == NIS2_TRANSPOSITION_DEADLINE
