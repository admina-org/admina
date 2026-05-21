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

"""Tests for the cross-regulation control matrix."""

from __future__ import annotations

from admina.domains.compliance.cross_regulation import (
    CROSS_REGULATION_MATRIX,
    REGULATIONS,
    coverage_summary,
    to_markdown,
)


class TestMatrixShape:
    def test_at_least_ten_controls(self) -> None:
        # Twelve at the time of writing — a few less is fine, more is great.
        assert len(CROSS_REGULATION_MATRIX) >= 10

    def test_three_regulations_tracked(self) -> None:
        assert set(REGULATIONS) == {"eu_ai_act", "nis2", "gdpr"}

    def test_each_control_has_required_fields(self) -> None:
        for ctrl_id, ctrl in CROSS_REGULATION_MATRIX.items():
            assert ctrl["title"], f"missing title in {ctrl_id}"
            assert ctrl["description"], f"missing description in {ctrl_id}"
            assert "mappings" in ctrl, f"missing mappings in {ctrl_id}"
            for reg in REGULATIONS:
                assert reg in ctrl["mappings"], f"{ctrl_id} missing key {reg}"

    def test_each_mapping_entry_has_ref_and_note(self) -> None:
        for ctrl in CROSS_REGULATION_MATRIX.values():
            for reg, refs in ctrl["mappings"].items():
                for entry in refs:
                    assert "ref" in entry
                    assert "note" in entry

    def test_every_control_touches_at_least_one_regulation(self) -> None:
        for ctrl_id, ctrl in CROSS_REGULATION_MATRIX.items():
            touches = sum(1 for reg in REGULATIONS if ctrl["mappings"].get(reg))
            assert touches >= 1, f"{ctrl_id} maps to no regulation at all"


class TestCoverageSummary:
    def test_summary_totals_match_matrix(self) -> None:
        s = coverage_summary()
        assert s["total_controls"] == len(CROSS_REGULATION_MATRIX)
        assert set(s["regulations"]) == set(REGULATIONS)
        for reg in REGULATIONS:
            assert s["controls_per_regulation"][reg] >= 0

    def test_eu_ai_act_and_gdpr_covered_by_majority(self) -> None:
        # Sanity: AI Act and GDPR should each touch most controls.
        s = coverage_summary()
        total = s["total_controls"]
        assert s["controls_per_regulation"]["eu_ai_act"] >= total * 0.5
        assert s["controls_per_regulation"]["gdpr"] >= total * 0.5


class TestMarkdownExport:
    def test_renders_valid_table(self) -> None:
        md = to_markdown()
        assert md.startswith("# Cross-regulation control matrix")
        assert "| Control | EU AI Act | NIS2 | GDPR |" in md
        # Must contain at least one Art. ref
        assert "Art." in md

    def test_no_empty_cells_left_blank(self) -> None:
        # Empty cells render as "—", never as plain whitespace
        md = to_markdown()
        # No double bar pipe with whitespace only between
        for line in md.splitlines():
            if line.startswith("|") and " | " in line and "Art." in line:
                # Data rows: every cell has either Art. or "—"
                for cell in line.split("|")[1:-1]:
                    cell = cell.strip()
                    assert cell, f"blank cell in row: {line}"
