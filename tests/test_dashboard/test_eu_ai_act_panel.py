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

"""The EU AI Act panel of the bundled dashboard with a NOT_APPLICABLE
assessment (limited- or minimal-risk system).

The panel shows the not-applicable state (system name, risk category, date,
"Articles 9–15 are not required"), no article grid and no "How to populate"
notice; the notice stays for the case without any assessment. A voluntary
self-assessment shows its grid labelled as voluntary. The Admina Score card
shows the EU AI Act component as N/A when the score API reports it null.
"""

from __future__ import annotations

import re
from pathlib import Path

import admina

_INDEX = Path(admina.__file__).parent / "dashboard" / "static" / "index.html"


def _html() -> str:
    return _INDEX.read_text(encoding="utf-8")


def _getter(name: str) -> str:
    return _html().split(f"get {name}()", 1)[1].split("\n    },", 1)[0]


def _element_with(attr: str) -> str:
    """The opening tag and body of the first element whose attributes
    contain *attr*, up to its closing tag at the same indentation."""
    html = _html()
    start = html.index(attr)
    line_start = html.rindex("\n", 0, start) + 1
    indent = re.match(r"\s*", html[line_start:]).group(0)
    tag = re.match(r"<(\w+)", html[line_start + len(indent) :]).group(1)
    end = html.index(f"\n{indent}</{tag}>", start)
    return html[line_start:end]


def test_the_how_to_populate_notice_needs_no_assessment_at_all():
    notice = _element_with('<div x-show="!hasAssessment"')
    assert "No real assessment recorded" in notice
    assert "showAssessmentHelp = true" in notice


def test_not_applicable_is_a_status_of_the_latest_assessment():
    body = _getter("complianceNotApplicable")
    assert "this.hasAssessment" in body
    assert "'NOT_APPLICABLE'" in body


def test_not_applicable_state_shows_name_category_and_date():
    block = _element_with('x-show="complianceNotApplicable"')
    assert "Articles 9–15 are not required for" in block
    assert "latest?.risk_category" in block
    assert "latest?.system_name" in block
    assert "latest?.assessed_at" in block
    assert "Admina Score" in block


def test_no_article_grid_for_a_not_applicable_assessment():
    body = _getter("complianceArticles")
    assert "!latest.applicable && !latest.voluntary" in body


def test_no_overall_percentage_for_a_not_applicable_assessment():
    html = _html()
    assert '<template x-if="hasAssessment && !complianceNotApplicable">' in html


def test_voluntary_self_assessment_is_labelled():
    assert "this.complianceNotApplicable" in _getter("complianceVoluntary")
    label = _element_with('x-show="complianceVoluntary"')
    assert "Voluntary self-assessment" in label
    assert "not counted in the Admina Score" in label


def test_score_card_shows_a_null_component_as_not_applicable():
    items = _getter("scoreItems")
    assert "bd.eu_ai_act_coverage === null" in items
    html = _html()
    assert "item.na ? 'N/A'" in html


def test_help_explains_limited_and_minimal_systems():
    html = _html()
    modal = html.split("How to populate the EU AI Act gap analysis", 2)[2]
    assert '"risk_category": "limited"' in modal
    assert "/api/compliance/gap-analysis/latest" in modal
    assert "ADMINA_EU_AI_ACT_ASSESSMENTS_PATH" in modal
