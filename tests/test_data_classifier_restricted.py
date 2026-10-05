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

"""Special categories of personal data are classified ``restricted``.

The categories of GDPR art. 9 (health, genetic and biometric data, racial or
ethnic origin, political opinions, religious or philosophical beliefs, trade
union membership, sex life and sexual orientation) and art. 10 (criminal
convictions and offences) give ``SensitivityLevel.RESTRICTED``, whatever the
case of their names. A PII engine may declare more special categories.
"""

from __future__ import annotations

import pytest

from admina.domains.data_sovereignty.classification import (
    SPECIAL_CATEGORIES,
    DataClassifier,
    SensitivityLevel,
)

ART_9_AND_10 = [
    "health",
    "genetic",
    "biometric",
    "racial_or_ethnic_origin",
    "political_opinions",
    "religious_or_philosophical_beliefs",
    "trade_union_membership",
    "sex_life",
    "sexual_orientation",
    "criminal_convictions",
    "criminal_offences",
]


def test_special_categories_cover_art_9_and_10():
    assert set(ART_9_AND_10) <= SPECIAL_CATEGORIES
    assert {"medical", "criminal"} <= SPECIAL_CATEGORIES


@pytest.mark.parametrize("category", ART_9_AND_10)
def test_special_category_is_restricted(category):
    result = DataClassifier().classify(pii_categories=[category])
    assert result["level"] == SensitivityLevel.RESTRICTED.value == "restricted"


@pytest.mark.parametrize("category", ["HEALTH", "Criminal_Offences", "BIOMETRIC"])
def test_case_does_not_matter(category):
    assert DataClassifier().classify(pii_categories=[category])["level"] == "restricted"


def test_special_category_wins_over_other_pii():
    result = DataClassifier().classify(pii_categories=["EMAIL", "IBAN", "HEALTH"])
    assert result["level"] == "restricted"
    assert "HEALTH" in result["reason"]


def test_categories_declared_by_an_engine_are_restricted():
    classifier = DataClassifier(special_categories=["HEALTH_RECORD", "court_case"])
    assert classifier.classify(pii_categories=["health_record"])["level"] == "restricted"
    assert classifier.classify(pii_categories=["COURT_CASE"])["level"] == "restricted"
    assert classifier.classify(pii_categories=["health"])["level"] == "restricted"


def test_other_levels_are_unchanged():
    classifier = DataClassifier()
    assert classifier.classify(pii_categories=[])["level"] == "internal"
    assert classifier.classify(pii_categories=["EMAIL"])["level"] == "confidential"
    assert classifier.classify(pii_categories=["iban"])["level"] == "confidential"
    assert (
        DataClassifier(special_categories=["HEALTH_RECORD"]).classify(pii_categories=["PERSON"])[
            "level"
        ]
        == "confidential"
    )
