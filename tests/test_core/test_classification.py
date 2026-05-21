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

"""Tests for domains.data_sovereignty.classification module."""

from admina.domains.data_sovereignty.classification import DataClassifier, SensitivityLevel


class TestDataClassifier:
    def test_no_pii(self):
        classifier = DataClassifier()
        result = classifier.classify(pii_categories=[])
        assert result["level"] == SensitivityLevel.INTERNAL.value
        assert result["pii_found"] == []

    def test_email_pii(self):
        classifier = DataClassifier()
        result = classifier.classify(pii_categories=["email"])
        assert result["level"] == SensitivityLevel.CONFIDENTIAL.value

    def test_credit_card_pii(self):
        classifier = DataClassifier()
        result = classifier.classify(pii_categories=["credit_card"])
        assert result["level"] == SensitivityLevel.CONFIDENTIAL.value

    def test_restricted_pii(self):
        classifier = DataClassifier()
        result = classifier.classify(pii_categories=["medical"])
        assert result["level"] == SensitivityLevel.RESTRICTED.value

    def test_mixed_pii_takes_highest(self):
        classifier = DataClassifier()
        result = classifier.classify(pii_categories=["email", "medical"])
        assert result["level"] == SensitivityLevel.RESTRICTED.value

    def test_custom_default_level(self):
        classifier = DataClassifier(default_level=SensitivityLevel.PUBLIC)
        result = classifier.classify(pii_categories=[])
        assert result["level"] == SensitivityLevel.PUBLIC.value

    def test_stats(self):
        classifier = DataClassifier()
        classifier.classify(pii_categories=[])
        classifier.classify(pii_categories=["email"])
        assert classifier.get_stats()["classifications_total"] == 2
