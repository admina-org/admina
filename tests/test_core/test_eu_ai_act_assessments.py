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

"""EU AI Act assessments: every risk category is recorded, the list is
bounded, and the assessments persist in an opt-in JSON file."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from admina.domains.compliance.eu_ai_act import (
    MAX_ASSESSMENTS,
    NOT_APPLICABLE_MESSAGE,
    EUAIActCompliance,
)

ALL_MET = {
    key: [True] * 4
    for key in (
        "risk_management",
        "data_governance",
        "technical_documentation",
        "record_keeping",
        "transparency",
        "human_oversight",
        "accuracy_robustness",
    )
}


# ── Categories ──────────────────────────────────────────────


@pytest.mark.parametrize("category", ["high", "unacceptable"])
def test_applicable_categories_keep_the_gap_analysis(category):
    c = EUAIActCompliance()
    r = c.gap_analysis(category, {"record_keeping": [True] * 4}, system_name="Scoring")
    assert r["applicable"] is True
    assert r["status"] == "GAPS_FOUND"
    assert r["total_checks"] == 28
    assert r["passed_checks"] == 4
    assert r["gap_count"] == 24
    assert r["risk_category"] == category
    assert r["system_name"] == "Scoring"
    assert c.assessments == [r]


def test_applicable_without_system_name_echoes_none():
    r = EUAIActCompliance().gap_analysis("high", ALL_MET)
    assert r["status"] == "COMPLIANT"
    assert r["system_name"] is None


@pytest.mark.parametrize("category", ["limited", "minimal"])
def test_non_applicable_categories_are_recorded(category):
    c = EUAIActCompliance()
    r = c.gap_analysis(category, {}, system_name="Helpdesk bot")
    assert r["applicable"] is False
    assert r["status"] == "NOT_APPLICABLE"
    assert r["risk_category"] == category
    assert r["system_name"] == "Helpdesk bot"
    assert r["message"] == NOT_APPLICABLE_MESSAGE
    assert r["compliance_score"] is None
    assert r["total_checks"] == 0
    assert "gaps" not in r
    assert r["assessed_at"]
    assert r["enforcement_deadline"]
    assert c.assessments == [r]


def test_non_applicable_ignores_current_compliance():
    r = EUAIActCompliance().gap_analysis("minimal", ALL_MET)
    assert r["compliance_score"] is None
    assert r["total_checks"] == 0
    assert "voluntary" not in r


@pytest.mark.parametrize("category", ["", "High", "medium", None, ["high"]])
def test_unknown_category_is_rejected(category):
    c = EUAIActCompliance()
    with pytest.raises(ValueError, match="risk category"):
        c.gap_analysis(category, {})
    assert c.assessments == []


def test_latest_is_the_most_recent():
    c = EUAIActCompliance()
    assert c.latest() is None
    c.gap_analysis("high", {})
    second = c.gap_analysis("limited", {})
    assert c.latest() == second


def test_the_list_is_bounded():
    c = EUAIActCompliance()
    for i in range(MAX_ASSESSMENTS + 5):
        c.gap_analysis("minimal", {}, system_name=f"s{i}")
    assert MAX_ASSESSMENTS == 100
    assert len(c.assessments) == MAX_ASSESSMENTS
    assert c.assessments[0]["system_name"] == "s5"
    assert c.latest()["system_name"] == f"s{MAX_ASSESSMENTS + 4}"


# ── Voluntary self-assessment ───────────────────────────────


@pytest.mark.parametrize("category", ["limited", "minimal"])
def test_voluntary_self_assessment_keeps_the_checks(category):
    r = EUAIActCompliance().gap_analysis(category, {"record_keeping": [True] * 4}, voluntary=True)
    assert r["applicable"] is False
    assert r["status"] == "NOT_APPLICABLE"
    assert r["voluntary"] is True
    assert r["total_checks"] == 28
    assert r["passed_checks"] == 4
    assert r["compliance_score"] == pytest.approx(14.3)
    assert r["gap_count"] == 24


def test_voluntary_is_ignored_for_applicable_categories():
    r = EUAIActCompliance().gap_analysis("high", {}, voluntary=True)
    assert r["applicable"] is True
    assert "voluntary" not in r


# ── Persistence ─────────────────────────────────────────────


def test_in_memory_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    c = EUAIActCompliance()
    c.gap_analysis("high", {})
    assert c.storage_path is None
    assert list(tmp_path.iterdir()) == []
    assert c.get_stats()["persistence"] == "in-memory"


def test_latest_survives_a_restart(tmp_path):
    path = tmp_path / "sub" / "eu-ai-act.json"
    first = EUAIActCompliance(storage_path=path)
    first.gap_analysis("high", {})
    latest = first.gap_analysis("limited", {}, system_name="Helpdesk bot")
    assert json.loads(path.read_text(encoding="utf-8"))[-1] == latest

    restarted = EUAIActCompliance(storage_path=path)
    assert len(restarted.assessments) == 2
    assert restarted.latest() == latest
    stats = restarted.get_stats()
    assert stats["persistence"] == "filesystem"
    assert stats["storage_path"] == str(path)


def test_the_file_is_bounded(tmp_path):
    path = tmp_path / "eu-ai-act.json"
    c = EUAIActCompliance(storage_path=path)
    for _ in range(MAX_ASSESSMENTS + 3):
        c.gap_analysis("minimal", {})
    assert len(json.loads(path.read_text(encoding="utf-8"))) == MAX_ASSESSMENTS


def test_an_oversized_file_is_trimmed_on_load(tmp_path):
    path = tmp_path / "eu-ai-act.json"
    entries = [{"status": "NOT_APPLICABLE", "n": i} for i in range(MAX_ASSESSMENTS + 10)]
    path.write_text(json.dumps(entries), encoding="utf-8")
    c = EUAIActCompliance(storage_path=path)
    assert len(c.assessments) == MAX_ASSESSMENTS
    assert c.latest()["n"] == MAX_ASSESSMENTS + 9


def test_no_temporary_file_is_left(tmp_path):
    path = tmp_path / "eu-ai-act.json"
    EUAIActCompliance(storage_path=path).gap_analysis("high", {})
    assert [p.name for p in tmp_path.iterdir()] == ["eu-ai-act.json"]


@pytest.mark.parametrize(
    "content",
    [b"{not json", b'{"a": 1}', b"[1, 2]", b"\xff\xfe"],
    ids=["invalid_json", "not_a_list", "not_objects", "not_utf8"],
)
def test_a_corrupt_file_starts_empty_with_a_warning(tmp_path, caplog, content):
    path = tmp_path / "eu-ai-act.json"
    path.write_bytes(content)
    with caplog.at_level(logging.WARNING, logger="admina.eu_ai_act"):
        c = EUAIActCompliance(storage_path=path)
    assert c.assessments == []
    assert any(str(path) in rec.getMessage() for rec in caplog.records)
    # The next assessment replaces the corrupt file.
    c.gap_analysis("minimal", {})
    assert len(json.loads(path.read_text(encoding="utf-8"))) == 1


def test_a_missing_file_starts_empty_silently(tmp_path, caplog):
    with caplog.at_level(logging.WARNING, logger="admina.eu_ai_act"):
        c = EUAIActCompliance(storage_path=tmp_path / "absent.json")
    assert c.assessments == []
    assert caplog.records == []


def test_a_write_failure_keeps_the_assessment_in_memory(tmp_path, caplog):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    c = EUAIActCompliance(storage_path=blocker / "eu-ai-act.json")
    with caplog.at_level(logging.WARNING, logger="admina.eu_ai_act"):
        r = c.gap_analysis("high", {})
    assert c.latest() == r
    assert any("persist" in rec.getMessage() for rec in caplog.records)


def test_storage_path_accepts_a_string(tmp_path):
    path = tmp_path / "eu-ai-act.json"
    EUAIActCompliance(storage_path=str(path)).gap_analysis("high", {})
    assert EUAIActCompliance(storage_path=Path(str(path))).latest()["risk_category"] == "high"
