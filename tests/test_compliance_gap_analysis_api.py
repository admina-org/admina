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

"""POST /api/compliance/gap-analysis and GET /api/compliance/gap-analysis/latest
on the real proxy app: validation, authentication, and the assessments file
named by ADMINA_EU_AI_ACT_ASSESSMENTS_PATH."""

from __future__ import annotations

import json

import pytest

from tests._proxy_app import API_KEY, isolate, serve, with_key

POST = "/api/compliance/gap-analysis"
LATEST = "/api/compliance/gap-analysis/latest"


@pytest.fixture
def proxy(monkeypatch):
    from admina.proxy import main as proxy_main

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", API_KEY)
    monkeypatch.delenv("ADMINA_EU_AI_ACT_ASSESSMENTS_PATH", raising=False)
    isolate(monkeypatch)


def _post(body: dict) -> dict:
    return with_key({"method": "POST", "url": POST, "json": body})


def _latest() -> dict:
    return with_key({"method": "GET", "url": LATEST})


def test_limited_is_recorded_and_read_back(proxy):
    responses, _ = serve(
        [_latest(), _post({"risk_category": "limited", "system_name": "Helpdesk bot"}), _latest()]
    )
    assert responses[0].status_code == 404
    assert responses[1].status_code == 200
    posted = responses[1].json()
    assert posted["applicable"] is False
    assert posted["status"] == "NOT_APPLICABLE"
    assert posted["message"]
    assert posted["system_name"] == "Helpdesk bot"
    assert responses[2].status_code == 200
    assert responses[2].json() == posted


def test_high_keeps_the_fields_and_adds_category_and_name(proxy):
    responses, _ = serve(
        [_post({"risk_category": "high", "current_compliance": {"record_keeping": [True] * 4}})]
    )
    body = responses[0].json()
    assert responses[0].status_code == 200
    for key in (
        "applicable",
        "compliance_score",
        "total_checks",
        "passed_checks",
        "gaps",
        "gap_count",
        "status",
        "enforcement_deadline",
        "assessed_at",
    ):
        assert key in body
    assert body["risk_category"] == "high"
    assert body["system_name"] is None


def test_missing_category_defaults_to_high(proxy):
    responses, _ = serve([_post({})])
    assert responses[0].json()["risk_category"] == "high"


@pytest.mark.parametrize(
    "body",
    [
        {"risk_category": "medium"},
        {"risk_category": 3},
        {"risk_category": "high", "current_compliance": [True]},
        {"risk_category": "limited", "system_name": 7},
        {"risk_category": "limited", "voluntary": "yes"},
    ],
    ids=["unknown", "not_a_string", "compliance_not_object", "name_not_string", "voluntary"],
)
def test_invalid_bodies_answer_400_and_record_nothing(proxy, body):
    responses, state = serve([_post(body), _latest()])
    assert responses[0].status_code == 400
    assert responses[0].json()["detail"]
    assert responses[1].status_code == 404
    assert state.compliance.assessments == []


@pytest.mark.parametrize(
    "request_",
    [
        {"method": "POST", "url": POST, "json": {"risk_category": "limited"}},
        {"method": "GET", "url": LATEST},
    ],
    ids=["post", "latest"],
)
def test_routes_require_the_api_key(proxy, request_):
    responses, state = serve([request_, with_key(request_, key="wrong-" + "0" * 26)])
    assert [r.status_code for r in responses] == [401, 401]
    assert state.compliance.assessments == []


def test_assessments_survive_a_restart(monkeypatch, proxy, tmp_path):
    path = tmp_path / "eu" / "assessments.json"
    monkeypatch.setenv("ADMINA_EU_AI_ACT_ASSESSMENTS_PATH", str(path))
    first, _ = serve([_post({"risk_category": "minimal", "system_name": "Spam filter"})])
    assert json.loads(path.read_text(encoding="utf-8"))[-1] == first[0].json()

    second, state = serve([_latest()])
    assert second[0].status_code == 200
    assert second[0].json() == first[0].json()
    assert state.compliance.get_stats()["persistence"] == "filesystem"


def test_report_records_the_system_name(proxy):
    body = {"system_name": "Helpdesk bot", "description": "chatbot", "use_case": "support"}
    responses, _ = serve(
        [with_key({"method": "POST", "url": "/api/compliance/report", "json": body}), _latest()]
    )
    assert responses[0].status_code == 200
    latest = responses[1].json()
    assert latest["system_name"] == "Helpdesk bot"
    assert latest["status"] == "NOT_APPLICABLE"


def test_markdown_report_shows_a_not_applicable_assessment(proxy):
    md = with_key({"method": "GET", "url": "/api/compliance/report?format=markdown"})
    responses, _ = serve([_post({"risk_category": "limited"}), md])
    text = responses[1].text
    assert "None%" not in text
    assert "not applicable" in text.lower()
