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

"""OISG adequacy score computed from evidence supplied by the caller."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from admina.domains.compliance import compute_oisg_score_from_evidence as exported
from admina.domains.compliance.oisg import CRITERIA, OISGResult, get_level
from admina.domains.compliance.oisg_evidence import (
    CRITERION_IDS,
    EVIDENCE_SCHEMA_PATH,
    STATUSES,
    CriterionEvidence,
    OISGEvidence,
    OISGEvidenceError,
    OISGEvidenceResult,
    compute_oisg_score_from_evidence,
    evidence_schema,
)

PILLARS = ("open", "intelligent", "secure", "governed")


def _evidence(default: str = "satisfied", **statuses: str) -> dict[str, Any]:
    """Evidence with every criterion at *default*, except those in *statuses*."""
    criteria = {}
    for cid in CRITERION_IDS:
        status = statuses.get(cid, default)
        entry = {"status": status, "evidence_ref": f"doc/{cid}.md"}
        if status == "accepted_gap":
            entry["reason"] = f"known gap for {cid}, accepted"
        criteria[cid] = entry
    return {"criteria": criteria}


def _criteria(result: OISGEvidenceResult) -> list:
    return [c for name in PILLARS for c in result.pillars[name].criteria]


# ── Criteria: the 20 of oisg.CRITERIA ─────────────────────────


def test_criterion_ids_follow_oisg_criteria():
    assert CRITERION_IDS == tuple(c["id"] for name in PILLARS for c in CRITERIA[name])
    assert len(CRITERION_IDS) == 20


def test_result_has_the_20_criteria_with_their_ids_and_labels():
    result = compute_oisg_score_from_evidence(_evidence())
    assert isinstance(result, OISGResult)
    assert list(result.pillars) == list(PILLARS)
    for name in PILLARS:
        got = [(c.id, c.label) for c in result.pillars[name].criteria]
        assert got == [(c["id"], c["label"]) for c in CRITERIA[name]]


def test_package_exports_the_function():
    assert exported is compute_oisg_score_from_evidence


@pytest.mark.parametrize("status", STATUSES)
def test_each_status_is_accepted_and_reported(status):
    evidence = _evidence(o1=status)
    evidence["criteria"]["o1"]["reason"] = "stated by the operator"
    result = compute_oisg_score_from_evidence(evidence)
    o1 = result.pillars["open"].criteria[0]
    assert (o1.id, o1.status, o1.reason, o1.evidence_ref) == (
        "o1",
        status,
        "stated by the operator",
        "doc/o1.md",
    )
    assert o1.satisfied is (status == "satisfied")


def test_statuses_are_the_four_literals():
    assert STATUSES == ("satisfied", "partial", "accepted_gap", "not_applicable")


def test_reason_and_evidence_ref_are_optional_except_for_a_gap():
    evidence = {"criteria": {cid: {"status": "satisfied"} for cid in CRITERION_IDS}}
    result = compute_oisg_score_from_evidence(evidence)
    first = result.pillars["open"].criteria[0]
    assert (first.reason, first.evidence_ref) == ("", "")


# ── Validation ────────────────────────────────────────────────


@pytest.mark.parametrize("reason", [None, "", "   \n"])
def test_accepted_gap_without_a_reason_is_refused(reason):
    evidence = _evidence(s4="accepted_gap")
    if reason is None:
        del evidence["criteria"]["s4"]["reason"]
    else:
        evidence["criteria"]["s4"]["reason"] = reason
    with pytest.raises(OISGEvidenceError) as exc:
        compute_oisg_score_from_evidence(evidence)
    assert "criteria.s4.reason" in str(exc.value)
    assert "accepted_gap" in str(exc.value)


def test_unknown_criterion_id_is_refused():
    evidence = _evidence()
    evidence["criteria"]["x9"] = {"status": "satisfied"}
    with pytest.raises(OISGEvidenceError, match=r"criteria\.x9: unknown criterion id"):
        compute_oisg_score_from_evidence(evidence)


def test_missing_criterion_is_refused():
    evidence = _evidence()
    del evidence["criteria"]["g5"]
    del evidence["criteria"]["o2"]
    with pytest.raises(OISGEvidenceError, match=r"criteria: missing o2, g5"):
        compute_oisg_score_from_evidence(evidence)


def test_unknown_status_is_refused():
    evidence = _evidence()
    evidence["criteria"]["i3"]["status"] = "done"
    with pytest.raises(OISGEvidenceError, match=r"criteria\.i3\.status"):
        compute_oisg_score_from_evidence(evidence)


def test_unknown_keys_and_wrong_types_are_refused_together():
    evidence = _evidence()
    evidence["extra"] = True
    evidence["criteria"]["o1"]["note"] = "x"
    evidence["criteria"]["o2"]["evidence_ref"] = ["a", "b"]
    del evidence["criteria"]["o3"]["status"]
    with pytest.raises(OISGEvidenceError) as exc:
        compute_oisg_score_from_evidence(evidence)
    assert exc.value.problems == [
        "extra: unknown key",
        "criteria.o1.note: unknown key",
        "criteria.o2.evidence_ref: must be a string",
        "criteria.o3.status: required",
    ]
    assert isinstance(exc.value, ValueError)


@pytest.mark.parametrize("data", [None, [], "criteria", {"criteria": []}, {}])
def test_evidence_that_is_not_the_documented_object_is_refused(data):
    with pytest.raises(OISGEvidenceError):
        compute_oisg_score_from_evidence(data)


def test_schema_version_other_than_1_is_refused():
    evidence = _evidence()
    evidence["schema_version"] = 2
    with pytest.raises(OISGEvidenceError, match="schema_version"):
        compute_oisg_score_from_evidence(evidence)
    evidence["schema_version"] = 1
    compute_oisg_score_from_evidence(evidence)


def test_every_criterion_not_applicable_is_refused():
    with pytest.raises(OISGEvidenceError, match="not_applicable"):
        compute_oisg_score_from_evidence(_evidence("not_applicable"))


def test_dataclass_evidence_is_accepted_and_validated():
    evidence = OISGEvidence(
        {cid: CriterionEvidence("satisfied", evidence_ref="signed images") for cid in CRITERION_IDS}
    )
    assert compute_oisg_score_from_evidence(evidence).total == 100.0
    assert OISGEvidence.from_dict(evidence.to_dict()) == evidence
    with pytest.raises(OISGEvidenceError, match=r"criteria\.s4\.reason"):
        OISGEvidence(
            {
                cid: CriterionEvidence("accepted_gap" if cid == "s4" else "satisfied")
                for cid in CRITERION_IDS
            }
        )


# ── Scoring rule ──────────────────────────────────────────────


def test_all_satisfied_scores_100():
    result = compute_oisg_score_from_evidence(_evidence())
    assert result.total == 100.0
    assert result.max_total == 100
    assert [result.pillars[n].score for n in PILLARS] == [25.0, 25.0, 25.0, 25.0]
    assert result.level == "OISG adequate"


def test_partial_is_half_the_points_and_gap_is_none():
    result = compute_oisg_score_from_evidence(_evidence(o1="partial", o2="accepted_gap"))
    o1, o2 = result.pillars["open"].criteria[:2]
    assert (o1.points, o2.points) == (2.5, 0.0)
    assert result.pillars["open"].score == 17.5  # 5 + 5 + 5 + 2.5 + 0
    assert result.total == 92.5


def test_not_applicable_is_left_out_and_the_pillar_rescaled():
    result = compute_oisg_score_from_evidence(_evidence(i1="not_applicable", i2="partial"))
    pillar = result.pillars["intelligent"]
    assert pillar.criteria[0].points is None
    assert pillar.applicable == 4
    # 17.5 points of 20 applicable, rescaled to 25
    assert pillar.score == 21.9  # 21.875, rounded half up to one decimal
    assert result.total == 96.9  # 25 + 21.875 + 25 + 25


def test_scores_round_half_up():
    # 5 points over 4 applicable criteria: 25 * 5 / 20 = 6.25 -> 6.3
    result = compute_oisg_score_from_evidence(
        _evidence(
            g1="not_applicable",
            g2="partial",
            g3="partial",
            g4="accepted_gap",
            g5="accepted_gap",
        )
    )
    assert result.pillars["governed"].score == 6.3


def test_a_pillar_without_applicable_criteria_has_no_score_and_the_total_is_rescaled():
    result = compute_oisg_score_from_evidence(
        _evidence(**{cid: "not_applicable" for cid in ("s1", "s2", "s3", "s4", "s5")}, o1="partial")
    )
    assert result.pillars["secure"].score is None
    assert result.pillars["secure"].applicable == 0
    # (22.5 + 25 + 25) of 75, rescaled to 100
    assert result.total == 96.7


def test_fixed_combination_of_statuses_has_a_deterministic_total():
    combination = {
        "o2": "partial",
        "o3": "not_applicable",
        "o5": "accepted_gap",
        "i4": "not_applicable",
        "s1": "partial",
        "s2": "partial",
        "s5": "accepted_gap",
        "g1": "not_applicable",
        "g2": "not_applicable",
        "g3": "not_applicable",
        "g4": "not_applicable",
        "g5": "not_applicable",
    }
    first = compute_oisg_score_from_evidence(_evidence(**combination))
    second = compute_oisg_score_from_evidence(_evidence(**combination))
    # open 12.5/20 -> 15.625; intelligent 20/20 -> 25; secure 15/25 -> 15;
    # governed not applicable; total (15.625 + 25 + 15) / 75 -> 74.1666...
    assert [first.pillars[n].score for n in PILLARS] == [15.6, 25.0, 15.0, None]
    assert first.total == 74.2
    assert first.level == "Good coverage"
    assert first.to_dict() | {"computed_at": ""} == second.to_dict() | {"computed_at": ""}


@pytest.mark.parametrize(
    ("statuses", "total"),
    [
        ({}, 100.0),
        ({f"{p}{n}": "partial" for p in "oisg" for n in (1, 2, 3)}, 70.0),
        ({f"{p}{n}": "accepted_gap" for p in "oisg" for n in (1, 2, 3)}, 40.0),
        ({f"{p}{n}": "accepted_gap" for p in "oisg" for n in (1, 2, 3, 4)}, 20.0),
    ],
)
def test_level_comes_from_get_level(statuses, total):
    result = compute_oisg_score_from_evidence(_evidence(**statuses))
    assert result.total == total
    assert result.level == get_level(total)


# ── Exports ───────────────────────────────────────────────────


def test_json_export_round_trips():
    result = compute_oisg_score_from_evidence(
        _evidence(o5="partial", s4="accepted_gap", g2="not_applicable")
    )
    text = result.to_json()
    assert json.loads(text) == result.to_dict()
    again = OISGEvidenceResult.from_dict(json.loads(text))
    assert again == result
    assert again.to_json() == text
    assert again.to_markdown() == result.to_markdown()


def test_json_export_has_a_stable_key_order():
    data = json.loads(compute_oisg_score_from_evidence(_evidence()).to_json())
    assert list(data) == ["total", "max_total", "level", "pillars", "computed_at"]
    assert list(data["pillars"]) == list(PILLARS)
    assert list(data["pillars"]["open"]) == [
        "name",
        "score",
        "max_score",
        "applicable",
        "criteria",
    ]
    assert list(data["pillars"]["open"]["criteria"][0]) == [
        "id",
        "label",
        "status",
        "satisfied",
        "reason",
        "evidence_ref",
        "points",
    ]


def test_markdown_export_lists_every_criterion_with_status_reason_and_evidence():
    evidence = _evidence(s4="accepted_gap", o5="partial", i3="not_applicable")
    evidence["criteria"]["o5"]["reason"] = "vendor | training data not published"
    result = compute_oisg_score_from_evidence(evidence)
    md = result.to_markdown()
    assert f"{result.total} / 100" in md
    assert result.level in md
    for criterion in _criteria(result):
        rows = [line for line in md.splitlines() if line.startswith(f"| {criterion.id} |")]
        assert len(rows) == 1, criterion.id
        assert f"| {criterion.status} |" in rows[0]
        assert criterion.evidence_ref in rows[0]
    assert "known gap for s4, accepted" in md
    assert "vendor \\| training data not published" in md  # a pipe cannot break the table
    for name in ("Open", "Intelligent", "Secure", "Governed"):
        assert f"## {name}" in md


# ── JSON Schema ───────────────────────────────────────────────


def test_schema_is_package_data_that_names_the_statuses_and_criteria():
    schema = evidence_schema()
    assert EVIDENCE_SCHEMA_PATH.name == "oisg-evidence.schema.json"
    assert json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8")) == schema
    entry = schema["$defs"]["criterion"]
    assert tuple(entry["properties"]["status"]["enum"]) == STATUSES
    assert tuple(schema["properties"]["criteria"]["required"]) == CRITERION_IDS
    assert tuple(schema["properties"]["criteria"]["propertyNames"]["enum"]) == CRITERION_IDS
    for word in ("satisfied", "partial", "not_applicable", "rescaled"):
        assert word in schema["description"]


def _check(schema: dict, value: Any, root: dict) -> list[str]:
    """Errors of *value* against the subset of JSON Schema the evidence schema uses."""
    if "$ref" in schema:
        name = schema["$ref"].removeprefix("#/$defs/")
        return _check(root["$defs"][name], value, root)
    errors: list[str] = []
    kind = schema.get("type")
    types = {"object": dict, "string": str, "integer": int}
    if kind and not (isinstance(value, types[kind]) and not isinstance(value, bool)):
        return [f"not {kind}: {value!r}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"not in enum: {value!r}")
    if "const" in schema and value != schema["const"]:
        errors.append(f"not const: {value!r}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append("too short")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"no match for {schema['pattern']}")
    if isinstance(value, dict):
        errors += [f"missing {k}" for k in schema.get("required", []) if k not in value]
        props = schema.get("properties", {})
        for key, item in value.items():
            if "propertyNames" in schema:
                errors += _check(schema["propertyNames"], key, root)
            if key in props:
                errors += _check(props[key], item, root)
            elif schema.get("additionalProperties") is False:
                errors.append(f"unknown key {key}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors += _check(schema["additionalProperties"], item, root)
    if "if" in schema and not _check(schema["if"], value, root):
        errors += _check(schema["then"], value, root)
    return errors


def _schema_errors(value: Any) -> list[str]:
    schema = evidence_schema()
    return _check(schema, value, schema)


def _invalid_examples() -> list[dict]:
    gap_without_reason = _evidence(s4="accepted_gap")
    del gap_without_reason["criteria"]["s4"]["reason"]
    gap_blank_reason = _evidence(s4="accepted_gap")
    gap_blank_reason["criteria"]["s4"]["reason"] = "  "
    unknown_id = _evidence()
    unknown_id["criteria"]["z1"] = {"status": "satisfied"}
    missing_id = _evidence()
    del missing_id["criteria"]["i5"]
    bad_status = _evidence()
    bad_status["criteria"]["i5"]["status"] = "yes"
    extra_key = _evidence()
    extra_key["criteria"]["i5"]["score"] = 5
    wrong_version = _evidence()
    wrong_version["schema_version"] = 3
    return [
        gap_without_reason,
        gap_blank_reason,
        unknown_id,
        missing_id,
        bad_status,
        extra_key,
        wrong_version,
    ]


@pytest.mark.parametrize(
    "evidence",
    [
        _evidence(),
        _evidence(o5="partial", s4="accepted_gap", g2="not_applicable"),
        {"schema_version": 1, **_evidence("partial")},
    ],
)
def test_valid_evidence_passes_the_schema_and_the_parser(evidence):
    assert _schema_errors(evidence) == []
    OISGEvidence.from_dict(evidence)


@pytest.mark.parametrize("evidence", _invalid_examples())
def test_invalid_evidence_fails_the_schema_and_the_parser(evidence):
    assert _schema_errors(evidence) != []
    with pytest.raises(OISGEvidenceError):
        OISGEvidence.from_dict(evidence)


def test_evidence_to_dict_passes_the_schema():
    evidence = OISGEvidence.from_dict(_evidence(o1="accepted_gap", o2="not_applicable"))
    assert _schema_errors(evidence.to_dict()) == []
    assert list(evidence.to_dict()["criteria"]) == list(CRITERION_IDS)
