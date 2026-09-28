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

"""Admina — OISG adequacy score from evidence.

:func:`compute_oisg_score_from_evidence` scores the 20 criteria of
:data:`~admina.domains.compliance.oisg.CRITERIA` (same ids and labels) from
evidence that the caller supplies, where
:func:`~admina.domains.compliance.oisg.compute_oisg_score` reads the runtime
state of Admina. Each criterion has a status, a reason and an evidence
reference:

- ``satisfied``: 5 points;
- ``partial``: 2.5 points;
- ``gap_consapevole``: a known gap, accepted with a reason (required and
  not blank): 0 points;
- ``not_applicable``: left out of the score.

Scoring: each pillar scores 25 × its points / (5 × its applicable
criteria), that is, it is rescaled to 25 over the criteria that are not
``not_applicable``. A pillar without applicable criteria has no score
(``None``) and the total is rescaled to 100 over the other pillars: the
total is 100 × the sum of the pillar scores / (25 × the pillars with a
score), which is the sum of the four pillar scores when every criterion
applies. Scores are rounded half up to one decimal, and the level is
:func:`~admina.domains.compliance.oisg.get_level` of the rounded total.
Evidence where every criterion is ``not_applicable`` is refused.

The evidence is a mapping (JSON Schema in :data:`EVIDENCE_SCHEMA_PATH`)::

    {
      "schema_version": 1,
      "criteria": {
        "o1": {"status": "satisfied", "reason": "...", "evidence_ref": "..."},
        ...
      }
    }

with an entry for each of the 20 criteria; ``schema_version``, ``reason``
and ``evidence_ref`` are optional. The result exports as JSON
(:meth:`OISGEvidenceResult.to_json`) and Markdown
(:meth:`OISGEvidenceResult.to_markdown`).
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from fractions import Fraction
from pathlib import Path
from typing import Any

from admina.domains.compliance.oisg import (
    CRITERIA,
    MAX_PILLAR_SCORE,
    MAX_TOTAL_SCORE,
    POINTS_PER_CRITERION,
    CriterionResult,
    OISGResult,
    PillarResult,
    get_level,
)

__all__ = [
    "CRITERION_IDS",
    "EVIDENCE_SCHEMA_PATH",
    "EVIDENCE_SCHEMA_VERSION",
    "GAP_CONSAPEVOLE",
    "NOT_APPLICABLE",
    "PARTIAL",
    "SATISFIED",
    "STATUSES",
    "CriterionEvidence",
    "EvidenceCriterionResult",
    "EvidencePillarResult",
    "OISGEvidence",
    "OISGEvidenceError",
    "OISGEvidenceResult",
    "compute_oisg_score_from_evidence",
    "evidence_schema",
]

SATISFIED = "satisfied"
PARTIAL = "partial"
GAP_CONSAPEVOLE = "gap_consapevole"
NOT_APPLICABLE = "not_applicable"

#: The statuses of a criterion.
STATUSES = (SATISFIED, PARTIAL, GAP_CONSAPEVOLE, NOT_APPLICABLE)

#: Points of the statuses that count in the score (``not_applicable`` does not).
_STATUS_POINTS = {
    SATISFIED: Fraction(POINTS_PER_CRITERION),
    PARTIAL: Fraction(POINTS_PER_CRITERION, 2),
    GAP_CONSAPEVOLE: Fraction(0),
}

#: The ids of the 20 criteria, pillar by pillar, as in ``CRITERIA``.
CRITERION_IDS = tuple(c["id"] for criteria in CRITERIA.values() for c in criteria)

EVIDENCE_SCHEMA_VERSION = 1

#: JSON Schema of the evidence (package data).
EVIDENCE_SCHEMA_PATH = Path(__file__).parent / "schemas" / "oisg-evidence.schema.json"

_ENTRY_KEYS = ("status", "reason", "evidence_ref")


def evidence_schema() -> dict[str, Any]:
    """The JSON Schema of the evidence (:data:`EVIDENCE_SCHEMA_PATH`)."""
    return json.loads(EVIDENCE_SCHEMA_PATH.read_text(encoding="utf-8"))


class OISGEvidenceError(ValueError):
    """The evidence does not match its schema. ``problems`` lists each
    problem with the path of its key (for example
    ``criteria.s4.reason: required for status gap_consapevole``)."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("OISG evidence: " + "; ".join(self.problems))


@dataclass(frozen=True)
class CriterionEvidence:
    """The evidence for one criterion."""

    status: str
    reason: str = ""
    evidence_ref: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "reason": self.reason, "evidence_ref": self.evidence_ref}


@dataclass(frozen=True)
class OISGEvidence:
    """The evidence for the 20 criteria, by criterion id.

    Raises:
        OISGEvidenceError: a criterion is missing or unknown, a status is
            unknown, or a ``gap_consapevole`` has no reason.
    """

    criteria: Mapping[str, CriterionEvidence]

    def __post_init__(self) -> None:
        if not isinstance(self.criteria, Mapping):
            raise OISGEvidenceError(["criteria: must be an object"])
        wrong = [
            f"criteria.{cid}: must be a CriterionEvidence"
            for cid, entry in self.criteria.items()
            if not isinstance(entry, CriterionEvidence)
        ]
        if wrong:
            raise OISGEvidenceError(wrong)
        problems = _problems(self.to_dict())
        if problems:
            raise OISGEvidenceError(problems)
        ordered = {cid: self.criteria[cid] for cid in CRITERION_IDS}
        object.__setattr__(self, "criteria", ordered)

    @classmethod
    def from_dict(cls, data: Any) -> OISGEvidence:
        """Parse evidence in the format of the JSON Schema.

        Raises:
            OISGEvidenceError: *data* does not match the schema.
        """
        problems = _problems(data)
        if problems:
            raise OISGEvidenceError(problems)
        return cls({cid: CriterionEvidence(**data["criteria"][cid]) for cid in CRITERION_IDS})

    def to_dict(self) -> dict[str, Any]:
        """The evidence in the format of the JSON Schema."""
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "criteria": {cid: entry.to_dict() for cid, entry in self.criteria.items()},
        }


def _problems(data: Any) -> list[str]:
    """The problems of evidence *data* against the schema, in key order."""
    if not isinstance(data, Mapping):
        return [f"evidence: must be an object, got {type(data).__name__}"]
    problems = [f"{key}: unknown key" for key in data if key not in ("schema_version", "criteria")]
    version = data.get("schema_version", EVIDENCE_SCHEMA_VERSION)
    if isinstance(version, bool) or version != EVIDENCE_SCHEMA_VERSION:
        problems.append(f"schema_version: must be {EVIDENCE_SCHEMA_VERSION}, got {version!r}")
    criteria = data.get("criteria")
    if not isinstance(criteria, Mapping):
        problems.append("criteria: must be an object with an entry for each criterion id")
        return problems
    problems += [
        f"criteria.{cid}: unknown criterion id" for cid in criteria if cid not in CRITERION_IDS
    ]
    missing = [cid for cid in CRITERION_IDS if cid not in criteria]
    if missing:
        problems.append(f"criteria: missing {', '.join(missing)}")
    for cid in CRITERION_IDS:
        if cid in criteria:
            problems += _entry_problems(f"criteria.{cid}", criteria[cid])
    if not problems and all(criteria[cid]["status"] == NOT_APPLICABLE for cid in CRITERION_IDS):
        problems.append("criteria: every criterion is not_applicable, there is nothing to score")
    return problems


def _entry_problems(where: str, entry: Any) -> list[str]:
    if not isinstance(entry, Mapping):
        return [f"{where}: must be an object"]
    problems = [f"{where}.{key}: unknown key" for key in entry if key not in _ENTRY_KEYS]
    if "status" not in entry:
        problems.append(f"{where}.status: required")
    elif entry["status"] not in STATUSES:
        problems.append(
            f"{where}.status: must be one of {', '.join(STATUSES)}, got {entry['status']!r}"
        )
    for key in ("reason", "evidence_ref"):
        if key in entry and not isinstance(entry[key], str):
            problems.append(f"{where}.{key}: must be a string")
    reason = entry.get("reason", "")
    if entry.get("status") == GAP_CONSAPEVOLE and not (isinstance(reason, str) and reason.strip()):
        problems.append(f"{where}.reason: required for status {GAP_CONSAPEVOLE}")
    return problems


# ── Result ──────────────────────────────────────────────────


@dataclass
class EvidenceCriterionResult(CriterionResult):
    """A criterion scored from evidence. ``satisfied`` is true for the
    status ``satisfied`` only; ``points`` is None for ``not_applicable``."""

    status: str = SATISFIED
    evidence_ref: str = ""
    points: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "satisfied": self.satisfied,
            "reason": self.reason,
            "evidence_ref": self.evidence_ref,
            "points": self.points,
        }


@dataclass
class EvidencePillarResult(PillarResult):
    """A pillar scored from evidence: ``score`` (0–25, one decimal) is
    rescaled over the ``applicable`` criteria, and None without any."""

    score: float | None  # type: ignore[assignment]
    criteria: list[EvidenceCriterionResult] = field(default_factory=list)  # type: ignore[assignment]
    applicable: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "max_score": self.max_score,
            "applicable": self.applicable,
            "criteria": [c.to_dict() for c in self.criteria],
        }


@dataclass
class OISGEvidenceResult(OISGResult):
    """OISG adequacy score computed from evidence: ``total`` (0–100, one
    decimal), ``level``, and the pillars with each criterion's status,
    reason, evidence reference and points."""

    total: float  # type: ignore[assignment]
    pillars: dict[str, EvidencePillarResult] = field(default_factory=dict)  # type: ignore[assignment]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "max_total": self.max_total,
            "level": self.level,
            "pillars": {key: pillar.to_dict() for key, pillar in self.pillars.items()},
            "computed_at": self.computed_at,
        }

    def to_json(self) -> str:
        """The result as JSON, keys in the order of :meth:`to_dict`."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> OISGEvidenceResult:
        """The result from its :meth:`to_dict` (or parsed :meth:`to_json`)."""
        pillars = {
            key: EvidencePillarResult(
                name=p["name"],
                score=p["score"],
                max_score=p["max_score"],
                applicable=p["applicable"],
                criteria=[EvidenceCriterionResult(**c) for c in p["criteria"]],
            )
            for key, p in data["pillars"].items()
        }
        return cls(
            total=data["total"],
            max_total=data["max_total"],
            level=data["level"],
            pillars=pillars,
            computed_at=data["computed_at"],
        )

    def to_markdown(self) -> str:
        """The result as Markdown: the total and level, then a table per
        pillar with each criterion's status, reason and evidence."""
        lines = [
            "# OISG adequacy score",
            "",
            f"Total: **{self.total} / {self.max_total}** ({self.level}). "
            f"Computed at {self.computed_at}.",
        ]
        for pillar in self.pillars.values():
            score = (
                "not applicable" if pillar.score is None else f"{pillar.score} / {pillar.max_score}"
            )
            lines += [
                "",
                f"## {pillar.name}: {score}",
                "",
                "| Id | Criterion | Status | Reason | Evidence |",
                "|---|---|---|---|---|",
            ]
            lines += [
                f"| {c.id} | {_cell(c.label)} | {c.status} | {_cell(c.reason)} "
                f"| {_cell(c.evidence_ref)} |"
                for c in pillar.criteria
            ]
        lines += [
            "",
            "_Scoring: satisfied 5 points, partial 2.5, gap_consapevole 0; not_applicable "
            "criteria are left out and each pillar is rescaled to 25 over the criteria "
            "that apply._",
        ]
        return "\n".join(lines) + "\n"


def _cell(text: str) -> str:
    """*text* as a Markdown table cell: pipes escaped, on one line, ``-`` when empty."""
    flat = " ".join(text.split())
    return flat.replace("|", "\\|") if flat else "-"


def _round(value: Fraction) -> float:
    """*value* (not negative) rounded half up to one decimal."""
    return math.floor(value * 10 + Fraction(1, 2)) / 10


def compute_oisg_score_from_evidence(
    evidence: Mapping[str, Any] | OISGEvidence,
) -> OISGEvidenceResult:
    """Compute the OISG adequacy score from *evidence*.

    Args:
        evidence: An :class:`OISGEvidence`, or a mapping in the format of
            the JSON Schema (:data:`EVIDENCE_SCHEMA_PATH`).

    Returns:
        The score of the 20 criteria of ``CRITERIA``: ``satisfied`` 5
        points, ``partial`` 2.5, ``gap_consapevole`` 0; ``not_applicable``
        criteria are left out, each pillar is rescaled to 25 over the
        criteria that apply, and the total to 100 over the pillars with a
        score (see the module docstring). Scores have one decimal, rounded
        half up; the level is :func:`get_level` of the total.

    Raises:
        OISGEvidenceError: *evidence* does not match the schema.
    """
    if not isinstance(evidence, OISGEvidence):
        evidence = OISGEvidence.from_dict(evidence)
    pillars: dict[str, EvidencePillarResult] = {}
    scores: list[Fraction] = []
    for key, definitions in CRITERIA.items():
        criteria: list[EvidenceCriterionResult] = []
        earned = Fraction(0)
        applicable = 0
        for definition in definitions:
            entry = evidence.criteria[definition["id"]]
            points = _STATUS_POINTS.get(entry.status)
            if points is not None:
                earned += points
                applicable += 1
            criteria.append(
                EvidenceCriterionResult(
                    id=definition["id"],
                    label=definition["label"],
                    satisfied=entry.status == SATISFIED,
                    reason=entry.reason,
                    status=entry.status,
                    evidence_ref=entry.evidence_ref,
                    points=None if points is None else float(points),
                )
            )
        score = None
        if applicable:
            exact = MAX_PILLAR_SCORE * earned / (POINTS_PER_CRITERION * applicable)
            scores.append(exact)
            score = _round(exact)
        pillars[key] = EvidencePillarResult(
            name=key.capitalize(),
            score=score,
            criteria=criteria,
            applicable=applicable,
        )
    total = _round(MAX_TOTAL_SCORE * sum(scores, Fraction(0)) / (MAX_PILLAR_SCORE * len(scores)))
    return OISGEvidenceResult(
        total=total,
        level=get_level(total),
        pillars=pillars,
        computed_at=datetime.now(UTC).isoformat(),
    )
