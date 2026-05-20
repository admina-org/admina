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

"""Admina — GDPR base hub.

Two primitives required by GDPR Art. 30 and Art. 35:

  - :class:`ProcessingActivitiesRegistry` — Art. 30 records of
    processing activities (RoPA): typed CRUD over JSON-on-disk.
    A single-host, single-controller registry; multi-tenant /
    multi-controller / role-based workflows are out of scope for
    this release.

  - :func:`render_dpia_template` — Art. 35 DPIA scaffold rendered
    as Markdown from the operator's input. The OSS module produces
    a *blank template populated with the operator's facts* — it is
    NOT a guided wizard, it does NOT score or recommend mitigations,
    and it is NOT legal advice. A real DPIA always involves the DPO
    and (for high-risk processing) the supervisory authority.

Out-of-scope (intentionally):
  - Guided DPIA wizard with risk scoring and mitigation suggestions
  - Pre-curated RoPA templates per sector
  - Workflow for Data Subject Requests (Art. 12-22)
  - Records of consent (Art. 6/7)
  - Automated TIA (Transfer Impact Assessment) under Schrems II
  - Branded board-ready reporting

References:
  - Regulation (EU) 2016/679 (GDPR)
  - EDPB Guidelines 4/2019 on Art. 25 (data protection by design and default)
  - WP29 WP248 rev.01 (DPIA guidelines)
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger("admina.gdpr")


# Recital 90 + WP29: criteria triggering "high risk" likely to require a DPIA.
DPIA_REQUIRED_CRITERIA: list[str] = [
    "evaluation_or_scoring",
    "automated_decision_with_legal_effect",
    "systematic_monitoring",
    "sensitive_or_highly_personal_data",
    "data_processed_on_a_large_scale",
    "matching_or_combining_datasets",
    "data_concerning_vulnerable_data_subjects",
    "innovative_use_or_applying_new_technological_solutions",
    "blocking_a_right_or_a_service_or_a_contract",
]


@dataclass
class ProcessingActivity:
    """Art. 30(1) record of processing activities — minimum content."""

    id: str = ""
    name: str = ""
    purpose: str = ""
    legal_basis: str = ""  # Art. 6(1) basis: consent | contract | legal_obligation | vital_interests | public_task | legitimate_interests
    data_categories: list[str] = field(default_factory=list)
    data_subjects: list[str] = field(default_factory=list)
    recipients: list[str] = field(default_factory=list)
    third_country_transfers: list[str] = field(default_factory=list)
    retention_period: str = ""
    technical_security_measures: list[str] = field(default_factory=list)
    organizational_security_measures: list[str] = field(default_factory=list)
    controller: str = ""
    dpo_contact: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        if not self.created_at:
            self.created_at = now
        self.updated_at = now


class ProcessingActivitiesRegistry:
    """Single-controller RoPA store backed by a JSON file on disk.

    The registry is intentionally minimal: a flat list of activities,
    no per-record permissions, no audit trail beyond the natural
    forensic_box (when used through the proxy). Multi-tenant /
    multi-controller / role-based workflows are out of scope for
    this release.
    """

    def __init__(self, storage_path: str | Path | None = None) -> None:
        # No filesystem default. The registry only persists if the
        # operator opts in by passing storage_path explicitly OR by
        # setting ADMINA_GDPR_ROPA_PATH in the environment. Without
        # either, the registry is in-memory only — events live for
        # the process lifetime, never silently written to disk.
        if storage_path is None:
            import os as _os

            env_path = _os.environ.get("ADMINA_GDPR_ROPA_PATH")
            if env_path:
                storage_path = env_path
        self.storage_path = Path(storage_path) if storage_path else None
        if self.storage_path is not None:
            try:
                self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                logger.warning(
                    "GDPR RoPA path %s not writable (%s) — falling back to in-memory",
                    self.storage_path,
                    exc,
                )
                self.storage_path = None
        self._activities: dict[str, ProcessingActivity] = {}
        self._load()

    # ── persistence ──────────────────────────────────────────────
    def _load(self) -> None:
        if self.storage_path is None or not self.storage_path.exists():
            return
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            for entry in data:
                act = ProcessingActivity(**entry)
                self._activities[act.id] = act
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            logger.warning("Failed to load RoPA from %s: %s", self.storage_path, exc)

    def _save(self) -> None:
        if self.storage_path is None:
            return  # in-memory mode
        try:
            data = [asdict(a) for a in self._activities.values()]
            self.storage_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Failed to persist RoPA to %s: %s", self.storage_path, exc)

    # ── CRUD ────────────────────────────────────────────────────
    def list(self) -> list[dict]:
        return [asdict(a) for a in self._activities.values()]

    def get(self, activity_id: str) -> dict | None:
        act = self._activities.get(activity_id)
        return asdict(act) if act else None

    def create(self, payload: dict) -> dict:
        # Strip server-managed fields if the client tries to set them
        for k in ("id", "created_at", "updated_at"):
            payload.pop(k, None)
        act = ProcessingActivity(**payload)
        self._activities[act.id] = act
        self._save()
        return asdict(act)

    def update(self, activity_id: str, payload: dict) -> dict | None:
        existing = self._activities.get(activity_id)
        if existing is None:
            return None
        merged = asdict(existing)
        merged.update(payload)
        merged["id"] = existing.id
        merged["created_at"] = existing.created_at
        merged["updated_at"] = datetime.now(UTC).isoformat()
        # Re-instantiate to validate / normalise via __post_init__
        new_act = ProcessingActivity(**merged)
        new_act.created_at = existing.created_at
        new_act.updated_at = merged["updated_at"]
        self._activities[activity_id] = new_act
        self._save()
        return asdict(new_act)

    def delete(self, activity_id: str) -> bool:
        if activity_id in self._activities:
            del self._activities[activity_id]
            self._save()
            return True
        return False

    def get_stats(self) -> dict:
        total = len(self._activities)
        by_basis: dict[str, int] = {}
        with_transfers = 0
        for a in self._activities.values():
            by_basis[a.legal_basis or "(unspecified)"] = (
                by_basis.get(a.legal_basis or "(unspecified)", 0) + 1
            )
            if a.third_country_transfers:
                with_transfers += 1
        return {
            "total_activities": total,
            "by_legal_basis": by_basis,
            "with_third_country_transfers": with_transfers,
            "storage_path": str(self.storage_path) if self.storage_path else None,
            "persistence": "filesystem" if self.storage_path else "in-memory",
        }


def render_dpia_template(payload: dict) -> str:
    """Render a Markdown DPIA scaffold from operator-supplied facts.

    The OSS template is intentionally a *scaffold*, not a guided
    wizard. It populates the standard sections of an Art. 35 DPIA
    with the values the operator passed in, leaves placeholders
    for everything else, and ends with the standard caveat that a
    real DPIA requires DPO involvement.

    Expected payload keys (all optional, all string except as noted):
      processing_name, controller, dpo_contact, processor,
      purposes, legal_basis, data_categories (list), data_subjects (list),
      recipients (list), third_countries (list), retention_period,
      necessity_proportionality_assessment,
      identified_risks (list of {risk, likelihood, severity, mitigation}),
      consultation_dpo (str), consultation_data_subjects (str)
    """
    p = payload or {}

    def _list(key: str) -> str:
        items = p.get(key) or []
        if not items:
            return "_TBD_"
        return "\n".join(f"- {item}" for item in items)

    def _scalar(key: str, default: str = "_TBD_") -> str:
        return str(p.get(key) or default)

    risks = p.get("identified_risks") or []
    risk_block = "_None recorded — TBD_"
    if risks:
        rows = [
            "| # | Risk | Likelihood | Severity | Mitigation |",
            "|---|------|------------|----------|------------|",
        ]
        for i, r in enumerate(risks, 1):
            rows.append(
                f"| {i} | {r.get('risk', '_TBD_')} "
                f"| {r.get('likelihood', '_TBD_')} "
                f"| {r.get('severity', '_TBD_')} "
                f"| {r.get('mitigation', '_TBD_')} |"
            )
        risk_block = "\n".join(rows)

    return f"""# Data Protection Impact Assessment (DPIA)

> Template generated by Admina at {datetime.now(UTC).isoformat()}.
> This is a **scaffold**, not legal advice. A real DPIA under
> GDPR Art. 35 requires DPO involvement (Art. 39) and may require
> consultation of the supervisory authority (Art. 36).

## 1. Identification

- **Processing name:** {_scalar("processing_name")}
- **Controller:** {_scalar("controller")}
- **Data Protection Officer (contact):** {_scalar("dpo_contact")}
- **Processor(s):** {_scalar("processor")}

## 2. Description of the processing

### Purposes
{_scalar("purposes")}

### Legal basis (Art. 6 / 9 / 10)
{_scalar("legal_basis")}

### Categories of personal data
{_list("data_categories")}

### Categories of data subjects
{_list("data_subjects")}

### Recipients (internal and external)
{_list("recipients")}

### International transfers
{_list("third_countries")}

### Retention
{_scalar("retention_period")}

## 3. Necessity and proportionality (Art. 35(7)(b))
{_scalar("necessity_proportionality_assessment")}

## 4. Risks to the rights and freedoms of data subjects (Art. 35(7)(c))
{risk_block}

## 5. Measures envisaged (Art. 35(7)(d))

_To be completed by the controller / DPO. Should reference both the
technical and organisational measures already in place in the RoPA
record for this processing._

## 6. Consultation

- **DPO opinion (Art. 35(2)):** {_scalar("consultation_dpo")}
- **Data subjects' views, where appropriate (Art. 35(9)):** {_scalar("consultation_data_subjects")}

## 7. Outcome

- [ ] Residual risk acceptable — no further action required
- [ ] Residual risk requires consultation of the supervisory
      authority under Art. 36
- [ ] Processing must not proceed in its current form

---

*Generated by Admina v0.x — `domains.compliance.gdpr.render_dpia_template`.
This file is a scaffold to support the controller; it does not
substitute for the analysis to be performed by the DPO.*
"""
