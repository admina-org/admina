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

"""Admina — NIS2 base self-assessment.

Provides a deterministic checklist + gap analysis for NIS2 (Directive
(EU) 2022/2555) Art. 21 cybersecurity risk-management measures and
Art. 23 incident reporting.

Scope of this OSS module: a *triage tool*. It enumerates the ten
measure areas required by Art. 21 and lets the operator declare for
each one which of a small number of standard controls is in place,
producing a coverage score and a list of gaps.

Out of scope (intentionally — this is the territory of dedicated
GRC tooling, not a framework primitive):
  - Incident reporting workflow (24h early warning + 72h notification
    + 1-month report) — needs human-in-the-loop and CSIRT routing
  - Pre-curated control templates per sector (energy, transport,
    health, finance, ...) — need expert-reviewed content
  - Mapping to specific national transposition acts
  - Board-ready PDF reporting

References:
  - Directive (EU) 2022/2555 (NIS2)
  - ENISA "Implementation Guide for NIS 2 Risk Management Measures"
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("admina.nis2")


# Art. 21(2) — minimum cybersecurity risk-management measures.
# Each area carries a short list of the standard controls associated
# with it. The operator declares one boolean per control; coverage =
# true_count / total_count.
NIS2_AREAS: dict[str, dict[str, Any]] = {
    "risk_analysis_and_security_policy": {
        "title": "Policies on risk analysis and information system security",
        "article": "Art. 21(2)(a)",
        "controls": [
            "documented_risk_analysis",
            "approved_information_security_policy",
            "policy_reviewed_annually",
            "scope_includes_supply_chain",
        ],
    },
    "incident_handling": {
        "title": "Incident handling",
        "article": "Art. 21(2)(b)",
        "controls": [
            "incident_response_plan_in_place",
            "responsible_team_designated",
            "lessons_learned_loop",
            "incident_classification_scheme",
        ],
    },
    "business_continuity": {
        "title": "Business continuity (backup, disaster recovery, crisis management)",
        "article": "Art. 21(2)(c)",
        "controls": [
            "business_continuity_plan_documented",
            "backups_tested_periodically",
            "disaster_recovery_tested_annually",
            "crisis_management_procedure",
        ],
    },
    "supply_chain_security": {
        "title": "Supply chain security",
        "article": "Art. 21(2)(d)",
        "controls": [
            "supplier_inventory_maintained",
            "supplier_risk_assessed",
            "contractual_security_clauses",
            "supplier_incident_notification_clause",
        ],
    },
    "secure_acquisition_development": {
        "title": "Security in network and IS acquisition, development, and maintenance",
        "article": "Art. 21(2)(e)",
        "controls": [
            "secure_development_lifecycle",
            "vulnerability_handling_policy",
            "change_management_procedure",
            "security_in_procurement_requirements",
        ],
    },
    "effectiveness_assessment": {
        "title": "Policies and procedures to assess effectiveness of measures",
        "article": "Art. 21(2)(f)",
        "controls": [
            "internal_audit_program",
            "external_audit_or_certification",
            "metrics_and_kpis_defined",
            "management_review_cycle",
        ],
    },
    "cyber_hygiene_and_training": {
        "title": "Basic cyber hygiene practices and cybersecurity training",
        "article": "Art. 21(2)(g)",
        "controls": [
            "user_awareness_training_annual",
            "phishing_drills",
            "patch_management_policy",
            "least_privilege_enforced",
        ],
    },
    "cryptography": {
        "title": "Policies and procedures regarding the use of cryptography",
        "article": "Art. 21(2)(h)",
        "controls": [
            "encryption_in_transit",
            "encryption_at_rest",
            "key_management_policy",
            "approved_algorithms_only",
        ],
    },
    "access_control_and_asset_management": {
        "title": "Human resources security, access control policies, asset management",
        "article": "Art. 21(2)(i)",
        "controls": [
            "asset_inventory_maintained",
            "rbac_or_abac_in_place",
            "joiner_mover_leaver_process",
            "privileged_access_review",
        ],
    },
    "mfa_and_secure_communications": {
        "title": "Multi-factor authentication and secure communications",
        "article": "Art. 21(2)(j)",
        "controls": [
            "mfa_for_admin_access",
            "mfa_for_remote_access",
            "secure_voice_video_text_internal",
            "emergency_communication_plan",
        ],
    },
}


# NIS2 entered into force on 17 January 2023; Member States had to
# transpose by 17 October 2024. Reference for the dashboard countdown.
NIS2_TRANSPOSITION_DEADLINE = "2024-10-17"


class NIS2Compliance:
    """Lightweight NIS2 self-assessment engine.

    Mirrors the shape of :class:`EUAIActCompliance` so the dashboard
    can treat the two compliance regimes uniformly.
    """

    def __init__(self) -> None:
        self.assessments: list[dict] = []

    def list_areas(self) -> dict[str, dict[str, Any]]:
        """Return the canonical area catalogue (id → metadata)."""
        return {k: dict(v) for k, v in NIS2_AREAS.items()}

    def assess(self, current_compliance: dict[str, list[bool]]) -> dict:
        """Run a coverage assessment.

        Args:
            current_compliance: ``{area_id: [True/False, ...]}`` — one
                boolean per control in the area's ``controls`` list.
                Missing areas are treated as fully un-implemented (all
                False) so partial submissions still produce an honest
                score.

        Returns:
            ``{
                applicable: bool,
                coverage_score: 0..100,
                total_controls: int,
                satisfied_controls: int,
                gaps: [{area, article, missing_controls: [...]}, ...],
                areas: {area_id: {coverage_pct, satisfied, total}},
                assessed_at: ISO8601 UTC,
                status: "FULLY_COMPLIANT" | "GAPS_FOUND",
            }``
        """
        total_controls = 0
        satisfied = 0
        gaps: list[dict] = []
        areas_summary: dict[str, dict[str, Any]] = {}

        for area_id, meta in NIS2_AREAS.items():
            controls = meta["controls"]
            declared = current_compliance.get(area_id) or [False] * len(controls)
            # Truncate / pad declared to match the canonical control count
            declared = list(declared)[: len(controls)]
            declared += [False] * (len(controls) - len(declared))

            area_total = len(controls)
            area_sat = sum(1 for v in declared if v)
            total_controls += area_total
            satisfied += area_sat

            missing = [c for c, v in zip(controls, declared) if not v]
            if missing:
                gaps.append(
                    {
                        "area": area_id,
                        "title": meta["title"],
                        "article": meta["article"],
                        "missing_controls": missing,
                    }
                )

            areas_summary[area_id] = {
                "title": meta["title"],
                "article": meta["article"],
                "satisfied": area_sat,
                "total": area_total,
                "coverage_pct": round(area_sat * 100 / area_total, 1) if area_total else 0.0,
            }

        coverage = round(satisfied * 100 / total_controls, 1) if total_controls else 0.0
        result = {
            "applicable": True,
            "coverage_score": coverage,
            "total_controls": total_controls,
            "satisfied_controls": satisfied,
            "gaps": gaps,
            "areas": areas_summary,
            "assessed_at": datetime.now(UTC).isoformat(),
            "status": "FULLY_COMPLIANT" if not gaps else "GAPS_FOUND",
            "transposition_deadline": NIS2_TRANSPOSITION_DEADLINE,
        }
        self.assessments.append(result)
        if len(self.assessments) > 100:
            self.assessments = self.assessments[-100:]
        return result

    def get_stats(self) -> dict:
        """Aggregate stats for the dashboard / metrics."""
        return {
            "total_assessments": len(self.assessments),
            "areas_count": len(NIS2_AREAS),
            "controls_count": sum(len(a["controls"]) for a in NIS2_AREAS.values()),
            "transposition_deadline": NIS2_TRANSPOSITION_DEADLINE,
        }
