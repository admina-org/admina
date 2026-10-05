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

"""
Admina — EU AI Act Compliance Engine — Compliance domain
Automated risk classification, gap analysis, and compliance reporting.
"""

import logging
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from admina.domains.compliance.ai_act_terms import RISK_ORDER, TERM_LANGUAGES, TERMS, find_terms

logger = logging.getLogger("admina.eu_ai_act")


def _coerce_checks(value: Any, n: int) -> list[bool]:
    """Normalise a declared-compliance value to exactly *n* booleans.

    bool → that value for the first check, the rest unmet (a single claim
    does not satisfy all N checks); list → padded with False / truncated to
    n; None → all unmet. Prevents a bool/short input from being zip-truncated
    into a falsely high score.
    """
    if value is None:
        return [False] * n
    if isinstance(value, bool):
        declared = [value]
    elif isinstance(value, list):
        declared = [bool(v) for v in value]
    else:
        declared = [False]
    declared = declared[:n]
    declared += [False] * (n - len(declared))
    return declared


# ── EU AI Act application timeline (Art. 113, Regulation 2024/1689) ─────────
# Reflects the "AI Act Omnibus" agreement reached by Council and Parliament
# on 7 May 2026 (Omnibus VII), which postponed several high-risk deadlines
# and added a new Art. 5 prohibition (NCII / synthetic CSAM).
#
# Sources:
#   - Reg. (EU) 2024/1689 (original AI Act)
#   - Council/Parliament press release 2026-05-07 (Omnibus VII agreement)
EU_AI_ACT_DEADLINES: dict[str, str] = {
    # Art. 5 prohibitions — already in force
    "prohibitions": "2025-02-02",
    # GPAI obligations Art. 50-55 — already in force
    "gpai_obligations": "2025-08-02",
    # Art. 50 transparency for synthetic content (watermarking).
    # Omnibus reduced the grace period 6m → 3m; new effective date below.
    "transparency_synthetic_content": "2026-12-02",
    # NEW Art. 5 prohibition: non-consensual intimate imagery + synthetic CSAM
    "prohibitions_ncii_csam": "2026-12-02",
    # Annex III high-risk (employment, education, biometrics, scoring, …)
    # Postponed from 2 Aug 2026 → 2 Dec 2027 by Omnibus VII.
    "high_risk_annex_iii": "2027-12-02",
    # National AI regulatory sandboxes (Art. 57)
    # Postponed from 2 Aug 2026 → 2 Aug 2027 by Omnibus VII.
    "national_sandboxes": "2027-08-02",
    # Annex I high-risk (medical devices, toys, regulated products)
    # Postponed from 2 Aug 2027 → 2 Aug 2028 by Omnibus VII.
    "high_risk_annex_i": "2028-08-02",
    # Latest applicable date — overall "full application" reference
    "full_application": "2028-08-02",
}

# Primary deadline used in dashboards / countdowns / single-value APIs.
# Annex III is the most relevant for the typical Admina user (it covers
# employment, scoring, education, biometrics — the bulk of operational AI).
EU_AI_ACT_ENFORCEMENT_DEADLINE: str = EU_AI_ACT_DEADLINES["high_risk_annex_iii"]


# ── Risk Classification Keywords ─────────────────────────────────────────────
# Source: EU AI Act Annex III + Art. 5 prohibited practices (Reg. 2024/1689,
# as amended by the Omnibus VII agreement of 7 May 2026).
# Update these when the Commission publishes delegated acts extending Annex III.

UNACCEPTABLE_RISK_KEYWORDS = [
    "social scoring",
    "social credit",
    "real-time biometric",
    "mass surveillance",
    "subliminal manipulation",
    # Added by Omnibus VII (effective 2 Dec 2026):
    "non-consensual intimate imagery",
    "non-consensual deepfake",
    "synthetic csam",
    "ai-generated child sexual abuse",
    "deepfake nudification",
    "nudifier",
]

HIGH_RISK_KEYWORDS = [
    "credit scor",
    "recruitment",
    "hiring",
    "law enforcement",
    "critical infrastructure",
    "healthcare",
    "medical",
    "education",
    "migration",
    "border",
    "judicial",
    "biometric",
    "financial",
    "trading",
    "insurance",
]

HIGH_RISK_SENSITIVE_DATA = ["health", "biometric", "financial", "criminal", "genetic"]

LIMITED_RISK_KEYWORDS = [
    "chatbot",
    "conversational",
    "content generation",
    "emotion recognition",
    "deepfake",
    "synthetic media",
]


# EU AI Act Risk Categories
RISK_CATEGORIES = {
    "unacceptable": {
        "level": 4,
        "description": "Prohibited AI practices",
        "examples": [
            "social scoring",
            "real-time biometric identification",
            "manipulation of vulnerable groups",
            "non-consensual intimate imagery / synthetic CSAM (Omnibus VII, effective 2 Dec 2026)",
        ],
        "action": "PROHIBITED — Must not deploy",
    },
    "high": {
        "level": 3,
        "description": "High-risk AI systems requiring conformity assessment",
        "examples": [
            "credit scoring",
            "recruitment",
            "law enforcement",
            "critical infrastructure",
            "healthcare diagnostics",
        ],
        "action": "Requires conformity assessment, logging, human oversight",
    },
    "limited": {
        "level": 2,
        "description": "Limited risk with transparency obligations",
        "examples": ["chatbots", "emotion recognition", "deepfakes", "content generation"],
        "action": "Must inform users they are interacting with AI",
    },
    "minimal": {
        "level": 1,
        "description": "Minimal or no risk",
        "examples": ["spam filters", "inventory management", "video game AI"],
        "action": "No specific obligations, voluntary codes of conduct",
    },
}

# Compliance requirements for high-risk systems
HIGH_RISK_REQUIREMENTS = {
    "risk_management": {
        "name": "Risk Management System",
        "article": "Art. 9",
        "checks": [
            "Documented risk management process",
            "Risk identification and analysis",
            "Risk mitigation measures implemented",
            "Residual risk assessment completed",
        ],
    },
    "data_governance": {
        "name": "Data Governance",
        "article": "Art. 10",
        "checks": [
            "Training data quality measures",
            "Data bias examination",
            "Data provenance documentation",
            "Privacy impact assessment",
        ],
    },
    "technical_documentation": {
        "name": "Technical Documentation",
        "article": "Art. 11",
        "checks": [
            "System description and purpose",
            "Development process documentation",
            "Performance metrics documented",
            "Limitations and risks documented",
        ],
    },
    "record_keeping": {
        "name": "Record Keeping / Logging",
        "article": "Art. 12",
        "checks": [
            "Automatic event logging enabled",
            "Log retention period defined (min 6 months)",
            "Logs include traceability data",
            "Tamper-proof logging mechanism",
        ],
    },
    "transparency": {
        "name": "Transparency",
        "article": "Art. 13",
        "checks": [
            "Instructions for use provided",
            "Capabilities and limitations documented",
            "Human oversight measures described",
            "Performance characteristics disclosed",
        ],
    },
    "human_oversight": {
        "name": "Human Oversight",
        "article": "Art. 14",
        "checks": [
            "Human oversight interface exists",
            "Override mechanism available",
            "Escalation procedures defined",
            "Monitoring dashboards operational",
        ],
    },
    "accuracy_robustness": {
        "name": "Accuracy, Robustness, Cybersecurity",
        "article": "Art. 15",
        "checks": [
            "Accuracy metrics defined and monitored",
            "Robustness testing performed",
            "Cybersecurity measures implemented",
            "Adversarial attack resistance tested",
        ],
    },
}


class EUAIActCompliance:
    """
    Automated EU AI Act compliance checking and reporting.
    """

    def __init__(
        self,
        *,
        term_languages: Iterable[str] | None = None,
        extra_terms: Mapping[str, Mapping[str, Iterable[str]]] | None = None,
    ):
        """
        Args:
            term_languages: Languages of :data:`~admina.domains.compliance.
                ai_act_terms.TERMS` matched besides the English keywords;
                ``None`` = all of them.
            extra_terms: Terms of the caller, ``{risk class: {area: [term,
                ...]}}`` with the risk classes ``unacceptable``, ``high``
                and ``limited``, matched as the terms of a language
                (reported with ``lang`` ``"custom"``).

        Raises:
            ValueError: An unknown language or risk class.
        """
        self.assessments: list[dict] = []
        languages = list(TERM_LANGUAGES if term_languages is None else term_languages)
        unknown = [lang for lang in languages if lang not in TERMS]
        if unknown:
            raise ValueError(
                f"Unknown term language(s) {', '.join(unknown)}; "
                f"available: {', '.join(TERM_LANGUAGES)}"
            )
        self._terms: dict[str, Mapping[str, Mapping[str, Iterable[str]]]] = {
            lang: TERMS[lang] for lang in languages
        }
        if extra_terms:
            bad = [risk for risk in extra_terms if risk not in RISK_ORDER]
            if bad:
                raise ValueError(
                    f"Unknown risk class(es) {', '.join(bad)} in extra_terms; "
                    f"expected {', '.join(RISK_ORDER)}"
                )
            self._terms["custom"] = extra_terms

    def classify_risk(self, system_description: str, use_case: str, data_types: list[str]) -> dict:
        """
        Classify an AI system's risk level under the EU AI Act.

        The English keyword lists of this module are matched by substring;
        the terms of the other languages and of the caller on whole words
        (:mod:`admina.domains.compliance.ai_act_terms`). The result adds to
        the class ``matched_terms`` (``lang``, ``risk``, ``area``, ``term``
        of every match; English keywords have the area ``"keywords"``) and
        ``matched_areas`` (the areas of the class returned). The class is a
        proposal for a person to confirm.
        """
        description_lower = system_description.lower()
        use_case_lower = use_case.lower()

        def keywords(risk: str, keyword_list: list[str]) -> list[dict[str, str]]:
            return [
                {"lang": "en", "risk": risk, "area": "keywords", "term": kw}
                for kw in keyword_list
                if kw in description_lower or kw in use_case_lower
            ]

        matches = (
            keywords("unacceptable", UNACCEPTABLE_RISK_KEYWORDS)
            + keywords("high", HIGH_RISK_KEYWORDS)
            + keywords("limited", LIMITED_RISK_KEYWORDS)
            + [m.as_dict() for m in find_terms(f"{system_description}\n{use_case}", self._terms)]
        )

        def result(category: str) -> dict:
            areas = sorted({m["area"] for m in matches if m["risk"] == category})
            return {
                "risk_category": category,
                **RISK_CATEGORIES[category],
                "matched_terms": matches,
                "matched_areas": areas,
            }

        risks = {m["risk"] for m in matches}

        # Check for unacceptable risk indicators
        if "unacceptable" in risks:
            return result("unacceptable")

        # Check for high-risk indicators
        high_risk_score = 0
        if "high" in risks:
            high_risk_score += 2
        if any(dt in HIGH_RISK_SENSITIVE_DATA for dt in [d.lower() for d in data_types]):
            high_risk_score += 1

        if high_risk_score >= 2:
            return result("high")

        # Check for limited risk
        if "limited" in risks:
            return result("limited")

        return result("minimal")

    def gap_analysis(self, risk_category: str, current_compliance: dict[str, list[bool]]) -> dict:
        """
        Perform gap analysis for a high-risk AI system.
        current_compliance: {requirement_key: [True/False for each check]}
        """
        if risk_category not in ("high", "unacceptable"):
            return {
                "applicable": False,
                "message": f"Full gap analysis not required for {risk_category}-risk systems",
            }

        gaps = []
        total_checks = 0
        passed_checks = 0

        for req_key, req_info in HIGH_RISK_REQUIREMENTS.items():
            n = len(req_info["checks"])
            declared = _coerce_checks(current_compliance.get(req_key), n)
            for i, (check_desc, is_met) in enumerate(zip(req_info["checks"], declared)):
                total_checks += 1
                if is_met:
                    passed_checks += 1
                else:
                    gaps.append(
                        {
                            "requirement": req_info["name"],
                            "article": req_info["article"],
                            "check": check_desc,
                            "status": "NOT_MET",
                        }
                    )

        compliance_score = round(passed_checks / max(total_checks, 1) * 100, 1)

        result = {
            "applicable": True,
            "compliance_score": compliance_score,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "gaps": gaps,
            "gap_count": len(gaps),
            "status": "COMPLIANT" if compliance_score == 100 else "GAPS_FOUND",
            "enforcement_deadline": EU_AI_ACT_ENFORCEMENT_DEADLINE,
            "assessed_at": datetime.now(UTC).isoformat(),
        }

        self.assessments.append(result)
        return result

    def generate_report(self, system_name: str, classification: dict, gap_result: dict) -> dict:
        """Generate a compliance report summary."""
        return {
            "report_title": f"EU AI Act Compliance Report — {system_name}",
            "generated_at": datetime.now(UTC).isoformat(),
            "system_name": system_name,
            "risk_classification": classification,
            "gap_analysis": gap_result,
            "recommendations": self._generate_recommendations(gap_result),
            "next_steps": [
                "Address all identified gaps before enforcement deadline",
                "Schedule conformity assessment if high-risk",
                "Establish ongoing monitoring and review process",
                "Appoint AI compliance officer",
            ],
        }

    def _generate_recommendations(self, gap_result: dict) -> list[str]:
        recs = []
        if not gap_result.get("applicable"):
            return ["Continue voluntary best practices"]

        gap_areas = set(g["requirement"] for g in gap_result.get("gaps", []))
        if "Record Keeping / Logging" in gap_areas:
            recs.append(
                "PRIORITY: Enable Admina Forensic Black Box for tamper-proof logging (Art. 12)"
            )
        if "Human Oversight" in gap_areas:
            recs.append(
                "PRIORITY: Configure escalation policies and human-in-the-loop workflows (Art. 14)"
            )
        if "Accuracy, Robustness, Cybersecurity" in gap_areas:
            recs.append("Enable Anti-Injection Firewall and Loop Breaker for robustness (Art. 15)")
        if "Transparency" in gap_areas:
            recs.append("Document agent capabilities and limitations in system registry (Art. 13)")
        if "Data Governance" in gap_areas:
            recs.append("Enable PII Redaction and configure data governance policies (Art. 10)")

        return recs if recs else ["All requirements met — maintain compliance posture"]

    def get_stats(self) -> dict:
        return {
            "total_assessments": len(self.assessments),
            "enforcement_deadline": EU_AI_ACT_ENFORCEMENT_DEADLINE,
        }
