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

Assessments: :meth:`EUAIActCompliance.gap_analysis` records one assessment
for every risk category. The last :data:`MAX_ASSESSMENTS` are kept in
memory and, when the engine has a ``storage_path``, in a JSON file written
atomically and read back at startup (in the proxy:
:data:`ASSESSMENTS_PATH_ENV`).
"""

import json
import logging
import os
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from admina.domains.compliance.ai_act_terms import RISK_ORDER, TERM_LANGUAGES, TERMS, find_terms
from admina.domains.compliance.forensic_files import atomic_write, ensure_directory

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

# Risk categories whose obligations include Articles 9–15: the gap analysis
# applies to them only.
GAP_ANALYSIS_CATEGORIES = ("high", "unacceptable")

# Message of an assessment of a category outside GAP_ANALYSIS_CATEGORIES.
NOT_APPLICABLE_MESSAGE = "Articles 9–15 apply to high-risk systems only"

# Assessments kept in memory and in the storage file (the most recent ones).
MAX_ASSESSMENTS = 100

# Environment variable of the proxy naming the JSON file of the assessments;
# unset, the proxy keeps them in memory only.
ASSESSMENTS_PATH_ENV = "ADMINA_EU_AI_ACT_ASSESSMENTS_PATH"

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
        storage_path: str | Path | None = None,
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
            storage_path: JSON file of the assessments, read here and
                rewritten atomically after each one; ``None`` = in memory
                only. A missing file starts empty. A malformed one is
                renamed to ``<name>.corrupt-<UTC time>`` and the store starts
                empty; one that cannot be read (or renamed) is left as it is
                and the assessments are kept in memory only. Both are logged.

        Raises:
            ValueError: An unknown language or risk class.
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self._write_blocked = False
        self.assessments: list[dict] = self._load()
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

    # ── persistence ──────────────────────────────────────────────
    def _load(self) -> list[dict]:
        if self.storage_path is None or not self.storage_path.exists():
            return []
        try:
            text = self.storage_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            self._set_aside(f"not UTF-8 ({exc.reason})")
            return []
        except OSError as exc:
            # Its content is unknown: the file is left as it is.
            self._write_blocked = True
            logger.warning(
                "Failed to read EU AI Act assessments from %s (%s); the file is not "
                "overwritten and new assessments are kept in memory only",
                self.storage_path,
                exc,
            )
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            self._set_aside(f"invalid JSON ({exc.msg})")
            return []
        if not isinstance(data, list) or not all(isinstance(a, dict) for a in data):
            self._set_aside("not a list of objects")
            return []
        return data[-MAX_ASSESSMENTS:]

    def _set_aside(self, reason: str) -> None:
        """Rename the malformed file to ``<name>.corrupt-<UTC time>`` so that
        the next assessment does not replace its content; when it cannot be
        renamed, it is not overwritten either."""
        path = self.storage_path
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        kept = path.with_name(f"{path.name}.corrupt-{stamp}")
        try:
            os.replace(path, kept)
        except OSError as exc:
            self._write_blocked = True
            logger.warning(
                "Ignoring EU AI Act assessments in %s: %s; it could not be renamed (%s), so "
                "it is not overwritten and new assessments are kept in memory only",
                path,
                reason,
                exc,
            )
            return
        logger.warning(
            "Ignoring EU AI Act assessments in %s: %s; the file was moved to %s",
            path,
            reason,
            kept.name,
        )

    def _save(self) -> None:
        if self.storage_path is None or self._write_blocked:
            return  # in-memory mode, or a file that must not be replaced
        try:
            ensure_directory(self.storage_path.parent)
            data = json.dumps(self.assessments, indent=2, ensure_ascii=False)
            atomic_write(self.storage_path, data.encode("utf-8"))
        except OSError as exc:
            logger.warning(
                "Failed to persist EU AI Act assessments to %s: %s", self.storage_path, exc
            )

    def _record(self, result: dict) -> None:
        self.assessments.append(result)
        if len(self.assessments) > MAX_ASSESSMENTS:
            self.assessments = self.assessments[-MAX_ASSESSMENTS:]
        self._save()

    def latest(self) -> dict | None:
        """The most recent assessment, or None without any."""
        return self.assessments[-1] if self.assessments else None

    # ── gap analysis ─────────────────────────────────────────────
    @staticmethod
    def _check_requirements(current_compliance: Mapping[str, Any]) -> dict:
        """Score the Art. 9–15 checks of *current_compliance*."""
        gaps = []
        total_checks = 0
        passed_checks = 0

        for req_key, req_info in HIGH_RISK_REQUIREMENTS.items():
            n = len(req_info["checks"])
            declared = _coerce_checks(current_compliance.get(req_key), n)
            for check_desc, is_met in zip(req_info["checks"], declared):
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

        return {
            "compliance_score": round(passed_checks / max(total_checks, 1) * 100, 1),
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "gaps": gaps,
            "gap_count": len(gaps),
        }

    def gap_analysis(
        self,
        risk_category: str,
        current_compliance: Mapping[str, Any] | None = None,
        system_name: str | None = None,
        *,
        voluntary: bool = False,
    ) -> dict:
        """Record an assessment of an AI system of *risk_category*.

        ``high`` / ``unacceptable``: gap analysis of Articles 9–15 from
        *current_compliance* (``{requirement_key: [True/False for each
        check]}``), ``applicable`` True and ``status`` ``COMPLIANT`` or
        ``GAPS_FOUND``.

        ``limited`` / ``minimal``: Articles 9–15 do not apply. The
        assessment has ``applicable`` False, ``status`` ``NOT_APPLICABLE``,
        ``compliance_score`` None and ``total_checks`` 0;
        *current_compliance* is ignored. With *voluntary* the checks of
        *current_compliance* are scored as for a high-risk system and kept
        with ``voluntary`` True, as a best-practice self-assessment; the
        status stays ``NOT_APPLICABLE``.

        Every assessment carries ``risk_category``, ``system_name``,
        ``assessed_at`` and ``enforcement_deadline``, and is recorded
        (:attr:`assessments`, at most :data:`MAX_ASSESSMENTS`).

        Raises:
            ValueError: *risk_category* is not one of ``RISK_CATEGORIES``.
        """
        if not isinstance(risk_category, str) or risk_category not in RISK_CATEGORIES:
            raise ValueError(
                f"Unknown risk category {risk_category!r}; "
                f"expected one of {', '.join(RISK_CATEGORIES)}"
            )
        current_compliance = current_compliance or {}

        if risk_category not in GAP_ANALYSIS_CATEGORIES:
            result: dict[str, Any] = {
                "applicable": False,
                "status": "NOT_APPLICABLE",
                "risk_category": risk_category,
                "system_name": system_name,
                "message": NOT_APPLICABLE_MESSAGE,
                "compliance_score": None,
                "total_checks": 0,
            }
            if voluntary:
                result.update(self._check_requirements(current_compliance))
                result["voluntary"] = True
            result["enforcement_deadline"] = EU_AI_ACT_ENFORCEMENT_DEADLINE
            result["assessed_at"] = datetime.now(UTC).isoformat()
            self._record(result)
            return result

        checks = self._check_requirements(current_compliance)
        result = {
            "applicable": True,
            **checks,
            "status": "COMPLIANT" if checks["compliance_score"] == 100 else "GAPS_FOUND",
            "risk_category": risk_category,
            "system_name": system_name,
            "enforcement_deadline": EU_AI_ACT_ENFORCEMENT_DEADLINE,
            "assessed_at": datetime.now(UTC).isoformat(),
        }

        self._record(result)
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
            "storage_path": str(self.storage_path) if self.storage_path else None,
            "persistence": "filesystem" if self.storage_path else "in-memory",
        }
