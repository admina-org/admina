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

"""Admina — cross-regulation control matrix (base).

A small, hand-curated mapping that shows which common operational
controls satisfy obligations across the three frameworks Admina
already covers in OSS: EU AI Act, NIS2, GDPR.

The matrix is **base coverage only** — twelve controls that show up
in essentially every operational compliance program. Full
sector-specific mappings (ISO 27001 ↔ NIS2 ↔ AI Act, NIST AI RMF ↔
ISO 42001, etc.) are out of scope for this release. Contributions
are welcome (see CONTRIBUTING.md).

Use cases:
  - Show "if you implement X, you also satisfy obligations from N
    different regulations" so the operator can plan once and report
    multiple times.
  - Drive a simple consolidated checklist in the dashboard.
  - Power the JSON / CSV / Markdown export for stakeholders that
    want to see all three regimes at a glance.
"""

from __future__ import annotations

from typing import Any

# Each entry: control id → {title, description, mappings}
# `mappings` is keyed by regulation; value is a short list of
# article references AND a one-liner explaining the link.
CROSS_REGULATION_MATRIX: dict[str, dict[str, Any]] = {
    "risk_assessment": {
        "title": "Documented risk assessment",
        "description": (
            "Periodic identification, evaluation and prioritisation of "
            "risks to the organisation's data, systems, and (where "
            "applicable) AI outputs."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 9", "note": "Risk management system for high-risk AI"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(a)", "note": "Risk analysis and security policy"},
            ],
            "gdpr": [
                {"ref": "Art. 35", "note": "DPIA when processing is likely to result in high risk"},
                {"ref": "Art. 32(1)", "note": "Security appropriate to risk"},
            ],
        },
    },
    "incident_handling": {
        "title": "Incident detection, response, and reporting",
        "description": (
            "Documented incident handling: detection, classification, "
            "internal response, post-mortem, regulator notification "
            "where required."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 62", "note": "Reporting of serious incidents"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(b)", "note": "Incident handling"},
                {"ref": "Art. 23", "note": "24h early warning + 72h notification + 1-month report"},
            ],
            "gdpr": [
                {"ref": "Art. 33", "note": "Personal data breach notification within 72h"},
                {"ref": "Art. 34", "note": "Communication to data subjects"},
            ],
        },
    },
    "encryption_in_transit_and_at_rest": {
        "title": "Encryption in transit and at rest",
        "description": "TLS for transport, encryption-at-rest for stored data.",
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 15(4)", "note": "Cybersecurity of high-risk systems"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(h)", "note": "Cryptography policies and procedures"},
            ],
            "gdpr": [
                {"ref": "Art. 32(1)(a)", "note": "Pseudonymisation and encryption"},
            ],
        },
    },
    "access_control_mfa": {
        "title": "Access control + MFA for privileged operations",
        "description": (
            "Role-based access control, MFA for admin and remote "
            "access, joiner/mover/leaver process."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 15(4)", "note": "Cybersecurity measures"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(i)", "note": "Access control + asset management"},
                {"ref": "Art. 21(2)(j)", "note": "Multi-factor authentication"},
            ],
            "gdpr": [
                {"ref": "Art. 32(1)(b)", "note": "Confidentiality and integrity"},
            ],
        },
    },
    "logging_and_audit_trail": {
        "title": "Tamper-evident logging and audit trail",
        "description": (
            "Append-only event log with chain integrity (hashes or "
            "signatures), enabling after-the-fact reconstruction of "
            "decisions and access."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 12", "note": "Record-keeping for high-risk systems"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(b)", "note": "Incident handling — supports investigation"},
            ],
            "gdpr": [
                {"ref": "Art. 30", "note": "Records of processing activities"},
                {"ref": "Art. 5(2)", "note": "Accountability principle"},
            ],
        },
    },
    "data_minimisation_and_retention": {
        "title": "Data minimisation and defined retention",
        "description": (
            "Collect only what is necessary; delete or anonymise when "
            "the retention period is reached."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 10(3)", "note": "Quality and relevance of training/validation data"},
            ],
            "nis2": [],  # no direct NIS2 obligation
            "gdpr": [
                {"ref": "Art. 5(1)(c)", "note": "Data minimisation"},
                {"ref": "Art. 5(1)(e)", "note": "Storage limitation"},
            ],
        },
    },
    "third_party_risk_management": {
        "title": "Third-party / supply-chain risk management",
        "description": (
            "Inventory of suppliers and processors, risk assessment, "
            "contractual security clauses, incident-notification clauses."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 25", "note": "Obligations along the AI value chain"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(d)", "note": "Supply chain security"},
            ],
            "gdpr": [
                {"ref": "Art. 28", "note": "Processor contractual obligations"},
                {"ref": "Art. 44-49", "note": "International transfers"},
            ],
        },
    },
    "human_oversight": {
        "title": "Human oversight of automated decisions",
        "description": (
            "A human reviewer can intervene, override, or audit "
            "decisions made by an automated system."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 14", "note": "Human oversight of high-risk AI"},
            ],
            "nis2": [],
            "gdpr": [
                {"ref": "Art. 22", "note": "Right not to be subject to solely automated decisions"},
            ],
        },
    },
    "transparency_and_information": {
        "title": "Transparency to end users / data subjects",
        "description": (
            "Users and data subjects are informed about purpose, "
            "logic, and consequences of processing — including AI "
            "interactions."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 13", "note": "Transparency for high-risk AI"},
                {"ref": "Art. 50", "note": "Transparency for chatbots / synthetic content"},
            ],
            "nis2": [],
            "gdpr": [
                {"ref": "Art. 12-14", "note": "Information to data subjects"},
            ],
        },
    },
    "training_and_awareness": {
        "title": "Staff training and security awareness",
        "description": "Annual training, phishing drills, role-specific awareness.",
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 4", "note": "AI literacy"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(g)", "note": "Cyber hygiene + cybersecurity training"},
            ],
            "gdpr": [
                {"ref": "Art. 39(1)(b)", "note": "DPO awareness-raising / training"},
            ],
        },
    },
    "business_continuity": {
        "title": "Business continuity and disaster recovery",
        "description": ("Backup strategy, disaster recovery plan, regular tests."),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 15(4)", "note": "Resilience of high-risk AI"},
            ],
            "nis2": [
                {
                    "ref": "Art. 21(2)(c)",
                    "note": "Business continuity, backup, DR, crisis management",
                },
            ],
            "gdpr": [
                {
                    "ref": "Art. 32(1)(c)",
                    "note": "Ability to restore availability and access in a timely manner",
                },
            ],
        },
    },
    "documentation_and_accountability": {
        "title": "Documentation of decisions and accountability",
        "description": (
            "Documented evidence that compliance measures are in place and operate as intended."
        ),
        "mappings": {
            "eu_ai_act": [
                {"ref": "Art. 11", "note": "Technical documentation for high-risk systems"},
            ],
            "nis2": [
                {"ref": "Art. 21(2)(f)", "note": "Effectiveness assessment"},
            ],
            "gdpr": [
                {"ref": "Art. 5(2)", "note": "Accountability principle"},
                {"ref": "Art. 24", "note": "Responsibility of the controller"},
            ],
        },
    },
}


REGULATIONS: tuple[str, ...] = ("eu_ai_act", "nis2", "gdpr")


def coverage_summary() -> dict[str, Any]:
    """Aggregate counts that can drive a compact dashboard widget.

    Returns the total number of controls and, for each regulation,
    how many controls touch it (i.e. have at least one mapping).
    """
    total = len(CROSS_REGULATION_MATRIX)
    by_reg: dict[str, int] = {r: 0 for r in REGULATIONS}
    for ctrl in CROSS_REGULATION_MATRIX.values():
        for reg in REGULATIONS:
            if ctrl["mappings"].get(reg):
                by_reg[reg] += 1
    return {
        "total_controls": total,
        "regulations": list(REGULATIONS),
        "controls_per_regulation": by_reg,
    }


def to_markdown() -> str:
    """Render the matrix as a stand-alone Markdown table.

    Used by the reporting export endpoint when the operator picks
    `format=markdown`. The frontend can show the same data as an
    HTML table without re-implementing it.
    """
    lines = [
        "# Cross-regulation control matrix",
        "",
        "Base coverage of operational controls across EU AI Act, NIS2, and GDPR.",
        "",
        "| Control | EU AI Act | NIS2 | GDPR |",
        "|---|---|---|---|",
    ]
    for ctrl_id, ctrl in CROSS_REGULATION_MATRIX.items():
        cells = []
        for reg in REGULATIONS:
            refs = ctrl["mappings"].get(reg) or []
            if refs:
                cells.append(", ".join(r["ref"] for r in refs))
            else:
                cells.append("—")
        lines.append(
            f"| **{ctrl['title']}**<br/>_{ctrl_id}_ | {cells[0]} | {cells[1]} | {cells[2]} |"
        )
    return "\n".join(lines) + "\n"
