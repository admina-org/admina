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

"""Admina — Compliance Domain.

Forensic black box, EU AI Act compliance, OISG adequacy score,
and OpenTelemetry.

Heavy or extras-gated symbols (ForensicBlackBox needs ``minio`` from
the ``[proxy]`` extra) are resolved lazily via PEP 562 ``__getattr__``
so importing this package never fails on a pure-SDK install.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from admina.domains.compliance.cross_regulation import (
    CROSS_REGULATION_MATRIX,
)
from admina.domains.compliance.cross_regulation import (
    coverage_summary as cross_regulation_summary,
)
from admina.domains.compliance.cross_regulation import to_markdown as cross_regulation_to_markdown
from admina.domains.compliance.eu_ai_act import (
    EU_AI_ACT_ENFORCEMENT_DEADLINE,
    HIGH_RISK_KEYWORDS,
    HIGH_RISK_SENSITIVE_DATA,
    LIMITED_RISK_KEYWORDS,
    UNACCEPTABLE_RISK_KEYWORDS,
    EUAIActCompliance,
)
from admina.domains.compliance.gdpr import (
    DPIA_REQUIRED_CRITERIA,
    ProcessingActivitiesRegistry,
    ProcessingActivity,
    render_dpia_template,
)
from admina.domains.compliance.nis2 import (
    NIS2_AREAS,
    NIS2_TRANSPOSITION_DEADLINE,
    NIS2Compliance,
)
from admina.domains.compliance.oisg import (
    CRITERIA as OISG_CRITERIA,
)
from admina.domains.compliance.oisg import (
    PILLAR_COLORS as OISG_PILLAR_COLORS,
)
from admina.domains.compliance.oisg import (
    CriterionResult,
    OISGResult,
    PillarResult,
    compute_oisg_score,
)
from admina.domains.compliance.oisg import (
    get_level as oisg_get_level,
)
from admina.domains.compliance.otel import OTELGovernanceExporter

if TYPE_CHECKING:  # pragma: no cover
    from admina.domains.compliance.forensic import ForensicBlackBox

__all__ = [
    "ForensicBlackBox",
    "EUAIActCompliance",
    "NIS2Compliance",
    "ProcessingActivitiesRegistry",
    "ProcessingActivity",
    "DPIA_REQUIRED_CRITERIA",
    "render_dpia_template",
    "CROSS_REGULATION_MATRIX",
    "cross_regulation_summary",
    "cross_regulation_to_markdown",
    "OTELGovernanceExporter",
    "EU_AI_ACT_ENFORCEMENT_DEADLINE",
    "UNACCEPTABLE_RISK_KEYWORDS",
    "HIGH_RISK_KEYWORDS",
    "HIGH_RISK_SENSITIVE_DATA",
    "LIMITED_RISK_KEYWORDS",
    "NIS2_AREAS",
    "NIS2_TRANSPOSITION_DEADLINE",
    "compute_oisg_score",
    "oisg_get_level",
    "OISGResult",
    "PillarResult",
    "CriterionResult",
    "OISG_CRITERIA",
    "OISG_PILLAR_COLORS",
]


def __getattr__(name: str):
    if name == "ForensicBlackBox":
        from admina.domains.compliance.forensic import ForensicBlackBox

        return ForensicBlackBox
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
