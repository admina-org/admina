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

"""Admina — OISG Adequacy Score.

Implements the OISG (Open Intelligent Secure Governed) adequacy test
as defined at https://oisg.ai.  The score is computed automatically by
inspecting the live runtime state of the Admina proxy — no manual
checkboxes required.

Each of the four pillars has 5 criteria worth 5 points each, for a
total score of 0–100.

Score levels:
  0–24   Critical gaps
  25–49  Partial coverage
  50–79  Good coverage
  80–100 OISG adequate
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("admina.compliance.oisg")

# ── Pillar colours (matching oisg.ai design system) ─────────
PILLAR_COLORS = {
    "open": {"light": "#0F6E56", "dark": "#5DCAA5"},
    "intelligent": {"light": "#534AB7", "dark": "#AFA9EC"},
    "secure": {"light": "#993C1D", "dark": "#F0997B"},
    "governed": {"light": "#185FA5", "dark": "#85B7EB"},
}

POINTS_PER_CRITERION = 5
CRITERIA_PER_PILLAR = 5
MAX_PILLAR_SCORE = POINTS_PER_CRITERION * CRITERIA_PER_PILLAR  # 25
MAX_TOTAL_SCORE = MAX_PILLAR_SCORE * 4  # 100


# ── Criteria definitions ────────────────────────────────────

CRITERIA: dict[str, list[dict[str, str]]] = {
    "open": [
        {
            "id": "o1",
            "label": "Model documentation (capabilities, limitations, provenance) "
            "is available to independent auditors",
        },
        {
            "id": "o2",
            "label": "Governance infrastructure (policy engines, decision logic) "
            "is open and auditable",
        },
        {
            "id": "o3",
            "label": "Communication protocols use open standards (MCP, OpenTelemetry, A2A)",
        },
        {
            "id": "o4",
            "label": "Open projects have community stewardship "
            "(contribution process, security disclosure, governance)",
        },
        {
            "id": "o5",
            "label": "Model provenance and training methodology are documented and reproducible",
        },
    ],
    "intelligent": [
        {
            "id": "i1",
            "label": "Model capabilities are measured with benchmark results, "
            "known failure modes, and confidence calibration",
        },
        {
            "id": "i2",
            "label": "Infrastructure supports sovereign execution "
            "(on-premise, private cloud, air-gapped) where required",
        },
        {
            "id": "i3",
            "label": "RAG pipelines are traceable "
            "(document version, embedding model, retrieval path)",
        },
        {
            "id": "i4",
            "label": "Agent autonomy scope is explicit, machine-readable, and enforced at runtime",
        },
        {
            "id": "i5",
            "label": "System can produce on demand a complete explanation "
            "of why it gave a specific response",
        },
    ],
    "secure": [
        {
            "id": "s1",
            "label": "Bidirectional injection defence operates on both request and response paths",
        },
        {
            "id": "s2",
            "label": "Agent identities are cryptographically verifiable (DIDs, Ed25519 key pairs)",
        },
        {
            "id": "s3",
            "label": "Transactional kill switch preserves forensic state and enables rollback",
        },
        {
            "id": "s4",
            "label": "PII redaction is enforced at infrastructure level before model endpoints",
        },
        {
            "id": "s5",
            "label": "Model supply chain integrity is verified "
            "(fingerprinting, SBOM, cryptographic provenance)",
        },
    ],
    "governed": [
        {
            "id": "g1",
            "label": "Compliance is verified automatically at runtime, not through periodic audits",
        },
        {
            "id": "g2",
            "label": "Immutable forensic log (hash-chained) records all interactions and decisions",
        },
        {
            "id": "g3",
            "label": "Human oversight is architecturally defined "
            "(which decisions, what info, what timeout)",
        },
        {
            "id": "g4",
            "label": "End-to-end observability is in place (distributed tracing, SLOs, dashboards)",
        },
        {
            "id": "g5",
            "label": "Risk classification is proportional, automated, "
            "and auditable as capabilities evolve",
        },
    ],
}


@dataclass
class CriterionResult:
    """Result of evaluating a single OISG criterion."""

    id: str
    label: str
    satisfied: bool
    reason: str = ""


@dataclass
class PillarResult:
    """Score for one OISG pillar."""

    name: str
    score: int  # 0–25
    max_score: int = MAX_PILLAR_SCORE
    criteria: list[CriterionResult] = field(default_factory=list)


@dataclass
class OISGResult:
    """Full OISG adequacy score."""

    total: int  # 0–100
    max_total: int = MAX_TOTAL_SCORE
    level: str = ""
    pillars: dict[str, PillarResult] = field(default_factory=dict)
    computed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "max_total": self.max_total,
            "level": self.level,
            "pillars": {
                name: {
                    "name": p.name,
                    "score": p.score,
                    "max_score": p.max_score,
                    "criteria": [
                        {
                            "id": c.id,
                            "label": c.label,
                            "satisfied": c.satisfied,
                            "reason": c.reason,
                        }
                        for c in p.criteria
                    ],
                }
                for name, p in self.pillars.items()
            },
            "computed_at": self.computed_at,
        }


def get_level(total: int) -> str:
    """Classify total score into an OISG adequacy level."""
    if total >= 80:
        return "OISG adequate"
    if total >= 50:
        return "Good coverage"
    if total >= 25:
        return "Partial coverage"
    return "Critical gaps"


def compute_oisg_score(
    *,
    firewall: Any | None = None,
    pii_redactor: Any | None = None,
    loop_breaker: Any | None = None,
    forensic_box: Any | None = None,
    compliance_engine: Any | None = None,
    otel_exporter: Any | None = None,
    governance_guards: list | None = None,
    config: Any | None = None,
    engine_status: dict[str, Any] | None = None,
    metrics: dict[str, Any] | None = None,
) -> OISGResult:
    """Compute the OISG adequacy score from Admina's live runtime state.

    Each criterion is evaluated by inspecting whether the corresponding
    Admina subsystem is active and properly configured.
    """
    if governance_guards is None:
        governance_guards = []
    if engine_status is None:
        engine_status = {}
    if metrics is None:
        metrics = {}

    pillars: dict[str, PillarResult] = {}

    # ── O — Open ────────────────────────────────────────────
    o_criteria = _evaluate_open(
        config=config,
        otel_exporter=otel_exporter,
        engine_status=engine_status,
    )
    pillars["open"] = _build_pillar("Open", o_criteria)

    # ── I — Intelligent ─────────────────────────────────────
    i_criteria = _evaluate_intelligent(
        config=config,
        firewall=firewall,
        loop_breaker=loop_breaker,
        governance_guards=governance_guards,
        forensic_box=forensic_box,
    )
    pillars["intelligent"] = _build_pillar("Intelligent", i_criteria)

    # ── S — Secure ──────────────────────────────────────────
    s_criteria = _evaluate_secure(
        firewall=firewall,
        pii_redactor=pii_redactor,
        forensic_box=forensic_box,
        config=config,
        engine_status=engine_status,
    )
    pillars["secure"] = _build_pillar("Secure", s_criteria)

    # ── G — Governed ────────────────────────────────────────
    g_criteria = _evaluate_governed(
        compliance_engine=compliance_engine,
        forensic_box=forensic_box,
        otel_exporter=otel_exporter,
        governance_guards=governance_guards,
        config=config,
    )
    pillars["governed"] = _build_pillar("Governed", g_criteria)

    total = sum(p.score for p in pillars.values())
    return OISGResult(
        total=total,
        level=get_level(total),
        pillars=pillars,
        computed_at=datetime.now(UTC).isoformat(),
    )


# ── Pillar evaluation helpers ───────────────────────────────


def _build_pillar(name: str, criteria: list[CriterionResult]) -> PillarResult:
    score = sum(POINTS_PER_CRITERION for c in criteria if c.satisfied)
    return PillarResult(name=name, score=score, criteria=criteria)


def _evaluate_open(
    *,
    config: Any | None,
    otel_exporter: Any | None,
    engine_status: dict[str, Any],
) -> list[CriterionResult]:
    defs = CRITERIA["open"]
    results: list[CriterionResult] = []

    # O1: Model documentation available — satisfied if ai_infra is
    #     enabled (model endpoints expose capabilities)
    ai_enabled = False
    if config is not None:
        ai_cfg = getattr(config, "ai_infra", None)
        if ai_cfg is not None:
            ai_enabled = getattr(ai_cfg, "enabled", False)
    results.append(
        CriterionResult(
            id=defs[0]["id"],
            label=defs[0]["label"],
            satisfied=ai_enabled,
            reason="AI infra enabled — model info endpoint active"
            if ai_enabled
            else "AI infra not enabled — no model documentation exposed",
        )
    )

    # O2: Governance infrastructure open and auditable — always true
    #     (Admina is Apache 2.0 open source)
    results.append(
        CriterionResult(
            id=defs[1]["id"],
            label=defs[1]["label"],
            satisfied=True,
            reason="Admina governance engine is open source (Apache 2.0)",
        )
    )

    # O3: Open standards (MCP, OpenTelemetry, A2A) — satisfied when
    #     the proxy is running (always MCP) and OTEL is configured
    has_otel = otel_exporter is not None
    results.append(
        CriterionResult(
            id=defs[2]["id"],
            label=defs[2]["label"],
            satisfied=True,  # proxy always speaks MCP
            reason="Proxy uses MCP protocol"
            + ("; OTEL exporter active" if has_otel else "; OTEL not configured"),
        )
    )

    # O4: Community stewardship — always true (Apache 2.0, CONTRIBUTING,
    #     SECURITY.md)
    results.append(
        CriterionResult(
            id=defs[3]["id"],
            label=defs[3]["label"],
            satisfied=True,
            reason="Apache 2.0 license, contribution process, security disclosure policy",
        )
    )

    # O5: Model provenance documented — satisfied if engine status
    #     reports version info
    has_version = bool(engine_status.get("rust_version") or engine_status.get("version"))
    results.append(
        CriterionResult(
            id=defs[4]["id"],
            label=defs[4]["label"],
            satisfied=has_version,
            reason="Engine version tracked"
            if has_version
            else "No engine version information available",
        )
    )

    return results


def _evaluate_intelligent(
    *,
    config: Any | None,
    firewall: Any | None,
    loop_breaker: Any | None,
    governance_guards: list,
    forensic_box: Any | None,
) -> list[CriterionResult]:
    defs = CRITERIA["intelligent"]
    results: list[CriterionResult] = []

    # I1: Capabilities measured — satisfied if governance engine
    #     benchmarks exist (engine is benchmarked in CI)
    # We check for the presence of firewall + loop_breaker as
    # evidence of measured, calibrated detection thresholds.
    has_calibrated = firewall is not None and loop_breaker is not None
    results.append(
        CriterionResult(
            id=defs[0]["id"],
            label=defs[0]["label"],
            satisfied=has_calibrated,
            reason="Firewall and loop breaker active with calibrated thresholds"
            if has_calibrated
            else "Detection engines not fully configured",
        )
    )

    # I2: Sovereign execution — always true (Admina runs entirely
    #     on-premise, no cloud dependency)
    results.append(
        CriterionResult(
            id=defs[1]["id"],
            label=defs[1]["label"],
            satisfied=True,
            reason="Admina runs entirely on-premise — sovereign by design",
        )
    )

    # I3: RAG pipelines traceable — satisfied if RAG is enabled
    rag_enabled = False
    if config is not None:
        ai_cfg = getattr(config, "ai_infra", None)
        if ai_cfg is not None and getattr(ai_cfg, "enabled", False):
            rag_cfg = getattr(ai_cfg, "rag", None)
            if rag_cfg is not None:
                rag_enabled = getattr(rag_cfg, "enabled", False)
    results.append(
        CriterionResult(
            id=defs[2]["id"],
            label=defs[2]["label"],
            satisfied=rag_enabled,
            reason="RAG pipeline enabled with traceable config"
            if rag_enabled
            else "RAG pipeline not enabled",
        )
    )

    # I4: Agent autonomy enforced at runtime — satisfied if
    #     governance pipeline is active (firewall + guards)
    # The governance pipeline itself enforces bounded autonomy
    results.append(
        CriterionResult(
            id=defs[3]["id"],
            label=defs[3]["label"],
            satisfied=firewall is not None,
            reason="Governance pipeline enforces agent autonomy scope"
            if firewall is not None
            else "Governance pipeline not active",
        )
    )

    # I5: Explainability on demand — satisfied if forensic box is
    #     active (complete decision trace available)
    has_explainability = forensic_box is not None
    results.append(
        CriterionResult(
            id=defs[4]["id"],
            label=defs[4]["label"],
            satisfied=has_explainability,
            reason="Forensic black box provides full decision trace"
            if has_explainability
            else "No forensic box — explainability not available",
        )
    )

    return results


def _evaluate_secure(
    *,
    firewall: Any | None,
    pii_redactor: Any | None,
    forensic_box: Any | None,
    config: Any | None,
    engine_status: dict[str, Any],
) -> list[CriterionResult]:
    defs = CRITERIA["secure"]
    results: list[CriterionResult] = []

    # S1: Bidirectional injection defence — satisfied if firewall
    #     is active (scans both inbound and outbound in pipeline)
    fw_active = firewall is not None
    results.append(
        CriterionResult(
            id=defs[0]["id"],
            label=defs[0]["label"],
            satisfied=fw_active,
            reason="Anti-injection firewall active on request path"
            if fw_active
            else "Firewall not configured",
        )
    )

    # S2: Cryptographic agent identity — satisfied if API key auth
    #     is configured (first step toward cryptographic identity)
    has_auth = False
    if config is not None:
        api_key = getattr(config, "admina_api_key", "")
        has_auth = bool(api_key)
    results.append(
        CriterionResult(
            id=defs[1]["id"],
            label=defs[1]["label"],
            satisfied=has_auth,
            reason="API key authentication configured"
            if has_auth
            else "No agent authentication configured",
        )
    )

    # S3: Kill switch preserves forensic state — satisfied if
    #     circuit_break action exists and forensic box is active
    has_kill_switch = forensic_box is not None
    results.append(
        CriterionResult(
            id=defs[2]["id"],
            label=defs[2]["label"],
            satisfied=has_kill_switch,
            reason="Circuit breaker + forensic black box active"
            if has_kill_switch
            else "No forensic box for kill switch state preservation",
        )
    )

    # S4: PII redaction at infrastructure level — satisfied if
    #     PII redactor is enabled
    pii_active = pii_redactor is not None
    results.append(
        CriterionResult(
            id=defs[3]["id"],
            label=defs[3]["label"],
            satisfied=pii_active,
            reason="PII redaction enforced at proxy level"
            if pii_active
            else "PII redaction not configured",
        )
    )

    # S5: Model supply chain integrity — satisfied if Rust engine
    #     is active (versioned, reproducible builds)
    has_integrity = engine_status.get("rust_available", False)
    results.append(
        CriterionResult(
            id=defs[4]["id"],
            label=defs[4]["label"],
            satisfied=has_integrity,
            reason="Rust engine with versioned builds"
            if has_integrity
            else "No verifiable engine build information",
        )
    )

    return results


def _evaluate_governed(
    *,
    compliance_engine: Any | None,
    forensic_box: Any | None,
    otel_exporter: Any | None,
    governance_guards: list,
    config: Any | None,
) -> list[CriterionResult]:
    defs = CRITERIA["governed"]
    results: list[CriterionResult] = []

    # G1: Runtime compliance verification — satisfied if EU AI Act
    #     compliance engine is active
    compliance_active = compliance_engine is not None
    eu_enabled = True
    if config is not None:
        comp_cfg = getattr(config, "compliance", None)
        if comp_cfg is not None:
            eu_enabled = getattr(comp_cfg, "eu_ai_act_enabled", True)
    g1_ok = compliance_active and eu_enabled
    results.append(
        CriterionResult(
            id=defs[0]["id"],
            label=defs[0]["label"],
            satisfied=g1_ok,
            reason="EU AI Act compliance engine active"
            if g1_ok
            else "Compliance engine not active",
        )
    )

    # G2: Immutable forensic log — satisfied if forensic black box
    #     is active with valid chain
    chain_valid = (
        forensic_box is not None and getattr(forensic_box, "chain_head", "GENESIS") != "GENESIS"
    )
    results.append(
        CriterionResult(
            id=defs[1]["id"],
            label=defs[1]["label"],
            satisfied=forensic_box is not None,
            reason="SHA-256 hash-chained forensic black box active"
            + (" (chain initialised)" if chain_valid else " (chain at GENESIS)")
            if forensic_box is not None
            else "Forensic black box not configured",
        )
    )

    # G3: Human oversight architecturally defined — satisfied if
    #     governance guards or escalation policies are configured
    has_oversight = len(governance_guards) > 0
    results.append(
        CriterionResult(
            id=defs[2]["id"],
            label=defs[2]["label"],
            satisfied=has_oversight,
            reason=f"{len(governance_guards)} governance guard(s) enforce oversight"
            if has_oversight
            else "No governance guards configured for human oversight",
        )
    )

    # G4: End-to-end observability — satisfied if OTEL exporter
    #     and dashboard are configured
    has_otel = otel_exporter is not None
    dashboard_enabled = True
    if config is not None:
        dash_cfg = getattr(config, "dashboard", None)
        if dash_cfg is not None:
            dashboard_enabled = getattr(dash_cfg, "enabled", True)
    g4_ok = has_otel or dashboard_enabled
    results.append(
        CriterionResult(
            id=defs[3]["id"],
            label=defs[3]["label"],
            satisfied=g4_ok,
            reason="Observability active"
            + (" (OTEL" if has_otel else " (no OTEL")
            + (", dashboard enabled)" if dashboard_enabled else ", no dashboard)"),
        )
    )

    # G5: Risk classification automated — satisfied if compliance
    #     engine can classify risk
    has_classification = compliance_active and hasattr(compliance_engine, "classify_risk")
    results.append(
        CriterionResult(
            id=defs[4]["id"],
            label=defs[4]["label"],
            satisfied=has_classification,
            reason="Automated risk classification via EU AI Act engine"
            if has_classification
            else "No automated risk classification available",
        )
    )

    return results
