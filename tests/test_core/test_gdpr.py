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

"""Tests for the GDPR base hub: RoPA registry + DPIA template."""

from __future__ import annotations

from pathlib import Path

import pytest

from admina.domains.compliance.gdpr import (
    DPIA_REQUIRED_CRITERIA,
    ProcessingActivitiesRegistry,
    ProcessingActivity,
    render_dpia_template,
)


@pytest.fixture
def reg(tmp_path: Path) -> ProcessingActivitiesRegistry:
    return ProcessingActivitiesRegistry(storage_path=tmp_path / "ropa.json")


class TestProcessingActivity:
    def test_auto_id_and_timestamps(self) -> None:
        act = ProcessingActivity(name="HR onboarding", purpose="employment")
        assert len(act.id) == 36  # uuid4 string
        assert act.created_at and act.updated_at  # auto-set


class TestRegistryCRUD:
    def test_create_then_list(self, reg: ProcessingActivitiesRegistry) -> None:
        rec = reg.create({"name": "Newsletter", "purpose": "marketing", "legal_basis": "consent"})
        assert rec["id"]
        listing = reg.list()
        assert len(listing) == 1 and listing[0]["name"] == "Newsletter"

    def test_get_returns_none_for_unknown(self, reg: ProcessingActivitiesRegistry) -> None:
        assert reg.get("nonexistent") is None

    def test_update_merges_and_bumps_updated_at(self, reg: ProcessingActivitiesRegistry) -> None:
        rec = reg.create({"name": "X", "purpose": "old"})
        original_updated = rec["updated_at"]
        out = reg.update(rec["id"], {"purpose": "new"})
        assert out["purpose"] == "new"
        assert out["created_at"] == rec["created_at"]  # immutable
        assert out["updated_at"] >= original_updated

    def test_update_unknown_returns_none(self, reg: ProcessingActivitiesRegistry) -> None:
        assert reg.update("ghost", {"name": "z"}) is None

    def test_delete_removes_record(self, reg: ProcessingActivitiesRegistry) -> None:
        rec = reg.create({"name": "tmp"})
        assert reg.delete(rec["id"]) is True
        assert reg.list() == []

    def test_delete_unknown_returns_false(self, reg: ProcessingActivitiesRegistry) -> None:
        assert reg.delete("ghost") is False

    def test_persistence_across_instances(self, tmp_path: Path) -> None:
        path = tmp_path / "ropa.json"
        r1 = ProcessingActivitiesRegistry(storage_path=path)
        r1.create({"name": "Onboarding", "legal_basis": "contract"})
        r2 = ProcessingActivitiesRegistry(storage_path=path)
        assert len(r2.list()) == 1
        assert r2.list()[0]["name"] == "Onboarding"

    def test_client_cannot_set_id(self, reg: ProcessingActivitiesRegistry) -> None:
        rec = reg.create({"id": "EVIL", "name": "n"})
        assert rec["id"] != "EVIL"

    def test_stats_groups_by_legal_basis(self, reg: ProcessingActivitiesRegistry) -> None:
        reg.create({"name": "A", "legal_basis": "consent"})
        reg.create({"name": "B", "legal_basis": "consent"})
        reg.create({"name": "C", "legal_basis": "contract"})
        stats = reg.get_stats()
        assert stats["total_activities"] == 3
        assert stats["by_legal_basis"]["consent"] == 2
        assert stats["by_legal_basis"]["contract"] == 1


class TestNoFilesystemSideEffects:
    """The default registry MUST NOT write files anywhere — operators
    have to opt in to persistence by passing storage_path or setting
    ADMINA_GDPR_ROPA_PATH. Regression guard for the "don't write in
    the user's filesystem unbidden" rule."""

    def test_default_is_in_memory_no_path(self, monkeypatch) -> None:
        # Ensure no env var leaks from the parent shell
        monkeypatch.delenv("ADMINA_GDPR_ROPA_PATH", raising=False)
        reg = ProcessingActivitiesRegistry()
        assert reg.storage_path is None

    def test_default_create_does_not_create_files(self, monkeypatch, tmp_path) -> None:
        monkeypatch.delenv("ADMINA_GDPR_ROPA_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        reg = ProcessingActivitiesRegistry()
        reg.create({"name": "test"})
        # cwd must be untouched
        assert list(tmp_path.iterdir()) == []

    def test_env_var_opts_in_to_persistence(self, monkeypatch, tmp_path) -> None:
        ropa = tmp_path / "ropa.json"
        monkeypatch.setenv("ADMINA_GDPR_ROPA_PATH", str(ropa))
        reg = ProcessingActivitiesRegistry()
        reg.create({"name": "x"})
        assert ropa.exists()

    def test_stats_reports_persistence_mode(self, monkeypatch) -> None:
        monkeypatch.delenv("ADMINA_GDPR_ROPA_PATH", raising=False)
        reg = ProcessingActivitiesRegistry()
        s = reg.get_stats()
        assert s["persistence"] == "in-memory"
        assert s["storage_path"] is None


class TestDPIATemplate:
    def test_dpia_required_criteria_complete(self) -> None:
        # WP29 lists 9 criteria; we ship them all so the operator can
        # check off triggers when deciding whether a DPIA is needed.
        assert len(DPIA_REQUIRED_CRITERIA) == 9

    def test_minimal_template_renders_markdown(self) -> None:
        md = render_dpia_template({})
        assert md.startswith("# Data Protection Impact Assessment (DPIA)")
        assert "## 1. Identification" in md
        assert "## 4. Risks" in md
        assert "_TBD_" in md  # placeholders for unspecified fields

    def test_populated_template_includes_facts(self) -> None:
        md = render_dpia_template(
            {
                "processing_name": "Customer profiling",
                "controller": "Acme S.p.A.",
                "dpo_contact": "dpo@acme.it",
                "purposes": "personalised offers",
                "legal_basis": "Art. 6(1)(a) consent",
                "data_categories": ["name", "email", "purchase history"],
                "identified_risks": [
                    {
                        "risk": "re-identification",
                        "likelihood": "medium",
                        "severity": "high",
                        "mitigation": "k-anonymity ≥ 5",
                    },
                ],
            }
        )
        assert "Customer profiling" in md
        assert "Acme S.p.A." in md
        assert "purchase history" in md
        assert "re-identification" in md
        assert "k-anonymity" in md

    def test_template_warns_about_legal_advice(self) -> None:
        md = render_dpia_template({})
        assert "not legal advice" in md.lower()
        assert "DPO" in md
