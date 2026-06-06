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

"""Tests for top-level admina imports."""

from __future__ import annotations


class TestTopLevelImports:
    """Verify all 4 SDK classes are importable from admina."""

    def test_import_governed_model(self) -> None:
        """GovernedModel is importable from admina."""
        from admina import GovernedModel

        assert GovernedModel is not None

    def test_import_governed_data(self) -> None:
        """GovernedData is importable from admina."""
        from admina import GovernedData

        assert GovernedData is not None

    def test_import_governed_agent(self) -> None:
        """GovernedAgent is importable from admina."""
        from admina import GovernedAgent

        assert GovernedAgent is not None

    def test_import_compliance_kit(self) -> None:
        """ComplianceKit is importable from admina."""
        from admina import ComplianceKit

        assert ComplianceKit is not None

    def test_all_four_in_single_import(self) -> None:
        """All 4 classes importable in a single statement."""
        from admina import ComplianceKit, GovernedAgent, GovernedData, GovernedModel

        assert GovernedModel.__name__ == "GovernedModel"
        assert GovernedData.__name__ == "GovernedData"
        assert GovernedAgent.__name__ == "GovernedAgent"
        assert ComplianceKit.__name__ == "ComplianceKit"

    def test_sdk_imports(self) -> None:
        """All 4 classes also importable from admina.sdk."""
        from admina.sdk import ComplianceKit, GovernedAgent, GovernedData, GovernedModel

        assert GovernedModel.__name__ == "GovernedModel"
        assert GovernedData.__name__ == "GovernedData"
        assert GovernedAgent.__name__ == "GovernedAgent"
        assert ComplianceKit.__name__ == "ComplianceKit"


class TestSDKOnlyImport:
    """SDK-only install must not require any [proxy]/[nlp]/[telemetry] extras.

    A user following the README's "SDK only (lightweight)" path runs
    `pip install admina-framework` (no extras) and then
    `from admina import GovernedModel`. That import chain must not
    transitively pull in boto3, spacy, sklearn, numpy, or any other
    optional dependency, otherwise the lightweight install is broken.
    """

    def test_admina_imports_without_optional_deps(self) -> None:
        """Block every optional dependency at the import-machinery level
        and confirm `from admina import <SDK class>` still works."""
        import importlib
        import sys

        blocked = {
            "boto3",  # [proxy]
            "spacy",  # [nlp]
            "sklearn",  # [nlp]
            "numpy",  # [nlp]
            "fastapi",  # [proxy]
            "uvicorn",  # [proxy]
            "redis",  # [proxy]
            "clickhouse_connect",  # [proxy]
            "opentelemetry",  # [telemetry]
        }

        class _Blocker:
            # Modern meta_path finder API (find_spec). Raising here makes the
            # blocked import fail with ModuleNotFoundError, which is what the
            # test asserts the SDK must tolerate.
            def find_spec(self, name, path=None, target=None):
                if name in blocked or any(name.startswith(b + ".") for b in blocked):
                    raise ModuleNotFoundError(f"blocked-by-test: {name}")
                return None

        # Drop any cached admina/sdk/domains modules so the import
        # actually re-runs through the blocker.
        for mod in list(sys.modules):
            if mod.startswith(
                (
                    "admina",
                    "sdk",
                    "admina.domains.compliance",
                    "admina.domains.data_sovereignty",
                    "admina.domains.agent_security",
                )
            ):
                del sys.modules[mod]

        sys.meta_path.insert(0, _Blocker())
        try:
            importlib.invalidate_caches()
            from admina import (  # noqa: F401
                ComplianceKit,
                GovernedAgent,
                GovernedData,
                GovernedModel,
            )
        finally:
            sys.meta_path.pop(0)
