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

"""Tests for the n8n-nodes-admina community nodes package.

Validates:
1. Package structure completeness (all required files exist).
2. package.json is valid and has correct n8n configuration.
3. TypeScript node files have valid class exports and required properties.
4. Credentials file defines Admina API connection.
5. SVG icons exist for each node.
6. Node definitions reference the correct REST API endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

PACKAGE_DIR = (
    Path(__file__).parent.parent.parent / "admina" / "integrations" / "n8n" / "n8n-nodes-admina"
)


# ═══════════════════════════════════════════════════════════
# 1. Package structure
# ═══════════════════════════════════════════════════════════


class TestN8nPackageStructure:
    """Verify all required files exist in the package."""

    def test_package_json_exists(self) -> None:
        assert (PACKAGE_DIR / "package.json").is_file()

    def test_tsconfig_exists(self) -> None:
        assert (PACKAGE_DIR / "tsconfig.json").is_file()

    def test_readme_exists(self) -> None:
        assert (PACKAGE_DIR / "README.md").is_file()

    def test_credentials_file_exists(self) -> None:
        assert (PACKAGE_DIR / "credentials" / "AdminaApi.credentials.ts").is_file()

    def test_govern_node_exists(self) -> None:
        assert (PACKAGE_DIR / "nodes" / "AdminaGovern" / "AdminaGovern.node.ts").is_file()

    def test_audit_node_exists(self) -> None:
        assert (PACKAGE_DIR / "nodes" / "AdminaAudit" / "AdminaAudit.node.ts").is_file()

    def test_dashboard_trigger_exists(self) -> None:
        assert (PACKAGE_DIR / "nodes" / "AdminaDashboard" / "AdminaDashboard.trigger.ts").is_file()

    def test_govern_svg_exists(self) -> None:
        assert (PACKAGE_DIR / "nodes" / "AdminaGovern" / "admina-govern.svg").is_file()

    def test_audit_svg_exists(self) -> None:
        assert (PACKAGE_DIR / "nodes" / "AdminaAudit" / "admina-audit.svg").is_file()

    def test_dashboard_svg_exists(self) -> None:
        assert (PACKAGE_DIR / "nodes" / "AdminaDashboard" / "admina-dashboard.svg").is_file()


# ═══════════════════════════════════════════════════════════
# 2. package.json validation
# ═══════════════════════════════════════════════════════════


class TestN8nPackageJson:
    """Validate package.json has correct n8n community node config."""

    @pytest.fixture()
    def pkg(self) -> dict:
        return json.loads((PACKAGE_DIR / "package.json").read_text())

    def test_name(self, pkg: dict) -> None:
        assert pkg["name"] == "n8n-nodes-admina"

    def test_license(self, pkg: dict) -> None:
        assert pkg["license"] == "Apache-2.0"

    def test_has_n8n_section(self, pkg: dict) -> None:
        assert "n8n" in pkg

    def test_n8n_api_version(self, pkg: dict) -> None:
        assert pkg["n8n"]["n8nNodesApiVersion"] == 1

    def test_n8n_credentials_listed(self, pkg: dict) -> None:
        creds = pkg["n8n"]["credentials"]
        assert len(creds) == 1
        assert "AdminaApi.credentials" in creds[0]

    def test_n8n_nodes_listed(self, pkg: dict) -> None:
        nodes = pkg["n8n"]["nodes"]
        assert len(nodes) == 3
        node_names = " ".join(nodes)
        assert "AdminaGovern" in node_names
        assert "AdminaAudit" in node_names
        assert "AdminaDashboard" in node_names

    def test_has_community_keyword(self, pkg: dict) -> None:
        assert "n8n-community-node-package" in pkg.get("keywords", [])

    def test_has_build_script(self, pkg: dict) -> None:
        assert "build" in pkg.get("scripts", {})

    def test_has_typescript_dev_dependency(self, pkg: dict) -> None:
        dev_deps = pkg.get("devDependencies", {})
        assert "typescript" in dev_deps

    def test_has_n8n_workflow_peer_dependency(self, pkg: dict) -> None:
        peers = pkg.get("peerDependencies", {})
        assert "n8n-workflow" in peers


# ═══════════════════════════════════════════════════════════
# 3. TypeScript node definition validation
# ═══════════════════════════════════════════════════════════


class TestAdminaGovernNode:
    """Validate AdminaGovern.node.ts has correct structure."""

    @pytest.fixture()
    def source(self) -> str:
        return (PACKAGE_DIR / "nodes" / "AdminaGovern" / "AdminaGovern.node.ts").read_text()

    def test_exports_class(self, source: str) -> None:
        assert "export class AdminaGovern" in source

    def test_implements_inode_type(self, source: str) -> None:
        assert "implements INodeType" in source

    def test_has_description(self, source: str) -> None:
        assert "description: INodeTypeDescription" in source

    def test_display_name(self, source: str) -> None:
        assert "Admina Govern" in source

    def test_node_name(self, source: str) -> None:
        assert "'adminaGovern'" in source

    def test_has_execute_method(self, source: str) -> None:
        assert "async execute(" in source

    def test_uses_validate_endpoint(self, source: str) -> None:
        assert "/api/v1/validate" in source

    def test_uses_audit_endpoint(self, source: str) -> None:
        assert "/api/v1/audit" in source

    def test_references_credentials(self, source: str) -> None:
        assert "'adminaApi'" in source

    def test_has_check_mode_property(self, source: str) -> None:
        assert "'checkMode'" in source or '"checkMode"' in source

    def test_has_on_block_property(self, source: str) -> None:
        assert "'onBlock'" in source or '"onBlock"' in source

    def test_has_domain_options(self, source: str) -> None:
        assert "domainOptions" in source

    def test_domain_firewall(self, source: str) -> None:
        assert "firewall" in source.lower()

    def test_domain_pii(self, source: str) -> None:
        assert "pii" in source.lower()

    def test_domain_loop_breaker(self, source: str) -> None:
        assert "loopBreaker" in source or "loop" in source.lower()

    def test_has_log_to_forensic(self, source: str) -> None:
        assert "logToForensic" in source

    def test_icon_reference(self, source: str) -> None:
        assert "admina-govern.svg" in source


class TestAdminaAuditNode:
    """Validate AdminaAudit.node.ts has correct structure."""

    @pytest.fixture()
    def source(self) -> str:
        return (PACKAGE_DIR / "nodes" / "AdminaAudit" / "AdminaAudit.node.ts").read_text()

    def test_exports_class(self, source: str) -> None:
        assert "export class AdminaAudit" in source

    def test_implements_inode_type(self, source: str) -> None:
        assert "implements INodeType" in source

    def test_display_name(self, source: str) -> None:
        assert "Admina Audit" in source

    def test_node_name(self, source: str) -> None:
        assert "'adminaAudit'" in source

    def test_has_execute_method(self, source: str) -> None:
        assert "async execute(" in source

    def test_uses_audit_endpoint(self, source: str) -> None:
        assert "/api/v1/audit" in source

    def test_has_risk_classification(self, source: str) -> None:
        assert "riskClassification" in source

    def test_risk_options(self, source: str) -> None:
        assert "'high'" in source
        assert "'limited'" in source
        assert "'minimal'" in source

    def test_has_custom_metadata(self, source: str) -> None:
        assert "customMetadata" in source

    def test_icon_reference(self, source: str) -> None:
        assert "admina-audit.svg" in source


class TestAdminaDashboardTrigger:
    """Validate AdminaDashboard.trigger.ts has correct structure."""

    @pytest.fixture()
    def source(self) -> str:
        return (
            PACKAGE_DIR / "nodes" / "AdminaDashboard" / "AdminaDashboard.trigger.ts"
        ).read_text()

    def test_exports_class(self, source: str) -> None:
        assert "export class AdminaDashboard" in source

    def test_implements_inode_type(self, source: str) -> None:
        assert "implements INodeType" in source

    def test_display_name(self, source: str) -> None:
        assert "Admina Dashboard" in source

    def test_is_trigger(self, source: str) -> None:
        assert "'trigger'" in source

    def test_has_trigger_method(self, source: str) -> None:
        assert "async trigger(" in source

    def test_uses_websocket_endpoint(self, source: str) -> None:
        assert "/api/dashboard/live" in source

    def test_imports_websocket(self, source: str) -> None:
        assert "WebSocket" in source

    def test_has_event_filter(self, source: str) -> None:
        assert "eventFilter" in source

    def test_event_filter_block(self, source: str) -> None:
        assert "'BLOCK'" in source

    def test_event_filter_critical(self, source: str) -> None:
        assert "'CRITICAL'" in source

    def test_event_filter_pii(self, source: str) -> None:
        assert "'PII_DETECTED'" in source

    def test_has_reconnect(self, source: str) -> None:
        assert "reconnect" in source.lower()

    def test_has_close_function(self, source: str) -> None:
        assert "closeFunction" in source

    def test_icon_reference(self, source: str) -> None:
        assert "admina-dashboard.svg" in source


# ═══════════════════════════════════════════════════════════
# 4. Credentials validation
# ═══════════════════════════════════════════════════════════


class TestAdminaApiCredentials:
    """Validate AdminaApi.credentials.ts."""

    @pytest.fixture()
    def source(self) -> str:
        return (PACKAGE_DIR / "credentials" / "AdminaApi.credentials.ts").read_text()

    def test_exports_class(self, source: str) -> None:
        assert "export class AdminaApi" in source

    def test_implements_icredential_type(self, source: str) -> None:
        assert "implements ICredentialType" in source

    def test_has_name(self, source: str) -> None:
        assert "adminaApi" in source

    def test_has_proxy_url_property(self, source: str) -> None:
        assert "proxyUrl" in source

    def test_has_api_key_property(self, source: str) -> None:
        assert "apiKey" in source

    def test_proxy_url_default(self, source: str) -> None:
        assert "http://localhost:8080" in source

    def test_api_key_is_password(self, source: str) -> None:
        assert "password" in source


# ═══════════════════════════════════════════════════════════
# 5. SVG icon validation
# ═══════════════════════════════════════════════════════════


class TestSvgIcons:
    """Validate SVG icons are valid XML with svg root element."""

    @pytest.mark.parametrize(
        "svg_path",
        [
            "nodes/AdminaGovern/admina-govern.svg",
            "nodes/AdminaAudit/admina-audit.svg",
            "nodes/AdminaDashboard/admina-dashboard.svg",
        ],
    )
    def test_svg_is_valid(self, svg_path: str) -> None:
        content = (PACKAGE_DIR / svg_path).read_text()
        assert content.strip().startswith("<svg")
        assert "</svg>" in content
        assert 'xmlns="http://www.w3.org/2000/svg"' in content

    @pytest.mark.parametrize(
        "svg_path",
        [
            "nodes/AdminaGovern/admina-govern.svg",
            "nodes/AdminaAudit/admina-audit.svg",
            "nodes/AdminaDashboard/admina-dashboard.svg",
        ],
    )
    def test_svg_has_viewbox(self, svg_path: str) -> None:
        content = (PACKAGE_DIR / svg_path).read_text()
        assert "viewBox" in content


# ═══════════════════════════════════════════════════════════
# 6. tsconfig.json validation
# ═══════════════════════════════════════════════════════════


class TestTsConfig:
    """Validate tsconfig.json is valid and configured correctly."""

    @pytest.fixture()
    def tsconfig(self) -> dict:
        return json.loads((PACKAGE_DIR / "tsconfig.json").read_text())

    def test_target_es2020_or_later(self, tsconfig: dict) -> None:
        target = tsconfig["compilerOptions"]["target"]
        assert target in ("ES2020", "ES2021", "ES2022", "ESNext")

    def test_module_commonjs(self, tsconfig: dict) -> None:
        assert tsconfig["compilerOptions"]["module"] == "commonjs"

    def test_strict_mode(self, tsconfig: dict) -> None:
        assert tsconfig["compilerOptions"]["strict"] is True

    def test_out_dir(self, tsconfig: dict) -> None:
        assert tsconfig["compilerOptions"]["outDir"] == "./dist"

    def test_includes_nodes(self, tsconfig: dict) -> None:
        includes = tsconfig.get("include", [])
        assert any("nodes" in i for i in includes)

    def test_includes_credentials(self, tsconfig: dict) -> None:
        includes = tsconfig.get("include", [])
        assert any("credentials" in i for i in includes)


# ═══════════════════════════════════════════════════════════
# 7. README validation
# ═══════════════════════════════════════════════════════════


class TestReadme:
    """Validate README.md documents all nodes and endpoints."""

    @pytest.fixture()
    def readme(self) -> str:
        return (PACKAGE_DIR / "README.md").read_text()

    def test_mentions_all_nodes(self, readme: str) -> None:
        assert "Admina Govern" in readme
        assert "Admina Audit" in readme
        assert "Admina Dashboard" in readme

    def test_documents_validate_endpoint(self, readme: str) -> None:
        assert "/api/v1/validate" in readme

    def test_documents_audit_endpoint(self, readme: str) -> None:
        assert "/api/v1/audit" in readme

    def test_documents_websocket_endpoint(self, readme: str) -> None:
        assert "/api/dashboard/live" in readme

    def test_has_installation_instructions(self, readme: str) -> None:
        assert "install" in readme.lower()

    def test_has_workflow_example(self, readme: str) -> None:
        assert "workflow" in readme.lower()
