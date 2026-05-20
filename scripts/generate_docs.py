#!/usr/bin/env python3
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

"""Generate API reference pages and architecture diagram for MkDocs.

Scans the codebase for public modules, classes, and functions, then
generates Markdown files with mkdocstrings directives and a Mermaid
architecture diagram.

Usage:
    python scripts/generate_docs.py          # generate all
    python scripts/generate_docs.py --api    # API reference only
    python scripts/generate_docs.py --arch   # architecture diagram only
"""

from __future__ import annotations

import argparse
import ast
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
API_DIR = DOCS / "api"
GUIDES_DIR = DOCS / "guides"

# ── Helpers ──────────────────────────────────────────────────


def _public_names(module_path: Path) -> list[dict]:
    """Parse a Python file and return public classes/functions."""
    try:
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []

    names: list[dict] = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            doc = ast.get_docstring(node) or ""
            names.append({"name": node.name, "kind": kind, "doc": doc.split("\n")[0]})
    return names


def _find_all_in(module_path: str) -> list[str] | None:
    """Read __all__ from a module file, if defined."""
    fpath = ROOT / module_path.replace(".", "/")
    candidates = [fpath.with_suffix(".py"), fpath / "__init__.py"]
    for p in candidates:
        if not p.exists():
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, ast.List):
                            return [
                                elt.value  # type: ignore[union-attr]
                                for elt in node.value.elts
                                if isinstance(elt, ast.Constant)
                            ]
    return None


# ── API Reference Pages ──────────────────────────────────────

# Each entry: (output_filename, page_title, list of (module_path, heading))
API_PAGES: list[tuple[str, str, list[tuple[str, str]]]] = [
    (
        "sdk.md",
        "SDK Overview",
        [("admina", "Top-level Exports")],
    ),
    (
        "governed-model.md",
        "GovernedModel",
        [("sdk.governed_model", "sdk.governed_model")],
    ),
    (
        "governed-data.md",
        "GovernedData",
        [("sdk.governed_data", "sdk.governed_data")],
    ),
    (
        "governed-agent.md",
        "GovernedAgent",
        [("sdk.governed_agent", "sdk.governed_agent")],
    ),
    (
        "compliance-kit.md",
        "ComplianceKit",
        [("sdk.compliance_kit", "sdk.compliance_kit")],
    ),
    (
        "core-types.md",
        "Core Types & Enums",
        [("core.types", "core.types")],
    ),
    (
        "event-bus.md",
        "Event Bus",
        [("core.event_bus", "core.event_bus")],
    ),
    (
        "config.md",
        "Configuration",
        [("core.config", "core.config")],
    ),
    (
        "domain-data-sovereignty.md",
        "Data Sovereignty",
        [
            ("domains.data_sovereignty.pii", "PII Redaction"),
        ],
    ),
    (
        "domain-agent-security.md",
        "Agent Security",
        [
            ("domains.agent_security.firewall", "Injection Firewall"),
            ("domains.agent_security.loop_breaker", "Loop Breaker"),
        ],
    ),
    (
        "domain-compliance.md",
        "Compliance",
        [
            ("domains.compliance.forensic", "Forensic Black Box"),
            ("domains.compliance.eu_ai_act", "EU AI Act"),
            ("domains.compliance.otel", "OpenTelemetry Export"),
        ],
    ),
    (
        "domain-ai-infra.md",
        "AI Infrastructure",
        [
            ("domains.ai_infra.llm_engine", "LLM Engine"),
            ("domains.ai_infra.rag", "RAG Pipeline"),
            ("domains.ai_infra.webui", "Web UI"),
        ],
    ),
    (
        "integration-api.md",
        "Integration REST API",
        [("proxy.api.integration", "proxy.api.integration")],
    ),
    (
        "plugins-base.md",
        "Plugin Interfaces",
        [("admina.plugins.base", "admina.plugins.base")],
    ),
    (
        "plugins-registry.md",
        "Plugin Registry",
        [("admina.plugins.registry", "admina.plugins.registry")],
    ),
    (
        "plugins-builtin.md",
        "Builtin Plugins",
        [
            ("plugins.builtin.adapters.ollama", "OllamaAdapter"),
            ("plugins.builtin.adapters.openai", "OpenAIAdapter"),
            ("plugins.builtin.connectors.chromadb", "ChromaDBConnector"),
            ("plugins.builtin.connectors.filesystem", "FilesystemConnector"),
            ("plugins.builtin.transports.mcp", "MCP Transport"),
            ("plugins.builtin.transports.http_rest", "HTTP REST Transport"),
            ("plugins.builtin.pii.spacy_regex", "spaCy + Regex PII"),
            ("plugins.builtin.auth.apikey", "API Key Auth"),
            ("plugins.builtin.forensic.minio", "MinIO Forensic Store"),
            ("plugins.builtin.forensic.filesystem", "Filesystem Forensic Store"),
            ("plugins.builtin.compliance.eu_ai_act", "EU AI Act Template"),
            ("plugins.builtin.guards.guardrailsai_guard", "GuardrailsAI Guard"),
            ("plugins.builtin.alerts.log", "Log Alert Channel"),
            ("plugins.builtin.alerts.webhook", "Webhook Alert Channel"),
        ],
    ),
]


def generate_api_pages() -> int:
    """Generate all API reference Markdown pages. Returns count."""
    API_DIR.mkdir(parents=True, exist_ok=True)
    count = 0

    for filename, title, modules in API_PAGES:
        lines: list[str] = [f"# {title}\n"]

        for mod_path, heading in modules:
            lines.append(f"\n## {heading}\n")
            lines.append(f"::: {mod_path}\n")

            # Show what __all__ exports
            all_names = _find_all_in(mod_path)
            if all_names:
                lines.append(f"\n**Exports:** `{'`, `'.join(all_names)}`\n")

        (API_DIR / filename).write_text("\n".join(lines), encoding="utf-8")
        count += 1

    print(f"  Generated {count} API reference pages in docs/api/")
    return count


# ── Architecture Diagram ─────────────────────────────────────


def _count_py_files(pkg_dir: Path) -> int:
    """Count .py files (excluding __init__) in a package."""
    if not pkg_dir.is_dir():
        return 0
    return sum(
        1 for f in pkg_dir.rglob("*.py") if f.name != "__init__.py" and not f.name.startswith("_")
    )


def _list_classes(pkg_dir: Path, max_items: int = 6) -> list[str]:
    """List public class names from a package directory."""
    classes: list[str] = []
    if not pkg_dir.is_dir():
        return classes
    for py in sorted(pkg_dir.rglob("*.py")):
        if py.name.startswith("_"):
            continue
        for item in _public_names(py):
            if item["kind"] == "class" and len(classes) < max_items:
                classes.append(item["name"])
    return classes


def generate_architecture_diagram() -> None:
    """Generate docs/guides/architecture.md with a Mermaid diagram."""
    GUIDES_DIR.mkdir(parents=True, exist_ok=True)

    # Collect data from the actual codebase
    sdk_classes = _list_classes(ROOT / "sdk")
    core_classes = _list_classes(ROOT / "core")
    plugin_bases = _list_classes(ROOT / "admina" / "plugins")
    builtin_count = _count_py_files(ROOT / "plugins" / "builtin")

    domain_info = {}
    for d in ["data_sovereignty", "agent_security", "compliance", "ai_infra"]:
        dpath = ROOT / "domains" / d
        domain_info[d] = _list_classes(dpath, max_items=4)

    proxy_modules = [
        f.stem
        for f in sorted((ROOT / "proxy").glob("*.py"))
        if not f.name.startswith("_") and f.name != "__init__.py"
    ]

    content = textwrap.dedent(f"""\
    # Architecture

    Admina is organized into layers: **SDK** (in-process), **Proxy** (network),
    **Governance Domains**, **Plugin System**, and **Core** types/events.

    ## System Overview

    ```mermaid
    graph TB
        subgraph Client["Client Applications"]
            APP["Your App / Agent"]
        end

        subgraph SDK["SDK Layer (in-process)"]
            GM["GovernedModel"]
            GD["GovernedData"]
            GA["GovernedAgent"]
            CK["ComplianceKit"]
        end

        subgraph Proxy["Governance Proxy (network)"]
            FW["Injection Firewall"]
            PII["PII Redactor"]
            LB["Loop Breaker"]
            GG["Governance Guards"]
        end

        subgraph Domains["Governance Domains"]
            DS["Data Sovereignty\\n(PII, Residency, Classification)"]
            AS["Agent Security\\n(Firewall, Loop Breaker)"]
            CO["Compliance\\n(EU AI Act, Forensic, OTEL)"]
            AI["AI Infrastructure\\n(LLM Engine, RAG, WebUI)"]
        end

        subgraph Core["Core"]
            TY["Types & Enums\\n(RiskLevel, GovernanceAction, EventType)"]
            EB["Event Bus\\n(pub/sub governance events)"]
            CF["Config\\n(AdminaConfig, YAML)"]
        end

        subgraph Plugins["Plugin System ({builtin_count} builtin)"]
            PR["Plugin Registry"]
            BA["9 Base Interfaces"]
        end

        subgraph Storage["Infrastructure"]
            RE[("Redis\\n(rate limiting)")]
            CH[("ClickHouse\\n(event store)")]
            MI[("MinIO\\n(forensic store)")]
        end

        subgraph Upstream["Upstream"]
            MCP["MCP Servers"]
            OL["Ollama / LLM"]
        end

        APP -->|"import"| SDK
        APP -->|"POST /mcp"| Proxy

        SDK --> Domains
        Proxy --> Domains
        Proxy --> Storage

        Domains --> Core
        Plugins --> Domains
        Proxy --> Upstream

        SDK --> EB
        Proxy --> EB
    ```

    ## Layer Details

    ### SDK ({len(sdk_classes)} classes)

    The SDK provides in-process governance primitives:

    | Class | Purpose |
    |-------|---------|
    | `GovernedModel` | Governed LLM inference with PII redaction |
    | `GovernedData` | Governed data access with residency zones |
    | `GovernedAgent` | Governed agent-to-agent MCP calls |
    | `ComplianceKit` | EU AI Act risk classification & gap analysis |

    ### Governance Domains

    ```mermaid
    graph LR
        subgraph ds["Data Sovereignty"]
            {chr(10).join(f"            {c}" for c in domain_info.get("data_sovereignty", []))}
        end
        subgraph as2["Agent Security"]
            {chr(10).join(f"            {c}" for c in domain_info.get("agent_security", []))}
        end
        subgraph co["Compliance"]
            {chr(10).join(f"            {c}" for c in domain_info.get("compliance", []))}
        end
        subgraph ai["AI Infrastructure"]
            {chr(10).join(f"            {c}" for c in domain_info.get("ai_infra", []))}
        end
    ```

    ### Plugin System

    9 extensible plugin interfaces with {builtin_count} builtin implementations:

    | Interface | Builtin |
    |-----------|---------|
    | `BaseModelAdapter` | OllamaAdapter, OpenAIAdapter |
    | `BaseDataConnector` | ChromaDBConnector, FilesystemConnector |
    | `BaseGovernanceGuard` | GuardrailsAIGuard |
    | `BaseTransportAdapter` | MCPTransport, HTTPRESTTransport |
    | `BaseForensicStore` | MinIOForensicStore, FilesystemForensicStore |
    | `BaseAuthProvider` | APIKeyAuthProvider |
    | `BasePIIEngine` | SpaCyRegexPIIEngine |
    | `BaseAlertChannel` | LogAlertChannel, WebhookAlertChannel |
    | `BaseComplianceTemplate` | EUAIActTemplate |

    ### Proxy Pipeline

    ```mermaid
    sequenceDiagram
        participant C as Client
        participant P as Proxy
        participant FW as Firewall
        participant PII as PII Redactor
        participant LB as Loop Breaker
        participant G as Guards
        participant U as Upstream MCP

        C->>P: POST /mcp (JSON-RPC)
        P->>P: Auth middleware
        P->>P: Rate limiting (Redis)
        P->>FW: Scan for injections
        alt Injection detected
            FW-->>P: BLOCK (403)
            P-->>C: 403 Forbidden
        end
        P->>PII: Redact PII from request
        P->>LB: Check for reasoning loops
        alt Loop detected
            LB-->>P: CIRCUIT_BREAK (429)
            P-->>C: 429 Too Many Requests
        end
        P->>G: Plugin guards inspection
        P->>U: Forward to upstream
        U-->>P: Response
        P->>G: Response inspection
        P->>PII: Redact PII from response
        P->>P: Store event (ClickHouse)
        P->>P: Emit to Event Bus
        P-->>C: Governed response
    ```

    ### Proxy Modules

    | Module | Purpose |
    |--------|---------|
    {chr(10).join(f"    | `{m}` | Proxy component |" for m in proxy_modules)}

    ### Core Types

    ```mermaid
    classDiagram
        class RiskLevel {{
            LOW
            MEDIUM
            HIGH
            CRITICAL
        }}
        class GovernanceAction {{
            ALLOW
            BLOCK
            REDACT
            ESCALATE
            CIRCUIT_BREAK
        }}
        class EventType {{
            MCP_REQUEST
            MODEL_CALL
            DATA_ACCESS
            AGENT_REQUEST
            GOVERNANCE_DECISION
            ...
        }}
        class GovernanceRequest {{
            +str content
            +str method
            +str direction
            +str session_id
            +dict metadata
        }}
        class GovernanceResponse {{
            +str content
            +str action
            +str risk_level
            +float latency_us
        }}
    ```
    """)

    (GUIDES_DIR / "architecture.md").write_text(content, encoding="utf-8")
    print("  Generated docs/guides/architecture.md with Mermaid diagrams")


# ── Main ─────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Admina documentation")
    parser.add_argument("--api", action="store_true", help="Generate API reference only")
    parser.add_argument("--arch", action="store_true", help="Generate architecture diagram only")
    args = parser.parse_args()

    generate_all = not args.api and not args.arch

    print("Admina docs generator")
    print("=" * 40)

    if generate_all or args.api:
        generate_api_pages()

    if generate_all or args.arch:
        generate_architecture_diagram()

    print("=" * 40)
    print("Done. Run 'uv run mkdocs serve' to preview.")


if __name__ == "__main__":
    main()
