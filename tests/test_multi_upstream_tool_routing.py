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

"""Routing of /mcp calls by tool name.

The routing file (``ROUTING_CONFIG_PATH``) declares, per route, the tools the
server provides (``tools:``). A ``tools/call`` on ``/mcp`` for a declared tool
goes to that route's upstream; any other call goes to ``UPSTREAM_MCP_URL``.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from admina.proxy.multi_upstream import MultiUpstreamRouter


def _write_routing(tmp_path, routes: dict, suffix: str = ".json"):
    path = tmp_path / f"routing{suffix}"
    path.write_text(json.dumps({"routes": routes}))
    return path


# ── Router ────────────────────────────────────────────────────


class TestToolMappingFromConfig:
    def test_tools_declared_on_a_route_resolve_to_it(self, tmp_path):
        router = MultiUpstreamRouter()
        router.load_config(
            _write_routing(
                tmp_path,
                {
                    "github": {
                        "upstream_url": "http://github-mcp/mcp",
                        "tools": ["git_push", "create_issue"],
                    },
                    "files": {"upstream_url": "http://files-mcp/mcp", "tools": ["read_file"]},
                },
            )
        )

        assert router.resolve_by_tool("git_push").name == "github"
        assert router.resolve_by_tool("create_issue").name == "github"
        assert router.resolve_by_tool("read_file").name == "files"
        assert router.routes["github"].tool_names == ["git_push", "create_issue"]
        assert router.get_stats()["tool_mappings"] == 3

    def test_unknown_tool_resolves_to_nothing(self, tmp_path):
        router = MultiUpstreamRouter()
        router.load_config(
            _write_routing(tmp_path, {"github": {"upstream_url": "http://g", "tools": ["x"]}})
        )

        assert router.resolve_by_tool("not_declared") is None

    def test_route_without_tools_maps_nothing(self, tmp_path):
        router = MultiUpstreamRouter()
        router.load_config(_write_routing(tmp_path, {"github": {"upstream_url": "http://g"}}))

        assert router.tool_to_server == {}
        assert router.routes["github"].tool_names == []

    def test_tool_declared_by_two_routes_is_a_config_error(self, tmp_path):
        path = _write_routing(
            tmp_path,
            {
                "github": {"upstream_url": "http://g", "tools": ["search"]},
                "files": {"upstream_url": "http://f", "tools": ["search"]},
            },
        )

        with pytest.raises(ValueError, match="'search'.*'github'.*'files'"):
            MultiUpstreamRouter().load_config(path)

    @pytest.mark.parametrize(
        "tools",
        ["git_push", ["git_push", ""], ["git_push", 3], {"git_push": True}],
    )
    def test_tools_must_be_a_list_of_names(self, tmp_path, tools):
        path = _write_routing(tmp_path, {"github": {"upstream_url": "http://g", "tools": tools}})

        with pytest.raises(ValueError, match="routes.github.tools"):
            MultiUpstreamRouter().load_config(path)

    def test_register_tool_mapping_rejects_a_tool_of_another_server(self):
        router = MultiUpstreamRouter()
        router.register_tool_mapping("github", ["search"])

        with pytest.raises(ValueError, match="'search'"):
            router.register_tool_mapping("files", ["search"])

    def test_yaml_routing_file_is_read(self, tmp_path):
        path = tmp_path / "routing.yaml"
        path.write_text(
            "default_upstream: http://default\n"
            "routes:\n"
            "  github:\n"
            "    upstream_url: http://github-mcp/mcp\n"
            "    tools: [git_push]\n"
        )
        router = MultiUpstreamRouter()
        router.load_config(path)

        assert router.default_upstream == "http://default"
        assert router.resolve_by_tool("git_push").name == "github"


# ── /mcp end to end ───────────────────────────────────────────


class _FakeFirewall:
    def check(self, text: str) -> dict:
        return {"is_injection": False, "risk_level": "low"}


class _FakePII:
    def redact(self, text: str) -> dict:
        return {"redacted_text": text, "entities": [], "count": 0}

    def get_stats(self) -> dict:
        return {}


class _FakeLoopBreaker:
    def check(self, session_id: str, content: str) -> dict:
        return {"is_loop": False, "similarity": 0.0}


def _post_tools_call(monkeypatch, router: MultiUpstreamRouter, tool: str) -> str:
    """POST a tools/call for *tool* to /mcp; return the URL the proxy forwarded to."""
    pytest.importorskip("fastapi")
    from admina.proxy import main as proxy_main
    from admina.proxy.state import ProxyState

    monkeypatch.setattr(proxy_main.settings, "ADMINA_API_KEY", "")
    monkeypatch.setattr(proxy_main.settings, "ALLOW_UNAUTHENTICATED", True)
    monkeypatch.setattr(proxy_main.settings, "RATE_LIMIT_MAX_REQUESTS", 0)
    monkeypatch.setattr(proxy_main.settings, "UPSTREAM_MCP_URL", "http://default-upstream")

    mock_http = AsyncMock()
    mock_http.post = AsyncMock(
        return_value=httpx.Response(
            status_code=200,
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}).encode(),
            headers={"content-type": "application/json"},
        )
    )
    proxy_main.app.state.proxy = ProxyState(
        firewall=_FakeFirewall(),
        pii_redactor=_FakePII(),
        loop_breaker=_FakeLoopBreaker(),
        router=router,
        http_client=mock_http,
        redis=None,
        clickhouse=None,
        forensic_box=None,
        governance_guards=[],
        alert_channels=[],
        auth_providers=[],
    )

    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    }

    async def go():
        transport = httpx.ASGITransport(app=proxy_main.app, raise_app_exceptions=True)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/mcp", json=body)

    resp = asyncio.run(go())
    assert resp.status_code == 200, resp.text
    mock_http.post.assert_awaited_once()
    return mock_http.post.await_args.args[0]


class TestMcpRoutesByToolName:
    @pytest.fixture
    def router(self, tmp_path):
        router = MultiUpstreamRouter(default_upstream="http://default-upstream")
        router.load_config(
            _write_routing(
                tmp_path,
                {
                    "github": {"upstream_url": "http://github-mcp/mcp", "tools": ["git_push"]},
                    "files": {"upstream_url": "http://files-mcp/mcp", "tools": ["read_file"]},
                },
            )
        )
        return router

    def test_declared_tool_goes_to_its_route(self, monkeypatch, router):
        assert _post_tools_call(monkeypatch, router, "git_push") == "http://github-mcp/mcp"
        assert router.routes["github"].request_count > 0

    def test_other_route_tool_goes_to_its_route(self, monkeypatch, router):
        assert _post_tools_call(monkeypatch, router, "read_file") == "http://files-mcp/mcp"

    def test_undeclared_tool_goes_to_the_default_upstream(self, monkeypatch, router):
        assert _post_tools_call(monkeypatch, router, "unknown") == "http://default-upstream/mcp"
