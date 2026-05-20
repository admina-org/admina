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
Admina — Multi-Upstream MCP Router
Routes MCP calls to correct upstream servers. Enables OpenClaw integration.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("admina.router")


@dataclass
class ServerRoute:
    """A registered upstream MCP server."""

    name: str
    upstream_url: str = ""
    server_type: str = "sse"  # sse | http | stdio
    proxy_mode: str = "transparent"  # transparent | stdio_wrap
    headers: dict = field(default_factory=dict)
    tool_names: list = field(default_factory=list)  # tools this server provides
    healthy: bool = True
    request_count: int = 0
    block_count: int = 0


class MultiUpstreamRouter:
    """
    Manages routing to multiple MCP upstream servers.

    Loading:
      router = MultiUpstreamRouter()
      router.load_config("/app/routing.json")

    Routing:
      route = router.resolve("github")          # by server name
      route = router.resolve_by_tool("git_push") # by tool name (after discovery)
    """

    def __init__(self, default_upstream: str = "http://localhost:9000"):
        self.default_upstream = default_upstream
        self.routes: dict[str, ServerRoute] = {}
        self.tool_to_server: dict[str, str] = {}
        self.governance_config: dict = {}
        self._loaded = False

    def load_config(self, config_path: str | Path) -> None:
        """Load routing configuration from JSON file."""
        path = Path(config_path)
        if not path.exists():
            logger.warning("Routing config not found: %s, using default upstream", path)
            return

        with open(path) as f:
            config = json.load(f)

        self.default_upstream = config.get("default_upstream", self.default_upstream)
        self.governance_config = config.get("governance", {})

        for name, route_def in config.get("routes", {}).items():
            self.routes[name] = ServerRoute(
                name=name,
                upstream_url=route_def.get("upstream_url", ""),
                server_type=route_def.get("type", "sse"),
                proxy_mode=route_def.get("proxy_mode", "transparent"),
                headers=route_def.get("headers", {}),
            )

        self._loaded = True
        logger.info("Loaded %d upstream routes from %s", len(self.routes), path)

    def resolve(self, server_name: str) -> ServerRoute | None:
        """Resolve a server route by name."""
        route = self.routes.get(server_name)
        if route:
            route.request_count += 1
        return route

    def resolve_by_tool(self, tool_name: str) -> ServerRoute | None:
        """Resolve which server provides a given tool."""
        server_name = self.tool_to_server.get(tool_name)
        if server_name:
            return self.resolve(server_name)
        return None

    def register_tool_mapping(self, server_name: str, tool_names: list[str]) -> None:
        """After tool discovery, map tool names to their server."""
        for tool in tool_names:
            self.tool_to_server[tool] = server_name
        route = self.routes.get(server_name)
        if route:
            route.tool_names = tool_names
        logger.info("Registered %d tools for server '%s'", len(tool_names), server_name)

    def get_upstream_url(self, server_name: str | None = None) -> str:
        """Get the upstream URL for a given server, or default."""
        if server_name:
            route = self.resolve(server_name)
            if route and route.upstream_url:
                return route.upstream_url
        return self.default_upstream

    def get_upstream_headers(self, server_name: str | None = None) -> dict:
        """Get any extra headers for the upstream server."""
        if server_name:
            route = self.resolve(server_name)
            if route:
                return route.headers
        return {}

    def record_block(self, server_name: str) -> None:
        """Record that a request to this server was blocked."""
        route = self.routes.get(server_name)
        if route:
            route.block_count += 1

    def get_stats(self) -> dict:
        """Return routing statistics."""
        return {
            "total_routes": len(self.routes),
            "loaded": self._loaded,
            "default_upstream": self.default_upstream,
            "routes": {
                name: {
                    "type": r.server_type,
                    "upstream": r.upstream_url or "(stdio)",
                    "requests": r.request_count,
                    "blocks": r.block_count,
                    "tools": len(r.tool_names),
                    "healthy": r.healthy,
                }
                for name, r in self.routes.items()
            },
            "tool_mappings": len(self.tool_to_server),
        }

    @property
    def is_multi_upstream(self) -> bool:
        """Whether multi-upstream mode is active."""
        return self._loaded and len(self.routes) > 0
