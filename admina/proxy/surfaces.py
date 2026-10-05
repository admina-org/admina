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

"""Surfaces of the proxy, switched on and off by ``ADMINA_ENABLED_SURFACES``.

- ``gateway``: ``/v1/*``, the OpenAI-compatible gateway;
- ``mcp``: ``/mcp`` and ``/mcp/*``, the MCP governance proxy;
- ``integration``: ``/api/v1/*`` (validate, audit, forensic verify);
- ``compliance``: ``/api/compliance/*``;
- ``dashboard``: ``/api/dashboard/*`` (live feed and browser sign-in
  included), ``/api/stats``, ``/api/events`` and the dashboard shell
  (``/``, ``/heimdall.png``, ``/vendor/*``).

``/health``, ``/metrics`` and the OpenAPI documentation belong to no surface
and are always served (the documentation follows
``ADMINA_API_DOCS_ENABLED``).
"""

from __future__ import annotations

__all__ = ["SURFACES", "parse_surfaces", "surface_of"]

#: Every surface, in the order the proxy reports them.
SURFACES = ("gateway", "mcp", "integration", "compliance", "dashboard")

# Path prefixes of each surface: the prefix itself and everything below it.
_PREFIXES = (
    ("/v1", "gateway"),
    ("/mcp", "mcp"),
    ("/api/v1", "integration"),
    ("/api/compliance", "compliance"),
    ("/api/dashboard", "dashboard"),
    ("/api/stats", "dashboard"),
    ("/api/events", "dashboard"),
    ("/vendor", "dashboard"),
)
_DASHBOARD_SHELL = frozenset({"/", "/heimdall.png"})


def parse_surfaces(value: str) -> tuple[str, ...]:
    """The surfaces named in the comma-separated *value*, in the order of
    :data:`SURFACES`; an empty value (or one of empty items) means all.

    Names are case-insensitive and surrounding blanks are ignored.

    Raises:
        ValueError: *value* names an unknown surface.
    """
    names = {item.strip().lower() for item in value.split(",") if item.strip()}
    if not names:
        return SURFACES
    unknown = sorted(names.difference(SURFACES))
    if unknown:
        raise ValueError(
            f"unknown surface(s) {', '.join(unknown)}; the surfaces are: {', '.join(SURFACES)}"
        )
    return tuple(surface for surface in SURFACES if surface in names)


def surface_of(path: str) -> str | None:
    """The surface that serves *path*, or ``None`` for a path of no surface."""
    if path in _DASHBOARD_SHELL:
        return "dashboard"
    for prefix, surface in _PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return surface
    return None
