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

"""The routes an ASGI app serves, with their full paths.

FastAPI before 0.160 copies the routes of an included router into
``app.routes``; later versions keep the included router as one entry
(``original_router``, ``include_context.prefix``). Both are expanded here.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any


def served_routes(routes: Iterable[Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Yield ``(path, route)`` for every route, included routers expanded."""
    for route in routes:
        router = getattr(route, "original_router", None)
        if router is not None:
            yield from served_routes(router.routes, prefix + route.include_context.prefix)
        else:
            yield prefix + getattr(route, "path", ""), route


def route_paths(app: Any) -> set[str]:
    """The full paths of the routes of ``app``."""
    return {path for path, _ in served_routes(app.routes)}
