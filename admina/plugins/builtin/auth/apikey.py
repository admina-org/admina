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

"""Admina — API-key authentication provider.

Simple header-based authentication using constant-time comparison.
Supports both ``X-API-Key`` and ``Authorization: Bearer`` headers.

Cookies are never accepted here. The bundled dashboard's browser session is
handled by the proxy itself, which admits it only on the read-only dashboard
API (see ``admina.proxy.dashboard_session``).
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Any

from admina.plugins.base import BaseAuthProvider

logger = logging.getLogger("admina.plugins.auth.apikey")


class APIKeyAuthProvider(BaseAuthProvider):
    """Auth provider that validates requests against a static API key.

    Args:
        api_key: The expected API key.  If empty, all requests are
            authenticated (local-dev mode).
        exempt_paths: URL paths that bypass authentication.
    """

    name = "apikey"

    def __init__(
        self,
        api_key: str | None = None,
        exempt_paths: list[str] | None = None,
    ) -> None:
        # When the registry instantiates the plugin with no arguments
        # (cls()), fall back to the ADMINA_API_KEY environment variable
        # so the static .env key is honoured. An explicit api_key=""
        # is preserved as opt-in local-dev "allow everything" mode.
        if api_key is None:
            api_key = os.environ.get("ADMINA_API_KEY", "")
        self._api_key = api_key
        self._exempt_paths = exempt_paths or [
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc",
        ]

    # ── BaseAuthProvider interface ──────────────────────────────

    def is_configured(self) -> bool:
        """True if this provider has a key and can actually authenticate."""
        return bool(self._api_key)

    async def authenticate(self, request: Any) -> dict:
        """Authenticate a request by API key.

        Args:
            request: A dict with optional ``headers`` and ``path`` keys,
                or a Starlette/FastAPI Request object.

        Returns:
            ``{"user_id": str, "roles": list, "metadata": dict}``.

        Raises:
            PermissionError: If the key is missing or invalid.
        """
        # No key configured → this provider cannot authenticate anyone.
        # Returning an admin user here would be fail-open; instead reject so
        # the middleware's explicit ALLOW_UNAUTHENTICATED gate decides.
        if not self._api_key:
            raise PermissionError("API-key auth provider has no key configured")

        # Check exempt paths
        path = self._get_path(request)
        if path in self._exempt_paths:
            return {"user_id": "anonymous", "roles": ["public"], "metadata": {}}

        # Accept only the raw API key from X-API-Key or Authorization: Bearer.
        provided = self._extract_key(request)
        # Compare bytes: compare_digest raises TypeError on non-ASCII str.
        if provided and secrets.compare_digest(
            provided.encode("utf-8"), self._api_key.encode("utf-8")
        ):
            return {"user_id": "api_key_user", "roles": ["authenticated"], "metadata": {}}
        raise PermissionError("Invalid or missing API key")

    async def authorize(
        self,
        user: dict,
        action: str,
        resource: str = "",
    ) -> bool:
        """API-key auth grants full access to authenticated users."""
        return bool(user.get("roles"))

    @property
    def provider_name(self) -> str:
        """Provider name."""
        return "apikey"

    # ── Internal helpers ────────────────────────────────────────

    @staticmethod
    def _get_path(request: Any) -> str:
        """Extract the URL path from various request representations."""
        if isinstance(request, dict):
            return request.get("path", "")
        # Starlette Request
        return getattr(getattr(request, "url", None), "path", "")

    @staticmethod
    def _extract_key(request: Any) -> str:
        """Extract the raw API key from request headers (X-API-Key or Bearer)."""
        if isinstance(request, dict):
            headers = request.get("headers", {})
        else:
            headers = dict(getattr(request, "headers", {}))

        key = headers.get("x-api-key", "") or headers.get("X-API-Key", "")
        if not key:
            auth = headers.get("authorization", "") or headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                key = auth.removeprefix("Bearer ").strip()
        return key
