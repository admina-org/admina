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

"""Admina — Google Gemini model adapter.

Wraps the ``google-genai`` Python client (sync) to provide inference through
the Google Gemini GenerateContent API.

Requires: ``pip install 'admina-framework[gemini]'``  (optional dependency).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from admina.plugins.base import BaseModelAdapter

logger = logging.getLogger("admina.plugins.adapters.gemini")


class GeminiAdapter(BaseModelAdapter):
    """Model adapter for the Google Gemini GenerateContent API.

    Args:
        api_key: Google API key.  Falls back to ``ADMINA_GEMINI_API_KEY``,
            ``GOOGLE_API_KEY``, then ``GEMINI_API_KEY`` env vars.
        default_model: Default model identifier.  Falls back to
            ``ADMINA_GEMINI_MODEL`` env var.  No hardcoded ID — the caller
            or environment must supply a value.
    """

    name = "gemini"

    def __init__(
        self,
        api_key: str | None = None,
        default_model: str | None = None,
    ) -> None:
        self._api_key = (
            api_key
            or os.environ.get("ADMINA_GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
        )
        self._default_model = default_model or os.environ.get("ADMINA_GEMINI_MODEL")
        self._client: Any = None

    # ── lazy client init ────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazily import and create the Google Gemini client."""
        if self._client is None:
            try:
                from google import genai  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "The 'google-genai' package is required for GeminiAdapter. "
                    "Install it with: pip install 'admina-framework[gemini]'"
                ) from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = genai.Client(**kwargs)
        return self._client

    # ── BaseModelAdapter interface ──────────────────────────────

    async def send(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> dict:
        """Send a prompt to the Google Gemini GenerateContent API.

        Args:
            prompt: The text prompt.
            context: Optional system instruction string.
            **kwargs: Extra options forwarded to ``models.generate_content()``.
                Supports ``model`` to override the default.

        Returns:
            ``{"text": str, "metadata": {"tokens": int, "latency_ms": float, "model": str}}``.
        """
        from google.genai import types  # type: ignore[import-untyped]

        client = self._get_client()
        model = kwargs.pop("model", None) or self._default_model
        if not model:
            raise ValueError(
                "GeminiAdapter needs a model: pass model=... or set ADMINA_GEMINI_MODEL"
            )

        config = types.GenerateContentConfig(system_instruction=str(context)) if context else None

        start = time.monotonic()
        resp = await asyncio.to_thread(
            lambda: client.models.generate_content(
                model=model,
                contents=prompt,
                config=config,
                **kwargs,
            )
        )
        latency_ms = (time.monotonic() - start) * 1_000

        text = getattr(resp, "text", "") or ""
        usage = getattr(resp, "usage_metadata", None)
        tokens = (getattr(usage, "total_token_count", None) or 0) if usage else 0

        return {
            "text": text,
            "metadata": {
                "tokens": tokens,
                "latency_ms": round(latency_ms, 2),
                "model": model,
            },
        }

    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` for model names with the ``gemini-`` prefix."""
        return model_name.startswith("gemini-")
