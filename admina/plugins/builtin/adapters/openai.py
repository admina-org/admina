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

"""Admina — OpenAI model adapter.

Wraps the ``openai`` Python client to provide inference through
OpenAI-compatible APIs (OpenAI, Azure OpenAI, vLLM, LiteLLM, etc.).

Requires: ``pip install openai``  (optional dependency).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from admina.plugins.base import BaseModelAdapter

logger = logging.getLogger("admina.plugins.adapters.openai")


class OpenAIAdapter(BaseModelAdapter):
    """Model adapter for OpenAI-compatible APIs.

    Args:
        api_key: OpenAI API key.  Falls back to ``OPENAI_API_KEY`` env var.
        base_url: Override for Azure / local endpoints.
        default_model: Default model name.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        default_model: str | None = None,
    ) -> None:
        # ADMINA_OPENAI_* takes precedence over OPENAI_* env vars so the
        # operator can use a different OpenAI account for the governance
        # plane vs. the application.
        self._api_key = (
            api_key or os.environ.get("ADMINA_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        )
        self._base_url = (
            base_url
            or os.environ.get("ADMINA_OPENAI_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
        )
        self._default_model = default_model or os.environ.get("ADMINA_OPENAI_MODEL", "gpt-4o")
        self._client: Any = None

    # ── lazy client init ────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazily import and create the OpenAI client."""
        if self._client is None:
            try:
                import openai  # type: ignore[import-untyped]

                kwargs: dict[str, Any] = {}
                if self._api_key:
                    kwargs["api_key"] = self._api_key
                if self._base_url:
                    kwargs["base_url"] = self._base_url
                self._client = openai.OpenAI(**kwargs)
            except ImportError as exc:
                raise ImportError(
                    "The 'openai' package is required for OpenAIAdapter. "
                    "Install it with: pip install openai"
                ) from exc
        return self._client

    # ── BaseModelAdapter interface ──────────────────────────────

    async def send(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> dict:
        """Send a prompt to an OpenAI-compatible API.

        Args:
            prompt: The text prompt.
            context: Optional system message.
            **kwargs: Extra options forwarded to ``chat.completions.create()``.
                Supports ``model`` to override the default.

        Returns:
            ``{"text": str, "metadata": {"tokens": int, "latency_ms": float, "model": str}}``.
        """
        client = self._get_client()
        model = kwargs.pop("model", self._default_model)

        messages: list[dict[str, str]] = []
        if context:
            messages.append({"role": "system", "content": str(context)})
        messages.append({"role": "user", "content": prompt})

        start = time.monotonic()
        response = client.chat.completions.create(model=model, messages=messages, **kwargs)
        latency_ms = (time.monotonic() - start) * 1_000

        choice = response.choices[0] if response.choices else None
        text = choice.message.content if choice else ""
        usage = response.usage
        tokens = (usage.total_tokens if usage else 0) or 0

        return {
            "text": text or "",
            "metadata": {
                "tokens": tokens,
                "latency_ms": round(latency_ms, 2),
                "model": model,
            },
        }

    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` for models matching known OpenAI prefixes."""
        prefixes = ("gpt-", "o1", "o3", "chatgpt-", "text-", "davinci")
        return any(model_name.startswith(p) for p in prefixes)

    @property
    def name(self) -> str:
        """Adapter name."""
        return "openai"
