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

"""Admina — Mistral model adapter.

Wraps the ``mistralai`` Python client (sync) to provide inference through
the Mistral Chat Completions API.

Requires: ``pip install 'admina-framework[mistral]'``  (optional dependency).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from admina.plugins.base import BaseModelAdapter

logger = logging.getLogger("admina.plugins.adapters.mistral")


class MistralAdapter(BaseModelAdapter):
    """Model adapter for the Mistral Chat Completions API.

    Args:
        api_key: Mistral API key.  Falls back to ``ADMINA_MISTRAL_API_KEY``
            then ``MISTRAL_API_KEY`` env vars.
        default_model: Default model identifier.  Falls back to
            ``ADMINA_MISTRAL_MODEL`` env var.  No hardcoded ID — the caller
            or environment must supply a value.
    """

    name = "mistral"

    def __init__(
        self,
        api_key: str | None = None,
        default_model: str | None = None,
    ) -> None:
        self._api_key = (
            api_key or os.environ.get("ADMINA_MISTRAL_API_KEY") or os.environ.get("MISTRAL_API_KEY")
        )
        self._default_model = default_model or os.environ.get("ADMINA_MISTRAL_MODEL")
        self._client: Any = None

    # ── lazy client init ────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazily import and create the Mistral client."""
        if self._client is None:
            try:
                try:
                    from mistralai import Mistral  # type: ignore[import-untyped]
                except ImportError:
                    from mistralai.client import Mistral  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "The 'mistralai' package is required for MistralAdapter. "
                    "Install it with: pip install 'admina-framework[mistral]'"
                ) from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = Mistral(**kwargs)
        return self._client

    # ── BaseModelAdapter interface ──────────────────────────────

    async def send(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> dict:
        """Send a prompt to the Mistral Chat Completions API.

        Args:
            prompt: The text prompt (sent as the user message).
            context: Optional system prompt (prepended as a system message).
            **kwargs: Extra options forwarded to ``chat.complete()``.
                Supports ``model`` to override the default.

        Returns:
            ``{"text": str, "metadata": {"tokens": int, "latency_ms": float, "model": str}}``.
        """
        client = self._get_client()
        model = kwargs.pop("model", None) or self._default_model
        if not model:
            raise ValueError(
                "MistralAdapter needs a model: pass model=... or set ADMINA_MISTRAL_MODEL"
            )

        messages: list[dict[str, str]] = []
        if context:
            messages.append({"role": "system", "content": str(context)})
        messages.append({"role": "user", "content": prompt})

        start = time.monotonic()
        resp = await asyncio.to_thread(
            lambda: client.chat.complete(model=model, messages=messages, **kwargs)
        )
        latency_ms = (time.monotonic() - start) * 1_000

        choice = resp.choices[0] if resp.choices else None
        text = choice.message.content if choice else ""
        usage = resp.usage
        tokens = (getattr(usage, "total_tokens", 0) or 0) if usage else 0

        return {
            "text": text or "",
            "metadata": {
                "tokens": tokens,
                "latency_ms": round(latency_ms, 2),
                "model": model,
            },
        }

    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` for model names matching known Mistral prefixes."""
        prefixes = (
            "mistral-",
            "open-mistral",
            "open-mixtral",
            "codestral",
            "ministral",
            "magistral",
            "pixtral",
        )
        return any(model_name.startswith(p) for p in prefixes)
