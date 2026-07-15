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

"""Admina — Anthropic model adapter.

Wraps the ``anthropic`` Python client (sync) to provide inference through
the Anthropic Messages API.

Requires: ``pip install 'admina-framework[anthropic]'``  (optional dependency).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from admina.plugins.base import BaseModelAdapter
from admina.plugins.builtin.adapters._streaming import aiter_sync

logger = logging.getLogger("admina.plugins.adapters.anthropic")


class AnthropicAdapter(BaseModelAdapter):
    """Model adapter for the Anthropic Messages API.

    Args:
        api_key: Anthropic API key.  Falls back to ``ADMINA_ANTHROPIC_API_KEY``
            then ``ANTHROPIC_API_KEY`` env vars.
        default_model: Default model identifier.  Falls back to
            ``ADMINA_ANTHROPIC_MODEL`` env var.  No hardcoded ID — the caller
            or environment must supply a value.
        max_tokens: Default max tokens for responses.  Falls back to
            ``ADMINA_ANTHROPIC_MAX_TOKENS`` env var (default 1024).
    """

    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        default_model: str | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self._api_key = (
            api_key
            or os.environ.get("ADMINA_ANTHROPIC_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
        )
        self._default_model = default_model or os.environ.get("ADMINA_ANTHROPIC_MODEL")
        self._max_tokens = max_tokens or int(os.environ.get("ADMINA_ANTHROPIC_MAX_TOKENS", "1024"))
        self._client: Any = None

    # ── lazy client init ────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazily import and create the Anthropic client."""
        if self._client is None:
            try:
                import anthropic  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "The 'anthropic' package is required for AnthropicAdapter. "
                    "Install it with: pip install 'admina-framework[anthropic]'"
                ) from exc
            kwargs: dict[str, Any] = {}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            self._client = anthropic.Anthropic(**kwargs)
        return self._client

    # ── BaseModelAdapter interface ──────────────────────────────

    async def send(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> dict:
        """Send a prompt to the Anthropic Messages API.

        Args:
            prompt: The text prompt (sent as the user message).
            context: Optional system prompt (top-level ``system`` parameter).
            **kwargs: Extra options forwarded to ``messages.create()``.
                Supports ``model`` and ``max_tokens`` to override the defaults.

        Returns:
            ``{"text": str, "metadata": {"tokens": int, "latency_ms": float, "model": str}}``.
        """
        client = self._get_client()
        model = kwargs.pop("model", None) or self._default_model
        if not model:
            raise ValueError(
                "AnthropicAdapter needs a model: pass model=... or set ADMINA_ANTHROPIC_MODEL"
            )
        max_tokens = kwargs.pop("max_tokens", self._max_tokens)

        messages = [{"role": "user", "content": prompt}]
        create_kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": messages,
            **kwargs,
        }
        if context:
            create_kwargs["system"] = str(context)

        start = time.monotonic()
        resp = await asyncio.to_thread(lambda: client.messages.create(**create_kwargs))
        latency_ms = (time.monotonic() - start) * 1_000

        text = "".join(getattr(b, "text", "") for b in resp.content)
        usage = resp.usage
        tokens = (getattr(usage, "input_tokens", 0) or 0) + (
            getattr(usage, "output_tokens", 0) or 0
        )

        return {
            "text": text,
            "metadata": {
                "tokens": tokens,
                "latency_ms": round(latency_ms, 2),
                "model": model,
            },
        }

    async def send_stream(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> Any:
        """Stream text deltas from the Anthropic Messages API."""
        client = self._get_client()
        model = kwargs.pop("model", None) or self._default_model
        if not model:
            raise ValueError(
                "AnthropicAdapter needs a model: pass model=... or set ADMINA_ANTHROPIC_MODEL"
            )
        max_tokens = kwargs.pop("max_tokens", self._max_tokens)

        messages = [{"role": "user", "content": prompt}]
        create_kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": messages,
            "stream": True,
            **kwargs,
        }
        if context:
            create_kwargs["system"] = str(context)

        def _make() -> Any:
            return client.messages.create(**create_kwargs)

        async for event in aiter_sync(_make):
            if getattr(event, "type", None) == "content_block_delta":
                text = getattr(getattr(event, "delta", None), "text", None)
                if text:
                    yield text

    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` for model names with the ``claude-`` prefix."""
        return model_name.startswith("claude-")
