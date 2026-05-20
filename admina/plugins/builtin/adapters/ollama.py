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

"""Admina — Ollama model adapter.

Wraps the ``ollama`` Python client to provide local LLM inference
through the :class:`BaseModelAdapter` interface.

Requires: ``pip install ollama``  (optional dependency).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from admina.plugins.base import BaseModelAdapter

logger = logging.getLogger("admina.plugins.adapters.ollama")


class OllamaAdapter(BaseModelAdapter):
    """Model adapter for a local Ollama instance.

    Args:
        host: Ollama API base URL.  Defaults to ``http://localhost:11434``.
        default_model: Model name used when none is specified in ``send()``.
    """

    def __init__(
        self,
        host: str | None = None,
        default_model: str | None = None,
    ) -> None:
        # Fall back to standard env vars so the plugin works out-of-the-box
        # when the registry instantiates it with no explicit config.
        self._host = host or os.environ.get("ADMINA_OLLAMA_HOST", "http://localhost:11434")
        self._default_model = default_model or os.environ.get("ADMINA_OLLAMA_MODEL", "llama3.1:8b")
        self._client: Any = None

    # ── lazy client init ────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazily import and create the ollama client."""
        if self._client is None:
            try:
                import ollama  # type: ignore[import-untyped]

                self._client = ollama.Client(host=self._host)
            except ImportError as exc:
                raise ImportError(
                    "The 'ollama' package is required for OllamaAdapter. "
                    "Install it with: pip install ollama"
                ) from exc
        return self._client

    # ── BaseModelAdapter interface ──────────────────────────────

    async def send(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> dict:
        """Send a prompt to Ollama and return the response.

        Args:
            prompt: The text prompt.
            context: Optional system message.
            **kwargs: Extra options forwarded to ``ollama.chat()``.
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
        response = client.chat(model=model, messages=messages, **kwargs)
        latency_ms = (time.monotonic() - start) * 1_000

        text = response.get("message", {}).get("content", "")
        tokens = response.get("eval_count", 0) + response.get("prompt_eval_count", 0)

        return {
            "text": text,
            "metadata": {
                "tokens": tokens,
                "latency_ms": round(latency_ms, 2),
                "model": model,
            },
        }

    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` for any model name (Ollama pulls on demand)."""
        return True

    @property
    def name(self) -> str:
        """Adapter name."""
        return "ollama"
