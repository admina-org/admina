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

"""Admina — AWS Bedrock model adapter.

Wraps the ``boto3`` SDK to provide inference through the Amazon Bedrock
Converse API.  Authentication follows the standard AWS credential chain
(environment variables, ``~/.aws/credentials``, IAM instance role, etc.).

Requires: ``pip install 'admina-framework[bedrock]'``  (optional dependency).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

from admina.plugins.base import BaseModelAdapter

logger = logging.getLogger("admina.plugins.adapters.bedrock")

_DEFAULT_REGION = "us-east-1"
_DEFAULT_MAX_TOKENS = 1024


class BedrockAdapter(BaseModelAdapter):
    """Model adapter for the Amazon Bedrock Converse API.

    Args:
        region: AWS region name.  Falls back to ``ADMINA_BEDROCK_REGION``
            then ``AWS_REGION`` env vars; defaults to ``us-east-1``.
        default_model: Default Bedrock model ID.  Falls back to
            ``ADMINA_BEDROCK_MODEL`` env var.  No hardcoded ID — the caller
            or environment must supply a value.
        max_tokens: Default max tokens for responses.  Falls back to
            ``ADMINA_BEDROCK_MAX_TOKENS`` env var (default 1024).
    """

    name = "bedrock"

    def __init__(
        self,
        region: str | None = None,
        default_model: str | None = None,
        max_tokens: int | None = None,
    ) -> None:
        self._region = (
            region
            or os.environ.get("ADMINA_BEDROCK_REGION")
            or os.environ.get("AWS_REGION")
            or _DEFAULT_REGION
        )
        self._default_model = default_model or os.environ.get("ADMINA_BEDROCK_MODEL")
        self._max_tokens = max_tokens or int(
            os.environ.get("ADMINA_BEDROCK_MAX_TOKENS", str(_DEFAULT_MAX_TOKENS))
        )
        self._client: Any = None

    # ── lazy client init ────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazily import boto3 and create the bedrock-runtime client."""
        if self._client is None:
            try:
                import boto3  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "The 'boto3' package is required for BedrockAdapter. "
                    "Install it with: pip install 'admina-framework[bedrock]'"
                ) from exc
            self._client = boto3.client("bedrock-runtime", region_name=self._region)
        return self._client

    # ── BaseModelAdapter interface ──────────────────────────────

    async def send(
        self,
        prompt: str,
        context: Any = None,
        **kwargs: Any,
    ) -> dict:
        """Send a prompt to the Amazon Bedrock Converse API.

        Args:
            prompt: The text prompt (sent as the user message).
            context: Optional system prompt.
            **kwargs: Extra options; ``model`` overrides the default,
                ``max_tokens`` overrides the per-instance default.

        Returns:
            ``{"text": str, "metadata": {"tokens": int, "latency_ms": float, "model": str}}``.
        """
        client = self._get_client()
        model = kwargs.pop("model", None) or self._default_model
        if not model:
            raise ValueError(
                "BedrockAdapter needs a model: pass model=... or set ADMINA_BEDROCK_MODEL"
            )
        max_tokens = kwargs.pop("max_tokens", self._max_tokens)

        converse_req: dict[str, Any] = {
            "modelId": model,
            "messages": [
                {
                    "role": "user",
                    "content": [{"text": prompt}],
                }
            ],
            "inferenceConfig": {"maxTokens": max_tokens},
        }
        if context:
            converse_req["system"] = [{"text": str(context)}]

        start = time.monotonic()
        resp = await asyncio.to_thread(lambda: client.converse(**converse_req))
        latency_ms = (time.monotonic() - start) * 1_000

        text = resp.get("output", {}).get("message", {}).get("content", [{}])[0].get("text", "")
        usage = resp.get("usage", {})
        tokens = usage.get("inputTokens", 0) + usage.get("outputTokens", 0)

        return {
            "text": text or "",
            "metadata": {
                "tokens": tokens,
                "latency_ms": round(latency_ms, 2),
                "model": model,
            },
        }

    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` for model IDs matching known Bedrock namespace prefixes."""
        prefixes = (
            "anthropic.",
            "meta.",
            "mistral.",
            "amazon.",
            "cohere.",
            "ai21.",
            "us.",
            "eu.",
        )
        return any(model_name.startswith(p) for p in prefixes)
