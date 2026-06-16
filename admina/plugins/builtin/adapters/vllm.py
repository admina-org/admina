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

"""Admina — vLLM model adapter.

vLLM serves an OpenAI-compatible API; this adapter reuses ``OpenAIAdapter``
and points it at the local vLLM endpoint.  The model name must always be
supplied by the caller (it is the HuggingFace model id loaded by the server).

Requires: ``pip install openai``  (same dependency as the OpenAI adapter).
"""

from __future__ import annotations

import os

from admina.plugins.builtin.adapters.openai import OpenAIAdapter


class VLLMAdapter(OpenAIAdapter):
    """Model adapter for a local vLLM server (OpenAI-compatible API).

    Args:
        api_key: API key for the vLLM server.  Falls back to
            ``ADMINA_VLLM_API_KEY`` env var; defaults to ``"EMPTY"``
            (vLLM's conventional no-auth placeholder).
        base_url: Base URL of the vLLM server.  Falls back to
            ``ADMINA_VLLM_BASE_URL`` env var; defaults to
            ``"http://localhost:8000/v1"``.
        default_model: Default model name (HuggingFace model id loaded by
            the server).  Falls back to ``ADMINA_VLLM_MODEL`` env var.
    """

    name = "vllm"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        default_model: str | None = None,
    ) -> None:
        super().__init__(
            api_key=api_key or os.environ.get("ADMINA_VLLM_API_KEY", "EMPTY"),
            base_url=base_url or os.environ.get("ADMINA_VLLM_BASE_URL", "http://localhost:8000/v1"),
            default_model=default_model or os.environ.get("ADMINA_VLLM_MODEL"),
        )

    def supports_model(self, model_name: str) -> bool:
        """Return ``True`` for any model name (vLLM serves whatever is loaded)."""
        return True
