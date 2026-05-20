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

"""Admina — AI infrastructure domain.

Provides LLM engine, RAG pipeline, and Web UI integration modules.
"""

from __future__ import annotations

from admina.domains.ai_infra.llm_engine import (
    GPUInfo,
    GPUVendor,
    LLMBackend,
    LLMEngine,
    ModelStatus,
    OllamaConfig,
    VLLMConfig,
    detect_gpu,
)
from admina.domains.ai_infra.rag import (
    ChromaDBConfig,
    Chunk,
    ChunkingStrategy,
    Document,
    DocumentFormat,
    EmbeddingBackend,
    IngestResult,
    RAGPipeline,
    RetrievalResult,
)
from admina.domains.ai_infra.webui import (
    AuthConfig,
    AuthMode,
    LDAPConfig,
    OIDCConfig,
    OpenWebUIConfig,
    WebUIEngine,
)

__all__ = [
    # LLM engine
    "GPUInfo",
    "GPUVendor",
    "LLMBackend",
    "LLMEngine",
    "ModelStatus",
    "OllamaConfig",
    "VLLMConfig",
    "detect_gpu",
    # RAG pipeline
    "Chunk",
    "ChromaDBConfig",
    "ChunkingStrategy",
    "Document",
    "DocumentFormat",
    "EmbeddingBackend",
    "IngestResult",
    "RAGPipeline",
    "RetrievalResult",
    # Web UI
    "AuthConfig",
    "AuthMode",
    "LDAPConfig",
    "OIDCConfig",
    "OpenWebUIConfig",
    "WebUIEngine",
]
