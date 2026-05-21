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

"""Admina — ChromaDB data connector.

Wraps the ``chromadb`` Python client for vector-store operations.

Requires: ``pip install chromadb``  (optional dependency).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from admina.plugins.base import BaseDataConnector

logger = logging.getLogger("admina.plugins.connectors.chromadb")


class ChromaDBConnector(BaseDataConnector):
    """Data connector for ChromaDB vector store.

    Args:
        host: ChromaDB server host.
        port: ChromaDB server port.
        collection_name: Default collection to operate on.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        collection_name: str | None = None,
    ) -> None:
        self._host = host or os.environ.get("ADMINA_CHROMA_HOST", "localhost")
        self._port = port if port is not None else int(os.environ.get("ADMINA_CHROMA_PORT", "8000"))
        self._collection_name = collection_name or os.environ.get(
            "ADMINA_CHROMA_COLLECTION", "admina_default"
        )
        self._client: Any = None
        self._collection: Any = None

    def _get_collection(self) -> Any:
        """Lazily initialise the ChromaDB client and collection."""
        if self._collection is None:
            try:
                import chromadb  # type: ignore[import-untyped]

                self._client = chromadb.HttpClient(host=self._host, port=self._port)
                self._collection = self._client.get_or_create_collection(name=self._collection_name)
            except ImportError as exc:
                raise ImportError(
                    "The 'chromadb' package is required for ChromaDBConnector. "
                    "Install it with: pip install chromadb"
                ) from exc
        return self._collection

    # ── BaseDataConnector interface ─────────────────────────────

    async def ingest(self, source: Any, **kwargs: Any) -> dict:
        """Ingest documents into ChromaDB.

        Args:
            source: A list of dicts, each with ``"id"``, ``"text"``, and
                optional ``"metadata"``.
            **kwargs: Extra options (``collection_name``, etc.).

        Returns:
            ``{"doc_count": int, "chunk_count": int, "collection": str}``.
        """
        collection = self._get_collection()

        if isinstance(source, list):
            docs = source
        else:
            docs = [{"id": "doc_0", "text": str(source)}]

        ids = [d.get("id", f"doc_{i}") for i, d in enumerate(docs)]
        documents = [d.get("text", str(d)) for d in docs]
        metadatas = [d.get("metadata", {}) for d in docs]

        collection.add(ids=ids, documents=documents, metadatas=metadatas)

        return {
            "doc_count": len(docs),
            "chunk_count": len(docs),
            "collection": self._collection_name,
        }

    async def query(self, query: str, **kwargs: Any) -> list[dict]:
        """Query ChromaDB for similar documents.

        Args:
            query: Search query string.
            **kwargs: Supports ``top_k`` (default 5).

        Returns:
            Ranked list of ``{"text": str, "metadata": dict, "score": float}``.
        """
        collection = self._get_collection()
        top_k = kwargs.get("top_k", 5)

        results = collection.query(query_texts=[query], n_results=top_k)

        output: list[dict] = []
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for text, meta, dist in zip(documents, metadatas, distances):
            output.append(
                {
                    "text": text,
                    "metadata": meta or {},
                    "score": round(1.0 / (1.0 + dist), 4),
                }
            )

        return output

    @property
    def name(self) -> str:
        """Connector name."""
        return "chromadb"
