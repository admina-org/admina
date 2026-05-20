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

"""Admina — RAG pipeline module.

Document ingest (PDF, DOCX, HTML, CSV, XML), chunking (recursive character
and semantic), embedding (via Ollama or sentence-transformers), vector store
(ChromaDB default), and retrieval with ranking and source citation.

Heavy operations (container start) are orchestrated by the CLI / Docker
Compose template.  This module provides the pure-Python pipeline logic,
structured configuration, and Compose fragment generation for the ChromaDB
container.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("admina.ai_infra.rag")


# ── Document types ───────────────────────────────────────────


class DocumentFormat(str, Enum):
    """Supported document formats for ingest."""

    PDF = "pdf"
    DOCX = "docx"
    HTML = "html"
    CSV = "csv"
    XML = "xml"
    TXT = "txt"


@dataclass
class Document:
    """A raw document before chunking."""

    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    format: DocumentFormat = DocumentFormat.TXT
    doc_id: str = ""

    def __post_init__(self) -> None:
        if not self.doc_id:
            self.doc_id = hashlib.sha256((self.source + self.content[:256]).encode()).hexdigest()[
                :16
            ]


@dataclass
class Chunk:
    """A chunk of text produced by a chunking strategy."""

    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    chunk_index: int = 0
    doc_id: str = ""
    chunk_id: str = ""

    def __post_init__(self) -> None:
        if not self.chunk_id:
            self.chunk_id = hashlib.sha256(
                f"{self.doc_id}:{self.chunk_index}:{self.text[:64]}".encode()
            ).hexdigest()[:16]


@dataclass
class RetrievalResult:
    """A single retrieval result with ranking and citation."""

    text: str
    score: float
    source: str = ""
    doc_id: str = ""
    chunk_index: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Document parsing ─────────────────────────────────────────


_FORMAT_BY_SUFFIX: dict[str, DocumentFormat] = {
    ".pdf": DocumentFormat.PDF,
    ".docx": DocumentFormat.DOCX,
    ".html": DocumentFormat.HTML,
    ".htm": DocumentFormat.HTML,
    ".csv": DocumentFormat.CSV,
    ".xml": DocumentFormat.XML,
    ".txt": DocumentFormat.TXT,
}


def detect_format(path: str | Path) -> DocumentFormat:
    """Detect document format from file extension.

    Args:
        path: File path or name.

    Returns:
        The detected :class:`DocumentFormat`, defaulting to TXT.
    """
    suffix = Path(path).suffix.lower()
    return _FORMAT_BY_SUFFIX.get(suffix, DocumentFormat.TXT)


def parse_plain_text(content: str) -> str:
    """Identity parser for plain text / fallback."""
    return content


def parse_html(content: str) -> str:
    """Strip HTML tags and return plain text."""
    text = re.sub(r"<script[^>]*>.*?</script>", "", content, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_csv(content: str) -> str:
    """Convert CSV content to a newline-delimited text representation."""
    lines = content.strip().splitlines()
    return "\n".join(lines)


def parse_xml(content: str) -> str:
    """Strip XML tags and return text content."""
    text = re.sub(r"<[^>]+>", " ", content)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_document(content: str, fmt: DocumentFormat) -> str:
    """Parse raw content into plain text using the appropriate parser.

    Args:
        content: Raw file content as string.
        fmt: The document format.

    Returns:
        Extracted plain text.

    Note:
        PDF and DOCX require optional dependencies (``PyPDF2`` /
        ``python-docx``).  When unavailable the raw content is returned
        as-is with a warning.
    """
    if fmt == DocumentFormat.HTML:
        return parse_html(content)
    if fmt == DocumentFormat.CSV:
        return parse_csv(content)
    if fmt == DocumentFormat.XML:
        return parse_xml(content)
    if fmt == DocumentFormat.PDF:
        logger.warning("PDF binary parsing requires PyPDF2; returning raw text")
        return content
    if fmt == DocumentFormat.DOCX:
        logger.warning("DOCX binary parsing requires python-docx; returning raw text")
        return content
    return parse_plain_text(content)


# ── Chunking strategies ──────────────────────────────────────


class ChunkingStrategy(str, Enum):
    """Available chunking strategies."""

    RECURSIVE_CHARACTER = "recursive_character"
    SEMANTIC = "semantic"


def chunk_recursive_character(
    text: str,
    *,
    chunk_size: int = 512,
    chunk_overlap: int = 50,
    separators: list[str] | None = None,
) -> list[str]:
    """Split text using recursive character splitting.

    Tries each separator in order.  When a segment exceeds *chunk_size*
    the next separator is tried.  Falls back to character-level split.

    Args:
        text: Input text.
        chunk_size: Maximum characters per chunk.
        chunk_overlap: Overlap between consecutive chunks.
        separators: Separator hierarchy (default: paragraph, sentence,
            word, character).

    Returns:
        List of text chunks.
    """
    if separators is None:
        separators = ["\n\n", "\n", ". ", " ", ""]

    if not text or chunk_size <= 0:
        return []

    return _recursive_split(text, separators, chunk_size, chunk_overlap)


def _recursive_split(
    text: str,
    separators: list[str],
    chunk_size: int,
    chunk_overlap: int,
) -> list[str]:
    """Recursive helper for character splitting."""
    if len(text) <= chunk_size:
        return [text] if text.strip() else []

    sep = separators[0] if separators else ""
    remaining_seps = separators[1:] if len(separators) > 1 else []

    if sep == "":
        return _fixed_size_split(text, chunk_size, chunk_overlap)

    parts = text.split(sep)
    chunks: list[str] = []
    current = ""

    for part in parts:
        candidate = (current + sep + part) if current else part
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current:
                chunks.append(current.strip())
            if len(part) > chunk_size and remaining_seps:
                chunks.extend(_recursive_split(part, remaining_seps, chunk_size, chunk_overlap))
                current = ""
            else:
                current = part

    if current and current.strip():
        chunks.append(current.strip())

    return _apply_overlap(chunks, chunk_overlap) if chunk_overlap > 0 else chunks


def _fixed_size_split(text: str, size: int, overlap: int) -> list[str]:
    """Character-level fixed-size split with overlap."""
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start += size - overlap if overlap < size else size
    return chunks


def _apply_overlap(chunks: list[str], overlap: int) -> list[str]:
    """Add overlap context from previous chunk to each subsequent chunk."""
    if len(chunks) <= 1 or overlap <= 0:
        return chunks
    result = [chunks[0]]
    for i in range(1, len(chunks)):
        prefix = chunks[i - 1][-overlap:]
        result.append(prefix + chunks[i])
    return result


def chunk_semantic(
    text: str,
    *,
    chunk_size: int = 512,
    min_chunk_size: int = 100,
) -> list[str]:
    """Split text at sentence boundaries respecting chunk size limits.

    A lightweight semantic chunker that splits on sentence endings and
    keeps paragraphs together when they fit within *chunk_size*.

    Args:
        text: Input text.
        chunk_size: Target maximum characters per chunk.
        min_chunk_size: Minimum characters to form a chunk.

    Returns:
        List of text chunks.
    """
    if not text or chunk_size <= 0:
        return []

    sentences = re.split(r"(?<=[.!?])\s+", text)
    chunks: list[str] = []
    current = ""

    for sentence in sentences:
        candidate = (current + " " + sentence).strip() if current else sentence
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            if current and len(current) >= min_chunk_size:
                chunks.append(current)
            current = sentence

    if current and current.strip():
        chunks.append(current.strip())

    return chunks


# ── Embedding interface ──────────────────────────────────────


class EmbeddingBackend(str, Enum):
    """Supported embedding backends."""

    OLLAMA = "ollama"
    SENTENCE_TRANSFORMERS = "sentence-transformers"


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Protocol for embedding providers."""

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for a batch of texts."""
        ...

    @property
    def dimension(self) -> int:
        """Embedding vector dimension."""
        ...


@dataclass
class OllamaEmbedder:
    """Embedding provider using the Ollama API.

    Args:
        base_url: Ollama server URL.
        model: Embedding model name.
    """

    base_url: str = "http://localhost:11434"
    model: str = "nomic-embed-text"
    _dimension: int = 768

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings via Ollama ``/api/embed``.

        Args:
            texts: Texts to embed.

        Returns:
            List of embedding vectors.

        Raises:
            RuntimeError: When the Ollama API is unreachable or returns
                an error.
        """
        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "The 'httpx' package is required for OllamaEmbedder. "
                "Install it with: pip install httpx"
            ) from exc

        embeddings: list[list[float]] = []
        async with httpx.AsyncClient(timeout=60.0) as client:
            for text in texts:
                resp = await client.post(
                    f"{self.base_url}/api/embed",
                    json={"model": self.model, "input": text},
                )
                resp.raise_for_status()
                data = resp.json()
                embedding = data.get("embeddings", [[]])[0]
                embeddings.append(embedding)
                if embedding:
                    self._dimension = len(embedding)
        return embeddings

    @property
    def dimension(self) -> int:
        """Embedding vector dimension."""
        return self._dimension


@dataclass
class SentenceTransformerEmbedder:
    """Embedding provider using sentence-transformers.

    Args:
        model_name: HuggingFace model name.
    """

    model_name: str = "all-MiniLM-L6-v2"
    _model: Any = field(default=None, repr=False)
    _dimension: int = 384

    def _get_model(self) -> Any:
        """Lazily load the sentence-transformers model."""
        if self._model is None:
            try:
                from sentence_transformers import (
                    SentenceTransformer,  # type: ignore[import-untyped]
                )
            except ImportError as exc:
                raise ImportError(
                    "The 'sentence-transformers' package is required. "
                    "Install it with: pip install sentence-transformers"
                ) from exc
            self._model = SentenceTransformer(self.model_name)
            self._dimension = self._model.get_sentence_embedding_dimension()
        return self._model

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings via sentence-transformers.

        Args:
            texts: Texts to embed.

        Returns:
            List of embedding vectors.
        """
        model = self._get_model()
        loop = asyncio.get_event_loop()
        vectors = await loop.run_in_executor(None, model.encode, texts)
        return [v.tolist() for v in vectors]

    @property
    def dimension(self) -> int:
        """Embedding vector dimension."""
        return self._dimension


# ── Vector store interface ───────────────────────────────────


@dataclass
class ChromaDBConfig:
    """Container configuration for ChromaDB."""

    image: str = "chromadb/chroma:0.5.23"
    container_name: str = "admina-chromadb"
    port: int = 8000
    persist_directory: str = "/chroma/chroma"

    def to_compose_dict(self) -> dict[str, Any]:
        """Return a docker-compose service fragment."""
        return {
            "image": self.image,
            "container_name": self.container_name,
            "ports": [f"{self.port}:8000"],
            "volumes": ["chromadb-data:/chroma/chroma"],
            "environment": [
                "IS_PERSISTENT=TRUE",
                f"PERSIST_DIRECTORY={self.persist_directory}",
                "ANONYMIZED_TELEMETRY=FALSE",
            ],
            "healthcheck": {
                "test": ["CMD", "curl", "-f", "http://localhost:8000/api/v1/heartbeat"],
                "interval": "15s",
                "timeout": "5s",
                "retries": 5,
            },
            "networks": ["admina"],
            "restart": "unless-stopped",
        }


# ── Ingest result ────────────────────────────────────────────


@dataclass
class IngestResult:
    """Result of a document ingest operation."""

    doc_count: int = 0
    chunk_count: int = 0
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── RAG Pipeline ─────────────────────────────────────────────


@dataclass
class RAGPipeline:
    """Orchestrates the full RAG pipeline.

    Handles document ingest (parse → chunk → embed → store) and retrieval
    (query → embed → search → rank → cite).
    """

    chunk_size: int = 512
    chunk_overlap: int = 50
    chunking_strategy: ChunkingStrategy = ChunkingStrategy.RECURSIVE_CHARACTER
    embedding_backend: EmbeddingBackend = EmbeddingBackend.OLLAMA
    embedding_model: str = "nomic-embed-text"
    chromadb_host: str = "localhost"
    chromadb_port: int = 8000
    collection_name: str = "admina_default"

    # ── Factory ──────────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        *,
        backend: str = "chromadb",
        chunk_size: int = 512,
        chunk_overlap: int = 50,
        chunking_strategy: str = "recursive_character",
        embedding_backend: str = "ollama",
        embedding_model: str = "nomic-embed-text",
        chromadb_host: str = "localhost",
        chromadb_port: int = 8000,
        collection_name: str = "admina_default",
    ) -> RAGPipeline:
        """Create a pipeline from admina.yaml values.

        Args:
            backend: Vector store backend (currently only ``"chromadb"``).
            chunk_size: Maximum characters per chunk.
            chunk_overlap: Overlap between consecutive chunks.
            chunking_strategy: ``"recursive_character"`` or ``"semantic"``.
            embedding_backend: ``"ollama"`` or ``"sentence-transformers"``.
            embedding_model: Model name for embeddings.
            chromadb_host: ChromaDB server host.
            chromadb_port: ChromaDB server port.
            collection_name: Default collection name.
        """
        return cls(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            chunking_strategy=ChunkingStrategy(chunking_strategy),
            embedding_backend=EmbeddingBackend(embedding_backend),
            embedding_model=embedding_model,
            chromadb_host=chromadb_host,
            chromadb_port=chromadb_port,
            collection_name=collection_name,
        )

    # ── Document parsing ─────────────────────────────────────

    def parse(self, content: str, fmt: DocumentFormat) -> str:
        """Parse raw content into plain text.

        Args:
            content: Raw file content.
            fmt: Document format.

        Returns:
            Extracted plain text.
        """
        return parse_document(content, fmt)

    # ── Chunking ─────────────────────────────────────────────

    def chunk(self, text: str) -> list[Chunk]:
        """Split text into chunks using the configured strategy.

        Args:
            text: Plain text to chunk.

        Returns:
            List of :class:`Chunk` objects.
        """
        if self.chunking_strategy == ChunkingStrategy.SEMANTIC:
            raw_chunks = chunk_semantic(
                text,
                chunk_size=self.chunk_size,
            )
        else:
            raw_chunks = chunk_recursive_character(
                text,
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
            )

        return [Chunk(text=c, chunk_index=i) for i, c in enumerate(raw_chunks)]

    # ── Embedding ────────────────────────────────────────────

    def _get_embedder(self) -> OllamaEmbedder | SentenceTransformerEmbedder:
        """Return the configured embedding provider."""
        if self.embedding_backend == EmbeddingBackend.SENTENCE_TRANSFORMERS:
            return SentenceTransformerEmbedder(model_name=self.embedding_model)
        return OllamaEmbedder(model=self.embedding_model)

    # ── Full ingest pipeline ─────────────────────────────────

    async def ingest_documents(
        self,
        documents: list[Document],
    ) -> IngestResult:
        """Run the full ingest pipeline: parse → chunk → embed → store.

        Args:
            documents: Documents to ingest.

        Returns:
            An :class:`IngestResult` with counts and any errors.

        Note:
            Requires a running ChromaDB instance and embedding backend.
            In unit tests, mock the ``_store_chunks`` method.
        """
        result = IngestResult()
        all_chunks: list[Chunk] = []

        for doc in documents:
            try:
                text = self.parse(doc.content, doc.format)
                chunks = self.chunk(text)
                for chunk in chunks:
                    chunk.doc_id = doc.doc_id
                    chunk.metadata.update(doc.metadata)
                    chunk.metadata["source"] = doc.source
                all_chunks.extend(chunks)
                result.doc_count += 1
                result.sources.append(doc.source)
            except (OSError, ValueError, RuntimeError) as exc:
                result.errors.append(f"{doc.source}: {exc}")
                logger.error("Ingest error for %s: %s", doc.source, exc)

        result.chunk_count = len(all_chunks)

        if all_chunks:
            try:
                await self._store_chunks(all_chunks)
            except (OSError, ValueError, RuntimeError) as exc:
                result.errors.append(f"store: {exc}")
                logger.error("Failed to store chunks: %s", exc)

        return result

    def ingest_documents_sync(self, documents: list[Document]) -> IngestResult:
        """Synchronous convenience wrapper for :meth:`ingest_documents`."""
        return asyncio.get_event_loop().run_until_complete(self.ingest_documents(documents))

    async def _store_chunks(self, chunks: list[Chunk]) -> None:
        """Store chunks in ChromaDB via the plugin connector.

        Args:
            chunks: Processed chunks to store.
        """
        try:
            import chromadb  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "The 'chromadb' package is required for vector storage. "
                "Install it with: pip install chromadb"
            ) from exc

        client = chromadb.HttpClient(
            host=self.chromadb_host,
            port=self.chromadb_port,
        )
        collection = client.get_or_create_collection(name=self.collection_name)

        embedder = self._get_embedder()
        texts = [c.text for c in chunks]
        embeddings = await embedder.embed(texts)

        collection.add(
            ids=[c.chunk_id for c in chunks],
            documents=texts,
            embeddings=embeddings,
            metadatas=[c.metadata for c in chunks],
        )

    # ── Retrieval ────────────────────────────────────────────

    async def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float = 0.0,
    ) -> list[RetrievalResult]:
        """Query the vector store and return ranked results with citations.

        Args:
            query: Search query string.
            top_k: Maximum number of results.
            min_score: Minimum similarity score threshold.

        Returns:
            Ranked list of :class:`RetrievalResult` objects.
        """
        try:
            import chromadb  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "The 'chromadb' package is required for retrieval. "
                "Install it with: pip install chromadb"
            ) from exc

        client = chromadb.HttpClient(
            host=self.chromadb_host,
            port=self.chromadb_port,
        )
        collection = client.get_or_create_collection(name=self.collection_name)

        embedder = self._get_embedder()
        query_embedding = (await embedder.embed([query]))[0]

        raw = collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
        )

        return self._rank_results(raw, min_score=min_score)

    def retrieve_sync(
        self,
        query: str,
        *,
        top_k: int = 5,
        min_score: float = 0.0,
    ) -> list[RetrievalResult]:
        """Synchronous convenience wrapper for :meth:`retrieve`."""
        return asyncio.get_event_loop().run_until_complete(
            self.retrieve(query, top_k=top_k, min_score=min_score)
        )

    @staticmethod
    def _rank_results(
        raw: dict[str, Any],
        *,
        min_score: float = 0.0,
    ) -> list[RetrievalResult]:
        """Convert ChromaDB query results to ranked RetrievalResults.

        Args:
            raw: Raw ChromaDB query output.
            min_score: Filter results below this score.

        Returns:
            Sorted list of :class:`RetrievalResult`.
        """
        documents = raw.get("documents", [[]])[0]
        metadatas = raw.get("metadatas", [[]])[0]
        distances = raw.get("distances", [[]])[0]

        results: list[RetrievalResult] = []
        for text, meta, dist in zip(documents, metadatas, distances):
            score = round(1.0 / (1.0 + dist), 4)
            if score < min_score:
                continue
            results.append(
                RetrievalResult(
                    text=text,
                    score=score,
                    source=meta.get("source", "") if meta else "",
                    doc_id=meta.get("doc_id", "") if meta else "",
                    chunk_index=meta.get("chunk_index", 0) if meta else 0,
                    metadata=meta or {},
                )
            )

        results.sort(key=lambda r: r.score, reverse=True)
        return results

    # ── Compose generation ───────────────────────────────────

    def compose_service(
        self,
        project_name: str = "admina",
    ) -> dict[str, Any]:
        """Return the docker-compose service dict for ChromaDB.

        Args:
            project_name: Used for container naming.
        """
        cfg = ChromaDBConfig(
            container_name=f"{project_name}-chromadb",
            port=self.chromadb_port,
        )
        return cfg.to_compose_dict()

    # ── Status ───────────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of pipeline config."""
        return {
            "chunk_size": self.chunk_size,
            "chunk_overlap": self.chunk_overlap,
            "chunking_strategy": self.chunking_strategy.value,
            "embedding_backend": self.embedding_backend.value,
            "embedding_model": self.embedding_model,
            "chromadb_host": self.chromadb_host,
            "chromadb_port": self.chromadb_port,
            "collection_name": self.collection_name,
        }
