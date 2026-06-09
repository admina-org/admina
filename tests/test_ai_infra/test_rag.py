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

"""Tests for ``domains.ai_infra.rag``."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from admina.domains.ai_infra.rag import (
    ChromaDBConfig,
    Chunk,
    ChunkingStrategy,
    Document,
    DocumentFormat,
    EmbeddingBackend,
    RAGPipeline,
    RetrievalResult,
    chunk_recursive_character,
    chunk_semantic,
    detect_format,
    parse_csv,
    parse_document,
    parse_html,
    parse_xml,
)

# ── Document / Chunk dataclasses ─────────────────────────────


class TestDocument:
    """Tests for Document dataclass."""

    def test_auto_id(self) -> None:
        """Auto-generates doc_id from source + content."""
        doc = Document(content="hello world", source="test.txt")
        assert doc.doc_id
        assert len(doc.doc_id) == 16

    def test_explicit_id(self) -> None:
        """Respects explicitly set doc_id."""
        doc = Document(content="hello", doc_id="custom123")
        assert doc.doc_id == "custom123"

    def test_deterministic_id(self) -> None:
        """Same source + content produces same id."""
        d1 = Document(content="hello", source="a.txt")
        d2 = Document(content="hello", source="a.txt")
        assert d1.doc_id == d2.doc_id

    def test_default_format(self) -> None:
        doc = Document(content="test")
        assert doc.format == DocumentFormat.TXT


class TestChunk:
    """Tests for Chunk dataclass."""

    def test_auto_chunk_id(self) -> None:
        chunk = Chunk(text="some text", chunk_index=0, doc_id="abc")
        assert chunk.chunk_id
        assert len(chunk.chunk_id) == 16

    def test_explicit_chunk_id(self) -> None:
        chunk = Chunk(text="x", chunk_id="myid")
        assert chunk.chunk_id == "myid"


# ── Format detection ─────────────────────────────────────────


class TestDetectFormat:
    """Tests for file format detection."""

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("report.pdf", DocumentFormat.PDF),
            ("doc.docx", DocumentFormat.DOCX),
            ("page.html", DocumentFormat.HTML),
            ("page.htm", DocumentFormat.HTML),
            ("data.csv", DocumentFormat.CSV),
            ("admina.config.xml", DocumentFormat.XML),
            ("notes.txt", DocumentFormat.TXT),
            ("unknown.xyz", DocumentFormat.TXT),
        ],
    )
    def test_detect(self, path: str, expected: DocumentFormat) -> None:
        assert detect_format(path) == expected


# ── Document parsing ─────────────────────────────────────────


class TestParsing:
    """Tests for document parsers."""

    def test_parse_html_strips_tags(self) -> None:
        html = "<html><body><p>Hello <b>world</b></p></body></html>"
        assert "Hello" in parse_html(html)
        assert "world" in parse_html(html)
        assert "<" not in parse_html(html)

    def test_parse_html_strips_script(self) -> None:
        html = "<p>Text</p><script>alert('x')</script><p>More</p>"
        result = parse_html(html)
        assert "alert" not in result
        assert "Text" in result
        assert "More" in result

    def test_parse_html_strips_style(self) -> None:
        html = "<style>.x{color:red}</style><p>Content</p>"
        result = parse_html(html)
        assert "color" not in result
        assert "Content" in result

    def test_parse_html_strips_malformed_script(self) -> None:
        # Nested/malformed tag that bypassed the old regex tag-stripper
        # (CodeQL py/bad-tag-filter). The HTMLParser-based extractor must
        # not leak the script body into the extracted text.
        html = "<p>Text</p><scr<script>ipt>alert(1)</script><p>More</p>"
        result = parse_html(html)
        assert "alert" not in result
        assert "Text" in result
        assert "More" in result

    def test_parse_csv(self) -> None:
        csv_content = "name,age\nAlice,30\nBob,25"
        result = parse_csv(csv_content)
        assert "Alice,30" in result
        assert "Bob,25" in result

    def test_parse_xml_strips_tags(self) -> None:
        xml = "<root><item>Value1</item><item>Value2</item></root>"
        result = parse_xml(xml)
        assert "Value1" in result
        assert "Value2" in result
        assert "<" not in result

    def test_parse_document_txt(self) -> None:
        assert parse_document("hello", DocumentFormat.TXT) == "hello"

    def test_parse_document_html(self) -> None:
        result = parse_document("<p>Hi</p>", DocumentFormat.HTML)
        assert "Hi" in result
        assert "<" not in result

    def test_parse_document_pdf_fallback(self) -> None:
        """PDF returns raw content with warning when PyPDF2 unavailable."""
        result = parse_document("raw pdf bytes", DocumentFormat.PDF)
        assert result == "raw pdf bytes"

    def test_parse_document_docx_fallback(self) -> None:
        """DOCX returns raw content with warning when python-docx unavailable."""
        result = parse_document("raw docx bytes", DocumentFormat.DOCX)
        assert result == "raw docx bytes"


# ── Chunking ─────────────────────────────────────────────────


class TestRecursiveCharacterChunking:
    """Tests for recursive character chunking."""

    def test_short_text_single_chunk(self) -> None:
        chunks = chunk_recursive_character("Hello world", chunk_size=100)
        assert len(chunks) == 1
        assert chunks[0] == "Hello world"

    def test_empty_text(self) -> None:
        assert chunk_recursive_character("") == []

    def test_zero_chunk_size(self) -> None:
        assert chunk_recursive_character("text", chunk_size=0) == []

    def test_splits_on_paragraphs(self) -> None:
        text = "Paragraph one.\n\nParagraph two.\n\nParagraph three."
        chunks = chunk_recursive_character(text, chunk_size=20, chunk_overlap=0)
        assert len(chunks) >= 2
        assert "Paragraph one." in chunks[0]

    def test_splits_on_sentences(self) -> None:
        text = "First sentence. Second sentence. Third sentence."
        chunks = chunk_recursive_character(text, chunk_size=20, chunk_overlap=0)
        assert len(chunks) >= 2

    def test_overlap(self) -> None:
        text = "AAAA\n\nBBBB\n\nCCCC"
        chunks = chunk_recursive_character(text, chunk_size=5, chunk_overlap=2)
        assert len(chunks) >= 2
        # With overlap, second chunk should have prefix from first
        if len(chunks) > 1:
            assert len(chunks[1]) > 4  # has overlap prefix

    def test_respects_chunk_size(self) -> None:
        text = "word " * 200  # ~1000 chars
        chunks = chunk_recursive_character(text, chunk_size=100, chunk_overlap=0)
        for chunk in chunks:
            # Allow some slack for splitting at word boundaries
            assert len(chunk) <= 150


class TestSemanticChunking:
    """Tests for semantic (sentence-boundary) chunking."""

    def test_short_text_single_chunk(self) -> None:
        chunks = chunk_semantic("Hello world.", chunk_size=100)
        assert len(chunks) == 1

    def test_empty_text(self) -> None:
        assert chunk_semantic("") == []

    def test_splits_on_sentence_boundaries(self) -> None:
        text = (
            "This is the first sentence with enough words to be substantial. "
            "Here comes the second sentence which is also quite long. "
            "A third sentence adds more content to force splitting. "
            "And finally a fourth sentence rounds it all out nicely."
        )
        chunks = chunk_semantic(text, chunk_size=120, min_chunk_size=20)
        assert len(chunks) >= 2
        # Each chunk should end at a sentence boundary
        for chunk in chunks:
            assert chunk.strip()

    def test_respects_min_chunk_size(self) -> None:
        text = "A. B. C. D. E. F."
        chunks = chunk_semantic(text, chunk_size=10, min_chunk_size=5)
        for chunk in chunks:
            assert len(chunk) >= 2  # at least non-empty


# ── ChromaDBConfig ───────────────────────────────────────────


class TestChromaDBConfig:
    """Tests for ChromaDB compose generation."""

    def test_compose_dict_structure(self) -> None:
        cfg = ChromaDBConfig()
        svc = cfg.to_compose_dict()
        assert svc["image"] == "chromadb/chroma:0.5.23"
        assert "8000:8000" in svc["ports"]
        assert svc["healthcheck"]["test"][0] == "CMD"
        assert "chromadb-data:/chroma/chroma" in svc["volumes"]

    def test_custom_container_name(self) -> None:
        cfg = ChromaDBConfig(container_name="myapp-chromadb")
        svc = cfg.to_compose_dict()
        assert svc["container_name"] == "myapp-chromadb"

    def test_environment_vars(self) -> None:
        cfg = ChromaDBConfig()
        svc = cfg.to_compose_dict()
        assert "IS_PERSISTENT=TRUE" in svc["environment"]
        assert "ANONYMIZED_TELEMETRY=FALSE" in svc["environment"]


# ── RAGPipeline ──────────────────────────────────────────────


class TestRAGPipeline:
    """Tests for the RAGPipeline orchestrator."""

    def test_from_config_defaults(self) -> None:
        pipe = RAGPipeline.from_config()
        assert pipe.chunk_size == 512
        assert pipe.chunk_overlap == 50
        assert pipe.chunking_strategy == ChunkingStrategy.RECURSIVE_CHARACTER
        assert pipe.embedding_backend == EmbeddingBackend.OLLAMA

    def test_from_config_semantic(self) -> None:
        pipe = RAGPipeline.from_config(chunking_strategy="semantic")
        assert pipe.chunking_strategy == ChunkingStrategy.SEMANTIC

    def test_from_config_sentence_transformers(self) -> None:
        pipe = RAGPipeline.from_config(embedding_backend="sentence-transformers")
        assert pipe.embedding_backend == EmbeddingBackend.SENTENCE_TRANSFORMERS

    def test_parse_delegates(self) -> None:
        pipe = RAGPipeline()
        result = pipe.parse("<p>Hi</p>", DocumentFormat.HTML)
        assert "Hi" in result
        assert "<" not in result

    def test_chunk_recursive(self) -> None:
        pipe = RAGPipeline(chunk_size=20, chunk_overlap=0)
        chunks = pipe.chunk("Hello world. " * 10)
        assert len(chunks) >= 2
        assert all(isinstance(c, Chunk) for c in chunks)

    def test_chunk_semantic(self) -> None:
        pipe = RAGPipeline(
            chunk_size=30,
            chunking_strategy=ChunkingStrategy.SEMANTIC,
        )
        text = "First sentence. Second sentence. Third sentence."
        chunks = pipe.chunk(text)
        assert len(chunks) >= 1
        assert all(isinstance(c, Chunk) for c in chunks)

    def test_chunk_indices(self) -> None:
        pipe = RAGPipeline(chunk_size=20, chunk_overlap=0)
        chunks = pipe.chunk("A" * 50)
        indices = [c.chunk_index for c in chunks]
        assert indices == list(range(len(chunks)))

    def test_compose_service(self) -> None:
        pipe = RAGPipeline()
        svc = pipe.compose_service(project_name="myapp")
        assert svc["container_name"] == "myapp-chromadb"

    def test_summary(self) -> None:
        pipe = RAGPipeline()
        s = pipe.summary()
        assert s["chunk_size"] == 512
        assert s["embedding_backend"] == "ollama"
        assert s["chunking_strategy"] == "recursive_character"

    def test_get_embedder_ollama(self) -> None:
        pipe = RAGPipeline(embedding_backend=EmbeddingBackend.OLLAMA)
        from admina.domains.ai_infra.rag import OllamaEmbedder

        embedder = pipe._get_embedder()
        assert isinstance(embedder, OllamaEmbedder)

    def test_get_embedder_sentence_transformers(self) -> None:
        pipe = RAGPipeline(
            embedding_backend=EmbeddingBackend.SENTENCE_TRANSFORMERS,
        )
        from admina.domains.ai_infra.rag import SentenceTransformerEmbedder

        embedder = pipe._get_embedder()
        assert isinstance(embedder, SentenceTransformerEmbedder)


# ── Ingest pipeline ──────────────────────────────────────────


class TestIngestPipeline:
    """Tests for the full ingest pipeline (with mocked storage)."""

    def test_ingest_documents(self) -> None:
        """Ingest parses, chunks, and stores documents."""
        pipe = RAGPipeline(chunk_size=50, chunk_overlap=0)
        docs = [
            Document(
                content="Hello world. This is a test document.",
                source="test.txt",
                format=DocumentFormat.TXT,
            ),
        ]

        with patch.object(pipe, "_store_chunks", new_callable=AsyncMock):
            result = asyncio.run(pipe.ingest_documents(docs))

        assert result.doc_count == 1
        assert result.chunk_count >= 1
        assert "test.txt" in result.sources
        assert result.errors == []

    def test_ingest_multiple_documents(self) -> None:
        """Ingest handles multiple documents."""
        pipe = RAGPipeline(chunk_size=50, chunk_overlap=0)
        docs = [
            Document(content="First document.", source="a.txt"),
            Document(content="Second document.", source="b.txt"),
        ]

        with patch.object(pipe, "_store_chunks", new_callable=AsyncMock):
            result = asyncio.run(pipe.ingest_documents(docs))

        assert result.doc_count == 2
        assert result.chunk_count >= 2
        assert "a.txt" in result.sources
        assert "b.txt" in result.sources

    def test_ingest_html_document(self) -> None:
        """Ingest handles HTML parsing."""
        pipe = RAGPipeline(chunk_size=500, chunk_overlap=0)
        docs = [
            Document(
                content="<html><body><p>Hello from HTML</p></body></html>",
                source="page.html",
                format=DocumentFormat.HTML,
            ),
        ]

        with patch.object(pipe, "_store_chunks", new_callable=AsyncMock) as mock_store:
            result = asyncio.run(pipe.ingest_documents(docs))

        assert result.doc_count == 1
        # Verify the chunks passed to store have parsed content
        stored_chunks = mock_store.call_args[0][0]
        assert "Hello from HTML" in stored_chunks[0].text
        assert "<" not in stored_chunks[0].text

    def test_ingest_sets_metadata(self) -> None:
        """Chunks inherit document metadata and source."""
        pipe = RAGPipeline(chunk_size=500, chunk_overlap=0)
        docs = [
            Document(
                content="Test content",
                source="doc.txt",
                metadata={"author": "test"},
            ),
        ]

        with patch.object(pipe, "_store_chunks", new_callable=AsyncMock) as mock_store:
            asyncio.run(pipe.ingest_documents(docs))

        stored_chunks = mock_store.call_args[0][0]
        assert stored_chunks[0].metadata["source"] == "doc.txt"
        assert stored_chunks[0].metadata["author"] == "test"

    def test_ingest_error_handling(self) -> None:
        """Store failure is captured in errors list."""
        pipe = RAGPipeline(chunk_size=500, chunk_overlap=0)
        docs = [Document(content="Test", source="test.txt")]

        with patch.object(
            pipe,
            "_store_chunks",
            new_callable=AsyncMock,
            side_effect=RuntimeError("connection refused"),
        ):
            result = asyncio.run(pipe.ingest_documents(docs))

        assert result.doc_count == 1
        assert len(result.errors) == 1
        assert "connection refused" in result.errors[0]

    def test_ingest_empty_list(self) -> None:
        """Ingest of empty list returns zero counts."""
        pipe = RAGPipeline()
        result = asyncio.run(pipe.ingest_documents([]))
        assert result.doc_count == 0
        assert result.chunk_count == 0


# ── Retrieval / ranking ──────────────────────────────────────


class TestRetrieval:
    """Tests for retrieval result ranking."""

    def test_rank_results_basic(self) -> None:
        """Converts raw ChromaDB output to ranked results."""
        raw = {
            "documents": [["doc1 text", "doc2 text"]],
            "metadatas": [
                [
                    {"source": "a.txt", "doc_id": "abc"},
                    {"source": "b.txt", "doc_id": "def"},
                ]
            ],
            "distances": [[0.5, 1.5]],
        }
        results = RAGPipeline._rank_results(raw)
        assert len(results) == 2
        assert all(isinstance(r, RetrievalResult) for r in results)
        # Lower distance → higher score → ranked first
        assert results[0].score > results[1].score
        assert results[0].source == "a.txt"

    def test_rank_results_min_score_filter(self) -> None:
        """Filters results below min_score."""
        raw = {
            "documents": [["close", "far"]],
            "metadatas": [[{"source": "a"}, {"source": "b"}]],
            "distances": [[0.1, 100.0]],
        }
        results = RAGPipeline._rank_results(raw, min_score=0.5)
        assert len(results) == 1
        assert results[0].text == "close"

    def test_rank_results_empty(self) -> None:
        """Handles empty results gracefully."""
        raw = {"documents": [[]], "metadatas": [[]], "distances": [[]]}
        results = RAGPipeline._rank_results(raw)
        assert results == []

    def test_rank_results_null_metadata(self) -> None:
        """Handles None metadata entries."""
        raw = {
            "documents": [["text"]],
            "metadatas": [[None]],
            "distances": [[0.5]],
        }
        results = RAGPipeline._rank_results(raw)
        assert len(results) == 1
        assert results[0].source == ""

    def test_rank_results_sorted(self) -> None:
        """Results are sorted by score descending."""
        raw = {
            "documents": [["a", "b", "c"]],
            "metadatas": [[{}, {}, {}]],
            "distances": [[2.0, 0.1, 1.0]],
        }
        results = RAGPipeline._rank_results(raw)
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)


# ── Enums ────────────────────────────────────────────────────


class TestEnums:
    """Tests for enum values."""

    def test_document_format_values(self) -> None:
        assert DocumentFormat.PDF.value == "pdf"
        assert DocumentFormat.DOCX.value == "docx"
        assert DocumentFormat.HTML.value == "html"
        assert DocumentFormat.CSV.value == "csv"
        assert DocumentFormat.XML.value == "xml"
        assert DocumentFormat.TXT.value == "txt"

    def test_chunking_strategy_values(self) -> None:
        assert ChunkingStrategy.RECURSIVE_CHARACTER.value == "recursive_character"
        assert ChunkingStrategy.SEMANTIC.value == "semantic"

    def test_embedding_backend_values(self) -> None:
        assert EmbeddingBackend.OLLAMA.value == "ollama"
        assert EmbeddingBackend.SENTENCE_TRANSFORMERS.value == "sentence-transformers"
