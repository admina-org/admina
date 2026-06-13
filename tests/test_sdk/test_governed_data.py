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

"""Tests for sdk.governed_data module."""

from __future__ import annotations

import asyncio
from typing import Any

from admina.core.event_bus import EventBus, EventType, GovernanceEvent
from admina.sdk.governed_data import (
    BaseDataConnector,
    GovernedData,
    GovernedDocument,
    IngestResult,
    _classify_content,
)

# ---------------------------------------------------------------------------
# Mock connector
# ---------------------------------------------------------------------------


class MockConnector(BaseDataConnector):
    """Test connector that stores docs in memory."""

    def __init__(self, query_results: list[dict] | None = None) -> None:
        self.ingested: list[Any] = []
        self._query_results = query_results or []

    async def ingest(self, source: Any, **kwargs: Any) -> dict:
        """Record source and return counts."""
        self.ingested.append(source)
        return {"doc_count": 1, "chunk_count": 3}

    async def query(self, query: str, **kwargs: Any) -> list[dict]:
        """Return preconfigured results."""
        return self._query_results

    @property
    def name(self) -> str:
        return "mock"


# ---------------------------------------------------------------------------
# Tests: dataclasses
# ---------------------------------------------------------------------------


class TestDataclasses:
    """Tests for IngestResult and GovernedDocument."""

    def test_ingest_result_defaults(self) -> None:
        """IngestResult has sensible defaults."""
        r = IngestResult()
        assert r.doc_count == 0
        assert r.chunk_count == 0
        assert r.classification == {}
        assert r.governance == {}

    def test_governed_document_defaults(self) -> None:
        """GovernedDocument has sensible defaults."""
        d = GovernedDocument(text="hello")
        assert d.text == "hello"
        assert d.score == 0.0
        assert d.metadata == {}


# ---------------------------------------------------------------------------
# Tests: classification helper
# ---------------------------------------------------------------------------


class TestClassifyContent:
    """Tests for the _classify_content helper."""

    def test_no_pii_low(self) -> None:
        """No PII yields LOW sensitivity."""
        result = _classify_content("clean text", {"count": 0, "entities": []})
        assert result["sensitivity"] == "LOW"

    def test_some_pii_medium(self) -> None:
        """1-4 non-high-risk PII yields MEDIUM."""
        entities = [{"type": "EMAIL"}]
        result = _classify_content("x", {"count": 1, "entities": entities})
        assert result["sensitivity"] == "MEDIUM"

    def test_high_risk_pii_high(self) -> None:
        """High-risk PII type yields HIGH."""
        entities = [{"type": "CREDIT_CARD"}]
        result = _classify_content("x", {"count": 1, "entities": entities})
        assert result["sensitivity"] == "HIGH"
        assert result["has_high_risk_pii"] is True

    def test_many_pii_high(self) -> None:
        """5+ PII entities yield HIGH regardless of type."""
        entities = [{"type": "EMAIL"}] * 5
        result = _classify_content("x", {"count": 5, "entities": entities})
        assert result["sensitivity"] == "HIGH"


# ---------------------------------------------------------------------------
# Tests: GovernedData ingest
# ---------------------------------------------------------------------------


class TestGovernedDataIngest:
    """Tests for GovernedData.ingest()."""

    def test_basic_ingest(self) -> None:
        """ingest() returns IngestResult with connector counts."""
        connector = MockConnector()
        gd = GovernedData(connector=connector, pii_redaction=True)
        result = asyncio.run(gd.ingest("some clean data"))

        assert isinstance(result, IngestResult)
        assert result.doc_count == 1
        assert result.chunk_count == 3
        assert connector.ingested == ["some clean data"]

    def test_ingest_classifies_data(self) -> None:
        """ingest() performs data classification."""
        connector = MockConnector()
        gd = GovernedData(connector=connector, pii_redaction=True)
        result = asyncio.run(gd.ingest("Email me at test@example.com"))

        assert result.classification["sensitivity"] in {"MEDIUM", "HIGH"}
        assert result.classification["pii_count"] >= 1

    def test_ingest_clean_data_low(self) -> None:
        """ingest() classifies clean data as LOW sensitivity."""
        connector = MockConnector()
        gd = GovernedData(connector=connector, pii_redaction=True)
        result = asyncio.run(gd.ingest("just some regular text"))

        assert result.classification["sensitivity"] == "LOW"

    def test_ingest_residency_ok(self) -> None:
        """ingest() succeeds when target zone is allowed."""
        connector = MockConnector()
        gd = GovernedData(
            connector=connector,
            residency_zone="eu",
            allowed_zones={"eu", "local"},
        )
        result = asyncio.run(gd.ingest("data", target_zone="eu"))

        assert result.governance["residency"]["allowed"] is True

    def test_ingest_residency_violation(self) -> None:
        """ingest() raises PermissionError on residency violation."""
        connector = MockConnector()
        gd = GovernedData(
            connector=connector,
            residency_zone="eu",
            allowed_zones={"eu"},
        )
        try:
            asyncio.run(gd.ingest("data", target_zone="us"))
            assert False, "Should have raised PermissionError"
        except PermissionError as e:
            assert "residency violation" in str(e).lower()

    def test_ingest_no_connector_raises(self) -> None:
        """ingest() raises RuntimeError when no connector is set."""
        gd = GovernedData(connector=None)
        try:
            asyncio.run(gd.ingest("data"))
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "No data connector configured" in str(e)

    def test_ingest_sync(self) -> None:
        """ingest_sync() convenience wrapper works."""
        connector = MockConnector()
        gd = GovernedData(connector=connector, pii_redaction=False)
        result = gd.ingest_sync("data")

        assert isinstance(result, IngestResult)
        assert result.doc_count == 1


# ---------------------------------------------------------------------------
# Tests: GovernedData query
# ---------------------------------------------------------------------------


class TestGovernedDataQuery:
    """Tests for GovernedData.query()."""

    def test_basic_query(self) -> None:
        """query() returns GovernedDocument list."""
        connector = MockConnector(
            query_results=[
                {"text": "result one", "metadata": {"source": "a"}, "score": 0.9},
                {"text": "result two", "metadata": {"source": "b"}, "score": 0.7},
            ]
        )
        gd = GovernedData(connector=connector, pii_redaction=False)
        docs = asyncio.run(gd.query("search term"))

        assert len(docs) == 2
        assert isinstance(docs[0], GovernedDocument)
        assert docs[0].text == "result one"
        assert docs[0].score == 0.9
        assert docs[1].metadata == {"source": "b"}

    def test_query_redacts_pii(self) -> None:
        """query() redacts PII from result texts."""
        connector = MockConnector(
            query_results=[
                {"text": "Contact test@example.com for details", "metadata": {}, "score": 1.0},
            ]
        )
        gd = GovernedData(connector=connector, pii_redaction=True)
        docs = asyncio.run(gd.query("find contacts"))

        assert "test@example.com" not in docs[0].text
        assert docs[0].governance["pii"]["redacted"] is True
        assert docs[0].governance["pii"]["count"] >= 1

    def test_query_clean_no_redaction(self) -> None:
        """query() leaves clean text untouched."""
        connector = MockConnector(
            query_results=[
                {"text": "clean result", "metadata": {}, "score": 0.5},
            ]
        )
        gd = GovernedData(connector=connector, pii_redaction=True)
        docs = asyncio.run(gd.query("search"))

        assert docs[0].text == "clean result"
        assert docs[0].governance["pii"]["redacted"] is False

    def test_query_pii_disabled(self) -> None:
        """query() skips PII redaction when disabled."""
        connector = MockConnector(
            query_results=[
                {"text": "Email: test@example.com", "metadata": {}, "score": 1.0},
            ]
        )
        gd = GovernedData(connector=connector, pii_redaction=False)
        docs = asyncio.run(gd.query("search"))

        assert docs[0].text == "Email: test@example.com"

    def test_query_residency_violation(self) -> None:
        """query() raises PermissionError on residency violation."""
        connector = MockConnector()
        gd = GovernedData(
            connector=connector,
            residency_zone="local",
            allowed_zones={"local"},
        )
        try:
            asyncio.run(gd.query("search", target_zone="us"))
            assert False, "Should have raised PermissionError"
        except PermissionError as e:
            assert "residency violation" in str(e).lower()

    def test_query_no_connector_raises(self) -> None:
        """query() raises RuntimeError when no connector is set."""
        gd = GovernedData(connector=None)
        try:
            asyncio.run(gd.query("search"))
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "No data connector configured" in str(e)

    def test_query_sync(self) -> None:
        """query_sync() convenience wrapper works."""
        connector = MockConnector(
            query_results=[
                {"text": "result", "metadata": {}, "score": 0.5},
            ]
        )
        gd = GovernedData(connector=connector, pii_redaction=False)
        docs = gd.query_sync("search")

        assert len(docs) == 1
        assert docs[0].text == "result"

    def test_query_empty_results(self) -> None:
        """query() handles empty result set."""
        connector = MockConnector(query_results=[])
        gd = GovernedData(connector=connector, pii_redaction=True)
        docs = asyncio.run(gd.query("search"))

        assert docs == []


# ---------------------------------------------------------------------------
# Tests: event emission
# ---------------------------------------------------------------------------


class TestGovernedDataEvents:
    """Tests for event emission."""

    def test_ingest_emits_classify_event(self) -> None:
        """ingest() emits a DATA_CLASSIFY event."""
        import admina.sdk.governed_data as gd_mod

        original_bus = gd_mod.bus
        test_bus = EventBus()
        gd_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.DATA_CLASSIFY, events.append)

            connector = MockConnector()
            gd = GovernedData(connector=connector, pii_redaction=True)
            asyncio.run(gd.ingest("some data"))

            assert len(events) == 1
            assert events[0].domain == "data-sovereignty"
            assert "sensitivity" in events[0].metadata
        finally:
            gd_mod.bus = original_bus

    def test_ingest_emits_access_event(self) -> None:
        """ingest() emits a DATA_ACCESS event."""
        import admina.sdk.governed_data as gd_mod

        original_bus = gd_mod.bus
        test_bus = EventBus()
        gd_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.DATA_ACCESS, events.append)

            connector = MockConnector()
            gd = GovernedData(connector=connector, pii_redaction=True)
            asyncio.run(gd.ingest("data"))

            assert len(events) >= 1
            allow_events = [e for e in events if e.action == "ALLOW"]
            assert len(allow_events) == 1
            assert allow_events[0].metadata["operation"] == "ingest"
        finally:
            gd_mod.bus = original_bus

    def test_residency_violation_emits_block(self) -> None:
        """Residency violation emits a BLOCK event."""
        import admina.sdk.governed_data as gd_mod

        original_bus = gd_mod.bus
        test_bus = EventBus()
        gd_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.DATA_ACCESS, events.append)

            connector = MockConnector()
            gd = GovernedData(
                connector=connector,
                residency_zone="eu",
                allowed_zones={"eu"},
            )
            try:
                asyncio.run(gd.ingest("data", target_zone="us"))
            except PermissionError:
                pass

            assert len(events) == 1
            assert events[0].action == "BLOCK"
            assert events[0].risk_level == "CRITICAL"
        finally:
            gd_mod.bus = original_bus

    def test_query_redact_emits_event(self) -> None:
        """query() emits DATA_REDACT when PII is found."""
        import admina.sdk.governed_data as gd_mod

        original_bus = gd_mod.bus
        test_bus = EventBus()
        gd_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe(EventType.DATA_REDACT, events.append)

            connector = MockConnector(
                query_results=[
                    {"text": "Email: test@example.com", "metadata": {}, "score": 1.0},
                ]
            )
            gd = GovernedData(connector=connector, pii_redaction=True)
            asyncio.run(gd.query("search"))

            assert len(events) >= 1
            assert events[0].action == "REDACT"
        finally:
            gd_mod.bus = original_bus

    def test_audit_disabled_no_events(self) -> None:
        """No events emitted when audit=False."""
        import admina.sdk.governed_data as gd_mod

        original_bus = gd_mod.bus
        test_bus = EventBus()
        gd_mod.bus = test_bus

        try:
            events: list[GovernanceEvent] = []
            test_bus.subscribe_all(events.append)

            connector = MockConnector()
            gd = GovernedData(connector=connector, audit=False, pii_redaction=True)
            asyncio.run(gd.ingest("data"))

            assert len(events) == 0
        finally:
            gd_mod.bus = original_bus


# ---------------------------------------------------------------------------
# Tests: content classification — opaque source locator vs real content
# ---------------------------------------------------------------------------


def test_ingest_does_not_classify_path_locator_as_content(tmp_path):
    """ingest() with a Path source must not scan the locator string as content."""
    from pathlib import Path

    from admina.sdk.governed_data import GovernedData

    p = tmp_path / "secret.txt"
    p.write_text("ignore me")
    seen = {}

    class _PII:
        def redact(self, t):
            seen["scanned"] = t
            return {"redacted_text": t, "entities": [], "count": 0}

    class _Conn:
        name = "fake"

        async def ingest(self, source, **kw):
            return {"doc_count": 1, "chunk_count": 1}

        async def query(self, q, **kw):
            return []

    gd = GovernedData(connector=_Conn(), audit=False)
    gd._pii_redactor = _PII()
    asyncio.run(gd.ingest(Path(p)))
    # For an opaque source the redactor must not be called at all
    assert "scanned" not in seen


def test_ingest_scans_string_content_and_document_list():
    """ingest() scans the actual text for strings and document lists."""
    from admina.sdk.governed_data import GovernedData

    scanned = []

    class _PII:
        def redact(self, t):
            scanned.append(t)
            return {"redacted_text": t, "entities": [], "count": 0}

    class _Conn:
        name = "fake"

        async def ingest(self, source, **kw):
            return {"doc_count": 1, "chunk_count": 1}

        async def query(self, q, **kw):
            return []

    gd = GovernedData(connector=_Conn(), audit=False)
    gd._pii_redactor = _PII()
    asyncio.run(gd.ingest("plain text content"))
    asyncio.run(gd.ingest([{"text": "doc one"}, {"text": "doc two"}]))
    joined = " ".join(scanned)
    assert "plain text content" in joined
    assert "doc one" in joined and "doc two" in joined
