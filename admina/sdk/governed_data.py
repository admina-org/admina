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

"""Admina — GovernedData SDK primitive.

Wraps a data connector with automatic data classification, residency
enforcement, PII redaction, and governance event emission.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from admina.core.event_bus import EventType, GovernanceEvent, bus
from admina.plugins.base import BaseDataConnector
from admina.sdk._compat import run_sync
from admina.sdk.retry import RetryPolicy, run_with_retry

__all__ = ["GovernedData", "GovernedDocument", "IngestResult", "BaseDataConnector"]


@dataclass
class IngestResult:
    """Result of a GovernedData.ingest() call.

    Attributes:
        doc_count: Number of documents ingested.
        chunk_count: Number of chunks produced.
        classification: Data classification results (PII stats, sensitivity).
        governance: Governance decisions applied during ingest.
    """

    doc_count: int = 0
    chunk_count: int = 0
    classification: dict[str, Any] = field(default_factory=dict)
    governance: dict[str, Any] = field(default_factory=dict)


@dataclass
class GovernedDocument:
    """A single document returned by GovernedData.query().

    Attributes:
        text: Document text (PII-redacted if applicable).
        metadata: Document metadata from the connector.
        score: Relevance score from the connector.
        governance: Governance decisions applied to this document.
    """

    text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0
    governance: dict[str, Any] = field(default_factory=dict)


# Allowed residency zones
VALID_ZONES = {"local", "eu", "us", "custom"}


def _load_pii_redactor() -> Any:
    """Engine from admina.engines (honors ADMINA_ENGINE and pii_engine)."""
    from admina.engines import get_pii_engine

    return get_pii_engine()


def _classify_content(text: str, pii_result: dict) -> dict[str, Any]:
    """Classify content sensitivity based on PII scan results.

    Args:
        text: The original text.
        pii_result: Result dict from PIIRedactor.redact().

    Returns:
        Classification dict with sensitivity level and details.
    """
    pii_count = pii_result.get("count", 0)
    pii_types = {e["type"] for e in pii_result.get("entities", [])}

    high_risk_types = {"CREDIT_CARD", "SSN", "IBAN"}
    has_high_risk = bool(pii_types & high_risk_types)

    if has_high_risk or pii_count >= 5:
        sensitivity = "HIGH"
    elif pii_count >= 1:
        sensitivity = "MEDIUM"
    else:
        sensitivity = "LOW"

    return {
        "sensitivity": sensitivity,
        "pii_count": pii_count,
        "pii_types": sorted(pii_types),
        "has_high_risk_pii": has_high_risk,
    }


class GovernedData:
    """SDK primitive for governed data access.

    Wraps a data connector with automatic data classification,
    residency zone enforcement, PII redaction, and event emission.

    Args:
        connector: A BaseDataConnector instance, or None.
        residency_zone: Data residency zone (local, eu, us, custom).
        allowed_zones: Set of zones this instance may access.
        audit: Whether to emit governance events.
        pii_redaction: Whether to run PII redaction on query results.
    """

    def __init__(
        self,
        connector: BaseDataConnector | None = None,
        residency_zone: str = "local",
        allowed_zones: set[str] | None = None,
        audit: bool = True,
        pii_redaction: bool = True,
        retry: RetryPolicy | None = None,
    ) -> None:
        """Initialize GovernedData.

        Args:
            connector: Data connector instance. Can be resolved via
                :class:`PluginRegistry` or passed explicitly.
            residency_zone: Zone where this data resides.
            allowed_zones: Zones allowed for data access. Defaults to
                {residency_zone}.
            audit: If True, emit events to the event bus.
            pii_redaction: If True, redact PII from query results.
            retry: Optional RetryPolicy for transient connector errors. Default
                None (single attempt, unchanged behaviour). Residency refusals
                are raised before the connector call and are never retried.
        """
        self._connector = connector
        self.residency_zone = residency_zone
        self.allowed_zones = allowed_zones or {residency_zone}
        self._audit = audit
        self._pii_redaction = pii_redaction
        self._retry = retry
        self._pii_redactor: Any = None

    def _get_pii_redactor(self) -> Any:
        """Return the PII redactor, creating it lazily."""
        if self._pii_redactor is None:
            self._pii_redactor = _load_pii_redactor()
        return self._pii_redactor

    def _check_residency(self, target_zone: str) -> bool:
        """Check if access to target_zone is allowed.

        Args:
            target_zone: The zone being accessed.

        Returns:
            True if allowed.

        Raises:
            PermissionError: If the zone is not in allowed_zones.
        """
        if target_zone not in self.allowed_zones:
            raise PermissionError(
                f"Data residency violation: zone '{target_zone}' "
                f"not in allowed zones {self.allowed_zones}"
            )
        return True

    async def ingest(
        self,
        source: Any,
        target_zone: str | None = None,
        **kwargs: Any,
    ) -> IngestResult:
        """Ingest data with governance checks.

        Classifies data (PII scan, sensitivity), checks residency rules,
        emits events, and passes to the connector.

        Args:
            source: Data source (string content, file path, etc.).
            target_zone: Zone to ingest into. Defaults to residency_zone.
            **kwargs: Forwarded to connector.ingest().

        Returns:
            IngestResult with counts, classification, and governance info.

        Raises:
            RuntimeError: If no connector is configured.
            PermissionError: If residency check fails.
        """
        if self._connector is None:
            raise RuntimeError(
                "No data connector configured. Pass a connector to "
                "GovernedData() or resolve one via PluginRegistry."
            )

        zone = target_zone or self.residency_zone
        session_id = kwargs.pop("session_id", None) or str(uuid.uuid4())
        start_us = time.time() * 1_000_000
        governance: dict[str, Any] = {"residency": {"zone": zone, "allowed": True}}

        # 1. Check residency
        try:
            self._check_residency(zone)
        except PermissionError:
            governance["residency"]["allowed"] = False
            if self._audit:
                await bus.emit(
                    GovernanceEvent(
                        event_type=EventType.DATA_ACCESS,
                        session_id=session_id,
                        domain="data-sovereignty",
                        action="BLOCK",
                        risk_level="CRITICAL",
                        metadata={"reason": "residency_violation", "zone": zone},
                    )
                )
            raise

        # 2. Classify content (PII scan) — scan the actual ingested content
        #    (a string, or a document collection), NOT an opaque source
        #    locator (a file path / URL the connector will read itself).
        from admina.domains.governance import _extract_text_fields

        classification: dict[str, Any] = {}
        if isinstance(source, str):
            content_for_scan = source
        else:
            content_for_scan = " ".join(_extract_text_fields(source))

        if content_for_scan:
            pii_result = self._get_pii_redactor().redact(content_for_scan)
            classification = _classify_content(content_for_scan, pii_result)
            classification["source_scanned"] = True
        else:
            # Opaque source (e.g. a file path / URL) — we cannot classify
            # content we never see; flag it rather than misclassifying the
            # locator string.
            classification = _classify_content("", {"count": 0, "entities": []})
            classification["source_scanned"] = False

        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.DATA_CLASSIFY,
                    session_id=session_id,
                    domain="data-sovereignty",
                    metadata={
                        "sensitivity": classification["sensitivity"],
                        "pii_count": classification["pii_count"],
                    },
                )
            )

        # 3. Emit DATA_ACCESS event
        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.DATA_ACCESS,
                    session_id=session_id,
                    domain="data-sovereignty",
                    action="ALLOW",
                    metadata={
                        "operation": "ingest",
                        "zone": zone,
                        "connector": self._connector.name,
                    },
                )
            )

        # 4. Pass to connector
        connector_result = await run_with_retry(
            lambda: self._connector.ingest(source, **kwargs),
            self._retry,
        )

        latency_us = time.time() * 1_000_000 - start_us
        governance["latency_us"] = latency_us

        return IngestResult(
            doc_count=connector_result.get("doc_count", 0),
            chunk_count=connector_result.get("chunk_count", 0),
            classification=classification,
            governance=governance,
        )

    async def query(
        self,
        query: str,
        target_zone: str | None = None,
        **kwargs: Any,
    ) -> list[GovernedDocument]:
        """Query data with governance checks.

        Checks residency, retrieves from connector, redacts PII if needed,
        and emits events.

        Args:
            query: The query string.
            target_zone: Zone to query from. Defaults to residency_zone.
            **kwargs: Forwarded to connector.query().

        Returns:
            List of GovernedDocument with redacted text and governance info.

        Raises:
            RuntimeError: If no connector is configured.
            PermissionError: If residency check fails.
        """
        if self._connector is None:
            raise RuntimeError(
                "No data connector configured. Pass a connector to "
                "GovernedData() or resolve one via PluginRegistry."
            )

        zone = target_zone or self.residency_zone
        session_id = kwargs.pop("session_id", None) or str(uuid.uuid4())

        # 1. Check residency
        try:
            self._check_residency(zone)
        except PermissionError:
            if self._audit:
                await bus.emit(
                    GovernanceEvent(
                        event_type=EventType.DATA_ACCESS,
                        session_id=session_id,
                        domain="data-sovereignty",
                        action="BLOCK",
                        risk_level="CRITICAL",
                        metadata={"reason": "residency_violation", "zone": zone},
                    )
                )
            raise

        # 2. Emit DATA_ACCESS event
        if self._audit:
            await bus.emit(
                GovernanceEvent(
                    event_type=EventType.DATA_ACCESS,
                    session_id=session_id,
                    domain="data-sovereignty",
                    action="ALLOW",
                    metadata={
                        "operation": "query",
                        "zone": zone,
                        "connector": self._connector.name,
                    },
                )
            )

        # 3. Retrieve from connector
        raw_results = await run_with_retry(
            lambda: self._connector.query(query, **kwargs),
            self._retry,
        )

        # 4. Redact PII and wrap results
        documents: list[GovernedDocument] = []
        for raw in raw_results:
            raw_text = raw.get("text", "")
            doc_governance: dict[str, Any] = {"pii": {"redacted": False, "count": 0}}

            if self._pii_redaction and raw_text:
                pii_result = self._get_pii_redactor().redact(raw_text)
                text = pii_result["redacted_text"]
                if pii_result["count"] > 0:
                    doc_governance["pii"] = {
                        "redacted": True,
                        "count": pii_result["count"],
                    }
                    if self._audit:
                        await bus.emit(
                            GovernanceEvent(
                                event_type=EventType.DATA_REDACT,
                                session_id=session_id,
                                domain="data-sovereignty",
                                action="REDACT",
                                metadata={"pii_count": pii_result["count"]},
                            )
                        )
            else:
                text = raw_text

            documents.append(
                GovernedDocument(
                    text=text,
                    metadata=raw.get("metadata", {}),
                    score=raw.get("score", 0.0),
                    governance=doc_governance,
                )
            )

        return documents

    def ingest_sync(self, source: Any, **kwargs: Any) -> IngestResult:
        """Synchronous convenience wrapper around ingest().

        Args:
            source: Data source.
            **kwargs: Forwarded to ingest().

        Returns:
            IngestResult.
        """
        return run_sync(self.ingest(source, **kwargs))

    def query_sync(self, query: str, **kwargs: Any) -> list[GovernedDocument]:
        """Synchronous convenience wrapper around query().

        Args:
            query: The query string.
            **kwargs: Forwarded to query().

        Returns:
            List of GovernedDocument.
        """
        return run_sync(self.query(query, **kwargs))
