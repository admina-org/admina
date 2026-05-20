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

"""Tests for the 9 plugin abstract base classes.

Each test creates a concrete mock implementation, instantiates it,
and verifies that all required methods and properties are callable.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from admina.plugins.base import (
    BaseAlertChannel,
    BaseAuthProvider,
    BaseComplianceTemplate,
    BaseDataConnector,
    BaseForensicStore,
    BaseGovernanceGuard,
    BaseModelAdapter,
    BasePIIEngine,
    BaseTransportAdapter,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. BaseModelAdapter
# ---------------------------------------------------------------------------


class MockModelAdapter(BaseModelAdapter):
    async def send(self, prompt, context=None, **kwargs):
        return {"text": f"echo: {prompt}", "metadata": {"tokens": 3, "latency_ms": 1.0}}

    def supports_model(self, model_name):
        return model_name == "mock-llm"

    @property
    def name(self):
        return "mock"


class TestBaseModelAdapter:
    def test_instantiation(self):
        adapter = MockModelAdapter()
        assert adapter.name == "mock"

    def test_supports_model(self):
        adapter = MockModelAdapter()
        assert adapter.supports_model("mock-llm") is True
        assert adapter.supports_model("other") is False

    def test_send(self):
        adapter = MockModelAdapter()
        result = _run(adapter.send("hello"))
        assert result["text"] == "echo: hello"
        assert "tokens" in result["metadata"]

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseModelAdapter()


# ---------------------------------------------------------------------------
# 2. BaseDataConnector
# ---------------------------------------------------------------------------


class MockDataConnector(BaseDataConnector):
    async def ingest(self, source, **kwargs):
        return {"doc_count": 1, "chunk_count": 10}

    async def query(self, query, **kwargs):
        return [{"text": "result", "metadata": {}, "score": 0.95}]

    @property
    def name(self):
        return "mock-data"


class TestBaseDataConnector:
    def test_instantiation(self):
        conn = MockDataConnector()
        assert conn.name == "mock-data"

    def test_ingest(self):
        conn = MockDataConnector()
        result = _run(conn.ingest("/tmp/data.csv"))
        assert result["doc_count"] == 1
        assert result["chunk_count"] == 10

    def test_query(self):
        conn = MockDataConnector()
        results = _run(conn.query("search term"))
        assert len(results) == 1
        assert results[0]["score"] == 0.95

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseDataConnector()


# ---------------------------------------------------------------------------
# 3. BaseGovernanceGuard
# ---------------------------------------------------------------------------


class MockGovernanceDomain(BaseGovernanceGuard):
    async def inspect_request(self, request):
        return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

    async def inspect_response(self, response):
        return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

    @property
    def name(self):
        return "mock-domain"


class TestBaseGovernanceGuard:
    def test_instantiation(self):
        guard = MockGovernanceDomain()
        assert guard.name == "mock-domain"

    def test_inspect_request(self):
        guard = MockGovernanceDomain()
        result = _run(guard.inspect_request({"content": "test"}))
        assert result["action"] == "ALLOW"

    def test_inspect_response(self):
        guard = MockGovernanceDomain()
        result = _run(guard.inspect_response({"content": "reply"}))
        assert result["action"] == "ALLOW"

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseGovernanceGuard()


# ---------------------------------------------------------------------------
# 4. BaseComplianceTemplate
# ---------------------------------------------------------------------------


class MockComplianceTemplate(BaseComplianceTemplate):
    def get_requirements(self):
        return [{"id": "r1", "title": "Test requirement", "checks": []}]

    def evaluate(self, governance_state):
        return {"score": 1.0, "gaps": [], "covered": ["r1"]}

    @property
    def framework_name(self):
        return "mock-framework"


class TestBaseComplianceTemplate:
    def test_instantiation(self):
        tmpl = MockComplianceTemplate()
        assert tmpl.framework_name == "mock-framework"

    def test_get_requirements(self):
        tmpl = MockComplianceTemplate()
        reqs = tmpl.get_requirements()
        assert len(reqs) == 1
        assert reqs[0]["id"] == "r1"

    def test_evaluate(self):
        tmpl = MockComplianceTemplate()
        result = tmpl.evaluate({"domains_active": 6})
        assert result["score"] == 1.0
        assert result["gaps"] == []

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseComplianceTemplate()


# ---------------------------------------------------------------------------
# 5. BaseTransportAdapter
# ---------------------------------------------------------------------------


class MockTransportAdapter(BaseTransportAdapter):
    async def parse_request(self, raw_request):
        from admina.core.types import GovernanceRequest

        return GovernanceRequest(content=str(raw_request), protocol="mock")

    async def format_response(self, gov_response, original):
        return {"status": "ok", "action": gov_response.action}

    def register_routes(self, app):
        pass  # no-op for test

    @property
    def protocol_name(self):
        return "mock-protocol"


class TestBaseTransportAdapter:
    def test_instantiation(self):
        adapter = MockTransportAdapter()
        assert adapter.protocol_name == "mock-protocol"

    def test_parse_request(self):
        adapter = MockTransportAdapter()
        req = _run(adapter.parse_request({"data": "test"}))
        assert req.protocol == "mock"

    def test_format_response(self):
        from admina.core.types import GovernanceResponse

        adapter = MockTransportAdapter()
        resp = GovernanceResponse(content="ok", action="ALLOW")
        result = _run(adapter.format_response(resp, {}))
        assert result["action"] == "ALLOW"

    def test_register_routes_callable(self):
        adapter = MockTransportAdapter()
        adapter.register_routes(None)  # should not raise

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseTransportAdapter()


# ---------------------------------------------------------------------------
# 6. BaseForensicStore
# ---------------------------------------------------------------------------


class MockForensicStore(BaseForensicStore):
    def __init__(self):
        self._records = []

    async def append(self, record):
        self._records.append(record)
        return f"id-{len(self._records)}"

    async def verify_chain(self, last_n=0):
        return {"valid": True, "records": len(self._records), "last_hash": "abc123"}

    @property
    def store_name(self):
        return "mock-store"


class TestBaseForensicStore:
    def test_instantiation(self):
        store = MockForensicStore()
        assert store.store_name == "mock-store"

    def test_append(self):
        store = MockForensicStore()
        record_id = _run(store.append({"hash": "abc", "data": "test"}))
        assert record_id == "id-1"

    def test_verify_chain(self):
        store = MockForensicStore()
        _run(store.append({"hash": "abc"}))
        result = _run(store.verify_chain())
        assert result["valid"] is True
        assert result["records"] == 1

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseForensicStore()


# ---------------------------------------------------------------------------
# 7. BaseAuthProvider
# ---------------------------------------------------------------------------


class MockAuthProvider(BaseAuthProvider):
    async def authenticate(self, request):
        return {"user_id": "user-1", "roles": ["admin"], "metadata": {}}

    async def authorize(self, user, action, resource=""):
        return "admin" in user["roles"]

    @property
    def provider_name(self):
        return "mock-auth"


class TestBaseAuthProvider:
    def test_instantiation(self):
        auth = MockAuthProvider()
        assert auth.provider_name == "mock-auth"

    def test_authenticate(self):
        auth = MockAuthProvider()
        user = _run(auth.authenticate({"headers": {"x-api-key": "secret"}}))
        assert user["user_id"] == "user-1"
        assert "admin" in user["roles"]

    def test_authorize(self):
        auth = MockAuthProvider()
        user = {"user_id": "u1", "roles": ["admin"], "metadata": {}}
        assert _run(auth.authorize(user, "model.call")) is True
        user_no_admin = {"user_id": "u2", "roles": ["viewer"], "metadata": {}}
        assert _run(auth.authorize(user_no_admin, "model.call")) is False

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseAuthProvider()


# ---------------------------------------------------------------------------
# 8. BasePIIEngine
# ---------------------------------------------------------------------------


class MockPIIEngine(BasePIIEngine):
    async def detect(self, text, categories=None):
        matches = []
        if "@" in text:
            idx = text.index("@")
            start = text.rfind(" ", 0, idx) + 1
            end = text.find(" ", idx)
            if end == -1:
                end = len(text)
            matches.append(
                {
                    "type": "EMAIL",
                    "start": start,
                    "end": end,
                    "text": text[start:end],
                    "confidence": 0.99,
                }
            )
        return matches

    async def redact(self, text, matches):
        result = text
        for m in sorted(matches, key=lambda x: x["start"], reverse=True):
            result = result[: m["start"]] + f"[{m['type']}]" + result[m["end"] :]
        return result

    @property
    def supported_languages(self):
        return ["en"]


class TestBasePIIEngine:
    def test_instantiation(self):
        engine = MockPIIEngine()
        assert engine.supported_languages == ["en"]

    def test_detect(self):
        engine = MockPIIEngine()
        matches = _run(engine.detect("contact foo@bar.com please"))
        assert len(matches) == 1
        assert matches[0]["type"] == "EMAIL"

    def test_detect_no_pii(self):
        engine = MockPIIEngine()
        matches = _run(engine.detect("no personal info here"))
        assert matches == []

    def test_redact(self):
        engine = MockPIIEngine()
        matches = _run(engine.detect("contact foo@bar.com please"))
        redacted = _run(engine.redact("contact foo@bar.com please", matches))
        assert "[EMAIL]" in redacted
        assert "foo@bar.com" not in redacted

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BasePIIEngine()


# ---------------------------------------------------------------------------
# 9. BaseAlertChannel
# ---------------------------------------------------------------------------


class MockAlertChannel(BaseAlertChannel):
    def __init__(self):
        self.sent = []

    async def send_alert(self, alert):
        self.sent.append(alert)
        return True

    @property
    def channel_name(self):
        return "mock-alert"


class TestBaseAlertChannel:
    def test_instantiation(self):
        ch = MockAlertChannel()
        assert ch.channel_name == "mock-alert"

    def test_send_alert(self):
        ch = MockAlertChannel()
        alert = {
            "level": "HIGH",
            "domain": "firewall",
            "summary": "Injection attempt blocked",
            "details": {"pattern": "DROP TABLE"},
            "timestamp": datetime.now(tz=UTC),
        }
        result = _run(ch.send_alert(alert))
        assert result is True
        assert len(ch.sent) == 1
        assert ch.sent[0]["level"] == "HIGH"

    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BaseAlertChannel()
