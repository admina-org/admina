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

"""Tests for all builtin reference plugins.

Each plugin is tested for:
1. Instantiation without external dependencies (lazy loading / mocking).
2. Correct base class inheritance.
3. Core method behavior.
4. Registry discoverability.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from admina.plugins.base import (
    BaseAlertChannel,
    BaseAuthProvider,
    BaseComplianceTemplate,
    BaseDataConnector,
    BaseForensicStore,
    BaseModelAdapter,
    BasePIIEngine,
    BaseTransportAdapter,
)
from admina.plugins.registry import PluginRegistry


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.run(coro)


# ═══════════════════════════════════════════════════════════════
# 1. OllamaAdapter
# ═══════════════════════════════════════════════════════════════


class TestOllamaAdapter:
    def test_is_model_adapter(self):
        from admina.plugins.builtin.adapters.ollama import OllamaAdapter

        adapter = OllamaAdapter()
        assert isinstance(adapter, BaseModelAdapter)
        assert adapter.name == "ollama"

    def test_supports_any_model(self):
        from admina.plugins.builtin.adapters.ollama import OllamaAdapter

        adapter = OllamaAdapter()
        assert adapter.supports_model("llama3") is True
        assert adapter.supports_model("anything") is True

    def test_send_calls_client(self):
        from admina.plugins.builtin.adapters.ollama import OllamaAdapter

        adapter = OllamaAdapter()
        mock_client = MagicMock()
        mock_client.chat.return_value = {
            "message": {"content": "Hello!"},
            "eval_count": 5,
            "prompt_eval_count": 3,
        }
        adapter._client = mock_client

        result = _run(adapter.send("Hi"))
        assert result["text"] == "Hello!"
        assert result["metadata"]["tokens"] == 8
        mock_client.chat.assert_called_once()

    def test_send_with_context(self):
        from admina.plugins.builtin.adapters.ollama import OllamaAdapter

        adapter = OllamaAdapter()
        mock_client = MagicMock()
        mock_client.chat.return_value = {"message": {"content": "ok"}}
        adapter._client = mock_client

        _run(adapter.send("Hi", context="Be helpful"))
        args = mock_client.chat.call_args
        messages = args[1]["messages"] if "messages" in args[1] else args[0][1]
        # Should have system + user messages
        assert len(messages) == 2


# ═══════════════════════════════════════════════════════════════
# 2. OpenAIAdapter
# ═══════════════════════════════════════════════════════════════


class TestOpenAIAdapter:
    def test_is_model_adapter(self):
        from admina.plugins.builtin.adapters.openai import OpenAIAdapter

        adapter = OpenAIAdapter(api_key="test-key")
        assert isinstance(adapter, BaseModelAdapter)
        assert adapter.name == "openai"

    def test_supports_model(self):
        from admina.plugins.builtin.adapters.openai import OpenAIAdapter

        adapter = OpenAIAdapter(api_key="test-key")
        assert adapter.supports_model("gpt-4o") is True
        assert adapter.supports_model("o1") is True
        assert adapter.supports_model("llama3") is False

    def test_send_calls_client(self):
        from admina.plugins.builtin.adapters.openai import OpenAIAdapter

        adapter = OpenAIAdapter(api_key="test-key")

        # Mock the OpenAI client
        mock_choice = MagicMock()
        mock_choice.message.content = "Hello from GPT"
        mock_usage = MagicMock()
        mock_usage.total_tokens = 15
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = mock_usage

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        adapter._client = mock_client

        result = _run(adapter.send("Hi"))
        assert result["text"] == "Hello from GPT"
        assert result["metadata"]["tokens"] == 15


# ═══════════════════════════════════════════════════════════════
# 3. ChromaDBConnector
# ═══════════════════════════════════════════════════════════════


class TestChromaDBConnector:
    def test_is_data_connector(self):
        from admina.plugins.builtin.connectors.chromadb import ChromaDBConnector

        conn = ChromaDBConnector()
        assert isinstance(conn, BaseDataConnector)
        assert conn.name == "chromadb"

    def test_ingest_calls_collection(self):
        from admina.plugins.builtin.connectors.chromadb import ChromaDBConnector

        conn = ChromaDBConnector()
        mock_collection = MagicMock()
        conn._collection = mock_collection

        docs = [
            {"id": "d1", "text": "hello", "metadata": {"src": "test"}},
            {"id": "d2", "text": "world"},
        ]
        result = _run(conn.ingest(docs))
        assert result["doc_count"] == 2
        mock_collection.add.assert_called_once()

    def test_query_calls_collection(self):
        from admina.plugins.builtin.connectors.chromadb import ChromaDBConnector

        conn = ChromaDBConnector()
        mock_collection = MagicMock()
        mock_collection.query.return_value = {
            "documents": [["text1", "text2"]],
            "metadatas": [[{}, {}]],
            "distances": [[0.1, 0.5]],
        }
        conn._collection = mock_collection

        results = _run(conn.query("search term"))
        assert len(results) == 2
        assert results[0]["score"] > results[1]["score"]


# ═══════════════════════════════════════════════════════════════
# 4. FilesystemConnector
# ═══════════════════════════════════════════════════════════════


class TestFilesystemConnector:
    def test_is_data_connector(self):
        from admina.plugins.builtin.connectors.filesystem import FilesystemConnector

        conn = FilesystemConnector()
        assert isinstance(conn, BaseDataConnector)
        assert conn.name == "filesystem"

    def test_ingest_file(self, tmp_path):
        from admina.plugins.builtin.connectors.filesystem import FilesystemConnector

        f = tmp_path / "test.txt"
        f.write_text("hello world")

        conn = FilesystemConnector(base_dir=str(tmp_path))
        result = _run(conn.ingest(str(f)))
        assert result["doc_count"] == 1
        assert result["chunk_count"] == 1

    def test_ingest_directory(self, tmp_path):
        from admina.plugins.builtin.connectors.filesystem import FilesystemConnector

        (tmp_path / "a.txt").write_text("aaa")
        (tmp_path / "b.txt").write_text("bbb")

        conn = FilesystemConnector()
        result = _run(conn.ingest(str(tmp_path), glob="*.txt"))
        assert result["doc_count"] == 2

    def test_query_finds_matching_file(self, tmp_path):
        from admina.plugins.builtin.connectors.filesystem import FilesystemConnector

        (tmp_path / "match.txt").write_text("governance framework details")
        (tmp_path / "no_match.txt").write_text("nothing here")

        conn = FilesystemConnector(base_dir=str(tmp_path))
        results = _run(conn.query("governance"))
        assert len(results) == 1
        assert "governance" in results[0]["text"]


# ═══════════════════════════════════════════════════════════════
# 5. HTTPRESTTransportAdapter
# ═══════════════════════════════════════════════════════════════


class TestHTTPRESTTransportAdapter:
    def test_is_transport_adapter(self):
        from admina.plugins.builtin.transports.http_rest import HTTPRESTTransportAdapter

        adapter = HTTPRESTTransportAdapter()
        assert isinstance(adapter, BaseTransportAdapter)
        assert adapter.protocol_name == "http_rest"

    def test_parse_request(self):
        from admina.plugins.builtin.transports.http_rest import HTTPRESTTransportAdapter

        adapter = HTTPRESTTransportAdapter()
        body = {
            "content": "hello world",
            "method": "chat",
            "session_id": "s1",
        }
        req = _run(adapter.parse_request(body))
        assert req.content == "hello world"
        assert req.method == "chat"
        assert req.protocol == "http_rest"
        assert req.session_id == "s1"

    def test_format_response(self):
        from admina.core.types import GovernanceResponse
        from admina.plugins.builtin.transports.http_rest import HTTPRESTTransportAdapter

        adapter = HTTPRESTTransportAdapter()
        gov = GovernanceResponse(
            content="ok",
            action="ALLOW",
            risk_level="LOW",
            request_id="r1",
            latency_us=50.5,
        )
        result = _run(adapter.format_response(gov, {}))
        assert result["action"] == "ALLOW"
        assert result["request_id"] == "r1"
        assert result["latency_us"] == 50.5


# ═══════════════════════════════════════════════════════════════
# 6. FilesystemForensicStore
# ═══════════════════════════════════════════════════════════════


class TestFilesystemForensicStore:
    def test_is_forensic_store(self, tmp_path):
        from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

        store = FilesystemForensicStore(base_dir=str(tmp_path / "forensic"))
        assert isinstance(store, BaseForensicStore)
        assert store.store_name == "filesystem"

    def test_append_creates_file(self, tmp_path):
        from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

        base = tmp_path / "forensic"
        store = FilesystemForensicStore(base_dir=str(base))
        record_hash = _run(store.append({"event": "test"}))
        assert len(record_hash) == 64

        record_file = base / "00000001.json"
        assert record_file.exists()
        data = json.loads(record_file.read_text())
        assert data["event"]["event"] == "test"

    def test_verify_chain_valid(self, tmp_path):
        from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

        store = FilesystemForensicStore(base_dir=str(tmp_path / "forensic"))
        _run(store.append({"a": 1}))
        _run(store.append({"b": 2}))

        result = _run(store.verify_chain())
        assert result["valid"] is True
        assert result["records"] == 2

    def test_verify_chain_detects_tampering(self, tmp_path):
        from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

        base = tmp_path / "forensic"
        store = FilesystemForensicStore(base_dir=str(base))
        _run(store.append({"a": 1}))

        # Tamper with the record
        record_file = base / "00000001.json"
        data = json.loads(record_file.read_text())
        data["event"]["a"] = 999
        record_file.write_text(json.dumps(data, indent=2))

        result = _run(store.verify_chain())
        assert result["valid"] is False

    def test_chain_state_persistence(self, tmp_path):
        from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

        base = str(tmp_path / "forensic")
        store1 = FilesystemForensicStore(base_dir=base)
        h1 = _run(store1.append({"event": "one"}))

        # Create a new store instance — should restore state
        store2 = FilesystemForensicStore(base_dir=base)
        h2 = _run(store2.append({"event": "two"}))
        assert h1 != h2

        result = _run(store2.verify_chain())
        assert result["valid"] is True
        assert result["records"] == 2


def test_plugin_forensic_reconstructs_after_state_loss(tmp_path):
    from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

    s = FilesystemForensicStore(base_dir=str(tmp_path))
    _run(s.append({"e": 1}))
    _run(s.append({"e": 2}))
    head, count = s._chain_head, s._record_count

    (tmp_path / "_chain_state.json").unlink()  # lose state

    s2 = FilesystemForensicStore(base_dir=str(tmp_path))
    assert s2._record_count == count   # reconstructed, not 0
    assert s2._chain_head == head      # reconstructed, not GENESIS

    # next append continues the chain and does NOT overwrite record 1
    _run(s2.append({"e": 3}))
    assert (tmp_path / "00000003.json").exists()
    original_rec1 = (tmp_path / "00000001.json").read_text()
    assert '"sequence_number": 1' in original_rec1  # still the ORIGINAL record 1


def test_plugin_forensic_refuses_overwrite(tmp_path):
    from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

    s = FilesystemForensicStore(base_dir=str(tmp_path))
    _run(s.append({"e": 1}))
    # force a state that would re-write sequence 1 (simulate a reset bug slipping through)
    s._record_count = 0
    with pytest.raises(RuntimeError, match="already exists"):
        _run(s.append({"e": "dup"}))  # would write 00000001.json again


def test_plugin_forensic_verify_detects_truncation(tmp_path):
    from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

    s = FilesystemForensicStore(base_dir=str(tmp_path))
    for i in range(4):
        _run(s.append({"e": i}))
    assert _run(s.verify_chain())["valid"] is True
    sorted(tmp_path.glob("[0-9]*.json"))[-1].unlink()  # truncate tail
    assert _run(s.verify_chain())["valid"] is False


# ═══════════════════════════════════════════════════════════════
# 8. APIKeyAuthProvider
# ═══════════════════════════════════════════════════════════════


class TestAPIKeyAuthProvider:
    def test_is_auth_provider(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider()
        assert isinstance(auth, BaseAuthProvider)
        assert auth.provider_name == "apikey"

    def test_no_key_allows_everything(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="")
        user = _run(auth.authenticate({"headers": {}}))
        assert user["user_id"] == "anonymous"
        assert "admin" in user["roles"]

    def test_valid_key_authenticates(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="secret123")
        user = _run(
            auth.authenticate(
                {
                    "headers": {"X-API-Key": "secret123"},
                    "path": "/mcp",
                }
            )
        )
        assert user["user_id"] == "api_key_user"

    def test_invalid_key_raises(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="secret123")
        with pytest.raises(PermissionError):
            _run(
                auth.authenticate(
                    {
                        "headers": {"X-API-Key": "wrong"},
                        "path": "/mcp",
                    }
                )
            )

    def test_exempt_path_bypasses_auth(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="secret123")
        user = _run(auth.authenticate({"headers": {}, "path": "/health"}))
        assert user["user_id"] == "anonymous"

    def test_bearer_token(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="mytoken")
        user = _run(
            auth.authenticate(
                {
                    "headers": {"Authorization": "Bearer mytoken"},
                    "path": "/mcp",
                }
            )
        )
        assert user["user_id"] == "api_key_user"

    def test_authorize(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider()
        assert _run(auth.authorize({"roles": ["admin"]}, "model.call")) is True
        assert _run(auth.authorize({"roles": []}, "model.call")) is False


# ═══════════════════════════════════════════════════════════════
# 9. SpaCyRegexPIIEngine
# ═══════════════════════════════════════════════════════════════


class TestSpaCyRegexPIIEngine:
    def test_is_pii_engine(self):
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

        engine = SpaCyRegexPIIEngine()
        assert isinstance(engine, BasePIIEngine)
        assert "en" in engine.supported_languages

    def test_detect_email(self):
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

        engine = SpaCyRegexPIIEngine()
        engine._nlp_loaded = True  # skip spaCy loading
        engine._nlp = None

        matches = _run(engine.detect("contact user@example.com please"))
        assert len(matches) >= 1
        assert any(m["type"] == "EMAIL" for m in matches)

    def test_detect_phone(self):
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

        engine = SpaCyRegexPIIEngine()
        engine._nlp_loaded = True
        engine._nlp = None

        matches = _run(engine.detect("call me at (555) 123-4567"))
        assert len(matches) >= 1
        assert any(m["type"] == "PHONE" for m in matches)

    def test_detect_ssn(self):
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

        engine = SpaCyRegexPIIEngine()
        engine._nlp_loaded = True
        engine._nlp = None

        matches = _run(engine.detect("SSN is 123-45-6789"))
        assert any(m["type"] == "SSN" for m in matches)

    def test_detect_with_category_filter(self):
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

        engine = SpaCyRegexPIIEngine()
        engine._nlp_loaded = True
        engine._nlp = None

        text = "email user@example.com and SSN 123-45-6789"
        matches = _run(engine.detect(text, categories=["EMAIL"]))
        assert all(m["type"] == "EMAIL" for m in matches)

    def test_detect_empty_text(self):
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

        engine = SpaCyRegexPIIEngine()
        assert _run(engine.detect("")) == []

    def test_redact(self):
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

        engine = SpaCyRegexPIIEngine()
        engine._nlp_loaded = True
        engine._nlp = None

        text = "email is user@example.com"
        matches = _run(engine.detect(text))
        redacted = _run(engine.redact(text, matches))
        assert "[EMAIL]" in redacted
        assert "user@example.com" not in redacted


# ═══════════════════════════════════════════════════════════════
# 10. LogAlertChannel
# ═══════════════════════════════════════════════════════════════


class TestLogAlertChannel:
    def test_is_alert_channel(self):
        from admina.plugins.builtin.alerts.log import LogAlertChannel

        ch = LogAlertChannel()
        assert isinstance(ch, BaseAlertChannel)
        assert ch.channel_name == "log"

    def test_send_alert(self):
        from admina.plugins.builtin.alerts.log import LogAlertChannel

        ch = LogAlertChannel()
        alert = {
            "level": "HIGH",
            "domain": "firewall",
            "summary": "Injection blocked",
            "details": {},
            "timestamp": datetime.now(tz=UTC),
        }
        result = _run(ch.send_alert(alert))
        assert result is True


# ═══════════════════════════════════════════════════════════════
# 11. WebhookAlertChannel
# ═══════════════════════════════════════════════════════════════


class TestWebhookAlertChannel:
    def test_is_alert_channel(self):
        from admina.plugins.builtin.alerts.webhook import WebhookAlertChannel

        ch = WebhookAlertChannel(url="https://hooks.example.com/test")
        assert isinstance(ch, BaseAlertChannel)
        assert ch.channel_name == "webhook"

    def test_no_url_returns_false(self):
        from admina.plugins.builtin.alerts.webhook import WebhookAlertChannel

        ch = WebhookAlertChannel(url="")
        result = _run(ch.send_alert({"level": "HIGH", "summary": "test"}))
        assert result is False

    def test_event_filter(self):
        from admina.plugins.builtin.alerts.webhook import WebhookAlertChannel

        ch = WebhookAlertChannel(
            url="https://hooks.example.com/test",
            events=["CRITICAL"],
        )
        # LOW alert should be filtered out (not sent, returns True)
        result = _run(ch.send_alert({"level": "LOW", "summary": "minor"}))
        assert result is True


# ═══════════════════════════════════════════════════════════════
# 12. EUAIActComplianceTemplate
# ═══════════════════════════════════════════════════════════════


class TestEUAIActComplianceTemplate:
    def test_is_compliance_template(self):
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate

        tmpl = EUAIActComplianceTemplate()
        assert isinstance(tmpl, BaseComplianceTemplate)
        assert tmpl.framework_name == "EU AI Act"

    def test_get_requirements(self):
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate

        tmpl = EUAIActComplianceTemplate()
        reqs = tmpl.get_requirements()
        assert len(reqs) == 7
        assert any(r["article"] == "Art. 9" for r in reqs)
        assert any(r["article"] == "Art. 15" for r in reqs)

    def test_evaluate_minimal_risk(self):
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate

        tmpl = EUAIActComplianceTemplate()
        result = tmpl.evaluate({"risk_category": "minimal"})
        assert result["score"] == 1.0
        assert result["gaps"] == []

    def test_evaluate_high_risk_all_gaps(self):
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate

        tmpl = EUAIActComplianceTemplate()
        result = tmpl.evaluate(
            {
                "risk_category": "high",
                "current_compliance": {},  # nothing met
            }
        )
        assert result["score"] == 0.0
        assert len(result["gaps"]) == 28  # 7 requirements × 4 checks each

    def test_evaluate_high_risk_partial(self):
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate

        tmpl = EUAIActComplianceTemplate()
        result = tmpl.evaluate(
            {
                "risk_category": "high",
                "current_compliance": {
                    "risk_management": [True, True, True, True],
                    "record_keeping": [True, True, True, True],
                },
            }
        )
        assert result["passed_checks"] == 8
        assert result["score"] == round(8 / 28, 4)

    def test_classify_risk(self):
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate

        tmpl = EUAIActComplianceTemplate()
        assert tmpl.classify_risk("social scoring system", "governance") == "unacceptable"
        assert tmpl.classify_risk("credit scoring engine", "lending", ["financial"]) == "high"
        assert tmpl.classify_risk("chatbot for support", "customer service") == "limited"
        assert tmpl.classify_risk("spam filter", "email") == "minimal"

    def test_yaml_loads_correctly(self):
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate

        tmpl = EUAIActComplianceTemplate()
        assert tmpl._data.get("framework_name") == "EU AI Act"
        assert tmpl._data.get("enforcement_deadline") == "2027-12-02"


# ═══════════════════════════════════════════════════════════════
# 13. Registry integration — all plugins discoverable
# ═══════════════════════════════════════════════════════════════


class TestRegistryDiscovery:
    def test_register_all_builtin_plugins_manually(self):
        """All builtin plugins can be registered with the registry."""
        from admina.plugins.builtin.adapters.ollama import OllamaAdapter
        from admina.plugins.builtin.adapters.openai import OpenAIAdapter
        from admina.plugins.builtin.alerts.log import LogAlertChannel
        from admina.plugins.builtin.alerts.webhook import WebhookAlertChannel
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider
        from admina.plugins.builtin.compliance.eu_ai_act import EUAIActComplianceTemplate
        from admina.plugins.builtin.connectors.chromadb import ChromaDBConnector
        from admina.plugins.builtin.connectors.filesystem import FilesystemConnector
        from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore
        from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine
        from admina.plugins.builtin.transports.http_rest import HTTPRESTTransportAdapter

        reg = PluginRegistry()
        classes = [
            OllamaAdapter,
            OpenAIAdapter,
            ChromaDBConnector,
            FilesystemConnector,
            HTTPRESTTransportAdapter,
            FilesystemForensicStore,
            APIKeyAuthProvider,
            SpaCyRegexPIIEngine,
            LogAlertChannel,
            WebhookAlertChannel,
            EUAIActComplianceTemplate,
        ]
        for cls in classes:
            reg.register(cls)

        all_plugins = reg.list_all()
        total = sum(len(v) for v in all_plugins.values())
        assert total == 11

        # Builtin plugins register under their declared class-level `name`
        assert reg.get("model_adapter", "ollama") is OllamaAdapter
        assert reg.get("model_adapter", "openai") is OpenAIAdapter
        assert reg.get("forensic_store", "filesystem") is FilesystemForensicStore
        assert reg.get("auth_provider", "apikey") is APIKeyAuthProvider
        assert reg.get("alert_channel", "log") is LogAlertChannel

    def test_discover_builtin_directory(self):
        """Registry discover() finds plugins in the builtin dir."""
        builtin_path = Path(__file__).parent.parent.parent / "admina" / "plugins" / "builtin"
        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=builtin_path,
            user_path=Path("/nonexistent"),
        )
        # Should find at least the 11 builtin plugin classes
        assert count >= 11
