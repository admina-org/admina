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
# 3. AnthropicAdapter
# ═══════════════════════════════════════════════════════════════


class TestAnthropicAdapter:
    def test_name_and_supports_model(self):
        pytest.importorskip("anthropic")
        from admina.plugins.builtin.adapters.anthropic import AnthropicAdapter

        a = AnthropicAdapter(api_key="k", default_model="claude-x")
        assert a.name == "anthropic"
        assert a.supports_model("claude-x") is True
        assert a.supports_model("gpt-4o") is False

    def test_send_shapes_request_and_normalizes_response(self):
        pytest.importorskip("anthropic")
        import asyncio

        from admina.plugins.builtin.adapters.anthropic import AnthropicAdapter

        class _Block:
            type = "text"
            text = "hi there"

        class _Usage:
            input_tokens = 3
            output_tokens = 5

        class _Msg:
            content = [_Block()]
            usage = _Usage()

        class _Messages:
            def create(self, **kw):
                _Messages.kw = kw
                return _Msg()

        class _Client:
            messages = _Messages()

        a = AnthropicAdapter(api_key="k", default_model="claude-x")
        a._client = _Client()
        out = asyncio.run(a.send("hello", context="be brief", max_tokens=64))
        assert out["text"] == "hi there"
        assert out["metadata"]["tokens"] == 8
        assert out["metadata"]["model"] == "claude-x"
        assert _Messages.kw["system"] == "be brief"
        assert _Messages.kw["messages"] == [{"role": "user", "content": "hello"}]
        assert _Messages.kw["max_tokens"] == 64

    def test_requires_model(self):
        pytest.importorskip("anthropic")
        import asyncio

        from admina.plugins.builtin.adapters.anthropic import AnthropicAdapter

        a = AnthropicAdapter(api_key="k")  # no default_model, no env
        a._client = object()
        with pytest.raises(ValueError, match="model"):
            asyncio.run(a.send("hi"))


# ═══════════════════════════════════════════════════════════════
# 4. ChromaDBConnector
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
    assert s2._record_count == count  # reconstructed, not 0
    assert s2._chain_head == head  # reconstructed, not GENESIS

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

    def test_no_key_is_fail_closed(self):
        # Previously this returned {"user_id": "anonymous", "roles": ["admin"]} — fail-open bug.
        # Fixed: a keyless provider raises PermissionError so it cannot grant access to anyone.
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="")
        assert auth.is_configured() is False
        with pytest.raises(PermissionError):
            _run(auth.authenticate({"headers": {}}))

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

    def test_apikey_provider_accepts_signed_cookie(self):
        import base64
        import hashlib
        import hmac
        import time

        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        key = "supersecretkey123456"
        provider = APIKeyAuthProvider(api_key=key)

        def _mint(k):
            exp = int(time.time()) + 3600
            payload = str(exp)
            sig = hmac.new(k.encode(), payload.encode(), hashlib.sha256).hexdigest()
            return base64.urlsafe_b64encode(f"{payload}.{sig}".encode()).decode("ascii")

        # valid signed cookie → authenticated
        user = _run(
            provider.authenticate(
                {"path": "/api/x", "headers": {}, "cookies": {"admina_session": _mint(key)}}
            )
        )
        assert user and user.get("user_id")

        # raw key as cookie → REJECTED (must be a signed token, not the raw key)
        with pytest.raises(PermissionError):
            _run(
                provider.authenticate(
                    {"path": "/api/x", "headers": {}, "cookies": {"admina_session": key}}
                )
            )

        # tampered cookie → rejected
        with pytest.raises(PermissionError):
            _run(
                provider.authenticate(
                    {
                        "path": "/api/x",
                        "headers": {},
                        "cookies": {"admina_session": "garbage.tampered"},
                    }
                )
            )

        # raw key via header still works
        user2 = _run(provider.authenticate({"path": "/api/x", "headers": {"X-API-Key": key}}))
        assert user2 and user2.get("user_id")

    def test_is_configured_with_key(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="some-key-abc")
        assert auth.is_configured() is True

    def test_is_configured_without_key(self):
        from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

        auth = APIKeyAuthProvider(api_key="")
        assert auth.is_configured() is False


def test_apikey_provider_keyless_is_fail_closed():
    """A keyless APIKeyAuthProvider must raise PermissionError, not return admin."""
    import asyncio

    import pytest

    from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

    p = APIKeyAuthProvider(api_key="")
    assert p.is_configured() is False
    with pytest.raises(PermissionError):
        asyncio.run(p.authenticate({"path": "/api/x", "headers": {}}))


def test_unconfigured_provider_filter_drops_keyless():
    """The lifespan filter expression drops keyless providers, keeps configured ones."""
    from admina.plugins.builtin.auth.apikey import APIKeyAuthProvider

    keyless = APIKeyAuthProvider(api_key="")
    keyed = APIKeyAuthProvider(api_key="k" * 16)
    providers = [keyless, keyed]

    filtered = [p for p in providers if getattr(p, "is_configured", lambda: True)()]
    assert filtered == [keyed]
    assert keyless not in filtered


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


def test_spacy_regex_resolve_overlaps_no_corruption():
    from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

    # directly exercise the overlap resolver (static) with deliberately overlapping spans
    overlapping = [
        {"type": "EMAIL", "start": 5, "end": 20, "text": "a@b.com.example", "confidence": 0.95},
        {"type": "URL", "start": 12, "end": 28, "text": "example.com/path", "confidence": 0.9},
    ]
    resolved = SpaCyRegexPIIEngine._resolve_overlaps(overlapping)
    spans = sorted((m["start"], m["end"]) for m in resolved)
    for (s1, e1), (s2, e2) in zip(spans, spans[1:]):
        assert e1 <= s2, f"overlap remains: {(s1, e1)} {(s2, e2)}"
    # the union [5,28] must be fully covered (no fragment): the kept span(s) span 5..28
    assert min(s for s, _ in spans) == 5
    assert max(e for _, e in spans) == 28


def test_spacy_regex_redact_no_fragment_on_overlap():
    import asyncio

    from admina.plugins.builtin.pii.spacy_regex import SpaCyRegexPIIEngine

    eng = SpaCyRegexPIIEngine()
    text = "x" * 5 + "a@b.com.example/" + "y" * 5  # positions 5..20-ish
    matches = [
        {"type": "EMAIL", "start": 5, "end": 20, "text": text[5:20], "confidence": 0.95},
        {"type": "URL", "start": 12, "end": 25, "text": text[12:25], "confidence": 0.9},
    ]
    red = asyncio.run(eng.redact(text, matches))
    # no leftover fragment from either span; the redacted region is a single placeholder run
    assert "a@b.com" not in red
    assert text[12:25] not in red


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


# ═══════════════════════════════════════════════════════════════
# 14. MistralAdapter
# ═══════════════════════════════════════════════════════════════


class TestMistralAdapter:
    def test_name_and_supports_model(self):
        pytest.importorskip("mistralai")
        from admina.plugins.builtin.adapters.mistral import MistralAdapter

        a = MistralAdapter(api_key="k", default_model="mistral-small")
        assert a.name == "mistral"
        assert a.supports_model("mistral-small") is True
        assert a.supports_model("codestral-latest") is True
        assert a.supports_model("open-mixtral-8x7b") is True
        assert a.supports_model("ministral-3b") is True
        assert a.supports_model("gpt-4o") is False

    def test_send_shapes_request_and_normalizes_response(self):
        pytest.importorskip("mistralai")
        import asyncio

        from admina.plugins.builtin.adapters.mistral import MistralAdapter

        # Fake response mirroring real mistralai v2 ChatCompletionResponse shape:
        # resp.choices[0].message.content (str)
        # resp.usage.prompt_tokens, resp.usage.completion_tokens, resp.usage.total_tokens
        class _Usage:
            prompt_tokens = 4
            completion_tokens = 6
            total_tokens = 10

        class _Message:
            content = "hello from mistral"

        class _Choice:
            message = _Message()

        class _Resp:
            choices = [_Choice()]
            usage = _Usage()

        class _Chat:
            def complete(self, **kw):
                _Chat.kw = kw
                return _Resp()

        class _Client:
            chat = _Chat()

        a = MistralAdapter(api_key="k", default_model="mistral-small")
        a._client = _Client()
        out = asyncio.run(a.send("hello", context="be brief"))
        assert out["text"] == "hello from mistral"
        assert out["metadata"]["tokens"] == 10
        assert out["metadata"]["model"] == "mistral-small"
        # system message prepended when context is given
        msgs = _Chat.kw["messages"]
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == "be brief"
        assert msgs[-1]["role"] == "user"
        assert msgs[-1]["content"] == "hello"

    def test_requires_model(self):
        pytest.importorskip("mistralai")
        import asyncio

        from admina.plugins.builtin.adapters.mistral import MistralAdapter

        a = MistralAdapter(api_key="k")  # no default_model, no env
        a._client = object()
        with pytest.raises(ValueError, match="model"):
            asyncio.run(a.send("hi"))


# ═══════════════════════════════════════════════════════════════
# 15. BedrockAdapter
# ═══════════════════════════════════════════════════════════════


class TestBedrockAdapter:
    def test_name_and_supports_model(self):
        pytest.importorskip("boto3")
        from admina.plugins.builtin.adapters.bedrock import BedrockAdapter

        a = BedrockAdapter(default_model="anthropic.claude-3-sonnet-20240229-v1:0")
        assert a.name == "bedrock"
        assert a.supports_model("anthropic.claude-3") is True
        assert a.supports_model("meta.llama2-13b") is True
        assert a.supports_model("amazon.titan-text") is True
        assert a.supports_model("us.anthropic.claude-3") is True
        assert a.supports_model("gpt-4o") is False

    def test_send_shapes_request_and_normalizes_response(self):
        pytest.importorskip("boto3")
        import asyncio

        from admina.plugins.builtin.adapters.bedrock import BedrockAdapter

        # Fake response mirroring real Bedrock Converse dict response:
        # resp["output"]["message"]["content"][0]["text"]
        # resp["usage"]["inputTokens"] + resp["usage"]["outputTokens"]
        canned_response = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "hello from bedrock"}],
                }
            },
            "usage": {
                "inputTokens": 7,
                "outputTokens": 5,
                "totalTokens": 12,
            },
            "stopReason": "end_turn",
        }

        class _FakeClient:
            def converse(self, **kw):
                _FakeClient.kw = kw
                return canned_response

        a = BedrockAdapter(default_model="anthropic.claude-3-sonnet-20240229-v1:0")
        a._client = _FakeClient()
        out = asyncio.run(a.send("hello", context="be brief"))
        assert out["text"] == "hello from bedrock"
        assert out["metadata"]["tokens"] == 12
        assert out["metadata"]["model"] == "anthropic.claude-3-sonnet-20240229-v1:0"
        # Verify Converse request structure
        kw = _FakeClient.kw
        assert kw["modelId"] == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert kw["messages"][0]["role"] == "user"
        assert kw["messages"][0]["content"] == [{"text": "hello"}]
        assert kw["system"] == [{"text": "be brief"}]
        assert "maxTokens" in kw["inferenceConfig"]

    def test_requires_model(self):
        pytest.importorskip("boto3")
        import asyncio

        from admina.plugins.builtin.adapters.bedrock import BedrockAdapter

        a = BedrockAdapter()  # no default_model, no env
        a._client = object()
        with pytest.raises(ValueError, match="model"):
            asyncio.run(a.send("hi"))


# ═══════════════════════════════════════════════════════════════
# 16. GeminiAdapter
# ═══════════════════════════════════════════════════════════════


class TestGeminiAdapter:
    def test_name_and_supports_model(self):
        pytest.importorskip("google.genai")
        from admina.plugins.builtin.adapters.gemini import GeminiAdapter

        a = GeminiAdapter(api_key="k", default_model="gemini-1.5-pro")
        assert a.name == "gemini"
        assert a.supports_model("gemini-1.5-pro") is True
        assert a.supports_model("gemini-2.0-flash") is True
        assert a.supports_model("gpt-4o") is False

    def test_send_shapes_request_and_normalizes_response(self):
        pytest.importorskip("google.genai")
        import asyncio

        from admina.plugins.builtin.adapters.gemini import GeminiAdapter

        # Fake response mirroring real google-genai GenerateContentResponse:
        # resp.text (property)
        # resp.usage_metadata.prompt_token_count / .candidates_token_count / .total_token_count
        class _UsageMeta:
            prompt_token_count = 3
            candidates_token_count = 7
            total_token_count = 10

        class _Resp:
            text = "hello from gemini"
            usage_metadata = _UsageMeta()

        class _Models:
            def generate_content(self, **kw):
                _Models.kw = kw
                return _Resp()

        class _Client:
            models = _Models()

        a = GeminiAdapter(api_key="k", default_model="gemini-1.5-pro")
        a._client = _Client()
        out = asyncio.run(a.send("hello", context="be brief"))
        assert out["text"] == "hello from gemini"
        assert out["metadata"]["tokens"] == 10
        assert out["metadata"]["model"] == "gemini-1.5-pro"
        kw = _Models.kw
        assert kw["model"] == "gemini-1.5-pro"
        assert kw["contents"] == "hello"
        assert kw["config"] is not None  # system instruction config present

    def test_requires_model(self):
        pytest.importorskip("google.genai")
        import asyncio

        from admina.plugins.builtin.adapters.gemini import GeminiAdapter

        a = GeminiAdapter(api_key="k")  # no default_model, no env
        a._client = object()
        with pytest.raises(ValueError, match="model"):
            asyncio.run(a.send("hi"))


# ═══════════════════════════════════════════════════════════════
# 17. VLLMAdapter
# ═══════════════════════════════════════════════════════════════


class TestVLLMAdapter:
    def test_name_and_defaults(self):
        pytest.importorskip("openai")
        from admina.plugins.builtin.adapters.vllm import VLLMAdapter

        a = VLLMAdapter()
        assert a.name == "vllm"
        assert "8000" in a._base_url

    def test_supports_any_model(self):
        pytest.importorskip("openai")
        from admina.plugins.builtin.adapters.vllm import VLLMAdapter

        a = VLLMAdapter()
        assert a.supports_model("meta-llama/Llama-3-8B-Instruct") is True
        assert a.supports_model("any/hf-id") is True
        assert a.supports_model("gpt-4o") is True

    def test_vllm_requires_model(self, monkeypatch):
        pytest.importorskip("openai")
        import asyncio

        from admina.plugins.builtin.adapters.vllm import VLLMAdapter

        monkeypatch.delenv("ADMINA_VLLM_MODEL", raising=False)
        monkeypatch.delenv("ADMINA_OPENAI_MODEL", raising=False)
        a = VLLMAdapter()  # no model, no env
        a._client = object()
        with pytest.raises(ValueError, match="model"):
            asyncio.run(a.send("hi"))


# ═══════════════════════════════════════════════════════════════
# 18. Registry — all 7 builtin model adapters
# ═══════════════════════════════════════════════════════════════


def test_all_builtin_adapters_register_by_name():
    from admina.plugins.registry import PluginRegistry

    reg = PluginRegistry()
    reg.discover()
    names = set(reg.list("model_adapter"))
    expected = {"ollama", "openai", "anthropic", "mistral", "bedrock", "gemini", "vllm"}
    missing = expected - names
    assert not missing, f"adapters missing from registry: {missing}"
