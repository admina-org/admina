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

"""Tests for the plugin registry — discovery, registration, and lookup."""

from __future__ import annotations

import textwrap

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
from admina.plugins.registry import PLUGIN_TYPES, PluginRegistry

# ---------------------------------------------------------------------------
# Mock plugin classes (concrete implementations for testing)
# ---------------------------------------------------------------------------


class FakeModelAdapter(BaseModelAdapter):
    async def send(self, prompt, context=None, **kwargs):
        return {"text": "ok", "metadata": {"tokens": 1, "latency_ms": 0.1}}

    def supports_model(self, model_name):
        return model_name == "fake"

    @property
    def name(self):
        return "fake-model"


class FakeDataConnector(BaseDataConnector):
    async def ingest(self, source, **kwargs):
        return {"doc_count": 0, "chunk_count": 0}

    async def query(self, query, **kwargs):
        return []

    @property
    def name(self):
        return "fake-data"


class FakeDomain(BaseGovernanceGuard):
    name = "fake-domain"

    async def inspect_request(self, request):
        return {"action": "ALLOW", "risk_level": "LOW", "details": ""}

    async def inspect_response(self, response):
        return {"action": "ALLOW", "risk_level": "LOW", "details": ""}


class FakeCompliance(BaseComplianceTemplate):
    def get_requirements(self):
        return []

    def evaluate(self, governance_state):
        return {"score": 1.0, "gaps": [], "covered": []}

    @property
    def framework_name(self):
        return "fake-framework"


class FakeTransport(BaseTransportAdapter):
    async def parse_request(self, raw_request):
        pass

    async def format_response(self, gov_response, original):
        pass

    def register_routes(self, app):
        pass

    @property
    def protocol_name(self):
        return "fake-proto"


class FakeForensicStore(BaseForensicStore):
    async def append(self, record):
        return "id-1"

    async def verify_chain(self, last_n=0):
        return {"valid": True, "records": 0, "last_hash": ""}

    @property
    def store_name(self):
        return "fake-store"


class FakeAuth(BaseAuthProvider):
    async def authenticate(self, request):
        return {"user_id": "u", "roles": [], "metadata": {}}

    async def authorize(self, user, action, resource=""):
        return True

    @property
    def provider_name(self):
        return "fake-auth"


class FakePII(BasePIIEngine):
    async def detect(self, text, categories=None):
        return []

    async def redact(self, text, matches):
        return text

    @property
    def supported_languages(self):
        return ["en"]


class FakeAlert(BaseAlertChannel):
    async def send_alert(self, alert):
        return True

    @property
    def channel_name(self):
        return "fake-alert"


# ---------------------------------------------------------------------------
# Tests — PluginRegistry.register() / get() / list()
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_model_adapter(self):
        reg = PluginRegistry()
        reg.register(FakeModelAdapter)
        assert (
            reg.get("model_adapter", "fakeModelAdapter") is not None
            or reg.get("model_adapter", "fakemodeladapter") is not None
        )

    def test_register_all_nine_types(self):
        reg = PluginRegistry()
        classes = [
            FakeModelAdapter,
            FakeDataConnector,
            FakeDomain,
            FakeCompliance,
            FakeTransport,
            FakeForensicStore,
            FakeAuth,
            FakePII,
            FakeAlert,
        ]
        for cls in classes:
            reg.register(cls)

        all_plugins = reg.list_all()
        registered_count = sum(len(v) for v in all_plugins.values())
        assert registered_count == 9

    def test_register_abstract_raises(self):
        reg = PluginRegistry()
        with pytest.raises(TypeError, match="abstract"):
            reg.register(BaseModelAdapter)

    def test_register_non_plugin_raises(self):
        reg = PluginRegistry()

        class NotAPlugin:
            pass

        with pytest.raises(TypeError, match="does not extend"):
            reg.register(NotAPlugin)


class TestGet:
    def test_get_returns_class(self):
        reg = PluginRegistry()
        reg.register(FakeDomain)
        result = reg.get("governance_guard", "fake-domain")
        assert result is FakeDomain

    def test_get_unknown_returns_none(self):
        reg = PluginRegistry()
        assert reg.get("model_adapter", "nonexistent") is None

    def test_get_unknown_type_returns_none(self):
        reg = PluginRegistry()
        assert reg.get("nonexistent_type", "foo") is None


class TestList:
    def test_list_empty(self):
        reg = PluginRegistry()
        assert reg.list("model_adapter") == {}

    def test_list_returns_registered(self):
        reg = PluginRegistry()
        reg.register(FakeModelAdapter)
        reg.register(FakeDataConnector)
        adapters = reg.list("model_adapter")
        assert len(adapters) == 1
        connectors = reg.list("data_connector")
        assert len(connectors) == 1

    def test_list_all_groups_by_type(self):
        reg = PluginRegistry()
        reg.register(FakeModelAdapter)
        reg.register(FakeDomain)
        all_p = reg.list_all()
        assert "model_adapter" in all_p
        assert "governance_guard" in all_p
        assert len(all_p["model_adapter"]) == 1
        assert len(all_p["governance_guard"]) == 1


# ---------------------------------------------------------------------------
# Tests — PluginRegistry.discover() with filesystem
# ---------------------------------------------------------------------------


class TestDiscover:
    def test_discover_empty_directory(self, tmp_path):
        """Discovery on an empty dir registers nothing."""
        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=tmp_path / "builtin",
            user_path=tmp_path / "user",
            extra_modules=[],
        )
        assert count == 0

    def test_discover_builtin_directory(self, tmp_path):
        """Discovery picks up a plugin .py file from the builtin dir."""
        builtin = tmp_path / "builtin"
        builtin.mkdir()

        # Write a plugin module
        (builtin / "my_adapter.py").write_text(
            textwrap.dedent("""\
            from admina.plugins.base import BaseModelAdapter

            class TestBuiltinAdapter(BaseModelAdapter):
                async def send(self, prompt, context=None, **kwargs):
                    return {"text": "hi", "metadata": {"tokens": 1, "latency_ms": 0.0}}

                def supports_model(self, model_name):
                    return True

                @property
                def name(self):
                    return "test-builtin"
        """)
        )

        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=builtin,
            user_path=tmp_path / "no_user",
        )
        assert count == 1
        assert reg.get("model_adapter", "testbuiltinadapter") is not None

    def test_discover_user_directory(self, tmp_path):
        """Discovery picks up plugins from the user dir."""
        user_dir = tmp_path / "user_plugins"
        user_dir.mkdir()

        (user_dir / "my_alert.py").write_text(
            textwrap.dedent("""\
            from admina.plugins.base import BaseAlertChannel

            class UserSlackAlert(BaseAlertChannel):
                async def send_alert(self, alert):
                    return True

                @property
                def channel_name(self):
                    return "slack"
        """)
        )

        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=tmp_path / "no_builtin",
            user_path=user_dir,
        )
        assert count == 1
        assert reg.get("alert_channel", "userslackalert") is not None

    def test_discover_extra_modules(self, tmp_path, monkeypatch):
        """Discovery loads explicit module paths from admina.yaml plugins list."""
        mod_dir = tmp_path / "extra"
        mod_dir.mkdir()

        (mod_dir / "custom_store.py").write_text(
            textwrap.dedent("""\
            from admina.plugins.base import BaseForensicStore

            class S3ForensicStore(BaseForensicStore):
                async def append(self, record):
                    return "s3-id"

                async def verify_chain(self, last_n=0):
                    return {"valid": True, "records": 0, "last_hash": ""}

                @property
                def store_name(self):
                    return "s3"
        """)
        )

        monkeypatch.syspath_prepend(str(mod_dir))

        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=tmp_path / "no_builtin",
            user_path=tmp_path / "no_user",
            extra_modules=["custom_store"],
        )
        assert count == 1
        assert reg.get("forensic_store", "s3forensicstore") is not None

    def test_discover_skips_abstract_classes(self, tmp_path):
        """Discovery does not register abstract classes."""
        builtin = tmp_path / "builtin"
        builtin.mkdir()

        (builtin / "abstract_only.py").write_text(
            textwrap.dedent("""\
            from abc import abstractmethod
            from admina.plugins.base import BaseModelAdapter

            class StillAbstract(BaseModelAdapter):
                @abstractmethod
                def extra_method(self):
                    ...
        """)
        )

        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=builtin,
            user_path=tmp_path / "no_user",
        )
        assert count == 0

    def test_discover_bad_module_does_not_crash(self, tmp_path):
        """A broken module is logged and skipped, not raised."""
        builtin = tmp_path / "builtin"
        builtin.mkdir()

        (builtin / "broken.py").write_text("raise RuntimeError('boom')\n")

        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=builtin,
            user_path=tmp_path / "no_user",
        )
        assert count == 0

    def test_discover_multiple_plugins_one_module(self, tmp_path):
        """A single module can contribute multiple plugin types."""
        builtin = tmp_path / "builtin"
        builtin.mkdir()

        (builtin / "multi.py").write_text(
            textwrap.dedent("""\
            from admina.plugins.base import BaseModelAdapter, BaseAlertChannel

            class MultiAdapter(BaseModelAdapter):
                async def send(self, prompt, context=None, **kwargs):
                    return {"text": "", "metadata": {"tokens": 0, "latency_ms": 0.0}}
                def supports_model(self, model_name):
                    return False
                @property
                def name(self):
                    return "multi"

            class MultiAlert(BaseAlertChannel):
                async def send_alert(self, alert):
                    return True
                @property
                def channel_name(self):
                    return "multi"
        """)
        )

        reg = PluginRegistry()
        count = reg.discover(
            builtin_path=builtin,
            user_path=tmp_path / "no_user",
        )
        assert count == 2


# ---------------------------------------------------------------------------
# Tests — PLUGIN_TYPES constant
# ---------------------------------------------------------------------------


class TestPluginTypes:
    def test_nine_types_defined(self):
        assert len(PLUGIN_TYPES) == 9

    def test_all_keys_present(self):
        expected = {
            "model_adapter",
            "data_connector",
            "governance_guard",
            "compliance_template",
            "transport_adapter",
            "forensic_store",
            "auth_provider",
            "pii_engine",
            "alert_channel",
        }
        assert set(PLUGIN_TYPES.keys()) == expected

    def test_values_are_abc_classes(self):
        import inspect

        for key, cls in PLUGIN_TYPES.items():
            assert inspect.isabstract(cls), f"{key} → {cls} should be abstract"
