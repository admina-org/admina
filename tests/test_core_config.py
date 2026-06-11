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

"""Admina — Tests for core/config.py.

Validates YAML loading, .env fallback, and config structure.
"""

from __future__ import annotations

import textwrap

from admina.core.config import (
    AdminaConfig,
    _build_from_env,
    _build_from_yaml,
    load_config,
)


class TestAdminaConfigDefaults:
    """Default config values."""

    def test_default_config(self):
        cfg = AdminaConfig()
        assert cfg.schema_version == 1
        assert cfg.data_sovereignty.enabled is True
        assert cfg.ai_infra.enabled is False
        assert cfg.agent_security.enabled is True
        assert cfg.compliance.enabled is True
        assert cfg.dashboard.enabled is True
        assert cfg.dashboard.port == 3000

    def test_agent_security_defaults(self):
        cfg = AdminaConfig()
        assert cfg.agent_security.proxy.port == 8080
        assert cfg.agent_security.proxy.upstream == "http://localhost:9000"
        assert cfg.agent_security.firewall.enabled is True
        assert cfg.agent_security.loop_breaker.window_size == 10
        assert cfg.agent_security.loop_breaker.similarity_threshold == 0.85

    def test_compliance_defaults(self):
        cfg = AdminaConfig()
        assert cfg.compliance.forensic.storage == "filesystem"
        assert cfg.compliance.forensic.bucket == "forensic-blackbox"
        assert cfg.compliance.eu_ai_act_enabled is True
        assert cfg.compliance.otel.endpoint == "http://localhost:4317"

    def test_pii_defaults(self):
        cfg = AdminaConfig()
        assert cfg.data_sovereignty.pii.enabled is True
        assert "email" in cfg.data_sovereignty.pii.categories
        assert cfg.data_sovereignty.pii.ner_model == "en_core_web_sm"


class TestBuildFromYAML:
    """YAML config parsing."""

    def test_minimal_yaml(self):
        data = {"schema_version": 1}
        cfg = _build_from_yaml(data)
        assert cfg.schema_version == 1
        assert cfg.agent_security.enabled is True

    def test_full_yaml(self):
        data = {
            "schema_version": 1,
            "domains": {
                "data_sovereignty": {
                    "enabled": True,
                    "pii": {
                        "enabled": True,
                        "categories": ["email", "phone"],
                        "ner_model": "custom_model",
                    },
                },
                "ai_infra": {
                    "enabled": True,
                    "llm": {"backend": "openai", "model": "gpt-4"},
                },
                "agent_security": {
                    "enabled": True,
                    "proxy": {"port": 9090, "upstream": "http://custom:8000"},
                    "firewall": {"enabled": False, "heuristic_threshold": 0.9},
                    "loop_breaker": {"window_size": 20, "similarity_threshold": 0.9},
                },
                "compliance": {
                    "enabled": False,
                    "forensic": {"storage": "filesystem", "bucket": "my-bucket"},
                },
            },
            "dashboard": {"enabled": False, "port": 4000},
            "alert_channels": [
                {"type": "log"},
                {"type": "webhook", "url": "https://hooks.example.com", "events": ["HIGH"]},
            ],
        }
        cfg = _build_from_yaml(data)
        assert cfg.data_sovereignty.pii.categories == ["email", "phone"]
        assert cfg.data_sovereignty.pii.ner_model == "custom_model"
        assert cfg.ai_infra.enabled is True
        assert cfg.ai_infra.llm.backend == "openai"
        assert cfg.agent_security.proxy.port == 9090
        assert cfg.agent_security.firewall.enabled is False
        assert cfg.agent_security.loop_breaker.window_size == 20
        assert cfg.compliance.enabled is False
        assert cfg.compliance.forensic.storage == "filesystem"
        assert cfg.dashboard.enabled is False
        assert cfg.dashboard.port == 4000
        assert len(cfg.alert_channels) == 2
        assert cfg.alert_channels[1].url == "https://hooks.example.com"

    def test_empty_yaml(self):
        cfg = _build_from_yaml({})
        assert cfg.schema_version == 1
        assert cfg.agent_security.enabled is True

    def test_plugins_and_plugin_config_parsed(self):
        data = {
            "plugins": ["mypkg.plugins"],
            "plugin_config": {"my-guard": {"threshold": 0.8}},
        }
        cfg = _build_from_yaml(data)
        assert cfg.plugins == ["mypkg.plugins"]
        assert cfg.plugin_config == {"my-guard": {"threshold": 0.8}}

    def test_schema_version_parsed(self):
        assert _build_from_yaml({"schema_version": 1}).schema_version == 1
        assert _build_from_yaml({"schema_version": 3}).schema_version == 3
        # legacy/absent keys fall back to 1
        assert _build_from_yaml({}).schema_version == 1
        assert _build_from_yaml({"version": "2.0"}).schema_version == 1


class TestBuildFromEnv:
    """Environment variable fallback."""

    def test_defaults_without_env(self):
        cfg = _build_from_env()
        assert cfg.agent_security.proxy.upstream == "http://localhost:9000"
        assert cfg.agent_security.loop_breaker.window_size == 10

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("UPSTREAM_MCP_URL", "http://custom:5000")
        monkeypatch.setenv("LOOP_WINDOW_SIZE", "20")
        monkeypatch.setenv("LOOP_SIMILARITY_THRESHOLD", "0.9")
        monkeypatch.setenv("ADMINA_API_KEY", "test-key-1234567890")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        cfg = _build_from_env()
        assert cfg.agent_security.proxy.upstream == "http://custom:5000"
        assert cfg.agent_security.loop_breaker.window_size == 20
        assert cfg.agent_security.loop_breaker.similarity_threshold == 0.9
        assert cfg.admina_api_key == "test-key-1234567890"
        assert cfg.log_level == "DEBUG"

    def test_invalid_int_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("LOOP_WINDOW_SIZE", "not_a_number")
        cfg = _build_from_env()
        assert cfg.agent_security.loop_breaker.window_size == 10


class TestLoadConfig:
    """load_config() integration."""

    def test_loads_yaml_file(self, tmp_path):
        yaml_file = tmp_path / "admina.yaml"
        yaml_file.write_text(
            textwrap.dedent("""\
            schema_version: 1
            domains:
              agent_security:
                proxy:
                  port: 9999
        """)
        )
        cfg = load_config(yaml_path=str(yaml_file))
        assert cfg.agent_security.proxy.port == 9999

    def test_falls_back_to_env(self, tmp_path):
        # No yaml file exists in search path
        cfg = load_config(search_paths=[str(tmp_path)])
        assert isinstance(cfg, AdminaConfig)
        assert cfg.schema_version == 1

    def test_search_paths(self, tmp_path):
        yaml_file = tmp_path / "admina.yaml"
        yaml_file.write_text("schema_version: 3\n")
        cfg = load_config(search_paths=[str(tmp_path)])
        assert cfg.schema_version == 3
