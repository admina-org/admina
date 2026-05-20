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

"""Tests for ``domains.ai_infra.webui``."""

from __future__ import annotations

from admina.domains.ai_infra.webui import (
    AuthConfig,
    AuthMode,
    LDAPConfig,
    OIDCConfig,
    OpenWebUIConfig,
    WebUIEngine,
)

# ── AuthMode enum ────────────────────────────────────────────


class TestAuthMode:
    """Tests for AuthMode enum values."""

    def test_values(self) -> None:
        assert AuthMode.BUILTIN.value == "builtin"
        assert AuthMode.OIDC.value == "oidc"
        assert AuthMode.LDAP.value == "ldap"
        assert AuthMode.NONE.value == "none"


# ── OIDCConfig ───────────────────────────────────────────────


class TestOIDCConfig:
    """Tests for OIDC configuration."""

    def test_to_env_with_values(self) -> None:
        cfg = OIDCConfig(
            provider_url="https://accounts.google.com",
            client_id="my-id",
            client_secret="my-secret",
        )
        env = cfg.to_env()
        assert env["OAUTH_PROVIDER_URL"] == "https://accounts.google.com"
        assert env["OAUTH_CLIENT_ID"] == "my-id"
        assert env["OAUTH_CLIENT_SECRET"] == "my-secret"
        assert env["ENABLE_OAUTH_SIGNUP"] == "true"

    def test_to_env_empty_returns_empty(self) -> None:
        """Returns empty dict when provider_url or client_id missing."""
        cfg = OIDCConfig()
        assert cfg.to_env() == {}

    def test_to_env_missing_client_id(self) -> None:
        cfg = OIDCConfig(provider_url="https://example.com")
        assert cfg.to_env() == {}

    def test_custom_scopes(self) -> None:
        cfg = OIDCConfig(
            provider_url="https://example.com",
            client_id="id",
            scopes="openid email",
        )
        env = cfg.to_env()
        assert env["OAUTH_SCOPES"] == "openid email"


# ── LDAPConfig ───────────────────────────────────────────────


class TestLDAPConfig:
    """Tests for LDAP configuration."""

    def test_to_env_with_values(self) -> None:
        cfg = LDAPConfig(
            host="ldap.example.com",
            port=636,
            base_dn="dc=example,dc=com",
            bind_dn="cn=admin,dc=example,dc=com",
            bind_password="secret",
            use_tls=True,
        )
        env = cfg.to_env()
        assert env["LDAP_HOST"] == "ldap.example.com"
        assert env["LDAP_PORT"] == "636"
        assert env["LDAP_BASE_DN"] == "dc=example,dc=com"
        assert env["LDAP_USE_TLS"] == "true"

    def test_to_env_empty_returns_empty(self) -> None:
        cfg = LDAPConfig()
        assert cfg.to_env() == {}

    def test_to_env_missing_base_dn(self) -> None:
        cfg = LDAPConfig(host="ldap.example.com")
        assert cfg.to_env() == {}


# ── AuthConfig ───────────────────────────────────────────────


class TestAuthConfig:
    """Tests for aggregated auth configuration."""

    def test_builtin_mode(self) -> None:
        auth = AuthConfig(mode=AuthMode.BUILTIN, signup_enabled=True)
        env = auth.to_env()
        assert env["ENABLE_SIGNUP"] == "true"
        assert "OAUTH_PROVIDER_URL" not in env
        assert "LDAP_HOST" not in env

    def test_oidc_mode(self) -> None:
        auth = AuthConfig(
            mode=AuthMode.OIDC,
            oidc=OIDCConfig(
                provider_url="https://example.com",
                client_id="id",
                client_secret="secret",
            ),
        )
        env = auth.to_env()
        assert env["OAUTH_PROVIDER_URL"] == "https://example.com"
        assert env["OAUTH_CLIENT_ID"] == "id"

    def test_ldap_mode(self) -> None:
        auth = AuthConfig(
            mode=AuthMode.LDAP,
            ldap=LDAPConfig(
                host="ldap.example.com",
                base_dn="dc=example,dc=com",
            ),
        )
        env = auth.to_env()
        assert env["LDAP_HOST"] == "ldap.example.com"

    def test_none_mode(self) -> None:
        auth = AuthConfig(mode=AuthMode.NONE)
        env = auth.to_env()
        assert env["WEBUI_AUTH"] == "false"

    def test_signup_disabled(self) -> None:
        auth = AuthConfig(signup_enabled=False)
        env = auth.to_env()
        assert env["ENABLE_SIGNUP"] == "false"


# ── OpenWebUIConfig ──────────────────────────────────────────


class TestOpenWebUIConfig:
    """Tests for Open WebUI compose generation."""

    def test_compose_dict_structure(self) -> None:
        cfg = OpenWebUIConfig()
        svc = cfg.to_compose_dict()
        assert svc["image"] == "ghcr.io/open-webui/open-webui:main"
        assert "3080:8080" in svc["ports"]
        assert "webui-data:/app/backend/data" in svc["volumes"]
        assert svc["healthcheck"]["test"][0] == "CMD"
        assert "admina" in svc["networks"]

    def test_depends_on_ollama(self) -> None:
        cfg = OpenWebUIConfig()
        svc = cfg.to_compose_dict()
        assert "ollama" in svc["depends_on"]
        assert svc["depends_on"]["ollama"]["condition"] == "service_healthy"

    def test_custom_port(self) -> None:
        cfg = OpenWebUIConfig(port=9090)
        svc = cfg.to_compose_dict()
        assert "9090:8080" in svc["ports"]

    def test_custom_container_name(self) -> None:
        cfg = OpenWebUIConfig(container_name="myapp-webui")
        svc = cfg.to_compose_dict()
        assert svc["container_name"] == "myapp-webui"

    def test_ollama_url_in_env(self) -> None:
        cfg = OpenWebUIConfig(ollama_base_url="http://my-ollama:11434")
        svc = cfg.to_compose_dict()
        env_list = svc["environment"]
        assert "OLLAMA_BASE_URL=http://my-ollama:11434" in env_list

    def test_auth_env_included(self) -> None:
        auth = AuthConfig(
            mode=AuthMode.OIDC,
            oidc=OIDCConfig(
                provider_url="https://example.com",
                client_id="id",
                client_secret="secret",
            ),
        )
        cfg = OpenWebUIConfig(auth=auth)
        svc = cfg.to_compose_dict()
        env_list = svc["environment"]
        assert any("OAUTH_PROVIDER_URL" in e for e in env_list)

    def test_extra_env(self) -> None:
        cfg = OpenWebUIConfig(extra_env={"CUSTOM_VAR": "custom_value"})
        svc = cfg.to_compose_dict()
        assert "CUSTOM_VAR=custom_value" in svc["environment"]


# ── WebUIEngine ──────────────────────────────────────────────


class TestWebUIEngine:
    """Tests for WebUIEngine orchestrator."""

    def test_from_config_defaults(self) -> None:
        engine = WebUIEngine.from_config()
        assert engine.port == 3080
        assert engine.ollama_base_url == "http://ollama:11434"
        assert engine.auth.mode == AuthMode.BUILTIN

    def test_from_config_oidc(self) -> None:
        engine = WebUIEngine.from_config(
            auth_mode="oidc",
            oidc_provider_url="https://example.com",
            oidc_client_id="my-id",
            oidc_client_secret="my-secret",
        )
        assert engine.auth.mode == AuthMode.OIDC
        assert engine.auth.oidc.provider_url == "https://example.com"

    def test_from_config_ldap(self) -> None:
        engine = WebUIEngine.from_config(
            auth_mode="ldap",
            ldap_host="ldap.example.com",
            ldap_base_dn="dc=example,dc=com",
            ldap_use_tls=True,
        )
        assert engine.auth.mode == AuthMode.LDAP
        assert engine.auth.ldap.host == "ldap.example.com"
        assert engine.auth.ldap.use_tls is True

    def test_from_config_none_auth(self) -> None:
        engine = WebUIEngine.from_config(auth_mode="none")
        assert engine.auth.mode == AuthMode.NONE

    def test_from_config_custom_port(self) -> None:
        engine = WebUIEngine.from_config(port=9090)
        assert engine.port == 9090

    def test_compose_service(self) -> None:
        engine = WebUIEngine.from_config()
        svc = engine.compose_service(project_name="myapp")
        assert svc["container_name"] == "myapp-webui"
        assert "3080:8080" in svc["ports"]

    def test_compose_service_custom_port(self) -> None:
        engine = WebUIEngine.from_config(port=4000)
        svc = engine.compose_service()
        assert "4000:8080" in svc["ports"]

    def test_summary(self) -> None:
        engine = WebUIEngine.from_config()
        s = engine.summary()
        assert s["port"] == 3080
        assert s["auth_mode"] == "builtin"
        assert s["signup_enabled"] is True
        assert s["ollama_base_url"] == "http://ollama:11434"

    def test_summary_oidc(self) -> None:
        engine = WebUIEngine.from_config(auth_mode="oidc")
        s = engine.summary()
        assert s["auth_mode"] == "oidc"

    def test_signup_disabled(self) -> None:
        engine = WebUIEngine.from_config(signup_enabled=False)
        assert engine.auth.signup_enabled is False
        svc = engine.compose_service()
        assert any("ENABLE_SIGNUP=false" in e for e in svc["environment"])
