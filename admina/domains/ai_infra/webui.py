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

"""Admina — Web UI module.

Open WebUI container configuration, preconfigured Ollama connection,
and optional multi-user authentication (built-in, OIDC, LDAP).

This module produces Docker Compose configuration fragments and
structured settings — the actual container lifecycle is managed by
the CLI ``admina dev`` command.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("admina.ai_infra.webui")


# ── Auth configuration ───────────────────────────────────────


class AuthMode(str, Enum):
    """Supported authentication modes for Open WebUI."""

    BUILTIN = "builtin"
    OIDC = "oidc"
    LDAP = "ldap"
    NONE = "none"


@dataclass
class OIDCConfig:
    """OpenID Connect authentication settings.

    Args:
        provider_url: OIDC discovery URL (e.g. ``https://accounts.google.com``).
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret.
        scopes: Requested scopes.
    """

    provider_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: str = "openid email profile"

    def to_env(self) -> dict[str, str]:
        """Return environment variables for Open WebUI OIDC."""
        if not self.provider_url or not self.client_id:
            return {}
        return {
            "OAUTH_PROVIDER_URL": self.provider_url,
            "OAUTH_CLIENT_ID": self.client_id,
            "OAUTH_CLIENT_SECRET": self.client_secret,
            "OAUTH_SCOPES": self.scopes,
            "ENABLE_OAUTH_SIGNUP": "true",
        }


@dataclass
class LDAPConfig:
    """LDAP authentication settings.

    Args:
        host: LDAP server host.
        port: LDAP server port.
        base_dn: Base distinguished name for search.
        bind_dn: Bind DN for LDAP lookups.
        bind_password: Bind password.
    """

    host: str = ""
    port: int = 389
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    use_tls: bool = False

    def to_env(self) -> dict[str, str]:
        """Return environment variables for Open WebUI LDAP."""
        if not self.host or not self.base_dn:
            return {}
        return {
            "LDAP_HOST": self.host,
            "LDAP_PORT": str(self.port),
            "LDAP_BASE_DN": self.base_dn,
            "LDAP_BIND_DN": self.bind_dn,
            "LDAP_BIND_PASSWORD": self.bind_password,
            "LDAP_USE_TLS": str(self.use_tls).lower(),
        }


@dataclass
class AuthConfig:
    """Aggregated authentication configuration.

    Args:
        mode: Authentication mode.
        oidc: OIDC settings (used when mode is ``OIDC``).
        ldap: LDAP settings (used when mode is ``LDAP``).
        signup_enabled: Allow new user registration.
    """

    mode: AuthMode = AuthMode.BUILTIN
    oidc: OIDCConfig = field(default_factory=OIDCConfig)
    ldap: LDAPConfig = field(default_factory=LDAPConfig)
    signup_enabled: bool = True

    def to_env(self) -> dict[str, str]:
        """Return environment variables for the configured auth mode."""
        env: dict[str, str] = {
            "ENABLE_SIGNUP": str(self.signup_enabled).lower(),
        }
        if self.mode == AuthMode.OIDC:
            env.update(self.oidc.to_env())
        elif self.mode == AuthMode.LDAP:
            env.update(self.ldap.to_env())
        elif self.mode == AuthMode.NONE:
            env["WEBUI_AUTH"] = "false"
        return env


# ── Open WebUI container config ──────────────────────────────


@dataclass
class OpenWebUIConfig:
    """Container configuration for Open WebUI.

    Args:
        image: Docker image for Open WebUI.
        container_name: Docker container name.
        port: Host port mapping.
        ollama_base_url: Internal Ollama API URL.
        auth: Authentication configuration.
        extra_env: Additional environment variables.
    """

    image: str = "ghcr.io/open-webui/open-webui:main"
    container_name: str = "admina-webui"
    port: int = 3080
    ollama_base_url: str = "http://ollama:11434"
    auth: AuthConfig = field(default_factory=AuthConfig)
    extra_env: dict[str, str] = field(default_factory=dict)

    def to_compose_dict(self) -> dict[str, Any]:
        """Return a docker-compose service fragment.

        Returns:
            A dict suitable for inclusion in a docker-compose YAML.
        """
        env = {
            "OLLAMA_BASE_URL": self.ollama_base_url,
            "WEBUI_SECRET_KEY": "${WEBUI_SECRET_KEY:?WEBUI_SECRET_KEY must be set}",
            "ENABLE_RAG_WEB_SEARCH": "false",
        }
        env.update(self.auth.to_env())
        env.update(self.extra_env)

        svc: dict[str, Any] = {
            "image": self.image,
            "container_name": self.container_name,
            "ports": [f"{self.port}:8080"],
            "volumes": ["webui-data:/app/backend/data"],
            "environment": [f"{k}={v}" for k, v in sorted(env.items())],
            "depends_on": {
                "ollama": {"condition": "service_healthy"},
            },
            "healthcheck": {
                "test": ["CMD", "curl", "-f", "http://localhost:8080/"],
                "interval": "30s",
                "timeout": "5s",
                "retries": 3,
            },
            "networks": ["admina"],
            "restart": "unless-stopped",
        }
        return svc


# ── WebUI Engine ─────────────────────────────────────────────


@dataclass
class WebUIEngine:
    """Manages Open WebUI configuration and Docker Compose generation."""

    port: int = 3080
    ollama_base_url: str = "http://ollama:11434"
    auth: AuthConfig = field(default_factory=AuthConfig)

    # ── Factory ──────────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        *,
        port: int = 3080,
        ollama_base_url: str = "http://ollama:11434",
        auth_mode: str = "builtin",
        signup_enabled: bool = True,
        oidc_provider_url: str = "",
        oidc_client_id: str = "",
        oidc_client_secret: str = "",
        ldap_host: str = "",
        ldap_port: int = 389,
        ldap_base_dn: str = "",
        ldap_bind_dn: str = "",
        ldap_bind_password: str = "",
        ldap_use_tls: bool = False,
    ) -> WebUIEngine:
        """Create an engine from admina.yaml values.

        Args:
            port: Host port for the Web UI.
            ollama_base_url: Ollama API URL.
            auth_mode: ``"builtin"``, ``"oidc"``, ``"ldap"``, or ``"none"``.
            signup_enabled: Allow new user registration.
            oidc_provider_url: OIDC discovery URL.
            oidc_client_id: OIDC client ID.
            oidc_client_secret: OIDC client secret.
            ldap_host: LDAP server host.
            ldap_port: LDAP server port.
            ldap_base_dn: LDAP base DN.
            ldap_bind_dn: LDAP bind DN.
            ldap_bind_password: LDAP bind password.
            ldap_use_tls: Use TLS for LDAP.
        """
        auth = AuthConfig(
            mode=AuthMode(auth_mode),
            signup_enabled=signup_enabled,
            oidc=OIDCConfig(
                provider_url=oidc_provider_url,
                client_id=oidc_client_id,
                client_secret=oidc_client_secret,
            ),
            ldap=LDAPConfig(
                host=ldap_host,
                port=ldap_port,
                base_dn=ldap_base_dn,
                bind_dn=ldap_bind_dn,
                bind_password=ldap_bind_password,
                use_tls=ldap_use_tls,
            ),
        )
        return cls(port=port, ollama_base_url=ollama_base_url, auth=auth)

    # ── Compose generation ───────────────────────────────────

    def compose_service(
        self,
        project_name: str = "admina",
    ) -> dict[str, Any]:
        """Return the docker-compose service dict for Open WebUI.

        Args:
            project_name: Used for container naming.
        """
        cfg = OpenWebUIConfig(
            container_name=f"{project_name}-webui",
            port=self.port,
            ollama_base_url=self.ollama_base_url,
            auth=self.auth,
        )
        return cfg.to_compose_dict()

    # ── Status ───────────────────────────────────────────────

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of the Web UI config."""
        return {
            "port": self.port,
            "ollama_base_url": self.ollama_base_url,
            "auth_mode": self.auth.mode.value,
            "signup_enabled": self.auth.signup_enabled,
        }
