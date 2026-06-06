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

"""Admina — Secret Vault

Generates, stores, and retrieves secrets for the Admina platform.
Secrets are encrypted at rest using Fernet symmetric encryption.

Vault layout (per-project, under ``<project>/.admina/``):

    .admina/
        vault.key      — Fernet key (mode 0600, never committed)
        secrets.json   — encrypted secret values
"""

from __future__ import annotations

import json
import os
import re
import secrets
import string
from pathlib import Path

from cryptography.fernet import Fernet

# ── Secret Generation ────────────────────────────────────────


def generate_api_key() -> str:
    """Generate a 64-char hex API key (256-bit entropy)."""
    return secrets.token_hex(32)


def generate_password(length: int = 20) -> str:
    """Generate a random password meeting quality requirements.

    Guarantees at least one uppercase, one lowercase, one digit,
    and one special character.
    """
    if length < 12:
        length = 12

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#%&*+-"

    # Guarantee one of each class
    password_chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    # Fill the rest from the full alphabet
    alphabet = upper + lower + digits + special
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(alphabet))

    # Shuffle to avoid predictable positions
    shuffled = list(password_chars)
    for i in range(len(shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return "".join(shuffled)


# ── Password Validation ──────────────────────────────────────

_MIN_PASSWORD_LENGTH = 12


def validate_password(password: str) -> tuple[bool, list[str]]:
    """Check password quality. Returns (ok, list_of_issues)."""
    issues: list[str] = []

    if len(password) < _MIN_PASSWORD_LENGTH:
        issues.append(f"Minimum {_MIN_PASSWORD_LENGTH} characters (got {len(password)})")
    if not re.search(r"[A-Z]", password):
        issues.append("At least one uppercase letter")
    if not re.search(r"[a-z]", password):
        issues.append("At least one lowercase letter")
    if not re.search(r"\d", password):
        issues.append("At least one digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("At least one special character")

    return (len(issues) == 0, issues)


# ── Secret Vault ─────────────────────────────────────────────

# Keys managed by the vault
VAULT_KEYS = (
    "ADMINA_API_KEY",
    "ADMINA_DASHBOARD_PASSWORD",
    "CLICKHOUSE_PASSWORD",
    "GRAFANA_ADMIN_PASSWORD",
    # Used by the optional Open WebUI service in docker-compose when
    # ai_infra.webui is enabled. Generated unconditionally so the
    # compose file works whether or not the operator picked the
    # ai_infra domain — it's just a random session secret.
    "WEBUI_SECRET_KEY",
)


class SecretVault:
    """Encrypted secret store backed by a local JSON file.

    Parameters
    ----------
    project_dir:
        Root of the Admina project.  The vault lives at
        ``<project_dir>/.admina/secrets.json``.
    """

    def __init__(self, project_dir: str | Path) -> None:
        self._dir = Path(project_dir) / ".admina"
        self._key_path = self._dir / "vault.key"
        self._secrets_path = self._dir / "secrets.json"
        self._fernet: Fernet | None = None

    # ── public API ────────────────────────────────────────

    @property
    def is_initialized(self) -> bool:
        """True if the vault has been bootstrapped at least once."""
        return self._secrets_path.is_file() and self._key_path.is_file()

    def bootstrap(self) -> dict[str, str]:
        """Generate all platform secrets and store them in the vault.

        Returns the generated secrets as a plain dict (for one-time display).
        """
        generated: dict[str, str] = {
            "ADMINA_API_KEY": generate_api_key(),
            "ADMINA_DASHBOARD_PASSWORD": generate_password(),
            "CLICKHOUSE_PASSWORD": generate_password(),
            "GRAFANA_ADMIN_PASSWORD": generate_password(),
            # Independent random secret for the optional Open WebUI
            # session cookie — never share it with the user-facing
            # dashboard password.
            "WEBUI_SECRET_KEY": generate_api_key(),
        }

        # Use the same dashboard password for all web UIs (but NOT
        # the WEBUI session secret, which is internal only).
        shared_password = generated["ADMINA_DASHBOARD_PASSWORD"]
        generated["CLICKHOUSE_PASSWORD"] = shared_password
        generated["GRAFANA_ADMIN_PASSWORD"] = shared_password

        self._ensure_dir()
        self._ensure_key()
        self._save(generated)
        return generated

    def get(self, key: str) -> str | None:
        """Retrieve a single secret by key. Returns None if not found."""
        data = self._load()
        return data.get(key)

    def get_all(self) -> dict[str, str]:
        """Return all secrets as a plain dict."""
        return self._load()

    def set(self, key: str, value: str) -> None:
        """Set or update a single secret."""
        data = self._load()
        data[key] = value
        self._save(data)

    def update_password(self, new_password: str) -> None:
        """Update the shared web UI password across all services."""
        data = self._load()
        data["ADMINA_DASHBOARD_PASSWORD"] = new_password
        data["CLICKHOUSE_PASSWORD"] = new_password
        data["GRAFANA_ADMIN_PASSWORD"] = new_password
        self._save(data)

    def export_env(self) -> dict[str, str]:
        """Return secrets suitable for injection into subprocess env.

        Same as get_all() but filters to known VAULT_KEYS only.
        """
        data = self._load()
        return {k: v for k, v in data.items() if k in VAULT_KEYS}

    def write_dotenv(self, env_path: str | Path) -> None:
        """Write a .env file with the current vault secrets.

        The file is written with mode 0600.
        """
        data = self.export_env()
        lines = [
            "# Auto-generated by admina vault. Do not edit manually.",
            "# Regenerate with: admina password reset",
            "",
        ]
        for key in VAULT_KEYS:
            value = data.get(key, "")
            # Use double quotes — Docker Compose env_file strips them correctly.
            # Single quotes are taken literally by some env_file parsers.
            lines.append(f'{key}="{value}"')
        lines.append("")

        env_path = Path(env_path)
        env_path.write_text("\n".join(lines))
        os.chmod(env_path, 0o600)

    # ── internal ──────────────────────────────────────────

    def _ensure_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)

    def _ensure_key(self) -> None:
        if not self._key_path.is_file():
            key = Fernet.generate_key()
            self._key_path.write_bytes(key)
            os.chmod(self._key_path, 0o600)
        self._fernet = None  # reset cached fernet

    def _get_fernet(self) -> Fernet:
        if self._fernet is None:
            key = self._key_path.read_bytes().strip()
            self._fernet = Fernet(key)
        return self._fernet

    def _save(self, data: dict[str, str]) -> None:
        plaintext = json.dumps(data, indent=2).encode()
        encrypted = self._get_fernet().encrypt(plaintext)
        self._secrets_path.write_bytes(encrypted)
        os.chmod(self._secrets_path, 0o600)

    def _load(self) -> dict[str, str]:
        if not self._secrets_path.is_file():
            return {}
        encrypted = self._secrets_path.read_bytes()
        plaintext = self._get_fernet().decrypt(encrypted)
        return json.loads(plaintext)
