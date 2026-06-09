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

"""Tests for proxy security features.

Covers: identifier validation, ALLOW_UNAUTHENTICATED, IP rate limiting.
These tests do NOT require a running proxy — they test functions in isolation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure proxy/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "proxy"))


# ── _validate_identifier ─────────────────────────────────────


class TestValidateIdentifier:
    """SQL identifier validation for ClickHouse queries."""

    def _validate(self, name: str, label: str = "identifier") -> None:
        from admina.proxy.main import _validate_identifier

        _validate_identifier(name, label)

    def test_valid_simple(self):
        self._validate("admina")

    def test_valid_with_underscore(self):
        self._validate("my_database_1")

    def test_valid_starts_with_underscore(self):
        self._validate("_private")

    def test_valid_uppercase(self):
        self._validate("ADMINA_DB")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="Unsafe"):
            self._validate("")

    def test_rejects_spaces(self):
        with pytest.raises(ValueError, match="Unsafe"):
            self._validate("my database")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="Unsafe"):
            self._validate("admina; DROP TABLE")

    def test_rejects_dash(self):
        with pytest.raises(ValueError, match="Unsafe"):
            self._validate("my-database")

    def test_rejects_starts_with_number(self):
        with pytest.raises(ValueError, match="Unsafe"):
            self._validate("1database")

    def test_rejects_dot(self):
        with pytest.raises(ValueError, match="Unsafe"):
            self._validate("db.table")

    def test_rejects_quotes(self):
        with pytest.raises(ValueError, match="Unsafe"):
            self._validate("db'--")

    def test_label_in_error(self):
        with pytest.raises(ValueError, match="CLICKHOUSE_DB"):
            self._validate("bad name", "CLICKHOUSE_DB")


# ── ALLOW_UNAUTHENTICATED ────────────────────────────────────


class TestAllowUnauthenticated:
    """Settings.ALLOW_UNAUTHENTICATED defaults to False."""

    def test_default_is_false(self):
        from admina.proxy.config import Settings

        s = Settings(
            ADMINA_API_KEY="",
            _env_file=None,
        )
        assert s.ALLOW_UNAUTHENTICATED is False

    def test_can_be_enabled(self, monkeypatch):
        monkeypatch.setenv("ALLOW_UNAUTHENTICATED", "true")
        from admina.proxy.config import Settings

        s = Settings(
            ADMINA_API_KEY="",
            _env_file=None,
        )
        assert s.ALLOW_UNAUTHENTICATED is True


# ── IP Rate Limiting Config ──────────────────────────────────


class TestIPRateLimitConfig:
    """IP rate limit multiplier setting."""

    def test_default_multiplier(self):
        from admina.proxy.config import Settings

        s = Settings(
            _env_file=None,
        )
        assert s.RATE_LIMIT_IP_MULTIPLIER == 5

    def test_ip_limit_calculation(self):
        from admina.proxy.config import Settings

        s = Settings(
            RATE_LIMIT_MAX_REQUESTS=100,
            RATE_LIMIT_IP_MULTIPLIER=5,
            _env_file=None,
        )
        assert s.RATE_LIMIT_MAX_REQUESTS * s.RATE_LIMIT_IP_MULTIPLIER == 500

    def test_custom_multiplier(self, monkeypatch):
        monkeypatch.setenv("RATE_LIMIT_IP_MULTIPLIER", "10")
        from admina.proxy.config import Settings

        s = Settings(
            _env_file=None,
        )
        assert s.RATE_LIMIT_IP_MULTIPLIER == 10


# ── MAX_REQUEST_TOKENS Config ────────────────────────────────


class TestMaxRequestTokens:
    """MAX_REQUEST_TOKENS setting."""

    def test_default(self):
        from admina.proxy.config import Settings

        s = Settings(
            _env_file=None,
        )
        assert s.MAX_REQUEST_TOKENS == 100000


# ── CORS Wildcard Validation ─────────────────────────────────


class TestCORSWildcardValidation:
    """CORS_ORIGINS wildcard warning."""

    def test_wildcard_warns(self):
        import warnings

        from admina.proxy.config import Settings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings(
                CORS_ORIGINS="*",
                _env_file=None,
            )
            cors_warnings = [x for x in w if "CORS_ORIGINS" in str(x.message)]
            assert len(cors_warnings) >= 1
            assert "any domain" in str(cors_warnings[0].message)

    def test_specific_origins_no_warning(self):
        import warnings

        from admina.proxy.config import Settings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings(
                CORS_ORIGINS="http://localhost:3000,http://localhost:8080",
                _env_file=None,
            )
            cors_warnings = [x for x in w if "CORS_ORIGINS" in str(x.message)]
            assert len(cors_warnings) == 0

    def test_wildcard_among_others_warns(self):
        import warnings

        from admina.proxy.config import Settings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings(
                CORS_ORIGINS="http://localhost:3000,*",
                _env_file=None,
            )
            cors_warnings = [x for x in w if "CORS_ORIGINS" in str(x.message)]
            assert len(cors_warnings) >= 1


class TestDashboardSessionToken:
    """The dashboard session cookie carries a signed, expiring token — never
    the raw API key (CodeQL py/clear-text-storage). Verify the token logic."""

    def _patch_key(self, monkeypatch, key="test-key-abcdef123456"):
        from admina.proxy import main

        monkeypatch.setattr(main.settings, "ADMINA_API_KEY", key)
        return main

    def test_valid_token_verifies(self, monkeypatch):
        main = self._patch_key(monkeypatch)
        assert main._verify_dashboard_token(main._issue_dashboard_token()) is True

    def test_token_does_not_contain_api_key(self, monkeypatch):
        import base64

        main = self._patch_key(monkeypatch)
        raw = base64.urlsafe_b64decode(main._issue_dashboard_token()).decode("utf-8")
        assert "test-key-abcdef123456" not in raw

    def test_tampered_token_rejected(self, monkeypatch):
        main = self._patch_key(monkeypatch)
        tok = main._issue_dashboard_token()
        assert (
            main._verify_dashboard_token(tok[:-2] + ("aa" if not tok.endswith("aa") else "bb"))
            is False
        )

    def test_expired_token_rejected(self, monkeypatch):
        import time

        main = self._patch_key(monkeypatch)
        old = main._issue_dashboard_token(now=int(time.time()) - 10 * 86400)
        assert main._verify_dashboard_token(old) is False

    def test_empty_and_garbage_rejected(self, monkeypatch):
        main = self._patch_key(monkeypatch)
        assert main._verify_dashboard_token("") is False
        assert main._verify_dashboard_token("garbage") is False
        assert main._verify_dashboard_token("notbase64.sig") is False

    def test_token_from_other_key_rejected(self, monkeypatch):
        # A token signed with a different key must not validate.
        main = self._patch_key(monkeypatch, key="key-one-abcdef123456")
        tok = main._issue_dashboard_token()
        monkeypatch.setattr(main.settings, "ADMINA_API_KEY", "key-two-abcdef123456")
        assert main._verify_dashboard_token(tok) is False
