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

"""Settings reads the governance mode from the canonical ADMINA_ env var.

Exercises the real ``Settings`` class (not a SimpleNamespace double) with a
patched environment: ``Settings`` declares no ``env_prefix``, so without an
explicit ``validation_alias`` the documented ``ADMINA_GOVERNANCE_MODE`` name
was silently ignored (``extra="ignore"``).
"""

from __future__ import annotations

import pytest


class TestGovernanceModeConfig:
    def test_default_is_enforce(self):
        from admina.proxy.config import Settings

        s = Settings(_env_file=None)
        assert s.GOVERNANCE_MODE == "enforce"

    def test_reads_canonical_env_var(self, monkeypatch):
        monkeypatch.setenv("ADMINA_GOVERNANCE_MODE", "OBSERVE")
        from admina.proxy.config import Settings

        s = Settings(_env_file=None)
        assert s.GOVERNANCE_MODE == "observe"

    def test_dry_run_underscore_normalized(self, monkeypatch):
        monkeypatch.setenv("ADMINA_GOVERNANCE_MODE", "dry_run")
        from admina.proxy.config import Settings

        s = Settings(_env_file=None)
        assert s.GOVERNANCE_MODE == "dry-run"

    def test_invalid_value_rejected(self, monkeypatch):
        from pydantic import ValidationError

        from admina.proxy.config import Settings

        monkeypatch.setenv("ADMINA_GOVERNANCE_MODE", "maybe")
        with pytest.raises(ValidationError):
            Settings(_env_file=None)
