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

"""Proxy-side tests for the configurable guard fail mode (B3)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


class TestGuardFailModeConfig:
    def test_default_is_open(self):
        from admina.proxy.config import Settings

        s = Settings(_env_file=None)
        assert s.GUARD_FAIL_MODE == "open"

    def test_reads_canonical_env_var(self, monkeypatch):
        monkeypatch.setenv("ADMINA_GUARD_FAIL_MODE", "CLOSED")
        from admina.proxy.config import Settings

        s = Settings(_env_file=None)
        assert s.GUARD_FAIL_MODE == "closed"

    def test_invalid_value_rejected(self, monkeypatch):
        from pydantic import ValidationError

        from admina.proxy.config import Settings

        monkeypatch.setenv("ADMINA_GUARD_FAIL_MODE", "sometimes")
        with pytest.raises(ValidationError):
            Settings(_env_file=None)
