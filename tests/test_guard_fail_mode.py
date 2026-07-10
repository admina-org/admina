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

"""Tests for the configurable guard fail mode (B3)."""

from __future__ import annotations

import pytest

from admina.domains.governance import normalize_guard_fail_mode


class TestNormalizeGuardFailMode:
    def test_default_none_is_open(self):
        assert normalize_guard_fail_mode(None) == "open"

    def test_open_passthrough(self):
        assert normalize_guard_fail_mode("open") == "open"

    def test_closed_passthrough(self):
        assert normalize_guard_fail_mode("closed") == "closed"

    def test_case_and_space_insensitive(self):
        assert normalize_guard_fail_mode("  CLOSED ") == "closed"

    def test_empty_string_is_open(self):
        assert normalize_guard_fail_mode("") == "open"

    def test_invalid_raises_value_error(self):
        with pytest.raises(ValueError):
            normalize_guard_fail_mode("maybe")
