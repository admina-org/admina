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
"""Exception text must not reach API responses (CodeQL py/stack-trace-exposure).

Backend failures and guard crashes are logged server-side and recorded in the
forensic log with full detail; the HTTP responses carry a generic reason. The
raw text can embed hosts, ports and credentials from a connection URL.
"""

from __future__ import annotations

from admina.proxy.api.integration import _scrub_check_errors

# A secret-bearing message of the kind a real backend/guard failure produces.
_LEAKY = "Connection refused: redis://admin:s3cr3t@internal-cache.corp:6379/0"


class TestValidateResponseScrubsGuardErrors:
    """`/api/v1/validate` must not echo guard exception text to the caller."""

    def test_guard_error_text_is_replaced(self):
        scrubbed = _scrub_check_errors({"guard_boom": {"action": "ERROR", "error": _LEAKY}})
        assert scrubbed["guard_boom"]["error"] == "Guard error"
        assert "s3cr3t" not in str(scrubbed)
        assert "internal-cache.corp" not in str(scrubbed)

    def test_which_guard_failed_is_still_reported(self):
        """Scrubbing keeps the diagnostic signal: name + ERROR action."""
        scrubbed = _scrub_check_errors({"guard_boom": {"action": "ERROR", "error": _LEAKY}})
        assert "guard_boom" in scrubbed
        assert scrubbed["guard_boom"]["action"] == "ERROR"

    def test_non_error_checks_pass_through_untouched(self):
        checks = {
            "injection_firewall": {"is_injection": False, "risk_level": "none"},
            "pii_redaction": {"count": 2},
        }
        assert _scrub_check_errors(checks) == checks

    def test_does_not_mutate_the_caller_dict(self):
        """The forensic record shares this dict — it must keep the full text."""
        original = {"guard_boom": {"action": "ERROR", "error": _LEAKY}}
        _scrub_check_errors(original)
        assert original["guard_boom"]["error"] == _LEAKY


class TestDashboardHealthScrubsBackendErrors:
    """The dashboard services endpoint reports failure without the exception."""

    def test_source_returns_generic_reason_not_exception_text(self):
        """Redis/ClickHouse handlers must not put `str(exc)` in the payload."""
        import inspect

        from admina.proxy.api import dashboard

        source = inspect.getsource(dashboard)
        # The health handlers build their payload with a fixed string; the
        # exception itself goes to logger.warning instead.
        assert '"status": "unhealthy", "error": "Health check failed"' in source
        assert '"error": "Health check failed",' in source
        assert '"error": str(exc)' not in source
