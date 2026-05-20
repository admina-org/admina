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

"""Tests for domains.compliance.otel module."""

from admina.domains.compliance.otel import OTELGovernanceExporter


class TestOTELExporter:
    def test_init_without_otel_sdk(self):
        """Exporter should degrade gracefully if OTEL SDK isn't configured."""
        exporter = OTELGovernanceExporter(endpoint="http://nonexistent:4317")
        # Should not raise — either works or disables itself
        assert isinstance(exporter.enabled, bool)

    def test_trace_noop_when_disabled(self):
        """trace_governance_decision should be a no-op when OTEL is unavailable."""
        exporter = OTELGovernanceExporter.__new__(OTELGovernanceExporter)
        exporter._enabled = False
        exporter._tracer = None
        # Should not raise
        exporter.trace_governance_decision(
            domain="firewall", action="BLOCK", risk_level="HIGH", latency_us=14.0
        )

    def test_get_stats(self):
        exporter = OTELGovernanceExporter.__new__(OTELGovernanceExporter)
        exporter._enabled = False
        stats = exporter.get_stats()
        assert "enabled" in stats
