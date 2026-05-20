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

"""Admina — OpenTelemetry governance observability.

Provides structured OTEL tracing for governance decisions.
Every governance domain decision emits a span with action, risk level, latency.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("admina.compliance.otel")

# Try to import OTEL — optional dependency at module level
try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    logger.info("OpenTelemetry not installed — governance tracing disabled")


class OTELGovernanceExporter:
    """Exports governance decisions as OTEL spans.

    If OTEL SDK is not installed, all methods are no-ops.

    Args:
        endpoint: OTLP gRPC endpoint (e.g., "http://localhost:4317").
        service_name: Service name for the tracer.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:4317",
        service_name: str = "admina-governance",
    ) -> None:
        self._enabled = _OTEL_AVAILABLE
        self._tracer = None
        if self._enabled:
            try:
                provider = TracerProvider()
                exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
                provider.add_span_processor(BatchSpanProcessor(exporter))
                trace.set_tracer_provider(provider)
                self._tracer = trace.get_tracer(service_name)
                logger.info("OTEL exporter initialized -> %s", endpoint)
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("OTEL initialization failed: %s", exc)
                self._enabled = False

    def trace_governance_decision(
        self,
        *,
        domain: str,
        action: str,
        risk_level: str,
        latency_us: float,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a governance decision as an OTEL span."""
        if not self._enabled or self._tracer is None:
            return
        with self._tracer.start_as_current_span(f"governance.{domain}") as span:
            span.set_attribute("admina.domain", domain)
            span.set_attribute("admina.action", action)
            span.set_attribute("admina.risk_level", risk_level)
            span.set_attribute("admina.latency_us", latency_us)
            if session_id:
                span.set_attribute("admina.session_id", session_id)
            if metadata:
                for k, v in metadata.items():
                    span.set_attribute(f"admina.meta.{k}", str(v))

    @property
    def enabled(self) -> bool:
        """Whether OTEL export is active."""
        return self._enabled

    def get_stats(self) -> dict[str, Any]:
        """Return exporter status for diagnostics."""
        return {"enabled": self._enabled, "engine": "otel"}
