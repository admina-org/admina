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

"""Proxy runtime state — holds connections, engines, and metrics."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import redis.asyncio as aioredis

from admina.domains.compliance.eu_ai_act import EUAIActCompliance
from admina.domains.compliance.forensic import ForensicBlackBox
from admina.domains.compliance.gdpr import ProcessingActivitiesRegistry
from admina.domains.compliance.nis2 import NIS2Compliance
from admina.domains.compliance.otel import OTELGovernanceExporter
from admina.plugins.registry import PluginRegistry
from admina.proxy.multi_upstream import MultiUpstreamRouter


@dataclass
class ProxyState:
    """Mutable runtime state for the proxy.

    Created once at startup, passed to handlers via app.state.
    """

    # Connections
    redis: aioredis.Redis | None = None
    clickhouse: Any = None
    http_client: httpx.AsyncClient | None = None

    # Governance engines (set by engine_bridge)
    firewall: Any = None
    pii_redactor: Any = None
    loop_breaker: Any = None

    # Subsystems
    forensic_box: ForensicBlackBox | None = None
    compliance: EUAIActCompliance = field(default_factory=EUAIActCompliance)
    nis2: NIS2Compliance = field(default_factory=NIS2Compliance)
    gdpr: ProcessingActivitiesRegistry = field(default_factory=ProcessingActivitiesRegistry)
    router: MultiUpstreamRouter | None = None
    registry: PluginRegistry = field(default_factory=PluginRegistry)

    # Plugins
    governance_guards: list = field(default_factory=list)
    alert_channels: list = field(default_factory=list)
    auth_providers: list = field(default_factory=list)

    # OTEL
    otel_exporter: OTELGovernanceExporter | None = None

    # Metrics
    metrics: dict[str, Any] = field(
        default_factory=lambda: {
            "requests_total": 0,
            "requests_blocked": 0,
            "requests_allowed": 0,
            "requests_redacted": 0,
            "avg_latency_ms": 0.0,
            "started_at": datetime.now(UTC).isoformat(),
        }
    )
    _metrics_lock: threading.Lock = field(default_factory=threading.Lock)

    def inc_metric(self, key: str, value: int = 1) -> None:
        with self._metrics_lock:
            self.metrics[key] += value

    def update_avg_latency(self, latency_ms: float) -> None:
        with self._metrics_lock:
            n = self.metrics["requests_total"]
            if n <= 1:
                self.metrics["avg_latency_ms"] = latency_ms
            else:
                self.metrics["avg_latency_ms"] = round(
                    (self.metrics["avg_latency_ms"] * (n - 1) + latency_ms) / n,
                    2,
                )
