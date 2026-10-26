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

"""FastAPI's own OpenTelemetry instrumentation is off in the proxy app.

FastAPI 0.160+ traces requests and logs validation failures, with the
input values, through the global OpenTelemetry providers. The proxy sets
a global tracer provider for its governance spans; requests must not
produce FastAPI spans next to them. The check runs in a subprocess, so the
global provider is the one it sets.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from _proxy_app import subprocess_env

_SCRIPT = """
import json
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

spans = InMemorySpanExporter()
provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(spans))
trace.set_tracer_provider(provider)

from fastapi.testclient import TestClient
from admina.proxy.main import app

with TestClient(app) as client:
    statuses = [
        client.get("/health").status_code,
        client.post("/api/v1/validate", json={"content": 1}).status_code,
    ]
print(json.dumps({"statuses": statuses, "spans": [s.name for s in spans.get_finished_spans()]}))
"""


def test_requests_produce_no_fastapi_spans():
    pytest.importorskip("opentelemetry.sdk.trace")
    env = subprocess_env(
        REDIS_URL="", CLICKHOUSE_HOST="", FORENSIC_BACKEND="memory", OTEL_ENABLED="false"
    )
    proc = subprocess.run(
        [sys.executable, "-c", _SCRIPT], env=env, capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    assert result["statuses"][0] == 200
    assert result["spans"] == []
