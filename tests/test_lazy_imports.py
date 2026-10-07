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

"""Optional dependencies are imported only when they are configured.

``redis`` only for a ``REDIS_URL`` with a Redis scheme, ``clickhouse_connect``
only for a non-empty ``CLICKHOUSE_HOST``, ``boto3`` only for
``FORENSIC_BACKEND=s3``; the loop breaker (numpy, scikit-learn on the Python
engine) only when a surface that runs it is enabled. Each check runs in a
fresh interpreter, so ``sys.modules`` shows what the proxy imported.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from _proxy_app import subprocess_env

OPTIONAL = ("redis", "clickhouse_connect", "boto3", "botocore")

# The proxy started through its lifespan, with every log record collected.
_STARTUP = textwrap.dedent(
    """
    import asyncio, json, logging, sys

    records = []

    class Collect(logging.Handler):
        def emit(self, record):
            records.append([record.levelname, record.name, record.getMessage()])

    logging.getLogger().addHandler(Collect())
    logging.getLogger().setLevel(logging.DEBUG)

    from admina.proxy import main

    async def go():
        async with main.lifespan(main.app):
            pass

    asyncio.run(go())
    print(json.dumps({{
        "modules": sorted(m for m in {optional!r} if m in sys.modules),
        "logs": records,
    }}))
    """
)

# Blocks the dependencies that proxy-minimal does not install, then serves
# the gateway, /health and /metrics through the ASGI app.
_MINIMAL = textwrap.dedent(
    """
    import asyncio, json, sys

    BLOCKED = {blocked!r}

    class Blocker:
        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in BLOCKED:
                raise ModuleNotFoundError(f"blocked: {{name}}")
            return None

    sys.meta_path.insert(0, Blocker())

    import httpx
    from admina.proxy import main

    def upstream(request):
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={{"object": "list", "data": [{{"id": "m1"}}]}})
        return httpx.Response(200, json={{
            "id": "c1", "object": "chat.completion", "model": "m1",
            "choices": [{{"index": 0, "finish_reason": "stop",
                         "message": {{"role": "assistant", "content": "hi"}}}}],
        }})

    async def go():
        async with main.lifespan(main.app):
            state = main.app.state.proxy
            await state.gateway_http_client.aclose()
            state.gateway_http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
            transport = httpx.ASGITransport(app=main.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                key = {{"Authorization": "Bearer " + "k" * 32}}
                chat = await c.post(
                    "/v1/chat/completions",
                    json={{"model": "m1", "messages": [{{"role": "user", "content": "hello"}}]}},
                    headers=key,
                )
                return {{
                    "health": (await c.get("/health")).status_code,
                    "metrics": (await c.get("/metrics")).status_code,
                    "models": (await c.get("/v1/models", headers=key)).status_code,
                    "chat": chat.status_code,
                    "chat_content": chat.json()["choices"][0]["message"]["content"],
                    "firewall": state.firewall.engine,
                }}

    result = asyncio.run(go())
    result["loaded"] = sorted(m for m in BLOCKED if m in sys.modules)
    print(json.dumps(result))
    """
)

# Not installed by the proxy-minimal extra.
NOT_IN_PROXY_MINIMAL = (
    "redis",
    "clickhouse_connect",
    "boto3",
    "botocore",
    "numpy",
    "scipy",
    "sklearn",
    "spacy",
    "opentelemetry",
    "typer",
    "admina_core",
)


def _run(code: str, cwd: Path, **env_extra: str) -> subprocess.CompletedProcess:
    defaults = {
        "REDIS_URL": "",
        "CLICKHOUSE_HOST": "",
        "OTEL_ENDPOINT": "",
        "ADMINA_API_KEY": "k" * 32,
    }
    env = subprocess_env("ADMINA_", "FORENSIC_", **{**defaults, **env_extra})
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def _startup(tmp_path: Path, **env_extra: str) -> dict:
    proc = _run(_STARTUP.format(optional=OPTIONAL), tmp_path, **env_extra)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


_CONNECTION = re.compile(
    r"(redis|clickhouse).*(connect|not available|unavailable|refused)"
    r"|(connect|not available|unavailable|refused).*(redis|clickhouse)",
    re.IGNORECASE,
)


def test_unconfigured_backends_are_not_imported(tmp_path):
    result = _startup(
        tmp_path,
        FORENSIC_BACKEND="filesystem",
        FORENSIC_BASE_DIR=str(tmp_path / "forensic"),
    )
    assert result["modules"] == []


def test_unconfigured_backends_leave_no_connection_log(tmp_path):
    result = _startup(
        tmp_path,
        FORENSIC_BACKEND="filesystem",
        FORENSIC_BASE_DIR=str(tmp_path / "forensic"),
    )
    attempts = [r for r in result["logs"] if _CONNECTION.search(r[2])]
    assert attempts == []
    warnings = [
        r
        for r in result["logs"]
        if r[0] in ("WARNING", "ERROR", "CRITICAL") and re.search("redis|clickhouse", r[2], re.I)
    ]
    assert warnings == []


def test_gateway_only_does_not_import_the_loop_breaker_stack(tmp_path):
    code = _STARTUP.format(optional=("sklearn",))
    proc = _run(code, tmp_path, ADMINA_ENABLED_SURFACES="gateway", ADMINA_ENGINE="python")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip().splitlines()[-1])["modules"] == []


def test_non_redis_scheme_is_not_a_connection(tmp_path):
    result = _startup(tmp_path, REDIS_URL="http://not-redis.test")
    assert result["modules"] == []


def test_gateway_runs_without_the_dependencies_proxy_minimal_leaves_out(tmp_path):
    proc = _run(
        _MINIMAL.format(blocked=NOT_IN_PROXY_MINIMAL),
        tmp_path,
        ADMINA_ENABLED_SURFACES="gateway",
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    assert result == {
        "health": 200,
        "metrics": 200,
        "models": 200,
        "chat": 200,
        "chat_content": "hi",
        "firewall": "python",
        "loaded": [],
    }


def test_loop_breaker_surfaces_explain_the_missing_dependencies(tmp_path):
    code = _MINIMAL.format(blocked=NOT_IN_PROXY_MINIMAL)
    proc = _run(code, tmp_path)  # every surface
    assert proc.returncode != 0
    assert "ADMINA_ENABLED_SURFACES=gateway" in proc.stderr
    assert "admina[proxy]" in proc.stderr


def test_configured_redis_without_the_package_is_a_warning(tmp_path):
    code = _MINIMAL.format(blocked=NOT_IN_PROXY_MINIMAL)
    proc = _run(
        code,
        tmp_path,
        ADMINA_ENABLED_SURFACES="gateway",
        REDIS_URL="redis://127.0.0.1:9/0",
        CLICKHOUSE_HOST="127.0.0.1",
    )
    assert proc.returncode == 0, proc.stderr
    assert "redis package is not installed" in proc.stderr
    assert "clickhouse-connect is not installed" in proc.stderr
