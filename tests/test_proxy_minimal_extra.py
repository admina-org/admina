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

"""The ``proxy-minimal`` extra serves the gateway.

Installs ``.[proxy-minimal]`` with uv into a throw-away virtual environment
under the temporary directory, then starts ``uvicorn admina.proxy.main:app``
from it with ``ADMINA_ENABLED_SURFACES=gateway`` against a local fake
upstream: ``/health`` (with the container healthcheck command), ``/metrics``
and ``/v1/chat/completions`` answer 200, and Redis, ClickHouse, boto3 and
the scientific stack are not installed.

The installation needs network access to the package index, so this test
carries the ``benchmark`` marker and is left out of the
``-m "not benchmark"`` runs.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = [
    pytest.mark.benchmark,
    pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv"),
]

HEALTHCHECK = (
    "import urllib.request,sys;"
    "sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:{port}/health',timeout=2)"
    ".status==200 else 1)"
)

LEFT_OUT = ("redis", "clickhouse_connect", "boto3", "numpy", "sklearn", "scipy", "spacy")


class _Upstream(BaseHTTPRequestHandler):
    """A fake OpenAI-compatible upstream."""

    def _reply(self, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        self._reply({"object": "list", "data": [{"id": "m1"}]})

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self._reply(
            {
                "id": "c1",
                "object": "chat.completion",
                "model": "m1",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "hi"},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    def log_message(self, *_args) -> None:
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _request(url: str, *, body: dict | None = None, key: str | None = None) -> tuple[int, str]:
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode()


def test_proxy_minimal_serves_the_gateway():
    uv = shutil.which("uv")
    with tempfile.TemporaryDirectory(prefix="admina-proxy-minimal-") as tmp:
        venv = Path(tmp) / "venv"
        python = venv / "bin" / "python"
        subprocess.run(
            [uv, "venv", "--quiet", "--python", sys.executable, str(venv)],
            check=True,
            timeout=300,
        )
        subprocess.run(
            [
                uv,
                "pip",
                "install",
                "--quiet",
                "--python",
                str(python),
                "-e",
                f"{ROOT}[proxy-minimal]",
            ],
            check=True,
            timeout=600,
        )
        missing = subprocess.run(
            [
                str(python),
                "-c",
                "import importlib.util, json; "
                f"print(json.dumps([m for m in {LEFT_OUT!r} if importlib.util.find_spec(m)]))",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(missing.stdout) == []

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        port = _free_port()
        key = "k" * 32
        env = {k: v for k, v in os.environ.items() if not k.startswith(("ADMINA_", "FORENSIC_"))}
        env.update(
            {
                "ADMINA_ENABLED_SURFACES": "gateway",
                "ADMINA_API_KEY": key,
                "ADMINA_GATEWAY_UPSTREAM": f"http://127.0.0.1:{upstream.server_port}/v1",
                "REDIS_URL": "",
                "CLICKHOUSE_HOST": "",
                "FORENSIC_BACKEND": "filesystem",
                "FORENSIC_BASE_DIR": str(Path(tmp) / "forensic"),
            }
        )
        server = subprocess.Popen(
            [
                str(venv / "bin" / "uvicorn"),
                "admina.proxy.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--workers",
                "1",
                "--no-access-log",
                "--log-level",
                "warning",
                "--timeout-keep-alive",
                "75",
            ],
            cwd=tmp,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.monotonic() + 60
            healthy = False
            while time.monotonic() < deadline and server.poll() is None:
                check = subprocess.run(
                    [str(python), "-c", HEALTHCHECK.format(port=port)], capture_output=True
                )
                if check.returncode == 0:
                    healthy = True
                    break
                time.sleep(0.5)
            assert healthy, server.stdout.read() if server.poll() is not None else "timeout"

            base = f"http://127.0.0.1:{port}"
            status, text = _request(f"{base}/health")
            assert status == 200
            assert json.loads(text)["surfaces"] == ["gateway"]
            assert _request(f"{base}/metrics")[0] == 200
            status, text = _request(
                f"{base}/v1/chat/completions",
                body={"model": "m1", "messages": [{"role": "user", "content": "hello"}]},
                key=key,
            )
            assert status == 200
            assert json.loads(text)["choices"][0]["message"]["content"] == "hi"
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                server.kill()
            upstream.shutdown()
