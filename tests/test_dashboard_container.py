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

"""The dashboard container of the Docker Compose stack (``dashboard/``).

nginx serves the dashboard page and forwards the API to the proxy. With
``ADMINA_API_KEY`` set, it adds the key only to the read-only routes the
page reads (``/api/dashboard/*``, its live feed, ``/api/stats``), behind
HTTP Basic Auth: the init script stops the container without
``ADMINA_DASHBOARD_PASSWORD``. Without the key it adds no key header, and
the page signs in with the API key itself. ``/mcp`` and the other ``/api/``
routes are forwarded as received. Compose publishes the dashboard on the
loopback interface only.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
NGINX_CONF = REPO / "dashboard" / "nginx.conf"
INIT_SCRIPT = REPO / "dashboard" / "docker-entrypoint.sh"
PLACEHOLDER = "__ADMINA_API_KEY__"
KEY = "0123456789abcdef" * 4
PASSWORD = "Pw-QzX7wK9jQ2x"
KEY_ROUTES = {"/api/dashboard/live", "/api/dashboard/", "= /api/stats"}

_LOCATION_RX = re.compile(r"location\s+([^{]+?)\s*\{([^}]*)\}")
_COMMENT_RX = re.compile(r"#[^\n]*")


def _locations(conf: str) -> dict[str, str]:
    """The body of each location block of *conf*, comments left out."""
    return {m.group(1): m.group(2) for m in _LOCATION_RX.finditer(_COMMENT_RX.sub("", conf))}


def _key_routes(conf: str, key: str) -> set[str]:
    return {spec for spec, body in _locations(conf).items() if key in body}


def test_the_key_placeholder_is_only_on_the_dashboard_read_routes():
    conf = NGINX_CONF.read_text(encoding="utf-8")
    locations = _locations(conf)
    assert {"/api/", "/mcp"} <= set(locations)
    assert _key_routes(conf, PLACEHOLDER) == KEY_ROUTES
    assert conf.count(PLACEHOLDER) == len(KEY_ROUTES)
    for spec in ("/api/", "/mcp"):
        assert "X-API-Key" not in locations[spec]


def test_compose_publishes_the_dashboard_on_the_loopback_interface():
    yaml = pytest.importorskip("yaml")
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["services"]["dashboard"]["ports"] == ["127.0.0.1:3000:80"]


# ── The init script ───────────────────────────────────────────

pytestmark_sh = pytest.mark.skipif(
    shutil.which("sh") is None or shutil.which("sed") is None, reason="needs sh and sed"
)


def _install(tmp_path: Path) -> tuple[Path, Path, Path]:
    """The init script with its paths moved under *tmp_path*, a copy of the
    nginx configuration, and a stand-in ``openssl`` that records its
    arguments."""
    conf = tmp_path / "default.conf"
    conf.write_text(NGINX_CONF.read_text(encoding="utf-8"), encoding="utf-8")
    htpasswd = tmp_path / ".htpasswd"
    script = tmp_path / "90-api-key.sh"
    script.write_text(
        INIT_SCRIPT.read_text(encoding="utf-8")
        .replace("/etc/nginx/conf.d/default.conf", str(conf))
        .replace("/etc/nginx/.htpasswd", str(htpasswd)),
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    openssl = bin_dir / "openssl"
    openssl.write_text(
        f'#!/bin/sh\necho "$@" >> "{tmp_path}/openssl-args"\ncat > /dev/null\n'
        "echo '$apr1$salt$hash'\n",
        encoding="utf-8",
    )
    openssl.chmod(0o755)
    return script, conf, htpasswd


def _run(script: Path, **env: str) -> subprocess.CompletedProcess:
    path = f"{script.parent / 'bin'}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
    return subprocess.run(
        ["sh", str(script)],
        env={"PATH": path, **env},
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytestmark_sh
def test_with_the_key_it_does_not_start_without_a_password(tmp_path):
    script, conf, _ = _install(tmp_path)
    before = conf.read_text(encoding="utf-8")
    for password in (None, ""):
        env = {"ADMINA_API_KEY": KEY}
        if password is not None:
            env["ADMINA_DASHBOARD_PASSWORD"] = password
        proc = _run(script, **env)
        assert proc.returncode == 1
        assert "ADMINA_DASHBOARD_PASSWORD" in proc.stderr
        assert KEY not in proc.stdout + proc.stderr
        assert conf.read_text(encoding="utf-8") == before


@pytestmark_sh
def test_with_the_key_and_a_password_the_key_is_added_to_the_read_routes_only(tmp_path):
    script, conf, htpasswd = _install(tmp_path)
    proc = _run(script, ADMINA_API_KEY=KEY, ADMINA_DASHBOARD_PASSWORD=PASSWORD)
    assert proc.returncode == 0, proc.stderr
    text = conf.read_text(encoding="utf-8")
    assert PLACEHOLDER not in text and "__AUTH_BASIC__" not in text
    assert _key_routes(text, KEY) == KEY_ROUTES
    assert 'auth_basic "Admina Dashboard";' in text
    assert htpasswd.read_text(encoding="utf-8") == "admin:$apr1$salt$hash\n"
    # The password reaches openssl on stdin, not on its command line.
    assert PASSWORD not in (tmp_path / "openssl-args").read_text(encoding="utf-8")
    assert KEY not in proc.stdout + proc.stderr


@pytestmark_sh
def test_without_the_key_no_key_header_is_set(tmp_path):
    script, conf, htpasswd = _install(tmp_path)
    proc = _run(script)
    assert proc.returncode == 0, proc.stderr
    text = conf.read_text(encoding="utf-8")
    assert "X-API-Key" not in text and PLACEHOLDER not in text
    assert "auth_basic off;" in text
    assert htpasswd.read_text(encoding="utf-8") == ""


@pytestmark_sh
def test_without_the_key_a_password_still_turns_basic_auth_on(tmp_path):
    script, conf, _ = _install(tmp_path)
    proc = _run(script, ADMINA_DASHBOARD_PASSWORD=PASSWORD, ADMINA_DASHBOARD_USER="ops")
    assert proc.returncode == 0, proc.stderr
    text = conf.read_text(encoding="utf-8")
    assert "X-API-Key" not in text
    assert 'auth_basic "Admina Dashboard";' in text
    assert (tmp_path / ".htpasswd").read_text(encoding="utf-8").startswith("ops:")


@pytestmark_sh
@pytest.mark.parametrize("key", ['abc"def', "abc$host", "abc;def", "abc|def", "abc def"])
def test_a_key_that_cannot_be_written_into_the_configuration_is_refused(tmp_path, key):
    script, conf, _ = _install(tmp_path)
    before = conf.read_text(encoding="utf-8")
    proc = _run(script, ADMINA_API_KEY=key, ADMINA_DASHBOARD_PASSWORD=PASSWORD)
    assert proc.returncode == 1
    assert "ADMINA_API_KEY" in proc.stderr
    assert conf.read_text(encoding="utf-8") == before
