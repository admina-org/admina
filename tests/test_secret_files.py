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

"""ADMINA_API_KEY_FILE and ADMINA_FORENSIC_STATE_KEY_FILE.

Each key can be given directly or as a file (read once, one trailing
newline removed). A missing, unreadable or empty file, or a key set both
ways, stops the proxy at startup. Keys are random canaries: they must not
show up in logs, responses, error messages or forensic files.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from _proxy_app import CHAT, isolate, serve, subprocess_env, with_key
from pydantic import ValidationError

from admina.core.secretfile import SecretFileError, secret_from_env
from admina.domains.compliance.forensic import ForensicBlackBox
from admina.proxy.config import Settings

KEY_VARS = (
    "ADMINA_API_KEY",
    "ADMINA_API_KEY_FILE",
    "ADMINA_FORENSIC_STATE_KEY",
    "ADMINA_FORENSIC_STATE_KEY_FILE",
)


def _canary() -> str:
    return "canary-" + secrets.token_hex(16)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in KEY_VARS:
        monkeypatch.delenv(name, raising=False)


def _file(tmp_path: Path, content: str | bytes, name: str = "secret") -> str:
    path = tmp_path / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="")
    return str(path)


def _settings() -> Settings:
    return Settings(_env_file=None)


# ── ADMINA_API_KEY_FILE ───────────────────────────────────────


@pytest.mark.parametrize("ending", ["", "\n", "\r\n"], ids=["none", "lf", "crlf"])
def test_api_key_file_is_read_without_one_trailing_newline(tmp_path, monkeypatch, ending):
    key = _canary()
    monkeypatch.setenv("ADMINA_API_KEY_FILE", _file(tmp_path, key + ending))
    assert _settings().ADMINA_API_KEY == key


def test_api_key_file_is_read_once(tmp_path, monkeypatch):
    key = _canary()
    path = _file(tmp_path, key + "\n")
    monkeypatch.setenv("ADMINA_API_KEY_FILE", path)
    settings = _settings()
    os.remove(path)
    assert settings.ADMINA_API_KEY == key


def test_api_key_file_authenticates_requests(tmp_path, monkeypatch):
    from admina.proxy import main as proxy_main

    key = _canary()
    monkeypatch.setenv("ADMINA_API_KEY_FILE", _file(tmp_path, key + "\n"))
    monkeypatch.setattr(proxy_main, "settings", _settings())
    isolate(monkeypatch)

    responses, _ = serve(
        [
            CHAT,
            with_key(CHAT, key),
            {**CHAT, "headers": {"X-API-Key": key}},
            with_key(CHAT, "wrong-" + key),
            {"method": "GET", "url": "/v1/models", "headers": {"X-API-Key": key}},
        ]
    )
    assert [r.status_code for r in responses] == [401, 200, 200, 401, 200]
    assert responses[1].json()["choices"][0]["message"]["content"] == "hi"


def _unusable_api_key_setup(tmp_path, monkeypatch, case: str, key: str) -> None:
    if case == "missing":
        monkeypatch.setenv("ADMINA_API_KEY_FILE", str(tmp_path / "absent"))
    elif case == "directory":
        monkeypatch.setenv("ADMINA_API_KEY_FILE", str(tmp_path))
    elif case == "empty":
        monkeypatch.setenv("ADMINA_API_KEY_FILE", _file(tmp_path, ""))
    elif case == "newline_only":
        monkeypatch.setenv("ADMINA_API_KEY_FILE", _file(tmp_path, "\n"))
    elif case == "both_set":
        monkeypatch.setenv("ADMINA_API_KEY", key)
        monkeypatch.setenv("ADMINA_API_KEY_FILE", _file(tmp_path, _canary()))
    else:  # pragma: no cover
        raise AssertionError(case)


UNUSABLE = ["missing", "directory", "empty", "newline_only", "both_set"]


@pytest.mark.parametrize("case", UNUSABLE)
def test_unusable_api_key_file_is_a_settings_error(tmp_path, monkeypatch, case):
    key = _canary()
    _unusable_api_key_setup(tmp_path, monkeypatch, case, key)
    with pytest.raises(ValidationError, match="ADMINA_API_KEY") as excinfo:
        _settings()
    text = "".join(traceback.format_exception(excinfo.value))
    assert key not in text


@pytest.mark.parametrize("case", ["missing", "both_set"])
def test_proxy_does_not_start_with_an_unusable_api_key_file(tmp_path, monkeypatch, case):
    key = _canary()
    _unusable_api_key_setup(tmp_path, monkeypatch, case, key)
    proc = subprocess.run(
        [sys.executable, "-c", "import admina.proxy.main"],
        cwd=tmp_path,
        env=subprocess_env(REDIS_URL="", CLICKHOUSE_HOST=""),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode != 0
    assert "ADMINA_API_KEY" in proc.stderr
    assert key not in proc.stderr + proc.stdout
    file_key = Path(os.environ["ADMINA_API_KEY_FILE"])
    if file_key.is_file() and file_key.stat().st_size:
        assert file_key.read_text() not in proc.stderr + proc.stdout


# ── ADMINA_FORENSIC_STATE_KEY_FILE ────────────────────────────


def _signature(key: str, directory: Path) -> tuple[str, str]:
    payload = (directory / "_chain_state.json").read_bytes()
    expected = hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()
    return (directory / "_chain_state.json.sig").read_text().strip(), expected


def test_state_key_file_signs_the_chain_state(tmp_path, monkeypatch):
    key = _canary()
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", _file(tmp_path, key + "\n", "state_key"))
    store = tmp_path / "forensic"
    ForensicBlackBox(filesystem_dir=str(store)).record({"event_id": "e1", "action": "ALLOW"})
    actual, expected = _signature(key, store)
    assert actual == expected


def test_state_key_file_verifies_the_signed_state_on_restart(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", _file(tmp_path, _canary(), "state_key"))
    store = tmp_path / "forensic"
    ForensicBlackBox(filesystem_dir=str(store)).record({"event_id": "e1"})
    with caplog.at_level(logging.DEBUG, logger="admina.forensic_blackbox"):
        box = ForensicBlackBox(filesystem_dir=str(store))
    assert box.record_count == 1
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_state_key_file_signs_the_filesystem_plugin_store(tmp_path, monkeypatch):
    from admina.plugins.builtin.forensic.filesystem import FilesystemForensicStore

    key = _canary()
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", _file(tmp_path, key, "state_key"))
    store = tmp_path / "plugin-store"
    asyncio.run(FilesystemForensicStore(base_dir=str(store)).append({"event_id": "e1"}))
    actual, expected = _signature(key, store)
    assert actual == expected


def test_state_key_given_directly_still_works(tmp_path, monkeypatch):
    key = _canary()
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY", key)
    store = tmp_path / "forensic"
    ForensicBlackBox(filesystem_dir=str(store)).record({"event_id": "e1"})
    actual, expected = _signature(key, store)
    assert actual == expected


def _unusable_state_key_setup(tmp_path, monkeypatch, case: str, key: str) -> None:
    if case == "missing":
        monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", str(tmp_path / "absent"))
    elif case == "directory":
        monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", str(tmp_path))
    elif case == "empty":
        monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", _file(tmp_path, "", "state_key"))
    elif case == "newline_only":
        monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", _file(tmp_path, "\r\n", "state_key"))
    elif case == "both_set":
        monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY", key)
        monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", _file(tmp_path, _canary(), "k"))
    else:  # pragma: no cover
        raise AssertionError(case)


@pytest.mark.parametrize("case", UNUSABLE)
def test_unusable_state_key_file_is_an_error(tmp_path, monkeypatch, case):
    key = _canary()
    _unusable_state_key_setup(tmp_path, monkeypatch, case, key)
    with pytest.raises(SecretFileError, match="ADMINA_FORENSIC_STATE_KEY") as excinfo:
        ForensicBlackBox(filesystem_dir=str(tmp_path / "forensic"))
    assert key not in "".join(traceback.format_exception(excinfo.value))


@pytest.mark.parametrize("backend", ["filesystem", "memory"])
def test_proxy_does_not_start_with_an_unusable_state_key_file(tmp_path, monkeypatch, backend):
    from fastapi import FastAPI

    # Imported here: the error class of the admina modules the proxy uses now
    # (another test may have re-imported them).
    from admina.core.secretfile import SecretFileError
    from admina.proxy import main as proxy_main

    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", str(tmp_path / "absent"))
    isolate(monkeypatch, forensic_backend=backend, forensic_dir=str(tmp_path / "forensic"))

    async def go():
        async with proxy_main.lifespan(FastAPI()):
            pass

    with pytest.raises(SecretFileError, match="ADMINA_FORENSIC_STATE_KEY_FILE"):
        asyncio.run(go())


def test_secret_from_env_reads_the_variable_or_its_file(tmp_path):
    key = _canary()
    assert secret_from_env("X_KEY", {}) is None
    assert secret_from_env("X_KEY", {"X_KEY": key}) == key
    assert secret_from_env("X_KEY", {"X_KEY_FILE": _file(tmp_path, key + "\n")}) == key
    assert secret_from_env("X_KEY", {"X_KEY": "", "X_KEY_FILE": ""}) is None
    with pytest.raises(SecretFileError, match="both set"):
        secret_from_env("X_KEY", {"X_KEY": key, "X_KEY_FILE": _file(tmp_path, key)})


# ── Keys never logged ─────────────────────────────────────────


def test_keys_from_files_never_appear_in_logs_responses_or_forensic_files(
    tmp_path, monkeypatch, caplog
):
    from admina.proxy import main as proxy_main

    api_key = _canary()
    state_key = _canary()
    store = tmp_path / "forensic"
    monkeypatch.setenv("ADMINA_API_KEY_FILE", _file(tmp_path, api_key + "\n", "api_key"))
    monkeypatch.setenv("ADMINA_FORENSIC_STATE_KEY_FILE", _file(tmp_path, state_key, "state_key"))
    monkeypatch.setattr(proxy_main, "settings", _settings())
    isolate(monkeypatch, forensic_backend="filesystem", forensic_dir=str(store))

    with caplog.at_level(logging.DEBUG):
        responses, _ = serve(
            [
                {"method": "GET", "url": "/health"},
                {"method": "GET", "url": "/metrics"},
                CHAT,
                with_key(CHAT, api_key),
                with_key(CHAT, "wrong-key-" + "1" * 16),
                with_key({"method": "GET", "url": "/api/stats"}, api_key),
                with_key({"method": "GET", "url": "/v1/admina/ruleset"}, api_key),
            ]
        )

    assert [r.status_code for r in responses] == [200, 200, 401, 200, 401, 200, 200]
    logged = "\n".join(
        f"{r.getMessage()} {r.exc_text or ''} {json.dumps(r.args, default=str)}"
        for r in caplog.records
    )
    for key in (api_key, state_key):
        assert key not in logged
        for response in responses:
            assert key not in response.text
            assert key not in json.dumps(dict(response.headers))
        for path in store.rglob("*"):
            if path.is_file():
                assert key not in path.read_text(encoding="utf-8", errors="replace")
    assert (store / "_chain_state.json.sig").is_file()
    actual, expected = _signature(state_key, store)
    assert actual == expected
