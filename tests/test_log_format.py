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

"""ADMINA_LOG_FORMAT=json: one JSON object per log line.

The object holds the time, the level, the logger name, the message and the
exception text when there is one; attributes attached to a record (such as
request data passed with ``extra=``) are not copied into it.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys

import pytest

pytest.importorskip("pydantic_settings")

from _proxy_app import subprocess_env
from pydantic import ValidationError

from admina.proxy.config import Settings
from admina.proxy.log_format import JsonLogFormatter


def _record(exc_info=None) -> logging.LogRecord:
    return logging.LogRecord(
        "admina.proxy", logging.WARNING, __file__, 1, "hello %s", ("world",), exc_info
    )


def test_formatter_writes_the_fixed_fields():
    line = JsonLogFormatter().format(_record())
    data = json.loads(line)
    assert set(data) == {"timestamp", "level", "logger", "message"}
    assert data["level"] == "WARNING"
    assert data["logger"] == "admina.proxy"
    assert data["message"] == "hello world"
    assert data["timestamp"].endswith("Z")
    assert "\n" not in line


def test_formatter_adds_the_exception():
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        record = _record(exc_info=sys.exc_info())
    data = json.loads(JsonLogFormatter().format(record))
    assert "RuntimeError: boom" in data["exception"]


def test_formatter_ignores_extra_attributes():
    record = _record()
    record.content = "canary-request-content"
    record.body = {"messages": ["canary-request-content"]}
    assert "canary-request-content" not in JsonLogFormatter().format(record)


@pytest.mark.parametrize(
    ("value", "expected"), [("", "text"), ("JSON", "json"), (" text ", "text")]
)
def test_setting(monkeypatch, value, expected):
    monkeypatch.setenv("ADMINA_LOG_FORMAT", value)
    assert Settings(_env_file=None).ADMINA_LOG_FORMAT == expected


def test_unknown_format_is_a_settings_error(monkeypatch):
    monkeypatch.setenv("ADMINA_LOG_FORMAT", "xml")
    with pytest.raises(ValidationError, match="ADMINA_LOG_FORMAT"):
        Settings(_env_file=None)


def _log_from_proxy(fmt: str, tmp_path) -> list[str]:
    code = (
        "import logging, admina.proxy.main; "
        "logging.getLogger('admina.proxy').warning('hello %s', 'world')"
    )
    env = subprocess_env(ADMINA_LOG_FORMAT=fmt, REDIS_URL="", CLICKHOUSE_HOST="")
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stderr.strip().splitlines()


def test_proxy_logs_json_lines(tmp_path):
    lines = _log_from_proxy("json", tmp_path)
    data = json.loads(lines[-1])
    assert data["message"] == "hello world"
    assert data["logger"] == "admina.proxy"
    for line in lines:
        json.loads(line)


def test_proxy_logs_text_by_default(tmp_path):
    line = _log_from_proxy("text", tmp_path)[-1]
    assert line.endswith("[admina.proxy] WARNING: hello world")
