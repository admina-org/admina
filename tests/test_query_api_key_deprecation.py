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

"""The API key in the query string (``?api_key=``) is deprecated.

It is still accepted, and the first request that authenticates with it logs
a warning, once per process; the key never appears in the warning.
"""

from __future__ import annotations

import logging

import pytest

pytest.importorskip("fastapi")

_KEY = "canary-query-key-0123456789"


@pytest.fixture
def proxy_main(monkeypatch):
    from admina.proxy import main

    monkeypatch.setattr(main.settings, "ADMINA_API_KEY", _KEY)
    monkeypatch.setattr(main, "_query_key_warned", False)
    return main


def _warnings(caplog) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records if "api_key" in r.getMessage() and r.levelno == logging.WARNING
    ]


def test_query_key_is_accepted_and_logs_a_warning_once(proxy_main, caplog):
    caplog.set_level(logging.WARNING, logger="admina.proxy")
    assert proxy_main.verify_credential(query_params={"api_key": _KEY})
    assert proxy_main.verify_credential(query_params={"api_key": _KEY})
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "deprecated" in warnings[0].getMessage()
    assert _KEY not in caplog.text


def test_header_key_logs_nothing(proxy_main, caplog):
    caplog.set_level(logging.WARNING, logger="admina.proxy")
    assert proxy_main.verify_credential(headers={"x-api-key": _KEY})
    assert _warnings(caplog) == []


def test_wrong_query_key_logs_nothing(proxy_main, caplog):
    caplog.set_level(logging.WARNING, logger="admina.proxy")
    assert not proxy_main.verify_credential(query_params={"api_key": "wrong"})
    assert _warnings(caplog) == []
