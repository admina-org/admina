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

"""The proxy's forensic backend comes from the environment and admina.yaml.

``FORENSIC_BACKEND`` and ``FORENSIC_BASE_DIR``, when set (environment or
``.env``), win over ``domains.compliance.forensic.backend`` (or its older
name ``storage``) and ``base_dir`` of admina.yaml; a value set in both places
with different values is logged at startup. With neither, the backend is
``memory``.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

pytest.importorskip("fastapi")

from _forensic_chain import record_files

from admina.core.config import _build_from_yaml
from admina.proxy.config import Settings
from admina.proxy.forensic_backend import (
    build_forensic_store,
    forensic_backend_choice,
)

_VARS = ("FORENSIC_BACKEND", "FORENSIC_BASE_DIR")


@pytest.fixture
def env(monkeypatch):
    """No forensic variable in the environment; returns a Settings factory."""
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)

    def make(**variables: str) -> Settings:
        for name, value in variables.items():
            monkeypatch.setenv(name, value)
        return Settings(_env_file=None)

    return make


def _yaml(**forensic):
    return _build_from_yaml({"domains": {"compliance": {"forensic": forensic}}})


def _conflicts(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


def test_yaml_backend_and_directory_are_honoured(env, tmp_path, caplog):
    config = _yaml(backend="filesystem", base_dir=str(tmp_path / "f"))
    choice = forensic_backend_choice(env(), config)
    assert (choice.backend, choice.base_dir) == ("filesystem", str(tmp_path / "f"))
    box = build_forensic_store(env(), config)
    assert box.filesystem_dir == (tmp_path / "f").resolve()
    assert not _conflicts(caplog)


def test_yaml_storage_is_the_older_name_of_backend(env, tmp_path):
    config = _yaml(storage="filesystem", base_dir=str(tmp_path / "f"))
    assert forensic_backend_choice(env(), config).backend == "filesystem"


def test_yaml_backend_wins_over_storage(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        config = _yaml(backend="memory", storage="filesystem")
    assert config.compliance.forensic.backend == "memory"
    assert any("storage" in m and "backend" in m for m in _conflicts(caplog))


def test_the_environment_wins_over_yaml_and_the_conflict_is_logged(env, tmp_path, caplog):
    config = _yaml(backend="filesystem", base_dir=str(tmp_path / "yaml"))
    settings = env(FORENSIC_BACKEND="filesystem", FORENSIC_BASE_DIR=str(tmp_path / "env"))
    with caplog.at_level(logging.WARNING):
        choice = forensic_backend_choice(settings, config)
    assert choice.base_dir == str(tmp_path / "env")
    (message,) = _conflicts(caplog)
    assert "FORENSIC_BASE_DIR" in message
    assert str(tmp_path / "env") in message and str(tmp_path / "yaml") in message


def test_an_environment_backend_overrides_the_yaml_one(env, tmp_path, caplog):
    config = _yaml(backend="filesystem", base_dir=str(tmp_path / "yaml"))
    with caplog.at_level(logging.WARNING):
        choice = forensic_backend_choice(env(FORENSIC_BACKEND="memory"), config)
    assert choice.backend == "memory"
    assert any("FORENSIC_BACKEND" in m and "filesystem" in m for m in _conflicts(caplog))


def test_the_same_value_in_both_places_is_no_conflict(env, tmp_path, caplog):
    config = _yaml(backend="filesystem", base_dir=str(tmp_path / "f"))
    settings = env(FORENSIC_BACKEND="filesystem", FORENSIC_BASE_DIR=str(tmp_path / "f"))
    with caplog.at_level(logging.WARNING):
        forensic_backend_choice(settings, config)
    assert not _conflicts(caplog)


def test_without_either_the_backend_is_memory(env):
    choice = forensic_backend_choice(env(), None)
    assert (choice.backend, choice.base_dir) == ("memory", "")
    choice = forensic_backend_choice(env(), _build_from_yaml({}))
    assert (choice.backend, choice.base_dir) == ("memory", "")


@pytest.mark.parametrize("value", ["disk", "sqlite"])
def test_an_unknown_yaml_backend_is_an_error(env, value):
    config = _yaml(backend=value)
    with pytest.raises(ValueError, match=r"domains\.compliance\.forensic\.backend"):
        forensic_backend_choice(env(), config)


def test_the_running_proxy_uses_the_yaml_directory(env, tmp_path, monkeypatch):
    from _proxy_app import isolate, serve

    from admina.proxy import main as proxy_main

    directory = tmp_path / "from-yaml"
    isolate(monkeypatch)
    for name in ("ADMINA_API_KEY", "ADMINA_API_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    settings = env(REDIS_URL="", CLICKHOUSE_HOST="", ALLOW_UNAUTHENTICATED="true")
    assert "FORENSIC_BACKEND" not in settings.model_fields_set
    monkeypatch.setattr(proxy_main, "settings", settings)
    monkeypatch.setattr(
        proxy_main, "_admina_config", _yaml(backend="filesystem", base_dir=str(directory))
    )

    responses, state = serve(
        [
            {
                "method": "POST",
                "url": "/v1/chat/completions",
                "json": {"model": "m1", "messages": [{"role": "user", "content": "hello"}]},
            }
        ]
    )
    assert responses[0].status_code == 200
    assert state.forensic_box.filesystem_dir == directory.resolve()
    assert len(record_files(directory)) == 2
    assert asyncio.run(state.forensic_box.verify_chain())["valid"] is True
